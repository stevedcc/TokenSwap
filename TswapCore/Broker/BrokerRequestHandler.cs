using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace TswapCore.Broker;

/// <summary>
/// An allowed request, ready to go upstream: the route, the outbound URI the broker built, the
/// route's secret, and the header names the client's raw <c>Connection</c> header listed (dropped).
/// </summary>
public sealed record BrokerForwardRequest(BrokerRoutePolicy Route, Uri Outbound, BrokerSecret Secret, IReadOnlySet<string> ConnectionNamed);

/// <summary>What forwarding did, for the log line.</summary>
public readonly record struct BrokerForwardOutcome(int Status, long BytesIn, long BytesOut, string? Reason = null);

/// <summary>Sends an allowed request upstream and streams the answer back (decisions 5 to 8).</summary>
public interface IBrokerForwarder
{
    Task<BrokerForwardOutcome> ForwardAsync(HttpContext http, BrokerForwardRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// One HTTP request on a broker socket, in order: the connection's identity (re-checked against the
/// config this request started with), the request target, the route (socket allow-list, method,
/// path), the unlock-failure limits, a request slot, a fresh unlock (serialised), then forwarding.
/// Every refusal of a route, method or path is the same uniform <c>404</c>.
/// </summary>
public sealed partial class BrokerRequestHandler(
    BrokerPolicyHolder policyHolder,
    IBrokerSecretSource secrets,
    IBrokerForwarder forwarder,
    BrokerLimiter limiter,
    BrokerUnlockGuard unlockGuard,
    BrokerLog log,
    TimeProvider time,
    BrokerLimits? limits = null,
    Action<string>? onFatal = null)
{
    private readonly BrokerLimits _limits = limits ?? new BrokerLimits();
    private int _timeoutsInARow;

    private readonly SemaphoreSlim _unlock = new(1, 1);

    /// <summary>Raised when a request starts waiting for the unlock (tests wait on it instead of sleeping).</summary>
    public event Action? WaitingForUnlock;

    public async Task HandleAsync(HttpContext http)
    {
        var items = http.Features.Get<IConnectionItemsFeature>()?.Items;
        var peer = items?.TryGetValue(BrokerServer.PeerItemKey, out var p) == true ? p as BrokerPeer : null;
        var sniffer = items?.TryGetValue(BrokerServer.SnifferItemKey, out var s) == true ? s as BrokerHeaderSniffer : null;
        if (peer is null || sniffer is null || !sniffer.HeadersSeen)
        {
            http.Abort(); // never reached through the gate; fail closed
            return;
        }
        // One request per connection: the header sniffer reads only the first request's Connection lines.
        http.Response.OnStarting(() =>
        {
            http.Response.Headers.Connection = "close";
            return Task.CompletedTask;
        });
        var policy = policyHolder.Current; // this request keeps this config
        var method = http.Request.Method;
        var rawTarget = http.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "";
        var record = new BrokerRequestRecord
        {
            Socket = peer.Socket,
            Uid = peer.Uid,
            Pid = peer.Pid,
            Method = method,
            Path = rawTarget,
        };

        // Read (and zero) the raw Connection header's names at once.
        var connectionNamed = sniffer.TakeConnectionNamedHeaders();
        if (!policy.Sockets.TryGetValue(peer.Socket, out var socket) || !socket.AllowsUid(peer.Uid))
        {
            // The config changed between accepting the connection and this request: close it, unanswered.
            log.Connection(peer.Socket, peer.Uid, peer.Pid, socket is null ? "socket-removed" : "uid-not-allowed");
            http.Abort();
            return;
        }

        if (HttpMethods.IsConnect(method) || !rawTarget.StartsWith('/'))
        {
            await WriteUniformAsync(http, StatusCodes.Status400BadRequest).ConfigureAwait(false);
            log.Request(record with { Status = 400, Reason = "request-target" });
            return;
        }

        // Brief T9: template calls share the socket, its identity check and its limits.
        if (rawTarget.StartsWith(TemplatePrefix, StringComparison.Ordinal))
        {
            await HandleTemplateAsync(http, peer, policy, socket, rawTarget).ConfigureAwait(false);
            return;
        }

        var target = BrokerRequestTarget.Parse(rawTarget);
        if (target.RouteName is null || !policy.Routes.TryGetValue(target.RouteName, out var route) || !socket.Routes.Contains(route.Name))
        {
            await NotFoundAsync(http, record, "route").ConfigureAwait(false);
            return;
        }
        record = record with { Route = route.Name };
        if (!route.Methods.Contains(method))
        {
            await NotFoundAsync(http, record, "method").ConfigureAwait(false);
            return;
        }
        var built = target.Build(route);
        if (built.Failure is { } failure)
        {
            if (built.DecodedPath != null)
                record = record with { Path = built.DecodedPath };
            await NotFoundAsync(http, record, failure).ConfigureAwait(false);
            return;
        }
        record = record with { Path = built.DecodedPath! };

        if (unlockGuard.Refusal(peer.Socket) is { } refused)
        {
            await WriteUniformAsync(http, StatusCodes.Status503ServiceUnavailable).ConfigureAwait(false);
            log.Request(record with { Status = 503, Reason = refused });
            return;
        }

        IDisposable? slot;
        try
        {
            slot = await limiter.TryAcquireAsync(peer.Socket, http.RequestAborted).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
        {
            log.Request(record with { Status = 499, Reason = "client-closed" });
            return;
        }
        using var slotLease = slot;
        if (slot is null)
        {
            await WriteUniformAsync(http, StatusCodes.Status503ServiceUnavailable).ConfigureAwait(false);
            log.Request(record with { Status = 503, Reason = "busy" });
            return;
        }

        // Decision 1: a fresh unlock for every request, one at a time, reading only this route's secret.
        var unlocked = await UnlockAsync(http, peer.Socket, () => secrets.Read(route.SecretName), s => s.Dispose()).ConfigureAwait(false);
        if (unlocked.Value is not { } secret)
        {
            if (unlocked.Status != 499)
                await WriteUniformAsync(http, unlocked.Status).ConfigureAwait(false);
            log.Request(record with { Status = unlocked.Status, Unlocks = unlocked.Unlocks, UnlockDuration = unlocked.Duration, Reason = unlocked.Reason });
            ReportFatal(unlocked.FatalReason);
            return;
        }
        record = record with { Unlocks = 1, UnlockDuration = unlocked.Duration };

        BrokerForwardOutcome outcome;
        using (secret)
        {
            try
            {
                outcome = await forwarder.ForwardAsync(http, new BrokerForwardRequest(route, built.Outbound!, secret, connectionNamed), http.RequestAborted).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
            {
                outcome = new BrokerForwardOutcome(499, 0, 0, "client-closed");
            }
        }
        log.Request(record with { Status = outcome.Status, BytesIn = outcome.BytesIn, BytesOut = outcome.BytesOut, Reason = outcome.Reason });
    }

    /// <summary>What <see cref="UnlockAsync"/> got: the value, or the status and reason to answer with.</summary>
    internal readonly record struct UnlockOutcome<T>(T? Value, int Status, string? Reason, TimeSpan Duration, int Unlocks, string? FatalReason = null)
        where T : class;

    /// <summary>
    /// Decision 1 (T8), shared by routes and templates (T9): waits for the unlock (serialised), checks
    /// the unlock-failure limits, then runs <paramref name="read"/> (one unlock) with the unlock
    /// timeout. A read abandoned after the timeout is passed to <paramref name="discard"/> when it
    /// finishes. Never writes the response; the caller answers <see cref="UnlockOutcome{T}.Status"/>
    /// (499: the client went away, answer nothing), logs, then calls <see cref="ReportFatal"/>.
    /// </summary>
    internal async Task<UnlockOutcome<T>> UnlockAsync<T>(HttpContext http, string socket, Func<T> read, Action<T> discard) where T : class
    {
        var started = time.GetTimestamp();
        WaitingForUnlock?.Invoke();
        try
        {
            await _unlock.WaitAsync(http.RequestAborted).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
        {
            // The client gave up while queued for the unlock.
            return new UnlockOutcome<T>(null, 499, "client-closed", TimeSpan.Zero, 0);
        }
        try
        {
            if (unlockGuard.Refusal(socket) is { } refusedNow)
                return new UnlockOutcome<T>(null, 503, refusedNow, TimeSpan.Zero, 0);
            unlockGuard.RecordAttempt();
            var task = Task.Run(read);
            try
            {
                // Fix round 1: an unlock that hangs (a wedged TPM) is abandoned, never waited on forever.
                await task.WaitAsync(_limits.UnlockTimeout, time).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not (TimeoutException or OperationCanceledException))
            {
                // The unlock completed, by failing: that also ends a run of timeouts. A cancelled
                // unlock did not complete, so it doesn't (a wedged TPM still reaches the exit).
                Interlocked.Exchange(ref _timeoutsInARow, 0);
                throw;
            }
            catch (TimeoutException)
            {
                // The abandoned unlock keeps running; whatever it returns is zeroed, never used.
                _ = task.ContinueWith(t =>
                {
                    if (t.IsCompletedSuccessfully)
                        discard(t.Result);
                    else
                        _ = t.Exception; // observed
                }, TaskScheduler.Default);
                string? fatal = null;
                if (Interlocked.Increment(ref _timeoutsInARow) >= _limits.UnlockTimeoutsBeforeExit)
                    fatal = $"{_limits.UnlockTimeoutsBeforeExit} unlocks in a row took longer than {_limits.UnlockTimeout.TotalSeconds:0} s; exiting so the service manager restarts serve";
                return new UnlockOutcome<T>(null, 503, "unlock-timeout", time.GetElapsedTime(started), 1, fatal);
            }
            Interlocked.Exchange(ref _timeoutsInARow, 0); // a completed unlock (success or failure) ends the run
            var value = await task.ConfigureAwait(false);
            unlockGuard.RecordSuccess(socket);
            return new UnlockOutcome<T>(value, 0, null, time.GetElapsedTime(started), 1);
        }
        catch (BrokerUnlockException)
        {
            if (unlockGuard.RecordFailure(socket))
                log.Event($"socket '{socket}' locked out after repeated unlock failures");
            return new UnlockOutcome<T>(null, 502, "unlock-failed", time.GetElapsedTime(started), 1);
        }
        catch (BrokerSecretException)
        {
            return new UnlockOutcome<T>(null, 502, "secret-unusable", time.GetElapsedTime(started), 1);
        }
        catch (Exception)
        {
            // Any other failure of the secret source (a cancellation, a bug): the same uniform
            // answer and a log line, never an unanswered 500. The message is not logged.
            return new UnlockOutcome<T>(null, 502, "secret-source-error", time.GetElapsedTime(started), 1);
        }
        finally
        {
            _unlock.Release();
        }
    }

    /// <summary>After the request's log line: a run of hung unlocks long enough ends serve (systemd restarts it).</summary>
    internal void ReportFatal(string? reason)
    {
        if (reason is null)
            return;
        log.Event(reason);
        onFatal?.Invoke(reason);
    }

    private async Task NotFoundAsync(HttpContext http, BrokerRequestRecord record, string reason)
    {
        await WriteUniformAsync(http, StatusCodes.Status404NotFound).ConfigureAwait(false);
        log.Request(record with { Status = 404, Reason = reason });
    }

    /// <summary>
    /// The broker's own answers (400, 404, 502, 503): a fixed body and headers, and the Date from the
    /// injected clock, so every refusal of one status is byte-identical (decision 4).
    /// </summary>
    public Task WriteUniformAsync(HttpContext http, int status) => WriteUniformAsync(http, status, time);

    /// <inheritdoc cref="WriteUniformAsync(HttpContext, int)"/>
    public static async Task WriteUniformAsync(HttpContext http, int status, TimeProvider time)
    {
        if (http.Response.HasStarted)
        {
            http.Abort();
            return;
        }
        var body = Encoding.ASCII.GetBytes(status switch
        {
            400 => "Bad Request\n",
            404 => "Not Found\n",
            502 => "Bad Gateway\n",
            429 => "Too Many Requests\n",
            503 => "Service Unavailable\n",
            _ => "Error\n",
        });
        http.Response.Clear();
        http.Response.StatusCode = status;
        http.Response.Headers.ContentType = "text/plain; charset=utf-8";
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Date = time.GetUtcNow().ToString("r", CultureInfo.InvariantCulture);
        http.Response.ContentLength = body.Length;
        await http.Response.Body.WriteAsync(body).ConfigureAwait(false);
    }
}
