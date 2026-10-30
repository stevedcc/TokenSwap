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
public sealed class BrokerRequestHandler(
    BrokerPolicyHolder policyHolder,
    IBrokerSecretSource secrets,
    IBrokerForwarder forwarder,
    BrokerLimiter limiter,
    BrokerUnlockGuard unlockGuard,
    BrokerLog log,
    TimeProvider time)
{
    private readonly SemaphoreSlim _unlock = new(1, 1);

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

        if (!policy.Sockets.TryGetValue(peer.Socket, out var socket) || !socket.AllowsUid(peer.Uid))
        {
            // The config changed under a kept-alive connection: close it, unanswered.
            log.Connection(peer.Socket, peer.Uid, peer.Pid, "uid-not-allowed");
            http.Abort();
            return;
        }

        if (HttpMethods.IsConnect(method) || !rawTarget.StartsWith('/'))
        {
            await WriteUniformAsync(http, StatusCodes.Status400BadRequest).ConfigureAwait(false);
            log.Request(record with { Status = 400, Reason = "request-target" });
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

        using var slot = await limiter.TryAcquireAsync(peer.Socket, http.RequestAborted).ConfigureAwait(false);
        if (slot is null)
        {
            await WriteUniformAsync(http, StatusCodes.Status503ServiceUnavailable).ConfigureAwait(false);
            log.Request(record with { Status = 503, Reason = "busy" });
            return;
        }

        // Decision 1: a fresh unlock for every request, one at a time, reading only this route's secret.
        BrokerSecret secret;
        var started = time.GetTimestamp();
        await _unlock.WaitAsync(http.RequestAborted).ConfigureAwait(false);
        try
        {
            if (unlockGuard.Refusal(peer.Socket) is { } refusedNow)
            {
                await WriteUniformAsync(http, StatusCodes.Status503ServiceUnavailable).ConfigureAwait(false);
                log.Request(record with { Status = 503, Reason = refusedNow });
                return;
            }
            secret = await Task.Run(() => secrets.Read(route.SecretName)).ConfigureAwait(false);
            unlockGuard.RecordSuccess(peer.Socket);
        }
        catch (BrokerUnlockException)
        {
            var lockedOut = unlockGuard.RecordFailure(peer.Socket);
            if (lockedOut)
                log.Event($"socket '{peer.Socket}' locked out after repeated unlock failures");
            await WriteUniformAsync(http, StatusCodes.Status502BadGateway).ConfigureAwait(false);
            log.Request(record with { Status = 502, Unlocks = 1, UnlockDuration = time.GetElapsedTime(started), Reason = "unlock-failed" });
            return;
        }
        catch (BrokerSecretException)
        {
            await WriteUniformAsync(http, StatusCodes.Status502BadGateway).ConfigureAwait(false);
            log.Request(record with { Status = 502, Unlocks = 1, UnlockDuration = time.GetElapsedTime(started), Reason = "secret-unusable" });
            return;
        }
        finally
        {
            _unlock.Release();
        }
        record = record with { Unlocks = 1, UnlockDuration = time.GetElapsedTime(started) };

        BrokerForwardOutcome outcome;
        using (secret)
        {
            try
            {
                outcome = await forwarder.ForwardAsync(http, new BrokerForwardRequest(route, built.Outbound!, secret, sniffer.ConnectionNamedHeaders), http.RequestAborted).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
            {
                outcome = new BrokerForwardOutcome(499, 0, 0, "client-closed");
            }
        }
        log.Request(record with { Status = outcome.Status, BytesIn = outcome.BytesIn, BytesOut = outcome.BytesOut, Reason = outcome.Reason });
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
