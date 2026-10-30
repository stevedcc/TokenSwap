using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using TswapCore;
using TswapCore.Broker;

namespace TswapTests;

/// <summary>
/// A <see cref="TimeProvider"/> that only moves when a test calls <see cref="Advance"/> (brief T8
/// decision 7: every broker wait uses the injected clock, so no test sleeps).
/// </summary>
public sealed class BrokerManualClock : TimeProvider
{
    private readonly Lock _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private DateTimeOffset _now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
            return _now;
    }

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => GetUtcNow().UtcTicks;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        lock (_gate)
            _timers.Add(timer);
        timer.Change(dueTime, period);
        return timer;
    }

    /// <summary>Moves the clock on and fires every timer that came due (outside the lock).</summary>
    public void Advance(TimeSpan by)
    {
        List<ManualTimer> due;
        lock (_gate)
        {
            _now += by;
            due = _timers.Where(t => t.Due is { } d && d <= _now).ToList();
            foreach (var t in due)
                t.Due = t.Period is { } p ? _now + p : null;
        }
        foreach (var t in due)
            t.Fire();
    }

    private sealed class ManualTimer(BrokerManualClock clock, TimerCallback callback, object? state) : ITimer
    {
        public DateTimeOffset? Due { get; set; }
        public TimeSpan? Period { get; set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (clock._gate)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? null : clock._now + dueTime;
                Period = period == Timeout.InfiniteTimeSpan || period == TimeSpan.Zero ? null : period;
            }
            return true;
        }

        public void Fire() => callback(state);

        public void Dispose()
        {
            lock (clock._gate)
            {
                Due = null;
                clock._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>A secret source for broker tests: counts unlocks, and can fail or block on demand.</summary>
public sealed class FakeBrokerSecrets(Func<string, string>? values = null) : IBrokerSecretSource
{
    private int _unlocks;
    private readonly Func<string, string> _values = values ?? (_ => "s3cr3t-Value_+/=");

    public int Unlocks => Volatile.Read(ref _unlocks);

    /// <summary>When set, every unlock fails.</summary>
    public bool Fail { get; set; }

    /// <summary>When set, an unlock waits for this before returning.</summary>
    public TaskCompletionSource? Gate { get; set; }

    /// <summary>Completed each time an unlock starts (a fresh one is made per call).</summary>
    public event Action<int>? UnlockStarted;

    public BrokerSecret Read(string secretName)
    {
        var n = Interlocked.Increment(ref _unlocks);
        UnlockStarted?.Invoke(n);
        Gate?.Task.GetAwaiter().GetResult();
        if (Fail)
            throw new BrokerUnlockException("simulated unlock failure");
        return new BrokerSecret(Encoding.UTF8.GetBytes(_values(secretName)));
    }
}

/// <summary>A forwarder for server tests: answers 200 "ok &lt;outbound&gt;" (or what <see cref="Respond"/> says), can block.</summary>
public sealed class FakeBrokerForwarder : IBrokerForwarder
{
    private int _calls;

    public int Calls => Volatile.Read(ref _calls);
    public List<Uri> Outbound { get; } = [];
    public TaskCompletionSource? Gate { get; set; }
    public event Action<int>? Entered;

    public async Task<BrokerForwardOutcome> ForwardAsync(HttpContext http, BrokerForwardRequest request, CancellationToken cancellationToken)
    {
        lock (Outbound)
            Outbound.Add(request.Outbound);
        var n = Interlocked.Increment(ref _calls);
        Entered?.Invoke(n);
        if (Gate != null)
            await Gate.Task.WaitAsync(cancellationToken);
        var body = Encoding.ASCII.GetBytes("ok " + request.Outbound.AbsoluteUri);
        http.Response.StatusCode = 200;
        http.Response.ContentLength = body.Length;
        await http.Response.Body.WriteAsync(body, cancellationToken);
        return new BrokerForwardOutcome(200, 0, body.Length);
    }
}

/// <summary>
/// A broker on real Unix sockets in a temp folder (mode 0700, this uid's), with a fake secret source
/// and (unless given) a fake forwarder.
/// </summary>
public sealed class BrokerHarness : IAsyncDisposable
{
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "tswap-bk-" + Guid.NewGuid().ToString("N")[..8]);
    public string SocketDir => Path.Combine(Root, "s");
    public StringWriter LogText { get; } = new();
    public BrokerManualClock Clock { get; } = new();
    public FakeBrokerSecrets Secrets { get; set; } = new();
    public FakeBrokerForwarder FakeForwarder { get; } = new();
    public BrokerServer? Server { get; private set; }
    public BrokerPolicyHolder? Holder { get; private set; }

    public static uint MyUid => new UnixOwnership().EffectiveUid;

    public BrokerHarness()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(SocketDir);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(SocketDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    /// <summary>A config with sockets <c>lane1</c> (this uid) and <c>other</c> (this uid) and the given routes.</summary>
    public string Config(string routesJson = DefaultRoutes, string? lane1Uids = null, string lane1Routes = "\"echo\"", string otherRoutes = "\"second\"") => $$"""
        {
          "version": 1,
          "socket_dir": {{System.Text.Json.JsonSerializer.Serialize(SocketDir)}},
          "sockets": [
            { "name": "lane1", "uids": [{{lane1Uids ?? $"\"{MyUid}\""}}], "routes": [{{lane1Routes}}] },
            { "name": "other", "uids": ["{{MyUid}}"], "routes": [{{otherRoutes}}] }
          ],
          "routes": [ {{routesJson}} ]
        }
        """;

    public const string DefaultRoutes = """
        { "name": "echo", "upstream": "https://upstream.example/base", "auth": { "type": "bearer", "secret": "{{tok}}" }, "path": "" },
        { "name": "second", "upstream": "https://second.example", "auth": { "type": "bearer", "secret": "{{tok2}}" }, "path": "" }
        """;

    public async Task<BrokerServer> StartAsync(string? configJson = null, IBrokerForwarder? forwarder = null,
        IUnixOwnership? ownership = null, BrokerLimits? limits = null)
    {
        Holder = new BrokerPolicyHolder(BrokerPolicy.Parse(configJson ?? Config()));
        Server = await BrokerServer.StartAsync(Options(forwarder, ownership, limits));
        return Server;
    }

    public BrokerServerOptions Options(IBrokerForwarder? forwarder = null, IUnixOwnership? ownership = null, BrokerLimits? limits = null) => new()
    {
        Policy = Holder!,
        Secrets = Secrets,
        Forwarder = forwarder ?? FakeForwarder,
        Log = new BrokerLog(LogText, null, Clock),
        Time = Clock,
        Ownership = ownership ?? new UnixOwnership(),
        Limits = limits ?? new BrokerLimits(),
    };

    public string SocketPath(string name) => BrokerServer.SocketPath(SocketDir, name);

    /// <summary>Sends raw bytes on a socket and reads until the broker closes the connection.</summary>
    public async Task<byte[]> SendRawAsync(string socketName, string request)
    {
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(SocketPath(socketName)));
        await client.SendAsync(Encoding.Latin1.GetBytes(request));
        var received = new MemoryStream();
        var buffer = new byte[8192];
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // a hang fails the test, it never passes it
        while (true)
        {
            int n;
            try
            {
                n = await client.ReceiveAsync(buffer, SocketFlags.None, guard.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                break;
            }
            if (n == 0)
                break;
            received.Write(buffer, 0, n);
        }
        return received.ToArray();
    }

    /// <summary>A GET with Connection: close; the whole response as text.</summary>
    public async Task<string> GetAsync(string socketName, string target, string extraHeaders = "", string method = "GET") =>
        Encoding.Latin1.GetString(await SendRawAsync(socketName, $"{method} {target} HTTP/1.1\r\nHost: broker\r\n{extraHeaders}Connection: close\r\n\r\n"));

    /// <summary>The body of an HTTP/1.1 response (de-chunked when chunked).</summary>
    public static string BodyOf(string response)
    {
        var split = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (split < 0)
            return "";
        var head = response[..split];
        var body = response[(split + 4)..];
        if (!head.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
            return body;
        var sb = new StringBuilder();
        var pos = 0;
        while (true)
        {
            var eol = body.IndexOf("\r\n", pos, StringComparison.Ordinal);
            var size = Convert.ToInt32(body[pos..eol].Split(';')[0], 16);
            if (size == 0)
                return sb.ToString();
            sb.Append(body, eol + 2, size);
            pos = eol + 2 + size + 2;
        }
    }

    public static int StatusOf(string response) =>
        response.StartsWith("HTTP/1.1 ", StringComparison.Ordinal) ? int.Parse(response.AsSpan(9, 3)) : -1;

    public async ValueTask DisposeAsync()
    {
        if (Server != null)
            await Server.DisposeAsync();
        if (Directory.Exists(Root))
            Directory.Delete(Root, true);
    }
}
