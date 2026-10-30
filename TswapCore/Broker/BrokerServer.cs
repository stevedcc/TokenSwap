using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace TswapCore.Broker;

/// <summary>Who is at the other end of a connection: the socket it arrived on and the kernel's peer credentials.</summary>
public sealed record BrokerPeer(string Socket, uint Uid, int Pid);

/// <summary>Everything <see cref="BrokerServer"/> needs; tests swap the clock, the secret source and the forwarder.</summary>
public sealed record BrokerServerOptions
{
    public required BrokerPolicyHolder Policy { get; init; }
    public required IBrokerSecretSource Secrets { get; init; }
    public required BrokerLog Log { get; init; }

    /// <summary>Forwards an allowed request upstream.</summary>
    public required IBrokerForwarder Forwarder { get; init; }

    public TimeProvider Time { get; init; } = TimeProvider.System;
    public BrokerLimits Limits { get; init; } = new();

    /// <summary>Owner lookups for the socket folder checks (tests fake another owner).</summary>
    public IUnixOwnership Ownership { get; init; } = new UnixOwnership();

    /// <summary>
    /// Test seam: accept a peer with the broker's own uid (brief T9 refuses it). The in-process
    /// tests connect as their own uid; the binary sets this only in a Debug build with
    /// <c>TSWAP_TEST_KEY</c> (never in Release).
    /// </summary>
    public bool AllowOwnUidForTests { get; init; }
}

/// <summary>
/// <c>tswap broker serve</c> (brief T8 decisions 1 to 3 and 7): Kestrel listening on one Unix socket
/// per configured client in <c>socket_dir</c>, HTTP/1.1 only, no TLS on the socket.
/// <list type="bullet">
/// <item>Refuses to start as root, when <c>socket_dir</c> is missing, a symlink, not owned by this
/// uid or group/world-writable, or when another <c>serve</c> holds the folder's <c>flock</c>.</item>
/// <item>Removes stale socket files only under that lock, and only sockets this uid owns.</item>
/// <item>Each connection's peer uid is read from the <b>accepted</b> socket
/// (<see cref="IConnectionSocketFeature"/>, then <c>SO_PEERCRED</c>/<c>getpeereid</c>); a uid not on
/// that socket's list, or unreadable credentials, closes the connection before anything is parsed,
/// unanswered, and is logged.</item>
/// </list>
/// </summary>
public sealed class BrokerServer : IAsyncDisposable
{
    public const string LockFileName = ".tswap-broker.lock";
    internal const string PeerItemKey = "tswap.broker.peer";
    internal const string SnifferItemKey = "tswap.broker.sniffer";

    private readonly BrokerServerOptions _options;
    private readonly FileStream _lock;
    private readonly WebApplication _app;
    private readonly IReadOnlyList<string> _socketPaths;
    private int _stopped;

    private BrokerServer(BrokerServerOptions options, FileStream lockFile, WebApplication app,
        IReadOnlyList<string> socketPaths)
    {
        _options = options;
        _lock = lockFile;
        _app = app;
        _socketPaths = socketPaths;
    }

    /// <summary>The socket file of <paramref name="socketName"/> in <paramref name="socketDir"/>.</summary>
    public static string SocketPath(string socketDir, string socketName) => Path.Combine(socketDir, socketName + ".sock");

    /// <summary>The request slots (tests watch its queue).</summary>
    internal BrokerLimiter Limiter { get; private init; } = null!;

    /// <summary>The request handler (tests watch its unlock queue).</summary>
    internal BrokerRequestHandler Handler { get; private init; } = null!;


    /// <summary>
    /// Completes (with the reason) when the broker can't go on, such as unlocks hanging
    /// <see cref="BrokerLimits.UnlockTimeoutsBeforeExit"/> times in a row: serve then exits non-zero
    /// so systemd restarts it.
    /// </summary>
    public Task<string> Fatal { get; private init; } = null!;

    /// <summary>Open connections per socket (tests watch it).</summary>
    internal BrokerConnectionCounter Connections { get; private init; } = null!;

    /// <summary>The socket files this server listens on.</summary>
    public IReadOnlyList<string> SocketPaths => _socketPaths;

    /// <summary>The Kestrel options in force (tests assert the limits).</summary>
    public KestrelServerOptions KestrelOptions =>
        _app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<KestrelServerOptions>>().Value;

    /// <summary>Validates, locks, cleans up and starts listening; throws <see cref="TswapException"/> when it may not start.</summary>
    public static async Task<BrokerServer> StartAsync(BrokerServerOptions options, CancellationToken cancellationToken = default)
    {
        if (OperatingSystem.IsWindows())
            throw new TswapException("'tswap broker serve' is not supported on Windows.");
        if (options.Ownership.IsPrivileged)
            throw new TswapException("'tswap broker serve' must run as the vault's own user, never as root (run it from the vault user's systemd user unit).");

        var policy = options.Policy.Current;
        if (policy.Sockets.Count == 0)
            throw new TswapException("broker.json defines no sockets; add one with 'sudo tswap broker socket add'.");
        var socketDir = CheckSocketDir(policy.SocketDir, options.Ownership);
        var lockFile = TakeLock(socketDir);
        WebApplication? app = null;
        try
        {
            var paths = new List<string>();
            foreach (var name in policy.Sockets.Keys.Order(StringComparer.Ordinal))
            {
                var path = SocketPath(socketDir, name);
                RemoveStaleSocket(path, options.Ownership);
                paths.Add(path);
            }

            var forwarder = options.Forwarder; // the caller owns and disposes it
            var limiter = new BrokerLimiter(options.Limits, options.Time);
            var connections = new BrokerConnectionCounter(options.Limits);
            var fatal = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var handler = new BrokerRequestHandler(options.Policy, options.Secrets, forwarder,
                limiter, new BrokerUnlockGuard(options.Limits, options.Time), options.Log, options.Time,
                options.Limits, reason => fatal.TrySetResult(reason));

            var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { ApplicationName = "tswap-broker" });
            builder.WebHost.UseKestrelCore();
            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                ConfigureLimits(kestrel);
                kestrel.Limits.MaxConcurrentConnections = options.Limits.MaxConnections;
                foreach (var name in policy.Sockets.Keys)
                {
                    var socketName = name;
                    kestrel.ListenUnixSocket(SocketPath(socketDir, socketName), listen =>
                    {
                        listen.Protocols = HttpProtocols.Http1;
                        listen.Use(next => connection => GateAsync(connection, socketName, next, options, connections));
                    });
                }
            });
            app = builder.Build();
            app.Run(handler.HandleAsync);
            await app.StartAsync(cancellationToken).ConfigureAwait(false);

            // A rootless container's uid is not this one, so the socket must be connectable by
            // anyone who can reach the file; the peer-uid check is the gate (decision 3).
            foreach (var path in paths)
                File.SetUnixFileMode(path, (UnixFileMode)0b110_110_110);

            options.Log.Event($"started: {paths.Count} socket(s) in {socketDir}");
            return new BrokerServer(options, lockFile, app, paths) { Limiter = limiter, Connections = connections, Handler = handler, Fatal = fatal.Task };
        }
        catch
        {
            if (app != null)
                await app.DisposeAsync().ConfigureAwait(false);
            lockFile.Dispose();
            throw;
        }
    }

    /// <summary>Decision 7's Kestrel limits.</summary>
    internal static void ConfigureLimits(KestrelServerOptions kestrel)
    {
        kestrel.AddServerHeader = false;
        kestrel.Limits.MaxRequestBodySize = null;                       // registry layers can be gigabytes
        kestrel.Limits.MinRequestBodyDataRate = new MinDataRate(16, TimeSpan.FromSeconds(60)); // relaxed for slow links
        kestrel.Limits.MinResponseDataRate = new MinDataRate(16, TimeSpan.FromSeconds(60));
        kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10); // no complete headers in 10 s: closed
    }

    /// <summary>
    /// Connection middleware, before any HTTP parsing: reads the peer credentials of the accepted
    /// socket and closes the connection (unanswered, logged) unless that uid may use this socket.
    /// </summary>
    private static async Task GateAsync(ConnectionContext connection, string socketName, ConnectionDelegate next,
        BrokerServerOptions options, BrokerConnectionCounter connections)
    {
        // Fix round 1: one client can't hold every connection (file descriptor) for all sockets.
        if (!connections.TryOpen(socketName))
        {
            options.Log.Connection(socketName, null, null, "too-many-connections");
            return; // closed, unanswered
        }
        try
        {
            var socket = connection.Features.Get<IConnectionSocketFeature>()?.Socket;
            var peer = socket is null ? null : BrokerNative.TryGetPeerCredentials(socket);
            if (peer is not { } creds)
            {
                options.Log.Connection(socketName, null, null, "no-peer-credentials");
                return; // returning without next closes the connection
            }
            // Brief T9: no client may share the broker's uid (the vault user's). A process with it
            // could read the broker's config and the vault directly, so the socket is not its way in,
            // and refusing it keeps a misconfigured container (rootless Podman run by the vault user)
            // from looking like a client.
            if (creds.Uid == options.Ownership.EffectiveUid && !options.AllowOwnUidForTests)
            {
                options.Log.Connection(socketName, creds.Uid, creds.Pid, "own-uid");
                return;
            }
            var policy = options.Policy.Current;
            if (!policy.Sockets.TryGetValue(socketName, out var allowed) || !allowed.AllowsUid(creds.Uid))
            {
                options.Log.Connection(socketName, creds.Uid, creds.Pid, allowed is null ? "socket-removed" : "uid-not-allowed");
                return;
            }
            connection.Items[PeerItemKey] = new BrokerPeer(socketName, creds.Uid, creds.Pid);
            // Kestrel hides the raw Connection header's tokens; read them from the bytes (decision 6).
            var sniffer = new BrokerHeaderSniffer(connection.Transport.Input);
            connection.Transport = new SniffedDuplexPipe(connection.Transport, sniffer);
            connection.Items[SnifferItemKey] = sniffer;
            await next(connection).ConfigureAwait(false);
        }
        finally
        {
            connections.Close(socketName);
        }
    }

    /// <summary>
    /// Decision 3: <c>socket_dir</c> must exist, not be a symlink, be owned by this uid and not be
    /// group- or world-writable; every folder above its real path must be root's or this uid's and
    /// not group- or world-writable (fix round 1). Returns the real path, which serve then uses.
    /// </summary>
    internal static string CheckSocketDir(string socketDir, IUnixOwnership ownership)
    {
        if (string.IsNullOrEmpty(socketDir))
            throw new TswapException("broker.json has no socket_dir.");
        var dir = Path.GetFullPath(socketDir);
        var stat = BrokerNative.LStat(dir)
            ?? throw new TswapException($"Can't read socket_dir {dir}.");
        switch (stat.Type)
        {
            case BrokerNative.EntryType.Missing:
                throw new TswapException($"socket_dir {dir} does not exist. Create it as the vault user: mkdir -m 0711 {dir}");
            case BrokerNative.EntryType.Symlink:
                throw new TswapException($"socket_dir {dir} is a symlink; use the real folder.");
            case not BrokerNative.EntryType.Directory:
                throw new TswapException($"socket_dir {dir} is not a folder.");
        }
        var owner = ownership.GetOwner(dir);
        if (owner is not { } o || o.Uid != ownership.EffectiveUid)
            throw new TswapException($"socket_dir {dir} is not owned by this user (uid {ownership.EffectiveUid}); it must be the vault user's own folder.");
        if ((stat.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new TswapException($"socket_dir {dir} is writable by group or others; make it 0711 (chmod 0711 {dir}).");

        // Fix round 1 (MiMo): resolve the whole path, then check every folder above it, so nobody
        // else can swap a parent (and so the folder) for one of their own.
        var real = BrokerNative.RealPath(dir)
            ?? throw new TswapException($"Can't resolve socket_dir {dir}.");
        for (var parent = Path.GetDirectoryName(real); parent != null; parent = Path.GetDirectoryName(parent))
            CheckParent(parent, ownership);
        return real;
    }

    /// <summary>
    /// A folder above socket_dir must be owned by root or this user and not writable by group or
    /// others, except a root-owned folder with the sticky bit (like /tmp): there others can't
    /// rename or remove what isn't theirs.
    /// </summary>
    private static void CheckParent(string parent, IUnixOwnership ownership)
    {
        var stat = BrokerNative.LStat(parent) ?? throw new TswapException($"Can't read {parent} (a folder above socket_dir).");
        var uid = ownership.GetOwner(parent)?.Uid;
        if (uid is null || (uid != 0 && uid != ownership.EffectiveUid))
            throw new TswapException($"{parent} (a folder above socket_dir) is owned by uid {uid?.ToString() ?? "?"}; every folder above it must be root's or the vault user's.");
        var writable = (stat.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0;
        var rootSticky = uid == 0 && (stat.Mode & UnixFileMode.StickyBit) != 0;
        if (writable && !rootSticky)
            throw new TswapException($"{parent} (a folder above socket_dir) is writable by group or others; every folder above socket_dir must not be (a root-owned sticky folder such as /tmp is allowed).");
    }

    /// <summary>One <c>serve</c> per socket folder: an exclusive <c>flock</c> on its lock file, held until stop.</summary>
    private static FileStream TakeLock(string socketDir)
    {
        var path = Path.Combine(socketDir, LockFileName);
        if (BrokerNative.LStat(path) is { Type: not (BrokerNative.EntryType.Missing or BrokerNative.EntryType.Regular) })
            throw new TswapException($"{path} is not a regular file; remove it.");
        FileStream stream;
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.ReadWrite,
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            stream = new FileStream(path, options);
        }
        catch (IOException ex) when (ex.HResult == BrokerNative.WouldBlockErrno)
        {
            throw new TswapException($"Another 'tswap broker serve' is running on {socketDir}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException($"Can't open the lock file {path}: {ex.Message}");
        }
        if (!BrokerNative.TryLockExclusive(stream.SafeFileHandle, out var heldElsewhere, out var errno))
        {
            stream.Dispose();
            throw heldElsewhere
                ? new TswapException($"Another 'tswap broker serve' is running on {socketDir}.")
                : new TswapException($"Can't lock {path} (flock errno {errno}).");
        }
        // Like broker.log: owner-only, whatever an earlier file had.
        try
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(stream.SafeFileHandle, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            stream.Dispose(); // and so the flock: a failed start never keeps the lock
            throw;
        }
        return stream;
    }

    /// <summary>Under the lock: removes a leftover socket file this uid owns; anything else at the path stops the start.</summary>
    private static void RemoveStaleSocket(string path, IUnixOwnership ownership)
    {
        var stat = BrokerNative.LStat(path) ?? throw new TswapException($"Can't read {path}.");
        if (stat.Type == BrokerNative.EntryType.Missing)
            return;
        if (stat.Type != BrokerNative.EntryType.Socket || ownership.GetOwner(path)?.Uid != ownership.EffectiveUid)
            throw new TswapException($"{path} exists and is not a stale socket of this user; remove it by hand.");
        File.Delete(path);
    }

    /// <summary>Re-reads the config with <paramref name="load"/> (SIGHUP): a valid file is swapped in, an invalid one keeps the current config.</summary>
    public bool Reload(Func<BrokerPolicy> load)
    {
        var ok = _options.Policy.TryReload(load, _options.Log.Event);
        if (ok)
        {
            var current = _options.Policy.Current;
            foreach (var path in _socketPaths)
            {
                var name = Path.GetFileNameWithoutExtension(path);
                if (!current.Sockets.ContainsKey(name))
                    _options.Log.Event($"socket '{name}' is no longer in broker.json: its connections are refused until restart");
            }
            foreach (var name in current.Sockets.Keys.Where(n => _socketPaths.All(p => Path.GetFileNameWithoutExtension(p) != n)))
                _options.Log.Event($"socket '{name}' is new in broker.json: restart serve to listen on it");
        }
        return ok;
    }

    /// <summary>Stops listening, removes the socket files and releases the lock.</summary>
    public async Task StopAsync()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0)
            return;
        try
        {
            await _app.StopAsync().ConfigureAwait(false);
            await _app.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            foreach (var path in _socketPaths)
            {
                try
                {
                    if (BrokerNative.LStat(path) is { Type: BrokerNative.EntryType.Socket })
                        File.Delete(path);
                }
                catch (IOException)
                {
                    // Removed under the lock at the next start.
                }
            }
            _options.Log.Event("stopped");
            _lock.Dispose();
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
