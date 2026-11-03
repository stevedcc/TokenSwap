using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore.Broker;

namespace TswapCore.Agent;

/// <summary>Everything <see cref="AgentServer"/> needs (brief T17 task 10).</summary>
/// <param name="SocketPath">The socket path (on Windows, the pipe name), from <see cref="AgentSocketPath.For"/>.</param>
/// <param name="VaultId">The vault whose password is held; requests for another vault never touch the hardware.</param>
/// <param name="UnlockVault">Runs the hardware unlock with the held password and returns <c>K_v</c>, which the server zeroes after sending.</param>
/// <param name="ExpiresAt">The absolute deadline (ruling 11), or null for none.</param>
/// <param name="Time">The clock of the deadline and of every timeout.</param>
/// <param name="OwnUid">The agent's own uid: the socket folder's owner and, with root, the only peer accepted.</param>
/// <param name="MaxConnections">Open connections at most; one beyond is closed at accept (ruling 8).</param>
public sealed record AgentServerOptions(string SocketPath, byte[] VaultId, Func<byte[]> UnlockVault, DateTimeOffset? ExpiresAt,
    TimeProvider Time, uint OwnUid, int MaxConnections = 16)
{
    /// <summary>The euid seam (root refusal) and owner lookups for the folder checks.</summary>
    public IUnixOwnership Ownership { get; init; } = new UnixOwnership();

    /// <summary>What the agent holds (the stretched password): disposed, so zeroed, the moment the agent stops.</summary>
    public IDisposable? Held { get; init; }

    /// <summary>Lines for the agent's log (refused peers, the <c>/proc</c> notice).</summary>
    public Action<string> Log { get; init; } = static _ => { };

    /// <summary>The vault user's name for the root refusal; looked up from <see cref="OwnUid"/> when null.</summary>
    public string? VaultUserName { get; init; }

    /// <summary>How long a client may take to send its request (ruling 8).</summary>
    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Connect and answer deadlines of the probe of an existing socket (ruling 21).</summary>
    public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromSeconds(2);
}

/// <summary>
/// The agent's server (brief T17 rulings 6, 7, 8, 11, 20 and 21).
/// <list type="bullet">
/// <item><b>Start:</b> refuses root before creating anything; creates and checks the socket folder;
/// takes <c>agent-&lt;16 hex&gt;.lock</c>'s <c>flock</c> beside the socket and holds it for its lifetime;
/// then, under the lock, binds, after removing a stale socket of this uid whose probe is refused.</item>
/// <item><b>Peers:</b> <see cref="PeerIdentity.Check"/> with <see cref="PeerPolicy.Agent"/>: its own uid
/// and root, user namespace and SELinux label (Linux). A refusal closes the connection unanswered and
/// is counted (<see cref="RefusedPeers"/>).</item>
/// <item><b>Requests:</b> one per connection, read within 5 s; unlocks one at a time, while
/// <c>status</c> and <c>stop</c> bypass that gate; at most 16 connections.</item>
/// <item><b>Stopping</b> (<c>stop</c>, the deadline, or disposal) zeroes <see cref="AgentServerOptions.Held"/>
/// at once however busy the agent is: unlocks in flight or waiting answer <see cref="AgentStatus.Expired"/>.</item>
/// </list>
/// </summary>
public sealed partial class AgentServer : IAsyncDisposable
{
    /// <summary>Test seam: sees each response frame after it was sent and zeroed.</summary>
    internal static Action<ReadOnlySpan<byte>>? AfterSendObserver;

    /// <summary>Test seam: an unlock request is about to wait for the unlock gate.</summary>
    internal static Action? UnlockQueuedObserver;

    /// <summary>Test seam: a connection's read deadline is set and its request is being read.</summary>
    internal static Action? ReadStartedObserver;

    private readonly AgentServerOptions _options;
    private readonly Socket? _listener;
    private readonly FileStream? _lock;
    private readonly string? _pipeName;
    private readonly CancellationTokenSource _stopping = new();
    private readonly TaskCompletionSource _stopSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _unlockGate = new(1, 1);
    private readonly SemaphoreSlim _connectionSlots;
    private ITimer? _expiry;
    private int _open;
    private int _refused;
    private int _stopState;

    private AgentServer(AgentServerOptions options, Socket? listener, FileStream? lockFile, string? pipeName)
    {
        _options = options;
        _listener = listener;
        _lock = lockFile;
        _pipeName = pipeName;
        _connectionSlots = new SemaphoreSlim(options.MaxConnections, options.MaxConnections);
    }

    /// <summary>The socket path (on Windows, the pipe name) this agent listens on.</summary>
    public string SocketPath => _options.SocketPath;

    /// <summary>Completes once the agent has stopped: the held password zeroed, the socket removed, the lock released.</summary>
    public Task Stopped => _stopped.Task;

    /// <summary>Peers refused by the checks so far (ruling 20; <c>agent status</c> reports it).</summary>
    public int RefusedPeers => Volatile.Read(ref _refused);

    /// <summary>The root refusal of ruling 21.</summary>
    public static string RootRefusal(string vaultUserName) =>
        $"Don't run the agent as root: run 'tswap agent start' as the vault user ({vaultUserName}), without sudo.";

    public static string AlreadyRunning(string socketPath) => $"An agent for this vault is already running ({socketPath}).";

    /// <summary>
    /// Starts the agent. Throws <see cref="TswapException"/> (exit 1) when it may not: as root, a bad
    /// socket folder, the lock or the socket held by a running agent, or something at the path that
    /// isn't a stale socket of this uid.
    /// </summary>
    public static async Task<AgentServer> StartAsync(AgentServerOptions options)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaxConnections, 1);
        if (options.VaultId.Length != AgentProtocol.VaultIdSize)
            throw new ArgumentException($"A vault id is {AgentProtocol.VaultIdSize} bytes", nameof(options));
        if (OperatingSystem.IsWindows())
            return StartPipe(options);

        // Ruling 21: before anything is created.
        if (options.Ownership.IsPrivileged)
            throw new TswapException(RootRefusal(options.VaultUserName ?? BrokerNative.NameOf(options.OwnUid) ?? $"uid {options.OwnUid}"));
        var path = Path.GetFullPath(options.SocketPath);
        AgentSocketPath.CheckLength(path);
        var folder = Path.GetDirectoryName(path) ?? throw new TswapException($"{path} has no folder.");
        AgentSocketPath.EnsureFolder(folder, options.OwnUid, options.Ownership);

        var lockFile = UnixLockFile.TryTake(Path.ChangeExtension(path, ".lock"), out _)
            ?? throw new TswapException(AlreadyRunning(path));
        Socket? listener = null;
        try
        {
            await ClearPathAsync(path, options).ConfigureAwait(false);
            listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(path));
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            listener.Listen(options.MaxConnections);
            var server = new AgentServer(options with { SocketPath = path }, listener, lockFile, pipeName: null);
            server.Begin();
            return server;
        }
        catch
        {
            listener?.Dispose();
            lockFile.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Ruling 21, under the lock: nothing at the path, bind; a stale socket of this uid (its probe is
    /// refused), remove it; anything else, refuse without touching it.
    /// </summary>
    private static async Task ClearPathAsync(string path, AgentServerOptions options)
    {
        var stat = BrokerNative.LStat(path) ?? throw new TswapException($"Can't read {path}.");
        if (stat.Type == BrokerNative.EntryType.Missing)
            return;
        if (stat.Type != BrokerNative.EntryType.Socket || options.Ownership.GetOwner(path)?.Uid != options.OwnUid)
            throw new TswapException($"{path} exists and is not a stale socket of this user; remove it by hand.");

        using var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        using (var connectDeadline = new CancellationTokenSource(options.ProbeTimeout, options.Time))
        {
            try
            {
                await probe.ConnectAsync(new UnixDomainSocketEndPoint(path), connectDeadline.Token).ConfigureAwait(false);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionRefused or SocketError.AddressNotAvailable)
            {
                File.Delete(path); // stale: nothing listens
                return;
            }
            catch (OperationCanceledException)
            {
                throw new TswapException(InUse(path));
            }
        }
        using var answerDeadline = new CancellationTokenSource(options.ProbeTimeout, options.Time);
        try
        {
            await using var stream = new NetworkStream(probe, ownsSocket: false);
            await stream.WriteAsync(AgentProtocol.EncodeRequest((byte)AgentOp.Status, options.VaultId), answerDeadline.Token)
                .ConfigureAwait(false);
            var first = new byte[1];
            if (await stream.ReadAsync(first, answerDeadline.Token).ConfigureAwait(false) > 0)
                throw new TswapException(AlreadyRunning(path));
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
        {
            // No answer in time, or closed unanswered.
        }
        throw new TswapException(InUse(path));
    }

    private static string InUse(string path) =>
        $"{path} is in use by a process that doesn't answer; stop it, or remove the socket by hand.";

    private void Begin()
    {
        if (OperatingSystem.IsLinux() && !PeerIdentity.ProcMounted())
            _options.Log(PeerIdentity.NoProcAgentMessage);
        _ = Task.Run(_pipeName is null ? AcceptSocketsAsync : AcceptPipesAsync);
        if (_options.ExpiresAt is { } deadline)
        {
            var due = deadline - _options.Time.GetUtcNow();
            if (due <= TimeSpan.Zero)
                BeginStop();
            else
                _expiry = _options.Time.CreateTimer(_ => BeginStop(), null, due, Timeout.InfiniteTimeSpan);
        }
    }

    // ------------------------------------------------------------------ Unix sockets

    private async Task AcceptSocketsAsync()
    {
        while (!_stopping.IsCancellationRequested)
        {
            Socket accepted;
            try
            {
                accepted = await _listener!.AcceptAsync(_stopping.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                if (_stopping.IsCancellationRequested)
                    return;
                continue;
            }
            if (Interlocked.Increment(ref _open) > _options.MaxConnections)
            {
                Interlocked.Decrement(ref _open);
                accepted.Dispose(); // closed at accept, like the broker's MaxConnections
                continue;
            }
            _ = Task.Run(() => HandleSocketAsync(accepted));
        }
    }

    private async Task HandleSocketAsync(Socket socket)
    {
        try
        {
            var verdict = PeerIdentity.Check(socket, PeerPolicy.Agent(_options.OwnUid));
            if (!verdict.Allowed)
            {
                Interlocked.Increment(ref _refused);
                _options.Log($"refused a peer: {verdict.Reason} (pid {verdict.Pid})");
                return; // closed unanswered; nothing read, no hardware touched
            }
            await using var stream = new NetworkStream(socket, ownsSocket: false);
            await ServeAsync(stream).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // The client went away.
        }
        finally
        {
            socket.Dispose();
            Interlocked.Decrement(ref _open);
        }
    }

    // ------------------------------------------------------------------ Windows named pipes

    private static AgentServer StartPipe(AgentServerOptions options)
    {
        NamedPipeServerStream first;
        try
        {
            first = NewPipe(options.SocketPath, options.MaxConnections, firstInstance: true);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            throw new TswapException(AlreadyRunning(options.SocketPath));
        }
        var server = new AgentServer(options, listener: null, lockFile: null, pipeName: options.SocketPath) { _firstPipe = first };
        server.Begin();
        return server;
    }

    private NamedPipeServerStream? _firstPipe;
    private NamedPipeServerStream? _waitingPipe;

    private static NamedPipeServerStream NewPipe(string name, int maxInstances, bool firstInstance) =>
        new(name, PipeDirection.InOut, maxInstances, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None));

    private async Task AcceptPipesAsync()
    {
        var next = _firstPipe;
        while (!_stopping.IsCancellationRequested)
        {
            try
            {
                await _connectionSlots.WaitAsync(_stopping.Token).ConfigureAwait(false);
                var pipe = next ?? NewPipe(_pipeName!, _options.MaxConnections, firstInstance: false);
                next = null;
                _waitingPipe = pipe;
                await pipe.WaitForConnectionAsync(_stopping.Token).ConfigureAwait(false);
                _waitingPipe = null;
                _ = Task.Run(() => HandlePipeAsync(pipe));
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or IOException)
            {
                if (_stopping.IsCancellationRequested)
                    return;
                _connectionSlots.Release();
            }
        }
    }

    private async Task HandlePipeAsync(NamedPipeServerStream pipe)
    {
        try
        {
            // CurrentUserOnly: only this user's processes can open the pipe; the client checks this server's SID.
            await ServeAsync(pipe).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
        }
        finally
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            _connectionSlots.Release();
        }
    }

    // ------------------------------------------------------------------ one request

    private async Task ServeAsync(Stream stream)
    {
        byte[] body;
        using (var timeout = new CancellationTokenSource(_options.ReadTimeout, _options.Time))
        using (var read = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, _stopping.Token))
        {
            ReadStartedObserver?.Invoke();
            try
            {
                var prefix = new byte[AgentProtocol.LengthPrefixSize];
                if (await stream.ReadAtLeastAsync(prefix, prefix.Length, throwOnEndOfStream: false, read.Token).ConfigureAwait(false)
                    < prefix.Length)
                    return;
                int length;
                try
                {
                    length = AgentProtocol.DecodeLength(prefix);
                }
                catch (AgentProtocolException)
                {
                    await SendAsync(stream, AgentStatus.Malformed, []).ConfigureAwait(false); // over 4096: refused unread
                    return;
                }
                body = new byte[length];
                if (await stream.ReadAtLeastAsync(body, length, throwOnEndOfStream: false, read.Token).ConfigureAwait(false) < length)
                    return;
            }
            catch (OperationCanceledException)
            {
                return; // too slow (5 s), or stopping: closed unanswered
            }
        }

        AgentRequest request;
        try
        {
            request = AgentProtocol.DecodeRequest(body);
        }
        catch (AgentProtocolException)
        {
            await SendAsync(stream, AgentStatus.Malformed, []).ConfigureAwait(false);
            return;
        }
        if (!CryptographicOperations.FixedTimeEquals(request.VaultId, _options.VaultId))
        {
            await SendAsync(stream, AgentStatus.OtherVault, []).ConfigureAwait(false); // never touches the hardware
            return;
        }
        switch ((AgentOp)request.Op)
        {
            case AgentOp.Status:
                await SendAsync(stream, AgentStatus.Ok,
                    AgentProtocol.EncodeStatusPayload(_options.ExpiresAt, (uint)RefusedPeers)).ConfigureAwait(false);
                break;
            case AgentOp.Stop:
                await SendAsync(stream, AgentStatus.Ok, []).ConfigureAwait(false);
                BeginStop();
                break;
            case AgentOp.Unlock:
                await UnlockAsync(stream).ConfigureAwait(false);
                break;
            default:
                await SendAsync(stream, AgentStatus.Malformed, []).ConfigureAwait(false);
                break;
        }
    }

    private async Task UnlockAsync(Stream stream)
    {
        UnlockQueuedObserver?.Invoke();
        try
        {
            await _unlockGate.WaitAsync(_stopping.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await SendAsync(stream, AgentStatus.Expired, []).ConfigureAwait(false); // stopped while it waited
            return;
        }
        try
        {
            if (_stopping.IsCancellationRequested)
            {
                await SendAsync(stream, AgentStatus.Expired, []).ConfigureAwait(false);
                return;
            }
            var work = Task.Run(_options.UnlockVault);
            if (await Task.WhenAny(work, _stopSignal.Task).ConfigureAwait(false) != work)
            {
                // The deadline (or stop) came first: answer now; zero the key if the unlock still returns one.
                _ = work.ContinueWith(static t =>
                {
                    if (t.IsCompletedSuccessfully)
                        CryptographicOperations.ZeroMemory(t.Result);
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                await SendAsync(stream, AgentStatus.Expired, []).ConfigureAwait(false);
                return;
            }
            byte[] key;
            try
            {
                key = await work.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await SendAsync(stream, AgentStatus.HardwareFailed, Encoding.UTF8.GetBytes(SafeMessage(ex))).ConfigureAwait(false);
                return;
            }
            try
            {
                if (_stopping.IsCancellationRequested)
                    await SendAsync(stream, AgentStatus.Expired, []).ConfigureAwait(false);
                else if (key.Length != AgentProtocol.VaultKeySize)
                    await SendAsync(stream, AgentStatus.HardwareFailed, "The agent's unlock returned no vault key."u8.ToArray())
                        .ConfigureAwait(false);
                else
                    await SendAsync(stream, AgentStatus.Ok, key).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
        finally
        {
            _unlockGate.Release();
        }
    }

    private static async Task SendAsync(Stream stream, AgentStatus status, byte[] payload)
    {
        var frame = AgentProtocol.EncodeResponse(status, payload);
        try
        {
            await stream.WriteAsync(frame).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // The client went away.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
            AfterSendObserver?.Invoke(frame);
        }
    }

    // A run this long of hex or base64 characters could be key material (32 bytes: 64 hex, 43 or 44
    // base64), never part of a fixed text, a path with dots, or a backend's error code.
    [GeneratedRegex("[A-Za-z0-9+/=_-]{40,}", RegexOptions.CultureInvariant)]
    private static partial Regex KeyLikeRun();

    /// <summary>
    /// The <see cref="AgentStatus.HardwareFailed"/> text (ruling 8): only a <see cref="TswapException"/>'s
    /// message (the fixed texts of rulings 3 and 18 and the backends' error texts), cut to printable
    /// ASCII, with any run that could be key material removed, and at most 512 bytes. Any other
    /// exception says only that the unlock failed.
    /// </summary>
    public static string SafeMessage(Exception ex)
    {
        var text = ex is TswapException ? ex.Message : "The agent's hardware unlock failed.";
        var printable = new StringBuilder(text.Length);
        foreach (var c in text)
            if (c is >= ' ' and <= '~')
                printable.Append(c);
        var safe = KeyLikeRun().Replace(printable.ToString(), "[removed]");
        if (safe.Length > AgentProtocol.MaxMessageBytes)
            safe = safe[..(AgentProtocol.MaxMessageBytes - 3)] + "...";
        return safe.Length == 0 ? "The agent's hardware unlock failed." : safe;
    }

    // ------------------------------------------------------------------ stopping

    private void BeginStop()
    {
        if (Interlocked.Exchange(ref _stopState, 1) != 0)
            return;
        // Zero first, whatever is in flight (ruling 11: however busy it is).
        try
        {
            _options.Held?.Dispose();
        }
        finally
        {
            _stopSignal.TrySetResult();
            _stopping.Cancel();
            _ = Task.Run(FinishStop);
        }
    }

    private void FinishStop()
    {
        try
        {
            _expiry?.Dispose();
            _listener?.Dispose();
            _waitingPipe?.Dispose();
            _firstPipe?.Dispose();
            if (_listener is not null)
            {
                try
                {
                    if (BrokerNative.LStat(SocketPath) is { Type: BrokerNative.EntryType.Socket })
                        File.Delete(SocketPath);
                }
                catch (IOException)
                {
                    // Replaced under the lock at the next start.
                }
            }
            _lock?.Dispose();
        }
        finally
        {
            _stopped.TrySetResult();
        }
    }

    /// <summary>Stops the agent (zeroing what it holds) and waits until it has stopped.</summary>
    public async Task StopAsync()
    {
        BeginStop();
        await _stopped.Task.ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
