using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Agent;
using TswapCore.VaultPassword;

namespace TswapCore.Broker;

/// <summary>The control socket's ops (brief T17 ruling 14), after the agent's 1 to 3.</summary>
public enum BrokerControlOp : byte
{
    /// <summary>Payload: the 32 stretched bytes, optionally followed by <c>expiresUnixSeconds 8 LE</c>.</summary>
    Unlock = 16,
    Lock = 17,
    Status = 18,
}

/// <summary>The control socket's payloads (ruling 14); the framing is the agent's (<see cref="AgentProtocol"/>).</summary>
public static class BrokerControlProtocol
{
    public const int PasswordPayloadSize = StretchedPassword.Size;
    public const int PasswordWithExpirySize = StretchedPassword.Size + 8;
    public const int StatusPayloadSize = 1 + 8 + 4;

    /// <summary><c>unlocked 1 | expiresUnixSeconds 8 LE (0 = none) | refusedPeers 4 LE</c>.</summary>
    public static byte[] EncodeStatus(bool unlocked, DateTimeOffset? expiresAt, uint refusedPeers)
    {
        var payload = new byte[StatusPayloadSize];
        payload[0] = unlocked ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(1), expiresAt?.ToUnixTimeSeconds() ?? 0);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(9), refusedPeers);
        return payload;
    }

    public static (bool Unlocked, DateTimeOffset? ExpiresAt, uint RefusedPeers) DecodeStatus(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != StatusPayloadSize || payload[0] > 1)
            throw new AgentProtocolException("Broker status: a malformed payload.");
        var seconds = BinaryPrimitives.ReadInt64LittleEndian(payload[1..]);
        if (seconds < 0 || seconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
            throw new AgentProtocolException("Broker status: an expiry out of range.");
        return (payload[0] == 1, seconds == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(seconds),
            BinaryPrimitives.ReadUInt32LittleEndian(payload[9..]));
    }
}

/// <summary>Everything <see cref="BrokerControlServer"/> needs (brief T17 task 12).</summary>
/// <param name="SocketPath"><c>&lt;agent socket folder&gt;/broker-&lt;16 hex&gt;/control.sock</c> (<see cref="AgentSocketPath.BrokerControlFor"/>).</param>
/// <param name="VaultId">This vault's id; a request for another vault is answered <see cref="AgentStatus.OtherVault"/>.</param>
/// <param name="OwnUid">The broker's (the vault user's) uid: the only peer accepted, and the folder's owner.</param>
/// <param name="State">What the broker holds.</param>
/// <param name="Prove">One real unlock with the candidate (<see cref="BrokerPasswordProof.Prove"/>): returns <c>K_v</c>, which the server zeroes.</param>
/// <param name="Guard">The broker's unlock-failure limits; wrong passwords count under <see cref="BrokerControlServer.GuardKey"/>.</param>
/// <param name="Time">The clock of the timeouts.</param>
public sealed record BrokerControlOptions(string SocketPath, byte[] VaultId, uint OwnUid, BrokerPasswordState State,
    Func<StretchedPassword, byte[]> Prove, BrokerUnlockGuard Guard, TimeProvider Time)
{
    /// <summary>The euid seam (root refusal) and owner lookups for the folder checks.</summary>
    public IUnixOwnership Ownership { get; init; } = new UnixOwnership();

    public Action<string> Log { get; init; } = static _ => { };

    /// <summary>The deferred ssh-key load (ruling 14), run once after a proof; throws <see cref="SshAgent.SshKeyLoadException"/>.</summary>
    public Action? LoadSshKeys { get; init; }

    public int MaxConnections { get; init; } = 16;

    /// <summary>How long a client may take to send a request's header, and later its payload.</summary>
    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(5);
}

/// <summary>
/// A password broker's control socket (brief T17 ruling 14): <c>broker unlock</c> (op 16), <c>broker
/// lock</c> (17) and <c>broker status</c> (18), with the agent's framing.
/// <list type="bullet">
/// <item><b>Start:</b> refuses root before creating anything; creates the folder 0700 (ruling 6's
/// checks); holds <c>control.lock</c>'s <c>flock</c> for its lifetime and, under it, replaces a stale
/// socket of this uid; the socket is 0600.</item>
/// <item><b>Peers:</b> the broker's own uid only, never root, plus ruling 20's user-namespace and
/// SELinux-label checks (<see cref="PeerPolicy.BrokerControl"/>). A refusal closes the connection unanswered.</item>
/// <item><b>Unlocks</b> run one at a time, end to end. On its turn a request is refused before its
/// payload is read when the broker is already unlocked, a return to locked caught it, or the guard
/// refuses; otherwise the process becomes non-dumpable and only then are the 32 bytes read.</item>
/// <item><b>lock</b> and <b>status</b> bypass that gate.</item>
/// </list>
/// </summary>
public sealed class BrokerControlServer : IAsyncDisposable
{
    /// <summary>The <see cref="BrokerUnlockGuard"/> key the control socket's proofs are counted under.</summary>
    public const string GuardKey = "control";

    public const string TooManyFailuresText =
        "Too many wrong vault passwords for this broker; wait a few minutes and try again.";

    public const string ExpiryPassedText = "That timeout has already passed.";

    /// <summary>Test seam: a request's payload (the stretched password) was read.</summary>
    internal static Action? PayloadReadObserver;

    /// <summary>Test seam: an unlock request is about to wait for the unlock gate.</summary>
    internal static Action? UnlockQueuedObserver;

    /// <summary>Test seam: a proof's candidate is now held; the answer has not been sent yet.</summary>
    internal static Action? ProofHeldObserver;

    internal static void ResetSeamsForTests()
    {
        PayloadReadObserver = null;
        UnlockQueuedObserver = null;
        ProofHeldObserver = null;
    }

    private readonly BrokerControlOptions _options;
    private readonly Socket _listener;
    private readonly FileStream _lock;
    private readonly CancellationTokenSource _stopping = new();
    private readonly SemaphoreSlim _unlockGate = new(1, 1);
    private int _open;
    private int _refused;
    private int _stopped;

    private BrokerControlServer(BrokerControlOptions options, Socket listener, FileStream lockFile)
    {
        _options = options;
        _listener = listener;
        _lock = lockFile;
    }

    public string SocketPath => _options.SocketPath;

    /// <summary>Peers refused by the checks so far.</summary>
    public int RefusedPeers => Volatile.Read(ref _refused);

    public static string AlreadyRunning(string socketPath) =>
        $"Another 'tswap broker serve' is running for this vault ({socketPath}).";

    public static async Task<BrokerControlServer> StartAsync(BrokerControlOptions options)
    {
        if (OperatingSystem.IsWindows())
            throw new TswapException("'tswap broker serve' is not supported on Windows.");
        if (options.VaultId.Length != AgentProtocol.VaultIdSize)
            throw new ArgumentException($"A vault id is {AgentProtocol.VaultIdSize} bytes", nameof(options));
        // Before anything is created (ruling 6), with serve's own words.
        if (options.Ownership.IsPrivileged)
            throw new TswapException("'tswap broker serve' must run as the vault's own user, never as root (run it from the vault user's systemd user unit).");

        var path = Path.GetFullPath(options.SocketPath);
        AgentSocketPath.CheckControlLength(path);
        var folder = Path.GetDirectoryName(path) ?? throw new TswapException($"{path} has no folder.");
        AgentSocketPath.EnsureFolder(folder, options.OwnUid, options.Ownership);

        var lockFile = UnixLockFile.TryTake(Path.ChangeExtension(path, ".lock"), out _)
            ?? throw new TswapException(AlreadyRunning(path));
        Socket? listener = null;
        try
        {
            RemoveStaleSocket(path, options);
            listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(path));
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            listener.Listen(options.MaxConnections);
            var server = new BrokerControlServer(options with { SocketPath = path }, listener, lockFile);
            server.Begin();
            await Task.CompletedTask.ConfigureAwait(false);
            return server;
        }
        catch
        {
            listener?.Dispose();
            lockFile.Dispose();
            throw;
        }
    }

    /// <summary>Under the lock (ruling 14): a leftover socket of this uid is removed; anything else at the path stops the start.</summary>
    private static void RemoveStaleSocket(string path, BrokerControlOptions options)
    {
        var stat = BrokerNative.LStat(path) ?? throw new TswapException($"Can't read {path}.");
        if (stat.Type == BrokerNative.EntryType.Missing)
            return;
        if (stat.Type != BrokerNative.EntryType.Socket || options.Ownership.GetOwner(path)?.Uid != options.OwnUid)
            throw new TswapException($"{path} exists and is not a stale socket of this user; remove it by hand.");
        File.Delete(path);
    }

    private void Begin()
    {
        if (OperatingSystem.IsLinux() && !PeerIdentity.ProcMounted())
            _options.Log(PeerIdentity.NoProcControlMessage);
        _ = Task.Run(AcceptAsync);
    }

    private async Task AcceptAsync()
    {
        while (!_stopping.IsCancellationRequested)
        {
            Socket accepted;
            try
            {
                accepted = await _listener.AcceptAsync(_stopping.Token).ConfigureAwait(false);
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
                accepted.Dispose();
                continue;
            }
            _ = Task.Run(() => HandleAsync(accepted));
        }
    }

    private async Task HandleAsync(Socket socket)
    {
        try
        {
            var verdict = PeerIdentity.Check(socket, PeerPolicy.BrokerControl(_options.OwnUid));
            if (!verdict.Allowed)
            {
                Interlocked.Increment(ref _refused);
                _options.Log($"control: refused a peer: {verdict.Reason} (pid {verdict.Pid})");
                return; // closed unanswered; nothing read
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

    // ------------------------------------------------------------------ one request

    private async Task ServeAsync(Stream stream)
    {
        int length;
        AgentRequest request;
        using (var timeout = new CancellationTokenSource(_options.ReadTimeout, _options.Time))
        using (var read = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, _stopping.Token))
        {
            try
            {
                var prefix = new byte[AgentProtocol.LengthPrefixSize];
                if (await stream.ReadAtLeastAsync(prefix, prefix.Length, throwOnEndOfStream: false, read.Token).ConfigureAwait(false)
                    < prefix.Length)
                    return;
                try
                {
                    length = AgentProtocol.DecodeLength(prefix);
                    if (length < AgentProtocol.RequestHeaderSize)
                        throw new AgentProtocolException("short");
                }
                catch (AgentProtocolException)
                {
                    await SendAsync(stream, AgentStatus.Malformed).ConfigureAwait(false);
                    return;
                }
                // The header only: an unlock's payload stays in the kernel until the request's turn.
                var header = new byte[AgentProtocol.RequestHeaderSize];
                if (await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, read.Token).ConfigureAwait(false)
                    < header.Length)
                    return;
                try
                {
                    request = AgentProtocol.DecodeRequestHeader(header);
                }
                catch (AgentProtocolException)
                {
                    await SendAsync(stream, AgentStatus.Malformed).ConfigureAwait(false);
                    return;
                }
            }
            catch (OperationCanceledException)
            {
                return; // too slow, or stopping: closed unanswered
            }
        }

        if (!CryptographicOperations.FixedTimeEquals(request.VaultId, _options.VaultId))
        {
            await SendAsync(stream, AgentStatus.OtherVault).ConfigureAwait(false);
            return;
        }
        var payloadLength = length - AgentProtocol.RequestHeaderSize;
        switch ((BrokerControlOp)request.Op)
        {
            case BrokerControlOp.Status when payloadLength == 0:
                var state = _options.State;
                await SendAsync(stream, AgentStatus.Ok,
                    BrokerControlProtocol.EncodeStatus(!state.IsLocked, state.ExpiresAt, (uint)RefusedPeers)).ConfigureAwait(false);
                break;
            case BrokerControlOp.Lock when payloadLength == 0:
                await _options.State.ReturnToLockedAsync("broker lock").ConfigureAwait(false);
                await SendAsync(stream, AgentStatus.Ok).ConfigureAwait(false);
                break;
            case BrokerControlOp.Unlock when payloadLength is BrokerControlProtocol.PasswordPayloadSize or BrokerControlProtocol.PasswordWithExpirySize:
                await UnlockAsync(stream, payloadLength).ConfigureAwait(false);
                break;
            default:
                await SendAsync(stream, AgentStatus.Malformed).ConfigureAwait(false);
                break;
        }
    }

    private async Task UnlockAsync(Stream stream, int payloadLength)
    {
        var state = _options.State;
        var arrived = state.Generation;
        UnlockQueuedObserver?.Invoke();
        try
        {
            await _unlockGate.WaitAsync(_stopping.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        try
        {
            // Refusals before the payload is read: it stays in the kernel's socket buffer.
            if (_options.Guard.Refusal(GuardKey) is not null)
            {
                await RefuseAsync(stream, TooManyFailuresText).ConfigureAwait(false);
                return;
            }
            if (state.BeginProof(arrived) is { } refusal)
            {
                await RefuseAsync(stream, refusal).ConfigureAwait(false);
                return;
            }

            // Non-dumpable now: read the stretched password.
            var payload = new byte[payloadLength];
            StretchedPassword? candidate = null;
            DateTimeOffset? expiresAt = null;
            try
            {
                using (var timeout = new CancellationTokenSource(_options.ReadTimeout, _options.Time))
                using (var read = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, _stopping.Token))
                {
                    var got = await stream.ReadAtLeastAsync(payload, payload.Length, throwOnEndOfStream: false, read.Token).ConfigureAwait(false);
                    PayloadReadObserver?.Invoke();
                    if (got < payload.Length)
                    {
                        state.FailProof(null);
                        return;
                    }
                }
                candidate = StretchedPassword.FromBytes(payload.AsSpan(0, StretchedPassword.Size));
                if (payloadLength == BrokerControlProtocol.PasswordWithExpirySize)
                {
                    var seconds = BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(StretchedPassword.Size));
                    if (seconds != 0)
                        expiresAt = seconds < 0 || seconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds()
                            ? DateTimeOffset.MinValue
                            : DateTimeOffset.FromUnixTimeSeconds(seconds);
                }
            }
            catch (OperationCanceledException)
            {
                state.FailProof(candidate);
                return;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
            if (expiresAt is { } e && e <= _options.Time.GetUtcNow())
            {
                state.FailProof(candidate);
                await RefuseAsync(stream, ExpiryPassedText).ConfigureAwait(false);
                return;
            }

            _options.Guard.RecordAttempt(GuardKey);
            byte[]? key = null;
            try
            {
                key = await Task.Run(() => _options.Prove(candidate)).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A missing or conflicting vault-password file is a broken configuration, not a guess:
                // like a broken ssh key, it must not trip the brute-force guard.
                if (ex is not VaultPasswordUnavailableException && _options.Guard.RecordFailure(GuardKey))
                    _options.Log("control: locked out after repeated wrong vault passwords");
                state.FailProof(candidate);
                _options.Log("control: unlock refused (the proof failed)");
                await RefuseAsync(stream, AgentServer.SafeMessage(ex)).ConfigureAwait(false);
                return;
            }
            finally
            {
                // The proof's K_v is never kept: zeroed before the candidate is held or discarded.
                if (key is not null)
                {
                    CryptographicOperations.ZeroMemory(key);
                    BrokerPasswordState.KeyZeroedObserver?.Invoke(key);
                }
            }
            _options.Guard.RecordSuccess(GuardKey);
            if (!state.CompleteProof(candidate, expiresAt, arrived))
            {
                await RefuseAsync(stream, BrokerPasswordState.LockedWhileUnlockingText).ConfigureAwait(false);
                return;
            }
            ProofHeldObserver?.Invoke();

            // Ruling 14: the ssh keys load now, under a lease, so a return to locked waits for them.
            if (_options.LoadSshKeys is { } load)
            {
                string? keyFailure = null;
                using (var lease = state.TryEnter())
                {
                    if (lease is null)
                    {
                        await RefuseAsync(stream, BrokerPasswordState.LockedWhileUnlockingText).ConfigureAwait(false);
                        return;
                    }
                    try
                    {
                        load();
                    }
                    catch (SshAgent.SshKeyLoadException ex)
                    {
                        keyFailure = $"ssh key '{ex.KeyName}' can't be loaded: {ex.Reason}";
                    }
                    catch (Exception ex) when (ex is TswapException or BrokerUnlockException or BrokerSecretException)
                    {
                        keyFailure = $"the ssh keys can't be loaded: {ex.Message}";
                    }
                }
                if (keyFailure is not null)
                {
                    // Not counted by the guard: the password was right; a broken key must not trip it.
                    await state.ReturnToLockedAsync("an ssh key can't be loaded").ConfigureAwait(false);
                    _options.Log($"control: {keyFailure}; locked again");
                    await RefuseAsync(stream, AgentServer.SafeMessage(new TswapException(keyFailure))).ConfigureAwait(false);
                    return;
                }
            }
            // A return to locked since the proof (broker lock, the timeout) caught this unlock, with or
            // without ssh keys to load: ruling 12's answer, never "Ok" for a broker that holds nothing.
            if (state.Generation != arrived || state.IsLocked)
            {
                await RefuseAsync(stream, BrokerPasswordState.LockedWhileUnlockingText).ConfigureAwait(false);
                return;
            }
            _options.Log(state.ExpiresAt is { } until
                ? $"unlocked until {until.UtcDateTime:yyyy-MM-dd HH:mm:ss}Z"
                : "unlocked (no timeout)");
            await SendAsync(stream, AgentStatus.Ok).ConfigureAwait(false);
        }
        finally
        {
            _unlockGate.Release();
        }
    }

    private static Task RefuseAsync(Stream stream, string message) =>
        SendAsync(stream, AgentStatus.HardwareFailed, Encoding.UTF8.GetBytes(message));

    private static async Task SendAsync(Stream stream, AgentStatus status, byte[]? payload = null)
    {
        var frame = AgentProtocol.EncodeResponse(status, payload ?? []);
        try
        {
            await stream.WriteAsync(frame).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // The client went away.
        }
    }

    // ------------------------------------------------------------------ stopping

    /// <summary>Stops listening, removes the socket and releases the lock. (The state is serve's to dispose.)</summary>
    public Task StopAsync()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0)
            return Task.CompletedTask;
        _stopping.Cancel();
        _listener.Dispose();
        try
        {
            if (BrokerNative.LStat(SocketPath) is { Type: BrokerNative.EntryType.Socket })
                File.Delete(SocketPath);
        }
        catch (IOException)
        {
            // Replaced under the lock at the next start.
        }
        _lock.Dispose();
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
