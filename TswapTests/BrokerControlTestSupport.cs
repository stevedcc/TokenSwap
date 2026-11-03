using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 12: a password broker's control socket in a temp folder, with a scripted proof
/// (the right password is <see cref="Right"/>), fake hardening steps, a manual clock, and one ordered
/// event list that every observer of ruling 12 writes to (<c>dumpable:True|False</c>,
/// <c>payload-read</c>, <c>free</c>, <c>key-zeroed</c>, <c>ssh-unloaded</c>, <c>deny-attach</c>,
/// <c>core-limit</c>, <c>drain-wait</c>), so a test can check their order.
/// </summary>
internal sealed class ControlHarness : IAsyncDisposable
{
    private readonly List<string> _events = [];
    private readonly List<string> _log = [];
    private int _queued;
    private readonly List<(int Count, TaskCompletionSource Done)> _queueWaiters = [];

    public ControlHarness(byte[]? vaultId = null)
    {
        // macOS's per-user temp folder is long: <root>/run/broker-<16 hex>/control.sock would pass the
        // 103-byte socket limit there (as under any long TMPDIR), so on Unix the root goes under /tmp instead.
        Root = !OperatingSystem.IsWindows()
            ? Directory.CreateDirectory(Path.Combine("/tmp", "tswap-ctl-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4))),
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute)
            : Directory.CreateTempSubdirectory("tswap-ctl-");
        VaultId = vaultId ?? RandomNumberGenerator.GetBytes(16);
        Guard = new BrokerUnlockGuard(new BrokerLimits(), Clock);
        BrokerPasswordState.DumpableObserver = d => Add($"dumpable:{d}");
        BrokerPasswordState.SshKeysUnloadedObserver = () => Add("ssh-unloaded");
        BrokerPasswordState.DenyAttachObserver = () => Add("deny-attach");
        BrokerPasswordState.KeyZeroedObserver = k => Add(k.ContainsAnyExcept((byte)0) ? "key-NOT-zeroed" : "key-zeroed");
        BrokerPasswordState.DrainWaitObserver = () => Add("drain-wait");
        BrokerControlServer.PayloadReadObserver = () => Add("payload-read");
        BrokerControlServer.UnlockQueuedObserver = () =>
        {
            lock (_queueWaiters)
            {
                _queued++;
                foreach (var w in _queueWaiters.Where(w => w.Count <= _queued).ToList())
                {
                    w.Done.TrySetResult();
                    _queueWaiters.Remove(w);
                }
            }
        };
        // The harness's own client copy (UnlockAsync) is logged apart: it is freed when the client returns, which
        // can race the server's return to dumpable (a lock waiting on this unlock), and it isn't the broker's.
        StretchedPassword.BeforeFreeObserver = span => Add(
            ClientFlow.Value ? "client-free" : span.ContainsAnyExcept((byte)0) ? "free-NOT-zeroed" : "free");
    }

    /// <summary>True in the flow of <see cref="UnlockAsync"/>'s client call (an AsyncLocal: the broker's own tasks don't see it).</summary>
    private static readonly AsyncLocal<bool> ClientFlow = new();

    public DirectoryInfo Root { get; }
    public byte[] VaultId { get; }
    public BrokerManualClock Clock { get; } = new();
    public BrokerUnlockGuard Guard { get; set; }
    public BrokerPasswordState State { get; private set; } = null!;
    public BrokerControlServer? Server { get; private set; }

    /// <summary>The stretched bytes the scripted proof accepts.</summary>
    public byte[] Right { get; } = RandomNumberGenerator.GetBytes(32);

    public int ProveCalls;

    /// <summary>When set, the proof waits for it (after taking its clone of the candidate, as the unlocker does).</summary>
    public TaskCompletionSource? ProveGate { get; set; }

    /// <summary>Completed when a proof has taken its clone and is about to wait on <see cref="ProveGate"/>.</summary>
    public TaskCompletionSource ProveEntered { get; private set; } = NewSignal();

    /// <summary>The deferred ssh-key load (null: none configured).</summary>
    public Action? LoadSshKeys { get; set; }

    public List<string> FatalReasons { get; } = [];

    /// <summary>When set, the fake <c>PR_SET_DUMPABLE 1</c> fails (0 still works).</summary>
    public bool DumpableOneFails { get; set; }

    public static uint MyUid => new UnixOwnership().EffectiveUid;

    public string RunDir => Path.Combine(Root.FullName, "run");

    public string SocketPath => Path.Combine(RunDir, $"broker-{AgentSocketPath.Prefix(VaultId)}", "control.sock");

    public static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Add(string e)
    {
        lock (_events)
            _events.Add(e);
    }

    public List<string> Events
    {
        get
        {
            lock (_events)
                return [.. _events];
        }
    }

    public int Mark => Events.Count;

    public List<string> EventsSince(int mark) => Events.Skip(mark).ToList();

    public string LogText
    {
        get
        {
            lock (_log)
                return string.Join('\n', _log);
        }
    }

    public BrokerHardening Hardening(ProcessHardening.Platform platform = ProcessHardening.Platform.Linux, bool dumpableWorks = true) => new(
        d =>
        {
            Add($"set-dumpable:{d}");
            return dumpableWorks && !(d && DumpableOneFails);
        },
        () =>
        {
            Add("deny-attach-native");
            return true;
        },
        () =>
        {
            Add("core-limit");
            return true;
        },
        platform);

    /// <summary>A locked state with fake hardening (never the test process's own prctl).</summary>
    public BrokerPasswordState NewState(ProcessHardening.Platform platform = ProcessHardening.Platform.Linux) =>
        State = new BrokerPasswordState(Hardening(platform), Clock, Log, reason =>
        {
            lock (FatalReasons)
                FatalReasons.Add(reason);
        });

    private void Log(string line)
    {
        lock (_log)
            _log.Add(line);
    }

    public BrokerControlOptions Options(IUnixOwnership? ownership = null, Func<StretchedPassword, byte[]>? prove = null) =>
        new(SocketPath, VaultId, MyUid, State, prove ?? Prove, Guard, Clock)
        {
            Ownership = ownership ?? new UnixOwnership(),
            Log = Log,
            LoadSshKeys = LoadSshKeys is null ? null : () => LoadSshKeys!(),
        };

    public async Task<BrokerControlServer> StartAsync(ProcessHardening.Platform platform = ProcessHardening.Platform.Linux,
        IUnixOwnership? ownership = null, Func<StretchedPassword, byte[]>? prove = null)
    {
        if (State is null)
            NewState(platform);
        Server = await BrokerControlServer.StartAsync(Options(ownership, prove));
        return Server;
    }

    /// <summary>The scripted proof: clones the candidate (as the unlocker's provider does), compares it with <see cref="Right"/>.</summary>
    public byte[] Prove(StretchedPassword candidate)
    {
        Interlocked.Increment(ref ProveCalls);
        using var clone = candidate.Clone();
        if (ProveGate is { } gate)
        {
            ProveEntered.TrySetResult();
            gate.Task.GetAwaiter().GetResult();
        }
        Span<byte> bytes = stackalloc byte[StretchedPassword.Size];
        clone.CopyTo(bytes);
        var right = CryptographicOperations.FixedTimeEquals(bytes, Right);
        CryptographicOperations.ZeroMemory(bytes);
        if (!right)
            throw new VaultPasswordRefusedException(VaultPasswordMessages.WrongPasswordTpm, VaultPasswordRefusal.WrongPassword);
        return RandomNumberGenerator.GetBytes(32);
    }

    public void ResetProveEntered() => ProveEntered = NewSignal();

    /// <summary>Completes once <paramref name="count"/> unlock requests in total have queued for the unlock gate.</summary>
    public Task QueuedAsync(int count)
    {
        var done = NewSignal();
        lock (_queueWaiters)
        {
            if (_queued >= count)
                return Task.CompletedTask;
            _queueWaiters.Add((count, done));
        }
        return done.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    public StretchedPassword Password(bool right = true) =>
        StretchedPassword.FromBytes(right ? Right : RandomNumberGenerator.GetBytes(32));

    /// <summary>The client's unlock, off the test thread (the client is synchronous).</summary>
    public Task<BrokerControlAnswer> UnlockAsync(bool right = true, DateTimeOffset? expiresAt = null) => Task.Run(() =>
    {
        ClientFlow.Value = true;
        using var password = Password(right);
        return BrokerControlClient.Unlock(SocketPath, VaultId, MyUid, password, expiresAt);
    });

    public Task<BrokerControlAnswer> LockAsync() => Task.Run(() => BrokerControlClient.Lock(SocketPath, VaultId, MyUid));

    public Task<BrokerControlAnswer> StatusAsync() => Task.Run(() => BrokerControlClient.Status(SocketPath, VaultId, MyUid));

    /// <summary>A raw op-16 frame with <paramref name="payload"/> (the client's own checks skipped).</summary>
    public byte[] UnlockFrame(byte[] payload) => AgentProtocol.EncodeRequest((byte)BrokerControlOp.Unlock, VaultId, payload);

    public byte[] Frame(BrokerControlOp op) => AgentProtocol.EncodeRequest((byte)op, VaultId);

    public byte[] HeldBytes()
    {
        using var held = State.CloneHeld();
        var bytes = new byte[StretchedPassword.Size];
        held.CopyTo(bytes);
        return bytes;
    }

    public static string Refusal(BrokerControlAnswer answer) => Assert.IsType<BrokerControlAnswer.Refused>(answer).Message;

    public async ValueTask DisposeAsync()
    {
        if (Server is not null)
            await Server.DisposeAsync();
        State?.Dispose();
        BrokerPasswordState.ResetSeamsForTests();
        BrokerControlServer.ResetSeamsForTests();
        BrokerControlClient.ResetSeamsForTests();
        PeerIdentity.ResetSeamsForTests();
        StretchedPassword.BeforeFreeObserver = null;
        if (!OperatingSystem.IsWindows())
            foreach (var dir in Directory.EnumerateDirectories(Root.FullName, "*", SearchOption.AllDirectories)
                         .Where(d => BrokerNative.LStat(d) is { Type: BrokerNative.EntryType.Directory }))
                File.SetUnixFileMode(dir, (UnixFileMode)0b111_000_000);
        Root.Delete(recursive: true);
    }
}

/// <summary>
/// A stand-in for the broker's control socket that is not a broker: it records every byte a client
/// sends and answers one canned frame (or nothing), so a test can show a client refused it before sending.
/// </summary>
internal sealed class FakeControlServer : IDisposable
{
    private readonly Socket _listener;
    private readonly MemoryStream _received = new();

    public FakeControlServer(string path, byte[]? answer)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        Path_ = path;
        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(path));
        _listener.Listen(4);
        Served = Task.Run(() => ServeAsync(answer));
    }

    public string Path_ { get; }

    /// <summary>Completes when the first bytes of a request have arrived.</summary>
    public Task FirstBytes => _firstBytes.Task;

    private readonly TaskCompletionSource _firstBytes = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes when the one client has gone.</summary>
    public Task Served { get; }

    public byte[] Received
    {
        get
        {
            lock (_received)
                return _received.ToArray();
        }
    }

    private async Task ServeAsync(byte[]? answer)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var client = await _listener.AcceptAsync(guard.Token);
        var buffer = new byte[4096];
        var answered = false;
        while (true)
        {
            int n;
            try
            {
                n = await client.ReceiveAsync(buffer, SocketFlags.None, guard.Token);
            }
            catch (SocketException)
            {
                return;
            }
            if (n == 0)
                return;
            lock (_received)
                _received.Write(buffer, 0, n);
            _firstBytes.TrySetResult();
            if (answer is not null && !answered)
            {
                answered = true;
                await client.SendAsync(answer);
            }
        }
    }

    public void Dispose() => _listener.Dispose();

    /// <summary>A framed answer: <c>"TSAG" | 1 | status | payloadLength | payload</c>.</summary>
    public static byte[] Answer(AgentStatus status, byte[]? payload = null) => AgentProtocol.EncodeResponse(status, payload ?? []);

    public static string Text(byte[] bytes) => Encoding.ASCII.GetString(bytes);
}
