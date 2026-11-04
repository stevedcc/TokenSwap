using System.Net.Sockets;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;

namespace TswapTests;

/// <summary>
/// Brief T17 task 10: an agent server in a temp folder with a scripted <c>UnlockVault</c>, a manual
/// clock, and raw clients that send frames without <see cref="AgentClient"/>'s own peer checks (so a
/// test can fake the server's view of a peer without the client refusing first).
/// </summary>
internal sealed class AgentHarness : IAsyncDisposable
{
    private readonly List<AgentServer> _servers = [];

    public AgentHarness()
    {
        Root = Directory.CreateTempSubdirectory("tswap-agent-");
        VaultId = RandomNumberGenerator.GetBytes(16);
        Key = RandomNumberGenerator.GetBytes(32);
    }

    public DirectoryInfo Root { get; }
    public byte[] VaultId { get; }
    public byte[] Key { get; }
    public BrokerManualClock Clock { get; } = new();
    public List<string> Log { get; } = [];
    public int UnlockCalls;

    /// <summary>The key arrays handed to the server, to check that it zeroed them.</summary>
    public List<byte[]> HandedOut { get; } = [];

    /// <summary>What <c>UnlockVault</c> does; the default counts and returns a copy of <see cref="Key"/>.</summary>
    public Func<byte[]>? Unlock { get; set; }

    public static uint MyUid => new UnixOwnership().EffectiveUid;

    public string Folder => Path.Combine(Root.FullName, "run");

    /// <summary>The socket path (on Windows, the pipe name: the real one plus a random suffix, so tests never meet a real agent).</summary>
    public string SocketPath => _socketPath ??= OperatingSystem.IsWindows()
        ? WindowsPipeIdentity.PipeName(WindowsPipeIdentity.CurrentUserSid()!, VaultId) + "-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4))
        : Path.Combine(Folder, AgentSocketPath.SocketName(VaultId));

    private string? _socketPath;

    public AgentServerOptions Options(DateTimeOffset? expiresAt = null, IUnixOwnership? ownership = null) =>
        new(SocketPath, VaultId, UnlockVault, expiresAt, Clock, MyUid)
        {
            Ownership = ownership ?? new UnixOwnership(),
            Log = line => { lock (Log) Log.Add(line); },
        };

    private byte[] UnlockVault()
    {
        Interlocked.Increment(ref UnlockCalls);
        if (Unlock is { } unlock)
            return unlock();
        var copy = Key.ToArray();
        lock (HandedOut)
            HandedOut.Add(copy);
        return copy;
    }

    public async Task<AgentServer> StartAsync(AgentServerOptions? options = null)
    {
        var server = await AgentServer.StartAsync(options ?? Options());
        _servers.Add(server);
        return server;
    }

    public string LogText
    {
        get
        {
            lock (Log)
                return string.Join('\n', Log);
        }
    }

    /// <summary>Sends <paramref name="frame"/> on a new connection; the response body, or null when closed unanswered.</summary>
    public static async Task<AgentResponse?> RawAsync(string path, byte[] frame)
    {
        using var socket = await ConnectAsync(path);
        return await SendOnAsync(socket, frame);
    }

    public static async Task<Socket> ConnectAsync(string path)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path));
        return socket;
    }

    /// <summary>
    /// Sends <paramref name="frame"/> and reads one response; null when the server closed the
    /// connection unanswered. Linux resets (<c>ECONNRESET</c>) a Unix socket whose peer closed with
    /// bytes unread, which is how a refused request that was already sent ends, so a reset is a close too.
    /// macOS fails the send with <c>ENOTCONN</c> when the server closed the accepted connection before the
    /// client wrote (CI run 41841651506, SeventeenthConnection_ClosedAtAccept): after a successful connect
    /// that is the same close.
    /// </summary>
    public static async Task<AgentResponse?> SendOnAsync(Socket socket, byte[] frame)
    {
        var stream = new NetworkStream(socket, ownsSocket: false);
        var prefix = new byte[4];
        try
        {
            await socket.SendAsync(frame);
            if (await stream.ReadAtLeastAsync(prefix, 4, throwOnEndOfStream: false) < 4)
                return null;
        }
        catch (Exception ex) when (ex is IOException or SocketException { SocketErrorCode: SocketError.ConnectionReset or SocketError.Shutdown or SocketError.NotConnected })
        {
            return null;
        }
        var body = new byte[AgentProtocol.DecodeLength(prefix)];
        await stream.ReadExactlyAsync(body);
        return AgentProtocol.DecodeResponse(body);
    }

    public Task<AgentResponse?> RawAsync(AgentOp op, byte[]? vaultId = null) =>
        RawAsync(SocketPath, AgentProtocol.EncodeRequest((byte)op, vaultId ?? VaultId));

    public async ValueTask DisposeAsync()
    {
        foreach (var server in _servers)
            await server.DisposeAsync();
        PeerIdentity.ResetSeamsForTests();
        AgentServer.AfterSendObserver = null;
        AgentServer.UnlockQueuedObserver = null;
        AgentServer.ReadStartedObserver = null;
        AgentClient.ResetSeamsForTests();
        // Review T17 p5 MiMo M4: a Windows test that fails before restoring this seam must not poison the next.
        WindowsPipeIdentity.ReadServerSid = WindowsPipeIdentity.DefaultReadServerSid;
        if (!OperatingSystem.IsWindows())
            foreach (var dir in Directory.EnumerateDirectories(Root.FullName, "*", SearchOption.AllDirectories)
                         .Where(d => BrokerNative.LStat(d) is { Type: BrokerNative.EntryType.Directory }))
                File.SetUnixFileMode(dir, (UnixFileMode)0b111_000_000);
        Root.Delete(recursive: true);
    }
}

/// <summary>Real ownership, except <see cref="IsPrivileged"/> (the euid seam of ruling 21).</summary>
internal sealed class AgentOwnership(bool privileged) : IUnixOwnership
{
    private readonly UnixOwnership _real = new();
    public bool IsPrivileged => privileged;
    public uint EffectiveUid => privileged ? 0 : _real.EffectiveUid;
    public (uint Uid, uint Gid)? GetOwner(string path) => _real.GetOwner(path);
    public IDisposable ActAs(uint uid, uint gid, string path) => throw new InvalidOperationException("no switch expected");
}
