using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;

namespace TswapTests;

/// <summary>
/// A broker with the ssh-agent endpoint (brief T10) on real Unix sockets in a temp folder: sockets
/// <c>lane1</c> (keys <c>k1</c>), <c>other</c> (key <c>k2</c>) and <c>plain</c> (no keys), and key
/// <c>k3</c> on no socket, unless the test passes its own config.
/// </summary>
public sealed class SshAgentHarness : IAsyncDisposable
{
    public BrokerHarness Broker { get; } = new();
    public BrokerServer? Server { get; private set; }
    public BrokerPolicyHolder? Holder { get; private set; }

    /// <summary>A fingerprint no test host key has.</summary>
    public const string SomeHostFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// <summary>A broker.json with the given ssh keys (name, secret, host fingerprints) and per-socket key lists.</summary>
    public string Config(
        IEnumerable<(string Name, string Secret, string[] Hosts)>? keys = null,
        string[]? lane1Keys = null, string[]? otherKeys = null, string? lane1Uids = null)
    {
        keys ??= [("k1", "key-one", [SomeHostFingerprint]), ("k2", "key-two", [SomeHostFingerprint]), ("k3", "key-three", [SomeHostFingerprint])];
        var keysJson = string.Join(",\n", keys.Select(k =>
            $$"""{ "name": "{{k.Name}}", "secret": "{{k.Secret}}", "allowed_host_keys": {{JsonSerializer.Serialize(k.Hosts)}} }"""));
        return $$"""
            {
              "version": 1,
              "socket_dir": {{JsonSerializer.Serialize(Broker.SocketDir)}},
              "sockets": [
                { "name": "lane1", "uids": [{{lane1Uids ?? $"\"{BrokerHarness.MyUid}\""}}], "routes": [], "ssh_keys": {{JsonSerializer.Serialize(lane1Keys ?? ["k1"])}} },
                { "name": "other", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "ssh_keys": {{JsonSerializer.Serialize(otherKeys ?? ["k2"])}} },
                { "name": "plain", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [] }
              ],
              "routes": [],
              "ssh_keys": [ {{keysJson}} ]
            }
            """;
    }

    /// <summary>Starts serve with the ssh-agent endpoint; <paramref name="agent"/> gets the policy and returns the agent options.</summary>
    /// <param name="allowOwnUid">
    /// The harness connects as its own uid, which both the HTTP and the agent sockets refuse; true (the
    /// default) sets the one test switch, <see cref="BrokerServerOptions.AllowOwnUidForTests"/>.
    /// </param>
    public async Task<BrokerServer> StartAsync(string configJson, Func<BrokerPolicy, SshAgentOptions> agent, BrokerLimits? limits = null,
        bool allowOwnUid = true)
    {
        var policy = BrokerPolicy.Parse(configJson);
        Holder = new BrokerPolicyHolder(policy);
        var options = Broker.Options(limits: limits) with { Policy = Holder, SshAgent = agent(policy), AllowOwnUidForTests = allowOwnUid };
        Server = await BrokerServer.StartAsync(options);
        return Server;
    }

    public string AgentSocket(string name) => SshAgentListener.SocketPath(Broker.SocketDir, name);

    public async Task<SshAgentTestClient> ConnectAsync(string socketName)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(AgentSocket(socketName)));
        return new SshAgentTestClient(socket);
    }

    public async ValueTask DisposeAsync()
    {
        if (Server != null)
            await Server.DisposeAsync();
        await Broker.DisposeAsync();
    }
}

/// <summary>A raw agent-protocol client: frames out, frames in, with a 30 s guard so a hang fails a test.</summary>
public sealed class SshAgentTestClient(Socket socket) : IDisposable
{
    public Socket Socket { get; } = socket;

    public async Task SendRawAsync(byte[] bytes) => await Socket.SendAsync(bytes);

    /// <summary>Sends <c>uint32 length ‖ body</c>.</summary>
    public async Task SendFrameAsync(byte[] body)
    {
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
        body.CopyTo(frame, 4);
        await SendRawAsync(frame);
    }

    /// <summary>The next reply's body, or null when the agent closed the connection first.</summary>
    public async Task<byte[]?> ReadFrameAsync()
    {
        var header = await ReadExactlyAsync(4);
        if (header is null)
            return null;
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length > SshAgentProtocol.MaxMessageLength)
            throw new InvalidOperationException($"reply length {length}");
        return await ReadExactlyAsync((int)length) ?? throw new InvalidOperationException("reply truncated");
    }

    public async Task<byte[]?> RequestAsync(byte[] body)
    {
        await SendFrameAsync(body);
        return await ReadFrameAsync();
    }

    /// <summary>True when the agent closes the connection without sending another byte.</summary>
    public async Task<bool> ClosedWithoutReplyAsync() => await ReadExactlyAsync(1) is null;

    private async Task<byte[]?> ReadExactlyAsync(int count)
    {
        var buffer = new byte[count];
        var read = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // a hang fails the test, it never passes it
        while (read < count)
        {
            int n;
            try
            {
                n = await Socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, guard.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                n = 0;
            }
            if (n == 0)
            {
                if (read == 0)
                    return null;
                throw new InvalidOperationException($"connection closed after {read} of {count} bytes");
            }
            read += n;
        }
        return buffer;
    }

    public void Dispose() => Socket.Dispose();
}

/// <summary>Builds agent messages and reads replies for tests.</summary>
public static class SshAgentMessages
{
    public static byte[] RequestIdentities => [SshAgentProtocol.RequestIdentities];

    /// <summary>The (blob, comment) pairs of an identities answer.</summary>
    public static List<(byte[] Blob, string Comment)> ParseIdentities(byte[] reply)
    {
        var reader = new SshReader(reply);
        if (reader.ReadByte() != SshAgentProtocol.IdentitiesAnswer)
            throw new InvalidOperationException($"not an identities answer: {Convert.ToHexString(reply)}");
        var count = reader.ReadUInt32();
        var list = new List<(byte[], string)>();
        for (var i = 0; i < count; i++)
            list.Add((reader.ReadString().ToArray(), System.Text.Encoding.UTF8.GetString(reader.ReadString())));
        reader.EnsureEnd();
        return list;
    }

    /// <summary>An <c>ssh-ed25519</c> public key blob with the given 32 bytes.</summary>
    public static byte[] Ed25519Blob(byte fill) => new SshWriter().String("ssh-ed25519").String(Enumerable.Repeat(fill, 32).ToArray()).ToArray();
}

/// <summary>
/// Early returns with a written reason (round 2, MiMo N4): a test that can't run here says why in its
/// output instead of passing silently.
/// </summary>
public static class SshTestSkip
{
    /// <summary>True on Windows, where the broker doesn't run (Unix sockets and peer credentials).</summary>
    public static bool OnWindows(Xunit.Abstractions.ITestOutputHelper output)
    {
        if (!OperatingSystem.IsWindows())
            return false;
        output.WriteLine("SKIPPED: the broker is Unix-only (Unix sockets and kernel peer credentials).");
        return true;
    }

    /// <summary>True when ssh-keygen or openssl (or Unix) is missing, so keys can't be generated here.</summary>
    public static bool WithoutKeyTools(Xunit.Abstractions.ITestOutputHelper output)
    {
        if (SshTestKeys.HaveTools)
            return false;
        output.WriteLine("SKIPPED: ssh-keygen or openssl is not installed (or this is Windows); the in-process key tests cover the parser.");
        return true;
    }

    /// <summary>True off Linux (the binary's serve tests use prctl and /proc).</summary>
    public static bool OffLinux(Xunit.Abstractions.ITestOutputHelper output)
    {
        if (OperatingSystem.IsLinux())
            return false;
        output.WriteLine("SKIPPED: the end-to-end serve test is Linux-only.");
        return true;
    }
}
