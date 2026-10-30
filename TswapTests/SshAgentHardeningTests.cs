using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;

namespace TswapTests;

/// <summary>
/// T10 fix round 1 (GLM and MiMo reviews): the unlock-failure lockout shared by a client's HTTP and
/// agent sockets, agent sockets removed by a reload, load-time caps and duplicates, and the
/// openssh-key-v1 / RSA parameter hardening.
/// </summary>
public class SshAgentHardeningTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private readonly SshAgentHarness _h = new();
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;
    private static readonly TestHostKey X = TestHostKey.NewEd25519();
    private static readonly byte[] KeyA = SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32));
    private static readonly byte[] BlobA = SshTestKeyMaker.PublicBlob(KeyA);

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    // ------------------------------------------------------------------ GLM 1: the shared lockout

    private const string TokRef = "{{tok}}";

    /// <summary>Socket lane1 with HTTP route <c>echo</c> and ssh key <c>a</c> (host X).</summary>
    private string SharedConfig() => $$"""
        {
          "version": 1,
          "socket_dir": {{JsonSerializer.Serialize(_h.Broker.SocketDir)}},
          "sockets": [ { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": ["echo"], "ssh_keys": ["a"] } ],
          "routes": [ { "name": "echo", "upstream": "https://upstream.example/base", "auth": { "type": "bearer", "secret": "{{TokRef}}" }, "path": "" } ],
          "ssh_keys": [ { "name": "a", "secret": "sa", "allowed_host_keys": ["{{X.Fingerprint}}"] } ]
        }
        """;

    private async Task<FakeSshKeySource> StartSharedAsync()
    {
        var source = new FakeSshKeySource(_ => (byte[])KeyA.Clone());
        await _h.StartAsync(SharedConfig(), p => new SshAgentOptions
        {
            Keys = SshAgentKeyLoader.Load(p, source),
            KeySource = source,
        });
        return source;
    }

    private async Task<(SshAgentTestClient Client, byte[] Request)> BoundSignRequestAsync()
    {
        var client = await _h.ConnectAsync("lane1");
        var sid = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(new[] { SshAgentProtocol.Success }, await client.RequestAsync(SshBindMessages.Bind(X.Blob, sid, X.Sign(sid))));
        return (client, SshBindMessages.SignRequest(BlobA, SshBindMessages.Userauth(sid, "ssh-ed25519", BlobA)));
    }

    [Fact]
    public async Task UnlockFailuresOnTheHttpSocket_LockOutTheAgentSocketOfTheSameClient()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var source = await StartSharedAsync();
        var loads = source.Reads;
        _h.Broker.Secrets.Fail = true;
        for (var i = 0; i < 3; i++)
            Assert.Equal(502, BrokerHarness.StatusOf(await _h.Broker.GetAsync("lane1", "/echo/x")));
        Assert.Equal(3, _h.Broker.Secrets.Unlocks);

        var (client, request) = await BoundSignRequestAsync();
        using var _ = client;

        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(request));
        Assert.Equal(0, source.Reads - loads); // refused before any unlock
        await _h.Broker.WaitForLogAsync("reason=locked-out");
    }

    [Fact]
    public async Task UnlockFailuresOnTheAgentSocket_LockOutTheHttpSocketOfTheSameClient()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var source = await StartSharedAsync();
        var loads = source.Reads;
        var (client, request) = await BoundSignRequestAsync();
        using var _ = client;
        source.FailUnlock = true;
        for (var i = 0; i < 3; i++)
            Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(request));
        Assert.Equal(3, source.Reads - loads);

        var response = await _h.Broker.GetAsync("lane1", "/echo/x");

        Assert.Equal(503, BrokerHarness.StatusOf(response));
        Assert.Equal(0, _h.Broker.Secrets.Unlocks);
        Assert.Contains("route=echo method=GET path=\"x\" status=503", _h.Broker.LogText.ToString());
        Assert.Contains("reason=locked-out", _h.Broker.LogText.ToString());
    }

    // ------------------------------------------------------------------ MiMo M1 / GLM 3: reload

    private static SshAgentOptions Agent(BrokerPolicy p) => new()
    {
        Keys = new Dictionary<string, SshAgentKey>
        {
            ["k1"] = new("k1", "key-one", SshAgentMessages.Ed25519Blob(1)),
            ["k2"] = new("k2", "key-two", SshAgentMessages.Ed25519Blob(2)),
            ["k3"] = new("k3", "key-three", SshAgentMessages.Ed25519Blob(3)),
        },
        KeySource = new FakeSshKeySource(_ => null),
    };

    [Fact]
    public async Task AReloadThatRemovesTheClientSocket_RemovesItsAgentSocket()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var server = await _h.StartAsync(_h.Config(), Agent);
        var without = _h.Config().Replace(
            $$"""{ "name": "other", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "ssh_keys": ["k2"] },""", "");
        Assert.DoesNotContain("\"other\"", without);

        Assert.True(server.Reload(() => BrokerPolicy.Parse(without)));

        Assert.False(File.Exists(_h.AgentSocket("other")));
        Assert.True(File.Exists(_h.AgentSocket("lane1")));
        Assert.Contains("agent socket 'other.ssh' removed", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task AReloadThatRemovesASocketsLastKey_RemovesItsAgentSocket()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var server = await _h.StartAsync(_h.Config(), Agent);

        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(lane1Keys: []))));

        Assert.False(File.Exists(_h.AgentSocket("lane1")));
        Assert.True(File.Exists(_h.AgentSocket("other")));
        Assert.True(File.Exists(BrokerServer.SocketPath(_h.Broker.SocketDir, "lane1"))); // the HTTP socket stays

        // A later reload that lists a key again can't bring the socket back: that needs a restart.
        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config())));
        Assert.False(File.Exists(_h.AgentSocket("lane1")));
        Assert.Contains("restart serve", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task AReloadAfterTheAgentSocketFileWentMissing_SaysSo_InsteadOfRemoved()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var server = await _h.StartAsync(_h.Config(), Agent);
        File.Delete(_h.AgentSocket("lane1"));

        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(lane1Keys: []))));

        Assert.Contains("agent socket 'lane1.ssh' was already gone", _h.Broker.LogText.ToString());
        Assert.DoesNotContain("agent socket 'lane1.ssh' removed", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task TheRestartNeededNotice_IsLoggedOnce_NotOnEveryReload()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var server = await _h.StartAsync(_h.Config(), Agent);
        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(lane1Keys: []))));

        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config())));
        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config())));

        var notices = _h.Broker.LogText.ToString().Split('\n').Count(l => l.Contains("agent socket 'lane1.ssh' has ssh keys again"));
        Assert.Equal(1, notices);
    }

    [Fact]
    public async Task AReloadListingMoreThan64Keys_IsWarnedOnce_AndOffersTheFirst64ByName()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var names = Enumerable.Range(0, 65).Select(i => $"k{i:D2}").ToList();
        var keys = names.Select((n, i) => (n, $"s{i}", new[] { SshAgentHarness.SomeHostFingerprint })).ToList();
        var loaded = names.Select((n, i) => new SshAgentKey(n, $"s{i}", SshAgentMessages.Ed25519Blob((byte)i))).ToDictionary(k => k.Name);
        var options = (BrokerPolicy _) => new SshAgentOptions { Keys = loaded, KeySource = new FakeSshKeySource(_ => null) };
        var server = await _h.StartAsync(_h.Config(keys: keys, lane1Keys: ["k00"], otherKeys: ["k01"]), options);

        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(keys: keys, lane1Keys: [.. names], otherKeys: ["k01"]))));
        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(keys: keys, lane1Keys: [.. names], otherKeys: ["k01"]))));

        using var client = await _h.ConnectAsync("lane1");
        var ids = SshAgentMessages.ParseIdentities((await client.RequestAsync(SshAgentMessages.RequestIdentities))!);
        Assert.Equal(names.Take(64), ids.Select(i => i.Comment));
        Assert.Equal(1, _h.Broker.LogText.ToString().Split('\n').Count(l => l.Contains("socket 'lane1' lists 65 ssh keys after the reload")));
    }

    [Fact]
    public async Task AKeyNamedTwiceOnOneSocket_IsOneIdentity()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        // T9's config model keeps a socket's ssh_keys as a set, so a name listed twice can't be listed
        // or matched twice (MiMo N3): nothing for the agent to refuse.
        await _h.StartAsync(_h.Config(lane1Keys: ["k1", "k1"]), Agent);
        using var client = await _h.ConnectAsync("lane1");

        var ids = SshAgentMessages.ParseIdentities((await client.RequestAsync(SshAgentMessages.RequestIdentities))!);

        Assert.Equal("k1", Assert.Single(ids).Comment);
    }

    // ------------------------------------------------------------------ MiMo M2 / GLM 2, M3: load-time caps and duplicates

    private static BrokerPolicy Policy(IEnumerable<(string Name, string Secret)> keys, IEnumerable<string>? socketKeys = null) => BrokerPolicy.Parse($$"""
        {
          "version": 1,
          "socket_dir": "/tmp",
          "sockets": [ { "name": "lane1", "uids": ["1"], "routes": [], "ssh_keys": {{JsonSerializer.Serialize(socketKeys ?? [])}} } ],
          "routes": [],
          "ssh_keys": [ {{string.Join(",", keys.Select(k => $$"""{ "name": "{{k.Name}}", "secret": "{{k.Secret}}", "allowed_host_keys": ["{{SshAgentHarness.SomeHostFingerprint}}"] }"""))}} ]
        }
        """);

    [Fact]
    public void ASocketListingMoreThan64Keys_StopsTheLoad_NamingIt()
    {
        var keys = Enumerable.Range(0, 65).Select(i => ($"k{i}", $"s{i}")).ToList();
        var source = new FakeSshKeySource(_ => SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)));

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy(keys, keys.Select(k => k.Item1)), source));

        Assert.Contains("Socket 'lane1'", ex.Message);
        Assert.Contains("64", ex.Message);
        Assert.Equal(0, source.Reads); // checked before any unlock
    }

    [Fact]
    public void SixtyFourKeysOnASocket_Load()
    {
        var keys = Enumerable.Range(0, 64).Select(i => ($"k{i}", $"s{i}")).ToList();
        var source = new FakeSshKeySource(_ => SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)));

        Assert.Equal(64, SshAgentKeyLoader.Load(Policy(keys, keys.Select(k => k.Item1)), source).Count);
    }

    [Fact]
    public void TwoKeysWithTheSameSecret_StopTheLoad_NamingBoth()
    {
        var source = new FakeSshKeySource(_ => (byte[])KeyA.Clone());

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy([("first", "same"), ("second", "same")]), source));

        Assert.Contains("'first'", ex.Message);
        Assert.Contains("'second'", ex.Message);
        Assert.Equal(0, source.Reads);
    }

    [Fact]
    public void TwoSecretsHoldingTheSameKey_StopTheLoad_NamingBoth()
    {
        var source = new FakeSshKeySource(_ => (byte[])KeyA.Clone());

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy([("first", "s1"), ("second", "s2")]), source));

        Assert.Contains("'first'", ex.Message);
        Assert.Contains("'second'", ex.Message);
        Assert.Contains("same private key", ex.Message);
    }

    // ------------------------------------------------------------------ MiMo M4: padding counter

    [Fact]
    public void OpensshPadding_ThatWrapsAByteCounter_IsRefused()
    {
        // A valid Ed25519 openssh-key-v1 whose padding runs 1..255, 0, 1, 2, ... (over 256 bytes): a byte
        // counter wraps and ends small enough to pass; an int counter sees a run longer than a block.
        var seed = RandomNumberGenerator.GetBytes(32);
        var a = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(seed, 0, a, 0);
        var blob = SshPublicKey.Ed25519Blob(a);
        var body = new SshWriter().UInt32(7).UInt32(7).String("ssh-ed25519").String(a).String([.. seed, .. a]).String("");
        var length = 257;
        while ((body.Length + length) % 8 != 0)
            length++;
        Assert.True(length % 256 <= 7); // so a wrapping byte counter would end at 8 or below
        for (var i = 1; i <= length; i++)
            body.Byte((byte)i);

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(OpenSshPem(blob, body.ToArray())));

        Assert.Contains("padding", ex.Message);
    }

    [Fact]
    public void OpensshPadding_NormalLength_StillLoads()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var a = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(seed, 0, a, 0);
        var body = new SshWriter().UInt32(7).UInt32(7).String("ssh-ed25519").String(a).String([.. seed, .. a]).String("");
        for (byte i = 1; body.Length % 8 != 0; i++)
            body.Byte(i);

        using var key = SshPrivateKey.Parse(OpenSshPem(SshPublicKey.Ed25519Blob(a), body.ToArray()));

        Assert.Equal(SshPublicKey.Ed25519Blob(a), key.PublicBlob);
    }

    // ------------------------------------------------------------------ MiMo M5: RSA parameters

    [Fact]
    public void RsaKeyWithExponentOne_IsRefused()
    {
        using var rsa = RSA.Create(3072);
        var p = rsa.ExportParameters(true);
        byte[] e = [1], d = [1]; // e·d ≡ 1 holds trivially, so the CRT checks alone pass it
        var body = new SshWriter().UInt32(9).UInt32(9).String("ssh-rsa")
            .PositiveMpint(p.Modulus).PositiveMpint(e).PositiveMpint(d).PositiveMpint(p.InverseQ).PositiveMpint(p.P).PositiveMpint(p.Q)
            .String("");
        for (byte i = 1; body.Length % 8 != 0; i++)
            body.Byte(i);

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(OpenSshPem(SshPublicKey.RsaBlob(e, p.Modulus), body.ToArray())));

        Assert.Contains("exponent", ex.Message);
    }

    [Theory]
    [InlineData("e=1")]
    [InlineData("e-even")]
    [InlineData("n-even")]
    public void RsaHostKeyWithDegenerateParameters_NeverVerifies(string shape)
    {
        using var rsa = RSA.Create(3072);
        var p = rsa.ExportParameters(false);
        var n = (byte[])p.Modulus!.Clone();
        byte[] e = shape switch { "e=1" => [1], "e-even" => [1, 0, 0], _ => p.Exponent! };
        if (shape == "n-even")
            n[^1] &= 0xFE;
        var host = SshPublicKey.Parse(SshPublicKey.RsaBlob(e, n));
        var sid = RandomNumberGenerator.GetBytes(32);
        // With e = 1 the "signature" of m is m itself: a forger would send the PKCS#1 encoding of H.
        var forged = new SshWriter().String("rsa-sha2-256").String(new byte[n.Length]).ToArray();

        Assert.Equal("rsa-parameters", host.VerifyRefusal(sid, forged));
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] OpenSshPem(byte[] publicBlob, byte[] privateSection)
    {
        var file = new SshWriter().Raw("openssh-key-v1\0"u8).String("none").String("none").String("").UInt32(1)
            .String(publicBlob).String(privateSection).ToArray();
        return Encoding.ASCII.GetBytes("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + Convert.ToBase64String(file, Base64FormattingOptions.InsertLineBreaks) + "\n-----END OPENSSH PRIVATE KEY-----\n");
    }
}
