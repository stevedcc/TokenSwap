using System.Security.Cryptography;
using System.Text;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;
using Ed25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace TswapTests;

/// <summary>Test keys made in-process (no tools): PKCS#8 PEMs the agent loads, and host keys that sign session identifiers.</summary>
public static class SshTestKeyMaker
{
    public static byte[] Ed25519Pem(byte[] seed)
    {
        // PKCS#8 PrivateKeyInfo for id-Ed25519 (RFC 8410 §7): the seed in an OCTET STRING in an OCTET STRING.
        byte[] der = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, .. seed];
        return Encoding.ASCII.GetBytes(PemEncoding.Write("PRIVATE KEY", der));
    }

    public static byte[] EcdsaPem(ECCurve curve)
    {
        using var ecdsa = ECDsa.Create(curve);
        return Encoding.ASCII.GetBytes(ecdsa.ExportPkcs8PrivateKeyPem());
    }

    public static byte[] RsaPem(int bits)
    {
        using var rsa = RSA.Create(bits);
        return Encoding.ASCII.GetBytes(rsa.ExportPkcs8PrivateKeyPem());
    }

    public static byte[] PublicBlob(byte[] pem)
    {
        using var key = SshPrivateKey.Parse(pem);
        return key.PublicBlob;
    }
}

/// <summary>A server host key: its blob and fingerprint, and the KEX signature over a session identifier.</summary>
public sealed class TestHostKey(byte[] pem)
{
    public byte[] Pem { get; } = pem;
    public byte[] Blob { get; } = SshTestKeyMaker.PublicBlob(pem);
    public string Fingerprint => SshFingerprint.Of(Blob);

    /// <summary>The host's signature blob over <paramref name="sessionId"/> (flags pick RSA's hash).</summary>
    public byte[] Sign(byte[] sessionId, uint flags = 0)
    {
        using var key = SshPrivateKey.Parse(Pem);
        return key.Sign(sessionId, flags);
    }

    public static TestHostKey NewEd25519() => new(SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)));
    public static TestHostKey NewEcdsa() => new(SshTestKeyMaker.EcdsaPem(ECCurve.NamedCurves.nistP256));
}

/// <summary>Agent messages for the bind and sign tests.</summary>
public static class SshBindMessages
{
    public static byte[] Bind(byte[] hostKeyBlob, byte[] sessionId, byte[] signature, byte forwarding = 0) =>
        new SshWriter().Byte(SshAgentProtocol.Extension).String(SshAgentProtocol.SessionBindExtension)
            .String(hostKeyBlob).String(sessionId).String(signature).Byte(forwarding).ToArray();

    public static byte[] SignRequest(byte[] keyBlob, byte[] data, uint flags = 0) =>
        new SshWriter().Byte(SshAgentProtocol.SignRequest).String(keyBlob).String(data).UInt32(flags).ToArray();

    /// <summary>An SSH publickey userauth request (RFC 4252 §7), optionally host-bound (with the server host key appended).</summary>
    public static byte[] Userauth(byte[] sessionId, string algorithm, byte[] keyBlob, string method = "publickey",
        byte[]? hostKey = null, string service = "ssh-connection", byte messageType = 50, byte hasSignature = 1, string user = "git")
    {
        var w = new SshWriter().String(sessionId).Byte(messageType).String(user).String(service).String(method)
            .Byte(hasSignature).String(algorithm).String(keyBlob);
        if (hostKey != null)
            w.String(hostKey);
        return w.ToArray();
    }

    /// <summary>Verifies an agent's signature independently: BouncyCastle for Ed25519, the BCL for ECDSA and RSA.</summary>
    public static bool Verify(byte[] publicBlob, byte[] data, byte[] signatureBlob)
    {
        var key = new SshReader(publicBlob);
        var type = Encoding.ASCII.GetString(key.ReadString());
        var sig = new SshReader(signatureBlob);
        var algorithm = Encoding.ASCII.GetString(sig.ReadString());
        var body = sig.ReadString().ToArray();
        sig.EnsureEnd();
        switch (type)
        {
            case "ssh-ed25519":
                return algorithm == "ssh-ed25519" && body.Length == 64 && Ed25519.Verify(body, 0, key.ReadString().ToArray(), 0, data, 0, data.Length);
            case "ssh-rsa":
            {
                var e = key.ReadPositiveMpint().ToArray();
                var n = key.ReadPositiveMpint().ToArray();
                using var rsa = RSA.Create(new RSAParameters { Exponent = e, Modulus = n });
                var hash = algorithm switch { "rsa-sha2-256" => HashAlgorithmName.SHA256, "rsa-sha2-512" => HashAlgorithmName.SHA512, _ => default };
                return hash != default && rsa.VerifyData(data, body, hash, RSASignaturePadding.Pkcs1);
            }
            default:
            {
                key.ReadString();
                var q = key.ReadString().ToArray();
                var size = (q.Length - 1) / 2;
                var (curve, hash) = size switch
                {
                    32 => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
                    48 => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
                    _ => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512),
                };
                using var ecdsa = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = q[1..(1 + size)], Y = q[(1 + size)..] } });
                var inner = new SshReader(body);
                var r = inner.ReadPositiveMpint().ToArray();
                var s = inner.ReadPositiveMpint().ToArray();
                inner.EnsureEnd();
                var p1363 = new byte[2 * size];
                r.CopyTo(p1363, size - r.Length);
                s.CopyTo(p1363, 2 * size - s.Length);
                return algorithm == type && ecdsa.VerifyData(data, p1363, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }
    }
}

/// <summary>
/// Brief T10 item 3: <c>session-bind@openssh.com</c> and the destination restriction (decision 4), on a
/// real Unix socket with in-process keys: host keys X (Ed25519) and Y (ECDSA); on socket lane1, key
/// <c>a</c> (Ed25519, X only), <c>b</c> (ECDSA, Y only), <c>r</c> (RSA 3072, X only); key <c>c</c>
/// (Ed25519, X) only on socket <c>other</c>. Every refusal is checked to cost no unlock.
/// </summary>
public class SshAgentBindTests : IAsyncLifetime
{
    private readonly SshAgentHarness _h = new();
    private static readonly TestHostKey X = TestHostKey.NewEd25519();
    private static readonly TestHostKey Y = TestHostKey.NewEcdsa();
    private static readonly TestHostKey Z = new(SshTestKeyMaker.RsaPem(3072)); // an RSA host key, allowed for key a
    private static readonly Dictionary<string, byte[]> Pems = new()
    {
        ["sa"] = SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)),
        ["sb"] = SshTestKeyMaker.EcdsaPem(ECCurve.NamedCurves.nistP256),
        ["sr"] = SshTestKeyMaker.RsaPem(3072),
        ["sc"] = SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)),
    };
    private static readonly byte[] A = SshTestKeyMaker.PublicBlob(Pems["sa"]);
    private static readonly byte[] B = SshTestKeyMaker.PublicBlob(Pems["sb"]);
    private static readonly byte[] R = SshTestKeyMaker.PublicBlob(Pems["sr"]);
    private static readonly byte[] C = SshTestKeyMaker.PublicBlob(Pems["sc"]);
    private readonly FakeSshKeySource _source = new(s => (byte[])Pems[s].Clone());
    private int _loadReads;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    /// <summary>Unlocks since serve started (the load's own reads excluded).</summary>
    private int SignUnlocks => _source.Reads - _loadReads;

    private async Task StartAsync(int signsPerMinute = 30)
    {
        var config = _h.Config(
            keys: [("a", "sa", [X.Fingerprint, Z.Fingerprint]), ("b", "sb", [Y.Fingerprint]), ("r", "sr", [X.Fingerprint]), ("c", "sc", [X.Fingerprint])],
            lane1Keys: ["a", "b", "r"], otherKeys: ["c"]);
        await _h.StartAsync(config, policy =>
        {
            var keys = SshAgentKeyLoader.Load(policy, _source);
            _loadReads = _source.Reads;
            return new SshAgentOptions { Keys = keys, KeySource = _source, AllowOwnUidForTests = true, SignsPerMinute = signsPerMinute };
        });
    }

    private static byte[] NewSessionId() => RandomNumberGenerator.GetBytes(32);

    /// <summary>Connects to lane1 and binds the connection to <paramref name="host"/> with a valid signature.</summary>
    private async Task<(SshAgentTestClient Client, byte[] SessionId)> BoundAsync(TestHostKey host, string socket = "lane1", uint hostFlags = 0)
    {
        var client = await _h.ConnectAsync(socket);
        var sid = NewSessionId();
        Assert.Equal(new[] { SshAgentProtocol.Success }, await client.RequestAsync(SshBindMessages.Bind(host.Blob, sid, host.Sign(sid, hostFlags))));
        return (client, sid);
    }

    private static byte[] SignatureOf(byte[]? reply)
    {
        Assert.NotNull(reply);
        var reader = new SshReader(reply);
        Assert.Equal(SshAgentProtocol.SignResponse, reader.ReadByte());
        var sig = reader.ReadString().ToArray();
        reader.EnsureEnd();
        return sig;
    }

    // ------------------------------------------------------------------ allowed

    [Theory]
    [InlineData("a", "publickey")]
    [InlineData("a", "publickey-hostbound-v00@openssh.com")]
    [InlineData("b", "publickey")]
    [InlineData("r", "publickey")]
    public async Task BoundToAnAllowedHost_ASignedUserauthRequest_Verifies(string keyName, string method)
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (blob, host, algorithm) = keyName switch
        {
            "a" => (A, X, "ssh-ed25519"),
            "b" => (B, Y, "ecdsa-sha2-nistp256"),
            _ => (R, X, "rsa-sha2-512"),
        };
        var flags = keyName == "r" ? SshAgentProtocol.RsaSha2_512 : 0u;
        var (client, sid) = await BoundAsync(host);
        using var _ = client;
        var data = SshBindMessages.Userauth(sid, algorithm, blob, method, method == "publickey" ? null : host.Blob);

        var signature = SignatureOf(await client.RequestAsync(SshBindMessages.SignRequest(blob, data, flags)));

        Assert.True(SshBindMessages.Verify(blob, data, signature));
        Assert.Equal(1, SignUnlocks);
        var log = _h.Broker.LogText.ToString();
        Assert.Contains($"ssh-sign socket=lane1.ssh uid={BrokerHarness.MyUid} pid={Environment.ProcessId} key={keyName} host={host.Fingerprint} result=ok", log);
        Assert.DoesNotContain(Convert.ToBase64String(data), log);
    }

    [Fact]
    public async Task RsaSha256_IsSignedWithSha256()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var _ = client;
        var data = SshBindMessages.Userauth(sid, "rsa-sha2-256", R);

        var signature = SignatureOf(await client.RequestAsync(SshBindMessages.SignRequest(R, data, SshAgentProtocol.RsaSha2_256)));

        Assert.Equal("rsa-sha2-256", Encoding.ASCII.GetString(new SshReader(signature).ReadString()));
        Assert.True(SshBindMessages.Verify(R, data, signature));
    }

    // ------------------------------------------------------------------ the bind

    [Theory]
    [InlineData(SshAgentProtocol.RsaSha2_256)]
    [InlineData(SshAgentProtocol.RsaSha2_512)]
    public async Task RsaHostKey_BindsWithASha2Signature(uint hostFlags)
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(Z, hostFlags: hostFlags);
        using var c = client;
        var data = SshBindMessages.Userauth(sid, "ssh-ed25519", A);

        Assert.True(SshBindMessages.Verify(A, data, SignatureOf(await client.RequestAsync(SshBindMessages.SignRequest(A, data)))));
    }

    private async Task AssertBindRefusedAndClosedAsync(SshAgentTestClient client, byte[] bind, string reason)
    {
        Assert.Equal(new[] { SshAgentProtocol.ExtensionFailure }, await client.RequestAsync(bind));
        Assert.True(await client.ClosedWithoutReplyAsync()); // a failed bind closes the connection
        await _h.Broker.WaitForLogAsync("reason=" + reason);
        Assert.Contains("ssh-bind socket=lane1.ssh", _h.Broker.LogText.ToString());
        Assert.Equal(0, SignUnlocks);
    }

    [Fact]
    public async Task ForgedBindSignature_IsRefused_AndClosesTheConnection()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var sid = NewSessionId();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(X.Blob, sid, X.Sign(NewSessionId())), "bad-signature");
    }

    [Fact]
    public async Task BindSignedByAnotherKey_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var sid = NewSessionId();
        var impostor = TestHostKey.NewEd25519();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(X.Blob, sid, impostor.Sign(sid)), "bad-signature");
    }

    [Fact]
    public async Task SecondBind_IsRefused_EvenAValidOne()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, _) = await BoundAsync(X);
        using var c = client;
        var sid = NewSessionId();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(X.Blob, sid, X.Sign(sid)), "second-bind");
    }

    [Fact]
    public async Task ForwardingBind_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var sid = NewSessionId();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(X.Blob, sid, X.Sign(sid), forwarding: 1), "forwarding");
    }

    [Fact]
    public async Task BindToAHostNoKeyOfThisSocketAllows_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var elsewhere = TestHostKey.NewEd25519();
        var sid = NewSessionId();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(elsewhere.Blob, sid, elsewhere.Sign(sid)), "host-not-allowed");
    }

    [Fact]
    public async Task Sha1RsaHostSignature_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        using var rsa = RSA.Create(3072);
        var hostBlob = SshPublicKey.RsaBlob(rsa.ExportParameters(false).Exponent!, rsa.ExportParameters(false).Modulus!);
        var sid = NewSessionId();
        // Refused by its algorithm name before any verification (this host's OpenSSL policy won't even make a
        // SHA-1 signature, so the body is a SHA-256 one under the "ssh-rsa" name).
        var sha1 = new SshWriter().String("ssh-rsa").String(rsa.SignData(sid, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)).ToArray();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(hostBlob, sid, sha1), "bad-signature");
        Assert.Contains("reason=bad-signature detail=sha1", _h.Broker.LogText.ToString());
    }

    [Theory]
    [InlineData("ssh-dss")]
    [InlineData("ssh-ed25519-cert-v01@openssh.com")]
    [InlineData("sk-ssh-ed25519@openssh.com")]
    public async Task UnsupportedHostKeyType_IsRefused(string type)
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var blob = new SshWriter().String(type).String(new byte[32]).ToArray();
        var sid = NewSessionId();

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(blob, sid, X.Sign(sid)), "host-key-type");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(129)]
    public async Task BindWithAnEmptyOrOversizeSessionId_IsRefused(int length)
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var sid = new byte[length];

        await AssertBindRefusedAndClosedAsync(client, SshBindMessages.Bind(X.Blob, sid, X.Sign(sid)), "malformed");
    }

    [Fact]
    public async Task BindWithTrailingBytes_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var sid = NewSessionId();

        await AssertBindRefusedAndClosedAsync(client, [.. SshBindMessages.Bind(X.Blob, sid, X.Sign(sid)), 0], "malformed");
    }

    // ------------------------------------------------------------------ sign-time checks

    private async Task AssertSignRefusedAsync(SshAgentTestClient client, byte[] request, string reason)
    {
        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(request));
        await _h.Broker.WaitForLogAsync("reason=" + reason);
        Assert.Contains("result=refused", _h.Broker.LogText.ToString());
        Assert.Equal(0, SignUnlocks); // every refusal costs no unlock
        // The connection stays open.
        Assert.Equal(3, SshAgentMessages.ParseIdentities((await client.RequestAsync(SshAgentMessages.RequestIdentities))!).Count);
    }

    [Fact]
    public async Task SignWithoutABind_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(A, SshBindMessages.Userauth(NewSessionId(), "ssh-ed25519", A)), "no-session-bind");
    }

    [Fact]
    public async Task ABindIsPerConnection_NotSharedWithAnother()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (bound, sid) = await BoundAsync(X);
        using var _ = bound;
        using var other = await _h.ConnectAsync("lane1");

        await AssertSignRefusedAsync(other, SshBindMessages.SignRequest(A, SshBindMessages.Userauth(sid, "ssh-ed25519", A)), "no-session-bind");
    }

    [Fact]
    public async Task SignForAnotherSession_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, _) = await BoundAsync(X);
        using var c = client;

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(A, SshBindMessages.Userauth(NewSessionId(), "ssh-ed25519", A)), "session-id");
    }

    [Fact]
    public async Task CrossProduct_ABindAllowedForKeyA_NeverLetsKeyBSign()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X); // X is allowed for a (and r), not for b (Y only)
        using var c = client;

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(B, SshBindMessages.Userauth(sid, "ecdsa-sha2-nistp256", B)), "host-not-allowed");
    }

    [Fact]
    public async Task AKeyOnAnotherSocketsList_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X); // c allows X, but c is on socket other's list only
        using var c = client;

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(C, SshBindMessages.Userauth(sid, "ssh-ed25519", C)), "key-not-allowed");
    }

    [Fact]
    public async Task AnUnknownKey_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var c = client;
        var stranger = SshTestKeyMaker.PublicBlob(SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)));

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(stranger, SshBindMessages.Userauth(sid, "ssh-ed25519", stranger)), "key-not-allowed");
    }

    [Theory]
    [InlineData(0u, "rsa-sha2-256")]
    [InlineData(6u, "rsa-sha2-256")]
    [InlineData(1u, "rsa-sha2-256")]
    public async Task RsaWithoutExactlyOneSha2Flag_IsRefused(uint flags, string algorithm)
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var c = client;

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(R, SshBindMessages.Userauth(sid, algorithm, R), flags), flags == 0 ? "rsa-sha1" : "flags");
    }

    [Fact]
    public async Task Ed25519WithAFlag_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var c = client;

        await AssertSignRefusedAsync(client, SshBindMessages.SignRequest(A, SshBindMessages.Userauth(sid, "ssh-ed25519", A), SshAgentProtocol.RsaSha2_256), "flags");
    }

    public static TheoryData<string> NotUserauth => ["trailing", "sshsig", "other-blob", "other-algorithm", "service", "method", "no-signature", "message-type", "hostbound-other-host", "hostbound-missing-host", "empty", "garbage"];

    [Theory]
    [MemberData(nameof(NotUserauth))]
    public async Task NotAnOracle_AnythingButThisSessionsUserauthRequest_IsRefused(string shape)
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var c = client;
        var data = shape switch
        {
            "trailing" => [.. SshBindMessages.Userauth(sid, "ssh-ed25519", A), 0],
            // An SSHSIG document (PROTOCOL.sshsig): magic, version, key, namespace, reserved, hash algorithm, hash.
            "sshsig" => new SshWriter().Raw("SSHSIG"u8).UInt32(1).String(A).String("git").String("").String("sha512").String(new byte[64]).ToArray(),
            "other-blob" => SshBindMessages.Userauth(sid, "ssh-ed25519", C),
            "other-algorithm" => SshBindMessages.Userauth(sid, "ecdsa-sha2-nistp256", A),
            "service" => SshBindMessages.Userauth(sid, "ssh-ed25519", A, service: "ssh-userauth"),
            "method" => SshBindMessages.Userauth(sid, "ssh-ed25519", A, method: "hostbased"),
            "no-signature" => SshBindMessages.Userauth(sid, "ssh-ed25519", A, hasSignature: 0),
            "message-type" => SshBindMessages.Userauth(sid, "ssh-ed25519", A, messageType: 51),
            "hostbound-other-host" => SshBindMessages.Userauth(sid, "ssh-ed25519", A, "publickey-hostbound-v00@openssh.com", Y.Blob),
            "hostbound-missing-host" => SshBindMessages.Userauth(sid, "ssh-ed25519", A, "publickey-hostbound-v00@openssh.com"),
            "empty" => [],
            _ => RandomNumberGenerator.GetBytes(200),
        };

        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(SshBindMessages.SignRequest(A, data)));

        await _h.Broker.WaitForLogAsync("result=refused");
        Assert.Equal(0, SignUnlocks);
        Assert.Contains("key=a", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task MalformedSignRequest_IsRefused_WithNoUnlock()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var c = client;

        await AssertSignRefusedAsync(client, [.. SshBindMessages.SignRequest(A, SshBindMessages.Userauth(sid, "ssh-ed25519", A)), 0], "malformed");
    }

    // ------------------------------------------------------------------ limits

    [Fact]
    public async Task SignRateLimit_RefusesBeyondIt_WithNoUnlock_UntilAMinutePasses()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync(signsPerMinute: 2);
        var (client, sid) = await BoundAsync(X);
        using var c = client;
        var request = SshBindMessages.SignRequest(A, SshBindMessages.Userauth(sid, "ssh-ed25519", A));

        SignatureOf(await client.RequestAsync(request));
        SignatureOf(await client.RequestAsync(request));
        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(request));
        Assert.Equal(2, SignUnlocks);
        await _h.Broker.WaitForLogAsync("reason=sign-rate");

        _h.Broker.Clock.Advance(TimeSpan.FromSeconds(61));
        SignatureOf(await client.RequestAsync(request));
        Assert.Equal(3, SignUnlocks);
    }

    [Fact]
    public async Task UnlockFailures_AreAnsweredWithFailure_AndLockTheSocketOut()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        var (client, sid) = await BoundAsync(X);
        using var c = client;
        var request = SshBindMessages.SignRequest(A, SshBindMessages.Userauth(sid, "ssh-ed25519", A));
        _source.FailUnlock = true;

        for (var i = 0; i < 3; i++)
            Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(request));
        Assert.Equal(3, SignUnlocks);
        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(request));

        Assert.Equal(3, SignUnlocks); // locked out: no fourth unlock
        await _h.Broker.WaitForLogAsync("reason=locked-out");
    }
}
