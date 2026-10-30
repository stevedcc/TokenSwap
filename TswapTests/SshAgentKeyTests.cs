using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;

namespace TswapTests;

/// <summary>
/// Real keys made by <c>ssh-keygen</c> (and <c>openssl</c> for PKCS#8 forms) in a temp folder, for
/// brief T10 item 2's tests. Skips (returns null) where the tools are missing.
/// </summary>
public sealed class SshTestKeys : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "tswap-sshk-" + Guid.NewGuid().ToString("N")[..8]);

    public SshTestKeys() => Directory.CreateDirectory(Dir);

    public static bool HaveTools => !OperatingSystem.IsWindows() && Which("ssh-keygen") != null && Which("openssl") != null;

    public static string? Which(string tool) =>
        new[] { "/usr/bin", "/bin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew/bin" }
            .Select(d => Path.Combine(d, tool)).FirstOrDefault(File.Exists);

    public static (int Exit, string Out, string Err) Run(string tool, params string[] args)
    {
        var psi = new ProcessStartInfo(Which(tool) ?? tool)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        psi.Environment.Remove("SSH_AUTH_SOCK"); // never the user's agent
        using var p = Process.Start(psi)!;
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, stdout.Result, stderr.Result);
    }

    public static string Ok(string tool, params string[] args)
    {
        var (exit, stdout, stderr) = Run(tool, args);
        Assert.True(exit == 0, $"{tool} {string.Join(' ', args)}: {stderr}");
        return stdout;
    }

    /// <summary>A new OpenSSH-format key (<c>ssh-keygen -t type [-b bits]</c>); returns its private key path.</summary>
    public string Generate(string name, string type, int? bits = null, string passphrase = "")
    {
        var path = Path.Combine(Dir, name);
        var args = new List<string> { "-q", "-t", type, "-N", passphrase, "-C", "test-comment", "-f", path };
        if (bits is { } b)
            args.InsertRange(0, ["-b", b.ToString()]);
        Ok("ssh-keygen", [.. args]);
        return path;
    }

    /// <summary>Rewrites a key file in place as unencrypted PKCS#8 (<c>ssh-keygen -p -m PKCS8</c>; RSA and ECDSA).</summary>
    public static void ToPkcs8(string path) => Ok("ssh-keygen", "-q", "-p", "-m", "PKCS8", "-N", "", "-P", "", "-f", path);

    /// <summary>The <c>SHA256:</c> fingerprint <c>ssh-keygen -lf</c> prints for a public key file.</summary>
    public static string Fingerprint(string publicKeyFile) => Ok("ssh-keygen", "-l", "-E", "sha256", "-f", publicKeyFile).Split(' ')[1];

    public static byte[] BlobOf(string publicKeyFile) => Convert.FromBase64String(File.ReadAllText(publicKeyFile).Split(' ')[1]);

    public void Dispose()
    {
        if (Directory.Exists(Dir))
            Directory.Delete(Dir, true);
    }
}

/// <summary>A key source for tests: serves key files by secret name, counts reads (each one a vault unlock).</summary>
public sealed class FakeSshKeySource(Func<string, byte[]?> keys) : ISshKeySource
{
    private int _reads;

    public int Reads => Volatile.Read(ref _reads);

    public List<string> Names { get; } = [];

    /// <summary>When set, every read fails as an unlock failure.</summary>
    public bool FailUnlock { get; set; }

    public byte[] ReadKey(string secretName)
    {
        Interlocked.Increment(ref _reads);
        lock (Names)
            Names.Add(secretName);
        if (FailUnlock)
            throw new BrokerUnlockException("simulated unlock failure");
        return keys(secretName) ?? throw new BrokerSecretException($"secret '{secretName}' is not in the vault");
    }
}

/// <summary>
/// Brief T10 item 2: private keys (openssh-key-v1 and PKCS#8) parsed, their public keys derived and
/// matched against ssh-keygen's, signatures in OpenSSH's blob format checked independently (BCL for
/// ECDSA and RSA, BouncyCastle for Ed25519), and the load-time refusals.
/// </summary>
public class SshAgentKeyTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;
    private readonly SshTestKeys _keys = new();

    public void Dispose() => _keys.Dispose();

    public static TheoryData<string, int?> KeyTypes => new()
    {
        { "ed25519", null },
        { "ecdsa", 256 },
        { "ecdsa", 384 },
        { "ecdsa", 521 },
        { "rsa", 3072 },
    };

    [Theory]
    [MemberData(nameof(KeyTypes))]
    public void OpensshKey_PublicBlobAndFingerprint_MatchSshKeygen(string type, int? bits)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", type, bits);

        using var key = SshPrivateKey.Parse(File.ReadAllBytes(path));

        Assert.Equal(SshTestKeys.BlobOf(path + ".pub"), key.PublicBlob);
        Assert.Equal(SshTestKeys.Fingerprint(path + ".pub"), SshFingerprint.Of(key.PublicBlob));
    }

    [Theory]
    [InlineData("ecdsa", 256)]
    [InlineData("ecdsa", 384)]
    [InlineData("ecdsa", 521)]
    [InlineData("rsa", 3072)]
    public void Pkcs8Key_PublicBlob_MatchesTheOriginal(string type, int? bits)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", type, bits);
        SshTestKeys.ToPkcs8(path);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", File.ReadAllText(path));

        using var key = SshPrivateKey.Parse(File.ReadAllBytes(path));

        Assert.Equal(SshTestKeys.BlobOf(path + ".pub"), key.PublicBlob);
    }

    /// <summary>
    /// An Ed25519 PKCS#8 key from openssl, with the expected public key also from openssl
    /// (<c>openssl pkey -pubout</c>), so the check doesn't depend on ssh-keygen reading PKCS#8 Ed25519
    /// (Ubuntu 24.04's OpenSSH 9.6 can't: round 3). Without an openssl that knows Ed25519 (macOS's
    /// LibreSSL), it says so and returns; the RFC 8032 and RFC 8410 fixed-DER tests run everywhere.
    /// </summary>
    [Fact]
    public void Pkcs8Ed25519Key_PublicBlob_MatchesOpensslsDerivation()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = Path.Combine(_keys.Dir, "k");
        var (exit, _, err) = SshTestKeys.Run("openssl", "genpkey", "-algorithm", "ed25519", "-out", path);
        if (exit != 0)
        {
            _output.WriteLine($"SKIPPED: this openssl can't make an Ed25519 key ({err.Trim()}); the fixed-DER Ed25519 tests cover the parser.");
            return;
        }
        var spki = Path.Combine(_keys.Dir, "k.spki");
        SshTestKeys.Ok("openssl", "pkey", "-in", path, "-pubout", "-outform", "DER", "-out", spki);
        var expected = File.ReadAllBytes(spki)[^32..]; // SubjectPublicKeyInfo ends with the 32-byte key (RFC 8410 §4)

        using var key = SshPrivateKey.Parse(File.ReadAllBytes(path));

        Assert.Equal(SshPublicKey.Ed25519Blob(expected), key.PublicBlob);
    }

    /// <summary>The same key as openssl writes it with explicit curve parameters (macOS's LibreSSL does so by default) loads as the named curve.</summary>
    [Theory]
    [InlineData("prime256v1")]
    [InlineData("secp384r1")]
    [InlineData("secp521r1")]
    public void ExplicitParameterEcKeyFromOpenssl_LoadsAsTheNamedCurve(string curve)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var named = Path.Combine(_keys.Dir, "named.pem");
        var sec1 = Path.Combine(_keys.Dir, "sec1.pem");
        var sec1Explicit = Path.Combine(_keys.Dir, "sec1x.pem");
        var explicitKey = Path.Combine(_keys.Dir, "explicit.pem");
        // Round 4 (MiMo): a capability probe like the Ed25519 one; an openssl that can't write explicit
        // parameters says so and the fixed-DER explicit-P-256 tests carry the check.
        foreach (var step in new[]
                 {
                     new[] { "ecparam", "-name", curve, "-genkey", "-noout", "-out", sec1 },
                     ["ec", "-in", sec1, "-param_enc", "explicit", "-out", sec1Explicit],
                 })
        {
            var (exit, _, err) = SshTestKeys.Run("openssl", step);
            if (exit != 0)
            {
                _output.WriteLine($"SKIPPED: this openssl can't run 'openssl {step[0]}' for {curve} with explicit parameters ({err.Trim()}); the fixed-DER explicit P-256 tests cover the parser.");
                return;
            }
        }
        SshTestKeys.Ok("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", sec1, "-out", named);
        SshTestKeys.Ok("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", sec1Explicit, "-out", explicitKey);

        using var fromNamed = SshPrivateKey.Parse(File.ReadAllBytes(named));
        using var fromExplicit = SshPrivateKey.Parse(File.ReadAllBytes(explicitKey));

        Assert.Equal(fromNamed.PublicBlob, fromExplicit.PublicBlob);
        Assert.Equal(fromNamed.Type, fromExplicit.Type);
    }

    [Fact]
    public void TheVaultSecret_MayLackTheTrailingNewline()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ed25519");
        var trimmed = Encoding.ASCII.GetBytes(File.ReadAllText(path).TrimEnd()); // 'tswap ingest' trims trailing whitespace

        using var key = SshPrivateKey.Parse(trimmed);

        Assert.Equal(SshTestKeys.BlobOf(path + ".pub"), key.PublicBlob);
    }

    // ------------------------------------------------------------------ signatures

    [Fact]
    public void Ed25519Signature_IsTheBlobOpenSshExpects_AndVerifiesWithBouncyCastle()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ed25519");
        var data = RandomNumberGenerator.GetBytes(100);
        using var key = SshPrivateKey.Parse(File.ReadAllBytes(path));

        var blob = key.Sign(data, 0);

        var reader = new SshReader(blob);
        Assert.Equal("ssh-ed25519", Encoding.ASCII.GetString(reader.ReadString()));
        var sig = reader.ReadString().ToArray();
        reader.EnsureEnd();
        Assert.Equal(64, sig.Length);
        var pub = new SshReader(key.PublicBlob);
        pub.ReadString();
        var a = pub.ReadString().ToArray();
        Assert.True(Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Verify(sig, 0, a, 0, data, 0, data.Length));
        data[0] ^= 1;
        Assert.False(Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Verify(sig, 0, a, 0, data, 0, data.Length));
    }

    [Theory]
    [InlineData(256, "nistp256")]
    [InlineData(384, "nistp384")]
    [InlineData(521, "nistp521")]
    public void EcdsaSignature_IsMpintRAndS_HashedPerCurve_AndVerifiesWithTheBcl(int bits, string curve)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ecdsa", bits);
        var data = RandomNumberGenerator.GetBytes(100);
        using var key = SshPrivateKey.Parse(File.ReadAllBytes(path));

        var blob = key.Sign(data, 0);

        var reader = new SshReader(blob);
        Assert.Equal("ecdsa-sha2-" + curve, Encoding.ASCII.GetString(reader.ReadString()));
        var inner = new SshReader(reader.ReadString());
        var r = inner.ReadPositiveMpint().ToArray();
        var s = inner.ReadPositiveMpint().ToArray();
        inner.EnsureEnd();
        reader.EnsureEnd();
        var size = (bits + 7) / 8;
        var p1363 = new byte[2 * size];
        r.CopyTo(p1363, size - r.Length);
        s.CopyTo(p1363, 2 * size - s.Length);

        // The public key, independently from ssh-keygen's .pub file: string type, string curve, string Q.
        var pub = new SshReader(SshTestKeys.BlobOf(path + ".pub"));
        pub.ReadString();
        pub.ReadString();
        var q = pub.ReadString().ToArray();
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = bits switch { 256 => ECCurve.NamedCurves.nistP256, 384 => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 },
            Q = new ECPoint { X = q[1..(1 + size)], Y = q[(1 + size)..] },
        });
        var hash = bits switch { 256 => HashAlgorithmName.SHA256, 384 => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
        Assert.True(ecdsa.VerifyData(data, p1363, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        // ...and not with another curve's hash (the curve fixes it).
        Assert.False(ecdsa.VerifyData(data, p1363, hash == HashAlgorithmName.SHA256 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Theory]
    [InlineData(SshAgentProtocol.RsaSha2_256, "rsa-sha2-256")]
    [InlineData(SshAgentProtocol.RsaSha2_512, "rsa-sha2-512")]
    public void RsaSignature_FollowsTheFlag_AndVerifiesWithTheBcl(uint flag, string algorithm)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "rsa", 3072);
        var data = RandomNumberGenerator.GetBytes(100);
        using var key = SshPrivateKey.Parse(File.ReadAllBytes(path));

        var blob = key.Sign(data, flag);

        var reader = new SshReader(blob);
        Assert.Equal(algorithm, Encoding.ASCII.GetString(reader.ReadString()));
        var sig = reader.ReadString().ToArray();
        reader.EnsureEnd();
        Assert.Equal(384, sig.Length); // the modulus' length
        var pub = new SshReader(SshTestKeys.BlobOf(path + ".pub"));
        pub.ReadString();
        var e = pub.ReadPositiveMpint().ToArray();
        var n = pub.ReadPositiveMpint().ToArray();
        using var rsa = RSA.Create(new RSAParameters { Exponent = e, Modulus = n });
        var hash = flag == SshAgentProtocol.RsaSha2_256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
        Assert.True(rsa.VerifyData(data, sig, hash, RSASignaturePadding.Pkcs1));
    }

    [Theory]
    [InlineData(0u)]                // no flag: SHA-1 ssh-rsa
    [InlineData(1u)]                // the reserved historical flag
    [InlineData(6u)]                // both SHA-2 flags
    [InlineData(0x02u | 0x10u)]     // an unknown bit
    public void RsaSignRequest_WithoutExactlyOneSha2Flag_IsRefused(uint flags)
    {
        Assert.NotNull(SshKeySigner.FlagsRefusal(SshKeyType.Rsa, flags));
    }

    [Theory]
    [InlineData(SshKeyType.Ed25519, 2u)]
    [InlineData(SshKeyType.EcdsaP256, 4u)]
    [InlineData(SshKeyType.EcdsaP384, 1u)]
    [InlineData(SshKeyType.EcdsaP521, 0x80u)]
    public void Ed25519AndEcdsa_RefuseAnyFlag(SshKeyType type, uint flags)
    {
        Assert.NotNull(SshKeySigner.FlagsRefusal(type, flags));
        Assert.Null(SshKeySigner.FlagsRefusal(type, 0));
    }

    [Fact]
    public void Sha1RsaRequest_IsRefusedBeforeAnyUnlock()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "rsa", 3072);
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(path));
        var keys = SshAgentKeyLoader.Load(Policy(("k", "key-k")), source);
        Assert.Equal(1, source.Reads);

        Assert.Throws<SshSignRefusedException>(() => SshKeySigner.Sign(source, keys["k"], [1, 2, 3], 0));

        Assert.Equal(1, source.Reads); // the refusal cost no unlock
    }

    // ------------------------------------------------------------------ load and unlock

    private static BrokerPolicy Policy(params (string Name, string Secret)[] keys) => BrokerPolicy.Parse($$"""
        {
          "version": 1,
          "socket_dir": {{System.Text.Json.JsonSerializer.Serialize(Path.GetTempPath())}},
          "sockets": [],
          "routes": [],
          "ssh_keys": [ {{string.Join(",", keys.Select(k => $$"""{ "name": "{{k.Name}}", "secret": "{{k.Secret}}", "allowed_host_keys": ["{{SshAgentHarness.SomeHostFingerprint}}"] }"""))}} ]
        }
        """);

    [Fact]
    public void Load_UnlocksOncePerKey_ReadingOnlyThatKeysSecret_AndKeepsOnlyThePublicKey()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var a = _keys.Generate("a", "ed25519");
        var b = _keys.Generate("b", "ecdsa", 256);
        var source = new FakeSshKeySource(s => File.ReadAllBytes(s == "sa" ? a : b));

        var keys = SshAgentKeyLoader.Load(Policy(("ka", "sa"), ("kb", "sb")), source);

        Assert.Equal(2, source.Reads);
        Assert.Equal(["sa", "sb"], source.Names.Order());
        Assert.Equal(SshTestKeys.BlobOf(a + ".pub"), keys["ka"].PublicBlob);
        Assert.Equal(SshKeyType.EcdsaP256, keys["kb"].Type);
        Assert.Equal("sb", keys["kb"].SecretName);
    }

    [Fact]
    public void EverySignature_UnlocksAfresh()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ed25519");
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(path));
        var key = SshAgentKeyLoader.Load(Policy(("k", "key-k")), source)["k"];

        SshKeySigner.Sign(source, key, [1], 0);
        SshKeySigner.Sign(source, key, [2], 0);
        SshKeySigner.Sign(source, key, [3], 0);

        Assert.Equal(4, source.Reads); // one at load, then one per signature
    }

    [Fact]
    public void AKeyReplacedInTheVaultSinceLoad_IsNotUsed()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var first = _keys.Generate("first", "ed25519");
        var second = _keys.Generate("second", "ed25519");
        var current = first;
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(current));
        var key = SshAgentKeyLoader.Load(Policy(("k", "key-k")), source)["k"];
        current = second;

        var ex = Assert.Throws<SshSignRefusedException>(() => SshKeySigner.Sign(source, key, [1], 0));

        Assert.Contains("changed", ex.Message);
    }

    [Fact]
    public void EncryptedPkcs8Key_StopsTheLoad_NamingTheKey()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var plain = _keys.Generate("k", "ecdsa", 256);
        SshTestKeys.ToPkcs8(plain);
        var encrypted = plain + ".enc";
        SshTestKeys.Ok("openssl", "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-passout", "pass:pw", "-in", plain, "-out", encrypted);
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", File.ReadAllText(encrypted));
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(encrypted));

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy(("deploy-key", "s")), source));

        Assert.Contains("'deploy-key'", ex.Message);
        Assert.Contains("encrypted", ex.Message);
    }

    [Fact]
    public void EncryptedOpensshKey_StopsTheLoad_NamingTheKey()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ed25519", passphrase: "pw");
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(path));

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy(("deploy-key", "s")), source));

        Assert.Contains("'deploy-key'", ex.Message);
        Assert.Contains("encrypted", ex.Message);
    }

    [Theory]
    [InlineData("ed25519", null)]
    [InlineData("ecdsa", 384)]
    [InlineData("rsa", 3072)]
    public void OpensshKeyWhoseEmbeddedPublicKeyDiffers_StopsTheLoad_NamingTheKey(string type, int? bits)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", type, bits);
        var other = _keys.Generate("other", type, bits);
        var forged = ReplaceOuterPublicKey(File.ReadAllText(path), SshTestKeys.BlobOf(other + ".pub"));
        var source = new FakeSshKeySource(_ => forged);

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy(("deploy-key", "s")), source));

        Assert.Contains("'deploy-key'", ex.Message);
        Assert.Contains("public key", ex.Message);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(1024)]
    public void RsaUnder3072Bits_IsRefused_NamingTheKey(int bits)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "rsa", bits);
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(path));

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy(("small", "s")), source));

        Assert.Contains("'small'", ex.Message);
        Assert.Contains("3072", ex.Message);
    }

    [Fact]
    public void Rsa2048InPkcs8_IsRefusedToo()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "rsa", 2048);
        SshTestKeys.ToPkcs8(path);

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(File.ReadAllBytes(path)));

        Assert.Contains("3072", ex.Message);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("garbage")]
    [InlineData("pkcs1")]
    [InlineData("huge")]
    [InlineData("unlock")]
    public void AKeyThatCantBeLoaded_StopsTheLoad_NamingIt(string problem)
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var rsa = _keys.Generate("pem", "rsa", 3072);
        SshTestKeys.Ok("ssh-keygen", "-q", "-p", "-m", "PEM", "-N", "", "-P", "", "-f", rsa); // BEGIN RSA PRIVATE KEY
        var source = new FakeSshKeySource(_ => problem switch
        {
            "missing" => null,
            "garbage" => "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"u8.ToArray(),
            "pkcs1" => File.ReadAllBytes(rsa),
            "huge" => new byte[SshAgentProtocol.MaxKeySecretLength + 1],
            _ => [],
        }) { FailUnlock = problem == "unlock" };

        var ex = Assert.Throws<TswapException>(() => SshAgentKeyLoader.Load(Policy(("good", "g"), ("bad-key", "s")), source));

        Assert.Contains("'bad-key'", ex.Message);
    }

    [Fact]
    public void TruncatedOrTrailingOpensshKeys_AreRefused_NeverACrash()
    {
        if (SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ecdsa", 256);
        var der = PemBody(File.ReadAllText(path));
        for (var cut = 1; cut < der.Length; cut += 7)
        {
            var truncated = Pem(der[..cut]);
            Assert.ThrowsAny<SshKeyException>(() => SshPrivateKey.Parse(truncated));
        }
        Assert.ThrowsAny<SshKeyException>(() => SshPrivateKey.Parse(Pem([.. der, 0])));
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] PemBody(string pem) =>
        Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----"))));

    private static byte[] Pem(byte[] body) =>
        Encoding.ASCII.GetBytes("-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(body, Base64FormattingOptions.InsertLineBreaks) + "\n-----END OPENSSH PRIVATE KEY-----\n");

    /// <summary>The same openssh-key-v1 file with its outer public key replaced (the private part untouched).</summary>
    private static byte[] ReplaceOuterPublicKey(string pem, byte[] publicBlob)
    {
        var body = PemBody(pem);
        var magic = "openssh-key-v1\0"u8.ToArray();
        var reader = new SshReader(body.AsSpan(magic.Length));
        var cipher = reader.ReadString().ToArray();
        var kdf = reader.ReadString().ToArray();
        var kdfOptions = reader.ReadString().ToArray();
        var n = reader.ReadUInt32();
        reader.ReadString(); // the original public key
        var priv = reader.ReadString().ToArray();
        var rebuilt = new SshWriter().Raw(magic).String(cipher).String(kdf).String(kdfOptions).UInt32(n).String(publicBlob).String(priv).ToArray();
        return Pem(rebuilt);
    }
}

/// <summary>
/// Brief T10 decision 5 (owner, 2026-10-30: "keep as little data unlocked for as short a time as
/// possible"): the key source reads only that key's record of a record-store vault, with a fresh
/// unlock per read, both at load and per signature.
/// </summary>
public class SshAgentVaultKeyTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;
    private readonly FleetMachine _m = new("sshkeyrec") { Tpm = RandomNumberGenerator.GetBytes(32) };
    private readonly SshTestKeys _keys = new();

    public void Dispose()
    {
        _m.Dispose();
        _keys.Dispose();
    }

    [Fact]
    public void LoadAndEachSignature_DecryptOnlyTheKeysRecord()
    {
        if (SshTestSkip.OnWindows(_output) || SshTestSkip.WithoutKeyTools(_output))
            return;
        var path = _keys.Generate("k", "ed25519");
        _m.Ok("", "init", "--tpm", "--no-recovery");
        for (var i = 0; i < 20; i++)
            _m.Ok($"value-{i}\n", "ingest", "s" + i);
        _m.Ok(File.ReadAllText(path), "ingest", "deploy-key"); // ingest trims the trailing newline
        _m.Ok("", "migrate", "--to-records");
        var store = Assert.IsType<TswapCore.RecordVaultStore>(TswapCore.VaultStores.Open(_m.Dir));
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;
        var unlocker = new TswapCore.Vault.VaultUnlocker(_m.Keys, overrideKey: null,
            additionalBackends: [new TswapCore.Vault.SimulatedHardwareService(TswapCore.HardwareBackend.Tpm, _m.Tpm!)]);
        var source = new VaultSshKeySource(store, unlocker);
        var policy = BrokerPolicy.Parse($$"""
            { "version": 1, "socket_dir": {{System.Text.Json.JsonSerializer.Serialize(Path.GetTempPath())}}, "sockets": [], "routes": [],
              "ssh_keys": [ { "name": "k", "secret": "deploy-key", "allowed_host_keys": ["{{SshAgentHarness.SomeHostFingerprint}}"] } ] }
            """);

        var key = SshAgentKeyLoader.Load(policy, source)["k"];
        Assert.Single(decrypted);
        Assert.Equal(SshTestKeys.BlobOf(path + ".pub"), key.PublicBlob);

        SshKeySigner.Sign(source, key, [1, 2, 3], 0);
        SshKeySigner.Sign(source, key, [4, 5, 6], 0);

        Assert.Equal(3, decrypted.Count);
        Assert.Single(decrypted.Distinct());
    }
}

/// <summary>
/// T10 round 3 (macOS CI): PKCS#8 shapes other tools emit, from fixed DERs so they run on every OS.
/// macOS's LibreSSL-linked ssh-keygen writes EC keys with explicit curve parameters; RFC 5958 v2
/// keys carry a public key (and maybe attributes). Each is accepted only when it is exactly a
/// supported curve and every embedded public key equals the one derived from the private key.
/// </summary>
public class SshAgentPkcs8ShapeTests
{
    // A test-only P-256 key (generated for this test; it opens nothing), as OpenSSL writes it with
    // named-curve parameters, and the same key with explicit parameters (openssl ec -param_enc explicit).
    private const string NamedP256 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiZOVRVUqgEOkluwMlF+pbVoir7yLOcA2hdisIzqSPyWhRANCAAT0LwuFgO4ManRkcOau9FjzyHB/bs34gUyEKdATDv/ZHd/intSBSaCrLY6agPF8aZmJ6sm/faPmD4/CMmJyXyAN";
    private const string ExplicitP256 = "MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQgiZOVRVUqgEOkluwMlF+pbVoir7yLOcA2hdisIzqSPyWhRANCAAT0LwuFgO4ManRkcOau9FjzyHB/bs34gUyEKdATDv/ZHd/intSBSaCrLY6agPF8aZmJ6sm/faPmD4/CMmJyXyAN";
    // Its public point, from `openssl ec -pubout` (independent of the parser).
    private const string P256Q = "04f42f0b8580ee0c6a746470e6aef458f3c8707f6ecdf8814c8429d0130effd91ddfe29ed48149a0ab2d8e9a80f17c699989eac9bf7da3e60f8fc23262725f200d";

    // RFC 8410 §10.3: an Ed25519 OneAsymmetricKey v2 with an attribute and the public key.
    private const string Rfc8410V2 =
        "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
    private const string Rfc8410Public = "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";

    private static byte[] Pem(byte[] der) => Encoding.ASCII.GetBytes(PemEncoding.Write("PRIVATE KEY", der));

    private static byte[] P256Blob()
    {
        var q = Convert.FromHexString(P256Q);
        return SshPublicKey.EcdsaBlob(SshKeyType.EcdsaP256, q.AsSpan(1, 32), q.AsSpan(33, 32));
    }

    [Fact]
    public void Ed25519Pkcs8_DerivesTheRfc8032TestVectorsPublicKey()
    {
        // RFC 8032 §7.1, TEST 1: secret key and public key.
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        using var key = SshPrivateKey.Parse(SshTestKeyMaker.Ed25519Pem(seed));

        Assert.Equal(SshPublicKey.Ed25519Blob(Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")), key.PublicBlob);
    }

    [Fact]
    public void Rfc8410V2Key_WithAnAttributeAndItsPublicKey_Loads()
    {
        using var key = SshPrivateKey.Parse(Pem(Convert.FromBase64String(Rfc8410V2)));

        Assert.Equal(SshPublicKey.Ed25519Blob(Convert.FromHexString(Rfc8410Public)), key.PublicBlob);
    }

    [Fact]
    public void Rfc8410V2Key_WhosePublicKeyDiffers_IsRefused()
    {
        var der = Convert.FromBase64String(Rfc8410V2);
        der[^1] ^= 1; // the last byte of the embedded public key

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(der)));

        Assert.Contains("public key", ex.Message);
    }

    [Fact]
    public void NamedCurveEcKey_Loads()
    {
        using var key = SshPrivateKey.Parse(Pem(Convert.FromBase64String(NamedP256)));

        Assert.Equal(P256Blob(), key.PublicBlob);
    }

    [Fact]
    public void ExplicitParameterEcKey_ThatIsExactlyP256_Loads()
    {
        using var key = SshPrivateKey.Parse(Pem(Convert.FromBase64String(ExplicitP256)));

        Assert.Equal(SshKeyType.EcdsaP256, key.Type);
        Assert.Equal(P256Blob(), key.PublicBlob);
    }

    [Theory]
    [InlineData("b")]
    [InlineData("order")]
    [InlineData("generator")]
    public void ExplicitParameterEcKey_ThatIsNotExactlyACurveWeSupport_IsRefused(string tamper)
    {
        var der = Convert.FromBase64String(ExplicitP256);
        var hex = Convert.ToHexString(der);
        var target = tamper switch
        {
            "b" => "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "order" => "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            _ => "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        };
        var at = hex.IndexOf(target, StringComparison.Ordinal);
        Assert.True(at >= 0);
        der[at / 2 + 4] ^= 0x01; // one bit inside that parameter

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(der)));

        Assert.Contains("curve", ex.Message);
    }

    [Fact]
    public void EcKeyWhoseInnerPublicKeyDiffers_IsRefused()
    {
        var der = Convert.FromBase64String(NamedP256);
        der[^1] ^= 1; // the last byte of ECPrivateKey's [1] public key

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(der)));

        Assert.Contains("public key", ex.Message);
    }

    /// <summary>The named P-256 key rewritten as an RFC 5958 v2 OneAsymmetricKey with the outer [1] publicKey.</summary>
    private static byte[] V2WithOuterPublicKey(byte[] publicPoint)
    {
        var reader = new System.Formats.Asn1.AsnReader(Convert.FromBase64String(NamedP256), System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        reader.ReadInteger();
        var algorithm = reader.ReadEncodedValue().ToArray();
        var privateKey = reader.ReadOctetString();
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteEncodedValue(algorithm);
            writer.WriteOctetString(privateKey);
            writer.WriteBitString(publicPoint, 0, new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 1));
        }
        return writer.Encode();
    }

    [Fact]
    public void V2EcKey_WithItsPublicKey_Loads()
    {
        using var key = SshPrivateKey.Parse(Pem(V2WithOuterPublicKey(Convert.FromHexString(P256Q))));

        Assert.Equal(P256Blob(), key.PublicBlob);
    }

    [Fact]
    public void V2EcKey_WhoseOuterPublicKeyDiffers_IsRefused()
    {
        var q = Convert.FromHexString(P256Q);
        q[^1] ^= 1;

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(V2WithOuterPublicKey(q))));

        Assert.Contains("public key", ex.Message);
    }
}
