using System.Diagnostics;
using System.Security.Cryptography;
using TswapCore.VaultPassword;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T17 task 1: the stretched vault password (rulings 1 and 5). Argon2id stretching
/// (<see cref="VaultPasswordKdf"/>) and the native, locked holder (<see cref="StretchedPassword"/>).
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class StretchedPasswordTests(ITestOutputHelper output)
{
    private static readonly byte[] Salt = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    // The cheapest parameters the decoder accepts: the determinism and normalisation tests don't
    // need the default cost, only the same derivation.
    private static readonly VaultPasswordParams Cheap = new(19456, 1, 1);

    private static byte[] Bytes(StretchedPassword stretched)
    {
        var copy = new byte[StretchedPassword.Size];
        stretched.CopyTo(copy);
        return copy;
    }

    private static byte[] StretchToBytes(string password, VaultPasswordParams p, byte[]? salt = null)
    {
        using var stretched = VaultPasswordKdf.Stretch(password, salt ?? Salt, p);
        return Bytes(stretched);
    }

    [Fact]
    public void Defaults_AreTheRulingOneParameters()
    {
        Assert.Equal(new VaultPasswordParams(65536, 3, 1), VaultPasswordParams.Default);
    }

    [Fact]
    public void Stretch_IsDeterministic_AndRespectsParams()
    {
        var a = StretchToBytes("correct horse battery staple", Cheap);
        var b = StretchToBytes("correct horse battery staple", Cheap);
        Assert.Equal(32, a.Length);
        Assert.Equal(a, b);

        Assert.NotEqual(a, StretchToBytes("correct horse battery staple", Cheap with { MemoryKiB = 20480 }));
        Assert.NotEqual(a, StretchToBytes("correct horse battery staple", Cheap with { TimeCost = 2 }));
        Assert.NotEqual(a, StretchToBytes("correct horse battery staple", Cheap with { Parallelism = 2 }));
        var otherSalt = (byte[])Salt.Clone();
        otherSalt[0] ^= 1;
        Assert.NotEqual(a, StretchToBytes("correct horse battery staple", Cheap, otherSalt));
        Assert.NotEqual(a, StretchToBytes("correct horse battery stapler", Cheap));
    }

    [Fact]
    public void Stretch_UnderOneSecond()
    {
        // Warm up the JIT and the allocator once, so the measured run is the derivation itself.
        StretchToBytes("warm-up", Cheap);

        var stopwatch = Stopwatch.StartNew();
        using var stretched = VaultPasswordKdf.Stretch("correct horse battery staple", Salt, VaultPasswordParams.Default);
        stopwatch.Stop();

        output.WriteLine($"Argon2id at the defaults (m 65536, t 3, p 1): {stopwatch.Elapsed.TotalMilliseconds:F0} ms");
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1),
            $"Stretching at the defaults took {stopwatch.Elapsed.TotalSeconds:F2} s, expected under 1 s (ruling 1)");
    }

    [Fact]
    public void Stretch_AtTheMaximum_CompletesAndIsMeasured()
    {
        var max = new VaultPasswordParams(262144, 8, 4);

        var stopwatch = Stopwatch.StartNew();
        using var stretched = VaultPasswordKdf.Stretch("correct horse battery staple", Salt, max);
        stopwatch.Stop();

        // The worst cost a planted vault-password file can impose on one unlock (ruling 1);
        // recorded in the implementation report.
        output.WriteLine($"Argon2id at the maximum (m 262144, t 8, p 4): {stopwatch.Elapsed.TotalMilliseconds:F0} ms");
        Assert.Equal(32, Bytes(stretched).Length);
        Assert.NotEqual(new byte[32], Bytes(stretched));
    }

    [Fact]
    public void WeakenedParams_DeriveDifferentBytes()
    {
        var real = StretchToBytes("correct horse battery staple", VaultPasswordParams.Default);
        var weakened = StretchToBytes("correct horse battery staple", VaultPasswordParams.Default with { TimeCost = 1 });
        Assert.NotEqual(real, weakened);
    }

    [Fact]
    public void Stretch_NfdAndNfcPasswordsAgree()
    {
        const string nfc = "pässwörd";
        const string nfd = "pässwörd";
        Assert.NotEqual(nfc, nfd); // the inputs really differ as strings

        Assert.Equal(StretchToBytes(nfc, Cheap), StretchToBytes(nfd, Cheap));
    }

    [Fact]
    public void Stretch_ZeroesItsBuffer()
    {
        byte[]? outputBuffer = null;
        byte[]? passwordBytes = null;
        VaultPasswordKdf.OutputBufferObserver = span => outputBuffer = span.ToArray();
        VaultPasswordKdf.PasswordBytesObserver = span => passwordBytes = span.ToArray();
        try
        {
            using var stretched = VaultPasswordKdf.Stretch("correct horse battery staple", Salt, Cheap);

            Assert.NotNull(outputBuffer);
            Assert.Equal(StretchedPassword.Size, outputBuffer!.Length);
            Assert.All(outputBuffer, b => Assert.Equal(0, b));
            Assert.NotNull(passwordBytes);
            Assert.Equal("correct horse battery staple".Length, passwordBytes!.Length);
            Assert.All(passwordBytes, b => Assert.Equal(0, b));
            // ...while the holder kept the derived bytes.
            Assert.NotEqual(new byte[32], Bytes(stretched));
        }
        finally
        {
            VaultPasswordKdf.OutputBufferObserver = null;
            VaultPasswordKdf.PasswordBytesObserver = null;
        }
    }

    [Fact]
    public void FromBytes_RoundTrips_AndRefusesAWrongLength()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        using var stretched = StretchedPassword.FromBytes(bytes);
        Assert.Equal(bytes, Bytes(stretched));

        Assert.Throws<ArgumentException>(() => StretchedPassword.FromBytes(new byte[31]));
        Assert.Throws<ArgumentException>(() => StretchedPassword.FromBytes(new byte[33]));
        Assert.Throws<ArgumentException>(() => stretched.CopyTo(new byte[31]));
    }

    [Fact]
    public void StretchedPassword_Dispose_ZeroesBeforeFree()
    {
        var stretched = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        var seen = new List<byte[]>();
        StretchedPassword.BeforeFreeObserver = span => seen.Add(span.ToArray());
        try
        {
            stretched.Dispose();
        }
        finally
        {
            StretchedPassword.BeforeFreeObserver = null;
        }

        var memory = Assert.Single(seen);
        Assert.Equal(StretchedPassword.Size, memory.Length);
        Assert.All(memory, b => Assert.Equal(0, b));
        Assert.Throws<ObjectDisposedException>(() => stretched.CopyTo(new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => stretched.Clone());
        stretched.Dispose(); // idempotent: no second free
    }

    [Fact]
    public void Clone_IsIndependent()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        using var original = StretchedPassword.FromBytes(bytes);
        var clone = original.Clone();
        Assert.Equal(bytes, Bytes(clone));

        clone.Dispose();

        Assert.Equal(bytes, Bytes(original));
        Assert.Throws<ObjectDisposedException>(() => clone.CopyTo(new byte[32]));
    }

    [Fact]
    public void StretchedPassword_ToString_HoldsNoBytes()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        using var stretched = StretchedPassword.FromBytes(bytes);

        var text = stretched.ToString();

        Assert.DoesNotContain(Convert.ToHexString(bytes), text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(bytes), text);
        Assert.DoesNotContain(Convert.ToHexString(bytes.AsSpan(0, 4)), text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StretchedPassword_IsLocked_OnThisMachine()
    {
        // mlock of one page is within every default RLIMIT_MEMLOCK; a failure would be a warning,
        // never a refusal (ruling 5), so this pins that the lock really is taken here.
        using var stretched = StretchedPassword.FromBytes(new byte[32]);
        Assert.True(stretched.IsLocked);
    }
}
