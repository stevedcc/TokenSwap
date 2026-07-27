using System.Diagnostics;
using System.Security.Cryptography;
using TswapCore;
using Xunit;

namespace TswapTests;

public class Argon2idTests
{
    [Fact]
    public void Argon2id_CompletesWithinBudget()
    {
        var salt = RandomNumberGenerator.GetBytes(32);

        var stopwatch = Stopwatch.StartNew();
        var derived = ExportCrypto.DeriveArgon2id("correct-horse-battery-staple", salt, ExportCrypto.DefaultArgon2idParams);
        stopwatch.Stop();

        Assert.Equal(32, derived.Length);

        // The doc comment on ExportCrypto's Argon2id constants claims this is "well under a
        // second on ordinary current hardware." Budget generously (well beyond that claim) to
        // leave headroom for slower/loaded CI runners without making this flaky, while still
        // catching a regression if someone bumps the parameters to something absurdly slow.
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3),
            $"Argon2id derivation took {stopwatch.Elapsed.TotalSeconds:F2}s, expected under 3s");
    }

    [Fact]
    public void Argon2id_Deterministic()
    {
        var salt = RandomNumberGenerator.GetBytes(32);

        var k1 = ExportCrypto.DeriveArgon2id("correct-horse-battery-staple", salt, ExportCrypto.DefaultArgon2idParams);
        var k2 = ExportCrypto.DeriveArgon2id("correct-horse-battery-staple", salt, ExportCrypto.DefaultArgon2idParams);

        Assert.Equal(k1, k2);
    }
}
