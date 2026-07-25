using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Linux TPM backend tests. Trait-gated (<c>Category=Tpm</c>) and excluded from the default
/// and <c>--unit</c> runs because they need a reachable TPM 2.0 device or simulator and the
/// <c>tpm2-tools</c> CLI installed. Run them explicitly on Linux with both available:
/// <code>
///   ./runtests.sh --tpm
///   # or: dotnet test ./TswapTests/TswapTests.csproj --filter Category=Tpm
/// </code>
///
/// <b>Dev/test setup:</b> these tests were developed and are meant to run against a software
/// TPM simulator (swtpm), not real hardware — see <c>HARDWARE_BACKENDS.md</c>'s Linux TPM
/// section and <c>TPM_LINUX_PLAN.md</c> §4 for the container setup
/// (<c>danieltrick/swtpm-docker</c>) and the <c>TPM2TOOLS_TCTI</c> environment variable that
/// points <c>tpm2-tools</c> at it. On real TPM hardware no environment variable is needed —
/// <c>tpm2-tools</c> falls back to the local device.
/// </summary>
[SupportedOSPlatform("linux")]
[Trait("Category", "Tpm")]
public class LinuxTpmHardwareServiceTests
{
    [Fact]
    public void SealUnseal_RoundTripsKey()
    {
        // The core primitive: a key sealed to the TPM must unseal back to itself, and the
        // sealed form must not be the plaintext.
        var svc = new LinuxTpmHardwareService();
        var key = RandomNumberGenerator.GetBytes(32);

        var sealedKey = svc.Seal(key);
        var recovered = svc.Unseal(sealedKey);

        Assert.Equal(key, recovered);
        Assert.NotEqual(key, sealedKey);
    }

    [Fact]
    public void Unlock_RecoversVaultKeyFromSlot()
    {
        var svc = new LinuxTpmHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var sealedKey = svc.Seal(vaultKey);

        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: Convert.ToBase64String(sealedKey));

        var recovered = svc.Unlock(config, _ => throw new InvalidOperationException("chooseSerial should not be called for TPM"));

        Assert.Equal(vaultKey, recovered);
    }

    [Fact]
    public void Unlock_MissingSealedKey_ThrowsClearError()
    {
        var svc = new LinuxTpmHardwareService();
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm);

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("tpm", ex.Message);
    }

    [Fact]
    public void Unlock_InvalidBase64_ThrowsClearError()
    {
        var svc = new LinuxTpmHardwareService();
        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: "not valid base64!!");

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("base64", ex.Message);
    }

    [Fact]
    public void Unlock_WrongLengthKey_ThrowsClearError()
    {
        // Unseal is a generic primitive (round-trips whatever was sealed, per
        // SealUnseal_RoundTripsKey), so a 16-byte payload round-trips fine at that layer.
        // Unlock specifically promises a 32-byte vault key, so it must reject this.
        var svc = new LinuxTpmHardwareService();
        var sealedKey = svc.Seal(RandomNumberGenerator.GetBytes(16));
        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: Convert.ToBase64String(sealedKey));

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("32-byte", ex.Message);
    }

    [Fact]
    public void Unseal_TooShortBlob_ThrowsClearError()
    {
        var svc = new LinuxTpmHardwareService();

        var ex = Assert.Throws<TswapException>(() => svc.Unseal(new byte[3]));
        Assert.Contains("too short", ex.Message);
    }

    [Fact]
    public void Unseal_HugeLengthPrefix_ThrowsClearErrorInsteadOfOverflowing()
    {
        // A pubLen near int.MaxValue makes the naive "4 + pubLen > wrapped.Length" bounds
        // check overflow (wraps to negative, so the comparison passes when it shouldn't),
        // reaching an oversized allocation. The fix uses a subtraction-based check instead;
        // this proves it rejects cleanly rather than attempting that allocation.
        var svc = new LinuxTpmHardwareService();
        var corrupted = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(corrupted, int.MaxValue - 1);

        var ex = Assert.Throws<TswapException>(() => svc.Unseal(corrupted));
        Assert.Contains("length prefix", ex.Message);
    }

    [Fact]
    public void Unseal_SealedOnADifferentTpm_ThrowsClearError()
    {
        // Simulates the "wrong machine" case by corrupting the private portion of a real
        // sealed blob so its TPM-checked integrity fails on load — the same failure mode as
        // loading a blob sealed under a genuinely different TPM's primary key (verified
        // manually against swtpm: both produce a "tpm:parameter(1):integrity check failed"
        // error from tpm2_load).
        var svc = new LinuxTpmHardwareService();
        var sealedKey = svc.Seal(RandomNumberGenerator.GetBytes(32));

        var pubLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(sealedKey);
        var corrupted = (byte[])sealedKey.Clone();
        for (var i = 4 + pubLen; i < corrupted.Length; i++)
            corrupted[i] ^= 0xFF;

        var ex = Assert.Throws<TswapException>(() => svc.Unseal(corrupted));
        Assert.Contains("Could not unlock", ex.Message);
    }
}
