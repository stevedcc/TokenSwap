using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Windows TPM backend tests. Trait-gated (<c>Category=TpmWindows</c> — deliberately distinct
/// from the Linux backend's <c>Category=Tpm</c>, since both test classes compile on every OS
/// regardless of <c>[SupportedOSPlatform]</c> and must be independently excludable/runnable)
/// and excluded from the default and <c>--unit</c> runs because they need a real or virtual TPM
/// exposed through Windows' "Microsoft Platform Crypto Provider". Run them explicitly on
/// Windows:
/// <code>
///   ./runtests.sh --tpm-windows
///   # or: dotnet test ./TswapTests/TswapTests.csproj --filter Category=TpmWindows
/// </code>
///
/// Every <see cref="WindowsTpmHardwareService.Wrap"/> call creates a fresh, randomly-named TPM
/// key (see <c>PlatformCryptoProviderInterop</c>'s header comment), so these tests never touch
/// or overwrite a real vault's TPM key — no isolation setup/teardown needed.
///
/// <b>Dev/test setup:</b> developed and verified against a Parallels VM's virtual TPM (Windows
/// 11, ARM64) — see <c>HARDWARE_BACKENDS.md</c>'s Windows TPM section for exactly what was and
/// wasn't verified.
/// </summary>
[SupportedOSPlatform("windows")]
[Trait("Category", "TpmWindows")]
public class WindowsTpmHardwareServiceTests
{
    [Fact]
    public void WrapUnwrap_RoundTripsKey()
    {
        // The core primitive: a key wrapped to the TPM must unwrap back to itself, and the
        // wrapped form must not be the plaintext.
        var svc = new WindowsTpmHardwareService();
        var key = RandomNumberGenerator.GetBytes(32);

        var wrapped = svc.Wrap(key);
        var recovered = svc.Unwrap(wrapped);

        Assert.Equal(key, recovered);
        Assert.NotEqual(key, wrapped);
    }

    [Fact]
    public void Wrap_TwoCallsUseIndependentKeys()
    {
        // The fix for the real bug Copilot flagged: a fixed key name meant a second Wrap()
        // (e.g. a second vault, or just the test suite) would silently invalidate the first.
        // Each call must get its own isolated, independently-unwrappable key.
        var svc = new WindowsTpmHardwareService();
        var key1 = RandomNumberGenerator.GetBytes(32);
        var key2 = RandomNumberGenerator.GetBytes(32);

        var wrapped1 = svc.Wrap(key1);
        var wrapped2 = svc.Wrap(key2);

        Assert.Equal(key1, svc.Unwrap(wrapped1));
        Assert.Equal(key2, svc.Unwrap(wrapped2));
    }

    [Fact]
    public void Unlock_RecoversVaultKeyFromSlot()
    {
        var svc = new WindowsTpmHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = svc.Wrap(vaultKey);

        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: Convert.ToBase64String(wrapped));

        var recovered = svc.Unlock(config, _ => throw new InvalidOperationException("chooseSerial should not be called for TPM"));

        Assert.Equal(vaultKey, recovered);
    }

    [Fact]
    public void Unlock_MissingSealedKey_ThrowsClearError()
    {
        var svc = new WindowsTpmHardwareService();
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm);

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("tpm", ex.Message);
    }

    [Fact]
    public void Unlock_InvalidBase64_ThrowsClearError()
    {
        var svc = new WindowsTpmHardwareService();
        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: "not valid base64!!");

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("base64", ex.Message);
    }

    [Fact]
    public void Unlock_WrongLengthKey_ThrowsClearError()
    {
        // Unwrap is a generic primitive (round-trips whatever was wrapped, per
        // WrapUnwrap_RoundTripsKey), so a 16-byte payload round-trips fine at that layer.
        // Unlock specifically promises a 32-byte vault key, so it must reject this.
        var svc = new WindowsTpmHardwareService();
        var wrapped = svc.Wrap(RandomNumberGenerator.GetBytes(16));
        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: Convert.ToBase64String(wrapped));

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("32-byte", ex.Message);
    }

    [Fact]
    public void Unwrap_TooShortBlob_ThrowsClearError()
    {
        var svc = new WindowsTpmHardwareService();

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(new byte[3]));
        Assert.Contains("too short", ex.Message);
    }

    [Fact]
    public void Unwrap_HugeLengthPrefix_ThrowsClearErrorInsteadOfOverflowing()
    {
        // A nameLen near int.MaxValue makes the naive "4 + nameLen > wrapped.Length" bounds
        // check overflow (wraps to negative, so the comparison passes when it shouldn't),
        // reaching an oversized allocation/read. The fix uses a subtraction-based check
        // instead; this proves it rejects cleanly rather than attempting that read.
        var svc = new WindowsTpmHardwareService();
        var corrupted = new byte[8];
        BinaryPrimitives.WriteInt32LittleEndian(corrupted, int.MaxValue - 1);

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(corrupted));
        Assert.Contains("length prefix", ex.Message);
    }

    [Fact]
    public void Unwrap_KeyDoesNotExist_ThrowsClearError()
    {
        // A blob whose embedded key name was never created by Wrap() — simulates either a
        // corrupted blob or a genuinely different machine, since real TPM key names never
        // collide across machines/processes (random per Wrap() call).
        var svc = new WindowsTpmHardwareService();
        var fakeName = Encoding.UTF8.GetBytes("tswap-vault-key-does-not-exist-" + Guid.NewGuid().ToString("N"));
        var fakeCiphertext = new byte[256];
        var blob = new byte[4 + fakeName.Length + fakeCiphertext.Length];
        BinaryPrimitives.WriteInt32LittleEndian(blob, fakeName.Length);
        fakeName.CopyTo(blob, 4);

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(blob));
        Assert.Contains("no matching TPM key", ex.Message);
    }

    [Fact]
    public void Unwrap_MalformedCiphertext_ThrowsClearError()
    {
        // A blob with a real, existing key name (so it passes the "does the key exist" check)
        // but corrupted ciphertext content — verified manually against this backend's TPM that
        // this fails as a TPM-reported CryptographicException, not a crash or silently-wrong
        // plaintext.
        var svc = new WindowsTpmHardwareService();
        var wrapped = svc.Wrap(RandomNumberGenerator.GetBytes(32));
        var nameLen = BinaryPrimitives.ReadInt32LittleEndian(wrapped);

        var corrupted = (byte[])wrapped.Clone();
        Array.Clear(corrupted, 4 + nameLen, corrupted.Length - (4 + nameLen));

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(corrupted));
        Assert.Contains("Could not unlock", ex.Message);
    }

    [Fact]
    public void Unwrap_WrongLengthCiphertext_ThrowsClearError()
    {
        var svc = new WindowsTpmHardwareService();
        var wrapped = svc.Wrap(RandomNumberGenerator.GetBytes(32));
        var nameLen = BinaryPrimitives.ReadInt32LittleEndian(wrapped);

        // Keep the real (existing) key name, but truncate the ciphertext portion.
        var truncated = wrapped.AsSpan(0, 4 + nameLen + 8).ToArray();

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(truncated));
        Assert.Contains("Could not unlock", ex.Message);
    }
}
