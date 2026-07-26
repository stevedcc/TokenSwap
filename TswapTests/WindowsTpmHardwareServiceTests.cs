using System.Runtime.Versioning;
using System.Security.Cryptography;
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
/// <b>Dev/test setup:</b> developed and verified against a Parallels VM's virtual TPM (Windows
/// 11, ARM64) — see <c>HARDWARE_BACKENDS.md</c>'s Windows TPM section for exactly what was and
/// wasn't verified. No extra tooling/container needed, unlike Linux's swtpm setup — Windows'
/// "Microsoft Platform Crypto Provider" is built in and reached entirely via managed CNG APIs.
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
    public void Unwrap_MalformedCiphertext_ThrowsClearError()
    {
        // Right-length-for-RSA-2048 (256 bytes) but garbage content — verified manually against
        // this backend's TPM that this fails as a TPM-reported CryptographicException, not a
        // crash or silently-wrong plaintext.
        var svc = new WindowsTpmHardwareService();
        // Ensure a key exists so this exercises "malformed ciphertext" rather than "no key yet".
        svc.Wrap(RandomNumberGenerator.GetBytes(32));

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(new byte[256]));
        Assert.Contains("Could not unlock", ex.Message);
    }

    [Fact]
    public void Unwrap_WrongLengthCiphertext_ThrowsClearError()
    {
        var svc = new WindowsTpmHardwareService();
        svc.Wrap(RandomNumberGenerator.GetBytes(32));

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(new byte[8]));
        Assert.Contains("Could not unlock", ex.Message);
    }

    [Fact]
    public void Unwrap_SealedByAPriorGeneration_ThrowsClearError()
    {
        // Verified manually: re-wrapping (which overwrites the named TPM key, exactly what
        // 're-run tswap init --tpm' does) cleanly invalidates ciphertext produced under the
        // previous generation of the key, rather than silently decrypting to garbage.
        var svc = new WindowsTpmHardwareService();
        var staleWrapped = svc.Wrap(RandomNumberGenerator.GetBytes(32));
        svc.Wrap(RandomNumberGenerator.GetBytes(32)); // overwrites the named key

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(staleWrapped));
        Assert.Contains("Could not unlock", ex.Message);
    }
}
