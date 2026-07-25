using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Secure Enclave backend tests. Trait-gated (<c>Category=SecureEnclave</c>) and excluded
/// from the default and <c>--unit</c> runs because they need a real Mac with a physical
/// Secure Enclave and will prompt for biometry/presence. Run them explicitly on a Mac:
/// <code>
///   ./runtests.sh --secure-enclave
///   # or: dotnet test ./TswapTests/TswapTests.csproj --filter Category=SecureEnclave
/// </code>
/// Each <c>Wrap</c> call creates a fresh Secure Enclave key (see
/// <c>AppleSecureEnclaveInterop</c>), so every test that calls <c>Unwrap</c> prompts for
/// Touch ID / presence separately.
/// </summary>
[SupportedOSPlatform("macos")]
[Trait("Category", "SecureEnclave")]
public class SecureEnclaveHardwareServiceTests
{
    [Fact]
    public void WrapUnwrap_RoundTripsKey()
    {
        // The core primitive: a key wrapped to the Enclave must unwrap back to itself,
        // and the wrapped form must not be the plaintext.
        var svc = new SecureEnclaveHardwareService();
        var key = RandomNumberGenerator.GetBytes(32);

        var wrapped = svc.Wrap(key);
        var recovered = svc.Unwrap(wrapped);

        Assert.Equal(key, recovered);
        Assert.NotEqual(key, wrapped);
    }

    [Fact]
    public void Unlock_RecoversVaultKeyFromSlot()
    {
        var svc = new SecureEnclaveHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = svc.Wrap(vaultKey);

        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(wrapped));

        var recovered = svc.Unlock(config, _ => throw new InvalidOperationException("chooseSerial should not be called for Secure Enclave"));

        Assert.Equal(vaultKey, recovered);
    }

    [Fact]
    public void Unlock_MissingWrappedKey_ThrowsClearError()
    {
        var svc = new SecureEnclaveHardwareService();
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave);

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("secure-enclave", ex.Message);
    }

    [Fact(Skip = "Manual: requires denying/cancelling the Touch ID prompt to assert the failure path.")]
    public void Unwrap_RequiresUserPresence()
    {
        // The Swift shim (TswapSecureEnclave.swift) creates every key with
        // [.privateKeyUsage, .userPresence] access control, so key agreement always prompts
        // for biometry/passcode. Manually verified: cancelling the prompt makes Unwrap throw
        // TswapException ("...verification failed or was cancelled"), not hang or crash. This
        // documents that invariant; verifying the *denial* path needs a human to cancel the
        // system prompt, so it stays manual rather than a CI-run fact.
    }
}
