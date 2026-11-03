using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 13: the Secure Enclave password slot with Touch ID as well. Trait-gated
/// (<c>Category=SecureEnclave</c>) like <see cref="SecureEnclaveHardwareServiceTests"/>: it prompts, so the
/// owner runs it on the Mac (<c>./runtests.sh --secure-enclave</c>). The no-presence cases run in CI
/// (<see cref="SecureEnclavePasswordRoundTripTests"/>).
/// </summary>
[SupportedOSPlatform("macos")]
[Trait("Category", "SecureEnclave")]
public class SecureEnclavePasswordHardwareTests
{
    [Fact]
    public void RealEnclave_TouchAndPassword_RoundTrips_WrongPasswordRefused()
    {
        // Touch the sensor when asked (twice: the right password, then possibly for the wrong one).
        using var password = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        using var wrong = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        var service = new SecureEnclaveHardwareService(requirePresence: true);
        var (kek, hwBlob) = service.Enroll(password);
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(hwBlob));
        Assert.True(SecureEnclaveSlotBlob.HasHeader(hwBlob));

        Assert.Equal(kek, service.Unlock(config, _ => 0, () => password.Clone()));

        var ex = Assert.ThrowsAny<TswapException>(() => service.Unlock(config, _ => 0, () => wrong.Clone()));
        Assert.True(ex is VaultPasswordRefusedException || ex.Message.Contains("code -8", StringComparison.Ordinal),
            $"expected the wrong-password text, or -8 if the prompt was cancelled; got: {ex.Message}");
    }
}
