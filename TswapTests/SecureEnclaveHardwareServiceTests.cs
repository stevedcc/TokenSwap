using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Secure Enclave backend tests — <b>skeletons</b>. They are trait-gated
/// (<c>Category=SecureEnclave</c>) and excluded from the default and <c>--unit</c> runs
/// because they need a real Mac with a physical Secure Enclave and will prompt for
/// biometry/presence. Run them explicitly on a Mac:
/// <code>
///   ./runtests.sh --secure-enclave
///   # or: dotnet test ./TswapTests/TswapTests.csproj --filter Category=SecureEnclave
/// </code>
///
/// To complete the backend: implement <see cref="SecureEnclaveHardwareService"/> (see its
/// class doc comment + <c>HARDWARE_BACKENDS.md</c> + <c>MULTI_MACHINE_KEYING.md</c>), then
/// remove the <c>Skip</c> from each fact and fill in the body. The <c>[Trait]</c> keeps them
/// out of Linux/Windows CI even after the <c>Skip</c> is gone.
/// </summary>
[SupportedOSPlatform("macos")]
[Trait("Category", "SecureEnclave")]
public class SecureEnclaveHardwareServiceTests
{
    [Fact(Skip = "Implement SecureEnclaveHardwareService.Wrap/Unwrap first (macOS + Secure Enclave).")]
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

    [Fact(Skip = "Implement SecureEnclaveHardwareService.Unlock first (needs the keyring/slot format).")]
    public void Unlock_RecoversVaultKeyFromSlot()
    {
        // TODO: build a Config carrying a Secure-Enclave slot (Wrap of a known K_v), then
        // assert Unlock(config, _) returns that K_v. Depends on the slot format in
        // MULTI_MACHINE_KEYING.md; chooseSerial is irrelevant for the Enclave.
        var svc = new SecureEnclaveHardwareService();
        _ = svc; // placeholder until the slot format lands
    }

    [Fact(Skip = "Implement the biometry/presence path; assert the prompt is required to unwrap.")]
    public void Unwrap_RequiresUserPresence()
    {
        // TODO: with a presence/biometry access-control policy, Unwrap must fail (or block for
        // the prompt) without user presence. Shape this around how the CI/interactive Mac is
        // set up; it documents the security-relevant invariant, so keep it even if manual.
    }
}
