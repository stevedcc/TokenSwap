using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 4: <see cref="SdkFido2Keys"/> against a real key. Trait-gated (<c>Category=YubiKey</c>, excluded
/// from <c>./runtests.sh</c> and <c>--unit</c>); run with <c>./runtests.sh --yubikey</c>, and only with
/// <c>TSWAP_TEST_FIDO2=1</c> set (unset, every test here skips).
///
/// <para>These tests are read-only and silent: they list the plugged-in keys (GetInfo, the PIN retry count) and send
/// the silent probe (user presence off, no PIN token) for a random credential id no key holds. None of them creates a
/// credential, asks for a PIN or a touch, or writes anything to a key. The ceremonies that do (make-credential, the
/// user-verified assertion, setting a PIN) are the owner's, through the CLI (FIDO2 plan, task 9 runbook): no
/// automated test runs them on a real key.</para>
/// </summary>
[Trait("Category", "YubiKey")]
public sealed class YubiKeyHardwareFido2Tests(ITestOutputHelper output)
{
    private const string GateVariable = "TSWAP_TEST_FIDO2";

    private bool Skip()
    {
        if (Environment.GetEnvironmentVariable(GateVariable) == "1")
            return false;
        output.WriteLine($"SKIPPED: {GateVariable} is not 1 (plug in a FIDO2 YubiKey and set it to run the read-only FIDO2 tests).");
        return true;
    }

    [Fact]
    public void RealKey_ListsAYubicoFido2Key()
    {
        if (Skip())
            return;

        var keys = new SdkFido2Keys().Find();

        Assert.Contains(keys, k => YubicoAaguids.IsYubico(k.Aaguid));
        foreach (var key in keys)
            output.WriteLine($"{Fido2SlotBlob.DisplayName(key.Serial, key.Aaguid)}: PIN set {key.PinSet}, tries left {key.PinRetries?.ToString() ?? "unknown"}");
    }

    [Fact]
    public void RealKey_ListingTwiceGivesTheSameHandles()
    {
        if (Skip())
            return;

        var keys = new SdkFido2Keys();

        Assert.Equal(keys.Find().Select(k => k.Key), keys.Find().Select(k => k.Key));
    }

    [Fact]
    public void RealKey_SilentProbeForAnUnknownCredentialFindsNoHolder()
    {
        if (Skip())
            return;

        Assert.Null(new SdkFido2Keys().FindHolder(RandomNumberGenerator.GetBytes(64)));
    }
}
