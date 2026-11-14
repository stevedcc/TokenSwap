using TswapCli;
using TswapCore;
using Xunit;

namespace TswapTests;

public class SecurityWarningsTests
{
    [Fact]
    public void WarnIfNoTouch_YubiKeyWithoutTouch_Warns()
    {
        var console = new FakeConsole();
        var config = new Config([1, 2], "aabb", TestTime.Fixed, RequiresTouch: false);

        SecurityWarnings.WarnIfNoTouch(console, config);

        Assert.Contains("YubiKey", console.ErrorText);
    }

    [Fact]
    public void WarnIfNoTouch_NonYubiKeyBackend_NeverWarns()
    {
        // TPM/Secure Enclave vaults have no YubiKeys at all; the YubiKey-specific wording
        // ("your YubiKeys", "tswap migrate") would be actively misleading for them, and
        // each backend already prints its own presence caveats at init time.
        var console = new FakeConsole();
        var tpmConfig = new Config([], "", TestTime.Fixed, RequiresTouch: false, Backend: HardwareBackend.Tpm);

        SecurityWarnings.WarnIfNoTouch(console, tpmConfig);

        Assert.Equal("", console.ErrorText);
    }

    /// <summary>
    /// FIDO2 plan, task 2 row 10: a FIDO2 slot always asks for a PIN and a touch, so it has no touch posture to warn
    /// about; the OTP slot beside it keeps its warning.
    /// </summary>
    [Fact]
    public void Warnings_Fido2SlotNeverWarns()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(TswapTests.SimulatedYubiKeyService.WithKeys(11111111), 11111111, requiresTouch: false);
        slots.AddFido2(Fido2TestSlots.Blob());
        var config = slots.Config(own: otp);

        var current = SecurityWarnings.Current(config);
        var changed = SecurityWarnings.Changed(config);

        var posture = Assert.Single(current);
        Assert.Equal($"YubiKey 11111111 (slot {Fido2TestSlots.Id8(otp)})", posture.Label);
        Assert.Equal(SecurityWarnings.NoTouch, posture.Posture);
        Assert.Equal(posture, Assert.Single(changed).Slot);
    }
}
