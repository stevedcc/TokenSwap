using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 2 rows 5 and 6: the unlocker's classification keeps FIDO2 slots apart from the OTP slots (task 7
/// adds the pass that tries them).
/// </summary>
public class VaultUnlockerFido2Tests
{
    private const int OtpSerial = 11111111;

    [Fact]
    public void Classify_Fido2NotAnOtpCandidate()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(OtpSerial), OtpSerial);
        var fido2Blob = Fido2TestSlots.Blob(requiresPassword: true);
        var fido2 = slots.AddFido2(fido2Blob);
        slots.AddRecovery();

        var plan = VaultUnlocker.Classify(slots.Config(own: otp), slots.Keyring, excludeSerial: null);

        var candidate = Assert.Single(plan.YubiKeyCandidates);
        Assert.Equal(otp.SlotId, candidate.Slot.SlotId);
        Assert.Equal(1, plan.YubiKeySlotCount);
        Assert.Empty(plan.PasswordSerials);
        Assert.Equal("", plan.SetAsideSuffix); // not "needs a newer tswap"
        var (slot, blob) = Assert.Single(plan.Fido2Candidates);
        Assert.Equal(fido2.SlotId, slot.SlotId);
        Assert.Equal(fido2Blob.CredentialId, blob.CredentialId);
        Assert.Equal(fido2Blob.PrfInput, blob.PrfInput);
        Assert.True(blob.RequiresPassword);
    }

    /// <summary>The excluded key's OTP slots are left out; its FIDO2 slot stays a candidate (task 7 relies on it).</summary>
    [Fact]
    public void Classify_ExcludeSerial_KeepsThatKeysFido2Slot()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(Fido2TestSlots.Fido2Serial), Fido2TestSlots.Fido2Serial);
        var fido2 = slots.AddFido2(Fido2TestSlots.Blob(Fido2TestSlots.Fido2Serial));

        var plan = VaultUnlocker.Classify(slots.Config(own: otp), slots.Keyring, excludeSerial: Fido2TestSlots.Fido2Serial);

        Assert.Empty(plan.YubiKeyCandidates);
        Assert.Equal(fido2.SlotId, Assert.Single(plan.Fido2Candidates).Slot.SlotId);
    }

    /// <summary>A vault made by <c>init --fido2</c>: its own slot is a FIDO2 slot, so there is no own backend path.</summary>
    [Fact]
    public void InitFido2Vault_HasNoOwnBackendPath()
    {
        var slots = new Fido2TestSlots();
        var fido2 = slots.AddFido2(Fido2TestSlots.Blob());
        slots.AddRecovery();

        var plan = VaultUnlocker.Classify(slots.Config(HardwareBackend.YubiKey, own: fido2), slots.Keyring, excludeSerial: null);

        Assert.False(plan.OwnPath);
        Assert.Equal(fido2.SlotId, Assert.Single(plan.Fido2Candidates).Slot.SlotId);
        Assert.Equal("", plan.SetAsideSuffix);
    }
}
