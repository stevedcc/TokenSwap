using TswapCli.Commands;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 8: <c>tswap slots</c> names a FIDO2 slot's key (its serial, else the model from the AAGUID) with
/// "FIDO2: PIN + touch", and counts password-free FIDO2 slots apart from the slots that open with nothing at all.
/// <see cref="Slots_ShowsFido2"/> replaces task 2's interim test (<c>SlotsCommandTests.Slots_Fido2Slot_ShowsInterimText</c>,
/// "YubiKey N, FIDO2"), which pinned the placeholder text this task was planned to replace; same setup, final text.
/// </summary>
public class SlotsCommandFido2Tests
{
    private const string Fido2FreeLine =
        "1 FIDO2 slot(s) open without the vault password (each still needs its key's FIDO2 PIN and a touch).";

    private const string OpensWithNothingLine = "1 slot(s) open without the password: keep them away from shared machines.";

    [Fact]
    public void Slots_ShowsFido2()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(11111111), 11111111);
        var withSerial = slots.AddFido2(Fido2TestSlots.Blob(requiresPassword: true));
        var withoutSerial = slots.AddFido2(Fido2TestSlots.Blob(serial: null));

        var lines = SlotsCommand.Format(slots.Config(own: otp)).Split('\n');

        var line = Assert.Single(lines, l => l.StartsWith(Fido2TestSlots.Id8(withSerial)));
        Assert.EndsWith($"  YubiKey {Fido2TestSlots.Fido2Serial}, FIDO2: PIN + touch, vault password", line);
        var modelLine = Assert.Single(lines, l => l.StartsWith(Fido2TestSlots.Id8(withoutSerial)));
        Assert.EndsWith($"  {Fido2TestSlots.ModelName}, FIDO2: PIN + touch, no password", modelLine);
        Assert.DoesNotContain(lines, l => l.Contains(SlotsCommand.NeedsNewerTswapMark));
    }

    [Fact]
    public void Slots_PasswordFreeFido2Slot_CountedApart()
    {
        var slots = new Fido2TestSlots();
        var keys = SimulatedYubiKeyService.WithKeys(11111111, 22222222);
        var own = slots.AddOtp(keys, 11111111, requiresPassword: true);
        slots.AddOtp(keys, 22222222);
        slots.AddFido2(Fido2TestSlots.Blob());

        var lines = SlotsCommand.Format(slots.Config(own: own)).Split('\n');

        Assert.Contains(OpensWithNothingLine, lines);
        Assert.Contains(Fido2FreeLine, lines);
    }

    [Fact]
    public void Slots_OnlyFido2OpensWithoutPassword_NoKeepAwayWarning()
    {
        var slots = new Fido2TestSlots();
        var own = slots.AddOtp(SimulatedYubiKeyService.WithKeys(11111111), 11111111, requiresPassword: true);
        slots.AddFido2(Fido2TestSlots.Blob());

        var text = SlotsCommand.Format(slots.Config(own: own));

        Assert.DoesNotContain("open without the password: keep them away", text);
        Assert.Contains(Fido2FreeLine, text.Split('\n'));
    }

    [Fact]
    public void Slots_NoPasswordSlot_NoFido2CountLine()
    {
        var slots = new Fido2TestSlots();
        var own = slots.AddOtp(SimulatedYubiKeyService.WithKeys(11111111), 11111111);
        slots.AddFido2(Fido2TestSlots.Blob());

        var text = SlotsCommand.Format(slots.Config(own: own));

        Assert.DoesNotContain("without the vault password", text);
        Assert.DoesNotContain("open without the password", text);
    }

    /// <summary>Brief T19, item 4: a slot of another brand (no serial, an AAGUID that isn't Yubico's) in <c>tswap slots</c>.</summary>
    [Fact]
    public void Slots_ASlotOfAnotherBrand_IsTheSecurityKeyItWasMadeWith()
    {
        var slots = new Fido2TestSlots();
        var token2 = slots.AddFido2(Fido2SlotBlob.Create(null, Guid.Parse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"), new byte[48], requiresPassword: false));
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(11111111), 11111111);

        var lines = SlotsCommand.Format(slots.Config(own: otp)).Split('\n');

        var line = Assert.Single(lines, l => l.StartsWith(Fido2TestSlots.Id8(token2)));
        Assert.EndsWith("  the security key this slot was made with, FIDO2: PIN + touch, no password", line);
    }
}
