using TswapCli.Commands;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 2 row 13: <c>tswap slots</c> lists a FIDO2 slot by its key ("YubiKey N, FIDO2", the model when
/// the serial is unknown) and its password standing, never as needing a newer tswap. Task 8 gives the final text.
/// </summary>
public class SlotsCommandTests
{
    [Fact]
    public void Slots_Fido2Slot_ShowsInterimText()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(11111111), 11111111);
        var withSerial = slots.AddFido2(Fido2TestSlots.Blob(requiresPassword: true));
        var withoutSerial = slots.AddFido2(Fido2TestSlots.Blob(serial: null));

        var lines = SlotsCommand.Format(slots.Config(own: otp)).Split('\n');

        var line = Assert.Single(lines, l => l.StartsWith(Fido2TestSlots.Id8(withSerial)));
        Assert.EndsWith($"YubiKey {Fido2TestSlots.Fido2Serial}, FIDO2, vault password", line);
        var modelLine = Assert.Single(lines, l => l.StartsWith(Fido2TestSlots.Id8(withoutSerial)));
        Assert.EndsWith($"{Fido2TestSlots.ModelName}, FIDO2, no password", modelLine);
        Assert.DoesNotContain(lines, l => l.Contains(SlotsCommand.NeedsNewerTswapMark));
    }
}
