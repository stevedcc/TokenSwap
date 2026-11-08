using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>FIDO2 plan, task 2 row 7: the agent never uses a FIDO2 slot, so its serial isn't one of the password keys.</summary>
public class AgentUnlockTests
{
    [Fact]
    public void AgentPasswordSerials_SkipFido2()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(11111111), 11111111, requiresPassword: true);
        slots.AddFido2(Fido2TestSlots.Blob(Fido2TestSlots.Fido2Serial, requiresPassword: true));

        var serials = AgentUnlock.PasswordYubiKeySerials(slots.Config(own: otp));

        Assert.Equal([11111111], serials);
    }
}
