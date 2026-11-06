using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 8: <c>yubikey setup --replace</c> counts a FIDO2 slot as another way into the vault only when it
/// opens now (the key's FIDO2 PIN and a touch, then the slot unwrapped). A wrong PIN, a cancelled prompt or no terminal
/// means it doesn't count, and the refusal names it. Reprogramming OTP slot 2 never touches the key's FIDO2 credentials,
/// so the same key's FIDO2 slot is a way in.
/// </summary>
public sealed class YubiKeySetupFido2Tests : IDisposable
{
    private const int SerialA = 41111111;
    private const int SerialB = 42222222;
    private const string Pin = FakeFido2Keys.DefaultPin;

    private readonly FleetMachine _m = new("setup-fido2", SimulatedYubiKeyService.WithKeys(SerialA))
    {
        Fido2Keys = new FakeFido2Keys(),
        Terminal = new FakeTerminal(),
    };

    public void Dispose() => _m.Dispose();

    private FakeFido2Keys Fido2 => _m.Fido2Keys!;

    /// <summary>A vault opened by YubiKey A's OTP slot and its FIDO2 slot (no recovery slot): nothing else gets in.</summary>
    private void VaultOnAOtpAndFido2()
    {
        _m.Ok("", "init", "--yubikey", "--no-recovery");
        _m.Ok("s3cret\ns3cret\n", "add", "tok");
        Fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        _m.Ok("", "slot", "add", "--fido2");
        Fido2.Calls.Clear();
        _m.Sudo = false; // setup needs no sudo
    }

    private (int Exit, string Out, string Err) SetupReplace() =>
        _m.RunOnTerminal($"{SerialA}\n", "yubikey", "setup", "--touch", "--replace", "--serial", $"{SerialA}");

    [Fact]
    public void SetupReplace_Fido2SlotCountsOnlyIfItOpensNow()
    {
        VaultOnAOtpAndFido2();
        _m.Terminal!.Enqueue(Pin);

        var (exit, stdout, stderr) = SetupReplace();

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal([(SerialA, true)], _m.Keys.Programmed);
        Assert.Contains(TswapCli.Commands.YubiKeyCommand.CheckingFido2Text, stderr);
        // The PIN was asked at the terminal, and the key answered once (a touch).
        Assert.Equal($"FIDO2 PIN for YubiKey {SerialA}: ", _m.Terminal.Reads[^1].Prompt[^$"FIDO2 PIN for YubiKey {SerialA}: ".Length..]);
        Assert.Equal(1, Fido2.Calls.Count(c => c.Op == FakeFido2Op.GetHmacSecret));
        Assert.Contains(Fido2Texts.TouchLine, stderr);
    }

    public static TheoryData<string> Failures => ["wrong PIN", "cancelled", "no terminal"];

    [Theory]
    [MemberData(nameof(Failures))]
    public void SetupReplace_Fido2SlotThatDoesNotOpenNow_DoesNotCount(string failure)
    {
        VaultOnAOtpAndFido2();
        string reason;
        switch (failure)
        {
            case "wrong PIN":
                _m.Terminal!.Enqueue("000000");
                reason = Fido2Texts.PinWrong($"YubiKey {SerialA}", 7);
                break;
            case "cancelled":
                _m.Terminal!.Enqueue("");
                reason = Fido2Texts.Cancelled($"YubiKey {SerialA}");
                break;
            default:
                _m.Terminal = null;
                reason = Fido2Texts.NoTerminal;
                break;
        }

        var (exit, stdout, stderr) = SetupReplace();

        Assert.NotEqual(0, exit);
        Assert.Empty(_m.Keys.Programmed);
        Assert.Contains(
            $"Refusing: apart from YubiKey {SerialA}, only the vault's FIDO2 slot (YubiKey {SerialA}) can open the vault in {_m.Dir}, " +
            $"and it didn't open now: {reason} Nothing was changed.", stderr);
        if (failure == "no terminal")
            Assert.Empty(Fido2.Calls);
        Assert.DoesNotContain("Programming", stdout + stderr);
    }

    [Fact]
    public void SetupReplace_OtherKeysOtpSlotOpens_NoPinAsked()
    {
        // Another key's OTP slot opens: the FIDO2 slot is never checked (no PIN try spent, no touch).
        _m.Keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        VaultOnAOtpAndFido2();
        _m.Sudo = true;
        _m.Ok("", "slot", "add", "--yubikey");
        _m.Sudo = false;
        Fido2.Calls.Clear();
        var reads = _m.Terminal!.Reads.Count;

        var (exit, stdout, stderr) = SetupReplace();

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal([(SerialA, true)], _m.Keys.Programmed);
        Assert.Contains(_m.Keys.Challenges, c => c.Serial == SerialB);
        Assert.DoesNotContain(TswapCli.Commands.YubiKeyCommand.CheckingFido2Text, stderr);
        Assert.Equal(reads, _m.Terminal.Reads.Count);
        Assert.Empty(Fido2.Calls);
    }

    [Fact]
    public void SetupReplace_RecoverySlot_NoPinAsked()
    {
        // A recovery slot opens the vault by itself: the FIDO2 slot is never checked. (A TPM slot takes the same
        // ByItself branch, but the simulated TPM's blob isn't in a real TPM package's shape, so it can't stand in here.)
        _m.Ok("", "init", "--yubikey");
        Fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        _m.Ok("", "slot", "add", "--fido2");
        Fido2.Calls.Clear();
        _m.Sudo = false;
        var reads = _m.Terminal.Reads.Count;

        var (exit, stdout, stderr) = SetupReplace();

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal([(SerialA, true)], _m.Keys.Programmed);
        Assert.DoesNotContain(TswapCli.Commands.YubiKeyCommand.CheckingFido2Text, stderr);
        Assert.Equal(reads, _m.Terminal.Reads.Count);
        Assert.Empty(Fido2.Calls);
    }

    [Fact]
    public void SetupReplace_OtherKeyNotPlugged_Fido2Opens_Proceeds()
    {
        // Another key's OTP slot that can't be checked here, and A's FIDO2 slot that opens now: setup goes on.
        _m.Keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        VaultOnAOtpAndFido2();
        _m.Sudo = true;
        _m.Ok("", "slot", "add", "--yubikey");
        _m.Sudo = false;
        _m.Keys.PluggedIn = [SerialA];
        Fido2.Calls.Clear();
        _m.Terminal!.Enqueue(Pin);

        var (exit, stdout, stderr) = SetupReplace();

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal([(SerialA, true)], _m.Keys.Programmed);
    }

    [Fact]
    public void SetupReplace_OtherKeyNotPlugged_Fido2Fails_NamesBoth()
    {
        _m.Keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        VaultOnAOtpAndFido2();
        _m.Sudo = true;
        _m.Ok("", "slot", "add", "--yubikey");
        _m.Sudo = false;
        _m.Keys.PluggedIn = [SerialA];
        Fido2.Calls.Clear();
        _m.Terminal!.Enqueue("");

        var (exit, _, stderr) = SetupReplace();

        Assert.NotEqual(0, exit);
        Assert.Empty(_m.Keys.Programmed);
        Assert.Contains($"YubiKey {SerialB} can't be checked here: plug it in so its slot can be checked.", stderr);
        Assert.Contains($"The vault's FIDO2 slot (YubiKey {SerialA}) didn't open now: {Fido2Texts.Cancelled($"YubiKey {SerialA}")}", stderr);
        Assert.Contains("Nothing was changed.", stderr);
    }
}
