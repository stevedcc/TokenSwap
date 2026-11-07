using System.Security.Cryptography;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Broker;

using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 8: <c>broker serve</c> can't use a FIDO2 slot (a PIN and a touch on every unlock). A machine whose
/// own slot is FIDO2 is refused at start, whatever other slots the vault has (fix round 1 ruling: a broker host needs a
/// TPM or Secure Enclave slot of its own); a machine whose own slot is a TPM starts, and its unlocks never touch the
/// vault's FIDO2 slots (no terminal, so no PIN source: no key call at all).
/// </summary>
public sealed class BrokerFido2Tests : IDisposable
{
    private const int Serial = 33060005;
    private const int OtpSerial = 44440000;
    private const string Pin = FakeFido2Keys.DefaultPin;

    private readonly FleetMachine _m = new("bk-fido2", SimulatedYubiKeyService.WithKeys())
    {
        Fido2Keys = new FakeFido2Keys(),
        Terminal = new FakeTerminal(),
    };

    public void Dispose() => _m.Dispose();

    private FakeFido2Keys Fido2 => _m.Fido2Keys!;

    private Config VaultConfig => _m.Context(new FakeConsole(""), ["slots"]).Storage.LoadConfig();

    private string ReadThroughBroker(string name)
    {
        var ctx = _m.Context(new FakeConsole(""), ["broker", "serve"]);
        var store = Assert.IsType<RecordVaultStore>(ctx.Storage);
        using var secret = new VaultBrokerSecretSource(store, ctx.Unlocker).Read(name);
        return System.Text.Encoding.UTF8.GetString(secret.Value);
    }

    private const string Password = "correct horse battery";

    public static TheoryData<string> OwnFido2Shapes => ["only FIDO2", "FIDO2 with the password", "plus a password-free OTP slot", "plus a password OTP slot"];

    [Theory]
    [MemberData(nameof(OwnFido2Shapes))]
    public void BrokerServe_Fido2OnlyMachine_RefusedAtStart(string shape)
    {
        if (OperatingSystem.IsWindows())
            return; // broker serve is Unix-only
        // Whatever other slots the vault has: this machine's own slot is FIDO2, so the broker has none of its own.
        Fido2.AddKey(Serial, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        if (shape == "FIDO2 with the password")
            _m.Ok($"{Password}\n{Password}\n", "init", "--fido2", "--password");
        else
            _m.Ok("", "init", "--fido2");
        if (shape.StartsWith("plus", StringComparison.Ordinal))
        {
            _m.Keys = SimulatedYubiKeyService.WithKeys(OtpSerial);
            _m.Terminal.Enqueue(Pin);
            if (shape == "plus a password OTP slot")
                _m.Ok($"{Password}\n{Password}\n", "slot", "add", "--yubikey", "--password");
            else
                _m.Ok("", "slot", "add", "--yubikey");
        }
        Fido2.Calls.Clear();
        var reads = _m.Terminal.Reads.Count;

        var (exit, _, stderr) = _m.Run("", "broker", "serve");

        Assert.NotEqual(0, exit);
        Assert.Contains("This machine's slot of the vault is a FIDO2 slot", stderr);
        Assert.Contains("a PIN and a touch on every unlock", stderr);
        Assert.Contains("this machine's own slot to be a TPM or Secure Enclave slot", stderr);
        Assert.Contains("'tswap slot request --tpm'", stderr);
        Assert.DoesNotContain("slot add --yubikey", stderr);
        Assert.Empty(Fido2.Calls);
        Assert.Equal(reads, _m.Terminal.Reads.Count);
        Assert.Throws<TswapException>(() => BrokerCommand.ServeStartsLocked(VaultConfig));
    }

    [Fact]
    public void BrokerServe_Fido2PlusOtherSlot_StartsAndIgnoresFido2()
    {
        _m.Tpm = RandomNumberGenerator.GetBytes(32);
        _m.Ok("", "init", "--tpm");
        _m.Ok("s3cret\ns3cret\n", "add", "tok");
        Fido2.AddKey(Serial, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        _m.Ok("", "slot", "add", "--fido2");
        Fido2.Calls.Clear();

        Assert.False(BrokerCommand.ServeStartsLocked(VaultConfig)); // starts, unlocked
        Assert.Equal("s3cret", ReadThroughBroker("tok"));
        Assert.Empty(Fido2.Calls);

        // With the TPM gone, only the FIDO2 slot is left: the broker's unlock fails without a key call or a PIN.
        _m.Tpm = RandomNumberGenerator.GetBytes(32);
        var failure = Assert.Throws<BrokerUnlockException>(() => ReadThroughBroker("tok"));
        Assert.Contains(TswapCore.Vault.Fido2.Fido2Texts.NoTerminal, failure.Message);
        Assert.Empty(Fido2.Calls);
        Assert.Empty(_m.Terminal.Reads.Skip(2));
    }

    // Final review (task 8 deferred minor): the own slot is found by its id's bytes, as the unlocker finds it, so a
    // KeyringSlotId written in a non-canonical base64 form (here with a space in it) still names the FIDO2 slot.
    [Fact]
    public void ServeStartsLocked_NonCanonicalOwnSlotId_StillFindsTheFido2Slot()
    {
        var slots = new Fido2TestSlots();
        slots.AddOtp(SimulatedYubiKeyService.WithKeys(OtpSerial), OtpSerial); // the first machine slot: not FIDO2
        var own = slots.AddFido2(Fido2TestSlots.Blob());
        var config = slots.Config(own: own);
        config = config with { KeyringSlotId = config.KeyringSlotId!.Insert(4, " ") };
        Assert.Equal(own.SlotId, Convert.FromBase64String(config.KeyringSlotId!)); // the same id

        var e = Assert.Throws<TswapException>(() => BrokerCommand.ServeStartsLocked(config));

        Assert.Contains("This machine's slot of the vault is a FIDO2 slot", e.Message);
    }
}
