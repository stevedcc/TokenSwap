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
/// own slot is FIDO2, with no YubiKey OTP slot besides, is refused at start; a vault that also has a slot the broker can
/// use starts, and its unlocks never touch the FIDO2 slots (no terminal, so no PIN source: no key call at all).
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

    [Fact]
    public void BrokerServe_Fido2OnlyMachine_RefusedAtStart()
    {
        if (OperatingSystem.IsWindows())
            return; // broker serve is Unix-only
        Fido2.AddKey(Serial, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        _m.Ok("", "init", "--fido2");
        Fido2.Calls.Clear();

        var (exit, _, stderr) = _m.Run("", "broker", "serve");

        Assert.NotEqual(0, exit);
        Assert.Contains(BrokerCommand.Fido2OnlyText, stderr);
        Assert.Empty(Fido2.Calls);
        Assert.Equal(
            "This machine's slot of the vault is a FIDO2 slot: it needs the key's PIN and a touch on every unlock, so the " +
            "broker can't use it. A broker opens the vault with a TPM, Secure Enclave or YubiKey OTP slot (no PIN): add a " +
            "YubiKey OTP slot with 'sudo tswap slot add --yubikey', or run the broker on a machine whose own slot is a TPM " +
            "or Secure Enclave slot.", BrokerCommand.Fido2OnlyText);
    }

    [Fact]
    public void BrokerServe_Fido2OnlyMachine_WithPasswordToo_RefusedAtStart()
    {
        // A FIDO2 own slot with the vault password reads as a password slot; it is refused all the same.
        Fido2.AddKey(Serial, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        _m.Ok("correct horse battery\ncorrect horse battery\n", "init", "--fido2", "--password");

        var ex = Assert.Throws<TswapException>(() => BrokerCommand.ServeStartsLocked(VaultConfig));

        Assert.Equal(BrokerCommand.Fido2OnlyText, ex.Message);
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

    [Fact]
    public void BrokerServe_OwnFido2PlusOtpSlot_StartsWithTheOtpSlot()
    {
        Fido2.AddKey(Serial, Fido2TestSlots.Aaguid);
        _m.Terminal!.Enqueue(Pin, Pin);
        _m.Ok("", "init", "--fido2");
        _m.Terminal.Enqueue(Pin);
        _m.Ok("s3cret\ns3cret\n", "add", "tok");
        _m.Keys = SimulatedYubiKeyService.WithKeys(OtpSerial);
        _m.Terminal.Enqueue(Pin);
        _m.Ok("", "slot", "add", "--yubikey");
        Fido2.Calls.Clear();

        Assert.False(BrokerCommand.ServeStartsLocked(VaultConfig));
        Assert.Equal("s3cret", ReadThroughBroker("tok"));
        Assert.Empty(Fido2.Calls);
    }
}
