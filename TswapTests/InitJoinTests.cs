using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>FIDO2 plan, task 2 row 11: <c>init --vault-dir</c>'s summary counts a FIDO2 slot as a YubiKey (it is one).</summary>
public sealed class InitJoinTests : IDisposable
{
    private const int Serial = 41111111;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(Serial);
    private readonly FleetMachine _home;
    private readonly FleetMachine _laptop;
    private readonly string _shared;

    public InitJoinTests()
    {
        _home = new FleetMachine("fido2-join-home", _keys);
        _laptop = new FleetMachine("fido2-join-laptop", _keys);
        _shared = Path.Combine(_home.Dir, "Sync", "tswap");
        _home.Ok("", "init", "--yubikey", "--folder", _shared);
    }

    public void Dispose()
    {
        _home.Dispose();
        _laptop.Dispose();
    }

    [Fact]
    public void Join_SummaryCountsFido2AsYubiKey()
    {
        var keyringPath = Path.Combine(_shared, RecordVaultStore.KeyringFileName);
        var keyring = Fido2TestSlots.WithFido2Slot(KeyringCodec.Decode(File.ReadAllBytes(keyringPath)), Fido2TestSlots.Blob());
        File.WriteAllBytes(keyringPath, KeyringCodec.Encode(keyring));

        var stdout = _laptop.Ok("", "init", "--vault-dir", _shared);

        Assert.Contains($"({keyring.Slots.Count} slot(s), 2 of them YubiKeys or other security keys)", stdout);
    }
}
