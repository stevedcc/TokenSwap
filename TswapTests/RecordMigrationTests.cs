using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>FIDO2 plan, task 2 rows 8 and 9: <c>migrate --to-records</c> reads FIDO2 slots without failing on them.</summary>
public sealed class RecordMigrationTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-migration-fido2-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>A plain XOR vault's converted copy is still recognised by its OTP slots when the copy also holds FIDO2 slots.</summary>
    [Fact]
    public void ConvertedCopy_IgnoresFido2Slots()
    {
        var slots = new Fido2TestSlots();
        slots.AddOtp(_keys, SerialA);
        slots.AddFido2(Fido2TestSlots.Blob(SerialA));
        slots.AddOtp(_keys, SerialB);
        slots.AddFido2(Fido2TestSlots.Blob(serial: null));
        slots.AddRecovery();
        File.WriteAllBytes(Path.Combine(_dir, RecordVaultStore.KeyringFileName), KeyringCodec.Encode(slots.Keyring));
        var classic = new Config([SerialB, SerialA], "xor", DateTime.UtcNow);

        var copy = RecordMigration.LooksLikeOwnConvertedCopy(DirectoryOwnerMatcher.Default, _dir, classic);

        Assert.Equal(RecordMigration.ConvertedCopy.SameYubiKeys, copy);
    }

    /// <summary>A FIDO2 slot is not checked after the conversion (it needs the key's PIN and a touch), and is not a failure.</summary>
    [Fact]
    public void Verify_Fido2Slot_NotCheckedNotFailed()
    {
        var slots = new Fido2TestSlots();
        slots.AddOtp(_keys, SerialA);
        var fido2 = slots.AddFido2(Fido2TestSlots.Blob());
        slots.AddRecovery();

        var check = RecordMigration.CheckSlots(_keys, slots.Keyring, slots.VaultKey, slots.RecoveryPrivateKey);

        Assert.Empty(check.Problems);
        Assert.Equal([$"Slot {Fido2TestSlots.Id8(fido2)} (FIDO2): not checked here (needs the key's PIN and a touch)."], check.Notes);
    }

    /// <summary>With nothing but FIDO2 slots, the check says it checked nothing rather than that everything opened.</summary>
    [Fact]
    public void Verify_OnlyFido2Slots_SaysNothingWasChecked()
    {
        var slots = new Fido2TestSlots();
        slots.AddFido2(Fido2TestSlots.Blob());

        var check = RecordMigration.CheckSlots(_keys, slots.Keyring, slots.VaultKey, recoveryPrivateKey: null);

        Assert.Empty(check.Problems);
        Assert.Contains(check.Notes, n => n.Contains("nothing here was checked"));
    }

    /// <summary>The control: an OTP slot that doesn't open is still a problem.</summary>
    [Fact]
    public void Verify_OtpSlotThatDoesNotOpen_IsAProblem()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(_keys, SerialA);
        _keys.PluggedIn = [];

        var check = RecordMigration.CheckSlots(_keys, slots.Keyring, slots.VaultKey, recoveryPrivateKey: null);

        Assert.Contains(check.Problems, p => p.StartsWith($"slot {Fido2TestSlots.Id8(otp)} does not open"));
        Assert.Empty(check.Notes);
    }
}
