using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T24 task 2: <c>sudo tswap slot add --secure-enclave --with-touch|--no-touch</c>, task 1's command for this
/// Mac's Secure Enclave (simulated, so it runs on Linux CI too). Task 1's scenarios
/// (<see cref="SlotAddHardwareScenarios"/>) with a with-touch slot, plus the touch choice. The owner checks the real
/// Secure Enclave on the Mac.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class SlotAddSecureEnclaveTests : IDisposable
{
    private readonly SlotAddHardwareScenarios _s = new(HardwareBackend.SecureEnclave);

    public void Dispose() => _s.Dispose();

    [Fact] public void SlotAddSecureEnclave_ThenTheSecureEnclaveAloneOpensTheVault() => _s.ThenTheChipAloneOpensTheVault();
    [Fact] public void SlotAddSecureEnclave_TheExistingYubiKeySlotStillOpens() => _s.TheExistingYubiKeySlotStillOpens();
    [Fact] public void SlotAddSecureEnclave_Password_OnAVaultWithoutOne_CreatesTheFirstPassword() => _s.Password_OnAVaultWithoutOne_CreatesTheFirstPassword();
    [Fact] public void SlotAddSecureEnclave_Password_Wrong_NothingWritten() => _s.Password_Wrong_NothingWritten();
    [Fact] public void SlotAddSecureEnclave_FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused() => _s.FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused();
    [Fact] public void SlotAddSecureEnclave_NoTerminal_NoFlag_AddsAPasswordFreeSlot() => _s.NoTerminal_NoFlag_AddsAPasswordFreeSlot();
    [Fact] public void SlotAddSecureEnclave_WorkingSecureEnclaveSlotAlready_Refused_NothingWritten() => _s.WorkingChipSlotAlready_Refused_NothingWritten();
    [Fact] public void SlotAddSecureEnclave_WorkingPasswordSecureEnclaveSlot_NoPasswordAtHand_Refused() => _s.WorkingPasswordChipSlot_NoPasswordAtHand_Refused();
    [Fact] public void SlotAddSecureEnclave_DeadOwnSecureEnclaveSlot_AddsANewOne() => _s.DeadOwnChipSlot_AddsANewOne();
    [Fact] public void SlotAddSecureEnclave_DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce() => _s.DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce();
    [Fact] public void SlotAddSecureEnclave_ReplacedSecureEnclave_Refused_NamesRecover() => _s.ClearedChip_Refused_NamesRecover();
    [Fact] public void SlotAddSecureEnclave_OwnSlotCheck_HardwareError_Refused_NothingWritten() => _s.OwnSlotCheck_HardwareError_Refused_NothingWritten();
    [Fact] public void SlotAddSecureEnclave_WrongPasswordForTheOwnSlotCheck_Refused_NothingWritten() => _s.WrongPasswordForTheOwnSlotCheck_Refused_NothingWritten();
    [Fact] public void SlotAddSecureEnclave_WorkingSecureEnclaveSlot_RefusedBeforeAnyPasswordStep() => _s.WorkingChipSlot_RefusedBeforeAnyPasswordStep();
    [Fact] public void SlotAddSecureEnclave_NoWayIn_RefusedBeforeAnyPasswordStep() => _s.NoWayIn_RefusedBeforeAnyPasswordStep();
    [Fact] public void SlotAddSecureEnclave_FirstPasswordGuard_BeforeAnyPrompt() => _s.FirstPasswordGuard_BeforeAnyPrompt();
    [Fact] public void SlotAddSecureEnclave_LegacyPairOwnSlot_Refused() => _s.LegacyPairOwnSlot_Refused();
    [Fact] public void SlotAddSecureEnclave_NoWayIn_Refused_NothingWritten() => _s.NoWayIn_Refused_NothingWritten();
    [Fact] public void SlotAddSecureEnclave_ClassicVault_Refused() => _s.ClassicVault_Refused();
    [Fact] public void SlotAddSecureEnclave_WithoutSudo_Refused() => _s.WithoutSudo_Refused();
    [Fact] public void SlotAddSecureEnclave_RecoveryKeyStdin_Works() => _s.RecoveryKeyStdin_Works();

    [Fact]
    public void SlotAddSecureEnclave_WithTouchOwnSlot_SaysTheCheckMayPrompt()
    {
        _s.ChipVault(password: false);
        var own = SlotAddHardwareScenarios.ShortId(_s.OwnSlot());

        var (exit, stdout, _) = _s.M.Run("", _s.Add("--no-password"));

        Assert.NotEqual(0, exit); // the slot still works
        Assert.Contains($"Checking whether this Mac's Secure Enclave slot {own} still opens the vault (Touch ID or password).", stdout);
    }

    [Theory]
    [InlineData]
    [InlineData("--no-password")]
    [InlineData("--password", "--recovery-key-stdin")]
    public void SlotAddSecureEnclave_NeitherTouchFlag_IsAUsageError(params string[] more)
    {
        _s.YubiKeyVault();
        var before = _s.Snapshot();
        var stdin = "anything\n";

        var (exit, _, stderr, calls) = _s.Observed(() => _s.M.Run(stdin, ["slot", "add", "--secure-enclave", .. more]));

        Assert.Equal(1, exit);
        Assert.Contains("Usage: tswap slot add --yubikey|--fido2|--tpm|--secure-enclave --with-touch|--no-touch", stderr);
        Assert.Contains("--secure-enclave needs exactly one of --with-touch", stderr);
        Assert.Contains("or --no-touch", stderr);
        Assert.Equal(stdin, _s.M.LastConsole!.In.ReadToEnd()); // nothing read
        Assert.Empty(calls);
        _s.AssertNothingWritten(before);
    }

    [Fact]
    public void SlotAddSecureEnclave_NoTouch_WarnsFirst_AndRecordsIt()
    {
        using var noTouch = new SlotAddHardwareScenarios(HardwareBackend.SecureEnclave, withTouch: false);
        noTouch.YubiKeyVault();

        var (exit, text) = noTouch.M.RunInterleaved("", noTouch.Add("--no-password"));

        Assert.True(exit == 0, text);
        var warning = text.IndexOf("WARNING (--no-touch): this Mac's Secure Enclave slot will unlock the vault without Touch ID or a password.", StringComparison.Ordinal);
        Assert.True(warning >= 0, text);
        Assert.True(warning < text.IndexOf("Previous config backed up to", StringComparison.Ordinal), text);
        Assert.False(noTouch.M.Config.RequiresTouch);
        Assert.Contains("Secure Enclave slot: no touch (unlocks without Touch ID or password)", text);

        // --with-touch records presence.
        _s.YubiKeyVault();
        var withTouchOut = _s.M.Ok("", _s.Add("--no-password"));
        Assert.True(_s.M.Config.RequiresTouch);
        Assert.Contains("Secure Enclave slot: touch (Touch ID or password on every unlock)", withTouchOut);
    }
}
