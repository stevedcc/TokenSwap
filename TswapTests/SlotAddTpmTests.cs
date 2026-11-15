using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T24 task 1 (issue #309): <c>sudo tswap slot add --tpm</c> makes this machine's TPM its own slot in the vault
/// it already opens, with no request, approve or accept. The scenarios are <see cref="SlotAddHardwareScenarios"/>'s.
/// No test for <c>--tpm</c> on macOS: with a test key <c>HardwareServices.Enrollment</c> returns the simulated TPM on
/// every OS, the same call <c>slot request --tpm</c> and <c>recover --tpm</c> make.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class SlotAddTpmTests : IDisposable
{
    private readonly SlotAddHardwareScenarios _s = new(HardwareBackend.Tpm);

    public void Dispose() => _s.Dispose();

    [Fact] public void SlotAddTpm_ThenTheTpmAloneOpensTheVault() => _s.ThenTheChipAloneOpensTheVault();
    [Fact] public void SlotAddTpm_TheExistingYubiKeySlotStillOpens() => _s.TheExistingYubiKeySlotStillOpens();
    [Fact] public void SlotAddTpm_Password_OnAVaultWithoutOne_CreatesTheFirstPassword() => _s.Password_OnAVaultWithoutOne_CreatesTheFirstPassword();
    [Fact] public void SlotAddTpm_Password_Wrong_NothingWritten() => _s.Password_Wrong_NothingWritten();
    [Fact] public void SlotAddTpm_FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused() => _s.FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused();
    [Fact] public void SlotAddTpm_NoTerminal_NoFlag_AddsAPasswordFreeSlot() => _s.NoTerminal_NoFlag_AddsAPasswordFreeSlot();
    [Fact] public void SlotAddTpm_WorkingTpmSlotAlready_Refused_NothingWritten() => _s.WorkingChipSlotAlready_Refused_NothingWritten();
    [Fact] public void SlotAddTpm_WorkingPasswordTpmSlot_NoPasswordAtHand_Refused() => _s.WorkingPasswordChipSlot_NoPasswordAtHand_Refused();
    [Fact] public void SlotAddTpm_DeadOwnTpmSlot_AddsANewOne() => _s.DeadOwnChipSlot_AddsANewOne();
    [Fact] public void SlotAddTpm_DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce() => _s.DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce();
    [Fact] public void SlotAddTpm_ClearedTpm_Refused_NamesRecover() => _s.ClearedChip_Refused_NamesRecover();
    [Fact] public void SlotAddTpm_OwnSlotCheck_HardwareError_Refused_NothingWritten() => _s.OwnSlotCheck_HardwareError_Refused_NothingWritten();
    [Fact] public void SlotAddTpm_WrongPasswordForTheOwnSlotCheck_Refused_NothingWritten() => _s.WrongPasswordForTheOwnSlotCheck_Refused_NothingWritten();
    [Fact] public void SlotAddTpm_WorkingTpmSlot_RefusedBeforeAnyPasswordStep() => _s.WorkingChipSlot_RefusedBeforeAnyPasswordStep();
    [Fact] public void SlotAddTpm_NoWayIn_RefusedBeforeAnyPasswordStep() => _s.NoWayIn_RefusedBeforeAnyPasswordStep();
    [Fact] public void SlotAddTpm_FirstPasswordGuard_BeforeAnyPrompt() => _s.FirstPasswordGuard_BeforeAnyPrompt();
    [Fact] public void SlotAddTpm_LegacyPairOwnSlot_Refused() => _s.LegacyPairOwnSlot_Refused();
    [Fact] public void SlotAddTpm_NoWayIn_Refused_NothingWritten() => _s.NoWayIn_Refused_NothingWritten();
    [Fact] public void SlotAddTpm_ClassicVault_Refused() => _s.ClassicVault_Refused();
    [Fact] public void SlotAddTpm_WithoutSudo_Refused() => _s.WithoutSudo_Refused();
    [Fact] public void SlotAddTpm_RecoveryKeyStdin_Works() => _s.RecoveryKeyStdin_Works();
}
