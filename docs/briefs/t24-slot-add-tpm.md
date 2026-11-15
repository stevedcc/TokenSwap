# Brief T24: `slot add --tpm` / `--secure-enclave`, and three messages that send people the wrong way

Issue: https://github.com/stevedcc/TokenSwap/issues/309 (the body and all three comments). Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/SlotCommand.cs`: `ExecuteRequest` and
`ExecuteHardwareRequest` (:103-310), `RequestNeedsFolderText`/`ReadRequestVaultPassword` (:320-343), `ExecuteAccept`
(:542-800, the receipt text at :787-793), `ExecuteAdd`/`ExecuteAddFido2`/`LoadKeyringForAdd`/`SaveWithNewSlot`/
`WorkingSlotText`/`Reenrol` (:881-1260), `UnlockForKeyringChange` (:1586); `TswapCli/Commands/RecoverCommand.cs` (its
`--tpm`/`--secure-enclave` path, :60-175, the model for this brief); `TswapCli/VaultPasswordChoice.cs`;
`TswapCli/SecureEnclaveTouchChoice.cs`; `TswapCli/HardwareServices.cs`; `TswapCore/Vault/VaultUnlocker.cs`
(`Classify`, `OwnBackend` and its comment, `FindOwnMachineSlot`, `YubiKeySlotOpens`, `UnlockHardware`);
`TswapCore/Vault/HardwareBlobLocator.cs`; `TswapCore/Vault/SimulatedHardwareService.cs`; `TswapCli/OtherMachinesGuide.cs`;
`docs/commands.md` (the sudo table row for `slot add` at :26), `docs/multi-machine.md` and
`docs/vault-password-and-agent.md`.

Review history: round 1 by MiMo and GLM-5.3 (`~/RiderProjects/tswap-wt/tools/t24-brief-r1-{mimo,glm}.md`), both "no".
This version names the three config fields the new slot needs, defines the working-slot check (this machine's own slot
only, password slots included), keys the accept text on where the keyring was written, makes the request messages a
decision table, reuses `recover --tpm`'s path, and lists the existing tests that change. "(MiMo I4)" / "(GLM I5)" point
at round 1.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys, real TPMs or `~/.config/tswap`: simulated services
(`SimulatedHardwareService`, `FleetMachine`), `TSWAP_CONFIG_DIR` and temp folders only. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion, except the one named
under "Existing tests" below.

**Parallel work:** the #311 fields branch edits `docs/commands.md` (the sudo table: it adds `field` rows; the
generated reference) and `TswapCli/CommandContext.cs`, and may touch AGENTS.md's sudo lists. T24 edits only the
`slot add` row of the sudo table, the generated reference (by regenerating), and two phrases in AGENTS.md (Task 4).
Do not edit `CommandContext.cs`: nothing here needs a seam there (the new check goes in `VaultUnlocker`; the unlock
uses `ctx.Unlock` and `ctx.Unlocker` as today). If you find you need one, stop and report.

## Why

Found while dogfooding 0.3.0 (owner, 2026-11-15): adding this machine's own TPM to a vault made with `init --fido2`
took `slot request --tpm` / `sudo slot approve` / `slot accept` against itself: three commands, two temporary files
and a fingerprint comparison with yourself. `slot add` covers every other local backend. And a vault with no password
yet can't get a password TPM slot that way at all (`slot request --password` only joins an existing password); the
only route was `sudo tswap recover --tpm --password` with the recovery key.

**Owner decision (2026-11-15):** when this machine already has a working TPM (or Secure Enclave) slot, `slot add
--tpm` refuses, with the same check and wording style as `slot add --yubikey`'s "already has a working slot".
Re-enrolling in place is #264, not this brief.

## Existing tests this brief touches

Rule 5's "the brief changed the rules" case. Each one is named here so the implementer is sanctioned; the commit
message says so for each.

- `VaultPasswordJoinTests.RequestWithPassword_FolderWithoutVaultPasswordFile_RefusesWithRuling16Text`: its scenario
  (`--vault-dir` at a folder with a keyring, no password slot and no `vault-password` file) is exactly Task 3's case
  (e). **Its expected text changes** from `NoFolderText` to `RequestNoPasswordYetText(<the folder's full path>)`,
  because the owner asks for that message in issue #309 comments 2 and 3. Its other assertions (non-zero exit, no
  request file) stay. This is the only assertion change in the brief.
- `SlotAddYubiKeyTests.WrongArguments_AreAUsageError`: the row `[InlineData("slot", "add", "--tpm")]` becomes a valid
  command. **Change the input, not the assertion:** the row becomes `("slot", "add", "--tpm", "--yubikey")` (two
  backends, still a usage error naming `slot add --yubikey`). Left as it is, the row would also drive
  `HardwareServices.Enrollment(Tpm, …)` with no test key, toward a real TPM.
- These must stay green **unchanged**; shape the code to keep them:
  - `SecureEnclaveTouchChoiceTests.SlotAdd_WithAChoice_IsRefused_NotIgnored`: every row stays a usage error that names
    `--secure-enclave`, `--with-touch` and `--no-touch`, reads nothing from stdin, prints no `--no-touch` warning and
    writes nothing. So the backend-count check runs before `WarnIfNoTouch`, and the add usage contains
    `SecureEnclaveTouchChoice.Flags`.
  - `CommandArgumentErrorTests.Slot_WithNoSubcommand_GivesItsUsage`: `Forms` still ends with `| slot add --yubikey`,
    so the new forms go before the `--fido2` one.
  - `SlotAddFido2Tests.SlotAddFido2_SerialWithYubiKeyFlag_IsAUsageError`: the add usage still contains
    `slot add --yubikey|--fido2`.
  - `SecureEnclaveTouchChoiceTests.TheHelpOfEachEnrolmentCommand_NamesBothChoices`.
  - `OtherMachinesGuideTests.FolderVariant_JoinsWithInitVaultDirAndHasNoMergeStep`: Task 4 keeps the request/approve/
    accept lines and adds the `slot add` route before them.
  - `VaultPasswordJoinTests.RequestWithPassword_NoFolder_RefusesWithRuling16Text`: no folder known keeps today's text.
  - `CommandReferenceIsCurrent`: regenerate in the same commit as each `Forms`/`Description` change (MiMo M4).

## Task 1: `slot add --tpm` (Linux, Windows)

`sudo tswap slot add --tpm [--password|--no-password] [--recovery-key-stdin]`. Reuse `RecoverCommand`'s
`--tpm`/`--secure-enclave` body (enrolment through `HardwareServices.Enrollment(backend, ctx.TestKey, ctx.OwnerScope,
requirePresence)`, `MachineSlotWrap.Wrap(...) with { HwBlob = hwBlob }`, the three config fields, the backup, the first
password's file, one `SaveConfig`): extract the shared part into one helper both commands call, with `recover`'s
behaviour, output and tests unchanged (MiMo M9). No second copy of the enrol-and-wrap code. (`slot request --tpm` only
seals; the wrap is `slot accept`'s, so `recover` is the closer model.)

**Order.** Each step comes before the next; every refusal writes nothing.

1. **Arguments.** In `ExecuteAdd`, `SecureEnclaveTouchChoice.Split(positional, addUsage)` replaces the
   `IsSecureEnclaveFlag` / `NotForSlotAdd` refusal. Delete `SecureEnclaveTouchChoice.NotForSlotAdd`: its text ("slot
   add --yubikey creates no Secure Enclave key …") becomes false (MiMo M2, GLM m2), and a touch flag without
   `--secure-enclave` is still refused by `Split`'s own text. Then `VaultPasswordChoice.Split`,
   `Fido2SlotEnrollment.SplitSerial`, then exactly one of `--yubikey`, `--fido2`, `--tpm`, `--secure-enclave`, and
   `--serial` only with `--fido2`; anything else is a usage error, before any read, prompt, hardware call or write.
   `addUsage` becomes
   `{prefix} slot add --yubikey|--fido2|--tpm|{SecureEnclaveTouchChoice.Flags} [--serial <n>] [--password|--no-password] [--recovery-key-stdin] (--serial only with --fido2)`
   (keeps the literals the tests above pin, MiMo M3). `--yubikey` and `--fido2` then run exactly as today.
2. `LoadKeyringForAdd` (keyring, format version 3, then `ctx.RequireSudo("slot add")`), as `--yubikey` does. Make its
   no-keyring text backend-neutral ("…so it has no slots to add one to…" instead of "…to add a YubiKey to…", MiMo M11;
   no test pins those words). Reword `RequireKeyringThatTakesYubiKeySlots`' format-version-2 refusal the same way (r2
   MiMo N4; it also serves `recover` and `slot merge`), keeping "format version {n}", which is all its tests assert:
   "This vault's keyring is format version {n}, made before keyring slots could carry their hardware's own
   parameters, so it cannot take a new YubiKey, FIDO2, TPM or Secure Enclave slot. It keeps working with its existing
   slots; to give it new slots, create a new vault with 'tswap init' and move the secrets across."
3. `HardwareServices.Enrollment(Tpm, …)`. On macOS it throws "--tpm is only supported on Windows and Linux." as
   `slot request --tpm` and `recover --tpm` do.
4. **A legacy pair own slot is refused** (MiMo I3). The condition: `(config.Backend ?? YubiKey) == YubiKey`, the
   config has the pair fields (`YubiKeySerials` and `RedundancyXor` not empty), and
   `VaultUnlocker.FindOwnMachineSlot` is a machine slot with no `HwBlob`. Making the TPM this machine's own slot would
   make `Classify` skip the pair slot (`case YubiKeySlotKind.None: continue`), so the pair would stop opening the vault
   on this machine. (Only here: `Backend` and `KeyringSlotId` are machine-local config fields, so other machines' copies
   are not affected; MiMo's "on every copy" is not so.) The condition stays as it is (orchestrator ruling, r2 GLM I1):
   `slot add --yubikey` never changes `KeyringSlotId` or the pair fields, so the refusal keeps protecting the pair here,
   and the text names the route that really unblocks it, `recover`, which does set `Backend` and `KeyringSlotId`.
   `LegacyPairOwnSlotText("TPM", "--tpm")`: "This machine's own slot is a legacy YubiKey pair slot, which opens only
   through this machine's config. Making the TPM this machine's slot would stop the pair opening the vault here, so
   nothing was changed. Give each YubiKey its own slot first (sudo tswap slot add --yubikey, once per key), then make
   the TPM this machine's own slot with the recovery key: sudo tswap recover --tpm --recovery-key-stdin." (Task 2:
   "Secure Enclave" and `--secure-enclave --with-touch|--no-touch`.)
5. **The working-slot check** (owner decision; GLM I5, MiMo I4). Only **this machine's own slot** is checked: when
   `config.Backend == Tpm` and `FindOwnMachineSlot(config, keyring)` finds it. Other TPM or Secure Enclave slots in the
   keyring belong to other machines (a shared folder holds them) and are never tried, as `OwnBackend`'s comment
   requires: each try costs TPM dictionary-attack exposure or a Touch ID prompt. (MiMo's "try every TPM-looking slot"
   is rejected for that reason.) When the config's backend isn't TPM (the dogfood case, a FIDO2 vault), there is
   nothing to check.
   - New method in `TswapCore`, not `CommandContext`: `VaultUnlocker.HardwareSlotOpens(Config config,
     VaultPasswordProvider? password)`, the twin of `YubiKeySlotOpens`. It calls `UnlockHardware(config, …, password)`
     (as `slot accept` calls it; `HardwareBlobLocator` reads the own slot's blob), then `UnwrapSlot` of the own slot,
     and zeroes the vault key at once. True: it opens. False: the hardware answered and the unwrap failed. A hardware or
     password failure is thrown as it is.
   - **"The object no longer loads" needs its own signal** (r2 GLM m2 ruling): today `Tpm2ToolsInterop.UnlockFailed`
     returns one generic `TswapException` for a cleared TPM, another machine's blob, a corrupted config and other
     failures. Add `HardwareSlotGoneException : TswapException` in `TswapCore` (same message, so every existing catch
     and text is unchanged), thrown only for a definite answer: by `Tpm2ToolsInterop` when `tpm2_load` fails without a
     lockout or auth code after `tpm2_createprimary` succeeded (the TPM answered: the integrity check failed, as after
     `tpm2_clear`), and by `SimulatedHardwareService` when a password-free blob doesn't decrypt under its machine key
     (its "made on a different machine" text). Windows TPM and the real Secure Enclave throw it only where an existing
     error code already says the key is gone; if none does, they always refuse, and the commit message says so.
     Simulator limit: a password blob under another machine key reads as a wrong password (the key is derived from
     both), so a dead *password* own slot is tested through the unwrap path instead (see the tests).
   - **A password own slot** (`SlotPassword.Classify(own) == Password`) needs the vault password for the check. Follow
     `Reenrol`'s steps 2 to 4. First decide the new slot's password (`VaultPasswordChoice.Decide(ctx, passwordFlag,
     HardwareBackend.Tpm)`). No `vault-password` file: refuse with `VaultPasswordMessages.MissingFile`. With
     `--recovery-key-stdin`, read the key here, before the check, as `Reenrol` does (`ReadRecoveryKey(ctx, keyring,
     keyOnFirstLine: true)`), then the password from the next line. No terminal and no
     `--recovery-key-stdin`: refuse with `OwnSlotNeedsPasswordText`, "This machine's TPM slot {shortId} needs the vault
     password to check whether it still works. It is read at a terminal (or, with --recovery-key-stdin, on the line
     after the recovery key), and stdin is not a terminal here. Run this at a terminal. Nothing was changed."
     Otherwise ask once (`AskUnverified`). The same typed value serves the check, the new slot when it gets the
     password, and the verifier check after the unlock (step 6). **A missing password never counts as "the slot doesn't
     work"**: that would let `--no-password` skip the owner's refusal (MiMo I4a).
   - Outcomes:
     - **Opens:** refuse with `WorkingHardwareSlotText("TPM", shortId)`: "This machine's TPM already has a working slot
       in this vault (slot {shortId} still opens it), so there is nothing to add. Each machine needs only one TPM
       slot." (`ShortId` is the existing 8-hex-digit helper.)
     - `VaultPasswordRefusedException` with `WrongPassword`: refuse with `VaultPasswordChoice.WrongPasswordText`.
     - `VaultPasswordUnavailableException`, `VaultPasswordCancelledException`, `OwnerSwitchException`: refusals, as
       thrown.
     - **Dead, a definite answer only** (orchestrator ruling on r2 GLM m2): false (the hardware answered and the
       unwrap failed) or `HardwareSlotGoneException` (the object no longer loads). Print one line on stderr, "This
       machine's TPM slot {shortId} no longer opens this vault ({reason}); adding a new one. The old slot is kept.",
       and go on, the way `slot add --yubikey` treats a reprogrammed key.
     - **Any other hardware error** (busy, unreachable, a corrupted blob, anything not definite): refuse with
       `OwnSlotUncheckedText`, "{error} This machine's TPM slot {shortId} couldn't be checked, so no new slot is added.
       Nothing was changed.", as `Reenrol` refuses a key that gives no answer. A transient failure must not add a
       second slot while the first still works.
6. **Unlock** as `Reenrol` unlocks (r2 MiMo N1, r2 GLM m4): when step 5 read the recovery key,
   `RecoveryKeyUnlock.Unlock(keyring, recoveryKey)` with that key (zeroed in a `finally`); **stdin is never read
   again**. `UnlockForKeyringChange` would re-read it and take the password line for the key. Otherwise (no own-slot
   check ran, or it read nothing) `UnlockForKeyringChange` as `--yubikey` does, with `keyOnFirstLine: passwordFlag ==
   true`. A password typed in step 5 must pass `file.Verifies(vaultKey, typed)`, else refuse with "This machine's TPM
   slot isn't added: the vault password didn't match this vault's (checked against the vault's password verifier).
   Nothing was changed." Accepted limit: with a dead password own slot, no `--recovery-key-stdin` and no password-free
   way in, the unlock's pass 3 asks for the password once more (handing it over would need a `CommandContext` seam).
7. **The new slot's password** when step 5 typed none. Do what `Resolve` does: `Decide` with `HardwareBackend.Tpm`
   (so the TPM lockout notice prints; `ExecuteAddFido2` passes `YubiKey`, GLM's note), then `AskExisting` when the
   folder has a `vault-password` file, else `CreateNew`. Compose these yourself rather than calling `Resolve`, to add
   one guard (MiMo I1b): **a first password is refused when the keyring already has a password slot**
   (`keyring.Slots.Any(SlotPassword.Requires)`) and the folder has no `vault-password` file, with
   `VaultPasswordMessages.MissingFile`, before any prompt. A freshly salted file would leave the existing password
   slots unopenable and conflict with the real file when it syncs back; `Reenrol` refuses the same state the same way.
   `--password` on a store that isn't a record vault keeps `NeedsRecordVaultText`. Neither flag: asked at a terminal;
   **no terminal: a password-free slot with `VaultPasswordChoice.NoPasswordLine`**, as `slot add --yubikey` does today
   (GLM m5; the previous brief's "refused" was wrong about today's behaviour).
8. **Enrol and write once:** `enrollment.Enroll(stretched or null)`, the wrap, then one config write in
   `SaveWithNewSlot`'s order: `config.json` backed up, then the first password's `vault-password` file, then
   `SaveConfig` (on a record vault: the shared `keyring`, then this machine's `config.json`). The new config sets
   **three fields** (GLM m1, MiMo I3; `slot accept` writes only `KeyringSlotId` and inherits the other two from the
   pending request, which `slot add` has no equivalent of):
   - `Backend = Tpm`: without it `Classify` routes the own slot to the YubiKey backend and the TPM slot is never tried;
   - `KeyringSlotId` = the new slot's id: what `HardwareBlobLocator` and `UnlockKeyring` read;
   - `RequiresTouch = false`.

   The new slot is acknowledged in `SecurityWarnings` as `SaveWithNewSlot` does. One-key YubiKey and FIDO2 slots still
   open the vault afterwards: `Classify` tries them whatever `KeyringSlotId` says.

**What a failed write leaves** (security-sensitive; nothing new, but say it in the code comment): a failure before
`SaveConfig` leaves the keyring as it was (a first password's `vault-password` file may already be there, and a rerun
asks once against it, as `slot add --yubikey` does today). A failure between the shared `keyring` and `config.json`
leaves an extra TPM slot this config doesn't point at: the vault opens as before, and a rerun adds another slot (the
orphan stays; keyrings merge as a union). No file is half written: both are the store's atomic, owner-preserving
writes.

**Under sudo** (issue #309 "Running under sudo"): every file goes through the store's `DirectoryOwnerMatcher` layer, so
`config.json`, its backup, the `keyring` and `vault-password` keep the vault folder owner's ownership and mode, as for
`slot add --yubikey` and `recover --tpm` today. The TPM object is sealed into the slot's blob in the keyring, and
`Tpm2ToolsInterop`'s temporary folders are removed (`DeleteBestEffort` in its `finally`), as under `recover --tpm`,
which already enrols a TPM under sudo
(so GLM I6's "the first sudo TPM enrolment path" is not so; its owner check is still added below).

**Success output:** "✓ This machine's TPM added as its own slot — it now opens this vault alone.", the password line
as `--yubikey` prints it, then the rest exactly as `recover` prints it after its password line (r2 MiMo N2, r2 GLM
m4): `PrintFingerprint`, "Slots in this machine's keyring: {n}", "Machines that share this vault folder get the new
slot with it.", "A machine with its own copy of the vault gets it once you copy {folder} there and run, on that
machine:" and the `sudo tswap vault merge <the copied folder>` line. Not `PrintAddedSlotFooter`'s "no sync in v0"
line, which is false for a shared folder (GLM m6; `--yubikey`/`--fido2` keep theirs, out of scope).

Update `SlotCommand.Forms` (`… | slot add --tpm {VaultPasswordChoice.Flags} | slot add --fido2 [--serial <n>] | slot
add --yubikey`) and `Description`, and regenerate the reference **in the same commit**
(`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`), so `--unit` stays green.

**Tests** (`SlotAddTpmTests`, `FleetMachine` with `Tpm` set, a record vault). "Nothing written" means `config.json`,
the folder's `keyring` and `vault-password` byte for byte unchanged and no new `config.json.bak-*` (GLM m7); where a
TPM call is named, `SimulatedHardwareService.ObserveCalls` shows it, as
`VaultPasswordJoinTests.Accept_WrongPassword_RefusesBeforeTouchingTheTpm` does (MiMo M5).
- `SlotAddTpm_ThenTheTpmAloneOpensTheVault`: an `init --yubikey --no-password` vault, `create alpha` first. After
  `slot add --tpm --no-password`, `config.json` has `Backend == Tpm`, `KeyringSlotId` == the last slot's id and
  `RequiresTouch == false`; with no YubiKey plugged in, `names` exits 0 and lists `alpha`; with `Tpm` replaced by other
  bytes, `names` fails.
- `SlotAddTpm_TheExistingYubiKeySlotStillOpens`: after the add, `Tpm = null` and the key plugged in: `names` lists
  `alpha` (MiMo I3).
- `SlotAddTpm_Password_OnAVaultWithoutOne_CreatesTheFirstPassword`: at a terminal, the password twice; a
  `vault-password` file appears; with only the TPM, `names` with that password works, and with a wrong one fails with
  `VaultPasswordMessages.WrongPasswordKdf`.
- `SlotAddTpm_Password_Wrong_NothingWritten`: a vault that has a password; a wrong one gives `WrongPasswordText`;
  nothing written; no `Tpm:Enroll` call.
- `SlotAddTpm_FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused`: a password slot in the keyring and the
  `vault-password` file deleted: `MissingFile`; nothing written, no `vault-password` file created.
- `SlotAddTpm_NoTerminal_NoFlag_AddsAPasswordFreeSlot`: stderr has `NoPasswordLine`; the new slot has no password.
- `SlotAddTpm_WorkingTpmSlotAlready_Refused_NothingWritten`: an `init --tpm` vault; the exact `WorkingHardwareSlotText`
  with the own slot's short id; a `Tpm:Unlock` call and no `Tpm:Enroll`; nothing written.
- `SlotAddTpm_WorkingPasswordTpmSlot_NoPasswordAtHand_Refused`: an `init --tpm --password` vault, `slot add --tpm
  --no-password` with stdin not a terminal: `OwnSlotNeedsPasswordText`; no TPM call at all; nothing written.
- `SlotAddTpm_DeadOwnTpmSlot_AddsANewOne`: an `init --tpm` vault with a recovery key, then `Tpm` replaced by other
  bytes; `slot add --tpm --no-password --recovery-key-stdin` succeeds, prints the "no longer opens" line, points
  `KeyringSlotId` at the new slot and keeps the old one; `names` then works with the new `Tpm` (the simulator's
  `HardwareSlotGoneException` path).
- `SlotAddTpm_DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce` (r2 MiMo N1): an `init --tpm --password` vault
  with a recovery key; make the own slot dead by the unwrap path (decode the folder's `keyring` with `KeyringCodec`,
  flip one byte of the own slot's `Wrapped`, write it back), since the simulator can't make a password blob "gone";
  `slot add --tpm --password --recovery-key-stdin` with stdin "{recovery key}\n{password}\n" adds the slot (the "no
  longer opens" line, `KeyringSlotId` = the new slot), `LastConsole.In.ReadToEnd()` is empty afterwards and nothing
  asked twice; with only the TPM and that password, `names` works.
- `SlotAddTpm_OwnSlotCheck_HardwareError_Refused_NothingWritten` (r2 GLM m2): an `init --tpm` vault whose own slot's
  `HwBlob` is truncated (a plain `TswapException`, not a definite answer): `OwnSlotUncheckedText` with that error; no
  `Tpm:Enroll`; nothing written.
- `SlotAddTpm_LegacyPairOwnSlot_Refused`: the `KeyringV3PairFixtureTests` fixture, converted first with `migrate
  --to-records` (key A plugged in) as that class's private `ConvertFixture` does, or the classic-vault refusal comes
  first (r2 MiMo N3); then the exact `LegacyPairOwnSlotText("TPM", "--tpm")`; nothing written.
- `SlotAddTpm_NoWayIn_Refused_NothingWritten`: no key plugged in, no agent, no recovery key.
- `SlotAddTpm_ClassicVault_Refused`: built as `SlotAddYubiKeyTests.PlainVault_IsRefused` builds it.
- `SlotAddTpm_WithoutSudo_Refused`: as `SlotAddYubiKeyTests.WithoutSudo_IsRefusedBeforeAnyUnlockOrWrite` (return early
  when `Environment.IsPrivilegedProcess`, `Sudo = false`, assert the platform-neutral "requires"); no TPM call, nothing
  written (MiMo M11).
- `SlotAddTpm_RecoveryKeyStdin_Works`.
- No test for `--tpm` on macOS (MiMo M1): with a test key `HardwareServices.Enrollment` returns the simulated TPM on
  every OS, so the refusal can't be reached in-process. It is the same call `slot request --tpm` and `recover --tpm`
  make; say so in the commit message.

**Break-it-once:** skip the config write: `SlotAddTpm_ThenTheTpmAloneOpensTheVault` fails. Leave out `Backend = Tpm`:
the same test fails. Drop the working-slot check: `SlotAddTpm_WorkingTpmSlotAlready_Refused_NothingWritten` fails.
Treat a missing password as a dead slot: `SlotAddTpm_WorkingPasswordTpmSlot_NoPasswordAtHand_Refused` fails. Drop the
first-password guard: `SlotAddTpm_FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused` fails. Unlock through
`UnlockForKeyringChange` after the pre-read: `SlotAddTpm_DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce`
fails. Count any hardware error as dead: `SlotAddTpm_OwnSlotCheck_HardwareError_Refused_NothingWritten` fails.

**Owner check on a real TPM** (MiMo M10, GLM I6; say it in the commit message, the owner runs it): on Linux, with a
FIDO2 or YubiKey vault, `sudo tswap slot add --tpm`; then as the user, unprivileged and with the key unplugged, `tswap
names` works, and `ls -l` shows `config.json`, its backup and `keyring` owned by the user.

## Task 2: `slot add --secure-enclave --with-touch|--no-touch` (macOS)

The same command for the Secure Enclave: Task 1's order with `HardwareBackend.SecureEnclave`, and `requirePresence`
from `SecureEnclaveTouchChoice.Split` (one of the two flags is required; `Split` refuses neither, both, and a touch
flag without `--secure-enclave`). The differences:
- `SecureEnclaveTouchChoice.WarnIfNoTouch` right after the argument checks of step 1, before any prompt, unlock or
  write; `SecureEnclaveTouchChoice.Summary(requirePresence)` in the success output, as `recover --secure-enclave`
  prints it (MiMo M6).
- `RequiresTouch = requirePresence` in the config: `SecureEnclaveHardwareService` reads it to choose the no-prompt
  unwrap.
- The working-slot check applies when `config.Backend == SecureEnclave`. A with-touch own slot costs one Touch ID
  prompt for it; print "Checking whether this Mac's Secure Enclave slot {shortId} still opens the vault (Touch ID or
  password)." first. The texts say "Secure Enclave" where Task 1's say "TPM".
- **Under sudo** the key is created as the vault folder's owner with no extra code:
  `HardwareServices.Enrollment(SecureEnclave, …, ctx.OwnerScope, …)` always returns the `OwnerScopedHardwareService`
  wrapper (brief T12, enforced by `SecureEnclaveFactoryScanTests`), as `recover --secure-enclave` uses it. (The previous
  brief named `init` as the precedent and asked to stop if it couldn't be reused; `init` isn't a sudo command and
  `recover` is the precedent, so there is nothing to stop for: MiMo M9, GLM.)
- `Forms` gains `slot add {SecureEnclaveTouchChoice.Flags} {VaultPasswordChoice.Flags}` before the `--fido2` form;
  regenerate the reference in the same commit.

Tests (`SlotAddSecureEnclaveTests`, `FleetMachine` with `SecureEnclave` set; the simulated Secure Enclave runs on Linux
CI, as `SlotRequestHardwareTests` shows): Task 1's set in full, for the Secure Enclave, except the TPM-only lockout
notice and the macOS-only case (r2 GLM m1): that includes the dead own slot (both the gone and the unwrap paths, with
the recovery-key stdin test), the hardware-error refusal and the legacy pair refusal with the Secure Enclave text,
plus:
- `SlotAddSecureEnclave_NeitherTouchFlag_IsAUsageError`: exit 1, the usage and `Split`'s text naming both flags,
  nothing read from stdin, no hardware call, nothing written (MiMo M1, GLM I7: the previous brief's break-it-once named
  this test without asking for it);
- `SlotAddSecureEnclave_NoTouch_WarnsFirst_AndRecordsIt`: the `--no-touch` warning is on stderr before any prompt,
  `RequiresTouch == false`, and the summary line is printed; `--with-touch` gives `RequiresTouch == true`.

A touch flag with `--yubikey`/`--fido2` is already covered by `SlotAdd_WithAChoice_IsRefused_NotIgnored` (unchanged),
so the previous brief's `SlotAdd_TouchFlagWithYubikey_StillRefused` is dropped. The owner checks the real Secure
Enclave on the Mac afterwards (`sudo tswap slot add --secure-enclave --with-touch`, then `tswap names` as the user);
say so in the commit message.

Break-it-once: drop the touch-choice requirement: `SlotAddSecureEnclave_NeitherTouchFlag_IsAUsageError` fails. Set
`RequiresTouch = true` always: the `--no-touch` test fails.

## Task 3: three messages (issue comments 2 and 3)

**`slot request --password`'s folder** (MiMo I1, I5; GLM m3, m4). `ReadRequestVaultPassword` tells these cases apart,
in this order. Each is a `TswapException` with nothing written and today's exit code. `{given}` is the `--vault-dir`
argument as typed, `{full}` its `Path.GetFullPath`; `{folder}` is the folder in use (`--vault-dir`'s full path, or this
record vault's `VaultDir`).
- (a) No folder known (no `--vault-dir`, not a record vault): today's `RequestNeedsFolderText`, unchanged.
- (b) `--vault-dir` given and the folder doesn't exist: `RequestFolderMissingText(given, full)`, "slot request
  --vault-dir {given}: there is no folder {full}. Nothing was changed. Check the path; the shared vault folder holds the
  vault's 'keyring' file."
- (c) The folder has no `keyring`: `RequestNotAVaultFolderText(folder)`, "{folder} has no keyring, so it is not a
  shared vault folder. Nothing was changed. Point --vault-dir at the folder the enrolled machines share (its 'keyring'
  file must be there)." (accept's A6 wording).
- (d) A `keyring`, no `vault-password` file, and a password slot in the keyring (`SlotPassword.Requires` on any machine
  slot): `RequestPasswordFileMissingText(folder)`, "The vault in {folder} has slots that need the vault password, but
  the folder has no vault-password file. If it is synced, wait for the sync; otherwise restore it from a backup of the
  folder. Nothing was changed." This is not "no password yet": pointing the user at a first password here would mint a
  second, conflicting one (MiMo I1).
- (e) A `keyring`, no `vault-password` file, no password slot: `RequestNoPasswordYetText(folder)`, "The vault in
  {folder} has no vault password yet (no slot needs one, and the folder has no vault-password file), so there is none
  to join. The first one is created on a machine that already opens the vault, with sudo {prefix} slot add --tpm
  --password (or --secure-enclave, --yubikey or --fido2, with --password). If this machine already opens it, run that
  here instead of slot request. Otherwise enrol without --password." It names every `slot add` backend (MiMo M8; the
  dangling "there" is gone, r2 GLM m4).
- Conflict copies keep ruling 2's text (they throw before any of these).

**`slot accept`'s receipt text** (MiMo I2, GLM I1). The new text is keyed on **where the keyring was written**, not on
the flag: `vaultDir is not null` **or** `ctx.Storage is RecordVaultStore`. A record-store machine without `--vault-dir`
writes the new slot into its folder's keyring too (:762-768), so today's "Until then, only this machine's copy of the
vault has the new slot" is just as false there. In those two branches, after the "Slots in this machine's local
keyring copy" line, print instead of today's last four lines (`{folder}` = `vaultDir` or the store's `VaultDir`):
"\nThe new slot is in the keyring of the vault folder {folder}: every machine that shares that folder has it, with no
merge." and "Receipt written to: {receiptPath} (only for a machine with its own copy of the vault, not this folder:
there, run sudo {prefix} slot merge <receipt-file>)." The receipt is still written. Only the third branch (a machine
without a vault, which gets a new vault at `<config dir>/vault`) keeps today's text. The wording is true whether or not
the folder is actually synced, which tswap can't know.

Tests (`SlotRequestPasswordFolderTests`, `SlotAcceptReceiptTextTests`): each of (b) to (e) exactly (the whole stderr
line), with a non-zero exit, no request file and no config written, as today; (a) is the existing
`RequestWithPassword_NoFolder_RefusesWithRuling16Text`, unchanged; (e) also through the record vault's own folder with
no `--vault-dir` (the issue's oort case). Accept: the new lines exactly for `--vault-dir` and for a record-store
machine, today's lines for a machine without a vault; the receipt file is written in all three, and the keyring files
end up as they do today.

Break-it-once, one per message (GLM m7): fold (d) into (e): the (d) test fails. Restore today's text for (b): its test
fails. Drop (c): its test fails. Key the accept text on `vaultDir` only: the record-store accept test fails.

## Task 4: docs and the printed guide

- The sudo table's `slot add` row (`docs/commands.md:26`): add "or this machine's TPM or Secure Enclave" **in the Why
  cell** only. The first cell stays exactly `slot add`: `SudoTableMatchesBehaviour` looks its drivers up by it and
  `SudoTableCoversSubcommands` needs it (r2 GLM m3; the row is at :26 at f75be2b, not :24). (The generated reference
  was regenerated in Tasks 1 and 2.)
- `TswapCli/OtherMachinesGuide.cs`, folder variant (MiMo M7, GLM I3): before the request/approve/accept lines, add the
  route for a machine that has joined and has a way in there: `(There, $"sudo {prefix} slot add --tpm")` and
  `(There, $"(on a Mac: sudo {prefix} slot add --secure-enclave --with-touch)")`, under a title such as "Optional: give
  that machine's own chip a slot, there, with a YubiKey that has a slot plugged in (or --recovery-key-stdin)". Keep the
  request/approve/accept lines as "Or, with no way in there, approve it from here". Both routes are real: a joined
  machine without a key to plug in still needs approval from here. New test
  `OtherMachinesGuideTests.FolderVariant_OffersSlotAddThere` (the line is there, before `slot request --tpm`; still no
  `slot merge` and no `--receipt`). The non-folder `ChipSteps` stay (another machine, no vault).
- `docs/multi-machine.md`: "What the guided `init` prints" (:75-78) to match the guide; the "Sharing a vault folder"
  block (:128-132): `sudo tswap slot add --tpm` for the joined machine, request/accept kept for a machine with no way
  in there. "Joining another machine" (:26-49) is the other-machine case and stays (the previous brief named it as a
  target, MiMo M7); add one sentence after its table: a machine that already opens the vault adds its own TPM or Secure
  Enclave with `sudo tswap slot add --tpm` (or `--secure-enclave --with-touch|--no-touch`).
- `docs/vault-password-and-agent.md`: the command block (:25-35) gains
  `sudo tswap slot add --tpm --password         # a TPM password slot; on a vault without a password, the first one`;
  the sentence at :40 names `slot add` (every backend) instead of `slot add --yubikey`.
- AGENTS.md (GLM I4): the "Requires sudo" list's `slot add --yubikey|--fido2` becomes
  `slot add --yubikey|--fido2|--tpm|--secure-enclave`, and the sentence on where `RequireSudo` fires (:107) names
  `slot add` (every backend). Two phrase edits only (the #311 branch may touch the same list).

## Out of scope

Re-enrolling an existing TPM slot in place (#264), `vault password change` (#313), FIDO2/YubiKey behaviour (including
their `PrintAddedSlotFooter` line, and step 7's first-password guard for `slot add --yubikey`/`--fido2` and `recover`),
Windows TPM specifics beyond what `recover --tpm` already does there.
