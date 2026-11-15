# Brief T24: `slot add --tpm` / `--secure-enclave`, and three messages that send people the wrong way

Issue: https://github.com/stevedcc/TokenSwap/issues/309 (the body and all three comments). Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/SlotCommand.cs`: `ExecuteRequest` and
`ExecuteHardwareRequest` (:103-345, how a TPM or Secure Enclave slot is made today), `ReadRequestVaultPassword` and
the text at :322, `ExecuteAccept` (:542-800, the receipt text at :789-793), `ExecuteAdd`/`ExecuteAddFido2`/
`LoadKeyringForAdd`/`SaveWithNewSlot`/`OneKeySlotsBySerial`/`WorkingSlotText` (:881-1100); `InitCommand`'s
`--tpm`/`--secure-enclave` path; `TswapCore/Vault/SimulatedHardwareService.cs`; `docs/commands.md` (the sudo table
row for `slot add` at :26 and the `### slot` section) and `docs/multi-machine.md` "Joining another machine" and
"Sharing a vault folder".

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys, real TPMs or `~/.config/tswap`: simulated services
(`SimulatedHardwareService`, `FleetMachine`), `TSWAP_CONFIG_DIR` and temp folders only. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion.

**Parallel work:** the #311 fields branch edits `docs/commands.md` (the sudo table: it adds `field` rows; the
generated reference) and `TswapCli/CommandContext.cs`. T24 edits only the `slot add` row of the sudo table and the
`### slot` section's text (by regenerating, see Task 4). Do not edit `CommandContext.cs`; if you need a seam there,
stop and report.

## Why

Found while dogfooding 0.3.0 (owner, 2026-11-15): adding this machine's own TPM to a vault made with `init --fido2`
took `slot request --tpm` / `sudo slot approve` / `slot accept` against itself: three commands, two temporary files
and a fingerprint comparison with yourself. `slot add` covers every other local backend. And a vault with no password
yet can't get a password TPM slot that way at all (`slot request --password` only joins an existing password); the
only route was `sudo tswap recover --tpm --password` with the recovery key.

**Owner decision (2026-11-15):** when this machine already has a working TPM (or Secure Enclave) slot, `slot add
--tpm` refuses, with the same check and wording style as `slot add --yubikey`'s "already has a working slot".
Re-enrolling in place is #264, not this brief.

## Task 1: `slot add --tpm` (Linux, Windows)

`sudo tswap slot add --tpm [--password|--no-password] [--recovery-key-stdin]`:

1. Unlocks the vault through the usual unlock path for a keyring change (another slot, the agent, or
   `--recovery-key-stdin`), as `slot add --yubikey` does (`UnlockForKeyringChange`).
2. Creates the TPM key and slot blob exactly as `slot request --tpm` does (reuse that code; no second copy).
3. Wraps the vault key for the new slot and writes the keyring **once** (`SaveWithNewSlot`), with no request or
   approve file.
4. Leaves this machine's config so that an unlock with **only** the TPM available opens the vault (find what `slot
   accept` writes for a machine slot and do the same; the test below is the definition).

The vault password, with `VaultPasswordChoice` as `slot add --yubikey` uses it: `--password` on a vault with a
password checks the typed one against the verifier before any write; on a vault with **no** password yet it creates
the vault's first password (asked twice, writes `vault-password`), as `slot add --yubikey --password` does. Neither
flag: asked at a terminal; no terminal: refused as today's `slot add` refuses.

Refusals (each writes nothing; assert the keyring file and config are byte for byte unchanged):
- this machine already has a working TPM slot (one of its TPM slots still unseals here): a message in the style of
  `WorkingSlotText`, naming the slot's short id;
- no way in (no slot opens, no agent, no recovery key);
- a wrong vault password for `--password`;
- a classic vault (as `slot add` refuses today);
- `--tpm` on macOS (as `slot request --tpm` refuses there).

Tests (`SlotAddTpmTests`, `SimulatedHardwareService` for the TPM, a FIDO2- or YubiKey-slot vault as the start):
- `SlotAddTpm_ThenTheTpmAloneOpensTheVault` (the other hardware made unavailable after the add: `names` works);
- `SlotAddTpm_Password_OnAVaultWithoutOne_CreatesTheFirstPassword` (then the TPM unlock needs it, and a wrong one
  fails);
- `SlotAddTpm_Password_Wrong_NothingWritten`;
- `SlotAddTpm_WorkingTpmSlotAlready_Refused_NothingWritten`;
- `SlotAddTpm_NoWayIn_Refused_NothingWritten`;
- `SlotAddTpm_WithoutSudo_Refused`;
- `SlotAddTpm_RecoveryKeyStdin_Works`.

Break-it-once: skip the keyring write; `SlotAddTpm_ThenTheTpmAloneOpensTheVault` fails. Drop the working-slot check;
its refusal test fails.

## Task 2: `slot add --secure-enclave --with-touch|--no-touch` (macOS)

The same command for the Secure Enclave, with `SecureEnclaveTouchChoice` as `slot request --secure-enclave` takes it
(one of the two is required). Today `slot add` refuses a touch flag with `SecureEnclaveTouchChoice.NotForSlotAdd`
(:887-888): that refusal goes for `--secure-enclave` (it stays for a touch flag given with `--yubikey`/`--fido2`).

Under `sudo` the Secure Enclave key must be usable by the invoking user afterwards: follow exactly what `init
--secure-enclave` does under sudo (brief T12: "under sudo, the Secure Enclave runs as the vault owner"); if that path
can't be reused for `slot add`, stop and report.

Tests: the Task 1 set for the Secure Enclave with the simulated service (what runs on Linux CI must not need macOS:
gate macOS-only behaviour the way existing Secure Enclave command tests do); plus `SlotAdd_TouchFlagWithYubikey_
StillRefused` (the existing refusal stays for the other backends). The owner checks the real Secure Enclave on the
Mac afterwards; say so in the commit message.

Break-it-once: drop the touch-choice requirement; the "neither flag" refusal test fails.

## Task 3: three messages (issue comments 2 and 3)

1. **`slot request --password` on a vault folder with no password yet** (today :322, "needs the shared vault folder
   (its vault-password file) … or pass --vault-dir", even when the folder is right there): say that the vault has no
   password yet, and point at `sudo tswap slot add --tpm --password` (or `--secure-enclave`) on a machine that already
   opens the vault, which now creates the first password.
2. **`slot request --password --vault-dir <folder>`** where the folder doesn't exist, or exists without a
   `vault-password` file: name the folder (as given, and the full path it resolved to) and say which of the two is
   wrong. The no-`--vault-dir` case keeps today's text.
3. **`slot accept --vault-dir <shared folder>`** (today :789-793: "Receipt written … run there: sudo tswap slot merge
   … Until then, only this machine's copy of the vault has the new slot."): when the keyring was written into the
   shared folder, that isn't true: the slot is already in the shared keyring and every machine syncing the folder gets
   it. Then print that instead, keep writing the receipt, and say it is only needed for a copy of the vault that
   doesn't sync this folder. Without `--vault-dir`, today's text stays.

Tests: each message exactly (the whole stderr or stdout line, as the existing slot tests assert), and that the
command's exit code and written files don't change from today's.

Break-it-once: restore the old accept text under `--vault-dir`; its test fails.

## Task 4: docs

- Regenerate the command reference (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`)
  after updating `SlotCommand`'s `Forms`/`Description` for `--tpm` and `--secure-enclave`.
- The sudo table's `slot add` row (`docs/commands.md:26`): "or this machine's TPM or Secure Enclave".
- `docs/multi-machine.md`: wherever it tells a machine that already opens the vault to add its own TPM or Secure
  Enclave through request/approve/accept (the comment at :128-132 and "Joining another machine"), use `slot add --tpm`
  / `--secure-enclave` instead; request/approve/accept stay the way for **another** machine.
- The vault-password guide (`docs/vault-password-and-agent.md`), where it says how a vault gets its first password
  slot: add `slot add --tpm --password`.

## Out of scope

Re-enrolling an existing TPM slot in place (#264), `vault password change` (#313), FIDO2/YubiKey behaviour, Windows
TPM specifics beyond what `slot request --tpm` already does there.
