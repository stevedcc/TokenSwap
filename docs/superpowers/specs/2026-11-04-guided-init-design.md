# Guided `tswap init` (v0.2.0)

Status: approved by the owner 2026-11-04. Branch `design/guided-init`.

## Why

A plain `tswap init` still means "YubiKey initialisation", from the days when a YubiKey was the only
backend. Since v0.2 a vault has one slot per device (YubiKey, TPM, Secure Enclave) plus a recovery slot,
but `init` only reaches the TPM and the Secure Enclave through flags a new user doesn't know. On
2026-11-04 the owner ran a plain `init` on a Mac with a good Secure Enclave and got eight lines of ykman
warnings (macOS blocks the YubiKey's OTP interface without Input Monitoring). v0.2.0 makes the Secure
Enclave and the TPM first-class, so its `init` must not assume a YubiKey.

## Goals

1. A plain `tswap init` at a terminal is a guided setup that offers what this machine actually has, and
   never picks hardware on its own.
2. It can set up several unlock methods in one run (say two YubiKeys and the Secure Enclave), not one
   plus later `sudo tswap slot add --yubikey` runs.
3. It ends with a step-by-step guide for other machines, with the exact commands.
4. Scripts keep working: every existing flag behaves as today, and a YubiKey vault has its own flag.

## Non-goals (v0.3.0)

- **Enrolling other machines over SSH** (`init` reaching out to `user@host`, and #191's `slot enroll
  --via`). The v0.2.0 guide prints the hand-carried steps; v0.3.0 replaces them.
- **FIDO2 slots.** They arrive with the YubiKey SDK work (`2026-11-04-yubikey-sdk-portable-design.md`).
  v0.2.0's YubiKey slots are the OTP challenge-response slots through ykman, as today.
- Joining an existing vault: that stays `slot request` / `init --vault-dir`; the guide points there.

## Anti-goals

- Choosing an unlock method without asking, including the machine's own chip ("people may want just
  security keys", owner).
- Prompting when no one is at a terminal (a script, an AI agent): that must fail with the flags to use.
- Needing sudo: `init` makes a new vault and stays a no-sudo command.
- A half-made vault: if any chosen method fails to enrol, nothing is written.
- **Overwriting an existing vault, in any mode (owner, hard rule).** Today's refusals stay exactly as they
  are, and the guided flow runs them before step 1, before any key is asked for:
  - a classic vault in the config folder is refused (`migrate`);
  - a config belonging to a record vault, wherever its folder is, is refused (another `TSWAP_CONFIG_DIR`);
  - a vault folder (default or `--folder`) that isn't empty is refused (`init --vault-dir` to join).
  The only "Reinitialize?" left is for a config holding just a pending `slot request`, which is not a vault.
  It backs that file up first, and a vault can still only be created in an empty folder. The existing tests
  for each refusal (`InitRecordVaultTests`, `CommandTests`, `MigrateToRecordsTests` and others) pass
  unchanged, and the guided flow gets the same three refusal tests of its own.

## The guided flow

Runs when `init` gets no backend flag (`--yubikey`, `--tpm`, `--secure-enclave`) and stdin and stdout are a
terminal. `--folder`, `--no-recovery`, `--password`/`--no-password` may still be given and pre-answer
their questions.

1. **Keys first.** "Plug in the security keys you want to use with this vault on this machine, then press
   Enter." No touch is asked for here, and the text says so (on 2026-11-04 the owner touched the key
   during a silent wait and it typed a Yubico OTP into the shell).
2. **What this machine has.** A numbered list:
   - each YubiKey found, by serial (whether its slot 2 is configured is left to enrolment, which says so;
     the YubiKey SDK in v0.3.0 can read it up front);
   - this machine's Secure Enclave (macOS) or TPM (Windows, Linux), when available.
   A source that can't be read is listed as a line saying why, not left out silently: on macOS, a
   YubiKey whose OTP interface is blocked gets "macOS is blocking access to this key (Input Monitoring
   for <terminal app>); use the Secure Enclave, or allow it in System Settings", and the other entries
   stay usable. Detection must not sit in ykman's retries for seconds without saying anything.
   **The macOS evidence (2026-11-04, ykman 5.9.2, macOS 27.2, Input Monitoring off):** listing works, because
   ykman reads the serial over the smart-card interface. The failure comes at `otp calculate`: ykman logs
   `Failed opening device` with `OSError: Failed to open device for communication: -536870174`
   (0xE00002E2, IOKit's IOReturnNoMedia). It retries about once a second for five seconds, then exits
   non-zero with `ERROR: The connection type required for this command is not supported/enabled on the
   YubiKey.` The detector matches that final line (ykman's stderr, as `ykman failed: …` today), and only
   on macOS. tswap can't shorten ykman's retries, so every ykman call in the guided flow is announced first
   ("Checking YubiKey 33060005…"). That is how "no silent wait" is met (my call: no timeout and no extra
   probe command). Where the block shows up depends on the order (my call): a key is listed by serial,
   and the explanation appears when its first challenge fails at step 6, after which `init` offers to
   carry on without that key or stop. Nothing is written in either case.
3. **Pick.** Any combination, at least one (e.g. `1 3`). For the Secure Enclave, the existing touch
   choice follows (Touch ID or password on every unlock, or none, with the existing `--no-touch` warning).
4. **Vault password.** The existing question (brief T17), asked once: one vault password. If yes, "Which slots
   need it?" lists the picked slots, default all. A slot left out opens the vault without the password: a backup
   key kept somewhere safe, so a forgotten password doesn't lock the owner out (owner, 2026-11-04). With one
   slot picked there is nothing to choose. `--password` means every picked slot needs it; `--no-password`, none.
5. **Recovery slot.** Recommended, on by default (`Y/n`); `--no-recovery` answers it.
6. **Create.** All chosen slots and the recovery slot are built in memory, then written in one step.
   Touches happen here, each announced before it is needed. A YubiKey is challenged twice as in every
   enrolment today (`YubiKeySlotEnrollment`'s two-answer check from the T4 review stays; my call: "touch"
   in this document means a touch whenever the slot asks, not one per key). A Secure Enclave slot with
   touch asks for Touch ID.
   **Several keys plugged in:** ykman addresses one key by serial (`--device`), and only that key waits and
   flashes, so the prompt names it: "YubiKey 33060005: if it flashes, touch it (that one, not another key)."
   tswap only learns whether a slot needs a touch from the challenge itself, so the line is conditional. Touching the other key fires its short-press slot, which
   types a Yubico OTP (a line of `c`, `b`, … modhex characters ending in Enter) into tswap's input. `init`
   recognises such a line while it waits, says "that was another key; touch the flashing one", and keeps
   waiting. It neither fails nor treats the line as an answer.
   The password-generation entropy question (`RngMode`, System RNG or YubiKey) is not asked: guided vaults
   use the system RNG, as TPM and Secure Enclave vaults do today. With mixed slots, a YubiKey RNG would
   make every `create` need a YubiKey even when the vault was opened with the chip. `init --yubikey` keeps
   today's question (my call).
7. **Other machines?** "Will other machines use this vault? (y/N)". On yes, the guide below.
8. **Summary.** The slots made (kind, serial or chip, touch, password), the vault folder, and the
   recovery key backup warning as today.

## The guide for other machines

Printed text, with this vault's real values filled in (config folder or `--folder`, file names). For each
kind of machine it gives the commands to run there and here, in order: `slot request` (with `--tpm` or
`--secure-enclave` and the touch choice), `sudo tswap slot approve` here, `slot accept` there, `sudo tswap
slot merge` here. It also covers:
- a vault in a synced folder (`--folder`): the other machine joins with `init --vault-dir` plus the same
  request/approve exchange;
- a YubiKey for the other machine is enrolled there (`slot request` there) or here (`slot add --yubikey`,
  if it travels with the user);
- a Mac whose Secure Enclave slot uses Touch ID needs the user at that Mac.

The guide's steps are written so v0.3.0 can replace "on that machine run … / here run …" with an SSH
step without changing the rest of the flow.

## Flags

| Invocation | Behaviour |
|---|---|
| `init` at a terminal | the guided flow |
| `init` without a terminal | refuses: "'tswap init' without a terminal needs the slot named: --yubikey, --tpm, or --secure-enclave with --with-touch or --no-touch." (exit 1) |
| `init --yubikey` | **new**: today's plain-`init` YubiKey vault, unchanged |
| `init --keyring` | **removed** (owner): refused with its own message, "--keyring is gone: run plain 'tswap init' for the guided setup, or name the slot with --yubikey, --tpm or --secure-enclave.", before any prompt or hardware (as #177's flag check) |
| `init --tpm`, `init --secure-enclave --with-touch\|--no-touch` | unchanged |
| `--password`, `--no-password`, `--no-recovery`, `--folder <dir>`, `--vault-dir` | unchanged; with the guided flow they pre-answer their question |

`--yubikey` with `--tpm` or `--secure-enclave` is a usage error, as `--tpm` with `--secure-enclave` is
today (several methods at once is the guided flow's job in v0.2.0).

Scripts and docs that run a plain `init` for a YubiKey vault without a terminal, or `init --keyring`, now get
a refusal that names the replacement; the release notes say so. Goal 4 ("scripts keep working") holds for
the backend flags; these two break on purpose, loudly. `--keyring` today appears in README.md (six places,
including the command table), MULTI_MACHINE_KEYING.md, HARDWARE_BACKENDS.md and 17 test files as an input
flag: the docs are rewritten, and the tests change their input to `--yubikey` (or drop it next to `--tpm` /
`--secure-enclave`), assertions unchanged, said in the commit. Tests, `HelpUsage`, the README, AGENTS.md and the skill's command list change with
it.

## What exists to build on

- `InitCommand`: flag parsing (#177's exact-flags check), `ExecuteKeyring` (YubiKey),
  `ExecuteHardwareKeyring` (TPM/Secure Enclave), `AssembleKeyring` (one machine slot + recovery),
  `VaultPasswordChoice`, `SecureEnclaveTouchChoice`, the recovery key warning.
- `slot add --yubikey` (`SlotCommand`): adding a one-key YubiKey slot to an existing keyring; the guided
  flow's extra YubiKeys are slots of that kind, added while `init` still holds the vault key.
- The simulated hardware used by the tests (TPM, Secure Enclave, YubiKeys).

## Left to the builder

- The order slots are created in, and which slot is the config's `KeyringSlotId` when several are made.
- Exact wording, and how terminal detection is done (`Console.IsInputRedirected` /
  `IsOutputRedirected` or the existing helpers).

## Tests (outcomes)

- Guided flow with simulated hardware: two YubiKeys + Secure Enclave picked → a vault that each of the
  three opens, plus the recovery key; nothing picked twice; an empty pick asks again.
- A chosen YubiKey failing mid-enrolment → no config or vault folder written.
- No terminal and no backend flag → the refusal, nothing written, no hardware touched.
- `--yubikey`, `--tpm`, `--secure-enclave` runs produce the same vaults as today's tests expect (existing
  init tests move from plain `init` to `init --yubikey` where they meant a YubiKey: an input change, said
  in the commit, assertions unchanged).
- macOS blocked-OTP case (simulated `ykman` failure with the final stderr line quoted above) → the explanatory
  line, the offer to carry on without that key, and the
  chip still offered.
- The guide contains this vault's folder and the commands for TPM, Secure Enclave and YubiKey machines.
