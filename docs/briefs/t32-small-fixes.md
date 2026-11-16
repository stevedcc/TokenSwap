# Brief T32: two small fixes: no first vault password while password slots lack their file (#320); `tswap names <pattern>...` (#7)

Issues: https://github.com/stevedcc/TokenSwap/issues/320 and https://github.com/stevedcc/TokenSwap/issues/7 (neither
has comments). Base: `origin/main` at c6d2ee3. Read AGENTS.md and CLAUDE.md first, then:
- for Task 1: `TswapCli/VaultPasswordChoice.cs` (`Decide`, `CreateNew`, `AskNew`, `Resolve`),
  `TswapCli/Commands/SlotCommand.cs` (`ExecuteAdd`'s first-enrolment tail and its `Resolve` call, `ExecuteAddFido2`,
  `ExecuteAddHardware` and its local `DecideNewSlotPassword`, which is brief T24's guard, `Reenrol` and its
  `firstPasswordFile`), `TswapCli/Commands/RecoverCommand.cs`, `TswapCore/VaultPassword/VaultPasswordRefusedException.cs`
  (`VaultPasswordMessages.MissingFile`), `TswapCore/Keyring/SlotPassword.cs` (`Requires`), and the tests
  `TswapTests/SlotAddHardwareScenarios.cs` (`FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused`,
  `FirstPasswordGuard_BeforeAnyPrompt`), `TswapTests/YubiKeyReenrolTests.cs` (`PasswordVaultOnAAndB`, `Reprogram`,
  `SlotAdd_KeySlotNeedsPassword_NoVaultPasswordFile_Refused`), `TswapTests/VaultPasswordEnrolmentTests.cs` and
  `TswapTests/SlotAddFido2Tests.cs` (`OtpVault`, `SlotAddFido2_WithPassword_UsesV2Kek`); `docs/vault-password-and-agent.md`.
- for Task 2: `TswapCli/Commands/NamesCommand.cs`, `TswapCli/CliJson.cs` (`JsonFlag`, `NameEntry`),
  `TswapCli/CommandRegistry.cs` (`Dispatch`, `HasGlobalFlagAmongOptions`), `TswapTests/CommandArgumentErrorTests.cs`,
  `TswapTests/VersionCommandTests.cs` (`VersionAfterAnotherCommand_IsThatCommandsUnknownOption_NamesIgnoresIt`),
  `TswapTests/Docs/CommandReferenceTests.cs` (`CommandReferenceIsCurrent`), `TswapCore/Prompt.cs`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services,
`TSWAP_CONFIG_DIR` and temp folders only. Tests never use the real clock or sleeps. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion (this brief sanctions
none). British spelling in new text.

**Review history.** None yet.

**Parallel briefs.** T29 owns the YubiKey service and cross-process locking, T30 redaction and matching
(`SecretMatcher`, the redactors), T31 prompt input reading and FIDO2 messages. T32 touches none of their code paths.
Two shared files, said here so the merge is expected: `TswapCli/VaultPasswordChoice.cs` (T32 changes `Resolve` and
adds two members; it does not touch `AskNew`, `AskUnverified` or any read of the console, which are T31's ground), and
`TswapCore/Prompt.cs` (one line, the `names` entry; T28 adds a `slot stage` line in another place of the same file).

## Why

**#320.** A vault whose keyring already has password slots, on a machine whose vault folder has no `vault-password`
file (it hasn't synced yet, or it was deleted), can be given a **new** `vault-password` file: `slot add --yubikey
--password`, `slot add --fido2 --password` and `recover ... --password` go through `VaultPasswordChoice.Resolve`, which
takes the "first password slot" path, asks for a new password twice and writes a freshly salted file. The existing
password slots don't open with that file (a different salt stretches the same password to a different key), and when
the folder syncs back the new file conflicts with the real one, or replaces it on every machine. The person sees
"New vault password:" where they expected "Vault password:", and later their password slots refuse a password they
know is right. `Reenrol` (`slot add --yubikey` for a key that already has slots) refuses the state only when one of
**that key's** slots needs the password; when only other slots do, it too asks twice and writes a new file. Brief T24
guarded `slot add --tpm` / `--secure-enclave` and left the existing commands to this issue.

**#7.** `tswap names` lists every name; with 50+ secrets an agent or a person has to read them all to find the
relevant ones. The issue asks for glob filtering, `tswap names 'k8s-authentik-*'`, and suggests the positional form.

## The design (decided; rulings marked)

### #320: no command creates a first vault password while password slots exist and the file is missing

**Every command that can create a vault's first password, and what each does now:**

| Command | Path | Exposed today | T32 |
|---|---|---|---|
| `slot add --yubikey` (a key with no slot yet) | `ExecuteAdd` → `Resolve` → `CreateNew` | yes | refused (the guard in `Resolve`) |
| `slot add --fido2` | `ExecuteAddFido2` → `Resolve` → `CreateNew` | yes | refused (the guard in `Resolve`) |
| `recover --yubikey\|--tpm\|--secure-enclave` | `RecoverCommand.Execute` → `Resolve` → `CreateNew` | yes | refused (the guard in `Resolve`) |
| `slot add --yubikey` (a key that has slots: re-enrolment) | `Reenrol` → `AskNew` + `firstPasswordFile` | yes, when only other slots need the password | refused (a guard in `Reenrol`) |
| `slot add --tpm` / `--secure-enclave` | `ExecuteAddHardware` → `DecideNewSlotPassword` | no (T24) | unchanged |
| `init` (any backend, guided or not) | `InitCommand.NewVaultPassword` → `CreateNew` | no: a new vault, new `K_v` and vault id, no existing slots | unchanged |
| `slot request --password` | `ReadRequestVaultPassword` | no: it refuses a folder without the file (`RequestPasswordFileMissingText` / `RequestNoPasswordYetText`) | unchanged |
| `slot accept` | `WriteMissingVaultPassword` | no: it writes the approving vault's own file, from the approve file | unchanged |
| `vault merge` | `vaultPasswordToCopy` | no: it copies the other copy's own file | unchanged |

**The guard.** New in `VaultPasswordChoice`:
- `internal static void RefuseFirstPasswordWithoutFile(VaultPasswordFile? file, TswapCore.Keyring.Keyring keyring)`:
  throws `new VaultPasswordUnavailableException(FirstPasswordWithoutFileText)` when `file is null &&
  keyring.Slots.Any(SlotPassword.Requires)`; does nothing otherwise.
- `public const string FirstPasswordWithoutFileText = VaultPasswordMessages.MissingFile + " Until it is back, no new
  slot gets the vault password: a new vault-password file would lock out the slots that need the old one. To add
  this slot without a password instead, run the command again with --no-password. Nothing was changed.";`
  The full text the person sees is therefore:
  ``This vault's slot needs the vault password, but the vault folder has no vault-password file. If it is synced, wait
  for the sync; otherwise restore it from a backup of the folder. Until it is back, no new slot gets the vault
  password: a new vault-password file would lock out the slots that need the old one. To add this slot without a
  password instead, run the command again with --no-password. Nothing was changed.``
- `Resolve`'s `byte[] vaultId` parameter becomes `TswapCore.Keyring.Keyring keyring` (it needs the slots; the vault id
  is `keyring.VaultId`). Its three callers (`ExecuteAdd`, `ExecuteAddFido2`, `RecoverCommand.Execute`) pass the
  `keyring` they already hold. In `Resolve`, after `Decide` chose a password and `store.ReadVaultPassword` returned
  null, call `RefuseFirstPasswordWithoutFile(null, keyring)` before `CreateNew`. So the refusal comes after the unlock
  (as T24's does) and before any password prompt, enrolment or write. Update `Resolve`'s doc comment.
- `Reenrol`: right after the existing `if (keySlotNeedsPassword && file is null) throw ... MissingFile` line, add
  `if (newSlotPassword) VaultPasswordChoice.RefuseFirstPasswordWithoutFile(file, keyring);`. That is before the
  recovery key is read, before any prompt and before the liveness challenges. The existing check stays first and keeps
  its plain `MissingFile` text, because when the key's own slot needs the password, `--no-password` doesn't help.
- Ruling: **the predicate is `keyring.Slots.Any(SlotPassword.Requires)`**, exactly T24's, so the four guarded paths
  agree. A slot that `Classify` calls `NeedsNewerTswap` or `Corrupt` doesn't count. Why: this build can't tell whether
  such a slot needs the password, and refusing on a guess would block a vault with one odd slot from ever getting its
  first password. The cost if this is wrong: a password slot made by a newer tswap could be stranded by a new file made
  here. That needs a mixed-version fleet and a missing file at once.
- Ruling: **`ExecuteAddHardware` keeps T24's inline guard and its plain `MissingFile` text.** Why: there, when this
  machine's own slot needs the password, the check refuses with `MissingFile` under `--no-password` too, so the
  `--no-password` advice would be wrong. The cost: `slot add --tpm --password` says less than `slot add --yubikey
  --password` in the same state. The two TPM/SE tests that pin it (`FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused`,
  `FirstPasswordGuard_BeforeAnyPrompt`) stay as they are.

**Ruling: refuse, not warn, for every one of these commands, `recover` included.** The owner prefers warnings over
refusals unless a refusal protects the vault. This one does:
- A warning followed by the old behaviour still writes the new file. In a synced folder it reaches every machine, and
  there either conflicts with the real file or replaces it. Each machine's password slots then refuse the right
  password (`VerifierMismatch`, or a wrong-password error). Undoing that needs the old file from a backup, which is
  exactly what this machine lacks.
- tswap has no "change the vault password" operation (`docs/vault-password-and-agent.md`: "Changing the password means
  a new vault"), and a new file is one in effect.
- The refusal leaves the person a way forward in the same command: `--no-password` adds the slot without a password.
  `recover --no-password` still breaks the glass, and so does `slot add --yubikey --no-password`. Waiting for the sync
  or restoring the file, then running the command again, gives the slot its password.
- The issue asks whether `recover --password` needs an exception, since creating a new password file on purpose may be
  its point. No: `recover` gets this machine into the vault, and `--no-password` does that. Creating a new password
  file would also disable every other machine's password slots, which is a separate decision from a break-glass
  recovery. tswap can't tell "not synced yet" from "lost for good". The cost if this is wrong: an owner whose file is
  really gone can't give new slots a password until a future change-password feature exists (owner question 1).

**Docs.** `docs/vault-password-and-agent.md`, after the "First and later slots" bullet, a new bullet:
"**A missing `vault-password` file.** When the vault has password slots but the vault folder has no `vault-password`
file (it hasn't synced yet, or it was deleted), no command makes a new one: `slot add` and `recover` with a password
refuse before asking for it, because a new file would lock out every slot that needs the old one. `--no-password` still
adds the slot. Wait for the sync or restore the file from a backup, then add the password slot." No help or usage
text changes, and no prompt change (the agent never runs these commands).

### #7: `tswap names [<pattern>...] [--json]`

- Ruling: **positional patterns, no `--filter` flag.** Why: the issue offers it, and it matches `ls`, which people
  already know for this. One form to document. The cost if wrong: adding `--filter` later is purely additive.
- Ruling: **glob, matched by the BCL's `System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(pattern, name,
  ignoreCase: true)`**: `*` is any run of characters (none included) and `?` is exactly one. No regex, no `[...]`
  classes, no braces. Why: the issue asks for glob, not regex. The owner prefers an established library to a
  hand-written matcher, and this one has exactly these two wildcards. (Checked on .NET 11: `k8s-*` matches `k8s-foo`;
  `*-pg-*` matches `k8s-authentik-pg-local`; `db?` matches `db1` but not `db` or `db12`; `K8S-*` matches `k8s-x` only
  with `ignoreCase: true`.) The cost: someone expecting regex gets the no-match line, which shows the glob form.
- Ruling: **a pattern matches the whole name** (anchored, as in a shell): `pg` lists only a secret named `pg`, and
  `*pg*` lists every name containing `pg`. Why: a glob is anchored everywhere people meet one, and the issue's
  examples write the `*` themselves. The cost: a bare word finds nothing. The no-match line says how to write the
  pattern.
- Ruling: **case is ignored.** Why: `names` is for finding things, and a few extra lines (both `DB` and `db`) cost
  nothing, since names are shown anyway. Missing a secret because of its case is the worse failure. Names are ASCII
  (`[a-zA-Z0-9_-]`), so no culture question arises. The cost: two names that differ only in case can't be told apart
  by a pattern, but both are listed and visibly different.
- Ruling: **several patterns are a union.** A name is listed when any pattern matches it, once, in the order plain
  `names` uses.
- Ruling: **a pattern has only the characters of a secret name plus `*` and `?`** (`^[A-Za-z0-9_*?-]+$`), checked
  before the config is loaded or anything is unlocked. Anything else, the empty pattern included, is refused with
  `NamesCommand.PatternText` (a `TswapException`, exit 1):
  ``A names pattern is made of the characters of a secret name (letters, digits, '_' and '-') and the wildcards '*'
  (any run of characters) and '?' (one character). Quote each pattern ('k8s-*') so the shell doesn't expand it into
  file names.``
  Why: it turns the commonest shell accident, an unquoted `k8s-*` expanded into `k8s-notes.txt`, into a clear refusal
  instead of a silent miss, and it rules out `\` (the BCL matcher's escape) and `[`, which would mean something else
  to someone used to a shell. The cost: none; no name can contain any other character.
- Ruling: **arguments starting with `-` are options, as today.** `--json` is used, and any other option is **ignored**,
  as `names` has always ignored unknown options (`VersionCommandTests.VersionAfterAnotherCommand_IsThatCommandsUnknownOption_NamesIgnoresIt`
  pins that `names --version` lists the names; it must keep passing unchanged). `-v`/`--verbose` before the first
  pattern still gets `CommandRegistry`'s global-flag hint, and `--help`/`-h` there still prints the usage. So a pattern
  can't start with `-` (to match names starting with `-`, begin the pattern with `?` or `*`). One side effect, said in
  no doc: the issue's `names --filter 'k8s-*'` works, because `--filter` is ignored and `k8s-*` is the pattern.
- Ruling: **output stays stable for scripts.** With patterns, the text output is exactly the lines plain `names`
  prints for the matching names: the same order (the existing `OrderBy(s => s.Name)`), the same format, and the same
  column width, which stays `Math.Min(40, <longest name in the whole vault>)` and is not recomputed over the filtered
  set. So `tswap names 'k8s-*'` prints exactly what `tswap names` prints for those names, and a script that cuts
  columns behaves the same either way. `--json` prints the same `NameEntry` array, filtered, in the same order. Without
  patterns nothing changes, byte for byte.
- Ruling: **no match is not an error.** With patterns and no matching name (an empty vault included): exit 0, nothing
  on stdout in text mode and `[]` in JSON mode, and on stderr `NamesCommand.NoMatchText`:
  ``No secret name matches the pattern(s) given (a pattern matches whole names, e.g. 'k8s-*' or '*-pg-*'; quote
  patterns so the shell doesn't expand them).``
  Plain `names` on an empty vault keeps printing `No secrets stored.` on stdout. Why exit 0: an empty result of a
  listing is an answer, and `tswap` uses exit 1 for failures, which an agent would read as "the command broke". The
  cost: a script tests for empty output (or `[]`) instead of an exit code, and changing that later would break
  scripts.
- Ruling: **no message echoes an argument.** Neither text names the pattern given. Why: `names` is agent-safe, and an
  argument made of name characters can be a pasted secret value. Keeping arguments out of the output keeps them out of
  logs and transcripts. The cost: with several patterns, the refusal doesn't say which one is bad.
- **Agent safety, unchanged:** no sudo (`RequiresSudo` stays `false`), the same unlock and the same metadata-only load
  (`view.LoadAll(FormatTwoRecords.Decode)`, values never decoded), and `FingerprintTexts.WarnFormatTwo` stays in the
  `finally`. Filtering runs over the loaded `SecretInfo` list only.

**Help and docs.**
- `HelpUsage` → `names [<pattern>...] [--json]`. `Description` → `List secret names (no values); with patterns, only
  the names matching one of them (* any characters, ? one character, case ignored; quote them)`.
- Regenerate `docs/commands.md`'s generated block: `TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter
  CommandReferenceIsCurrent`, then run `CommandReferenceIsCurrent` again without the variable.
- `docs/agent-integration.md`, the `names` row: `| \`names\` | List secret names, all or those matching a pattern |
  Reveals what secrets exist (names only) |`.
- `README.md`, after `tswap names` in the "See which secrets exist" block: `tswap names 'k8s-*'   # only the names
  that match (quote the pattern)`.
- Ruling: **the agent prompt mentions it.** `Prompt.cs`'s line `` - `%CMD% names` — List all secret names (no values
  shown)`` becomes `` - `%CMD% names [<pattern>...]` — List secret names (no values shown); with quoted glob patterns
  (`*`, `?`, whole names, case ignored) only the names that match, e.g. `%CMD% names 'k8s-*'` ``. Rules 4 and 6
  (`Check \`%CMD% names\` ...`) stay. Why: the issue's motivation is agents finding names among many. The cost: the
  prompt hash changes. No test pins its value (`PromptTests` checks determinism and content only); say in the commit
  that the prompt changed.

## Task 1: the first-password guard (#320)

Tests in a new `TswapTests/FirstVaultPasswordGuardTests.cs` (`FleetMachine`s as in `VaultPasswordEnrolmentTests`, two
simulated YubiKeys A and B and a simulated TPM). The shared state is a TPM vault without a password whose YubiKey A
slot needs the password, with the file gone: `init --tpm --no-password` (keep the recovery key from its output),
`create db`, plug only A, `slot add --yubikey --password` (the password twice), check that `vault-password` exists,
delete it, then plug only B. Each refusal test asserts all of: exit non-zero; stderr contains
`VaultPasswordChoice.FirstPasswordWithoutFileText`; stderr has no `New vault password` and no
`TerminalPasswordProvider.PromptText`; the vault folder has no `vault-password` file; the keyring file's bytes and
`config.json`'s bytes are those from before the run; and B was never challenged (no `m.Keys.Challenges` entry for B).
- `SlotAddYubiKey_Password_PasswordSlotsWithoutTheFile_Refused`: `slot add --yubikey --password` at a terminal, with
  the password twice on stdin.
- `SlotAddYubiKey_AnsweredYes_PasswordSlotsWithoutTheFile_Refused`: no flag, at a terminal, `yes` and the password
  twice on stdin (the `Decide` question path).
- `SlotAddYubiKey_NoPassword_PasswordSlotsWithoutTheFile_Adds`: `--no-password`: exit 0, still no `vault-password`
  file, and B's new slot doesn't need the password. Outcome: with the TPM replaced (`m.Tpm` = new random bytes) and
  only B plugged, `get db` returns the value without a password prompt.
- `Recover_Password_PasswordSlotsWithoutTheFile_Refused`: `recover --yubikey --password`, stdin = recovery key, then
  the password twice: the refusal, and the whole password part of stdin unread
  (`m.LastConsole!.In.ReadToEnd()` == the password lines).
- `Recover_NoPassword_PasswordSlotsWithoutTheFile_Recovers`: `recover --yubikey --no-password` with the recovery key:
  exit 0; with the TPM replaced and only B plugged, `get db` returns the value.
- In `TswapTests/SlotAddFido2Tests.cs` (its own `Context`/`Run`/`OtpVault`), new test
  `SlotAddFido2_Password_PasswordSlotsWithoutTheFile_Refused`: `OtpVault()`; add FIDO2 key A with `--password` (as
  `SlotAddFido2_WithPassword_UsesV2Kek` does); delete the vault folder's `vault-password`; add key B; `slot add --fido2
  --serial <B> --password`: exit non-zero, the text, no `vault-password` file, the keyring unchanged
  (`KeyringCodec.Encode(Keyring())` bytes before == after), and no `FakeFido2Op.MakeCredential` in `_fido2.Calls`
  after the snapshot point (no credential made on B).
- In `TswapTests/YubiKeyReenrolTests.cs`, two new tests with `PasswordVaultOnAAndB(bPassword: false, recovery: true)`,
  `Reprogram(m, SerialB)`, the vault folder's `vault-password` deleted, `m.Keys.Challenges.Clear()`, and only B plugged:
  - `SlotAdd_Reenrol_NewSlotPassword_OtherSlotsNeedTheMissingFile_Refused`: `slot add --yubikey --password
    --recovery-key-stdin`, stdin = `_recoveryKey`, then the password twice (not a terminal). Asserts exit non-zero, the
    text, `m.Keys.Challenges` empty (no liveness check), the keyring and config bytes unchanged, no `vault-password`
    file, `m.Keys.Programmed` empty, and all of stdin unread (`m.LastConsole!.In.ReadToEnd()` == the whole stdin).
  - `SlotAdd_Reenrol_NoPassword_OtherSlotsNeedTheMissingFile_Reenrols`: the same with `--no-password` and only the
    recovery key on stdin: exit 0, B has a second slot that doesn't need the password, and no `vault-password` file.
- Existing tests that must pass unchanged, among them: `SlotAddHardwareScenarios`'
  `FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused` and `FirstPasswordGuard_BeforeAnyPrompt` (via
  `SlotAddTpmTests` / `SlotAddSecureEnclaveTests`), `YubiKeyReenrolTests.SlotAdd_KeySlotNeedsPassword_NoVaultPasswordFile_Refused`
  (still the plain `MissingFile`: the existing check runs before the new one), and `VaultPasswordEnrolmentTests`'
  `SlotAdd_FirstPasswordSlot_OfAPasswordFreeVault_CreatesTheFile` and `Recover_WithPassword_UsesTheVaultPassword` (a
  vault with no password slots still gets its first file).
- Break-it-once: remove the `RefuseFirstPasswordWithoutFile` call from `Resolve`; then
  `SlotAddYubiKey_Password_PasswordSlotsWithoutTheFile_Refused` and `Recover_Password_PasswordSlotsWithoutTheFile_Refused`
  fail (exit 0, a new `vault-password` file). Remove it from `Reenrol`; then
  `SlotAdd_Reenrol_NewSlotPassword_OtherSlotsNeedTheMissingFile_Refused` fails.
- Docs: the `docs/vault-password-and-agent.md` bullet above.

Files: `TswapCli/VaultPasswordChoice.cs`, `TswapCli/Commands/SlotCommand.cs` (`ExecuteAdd`'s and `ExecuteAddFido2`'s
`Resolve` calls, `Reenrol`; nothing else), `TswapCli/Commands/RecoverCommand.cs`, `docs/vault-password-and-agent.md`,
`TswapTests/FirstVaultPasswordGuardTests.cs` (new), `TswapTests/SlotAddFido2Tests.cs` (one test added),
`TswapTests/YubiKeyReenrolTests.cs` (two tests added).

## Task 2: `names` patterns (#7)

In `NamesCommand.Execute`, after `JsonFlag.Consume`: the patterns are the arguments that don't start with `-` (other
options ignored, as today). Each is checked against `^[A-Za-z0-9_*?-]+$` (refusal `PatternText`) before
`ctx.Storage.LoadConfig()`. `Write` gets the patterns; with none it is exactly today's code. With patterns it computes
the width over all of `secrets`, then writes only the entries any pattern matches, through
`FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: true)`. If none matches, it writes nothing (text)
or `[]` (JSON) to stdout and `NoMatchText` to stderr, and returns 0. `PatternText` and `NoMatchText` are `public const
string`s on `NamesCommand`. Help and docs as above.

Tests in a new `TswapTests/NamesPatternTests.cs` (one `FleetMachine` with `Sudo = false`, `init --yubikey --no-password
--no-recovery` as in `VersionCommandTests`). The vault holds `k8s-authentik-pg-password`, `k8s-authentik-secret-key`,
`k8s-paperless-pg-app-password`, `db`, `db1`, `db12`, `Db-Admin`, `api-key`, and a name longer than every other that
matches none of the patterns below (for example `zz-the-longest-name-of-all-in-this-vault`, at most 40 characters). The
values come from `add` with known strings, and `k8s-authentik-secret-key` is burned. `Plain` is the stdout of plain
`names`.
- `Pattern_PrintsExactlyThePlainLinesOfTheMatchingNames`: `names 'k8s-*'` gives exit 0 and stdout ==
  the lines of `Plain` whose name starts with `k8s-`, joined in `Plain`'s order (byte-identical, padding included; the
  burned one keeps ` [BURNED]`), and stderr has no `No secret name matches`. Run without sudo.
- `SeveralPatterns_AreAUnion_EachNameOnce`: `names 'k8s-*' '*-pg-*' 'k8s-authentik-*'` == the lines of `Plain` for the
  three `k8s-` names, each once, in `Plain`'s order.
- `QuestionMark_IsExactlyOneCharacter`: `names 'db?'` lists `db1` only.
- `Case_IsIgnored`: `names 'DB*'` lists `db`, `db1`, `db12`, `Db-Admin` (their `Plain` lines).
- `Pattern_MatchesWholeNames`: `names pg`: exit 0, stdout `""`, stderr == `NoMatchText` + newline; `names '*pg*'` lists
  the two `-pg-` names.
- `Json_IsThePlainJsonFiltered`: `names --json 'k8s-*'` and `names 'k8s-*' --json` each deserialise (`CliJsonContext.Default.ListNameEntry`)
  to exactly the entries of plain `names --json` whose name starts with `k8s-`, in the same order, the burned flag and
  time included.
- `NoMatch_EmptyStdout_ExitZero`: `names 'nothing-*'` gives exit 0, stdout `""`, stderr == `NoMatchText` + newline;
  `names --json 'nothing-*'` gives stdout `[]` + newline, exit 0. On a second, freshly initialised empty vault,
  `names 'x*'` gives the same (no `No secrets stored.`), while plain `names` there still prints `No secrets stored.`.
- `NoValueInTheOutput`: across every run above, no stored value appears in stdout or stderr.
- `BadPattern_RefusedBeforeTheVaultIsRead` (Theory, on a `FleetMachine` with no `init`, as in
  `CommandArgumentErrorTests`): `k8s-notes.txt`, `''`, `a[b]`, `a\b`, `a b`, `k8s-*` plus `x.y`: exit 1, stdout `""`,
  stderr == `$"\n❌ Error: {NamesCommand.PatternText}{Environment.NewLine}"` (that file's `ErrorLine` shape). Without
  `init`, any check after the vault load would fail with another text, which is what proves the order.
- `UnknownOption_StillIgnored`: `names --filter 'k8s-*'` == `names 'k8s-*'` (stdout and exit), and `names --version`
  still == plain `names` (the existing `VersionCommandTests` test must also pass unchanged).
- `HelpShowsThePatterns`: `names --help` stdout contains `tswap names [<pattern>...] [--json]`.
- `CommandReferenceIsCurrent` passes after regenerating.
- Break-it-once: `ignoreCase: false`, and `Case_IsIgnored` fails. Recompute the width over the filtered entries, and
  `Pattern_PrintsExactlyThePlainLinesOfTheMatchingNames` fails. Drop the pattern check, and
  `BadPattern_RefusedBeforeTheVaultIsRead` fails (the uninitialised vault's error instead).

Files: `TswapCli/Commands/NamesCommand.cs`, `TswapCore/Prompt.cs` (the `names` line only), `docs/commands.md`
(regenerated block), `docs/agent-integration.md` (the `names` row), `README.md` (one example line),
`TswapTests/NamesPatternTests.cs` (new). T30 owns matching for redaction (`SecretMatcher`); `names` uses the BCL
matcher and touches none of T30's files.

## Out of scope

- A "change the vault password" or "replace a lost `vault-password` file" operation, or a flag that knowingly writes
  a new file while password slots exist (owner question 1).
- T24's `slot add --tpm`/`--secure-enclave` text (stays plain `MissingFile`).
- Patterns for `burned`, `list` or any other command; regex or character classes; an exit code for "no match".
- Refusing unknown `names` options (needs the T18 test changed; owner question 2).
- Shell completion of secret names.

## Owner questions

1. A `vault-password` file that is really lost (no sync, no backup): after T32 no command gives any new slot a
   password in that vault, and the old password slots are dead anyway. Do you want a deliberate path later (for
   example `slot add --password --new-vault-password` that says it strands the old password slots), or is "make a new
   vault" (today's documented answer for changing the password) enough?
2. `names` keeps ignoring unknown options (T18's pinned behaviour), so `names --filter 'k8s-*'` works by accident.
   Keep that, or refuse unknown options (a usage error) and change
   `VersionAfterAnotherCommand_IsThatCommandsUnknownOption_NamesIgnoresIt`?
