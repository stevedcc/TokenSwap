# Brief T56: four small fixes for 0.3.3 (#396, #395, #382, #361)

Milestone 0.3.3. Base: `origin/main` at 666336c (this brief's branch, `brief/t56`, starts there). Read AGENTS.md and
CLAUDE.md first, then: `TswapCli/Commands/BurnedCommand.cs` (all); `TswapCli/Commands/FieldCommand.cs` (the summary,
`Execute`, `Adopt`); `TswapCore/Fields/FieldSecretCheck.cs`; `VaultView.BuildIndex` (`TswapCore/VaultView.cs:121`);
`FingerprintHit` and `FingerprintIndex.Scan` (`TswapCore/Fingerprints/FingerprintIndex.cs:9`, `:83`);
`TswapCli/CliRunner.cs`; `TswapCli/CliEnvironment.cs` (the class's properties); `TswapCli/Commands/SlotEnrol.cs`
(`EnrolFileSeams`, `EnrolInteractively` from step 3 to step 4, `WriteLocal`, `ApproveNotSavedText`);
`SystemConsole.ReadLineWithoutEcho`; and the tests `MetadataCommandTests.Burned_DecryptsNoValue`, `FieldAdoptTests`,
`SlotEnrolTests` (the Enter gate section and `LocalAccessFails`) and, in `EndToEndTests`, `MakePsi`, `EnrolOnPty`,
`WaitForKeyRead` and the three `Enrol_*AtTheEnterGate_*` tests.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change except the two this brief
names** (Task 1: `MetadataCommandTests.Burned_DecryptsNoValue`; Task 4:
`SlotEnrolTests.EnterGate_ApproveFileNotDeletable_StillSaysWhatIsLeft`); both are sanctioned by the controller for
this brief, for the reasons given there. If any other existing test fails on an assertion, stop and list it.

The four tasks are independent: any order, no shared code. Do not touch `Redact`, `ToComment`, `SecretMatcher` or
`Validation` (other briefs own them), and do not change `TswapCore/Prompt.cs` (its text is hashed by `prompt-hash`).

## What is wrong (evidence)

- **#396.** `BurnedCommand.Write` (`BurnedCommand.cs:54-75`) prints the outstanding table under `⚠ Burned Secrets (n):`
  and the rotated history under `Rotated (burn superseded by a newer value) (n):`; each row (`PrintTable`, `:86-99`) is
  only name, date and reason. With nothing outstanding the first line is `No outstanding burned secrets.` and the rest
  is history. `tswap burned | tail -8` cut off both headings, and eight rotated rows were read as eight secrets needing
  rotation. `--json` (`:45-52`) carries `status` per entry and was read correctly. Also: the header pads `BURNED AT` to
  18 (`:81`) while the date is 16 wide, so `REASON` sits two columns right of the reasons (visible in
  `Burned_DecryptsNoValue`'s expected text).
- **#395.** `field adopt NAME FIELD --from SECRET` checks the value against every stored value except SECRET's own
  (`FieldCommand.cs:230-236`, `BuildIndex(keys, except: secret)`). Two username secrets `u1` and `u2` with the same
  value: adopting from `u1` is refused because `u2` holds it, and the other way round, so neither can ever be adopted
  (`FieldAdoptTests.FieldAdopt_SameLiveValueElsewhere_Refused` pins the refusal). The refusal is guard rail 1's generic
  `Refused: the value for 'NAME.FIELD' contains a stored secret value. ...` (`FieldSecretCheck.cs:34`), which names no
  secret, so the owner had to guess; the way out was deleting one secret. `field adopt` runs only under sudo
  (`RequireSudo`, `FieldCommand.cs:192`, before the vault is opened), where `get` shows any value, so naming the other
  secrets tells the caller nothing sudo doesn't.
- **#382.** Reproduced with tswap 0.3.1 on Linux, test mode, a vault in a temp config folder, run from a deleted folder
  (`sh -c 'cd "$d" && rmdir "$d" && exec tswap …'`):

  | Command | Output | Exit |
  |---|---|---|
  | `run true {{foo}}` | `❌ Error: Unable to find the specified file.` | 1 |
  | `run /usr/bin/true {{foo}}` | (runs) | 0 |
  | `init --tpm --no-recovery` (fresh folder) | `Sealing a new key to this machine's TPM...` then `❌ Error: Unable to find the specified file.` | 1 |
  | `check x.yaml` | `❌ Error: Path not found: x.yaml` | 1 |
  | `names`, `create foo`, `--version` | normal | 0 |

  .NET can't resolve the current folder (`getcwd` fails with ENOENT), and code that needs it throws a
  `FileNotFoundException` with no path; a bare program name fails because .NET's process start looks in the current
  folder before `PATH` (the absolute path works). `CliRunner.Run`'s catch (`CliRunner.cs:28-31`) prints only
  `ex.Message`.
- **#361.** `EnrolInteractively` writes `approve.json` (`SlotEnrol.cs:284`), prints `Approve file received: …` (it even
  says "press Ctrl-C now" if the fingerprints differ, `:287-289`), then the gate prints the prompt and calls
  `ReadLineWithoutEcho` (`:303`). Only inside that read is `TreatControlCAsInput` on (`SystemConsole.cs:62`), so Ctrl-C
  is a key and the gate deletes the file (`:312`). A Ctrl-C before the read starts reaches a terminal with ISIG on: on
  Linux and macOS the line discipline sends SIGINT and the process dies by signal; on Windows the console sends
  CTRL_C_EVENT and .NET's default ends the process (no `CancelKeyPress` handler is registered here; the only one is
  `AgentCommand.cs:651`). Either way `approve.json` stays in the enrolment folder without the person's Enter.

## Task 1 (#396): `burned` starts with a count line, and every row says its state

`BurnedCommand.Write`, text output only (`--json` unchanged):

- **Nothing burned at all:** unchanged, `No burned secrets. All secrets are clean.`
- **Otherwise the first line** of stdout is the summary (no blank line before it):
  - something outstanding: `$"⚠ {n} outstanding (rotate these), {m} rotated (history, nothing to do)."`
  - nothing outstanding: `$"No burned secrets need rotation: 0 outstanding, {m} rotated (history, nothing to do)."`
    (this replaces `No outstanding burned secrets.`).
- The two sections follow as today (headings, the `→ Rotate these secrets` line, the blank lines), with a **`STATE`
  column first** in each table: `outstanding` in the burned table, `rotated` in the history table. `PrintTable` takes
  the state word; the column is the word's width. A name longer than the name column keeps its own line, which now also
  starts with the state: `$"{state}  {name}"`, then `$"{state}  {pad}  {when}  {reason}"`. So every row line carries its
  state, and no slice of the output reads as a to-do list.
- The `BURNED AT` column is 16 wide (the width of `Hlc.Display`'s `yyyy-MM-dd HH:mm`), so `REASON` lines up.

`MetadataCommandTests.Burned_DecryptsNoValue`'s text expectation becomes exactly (sanctioned: #396 asks for this output;
the JSON half of the test does not change):

```
⚠ 1 outstanding (rotate these), 1 rotated (history, nothing to do).

⚠ Burned Secrets (1):
STATE        NAME  BURNED AT         REASON
------------------------------------------------------------
outstanding  beta  2026-01-02 03:14  seen in a log

→ Rotate these secrets: tswap rotate <name> [len], or <source> | tswap ingest --rotate <name>.

Rotated (burn superseded by a newer value) (1):
STATE    NAME   BURNED AT         REASON
------------------------------------------------------------
rotated  gamma  2026-01-02 03:24  pasted in chat

```

The other tests that read `burned` text (`CommandTests.Burned_*`, `RotateTests`, `EndToEndTests`, `HelpTests`,
`RecordStoreFileLayerTests`, `MigrateToRecordsTests` (one line per row containing `leak `),
`FormatTwoVaultCommandTests`) keep passing unchanged; check that they do.

New tests (in-process, `FleetMachine` with a fixed clock, as `MetadataCommandTests`):

| Vault | Expected stdout |
|---|---|
| no burns | `No burned secrets. All secrets are clean.\n` exactly |
| 0 outstanding, 2 rotated | first line `No burned secrets need rotation: 0 outstanding, 2 rotated (history, nothing to do).`; every line after the history heading's header and dash lines starts with `rotated  ` |
| 2 outstanding, 0 rotated | first line `⚠ 2 outstanding (rotate these), 0 rotated (history, nothing to do).`; each row starts with `outstanding  ` |
| one rotated secret with a 45-character name | the name line and its continuation line both start with `rotated  ` |
| the 0-outstanding, 9-rotated vault of #396 | `stdout` split into lines, the last 8: every non-empty one starts with `rotated  ` or is the dash/header line (no line looks outstanding) |

Key test: the 0-outstanding row. Break it once by printing `No outstanding burned secrets.` as the first line again; it
must fail.

## Task 2 (#395): `field adopt` names the other holders, and adopts several secrets in one command

**The form.** `field adopt NAME FIELD --from SECRET [NAME FIELD --from SECRET]…`: one or more groups of four. The
`Execute` arm (`FieldCommand.cs:60-61`) matches `["adopt", .. var rest]` where `rest.Length` is a positive multiple of
4 and every group is `[name, field, "--from", secret]` with none of `name`, `field`, `secret` starting with `-`;
anything else is the usage error, as now. `HelpUsage` and `Usage` read `field adopt NAME FIELD --from SECRET [NAME FIELD
--from SECRET]…`; the class summary says so. Regenerate the command block of `docs/commands.md`
(`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`).

**Checks, all before anything is written, in this order** (the first failure throws; nothing is staged until all
pass):

1. Per group, in the order given: `Validation.ValidateName(name)`, `ValidateName(secret)`, `FieldRules.ValidateName(field)`,
   and `secret == name` → the existing `'field adopt' needs two different secrets: '{name}' can't adopt its own value.`
2. Across groups: a SECRET named twice → `$"'field adopt' names '{secret}' twice after --from."`; a `NAME.FIELD` named
   twice → `$"'field adopt' names '{name}.{field}' twice."`; a SECRET that is another group's NAME →
   `$"'{secret}' is adopted (and deleted) in this command, so it can't receive a field in it too."`.
3. `ctx.RequireSudo("field adopt")`, then the vault opens as now (`ThrowIfAnyUnreadable`, the not-fingerprinted
   refusal, the older-variants note).
4. Per group, in order, today's checks: NAME exists, `NAME.FIELD` has no value, SECRET exists, SECRET has no fields of
   its own; then `ResolveToken(secret)` and `FieldRules.Validate`.
5. Guard rail 1, per group: one index for the command, built without **every** SECRET of the command (they are all
   deleted in the same commit). Add `VaultView.BuildIndex(FingerprintKeys keys, IReadOnlySet<string> except)` (ordinal);
   the existing `BuildIndex(keys, string? except)` calls it. A value it finds is refused with the message below.

Then one commit: one `writer.SetFields(name, edits, who)` per distinct NAME (its groups' `FieldEdit`s together, in the
order given), then `writer.Delete(secret)` per group, then `writer.Commit()`. Stdout: today's `✓` line, one per group, in
the order given. Each decrypted value is handled as today (no value in any message).

**The refusal names the holders** (adopt only; `field set` and the value commands keep guard rail 1's message, which
names nothing, since they run without sudo). Add to `FieldSecretCheck`:

```csharp
public sealed record SecretHolder(string Name, bool PreviousOnly);

/// Every secret whose stored value <paramref name="value"/> contains (scanned as Contains scans: NFC and as given),
/// distinct by name, ordered by name (ordinal); PreviousOnly when every hit on that name is a previous value.
public static IReadOnlyList<SecretHolder> Holders(FingerprintIndex stored, string value)
```

and in `FieldCommand`, `internal static string AdoptHolderRefusal(string name, string field, IReadOnlyList<SecretHolder> holders)`:

```
Refused: the value for '{name}.{field}' contains a stored secret value. Fields are visible; a secret never goes in one. It contains the value of {holders}. If those hold the same setting (one username for two services, say), adopt them in the same command, one NAME FIELD --from SECRET group each; otherwise change them first.
```

`{holders}` is the list joined with `", "`, each `'{Name}'`, or `'{Name}' (its previous value)` when `PreviousOnly`.
The first two sentences are guard rail 1's message unchanged, so `FieldAdopt_SameLiveValueElsewhere_Refused` keeps
passing as it is. No message contains a value.

Tests (in `FieldAdoptTests`; `u1`, `u2`, `u3` hold `svc-backup`; every refusal also asserts that nothing was written and
that neither stdout nor stderr contains `svc-backup`):

| Command (after setup) | Outcome |
|---|---|
| `adopt db username --from u1 b username --from u2` | exit 0; `db.username` and `b.username` are `svc-backup`; `u1`, `u2` tombstones; two `✓` lines in order |
| `adopt db username --from u1` (u2 live) | refused; stderr contains `It contains the value of 'u2'. If those hold the same setting` |
| as above, `u2` and `u3` live | refused naming `'u2', 'u3'` in that order |
| `adopt db username --from u1 b username --from u2` (u3 live) | refused naming `'u3'` only |
| `adopt db username --from u1`, `u2` rotated away from `svc-backup` | refused naming `'u2' (its previous value)` |
| `adopt db username --from u1 db host --from h1` (`h1` holds `db.example`) | exit 0; both fields on `db`, one field write |
| `adopt db username --from u1 nope username --from u2` | `No secret 'nope'.`; `u1` not deleted |
| `adopt db username --from u1 b kind --from u2` | the `kind` format refusal for group 2; group 1 not written |
| `adopt db username --from u1 b username --from u1` | `'field adopt' names 'u1' twice after --from.` |
| `adopt db username --from u1 db username --from u2` | `'field adopt' names 'db.username' twice.` |
| `adopt db username --from u1 u1 host --from u2` | `'u1' is adopted (and deleted) in this command, so it can't receive a field in it too.` |
| without sudo, two groups | the sudo refusal; nothing written |

Add to `FieldAdopt_BadArguments_Usage`'s rows: `adopt db username --from u1 b`, `adopt db username --from u1 b
username u2 x`, `adopt db username --from u1 b username --from` (each the usage error); its existing rows are kept.
A `Holders` unit test: a value containing `u2`'s current and `u3`'s previous value gives `[u2 false, u3 true]`; a value
containing nothing gives an empty list.

Key tests: the two-group success row (break it once by building the index with only the first group's SECRET left out:
it must be refused) and the one-holder refusal row (break it once by throwing guard rail 1's plain message: it must
fail).

## Task 3 (#382): a deleted current folder is named in the error

- Add to `CliEnvironment`: `public Func<string> CurrentDirectory { get; init; } = Directory.GetCurrentDirectory;`
  (a test seam; production never sets it).
- Add `internal static class CurrentFolder` (`TswapCli/CurrentFolder.cs`) with
  `public const string GoneText = "The current folder no longer exists (it was deleted or moved): cd to a folder that exists and run tswap again.";`
  and `public static bool IsGone(Func<string> currentDirectory)`: true when the call throws `FileNotFoundException` or
  `DirectoryNotFoundException`; false when it returns, and for any other exception (a permission error is not this
  case).
- `CliRunner.Run`: in the `TswapException` and the generic `Exception` catch, after the `❌ Error:` line, when
  `CurrentFolder.IsGone(ctx.Env.CurrentDirectory)`, write `CurrentFolder.GoneText` on its own line to stderr. The exit
  code is unchanged. Not on success, not for `OperationCanceledException`. A command that succeeds in a deleted folder
  (`names`, `create`) prints nothing new: a warning on every command would be noise, and the folder only matters when
  something failed.
- Why not refuse at start-up, or `cd` somewhere else: commands that work there today (`names`, `create`, `burned`)
  would break, and changing the folder would make a relative path or a `run` child act in a different place without
  saying so.

Tests:

| Test | Setup | Outcome |
|---|---|---|
| `IsGone` table | returns a path / throws `FileNotFoundException` / `DirectoryNotFoundException` / `UnauthorizedAccessException` / `IOException` | false / true / true / false / false |
| in-process, `TswapException` path | env `CurrentDirectory` throws `FileNotFoundException`; `redact missing.txt` | exit 1; stderr has the `File not found` error line, then `GoneText` on the next line |
| in-process, no hint when the folder exists | default seam; `redact missing.txt` | stderr has no `GoneText` |
| in-process, success | seam throws; `names` on an initialised vault | exit 0; no `GoneText` |
| E2E `[UnixFact("Windows can't delete a process's current folder, so the state can't arise there")]` | `/bin/sh -c 'cd "$1" && rmdir "$1" && exec "$2" run true "{{s}}"' sh <dir> <tswap>`, `MakePsi`'s environment, after `init` and `create s` | exit 1; stderr contains `Unable to find the specified file.` and `GoneText` |
| E2E, same attribute | the same shell form with `names` | exit 0; no `GoneText` |

Key tests: the in-process `TswapException` row and the E2E `run` row; break both once by removing the `GoneText` write
from the `TswapException` catch. For the generic catch, the E2E `run` row covers it (its exception is a
`FileNotFoundException`): remove that write once too and check the E2E row fails.

## Task 4 (#361): the approve file is written only after the Enter

**Decision: make the file's lifetime fail-safe, not catch the signal.** The approve file is written after the person's
Enter, so there is nothing to clean up if the process ends at any point before it: by SIGINT before the read starts
(Linux, macOS), by Windows' CTRL_C_EVENT, by SIGHUP when the terminal closes, by SIGKILL, or by a power cut. A
`PosixSignalRegistration` handler would cover only the signals it registers, would race the main thread over the file,
and would not run for SIGKILL or a crash. Entering the key-read mode before the prompt would shrink the window, not
close it (the file would still exist before the read). Nothing needs the file during the gate: accept parses the
received bytes (`approveText`, brief T28's A3), and the file exists only for the by-hand `slot accept` after a failed
accept.

In `EnrolInteractively`:

- Keep the get, the `ParsesAsApprove` check, `approveText` and the `Approve file received: …` line as they are (from
  `got.Stdout`).
- Move `WriteLocal(ctx, approveFile, got.Stdout)` and its `ApproveNotSavedText(...) + cleanSentence` refusal to **after
  the gate's loop ends on an empty line**, before step 4. The `try`/`finally` that zeroes `got.Stdout` now spans the
  gate and that write (the bytes are zeroed on every path, including the gate's refusal).
- The gate's end-of-input/Ctrl-C branch no longer deletes anything: drop the `TryDeleteLocal` call and the
  `Delete {approveFile} by hand …` clause; the message is otherwise unchanged. (`TryDeleteLocal` stays; the folder
  delete uses it.)
- `EnrolFileSeams`' summary: "each write of `approve.json` (after the Enter, in interactive mode)" instead of "each write
  of `approve.json` and its delete at the Enter gate".
- No start-up removal of an existing `approve.json`: after this change an interactive run leaves one only after the
  Enter, when accept failed and its message tells the person to run `slot accept` on that very file; deleting it at the
  next start would remove a confirmed file the failure message points at. Batch mode (`RunApprove`) has no gate and is
  unchanged.

**The one existing test this changes:** `SlotEnrolTests.EnterGate_ApproveFileNotDeletable_StillSaysWhatIsLeft` tests the
delete at the gate, which no longer exists (it expects the second access to `approve.json` to be a failed delete, the
`Delete … by hand` clause and the file left behind). Replace it (sanctioned: the behaviour it pins is the one #361
removes) with `EnterGate_EndOfInput_NeverWritesTheApproveFile`: seam counts accesses to `approve.json`; EOF at the gate
(`EnrolOnTerminal("\n\n\n")`) → nonzero exit, the "wasn't confirmed" message, no `by hand` in stderr, zero accesses, no
`approve.json`, `PendingSlotId` kept, host keyring unchanged.

New and kept tests:

| Test | Outcome |
|---|---|
| `EnterGate_EndOfInput_NeverWritesTheApproveFile` (above) | zero `approve.json` accesses |
| `EnterGate_Enter_WritesTheApproveFileOnce`: seam counts accesses, `EnrolOnTerminal(TerminalAnswers)` | exit 0, enrolled, exactly one access to `approve.json` |
| `EnterGate_TypedTextThenEnter_WritesNothingUntilTheEnter`: seam records, at each `approve.json` access, how many times `SlotCommand.EnterGateRetryText` was already printed (read the joiner's stdout so far, or count with a flag the seam sets; your choice) for input `"\n\n\n" + "x\n" + "\n"` | one access, after the retry text |
| existing `ApproveFileNotSaved_Interactive_TheRequestIsKept` | unchanged and passing (its answers end with the Enter, so the write still fails, now after it) |
| existing `EnterGate_TextThenEof_KeepsTheRequest`, the swapped-approve-file test, the three PTY gate tests | unchanged and passing |
| new PTY `[UnixFact] Enrol_CtrlCAsSoonAsThePromptShows_OnARealTerminal_LeavesNoApproveFile`: `WaitFor(EnterGatePrompt)`, then `Type("\x03")` at once (no `WaitForKeyRead`), then wait for exit | the process exits by itself; either exit 1 with `NotConfirmed`, or ended by SIGINT (exit 130 as .NET reports it; check what it reports and assert that value); in both: `request.json` kept, no `approve.json`, `PendingSlotId` kept, host keyring unchanged |

Key test: `EnterGate_EndOfInput_NeverWritesTheApproveFile`. Break it once by moving the write back before the gate; it
must fail. The PTY test can't make the window happen on demand (tswap usually reaches the read first), so it needs no
break-it-once; it pins that both ways a Ctrl-C can land leave the same state.

## Task 5: docs

- `docs/rotating-and-burning.md`, "The burn is kept as history": `tswap burned` starts with a count line
  (`0 outstanding, N rotated`) and marks every row `outstanding` or `rotated`.
- `docs/commands.md`: the `field adopt` bullet (`:227-230`) gives the group form (several `NAME FIELD --from SECRET`
  groups, adopted and deleted in one commit, for one value held by several secrets) and says its refusal names the
  other secrets holding the value (sudo); the guard rail 1 paragraph (`:204`) adds "(`field adopt`, under sudo, names
  them)". The generated block is regenerated in Task 2.
- `docs/security-model.md`: the same two points at `:756` and `:799-801`.
- `docs/multi-machine.md:141-142`: "or Ctrl-C if they differ (nothing is saved here: tswap writes the approve file only
  after your Enter)". `docs/security-model.md:137-140`: one clause that the joining machine writes `approve.json` only
  after the Enter.
- `docs/release-notes/v0.3.2.md` stays as it is. In your report, give one 0.3.3 release-note line per issue.

## Out of scope

- Making `run` work from a deleted folder (resolving a bare program name through `PATH` ourselves), and any start-up
  check or warning for it.
- Naming the matching secret in `field set` or the value commands' guard rail 1 refusal (they run without sudo; naming
  would let an agent probe which secret holds a value).
- Batch-mode enrolment's approve file, and a signal handler anywhere.
- `burned --json`, the agent prompt (`TswapCore/Prompt.cs`), and the `names`/`list`/`check` output.
- `Redact`, `ToComment`, `SecretMatcher`, `Validation` (other briefs).

## Owner decision (2026-11-23)

The two existing test changes this brief names (`MetadataCommandTests.Burned_DecryptsNoValue`, `SlotEnrolTests.EnterGate_ApproveFileNotDeletable_StillSaysWhatIsLeft`) are sanctioned by the owner.
