# Brief T34: `slot enrol` follow-ups: review minors from T27/T28 (#331) and snags from real runs (#337)

Issues: https://github.com/stevedcc/TokenSwap/issues/331 (body: the MiMo and GLM-5.3 minors on #330, brief T27; one
comment: the T28 review minors) and https://github.com/stevedcc/TokenSwap/issues/337 (body: snags 1 to 4 from the first
real runs; comments: snags 5 and 6, and the owner's sharper snag 5). Base: `main` at 51b0b37 (after T33: the command is
`slot enrol`, the files `SlotEnrol*.cs`, `enroll` a hidden synonym). Read AGENTS.md and CLAUDE.md first, then:
`TswapCli/Commands/SlotEnrol.cs` (all of it), `TswapCli/Commands/SlotStage.cs` (`ExecuteStage`, `ReadStaged`),
`TswapCli/Commands/SlotCommand.cs` (`ExecuteRequest`, `ExecuteHardwareRequest`, `RequestHooks`, `ReadRequestVaultPassword`,
`ExecuteApprove` up to its end, `ExecuteAccept`'s closing lines, `ReadBoundedStdin`, `HumanLinesToStderrConsole`,
`PrintFingerprint`), `TswapCli/Ssh/ProcessSshTransport.cs` and `ISshTransport.cs` (`SshRelay`), `TswapCli/IConsole.cs`,
`TswapCli/SystemConsole.cs`, `TswapCli/CliHost.cs` (`TestTerminalConsole`), `TswapCli/CliRunner.cs`; the tests
`TswapTests/SlotEnrolTests.cs` (`Enrol`, `EnrolOnTerminal`, `TerminalAnswers`, `InteractiveSsh`, `LoopbackSshTransport`,
`ReceiptPathIsAFolder`, the `ProcessSshTransport_*` stub tests), `TswapTests/SlotStageTests.cs`,
`TswapTests/SlotStdioTests.cs`, `TswapTests/SlotAcceptReceiptTextTests.cs`, `TswapTests/FakeConsole.cs`,
`TswapTests/FleetMachine.cs` (`RunOnTerminal`, `StagedSeams`), `TswapTests/SystemConsoleTests.cs`; and
`docs/multi-machine.md#enrolling-over-ssh` (to the end of "The enrolment folder and a retry").

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, and the full `./runtests.sh` at the end, each run
as `flock ~/.cache/tswap-suite.lock ./runtests.sh ...` (another implementer may run a suite at the same time). No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Tests never use the real clock or sleeps. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion unless this brief sanctions
it by name (it sanctions two, in Task 5). British spelling in new text.

**Review history.** None yet. Controller amendment A1 (Task 6 respells the banners, see there).

**Parallel briefs.** T35 (Windows output: console encoding and glyphs, `run`'s ConPTY, `InitCommand`'s `--yubikey`
header and closing line, `docs/install.md`), T36 (slot-kind labels in `slots`, tightening loose vault files,
`docs/multi-machine.md`'s "Sync transports" section), T37 (CI). T34 owns `SlotEnrol.cs`, `SlotStage.cs`,
`ProcessSshTransport.cs`/`ISshTransport.cs`, the request/accept/approve output in `SlotCommand.cs`, the enrolling-over-SSH
section of `docs/multi-machine.md`, and `SlotEnrolTests`/`SlotStdioTests`/`SlotStageTests`. Shared files, so the merges
are expected:
- `TswapCli/IConsole.cs`, `TswapCli/SystemConsole.cs`, `TswapCli/CliHost.cs`: T34 adds one member,
  `ReadLineWithoutEcho` (Task 2), to the interface, `SystemConsole`, and `CliHost.TestTerminalConsole`. It changes no
  existing member and no encoding. T35 may set the console's output encoding in the same files: different members.
- `TswapCli/Commands/InitCommand.cs` and `GuidedInit.cs`: T34 changes one string literal in each of four places, the
  `"║  ✓ INITIALIZATION COMPLETE            ║"` line (Task 6). T35 changes `InitCommand`'s `--yubikey` header and closing
  line (about 10 lines from one of them) and may change how banners are drawn on Windows. If T35 merges first and has
  replaced these literals, keep T35's form and make its closing banner line up (the Task 6 tests still apply).
- `docs/multi-machine.md`: T34 edits only "Enrolling over SSH" and its subsections; T36 edits "Sync transports".
- `TswapTests/FakeConsole.cs`, `FleetMachine.cs`, `TswapCli/CommandContext.cs`: one new member each (Tasks 2 and 3).

## Why

The owner's real runs on 2026-11-16 (a Windows laptop enrolled via oort with SSH password logins, seven logins; a Mac
enrolled with the Windows laptop as host, key login and `--no-remote-sudo`; earlier, a FIDO2 host in the CoreOS VM) all
worked, and showed what reads wrong:

- **#337.1.** Inside `enrol`, the request step still prints the hand-carry steps ("Move this file to an already-enrolled
  machine yourself (scp/USB/paste) ... There, run: sudo tswap slot approve <this-file> <approve-file> ... tswap slot
  accept <approve-file>", `SlotCommand.cs:230-234` and `:335-339`, and the intro "carry the request file this produces to
  an already-enrolled machine and run 'slot approve' there", `:163-165`, `:264-266`), and accept prints "Carry it back to
  the approving machine yourself ... sudo tswap slot merge <receipt-file>" (`:944-947`, and in the vault-folder branch
  `:941`). `enrol` does those steps itself. T27 left the output unchanged on purpose; this is the follow-up.
- **#337.2.** "(Not load-bearing in v0 — hand-carrying this file yourself is the trust boundary ...)"
  (`PrintFingerprint`, `SlotCommand.cs:2085-2086`) follows the slot fingerprint on both sides, right above the
  approve-file fingerprint compare that T28 made the check that counts.
- **#337.3.** The host's staged approve prints "Compare this against the fingerprint shown on the requesting machine
  before continuing." (`SlotCommand.cs:543`), which reads as if approve waits. It doesn't.
- **#337.4.** systemd's sudo on Fedora 44 / CoreOS writes OSC 3008 sequences (`ESC ] 3008;start=...;comm=sudo;... ESC \`)
  into the `ssh -t` stream: harmless at a terminal, visible in a captured log. A docs note only.
- **#337.5 (owner, sharpened).** At the Enter gate (`SlotEnrol.cs:247-255`) the owner typed the host key's FIDO2 PIN one
  prompt late, because the gate comes right after the host's PIN prompts and looks like one. `c.ReadLine()` echoed it
  and accepted it as the Enter. The fix: read the gate's line without echo, accept only an empty line, and otherwise say
  `Nothing was typed in, just press Enter (what you typed was not shown or used).` and ask again.
- **#337.6.** `║  ✓ INITIALIZATION COMPLETE            ║` is 41 characters, one short of its 42-character box
  (`InitCommand.cs:373`, `:441`, `:759`, `GuidedInit.cs:448`; checked: every other banner line in `TswapCli` is as wide as
  its box). A padding slip, not a width question about ✓: `║  ✓ SLOT REQUEST CREATED                ║` lines up.
- **Windows host (#349's comment).** On the Mac enrolled through the Windows laptop, the Terminal window kept the title
  `C:\WINDOWS\system32\conhost.exe`: the Windows host's pseudo console (sshd's ConPTY, on the `ssh -t` approve and merge
  steps) sent an OSC 0 title that outlived the session. OpenSSH-for-Windows behaviour; a docs note for the Windows-host
  paragraph.

**#331, checked against main at 51b0b37, item by item:**

| #331 item | State on main | T34 |
|---|---|---|
| `Directory.Delete` of the enrolment folder after "✓ Enrolled" (now `Enrolled`, `SlotEnrol.cs:462`) and for `--fresh` (`RequestStep`, `:351`) has no error handling | open | Task 3 |
| `ProcessSshTransport.Run`'s stderr relay is uncapped (`:131-138`, `ReadLine` with no line or total limit) | open | Task 4 |
| local IO failures (request read `:149`/`:220`, approve write `:489`/`:237`, receipt read `:162`/`:269`) escape without the "what is left" text | open | Task 3 |
| accept-failed hint omits `--vault-dir` (`AcceptStep`, `:385-386`) | open | Task 3 |
| `vault merge` hint says `sudo tswap` instead of the host's program (`:392`) | open | Task 3 |
| `HumanLinesToStderrConsole.IsOutputRedirected => true` (`SlotCommand.cs:1991`) | open | Task 5 (comment) |
| T27 ruling 10: `slot request`'s folder refusals come after the pre-flight SSH call | open | Task 3 |
| `SlotStdioTests.DashInput_ExactlyOneMiB_IsReadAndParsed` weak oracle (`:223-230`) | open | Task 5 |
| docs: the `[host]` label also covers ssh's own stderr | **fixed on main** for batch mode ("The host's lines, and ssh's own messages on stderr, appear here prefixed", multi-machine.md "Batch mode for scripts"); the interactive mode's batch-form calls are not mentioned | Task 7 adds the interactive sentence |
| docs: "readable by you only" is exact on Unix only | **fixed on main** ("on Unix the folder is 0700, readable by you only, and on Windows it is inside your config folder, with that folder's access rules") | nothing |
| comment: `ReadStaged` reads the whole file before the 1 MiB check (`SlotStage.cs:146-148`) | open | Task 5 |
| comment: `stage put`/`get` go through the console's text encoding | open (fails safe) | Task 5 (ruling: pin, don't change) |
| comment: `Stage_UnderSudo_IsRefused` is a no-op on a root runner (`SlotStageTests.cs:473-484`) | open | Task 5 |
| comment: the interactive accept-failure message names the `-` form of merge (`AcceptStep`, `:386`, shared by both modes) | open | Task 3 |
| owner check before release: one real `slot enrol --via` | **done** by the owner on 2026-11-16 (three hosts) | nothing |

## Task 1: enrol's own wording in request, accept and the staged approve (#337.1-3)

**Request, from `enrol`** (`ExecuteRequest` and `ExecuteHardwareRequest`, when `hooks is not null`; `slot request` by hand
passes no hooks and prints exactly what it prints today):
- The intro's last two lines become, for the YubiKey form:
  `X25519 keypair. Nothing is shared or usable as a vault yet: 'slot enrol' has` and
  `the host approve the request next.` followed by the blank line the intro ends with today (the first line,
  `Enrolling one YubiKey for this machine's slot, then generating the slot's`, and the hardware form's
  `Enrolling this machine's {hardware} for its slot, then generating the slot's`, stay).
- After `Request file written to: {path}` nothing more: the five hand-carry lines (`Move this file ...` to
  `  {prefix} slot accept <approve-file>`) are not printed.
- The fingerprint note: `RequestHooks` gets `public string? FingerprintNote { get; init; }`, and both request paths call
  `PrintFingerprint(c, "This machine's slot", slotKeyPair.PublicKey, hooks?.FingerprintNote)`.
- `PrintFingerprint` gets a fourth parameter, `string? note = null`: null prints today's two lines; otherwise the
  fingerprint line, then `note` on one line. Update its doc comment (the note is the caller's; by hand the v0 lines
  stay true, since there the hand-carried file is the trust boundary). `NewSlotWrite.cs:92` and `SlotCommand.cs:1377`
  are unchanged.
- `RequestStep` gets a `string fingerprintNote` parameter, set into the hooks. The two notes, `internal const`/`static`
  members of `SlotCommand` in `SlotEnrol.cs`:
  - interactive, `EnrolInteractiveFingerprintNote`: `(The host shows this fingerprint too when it approves. The check
    that guards the enrolment comes after that: the approve file's fingerprint, on both machines, before you press Enter
    here.)`
  - batch, `EnrolBatchFingerprintNote(string via)`: `(The host shows this fingerprint too when it approves, on a line
    starting [{via}].)` (the host's approve prints it on stderr, which the relay labels).

**Accept, from `enrol`**: `ExecuteAccept` gets `bool fromEnrol = false` after `approveText`; `AcceptStep` passes true. With
it, the closing lines after `Slots in this machine's local keyring copy: ...` are: in the vault-folder branch the
existing `The new slot is in the keyring of the vault folder ...` line, then `Receipt written to: {receiptPath} ('slot
enrol' has the host merge it next).`; in the own-copy branch the blank line and `Receipt written to: {receiptPath}
('slot enrol' has the host merge it next).` only. By hand (`fromEnrol` false), unchanged: `SlotAcceptReceiptTextTests`
pins that and must pass unchanged.

**The staged approve, on the host** (`ExecuteApprove` with `--staged`): the requester's fingerprint is printed with
`PrintFingerprint(c, "Requesting machine's slot", requesterPublicKey, StagedApproveFingerprintNote)` and the
`Compare this against ...` line is not printed. `internal const string StagedApproveFingerprintNote = "(The joining
machine shows the same fingerprint. Nothing here waits for you: the check to make is the approve file fingerprint below,
which the joining machine asks you to confirm.)"`. Every other form of approve (file, `-`) is unchanged.

Ruling: **`--batch`'s host output stays as it is** (`slot approve - -` prints the v0 note, the compare line and the
hand-carry lines on stderr, relayed as `[host]` lines). Why: `slot approve - -` is also a by-hand form
(`ssh host sudo tswap slot approve - - < request.json > approve.json`, docs "step by step"), and the host can't tell who
called it; a hidden "called by enrol" flag would be a new remote interface for wording. The cost: a batch run's log still
shows those lines, labelled as the host's.

Tests, in `SlotEnrolTests`:
- `Interactive_RequestAndAccept_PrintEnrolsOwnSteps_NotTheHandCarriedOnes`: `EnrolOnTerminal(TerminalAnswers)`, exit 0;
  stdout contains `EnrolInteractiveFingerprintNote`, the two new intro lines (consecutive),
  and `('slot enrol' has the host merge it next).`; stdout contains none of `Move this file`, `Carry it back`,
  `Not load-bearing`, `slot approve <this-file>`, `slot merge <receipt-file>`.
- `Interactive_TheHostsApprove_SaysItDoesntWait`: `ssh.InteractiveOutput` contains `StagedApproveFingerprintNote` and not
  `Compare this against`, and not `Not load-bearing`.
- `Batch_Request_NotesTheHostsLabelledLine`: `Enrol("")`, exit 0; stdout contains `EnrolBatchFingerprintNote(Via)` and
  none of `Move this file`, `Carry it back`; stderr contains a line starting `[{Via}] Requesting machine's slot
  fingerprint: ` with the same fingerprint as stdout's `This machine's slot fingerprint: ` line.
- `SlotRequest_ByHand_StillPrintsTheHandCarriedSteps` (in `SlotEnrolTests`, on the joiner, `slot request <file>`): stdout
  contains `Move this file to an already-enrolled machine yourself (scp/USB/paste) —` and `(Not load-bearing in v0`.
- Break-it-once: print the hand-carry block unconditionally again in `ExecuteRequest`; the first test fails. Drop the
  `--staged` condition on the compare line; the second fails.

Files: `TswapCli/Commands/SlotCommand.cs`, `TswapCli/Commands/SlotEnrol.cs`, `TswapTests/SlotEnrolTests.cs`.

## Task 2: the Enter gate reads without echo and takes only an empty line (#337.5)

- New `IConsole` member: `string? ReadLineWithoutEcho();` with the doc comment: one line, nothing shown while it is typed;
  null at the end of input; on a terminal what was typed before the read is discarded first (#293); Ctrl-C throws
  `OperationCanceledException`; piped input is read as it is.
- `SystemConsole.ReadLineWithoutEcho`: redirected: `_input.ReadLine()`. Terminal: `_input.DiscardTypeahead()`, then as
  `ReadPassword`'s terminal loop (`TreatControlCAsInput` true and restored in `finally`, `_input.ReadKey()`), except that
  it writes nothing at all: Enter returns the collected text; Ctrl-C throws `OperationCanceledException`; Ctrl-D with
  nothing collected returns null; Backspace removes the last collected character; other control characters are ignored.
  The caller writes the newline.
- The other implementers: `CliHost.TestTerminalConsole` and `SlotCommand.HumanLinesToStderrConsole` delegate to
  `inner.ReadLineWithoutEcho()`; `SlotStdioTests.ThrowingInConsole` reads through its throwing reader (`_in.ReadLine()`);
  `FakeConsole` counts a read (`Reads++`) and returns `_in.ReadLine()`, writing nothing. Find any other implementer with
  the compiler.
- `FakeConsole` also gets `public bool EchoesTypedLines { get; init; }`: when true and `IsInputRedirected` is false,
  `ReadLine` writes the line it read, then a newline, to `Out` (what a terminal in line mode shows), and `ReadPassword`
  writes one `*` per character before its newline (as `SystemConsole` does). `FleetMachine` gets
  `RunOnEchoingTerminal(string stdin, params string[] args)`, `RunOnTerminal` with that flag set.
- **The gate** (`EnrolInteractively`, after `Approve file received: ...`): a loop: `c.Out.Write("Press Enter to accept
  it here. ")`; `var typed = c.ReadLineWithoutEcho()` inside a `try` whose `catch (OperationCanceledException)` sets
  `typed = null`; on null the existing path (delete `approve.json`, throw the existing "wasn't confirmed" text, unchanged);
  otherwise `c.Out.WriteLine()`, and on `typed.Length == 0` leave the loop; else
  `c.Out.WriteLine(EnterGateRetryText)` and go round. `internal const string EnterGateRetryText = "Nothing was typed in,
  just press Enter (what you typed was not shown or used).";` (the owner's words). Only `""` passes: a space doesn't.
  Ruling: **Ctrl-C at the gate is the same as end of input**: the approve file is deleted and the same message names
  what is left (exit 1), rather than `CliRunner`'s bare `Cancelled.` (130), because the message's staging clean-up line
  is what the person needs then. Today, Ctrl-C kills the process there and leaves `approve.json` in the enrolment folder.

Tests:
- `SystemConsoleTests` (its `ScriptedInput`): `ReadLineWithoutEcho_OnATerminal_DiscardsTypeaheadFirst` (keys `1`, `2`,
  Backspace, `3`, Enter: returns `"13"`, and the `Log` has `discard` before the first key);
  `ReadLineWithoutEcho_CtrlD_OnAnEmptyLine_IsEndOfInput` (returns null);
  `ReadLineWithoutEcho_CtrlC_Cancels_AndPutsTheSettingBack` (as the `ReadPassword` one);
  `ReadLineWithoutEcho_Piped_ReadsTheLine` (no `discard` in the log). Nothing is shown because the terminal path reads
  with `ReadKey(intercept: true)` (`ConsoleInput.ReadKey`) and the method writes nothing; `SystemConsole` writes only to
  the process's `Console.Out`, which these tests don't capture (setting it is process-wide and would race other tests),
  so "shows nothing" is measured at the gate with `FakeConsole` below, and on a real terminal by the owner.
- `SlotEnrolTests.EnterGate_TypedText_IsNeitherShownNorAccepted`: `_joiner.RunOnEchoingTerminal("\n\n\n" +
  "PIN-MARKER-4711\n" + "\n", ["slot", "enrol", "--via", Via])` with `InteractiveSsh()`: exit 0, enrolled; stdout contains
  `EnterGateRetryText` exactly once and `Press Enter to accept it here. ` exactly twice; `PIN-MARKER-4711` appears in
  neither stdout nor stderr.
- `SlotEnrolTests.EnterGate_ASpace_IsNotAnEnter`: gate input `" \n\n"`: exit 0, `EnterGateRetryText` once.
- `SlotEnrolTests.EnterGate_TextThenEof_KeepsTheRequest`: gate input `"x\n"` then end of input: exit non-zero, the
  existing "wasn't confirmed" text on stderr, no `approve.json`, the pending request kept, the host's keyring unchanged.
- The existing `Interactive_AnApproveFileSwappedOnTheHost_ShowsAnotherFingerprint_AndEofAtTheEnterKeepsTheRequest` must
  pass unchanged (EOF at the gate).
- Break-it-once: use `c.ReadLine()` at the gate again; `EnterGate_TypedText_IsNeitherShownNorAccepted` fails (the marker is
  echoed, and accepted: no retry text). Accept any non-null line; it fails on the retry count.

Files: `TswapCli/IConsole.cs`, `TswapCli/SystemConsole.cs`, `TswapCli/CliHost.cs` (`TestTerminalConsole` only),
`TswapCli/Commands/SlotCommand.cs` (`HumanLinesToStderrConsole` only), `TswapCli/Commands/SlotEnrol.cs`,
`TswapTests/FakeConsole.cs`, `TswapTests/FleetMachine.cs`, `TswapTests/SlotStdioTests.cs` (`ThrowingInConsole` only),
`TswapTests/SystemConsoleTests.cs`, `TswapTests/SlotEnrolTests.cs`.

## Task 3: enrol's local failures say what is left, and its hints are exact (#331)

**A seam.** New `public sealed class EnrolFileSeams { public Action<string>? BeforeLocalAccess { get; init; } }` in
`SlotEnrol.cs`, `CommandContext.EnrolSeams` (`EnrolFileSeams?`, init) and `FleetMachine.EnrolSeams` passed through as
`StagedSeams` is (`FleetMachine.cs:190`). `enrol` calls `ctx.EnrolSeams?.BeforeLocalAccess?.Invoke(path)` with the path
just before each local read of `request.json` and `receipt.json`, each write of `approve.json`, and each enrolment-folder
delete (the folder's path). A test throws an `IOException` from it.

**The folder deletes.** A helper `TryDeleteEnrolmentFolder(CommandContext ctx, string folder)` returning `string?` (null:
deleted; otherwise `OneLine(ex.Message)`) calls the seam, then `Directory.Delete(folder, recursive: true)`, catching
`IOException` and `UnauthorizedAccessException` only.
- `Enrolled`: after the `✓ Enrolled: ...` line, on a failure it writes to stderr
  `Note: the enrolment folder is kept: {folder} ({reason}). Delete it by hand.` and still returns 0.
- `--fresh` in `RequestStep`: each other folder through the helper; on a failure, stderr
  `Note: couldn't delete the earlier enrolment folder {other} ({reason}); delete it by hand.` and the run goes on.

**Local IO during the steps.** Each local read and write named above is wrapped (`catch (Exception ex) when (ex is
IOException or UnauthorizedAccessException)`) and turned into the step's own failure with the reason
`couldn't read {path}: {OneLine(ex.Message)}` or `couldn't write {path}: {OneLine(ex.Message)}`:
- reading `request.json` (both modes): the approve failure (in batch, the text at `SlotEnrol.cs:151-155`; interactive,
  `ApproveFailed`). Factor batch's inline approve and merge texts into local functions `ApproveFailed(string reason)` and
  `MergeFailed(string reason)` as the interactive flow has, same texts.
- writing `approve.json` (`RunApprove`'s write in batch; `ctx.WriteOutputFile(approveFile, ...)` in interactive): the host
  has approved, so not the approve-failure text but `ApproveNotSavedText`: `The host approved the request, but this
  machine couldn't save the approve file ({reason}). This machine's pending request is kept; nothing was added on {via}.
  Fix the cause and run the same '{prefix} slot enrol' again (it continues from the kept request and has it approved
  again).` and, interactive, the `cleanSentence`. In batch `RunApprove` returns the write failure distinguishably (an
  out parameter or a small result type: implementer's choice of shape, not of text).
- reading `receipt.json` (both modes): the merge failure (`MergeFailed`).

**The hints.** In `AcceptStep` (it gets `bool interactive`; `EnrolInBatch` passes false, `EnrolInteractively` true):
- the pending-request case's accept command gains ` --vault-dir {Path.GetFullPath(vaultDir)}` when the run had
  `--vault-dir` (both modes); the merge it names is, in batch, unchanged (`'{hostTswap} slot merge - < receipt.json' on
  {via}.`) and, interactive, `then carry the receipt to {via} and run '{hostTswap} slot merge receipt.json' there.` in
  place of `then '{hostTswap} slot merge - < receipt.json' on {via}.`. So the batch text without `--vault-dir` is exactly
  today's (`AcceptFails_OnAnApproveFileForAnotherRequest_ThePendingRequestSurvives` pins it, unchanged).
- the no-receipt case's `'sudo {ctx.Prefix} vault merge <folder>'` becomes `'{hostTswap} vault merge <folder>'` (it runs
  on the host). With the defaults that is the same text (`ReceiptNotWritten_OwnCopy_SaysTheHostDoesntKnowTheSlot` pins
  it, unchanged).

**T27 ruling 10: folder refusals before the pre-flight.** In `ExecuteEnrol`, after the pending-state block and before
`new EnrolRun`: when `folder is null && passwordFlag == true`, call `ReadRequestVaultPassword(ctx, vaultDir)` and zero the
returned bytes (`CryptographicOperations.ZeroMemory`). So `--password`'s folder refusals (`RequestNeedsFolderText`,
`RequestFolderMissingText`, `RequestNotAVaultFolderText`, `RequestPasswordFileMissingText`, `RequestNoPasswordYetText`)
come before any SSH call. The request step reads the folder again (unchanged), so the files used are the ones there then.
Ruling: **only for `--password`**: without a flag, request asks the password question on a terminal, after the
pre-flight, and a "yes" there still meets these refusals after it; say so in the docs. Why: asking that question before
the pre-flight would reorder request's prompts, which T27 keeps "exactly as `slot request`".

Tests, in `SlotEnrolTests`:
- `FolderNotDeletable_StillEnrolled_SaysTheFolderIsKept`: `_joiner.EnrolSeams` throws `IOException("locked")` for a path
  that is a folder under `enrol/`: exit 0, enrolled (`AssertEnrolled`), stderr contains
  `Note: the enrolment folder is kept: {folder} (locked). Delete it by hand.`, the folder exists.
- `Fresh_AnOldFolderNotDeletable_GoesOn`: an old folder present, the seam throws for it: exit 0, the note, the old folder
  still there.
- `ApproveFileNotSaved_Interactive_TheRequestIsKept` and `ApproveFileNotSaved_Batch_TheRequestIsKept`: the seam throws for
  `approve.json`: exit non-zero, stderr contains `ApproveNotSavedText`'s opening `The host approved the request, but this
  machine couldn't save the approve file (couldn't write {path}: locked).`, the pending request kept, the host keyring
  unchanged, no merge call in the log; and running the same enrol again with no seam enrols.
- `ReceiptNotReadable_Interactive_SaysTheMergeIsLeft`: the seam throws for `receipt.json`: exit non-zero, the
  `MergeFailed` text with `(couldn't read {path}: locked)`, the joiner has its copy, the host keyring unchanged.
- `RequestNotReadable_Batch_SaysTheApproveIsLeft`: the seam throws for `request.json`: the approve-failure text with
  `(couldn't read ...)`, only `--version` in `CallLines`.
- `AcceptFails_WithVaultDir_TheHintNamesTheFolder`: as `AcceptFails_OnAnApproveFileForAnotherRequest_...`, with
  `--vault-dir <the host's shared folder>`: stderr contains `slot accept {approve} --vault-dir {full}' here`.
- `Interactive_AcceptFails_TheHintNamesTheFileFormOfMerge`: an interactive run whose host stages another request's
  approve file (the `StagedSeams.AfterApproveWritten` swap of
  `Interactive_AnApproveFileSwappedOnTheHost_...`), with the Enter given (`TerminalAnswers`), so accept refuses the slot
  id: stderr contains `then carry the receipt to {Via} and run 'sudo tswap slot merge receipt.json' there.` and not
  `slot merge - <`.
- `ReceiptNotWritten_TheHintUsesTheRemoteProgram`: `ReceiptPathIsAFolder()` with `--no-remote-sudo --remote-tswap
  /opt/tswap/tswap` (loopback as in `ApproveFails_TheHandCommandUsesTheRemoteProgram`): stderr contains
  `'/opt/tswap/tswap vault merge <folder>'`.
- `Password_FolderRefusals_ComeBeforeAnySshCall` (Theory): `--password` with no `--vault-dir` on a machine without a
  config (`RequestNeedsFolderText`), and `--password --vault-dir <an empty temp folder>` (`RequestNotAVaultFolderText`):
  exit non-zero, the text, `CallLines` empty, no `enrol/` folder.
- Break-it-once: drop the `catch` in `TryDeleteEnrolmentFolder` (the first test fails with exit 1); remove the pre-check
  (the Theory fails: `--version` was called); use `ctx.Prefix` again in the `vault merge` hint (the remote-program test
  fails).

Files: `TswapCli/Commands/SlotEnrol.cs`, `TswapCli/CommandContext.cs` (`EnrolSeams`), `TswapTests/FleetMachine.cs`
(`EnrolSeams`), `TswapTests/SlotEnrolTests.cs`.

## Task 4: the stderr relay has a line cap and a total cap (#331)

In `SshRelay`: `public const int MaxStderrLine = 4096;` (characters) and `public const int MaxStderr = 1024 * 1024;`
(characters). `ProcessSshTransport.Run`'s relay reads `process.StandardError` in chunks (not `ReadLine`), splits on `\n`,
and for each line keeps at most `MaxStderrLine` characters: a longer line is written as `SshRelay.Line(destination,
<its first 4096 characters>) + " [line cut]"` and the rest of it, up to its `\n`, is dropped. Every character read counts
towards `MaxStderr`; past it the relay sets a flag, kills the process tree (as the stdout cap does, the same
`InvalidOperationException` catch) and stops reading. A final line without `\n` is written as a line. After the waits,
the stdout cap is checked first (its message unchanged), then the stderr one: `throw new SshTransportException("its error
output was larger than 1 MiB, so ssh was stopped")` (stdout zeroed as for the stdout cap). Update the class doc comment
and `ISshTransport.Run`'s. `RunInteractive` is unchanged (the terminal is handed through).

Tests, in `SlotEnrolTests` next to the existing stub tests (POSIX shell stubs; return early on Windows as they do):
- `ProcessSshTransport_CutsALongStderrLine`: the stub prints a 10 000-character line of `y` then `next` on stderr, `ok`
  on stdout, exits 0: the result is exit 0 and `ok`; the relayed lines are exactly `[me@host] ` + 4096 `y` + ` [line cut]`
  and `[me@host] next`.
- `ProcessSshTransport_RefusesPastOneMiBOfStderr`: the stub writes 2 MiB of stderr in 64-character lines (a bounded
  loop, so it ends by itself), then `ok` on stdout, and exits 0: `Run` throws `SshTransportException` with exactly
  `its error output was larger than 1 MiB, so ssh was stopped`.
- `ProcessSshTransport_RefusesPastOneMiBOfStderr_OnOneLine`: the same with 2 MiB of `y` and no `\n` at all: the same
  exception, and at most one line was relayed, ending ` [line cut]`.
- The existing `ProcessSshTransport_*` tests pass unchanged.
- Break-it-once (the stubs end by themselves, so a removed cap shows as a returned result, never a hang): remove the line
  cut (write the whole line), and `ProcessSshTransport_CutsALongStderrLine` fails; remove the total check, and both
  `RefusesPastOneMiBOfStderr` tests fail (exit 0 and `ok` returned).

Files: `TswapCli/Ssh/ProcessSshTransport.cs`, `TswapCli/Ssh/ISshTransport.cs`, `TswapTests/SlotEnrolTests.cs`.

## Task 5: staging and `-`-form minors (#331's comment, and two from the body)

- **`ReadStaged` checks the length first** (`SlotStage.cs:146`): before `owner.ReadAllBytes(path)`, `if
  (owner.AsOwner(path, () => new FileInfo(path).Length) > MaxStdinFileSize)` refuse with the existing text (`The staged
  {what} is larger than 1 MiB, so it is not a {what}. Nothing was {verb}.`). The check after the read stays (the file can
  grow in between). Test in `SlotStageTests`: `ApproveStaged_AHugeStagedFile_IsRefusedBySize_BeforeItIsRead`: the staged
  `request.json` made a sparse file of `(long)int.MaxValue + 1` bytes (`FileStream.SetLength`); `slot approve --staged
  <id> --expect <64 zeros>`: exit non-zero, stderr contains `The staged request file is larger than 1 MiB, so it is not a
  request file. Nothing was approved.`, and `ApprovedSlots` is null. Return early on Windows (NTFS would allocate it);
  CI's Linux and macOS jobs run it. Break-it-once: remove the new check; `File.ReadAllBytes` then fails on a file over
  2 GiB with another message, and the test fails.
- **`Stage_UnderSudo_IsRefused` runs everywhere.** Its early return on `Environment.IsPrivilegedProcess`
  (`SlotStageTests.cs:475-476`) is not needed: the refusal reads only `ctx.Env.SudoEscalated` (`SlotStage.cs:73`), which
  the test sets through `FleetMachine.SudoEscalated` (`FleetMachine.cs:175`), whatever the process's privilege. Remove the
  two lines (sanctioned by name: the guard goes, the assertions stay). It then runs on CI's elevated Windows runner too.
  Break-it-once: remove the `SudoEscalated` check in `ExecuteStage`; the test fails.
- **The console encoding of `put`/`get`.** Ruling (controller default; owner may change): **no byte-stream seam.** Every
  file that travels is tswap's own JSON, written by `System.Text.Json` with its default encoder, which escapes every
  non-ASCII character, so it is pure ASCII and no code page changes it; anything else fails safe as a hash mismatch (A1)
  or a parse failure. The cost: if a file ever carries a raw non-ASCII byte, `put`/`get` through a non-UTF-8 Windows
  console refuse it instead of carrying it. Add a comment saying so at `put` and `get` in `ExecuteStage`, and pin the
  claim: `SlotStageTests.EnrolmentFiles_AreAscii_SoNoConsoleEncodingChangesThem`: after the round trip of
  `PutApproveGet_GivesOneApproveFile_ThatTheJoinerAccepts` plus the accept, every byte of the request, the approve file
  and the receipt is below 0x80. Break-it-once: prefix `WriteRequestFile`'s output with a UTF-8 BOM; the test fails.
- **`HumanLinesToStderrConsole.IsOutputRedirected`** stays `true`, with a comment: its `Out` is the original stderr and
  stdout carries the file, so nothing may treat it as a full terminal (guided questions and `enrol` ask only when stdout
  is a terminal). No test.
- **`SlotStdioTests.DashInput_ExactlyOneMiB_IsReadAndParsed` gets a real oracle** (sanctioned by name: its input and its
  exit assertion change, as #331 asks): the input is a valid request file (as the class's other tests make one) padded
  with trailing spaces to exactly `SlotStdioLimit` bytes; it asserts exit 0, stdout parses as an approve file
  (`SlotEnrolmentFileCodec.DeserializeApprove`), and keeps `Assert.DoesNotContain("larger than 1 MiB", stderr)`.
  Break-it-once: `read >= MaxStdinFileSize` in `ReadBoundedStdin`; the test fails.

Files: `TswapCli/Commands/SlotStage.cs`, `TswapCli/Commands/SlotCommand.cs` (`HumanLinesToStderrConsole` comment),
`TswapTests/SlotStageTests.cs`, `TswapTests/SlotStdioTests.cs`.

## Task 6: the init banner lines up (#337.6)

Replace `"║  ✓ INITIALIZATION COMPLETE            ║"` in `InitCommand.cs` (three places, `:373`, `:441`, `:759`) and
`GuidedInit.cs:448` with `"║  ✓ INITIALISATION COMPLETE            ║"` (British spelling, owner decision #254; the
same length), plus the one missing space before the closing `║`, so each is 42 characters like its `╔`/`╚` lines. Respell
the FIDO2 header `tswap - FIDO2 Keyring Initialization` the same way (`Initialisation`, keeping its box width), so #352
has nothing left in these banners. The tests that assert these banner texts change with them (sanctioned: a respelling
by owner decision); name them in the commit message. (Controller amendment A1: these literals are also on #352's list;
doing the spelling here avoids touching them twice.)

Tests:
- A helper `BannerAssert.LinesUp(string output)` (new `TswapTests/BannerAssert.cs`): at least one line starts with `║`,
  and every line that starts with `║` has the same length as the nearest line above it that starts with `╔`.
- `BannerAlignmentTests.InitTpm_BannersLineUp` (`init --tpm --no-password --no-recovery` on a `FleetMachine` with a TPM,
  as `AgentCommandTests` does), `InitYubiKey_BannersLineUp` (`init --yubikey --no-password --no-recovery`, one simulated
  key), `InitFido2_BannersLineUp` (as `BrokerFido2Tests` makes a FIDO2 vault), and in `GuidedInitTests`
  `Guided_TheBannersLineUp` (the setup of `Guided_TwoKeysAndSecureEnclave_EachOpensTheVault`): each `BannerAssert.LinesUp(stdout)`.
- `BannerAlignmentTests.EveryBannerLiteral_IsAsWideAsItsBox`: over `TswapCli/**/*.cs` (the repo root as
  `SecureEnclaveFactoryScanTests.RepoRoot` finds it), every string literal whose text starts and ends with `║` is as long
  as the nearest preceding literal in the same file whose text (a leading `\n` removed) starts with `╔`. It covers the
  banners no test runs (`MigrateCommand`'s 64-wide box included).
- Break-it-once: put back one literal's missing space as it is today; `InitTpm_BannersLineUp` (for `:759`) and the scan
  fail.

Files: `TswapCli/Commands/InitCommand.cs` (the three literals only), `TswapCli/Commands/GuidedInit.cs` (one literal),
`TswapTests/BannerAssert.cs`, `TswapTests/BannerAlignmentTests.cs` (new), `TswapTests/GuidedInitTests.cs` (one test).

## Task 7: docs (`docs/multi-machine.md`, enrolling over SSH)

- "What each step does", step 2: after "exactly as `tswap slot request` (its questions, touches and fingerprint)" add
  ", without its instructions for carrying the files". Step 4: the same for accept. Step 3: "Press Enter to go on, or
  Ctrl-C if they differ." becomes "Press Enter to go on (only Enter: anything typed at that point is not shown, and tswap
  asks again), or Ctrl-C if they differ (the approve file is then deleted here)." and, after "prints its fingerprint of
  the new slot: compare it with step 2's", add "(approve doesn't wait for you; the check that counts is the approve
  file's fingerprint below)".
- After the step list, one paragraph: "The calls without a terminal (pre-flight, `slot stage` put, get and clean) show the
  host's messages, and ssh's own on stderr (a host-key notice, `Permission denied`), here prefixed `[<user@host>] `; the
  prefix labels them and is not a security boundary. A line longer than 4096 characters is cut, and a call that writes
  more than 1 MiB of messages is stopped."
- Step 1: "`--password`'s checks of the vault folder (`--vault-dir`, its keyring and `vault-password` file) come before
  the pre-flight too; when request asks the password question instead, they come after it."
- "Prompts to expect", the Enter bullet: "**The Enter** after you have compared the approve file's fingerprints: Enter
  alone. A PIN or a stray key's code typed there is not shown and not used; tswap asks again."
- New subsection after "Prompts to expect", `### Terminal output from the host`:
  - "**systemd's sudo** (Fedora 44, Fedora CoreOS) writes OSC 3008 sequences (`ESC ] 3008;start=...;comm=sudo;... ESC \`)
    into the approve and merge steps' terminal. A terminal ignores them; a captured log of the session (`script`, a tmux
    pipe) shows them as text. Nothing to do."
  - "**A Windows host's** OpenSSH Server runs the approve and merge steps in a pseudo console, which sets the window title
    (OSC 0) to `C:\WINDOWS\system32\conhost.exe`; on some terminals (macOS Terminal) the title stays after the session.
    Set it back with your terminal's title setting, or `printf '\033]0;\007'`. This is OpenSSH-for-Windows behaviour, not
    tswap's."
  And in "Privilege on the host", the "**Windows hosts:**" paragraph ends with "(the window title it may leave behind:
  [Terminal output from the host](#terminal-output-from-the-host))".
- "The enrolment folder and a retry": after "The folder is deleted on success." add "If it can't be (a file in it is open
  elsewhere), the enrolment has still succeeded: tswap says the folder is kept and names it; delete it by hand." In the
  "Merge failed" bullet nothing changes. Add a bullet: "**The approve file couldn't be saved here:** the host has approved,
  but nothing was added there: run the same `tswap slot enrol` again, which has the kept request approved again."
- `DocLinkTests` and the other docs tests pass (the new anchor resolves).

Files: `docs/multi-machine.md` (the enrolling-over-SSH section only).

## Report

Write `t34-report.md` at the worktree's parent folder (`../t34-report.md`). It contains: the commits; each break-it-once
(line reverted, test that failed); the two sanctioned test changes (`Stage_UnderSudo_IsRefused`'s guard,
`DashInput_ExactlyOneMiB_IsReadAndParsed`'s input and oracle); the #331 table above with each row's outcome; the full
`./runtests.sh` summary lines; anything left undone; and for the owner to check by hand: the Enter gate on a real
terminal (type a few characters then Enter: nothing shown, asked again; Ctrl-C: the "wasn't confirmed" message and no
`approve.json`), on Linux, macOS and Windows (Windows' `Console.ReadKey` path is only exercised there).

## Out of scope

- `--batch`'s host-side wording (`slot approve - -`'s lines on stderr; ruling in Task 1).
- A byte-stream seam for `slot stage` (ruling in Task 5).
- Moving request's password question before the pre-flight.
- Stripping OSC sequences from the host's terminal steps: `RunInteractive` hands the terminal through, and tswap doesn't
  filter it.
- Windows' garbled glyphs and banners in PowerShell 5 (#294.4, T35).
