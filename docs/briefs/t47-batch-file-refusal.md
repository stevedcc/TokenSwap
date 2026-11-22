# Brief T47: `run` refuses to pass a secret that `cmd.exe` would re-parse to a batch file

Security fix with a private advisory (the controller holds it; **don't name an advisory or a CVE in commit messages,
PR titles or code comments until the owner publishes it**: say "batch files re-parse arguments"). Milestone 0.3.2. Base: `brief/t46` at e93526c (the evil-values corpus, not merged yet): its Windows test
`Run_BatchFile_EvilValues_NeverInject_Windows` is this brief's acceptance test and fails today.

Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/RunCommand.cs` (the checks before the child starts,
around `ThrowIfBlocked` and the second `GetBlockedInvocation` call near line 245, after substitution),
`TswapCore/Validation.cs` (`GetBlockedInvocation`, `ProgramName`, the `WindowsWayOut` text), `TswapTests/EvilValues.cs`,
the T46 test above and `docs/briefs/t46-evil-values-corpus.md` (A6, A9, A10).

One commit per task, test first, break-it-once named in the commit message, `./runtests.sh --unit` after each task,
the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits
end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase.
No existing test's assertions change.

## What happens today (CI run 45003711187, windows-latest)

`tswap run <x>.cmd {{name}}` (and `.bat`) with a secret value holding `"` plus `&` makes `cmd.exe` run the rest of the
value as a command, on both start paths: FallbackPty (.NET's process start, stdout redirected) and WindowsPty
(ConPTY, stdout a console). `.NET` and WindowsPty quote arguments by CommandLineToArgvW rules, which is right for normal
programs; `cmd.exe` parses a batch file's command line by its own rules. A control run with the vulnerable wrapping
outside tswap (run 45003739420) confirmed the test sees injections on that runner.

## Task 1: the check, as a pure function

In `TswapCore/Validation.cs`:

```csharp
public static string? BatchArgumentRefusal(string program, IReadOnlyList<(string Name, string Value)> substituted)
```

- Returns null unless `program` is a batch file or `cmd` itself: its basename ends in `.cmd` or `.bat` (any case), or
  `ProgramName(program)` is `cmd`.
- Then returns a refusal when **any** substituted value contains one of `"` `&` `|` `<` `>` `^` `%` `!`, CR or LF.
  The message names the **secret** (never the value, never which character):
  `Refused: tswap won't pass secret '<name>' to a batch file. cmd.exe parses a batch file's arguments again, and the
  value contains characters it interprets (one of " & | < > ^ % ! or a line break). Run a PowerShell script instead:
  'run powershell -File .\script.ps1 {{<name>}}' (the script reads it as $args[0]).`
  It must contain the words "batch file" (T46's test recognises a refusal by "batch").
- Pure and platform-independent, so its unit tests run on every OS.

Tests (`ValidationTests` or a new `BatchArgumentTests`): every T46 batch case value is refused for `x.cmd`,
`X.BAT`, `C:\dir\x.cmd`, `cmd`, `cmd.exe`; a value without those characters (`abc def-123_.`) is allowed for `x.cmd`;
any value is allowed for `x.exe`, `x.ps1`, `powershell`; the message contains the secret's name and none of the value's
characters beyond those the template itself contains (assert the value as a whole doesn't appear).

Break-it-once: drop `"` and `&` from the character set; the test for the `"&echo …&"` value must fail.

## Task 2: wire it into `run`, on Windows

In `RunCommand`, after substitution and before the child starts, for the program as tswap will actually start it:

- Resolve the program the way the start does: if it has no extension and isn't a path, find out whether tswap (or the
  runner it uses) would start a `.cmd`/`.bat` found through PATH and PATHEXT, and check that resolved path. Record in
  the report what each start path (FallbackPty, WindowsPty) does with an extension-less name; if neither starts a batch
  file without its extension, checking the given name is enough, and say so.
- Only `{{name}}` tokens in argv count; a `{{@file}}` token is a temporary path tswap made (no metacharacters) and
  `--env` values never reach the command line. Note `--env` in the docs (Task 3).
- Only on Windows (`OperatingSystem.IsWindows()`); elsewhere nothing changes.
- On refusal: exit 1, the message on stderr, the child never started.

Tests:
- In-process, every OS, through the existing seam: a context that reports Windows (find how `RunCommand` already
  decides `windows`; use that seam, never the real OS check) and a `RecordingPty`: `run x.cmd {{name}}` with a refused
  value exits 1, `Starts == 0`, the message names the secret; an allowed value starts the child with the exact
  argument; `run x.exe {{name}}` with a refused-class value starts normally.
- The T46 Windows test is the acceptance test: on Windows CI `marker.txt` never appears (the controller runs it).

Break-it-once: skip the call in `RunCommand`; the in-process refusal test must fail.

## Task 3: docs

- `docs/commands.md`, the `run` section: one paragraph. On Windows, `run` refuses to pass a secret to a `.cmd`/`.bat`
  file (or `cmd`) when its value holds a character `cmd.exe` interprets, because `cmd.exe` parses a batch file's
  arguments again; use a PowerShell script with `-File`. An `--env` variable read by a batch file as `%NAME%` is
  expanded by the batch itself, so the same care applies inside the script.
- `docs/install.md`'s Windows notes: one line pointing there.

## Out of scope

- Escaping for `cmd.exe` instead of refusing (owner's option B was refusal; escaping is notoriously error-prone).
- PowerShell scripts, Unix shells, the broker.
- Publishing the advisory and the release notes (the controller and the owner).
