# Brief T49: `run` refuses Windows PowerShell 5.1's positional command (#401)

Milestone 0.3.2 (owner, 2026-11-22). Base: `brief/t48` (T46–T48 and their review fixes; this brief's branch,
`brief/t49`, starts on its tip). Read AGENTS.md and CLAUDE.md first, then in `TswapCore/Validation.cs`:
`GetBlockedInvocation` (its `pwsh`/`powershell` branch), `PowerShellParameterKey`, `IsPowerShellInline`, `InlineReason`,
`WayOut`; and `TswapTests/InlineCodeBlockTests.cs`, `docs/scripts.md` (the PowerShell section), `docs/security-model.md`
(what the inline check doesn't catch).

One commit per task, test first, break-it-once per key test (name in the commit message the line changed and the test
that failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites, `ykman`,
`sudo`, real YubiKeys or `~/.config/tswap`. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`,
explicit-path commits, no push, merge or rebase; stop and report when the brief can't be built as written. **No existing
test's assertions change**; if an existing test expects a `powershell` command without `-File` to be allowed, stop and
list it.

## What is wrong

Windows PowerShell 5.1 (`powershell.exe`) treats its first argument that is not one of its own parameters as
**`-Command`**: `tswap run powershell Write-Host {{pw}}`, or `run powershell {{pw}}` (the value itself as code), runs the
secret as PowerShell code. `GetBlockedInvocation` refuses only the inline parameters (`-Command`, `-EncodedCommand`,
`-CommandWithArgs` in any spelling, since F9), so the positional form passes. PowerShell 7 (`pwsh`) is different: its
first positional argument is **`-File`** (a script path), which is the T47 ruling-2 basis; `pwsh` stays as it is.

## Task 1: `powershell` needs `-File` before anything positional

In `GetBlockedInvocation`'s PowerShell branch, after the existing inline check, for a program word that is
`powershell` (not `pwsh`; `ProgramName` already handles case, `.exe` and the Windows spellings since F12):

Walk the arguments. Windows PowerShell 5.1's own parameters are recognised **strictly**: a word starting with `-` or `/`
(only those two; 5.1's parser is closed source, so no Unicode dashes or `--` are trusted here), case-insensitive, whose
rest is a prefix of one of these names, at least as long as the minimum given (5.1 resolves unambiguous prefixes):

| Parameter | Takes a value | Minimum prefix |
|---|---|---|
| `PSConsoleFile` | yes | `ps` |
| `Version` | yes | `v` |
| `NoLogo` | no | `nol` |
| `NoExit` | no | `noe` |
| `Sta` | no | `s` |
| `Mta` | no | `m` |
| `NoProfile` | no | `nop` |
| `NonInteractive` | no | `noni` |
| `InputFormat` | yes | `i` |
| `OutputFormat` | yes | `o` |
| `WindowStyle` | yes | `w` |
| `ConfigurationName` | yes | `config` |
| `ExecutionPolicy` | yes | `ex` |
| `File` | yes (the script) | `f` |

A parameter that takes a value consumes the next word. The **first word that is not one of these** decides:
- it is reached right after a `File` parameter (it is the script path): allowed (what follows is the script's arguments);
- anything else (a word that isn't a 5.1 parameter, an unknown or ambiguous spelling, a Unicode-dash or `--` spelling, a
  `-Command`-like word already refused above, or the end of the arguments with no `-File`): **refused**.

So `powershell -File .\deploy.ps1 {{pw}}`, `powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1 {{pw}}`,
`powershell /f .\x.ps1 {{pw}}` are allowed; `powershell {{pw}}`, `powershell Write-Host {{pw}}`,
`powershell -NoProfile Write-Host {{pw}}`, `powershell -NoProfile`, `powershell —File .\x.ps1 {{pw}}`,
`powershell --File .\x.ps1 {{pw}}`, `powershell -Foo .\x.ps1 {{pw}}` are refused. The check applies to the raw command
words like the rest of `GetBlockedInvocation` (wrappers included: `timeout 5 powershell {{pw}}` refused,
`timeout 5 powershell -File .\x.ps1 {{pw}}` allowed).

The refusal (exact):
`'powershell' runs its first argument as code unless it is given -File (Windows PowerShell 5.1 treats a bare argument as -Command), which can transform and print secrets past redaction. Use 'run powershell -File .\script.ps1 {{name}}' (the script reads it as $args[0]).`
(`{{name}}` literally, as the other refusals' examples are written; no secret name or value in it.)

Tests (in `InlineCodeBlockTests`, the existing style): every allowed and refused example above as rows, for `powershell`,
`PowerShell.EXE` and `powershell.exe.`; `pwsh {{pw}}` and `pwsh Write-Host {{pw}}` still not refused by this rule (pwsh's
positional is a script file; a test names that as intended); the exact message once; the refusal never contains the
value (use a value with a set character). Break-it-once: make the walk accept the first non-parameter word without a
preceding `-File`; the `powershell Write-Host {{pw}}` row must fail. Second break: trust `--File`; its row must fail.

## Task 2: docs

- `docs/scripts.md`, PowerShell section: "Windows PowerShell 5.1 runs its first plain argument as code, so `run`
  refuses `powershell` unless `-File` comes first (after its own options); PowerShell 7's `pwsh` reads a plain first
  argument as a script file."
- `docs/security-model.md`, the inline-check list: add that `powershell` without `-File` is refused, and that only
  `-` and `/` spellings of 5.1's parameters are trusted.
- `TswapCore/Prompt.cs` stays as it is (rule 3 already says `-File`).
- In the report: a release-note line ("`run` refuses `powershell` without `-File`: Windows PowerShell 5.1 runs a bare
  argument as code").

## Out of scope

- `pwsh`'s behaviour (positional = `-File`), the batch check (F11 covers `powershell x.cmd`), other interpreters.

## Amendments (round 1; GLM and MiMo)

These replace the brief text they name; where they conflict with it, they win.

- **A1 (MiMo I2, GLM I3/I2; replaces the table's "Minimum prefix" column and "5.1 resolves unambiguous prefixes").**
  Windows PowerShell 5.1's docs document no abbreviations and its parser is closed, so a word counts as a 5.1 parameter
  only when, after one leading `-` or `/` (case-insensitive), it is **exactly** a full name from the table, or exactly
  one of these widely used short forms: `ep` and `ex` (ExecutionPolicy, value), `nop` (NoProfile), `noni`
  (NonInteractive), `nol` (NoLogo), `noe` (NoExit), `w` (WindowStyle, value), `f` (File, value), `if` (InputFormat,
  value), `of` (OutputFormat, value). Any other spelling, prefix or alias is "a word that isn't a 5.1 parameter" and is
  refused (fail closed). Allowed rows: `powershell -ep Bypass -File .\x.ps1 {{pw}}`, `powershell -nop -noni -w Hidden -ex
  Bypass -f .\x.ps1 {{pw}}`; refused rows: `powershell -m -File .\x.ps1 {{pw}}`, `powershell -s -File .\x.ps1 {{pw}}`,
  `powershell -NoProf -File .\x.ps1 {{pw}}`. `-Help`, `-?`, `/?`, `-EncodedArguments` are deliberately not in the list
  (refused, fail closed; say so in a comment).
- **A2 (GLM C1, MiMo I1): stdin is not a script.** When the word after a `File` parameter is in `Validation.StdinScripts`
  (`-`, `/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`), refuse with the existing stdin sentence ("reads code from stdin,
  which can transform and print secrets past redaction", reuse whatever builds it). This applies to `pwsh` too: for
  `pwsh`, a word whose `PowerShellParameterKey` is a prefix of `file` (length 1 or more) followed by a `StdinScripts` word
  is refused (the rest of `pwsh` stays as it is). `-NoExit` (or `noe`) anywhere before `-File` is refused for
  `powershell` (the shell keeps reading stdin after the script; fail closed). `-File` as the last word, with nothing
  after it: refused. Rows: `powershell -File - {{pw}}`, `powershell /f - {{pw}}`, `powershell -NoExit -File .\x.ps1
  {{pw}}`, `powershell -File`, `pwsh -File - {{pw}}`, `pwsh --file - {{pw}}`, `pwsh -f /dev/stdin {{pw}}` refused. Third
  break-it-once: treat `-` as a script path; the `powershell -File - {{pw}}` row must fail.
- **A3 (both; replaces the preamble's stop rule for these two tests only).** Two tests that exist only on `brief/t48`
  (never on main) change because T49 changes the rule; say so in the commit message ("#401: the rule changed, the brief
  names the rows"):
  - `InlineCodeBlockTests.PowerShellOtherParameter_IsNotInline`: the `pwsh` half stays as it is; for `powershell`, the
    `-File` and `-f` rows stay not-refused and the other rows move to a new theory asserting they are refused by the
    T49 rule (the message once).
  - `RunBatchRefusalTests.ABatchTargetBehindAWrapper_IsRefused`, rows `{"powershell", "x.cmd", "{{pw}}"}` and
    `{"powershell", "--file", "x.cmd", "{{pw}}"}`: T49's check runs before substitution, so they are now refused by T49
    (exit 1, the child never starts, the value never printed, the message names `powershell`). Move them to a new test
    asserting that; the `-File`/`/File` rows stay where they are (they still reach the batch check). Precedence is: the
    pre-substitution checks (inline code, T49) first, the batch check after substitution, as `RunCommand` already orders
    them.
  Any other existing assertion that would change: stop and list it.
- **A4 (both M; replaces the exact refusal text).** The reason is built like `InlineReason`, ending with the standard
  way-out sentence so `RunCommand`'s Windows wording swap applies (`RunWindowsWordingTests.EveryWayOutReason_EndsWithTheWholeSentence`
  must cover it): `$"'{program}' without -File runs its first argument as code (Windows PowerShell 5.1 reads it as
  -Command), which can transform and print secrets past redaction. {WayOut}"`, with `{program}` the word as typed. The
  test asserts this exact text for `powershell`.
- **A5 (MiMo M3/M4/M6/M7, GLM M3).** Spellings in the rows: `powershell`, `PowerShell.EXE` and `powershell.exe.` (the
  F12 trailing-dot spelling). The value in the "never printed" row is `a"b$c&d'e`. `powershell -File {{pw}}` (a token as
  the script path) is allowed: the value is a path, PowerShell's error echoes it and output redaction masks it; one test
  row names this as intended. Wrapper rows: `timeout 5 powershell {{pw}}` refused, `timeout 5 powershell -File .\x.ps1
  {{pw}}` allowed.
- **A6 (MiMo M8, GLM M4; Task 2).** `docs/scripts.md`'s sentence adds "only `-` and `/` spellings of its full parameter
  names (and the common short forms `-ep`, `-nop`, `-noni`, `-w`, `-f`) count, and `-File -` (a script from stdin) is
  refused". In `docs/security-model.md`, the row in "What tswap protects against" that lists the inline-code check gets
  the `powershell` sentence. British spelling (`SpellingTests`).
