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
