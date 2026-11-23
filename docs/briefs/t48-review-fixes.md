# Review fixes for T46, T47 and T48 (code review round 1, GLM and MiMo)

On `brief/t48` (it holds T46 and T47 too; this branch is merged as one). Same rules as the T48 brief: TDD, one commit
per item, break-it-once per key test in the commit message, `./runtests.sh --unit` after each item, the full
`./runtests.sh` at the end, no push, no assertion of an existing test changed except where an item says so.

## F1 (Important, MiMo, T47): PowerShell's slash spellings of its inline parameters

`Validation.IsPowerShellInline` matches only dash spellings (`-c`, `-e`, `-ec`, `-cwa`, prefixes of `-command`,
`-encodedcommand`, `-commandwithargs`). PowerShell's host accepts `/` as the parameter prefix too (ruling 2 relies on it
for `/File`), so `tswap run powershell /command x.cmd {{pw}}` is refused by neither the inline-code check nor the batch
check, and `pwsh /c Write-Host {{pw}}` runs a value as code. Fix: `IsPowerShellInline` treats a leading `/` exactly as a
leading `-` (same prefix lengths, any case), on every OS (fail closed). Tests, as rows next to the existing ones:
- `RunPowerShellEncodedTests` (or wherever the dash spellings of the inline check are tested): `/c`, `/C`, `/e`, `/ec`,
  `/cwa`, `/comm`, `/Command`, `/enc`, `/EncodedCommand`, `/commandwithargs` are refused for `powershell` and `pwsh`
  exactly as their dash forms are; `/co` (too short, as `-co`) behaves as `-co` does today.
- `BatchArgumentTests` / `RunBatchRefusalTests`: `powershell /command x.cmd {{v}}`, `powershell /c x.cmd {{v}}`,
  `pwsh /command x.cmd {{v}}` are refused (whichever refusal fires first; assert exit 1, the child never starts, the
  value never printed).
- Break-it-once: remove the `/` handling; the new rows fail.
- `docs/scripts.md`: where it says `run` refuses `-Command` and `-EncodedCommand`, add "(also spelt with `/`)". Don't
  touch `docs/scripts.md:52` (T48 A18 already changed it).

## F2 (Minor, MiMo, T46): the batch test's "refused" check matches cmd's own error text

`Run_BatchFile_EvilValues_NeverInject_Windows` counts a run as "refused, naming batch files" when the output contains
`batch`; cmd's own "…operable program or batch file." contains it too (CI run 45003711187 printed "refused, naming batch
files" for runs that injected). Make it: exit code non-zero **and** stderr contains `Refused: tswap won't pass` **and**
`to a batch file`. On the redirected leg use stderr; on the ConPTY leg (one combined stream) use the combined output.
This changes a check the brief's own test added, not an existing test's assertion; say so.

## F3 (Minor, MiMo, T46): failure messages that would print a value

`CheckEnvExact`'s `Assert.Equal(["tool"], pty.Argv!)`, `CheckRotatePrevious`'s `Assert.Equal(RotatedSibling, …)` and the
NFD facts' `Assert.StartsWith` print the actual text on failure. Turn each into `Assert.True(<same condition>, <message
naming the case and what differed, never the value>)`. Same conditions, so not an assertion change.

## F4 (Minor, GLM, T46): `CheckFillRoundtrip` compares to `stored`

Compare the decoded copy to the value the test stored (`stored`), not to `GetValue(caseName)`. Same expected value.

## F5 (Minor, both, T46): the findings name their issues

Finding 1 is #398, finding 2 is #399, findings 3–5 are #402. Append ` (#398)` / ` (#399)` / ` (#402)` to each finding's
line in `EvilValues.KnownFindings` (or its `FindingN` constant) and to the matching `Skip` text, so the guard that keeps
them in step still holds. Skip and line text only.

## F6 (Minor, MiMo, T47): the combined ruling-3 message

A `BatchArgumentTests` row: a refused `{{@file}}` copy whose **name and** temporary folder both hold a set character,
no secret: the exact message (the folder sentence and "Rename the file.").

## F7 (Minor, GLM and MiMo, T47): Git Bash tests never pass without Git Bash

`Run_GitBashScript_EvilValues_ArriveExactly_Windows` and `Run_GitBashScript_EnvValue_EvilValues_ArriveExactly_Windows`:
when `FindGitBash()` finds nothing, fail with a message saying so (as `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows`
does); it is on every GitHub Windows runner.

## F8 (Minor, GLM, T47): `docs/commands.md` "run and batch files"

"a `{{@file}}` copy whose name holds one" → "a `{{@file}}` copy whose name or temporary folder holds one".

## Not code (controller)

T46 detector proof (CI 45003739420 on `t46-detector`, and the head's own red run 45003711187, which is the batch
injection T47 fixes); the T46 tocomment-exclusion and Task 4 wording rulings, ratified; #402 gets the WindowsPty
quoting note for finding 5.

## Round 2 (controller ruling, after the F1 check found more spellings)

The F1 report showed PowerShell 7's host parser (`CommandLineParameterParser.GetSwitchKey`/`MatchSwitch`,
`CharExtensions.IsDash`) accepts more than `-` and `/`: a doubled dash, the Unicode dashes U+2013, U+2014, U+2015,
surrounding whitespace, and any prefix down to the parameter's short form (`-co`, `-com`, `-en`). A spelling list will
keep missing one, so both checks follow PowerShell's own rule, failing closed where Windows PowerShell 5.1's closed
parser could differ.

### F9: one PowerShell parameter normaliser

`Validation.PowerShellParameterKey(string arg)` (private or internal): trim whitespace (`string.Trim()`), then strip every
leading character that is `/`, `-`, U+2013, U+2014 or U+2015 (any number: fail closed), lower-case invariant. It returns
null when nothing was stripped (not a parameter) or nothing is left.

`IsPowerShellInline(arg)` is then: the key is non-null and is `ec` or `cwa`, or a prefix (length 1 or more) of
`command`, `encodedcommand` or `commandwithargs`. (So `-c`, `-co`, `-com`, `--command`, `–c`, `—Command`, ` -c `, `/c`,
`-e`, `-en`, `--encodedcommand` are all inline; `-ex` (ExecutionPolicy), `-config…`, `-nop`, `-f` are not.)

Tests (next to F1's rows): each of those spellings is refused for `powershell` and `pwsh`, and `-ExecutionPolicy`,
`-ConfigurationName`, `-NoProfile`, `-File` are not inline. **`PowerShellTooShortPrefix_SpeltWithASlash_BehavesAsItsDashForm`
(added in F1 on this branch, never on main) is replaced**: `-co`/`/co` are now refused. That test exists only on this
branch, so this is the brief's own correction, not a change to an existing test; say so in the commit. Break-it-once:
strip only `-` and `/`; the Unicode-dash and `--` rows fail.

### F10: the batch check after PowerShell fails closed

For a program word that is `powershell` or `pwsh` (as `IsInterpreter` names them, any case, with `.exe`), **every later
word that `IsBatchTarget` accepts after `Trim()`** counts as a batch target, whatever option or position it is in (this
replaces the `-File`/`/File`/positional walk for these two programs; it covers `--file`, Unicode dashes, padding and
Windows PowerShell 5.1's positional `-Command`, #401's case for batch files). This over-refuses a batch file's name passed
as a plain argument to a PowerShell script (`pwsh -File s.ps1 x.cmd {{pw}}`), as ruling 2 already did for pwsh;
accepted. Tests: `powershell x.cmd {{v}}`, `powershell --file x.cmd {{v}}`, `pwsh –File x.cmd {{v}}`, `pwsh " x.cmd" {{v}}`
are refused; `powershell -File .\deploy.ps1 {{v}}` and `pwsh -File ./deploy.ps1 {{v}}` are still allowed (the refusal's
own examples, `TheRefusalsOwnExamples_AreNotRefused`). If an existing test on main asserts that a batch-file word after
`powershell`/`pwsh` is allowed, stop and list it. Break-it-once: restore the old walk; the `--file` and positional rows
fail.

`docs/scripts.md`: the inline-code sentence says "in any spelling PowerShell accepts (`-`, `--`, `/`, the Unicode
dashes, a prefix)", and the batch section says any batch file named after `powershell` or `pwsh` counts.

## Round 3 (code review of T48 + fixes: GLM ready, MiMo one Important)

### F11 (Important, MiMo): the batch check looks at every word (replaces F10's trigger)

F10 checks words after a program word that `ProgramName` calls `pwsh`/`powershell`, but `ProgramName` doesn't normalise
as Windows does, so `"pwsh.exe."`, `"pwsh.exe "`, `"pwsh.exe::$DATA"`, an 8.3 name, or an unknown wrapper (`docker run …`)
still hand a value to `x.cmd`. Stop guessing which program starts it: on Windows, when a substituted value holds a set
character, **every word of the command (the raw words, as A20 keeps them, after `Trim()`) that `IsBatchTarget` accepts is
a batch target**, whatever program or position it is in. The program walk for batch purposes (`ProgramPositions` and the
F10 PowerShell rule) is no longer needed for this check; remove what only it used (keep what other checks use).
Over-refusal (accepted): any word that `IsBatchTarget` accepts, passed as plain data next to such a secret, is refused
too (`tool x.cmd {{pw}}`, `git commit -m "fix x.cmd" {{pw}}`, a word that is just `cmd`); the refusal message already
says how to pass the secret another way.
Tests: rows `["pwsh.exe.", "x.cmd", v]`, `["pwsh.exe ", "x.cmd", v]`, `["PowerShell.EXE.", "x.cmd", v]`,
`["pwsh.exe::$DATA", "x.cmd", v]`, `["POWERS~1.EXE", "x.cmd", v]`, `["docker", "run", "img", "x.cmd", v]`,
`["anytool", "--flag", "x.bat", v]` refused; the refusal's own examples still allowed (`TheRefusalsOwnExamples_AreNotRefused`),
`powershell -File .\deploy.ps1 {{v}}` allowed, `--env PW={{v}} deploy.cmd` allowed. Existing rows in `AllowedCommands`
that hold a batch word as data: if any exists, stop and list it. Break-it-once: restore F10's PowerShell-only trigger;
the `pwsh.exe.`, `docker` and `anytool` rows fail. `docs/scripts.md` and `docs/commands.md` "run and batch files" (GLM
minor 4): say a batch file named anywhere in the command counts.

### F12 (Important, MiMo): the inline check normalises the program word as Windows does

`ProgramName` (used by `GetBlockedInvocation`) strips, before its extension strip and comparisons, a drive prefix, a
`:stream` suffix and trailing dots and spaces, exactly as `IsBatchTarget` normalises (one shared helper for both). Rows
in `InlineCodeBlockTests`: `["pwsh.exe.", "-c", "Write-Host {{v}}"]`, `["pwsh.exe ", "-c", …]`, `["PowerShell.EXE.", "-c", …]`,
`["pwsh.exe::$DATA", "-c", …]` refused, and the same normalisation for the other interpreters it names (one row each for
`python.exe.` and `cmd.exe.`). 8.3 names can't be matched as text: say so in `docs/security-model.md`'s list of what the
inline check doesn't catch (it is a shallow guard). Break-it-once: drop the trailing-dot strip; the `pwsh.exe.` row fails.

### Minors

- F13 (MiMo M2): rename `PowerShellInlineParameter_InAnySpellingPowerShellAccepts_IsRefused` to
  `PowerShellInlineParameter_InAnySpellingPowerShellAccepts_OrANearMiss_IsRefused`, doc comment: `-/cwa` and `---ec` are
  near misses PowerShell 7 rejects, refused fail-closed.
- F14 (MiMo M3): `docs/commands.md` "(and every other command that reads piped input)" → "(and every other command that
  reads piped text)".

### F15 (controller, from the F12 report): image tags are not stream suffixes

F12's `WindowsFileName` cuts at the first `:` on every OS, so with a `{{@file}}` token an image tag (`python:3.12`,
`node:20`) reads as the interpreter `python`/`node` and is refused. Strip a `:stream` suffix only when the part before the
first `:` ends in `.exe`, `.cmd`, `.bat` or `.com` (any case, after the drive prefix): `pwsh.exe::$DATA`, `x.cmd::$DATA`,
`pwsh.exe:s` still normalise; `python:3.12`, `node:20`, `cmd:x` do not. Tests: `docker run -v {{@cfg.yaml}}:/c.yaml
python:3.12 app` and the same with `node:20` are not refused by the `{{@file}}` check (they weren't before F12; if main
has such a row already, it must still pass); the F11/F12 stream rows still refused. Break-it-once: cut at the first `:`
again; the image-tag rows fail. Also F16 (minor): `StrictStdin`'s refusal message keeps its exact text (the brief fixes
it), no change.

## Round 4 (code re-review: GLM ready, MiMo two Important)

### F17 (Important, MiMo I1 = GLM M1): trim before the stream gate
In `WindowsFileName`, take the part before the first `:`, `TrimEnd('.', ' ')` it, and test **that** with
`HasProgramExtension`; if it passes, the name becomes the trimmed head. Rows: `IsBatchTarget` true for `x.cmd.:s`,
`x.cmd :s`, `x.cmd.::$DATA`; `InlineCodeOrBlockedProgram_IsRefused` for `pwsh.exe.:$DATA -c …` and `pwsh.exe ::$DATA -c …`;
run row `["x.cmd.:s", "{{pw}}"]` refused; F15's image-tag rows still allowed. Break-it-once: test the untrimmed head
again; the new rows fail.

### F18 (Important, MiMo I2): an image tag that names an interpreter, behind a wrapper
In the wrapper/subcommand walk only (`CheckWrapper` and `find -exec`'s inner check), a word whose last path component,
with a trailing `:<tag>` removed, names a checked program (`python:3.12` → `python`, `node:20` → `node`,
`mcr.microsoft.com/powershell:7.4` → `powershell`) is checked as that program with the words after it as its arguments.
`GetFileTokenRefusal`'s data-word check stays as F15 has it. Rows: `docker run python:3.12 -c "print('{{pw}}')"`,
`docker run node:20 -e "console.log('{{pw}}')"`, `docker run mcr.microsoft.com/powershell:7.4 -c "Write-Host {{pw}}"`
refused; `docker run python:3.12 app.py {{pw}}` and F15's `docker run -v {{@cfg.yaml}}:/c.yaml python:3.12 app` allowed.
`docs/security-model.md`: an image whose entrypoint is an interpreter but whose name doesn't say so still runs
unchecked. Break-it-once: drop the tag strip; the three refused rows fail.

### F19 (Minor, MiMo M1): `wsl` is a wrapper
Add `wsl` to `Validation.Wrappers` (with its valued options `-d`, `--distribution`, `-u`, `--user`, `--cd`, `-e`/`--exec`
taking the command). Rows: `wsl bash -c "echo {{pw}}"` and `wsl -d Ubuntu bash -c "echo {{pw}}"` refused,
`wsl ./deploy.sh {{pw}}` allowed. If `wsl -e`/`--exec`'s command needs its own handling, treat the word after it as the
command. Break-it-once: remove `wsl`; the refused rows fail.

### F20 (Minor, MiMo M2): `IsBatchTarget`'s doc comment says the stream suffix is dropped only after a program extension.
