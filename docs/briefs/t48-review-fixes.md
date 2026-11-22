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
