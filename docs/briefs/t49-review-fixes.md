# Review fixes for T49 (and the last T48 round-4 points)

On `brief/t49`. Same rules as the T49 brief: TDD, one commit per item (G4 and G5 may share), break-it-once per key test in
the commit message, `./runtests.sh --unit` after each item, the full `./runtests.sh` once at the end, no push, no
subagents; only add test rows and assertions; if an existing assertion would have to change, stop and list it.

## G1 (Important, MiMo T49 finding 1): pwsh's unmatched word is its script
In `CheckPwsh`, a word whose `PowerShellParameterKey` matches none of the parameter branches is pwsh's positional script
file (pwsh's `GetSwitchKey`/`ParseFile` do the same): hand it to the script check (`PowerShellScript(program, args, i)` or
equivalent), so a `StdinScripts` word is refused with the stdin reason. Make the `StdinScripts` comparison
`OrdinalIgnoreCase` (also for `CheckInterpreter`). Rows refused: `pwsh /dev/stdin {{pw}}`, `pwsh /dev/fd/0 {{pw}}`,
`pwsh /proc/self/fd/0 {{pw}}`, `pwsh -NoProfile /dev/stdin {{pw}}`, `pwsh /dev/STDIN {{pw}}`; allowed: `pwsh /opt/x.ps1
{{pw}}`, `pwsh /opt/x.ps1 -pw={{pw}}`, and every existing allowed pwsh row. Break-it-once: skip unmatched words again;
the `/dev/stdin` rows fail.

## G2 (Important, MiMo T48 round 4): bare `cmd`, and `deno run -`
`cmd` never runs a program safely through `run`: with `/c` or `/k` it runs inline code (already refused), without them it
starts a shell reading stdin. Refuse `cmd` with no `/c`/`/k` with the no-command shell reason (`NoCommandShell` or the
reason `ShellWhenNoCommand` uses). `deno run` with a `StdinScripts` word as its script: the stdin reason. Rows refused:
`cmd`, `cmd /q`, `cmd.exe`, `timeout 5 cmd`, `deno run - {{pw}}`; existing `cmd /c` rows unchanged; `deno run app.ts
{{pw}}` allowed. Break-it-once: drop the `cmd` rule; its rows fail.

## G3 (Minor, MiMo T49 finding 2): the A11 row proves the file-token rule
In `RunFileTokenTests.RunFileToken_InterpreterAnywhereRefused`, add `Assert.Contains("filled copy", err)` for the
`powershell -File x.ps1 {{@f}}` row (an added assertion; if the test is a theory where the other rows' messages differ,
add a separate fact for this row instead).

## G4 (Minor, MiMo T49 finding 3): docs
`docs/security-model.md`: the Windows PowerShell 5.1 rule goes by the program's name, so a PowerShell 7 binary or image
named `powershell` gets 5.1's rule (use `-File`, which both accept).

## G5 (Minor, GLM and MiMo T48 round 4): doc comments
`IsBatchTarget`'s and `WindowsFileName`'s XML summaries: "…only after a name ending in .exe/.cmd/.bat/.com, or a head
Windows trimmed (F23)".

## Round 2 (MiMo re-review: one Important; GLM unavailable, Z.ai weekly limit)

### H1 (Important, MiMo): a stdin path anywhere after PowerShell
`run pwsh -i /dev/stdin {{pw}}` is allowed: the prefix rule reads `-i` as `-InputFormat` and consumes `/dev/stdin` as its
value, while pwsh reads `-i` as `-Interactive` and runs `/dev/stdin` as the script. Stop depending on which parameters
take a value: for `pwsh` and `powershell`, **any word (after `Trim()`) that is in `StdinScripts`** (case-insensitive),
in any position, is refused with the stdin reason, fail closed. Over-refusal accepted: a script argument that is
literally `-` or `/dev/stdin` (`pwsh -File ./x.ps1 -`). Rows refused: `pwsh -i /dev/stdin {{pw}}`, `pwsh -s /dev/fd/0
{{pw}}`, `pwsh -ep Bypass /dev/stdin {{pw}}`, `powershell -File .\x.ps1 -`. Existing allowed rows stay allowed (if one
doesn't, stop and list it). Break-it-once: drop the any-word rule; the `-i /dev/stdin` row fails.

### H2 (Minor, MiMo): the filed gaps are listed
`docs/security-model.md`'s list of what the inline-code check doesn't catch: `wsl` with options but no command (#405), a
`deno run` option value hiding a stdin script (#406), and an interpreter flag built from a token (#404).

### H3 (Minor, MiMo): G2's deno break-it-once
Run it now: drop the `deno run` stdin rule, the `deno run - {{pw}}` row must fail; restore. Record it in H1's commit
message (or a separate empty-diff note in the report if H1 doesn't touch deno).

## Round 3 (MiMo: one Important; GLM: ready, no findings)

### I1 (Important, MiMo): a stdin path in any spelling the system resolves
`StdinScripts` is an exact (ignore-case) match, so `/dev/./stdin`, `/dev//stdin`, `//dev//stdin`, `/dev/../dev/stdin`,
`/dev/fd/./0`, `//proc//self//fd//0` (and the same relative to the working folder, `../../dev/stdin`) pass every stdin
check while the kernel opens stdin. Add one `Validation.IsStdinScript(string word)` and use it in **every** place that
consults `StdinScripts` (H1's rule, `PowerShellScript`, `CheckInterpreter` (both), the awk rule, the `deno run` rule):
- trim; `-` → true;
- otherwise resolve the word with `Path.GetFullPath` (relative to the current folder, collapsing repeated separators and
  `.`/`..`), and compare, ignoring case, with `/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`, `/proc/thread-self/fd/0`, or
  match `^/proc/[0-9]+/fd/0$`; a word `GetFullPath` throws on → false (it is no path the kernel opens).
Rows refused: `pwsh -File /dev/./stdin {{pw}}`, `pwsh /dev//stdin {{pw}}`, `pwsh //dev//stdin {{pw}}`,
`pwsh -File /dev/../dev/stdin {{pw}}`, `pwsh -f /dev/fd/./0 {{pw}}`, `pwsh /proc/thread-self/fd/0 {{pw}}`,
`pwsh /proc/1/fd/0 {{pw}}`, `python3 //dev//stdin {{x}}`, `awk -f /dev/./stdin`, `deno run /dev/./stdin {{x}}`. Existing
rows unchanged (`pwsh -File ./x.ps1 {{pw}}`, `pwsh /opt/x.ps1 {{pw}}` stay allowed). The relative case needs a known
working folder: test it in a unit test of `IsStdinScript` with a word built from the real current folder's depth
(enough `../` to reach `/`, then `dev/stdin`), Unix only. `docs/security-model.md`: a symbolic link to stdin under
another name is not caught (next to renamed copies). Break-it-once: compare the raw word again; the dot and
double-slash rows fail.
