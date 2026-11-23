# Brief T51: `run`'s inline-code check follows the programs' own parsers (#404, #405, #406, #407)

Milestone 0.3.3. Base: `origin/main` at `3e22bcb`. Read AGENTS.md and CLAUDE.md first, then in `TswapCore/Validation.cs`:
`IsStdinScript` (548), `GetBlockedInvocation` (622: the awk branch, the `deno` branch at 722, the `pwsh`/`powershell`
branch at 744), `WrapperValued` (765), `CheckWrapper` (809, with its `wsl` block at 820), `NoCommandShell` (910),
`ImageProgram`/`WithImageProgram` (917, 935), `PowerShellScript` (1148), `CheckInterpreter` (1195); in
`TswapCli/Commands/RunCommand.cs` the checks before (88) and after (239–256) substitution; `TswapTests/InlineCodeBlockTests.cs`;
`docs/security-model.md` (rows at 171 and 185); and `docs/briefs/t48-review-fixes.md` and `t49-review-fixes.md`,
whose "Convergence rule" this brief obeys.

One commit per task, test first, break-it-once per key test (name in the commit message the line you changed and the
test that failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits (`git commit -F msg -- <paths>`), no
push, merge or rebase; stop and report when the brief can't be built as written. **No existing test's assertion
changes, except the two rows Task 4 names.** If any other existing test fails, stop and list it. Don't touch the
redaction or `tocomment` code (another brief owns it). No reason text repeats a word of the command: the walk also runs
after substitution, where a word can be a secret's value.

## Why parser-first

In 0.3.2 the inline-code check took eight review rounds because each fix matched example spellings. Here every rule
comes from the program's own parser or the kernel's rules (cited), and where those can't be followed exactly the
check fails closed. Accepted over-refusals are listed per task.

## What is wrong (evidence)

Reproduced at `3e22bcb` with `GetBlockedInvocation` from a scratch program and the Debug CLI in test mode
(`TSWAP_TEST_KEY`, a scratch `TSWAP_CONFIG_DIR`):

- **#404 is already refused at run time.** `run python3 -{{a}} {{b}}` and `run pwsh -{{a}} {{b}}` with `a` = `c` both
  end with "After substitution, the value of {{a}} makes this a command 'run' refuses…" (exit 1, nothing run): the
  check at RunCommand.cs:245 walks the substituted argv. The issue saw only the check on the typed words (88).
  `docs/security-model.md:185` still lists #404 as a gap. No test covers the flag-from-a-token shape with an
  interpreter other than `sh` (CommandTests.cs:862, 921 use `sh {{opt}}`).
- **#405:** `wsl -d Ubuntu`, `wsl -u root`, `wsl --cd /srv`, `wsl --`, `wsl ~`, `wsl --system`, `wsl --debug-shell`
  are allowed. Only `wsl` with no argument is refused (Validation.cs:825).
- **#405, found while reading wsl's source:** wsl.exe runs a non-empty command line **through the Linux shell** unless
  `-e`/`--exec` or `--shell-type none` is given. So the allowed `wsl ./deploy.sh {{x}}` is
  `$SHELL -c "./deploy.sh <value>"`: the value is parsed again as shell code, exactly what `sh -c` is refused for.
- **#406:** `deno run --config deno.json - x`, `deno run --config x /dev/stdin` and `deno --log-level debug run -` are
  allowed (Validation.cs:724 takes `debug` for the subcommand; 731 takes `deno.json` for the script). Bare `deno` (its
  REPL, reading stdin) is allowed too (`sub < 0` returns null, 725).
- **#407:** `run python3 /proc/self/root/dev/stdin {{a}}` and, from `/`, `run python3 proc/self/cwd/dev/stdin {{a}}`
  run code piped into `tswap run` (printed `RAN-stdin`, `RAN-cwd`). `/proc/self/task/1/fd/0` and `/proc/1/root/dev/stdin`
  are allowed too.
- **#407, wider:** with tswap at a terminal (reproduced under a pseudo-terminal), `run python3 /dev/stdout {{a}}`,
  `/dev/tty` and `/proc/self/fd/2` all ran the typed line `print("RAN-from-input")`. The child's stdin, stdout and
  stderr are one pseudo-terminal, so opening any of them, or `/dev/tty`, reads the terminal's input.
  `IsStdinScript_AnyOtherWord_IsFalse` (InlineCodeBlockTests.cs:627) pins `/dev/stdout` and `/dev/fd/1` as not stdin.
  Task 2 leaves that true of `IsStdinScript` and adds a wider check beside it.

## The real rules

**wsl.exe** (microsoft/WSL at `65719878ad3c`: `src/windows/common/WslClient.cpp` `WslMain`, `ParseLegacyArguments`;
option names `src/windows/inc/wsl.h`; usage text `MessageWslUsage`):
- It parses its own words left to right and compares each **exactly, case-sensitively** (`argument == WSL_…`).
- Run options:
  - Take the next word as their value: `-d`, `--distribution`, `--distribution-id`, `-u`, `--user`, `--cd`, `--shell-type`, `--parent-console`.
  - Take no value: `--system`.
  - `--shell-type none` selects exec mode, and `login` or `standard` select shell mode. The last one given wins. Any other value is an error.
  - `--` stops option parsing. The mode stays as it is.
  - `-e` and `--exec` stop option parsing and select exec mode.
- Management options run their action and return, so wsl starts no Linux command for them:
  - `--help`, `--list`/`-l`, `--status`, `--version`/`-v`, `--shutdown`, `--terminate`/`-t`.
  - `--set-default`/`-s`/`--setdefault`, `--set-default-version`, `--set-version`.
  - `--export`, `--import`, `--import-in-place`, `--unregister`.
  - `--mount`, `--unmount`, `--manage`, `--update`, `--uninstall`.
- Two management options do start something:
  - `--debug-shell` opens a debug shell.
  - `--install` launches the new distribution unless `--no-launch` is given.
- Any other word that starts with `-` is an error ("invalid command line"), and nothing runs.
- The first word that doesn't start with `-` begins the command line. A leading `~` or distribution GUID is taken out first, as a legacy option.
- What runs ("There are three possible cases"):
  - An empty command line starts the default shell (a login shell).
  - In exec mode, the rest is split with `CommandLineToArgvW` and executed directly.
  - Otherwise the rest of the raw command line runs as `$SHELL -c <commandline>`.

**deno** (denoland/deno at `d8c551b5a5b4`, v2.9.8: `libs/cli_parser/src/parse.rs` `resolve_subcommand`, `defs.rs`,
`convert.rs`):
- The root's default subcommand is `run`. `deno <script>` runs the script, and `deno` with no script starts the REPL, which reads code from stdin.
- `resolve_subcommand` walks past global options to find the subcommand:
  - A long option counts only if its exact name is a global one: `--env-file`, `--help`, `--version`, `--log-level` or `--quiet`. `--log-level` takes the next word unless written with `=`.
  - A word with one `-` counts by its second character only: `h`, `V`, `L` or `q`. Only `-L` written alone takes the next word.
  - The first other word ends the walk.
- `deno run` options that take the next word as their value, **even one starting with `-`** (`NumArgs::Exact(1)`, `OneOrMore`):
  - `--ext`, `--import-map`, `--config`/`-c`, `--cert`, `--min-dep-age`, `--inspect-publish-uid`.
  - `--location`, `--seed`, `--preload`, `--require`, `--conditions`.
  - `--cpu-prof-dir`, `--cpu-prof-name`, `--cpu-prof-interval`.
  - `--lock` takes an optional value.
  - The list grows with releases (`--min-dep-age` is recent). So the check doesn't use it.
- `-` as the script reads it from stdin. Everything after the script belongs to the script (`trailing_var_arg`).

**Linux** (proc(5), the kernel's path walk):
- `/proc/<pid>/root` and `/proc/<pid>/cwd` are magic links to that process's root and working folder. So are `self`, `thread-self` and `task/<tid>/` under them.
- A path through them reaches whatever the rest of the path names: `/proc/self/root/dev/stdin` is stdin.
- `/proc/<pid>/fd/<n>` and `/proc/<pid>/task/<tid>/fd/<n>` reopen that descriptor. `/dev/fd` is `/proc/self/fd`, and `/dev/stdin`, `/dev/stdout` and `/dev/stderr` are its 0, 1 and 2.
- Under a pseudo-terminal, 0, 1 and 2 and `/dev/tty` (and the slave's `/dev/pts/<n>`) are one device, and reading any of them reads the terminal's input.
- Lexically, the paths that can reach the input therefore lie under `/dev/` or `/proc/`. The exceptions are a symbolic link elsewhere (a documented gap) and a relative path resolved in another context (below).

**Windows** (CreateFileW, "Consoles": `CON` opened for reading is the console's input, `CONIN$` always is, `CONOUT$` is
the screen buffer; DOS device names ignore an extension and a folder on older Windows): under ConPTY the console input
is what `run` forwards.

## Task 1 (#404): pin the check after substitution

No production change: the substituted walk exists (RunCommand.cs:239–256). Add facts to `CommandTests` next to
`Run_InlineCodeFlagFromATokenAfterSubstitution_IsRefused`, each with `a` and `b` ingested (`RunTswapWithStdin`) and a
marker file that `b`'s code would create:

| Command | `a` | Outcome |
|---|---|---|
| `run python3 -{{a}} {{b}}` | `c` | exit ≠ 0; stderr has `After substitution, the value of {{a}} makes`; marker absent; neither stream contains `b`'s value |
| `run pwsh -{{a}} {{b}}` | `EncodedCommand` | same, and neither stream contains `EncodedCommand` |
| `run deno {{a}} {{b}}` | `eval` | exit ≠ 0; stderr has `After substitution, the value of {{a}} makes`; neither stream contains `b`'s value |
| `run wsl -e {{a}} -c {{b}}` | `bash` | same as the `deno` row |

All four are refused at the base (checked with a scratch program); if one isn't, stop and report. Break-it-once: remove the `if
(Validation.GetBlockedInvocation(argv) is { } blocked)` block (RunCommand.cs:245–256); the `python3` and `pwsh` rows
fail. Run it before Tasks 2–4 so the rows prove the existing check.

## Task 2 (#407): one input-path predicate, fail-closed

Add `public static bool IsInputPath(string word)` to `Validation`. `IsStdinScript` stays exactly as it is, with its tests.
Factor the path resolution of `IsStdinScript` (548–578: trim, `GetFullPath` on Unix, `ResolveUnixPath` for a
`/`-rooted word on Windows, null where it can't resolve) into a private `ResolveScriptPath(string) → string?` that both
use. `IsInputPath(word)` is true when:
1. `IsStdinScript(word)`, or
2. the resolved path, ignoring case, is `/dev` or `/proc` or starts with `/dev/` or `/proc/`, **except** `/dev/null`
   and anything under `/dev/shm/` (regular files on tmpfs), or
3. on every OS: the word with `\` turned into `/` starts with `//./` (the Win32 device namespace), or its last
   component, trailing dots and spaces trimmed and cut at its first `.`, is `CON`, `CONIN$` or `CONOUT$`, ignoring
   case.

Use `IsInputPath` in place of `IsStdinScript` at every call in the check: 697 (awk `-f`), 750 (`args.Any(...)`, the
PowerShell any-word rule), 1153 (`PowerShellScript`), 1202 and 1229 (`CheckInterpreter`), and in Task 3's deno rule.
Reason texts stay as they are.

Tests (`InlineCodeBlockTests`, a new theory `IsInputPath_…_IsTrue` and one `…_IsFalse`; `IsStdinScript`'s rows untouched):

| `IsInputPath` true | false |
|---|---|
| everything `IsStdinScript` accepts (reuse its rows) | `./x.py`, `/opt/x.ps1`, `x.py`, `--`, `""`, `{{pw}}` |
| `/proc/self/root/dev/stdin`, `/proc/1/root/dev/stdin`, `/proc/thread-self/root/dev/stdin` | `/dev/null`, `/DEV/NULL` |
| `/proc/self/cwd/dev/stdin`, `/proc/self/task/1/fd/0`, `/proc/4242/task/4243/fd/0` | `/dev/shm/x.py` |
| `/dev/stdout`, `/dev/stderr`, `/dev/tty`, `/dev/fd/1`, `/dev/pts/0`, `/proc/self/fd/2` | `console.py`, `icon`, `conf.ps1`, `/opt/CONTEXT` |
| `/proc/self/root/proc/self/root/dev/stdin`, `/proc` | `C:\scripts\deploy.ps1` |
| `CON`, `con.ps1`, `CONIN$`, `C:\x\CONIN$`, `\\.\CONIN$`, `//./CONIN$`, `\\?\C:\x\CON`, `CONOUT$ ` | |

`GetBlockedInvocation` rows refused: `python3 /proc/self/root/dev/stdin {{x}}`, `python3 /dev/stdout {{x}}`,
`bash /dev/tty {{x}}`, `awk -f /proc/self/fd/0`, `pwsh -i /proc/self/root/dev/stdin {{x}}`, `pwsh CONIN$ {{x}}`,
`docker run -i python:3.12 /proc/self/root/dev/stdin`. Allowed: `python3 /dev/shm/job.py {{x}}`,
`pwsh -File ./x.ps1 /dev/null {{x}}`. A Unix fact: from the real current folder, enough `../` to reach `/` then
`proc/self/cwd/dev/stdin` is an input path (the I1 relative test's pattern). Break-it-once: make `IsInputPath` return
`IsStdinScript(word)`; the `/proc/self/root` and `/dev/stdout` rows fail.

Accepted over-refusals: a script or argument under `/dev` or `/proc` (other than `/dev/null`, `/dev/shm/`) anywhere
after `pwsh`/`powershell` (H1's any-word rule) and `deno` (Task 3), e.g. `pwsh -File x.ps1 -Log /dev/stderr`; a file
whose name is `con…` up to its first dot, on every OS; a `\\.\` path.

**Another resolution context: documented, not refused.** A relative word resolved inside a container (its `WORKDIR`,
`-w`), under `wsl --cd`, `sudo -D`, `chroot`, `nsenter -w` or any wrapper that changes the root or working folder
resolves against a folder the command line doesn't show. Every relative word is an input path from some folder (`0`
from `/dev/fd`, `stdin` from `/dev`), so failing closed would refuse every relative script behind every such wrapper
(`docker run img python app.py`). Resolving against one assumed folder (say `/`) is the example-spelling fix the
convergence rule rejects. The check is a documented shallow guard. Task 5 names this.

## Task 3 (#406): `deno` by deno's own walk

Replace the `deno` branch (722–735) with `CheckDeno(string program, List<string> args)`:
1. Any word of `args` for which `IsInputPath` is true: refused with today's reason (`'deno run -' reads code from
   stdin…` + `WayOut`, unchanged text). This covers every subcommand and every position (an option's separate value
   included), so no option list is needed.
2. Walk the global options as `resolve_subcommand` does:
   - Skip a word that is `--quiet`, `--version`, `--help`, `--env-file`, or one that starts with `--help=`, `--env-file=` or `--log-level=`.
   - Skip `--log-level` and the word after it.
   - Skip a word that starts with a single `-`, is longer than one character, and has `h`, `V`, `L` or `q` as its second character. When the word is exactly `-L`, skip the word after it too.
   - Stop at any other word.
3. At the word where the walk stopped:
   - No word left (`deno`, `deno -q`, `deno --version`): refused. Reason: `'deno' with no script starts its REPL, which reads code from stdin and can transform and print secrets past redaction.` followed by `WayOut`.
   - The word is `eval` or `repl`: today's `InlineReason(program, "eval")`.
   - The word starts with `-` (a run option with no subcommand, as in `deno -A main.ts`): refused. Reason: `'deno' with options but no subcommand runs a script whose position this check can't find, or starts its REPL. Write 'deno run <options> <script>'.`
   - Anything else is a subcommand or a bare script: null.

Rows refused: `deno run --config deno.json - {{x}}`, `deno run --config x /dev/stdin`, `deno --log-level debug run -`,
`deno -L debug run -`, `deno -q run - {{x}}`, `deno -`, `deno`, `deno -q`, `deno -A main.ts {{x}}`,
`deno serve -`, `deno run --seed 1 /proc/self/root/dev/stdin`. Allowed: `deno run app.ts {{x}}`, `deno main.ts {{x}}`,
`deno -q run app.ts {{x}}`, `deno --log-level=debug run app.ts {{x}}`, `deno run -A --config deno.json app.ts {{x}}`,
`deno task build {{x}}`. Existing deno rows unchanged (InlineCodeBlockTests.cs:81, 242, 687–689; RunWindowsWordingTests.cs:108).
Add `["deno"]` to `RunWindowsWordingTests.WayOutReasons` (the REPL reason ends with `WayOut`) and update its comment's
count. Break-it-once: restore the old `FindIndex(a => !a.StartsWith('-'))` subcommand; the `--log-level debug run -`
row fails. Accepted over-refusals: `deno --version`/`-h` with a token, `deno fmt -`, a literal `-` or `/dev/…`
argument to a deno script, run options before a bare script.

## Task 4 (#405): `wsl` by wsl.exe's own walk

Add `CheckWsl(string program, List<string> args)`. `CheckWrapper` calls it first for `wsl`, replacing the F24 block
(820–830). It walks `args` with exact, ordinal comparisons, as wsl.exe does, with `exec = false` at the start:

| Word | Then |
|---|---|
| `-d`, `--distribution`, `--distribution-id`, `-u`, `--user`, `--cd`, `--parent-console` | skip it and the next word |
| `--shell-type` | next word `none` → `exec = true`; `login`/`standard` → `exec = false`; anything else or missing → refused (unknown) |
| `--system` | continue |
| `--` | the command is the rest |
| `-e`, `--exec` | `exec = true`; the command is the rest |
| a management option (the list above) | null (wsl runs its action, no Linux command) |
| `--debug-shell`, `--install` | `NoCommandShell(program)` |
| any other word starting with `-` (`--exec=bash`, `-ebash`, `-D`, `--Exec`) | refused (unknown) |
| any other word (including `~` or a GUID) | the command is this word and the rest |

Then, with the command:
- Empty and `exec` false (`wsl -d Ubuntu`, `wsl --`, `wsl -u root`, `wsl --cd /srv`): `NoCommandShell(program)`. This is #405.
- Empty and `exec` true: null. wsl fails with `E_INVALIDARG` and nothing runs.
- Non-empty and `exec` false: refused with the shell-mode reason below.
- Non-empty and `exec` true: `GetBlockedInvocation(WithImageProgram(command))`, wrapped as `'wsl' runs '<inner program>': <inner reason>`, exactly as `CheckWrapper.Wrapped` does.

Reasons (new constants; they don't end with `WayOut`, since wsl's way out is its own):
- Shell mode: `'wsl' without -e (or --shell-type none) runs its command line through the Linux shell ($SHELL -c), which parses a substituted value again and can transform and print secrets past redaction. Give the command after -e, e.g. 'run wsl -e ./script.sh {{secret}}'.`
- Unknown: `'wsl': an option this check doesn't know (wsl.exe matches its options exactly), so it can't tell what wsl runs. Give the command after -e, e.g. 'run wsl -e ./script.sh {{secret}}'.`

Extend `WrapperValued["wsl"]` (786) with `--distribution-id`, `--shell-type`, `--parent-console`, so the `{{@file}}`
program walk (`ProgramPositions`, 261) skips their values too.

**Existing rows that change (needs the controller's sanction before launch):** `ScriptFileOrOrdinaryProgram_IsAllowed`
rows `["wsl", "./deploy.sh", "{{x}}"]` and `["wsl", "-d", "Ubuntu", "./deploy.sh", "{{x}}"]` (InlineCodeBlockTests.cs:293–294)
move to `InlineCodeOrBlockedProgram_IsRefused`. wsl.exe runs both as `$SHELL -c "./deploy.sh <value>"`, the shape `sh -c`
is refused for (source above). Their replacements in the allowed list are `["wsl", "-e", "./deploy.sh", "{{x}}"]` and
`["wsl", "-d", "Ubuntu", "--exec", "./deploy.sh", "{{x}}"]`. Say so in the commit message. If the controller doesn't
sanction it, build everything else in this task and leave those two rows and the shell-mode rule out.

Rows refused: `wsl -d Ubuntu`, `wsl -u root`, `wsl --cd /srv`, `wsl --`, `wsl -d Ubuntu --`, `wsl ~`, `wsl --system`,
`wsl --debug-shell`, `wsl --install`, `wsl --shell-type login ./x.sh {{x}}`,
`wsl --shell-type none --shell-type standard ./x.sh {{x}}`, `wsl -D Ubuntu -e ./x.sh {{x}}`, `wsl --shell-type bogus`,
`wsl -e python3 /dev/stdin`, `wsl --shell-type none bash -c "echo {{x}}"`, `wsl -e bash`. Allowed: `wsl --list`,
`wsl -l -v`, `wsl --status`, `wsl --version`, `wsl --shutdown`, `wsl -d Ubuntu --list`, `wsl -e ./deploy.sh {{x}}`,
`wsl --shell-type none ./deploy.sh {{x}}`, `wsl -d Ubuntu -u app --cd /srv -e ./deploy.sh {{x}}`, `wsl -e`. Existing
refused rows (189–197) and `Wsl_WithNoArguments_IsRefusedAsAShellReadingStdin` (769–777) stay as they are. A fact pins
the shell-mode reason and the unknown reason exactly for `wsl ./x.sh {{x}}` and `wsl --exec=bash`.
Break-it-once: treat shell mode with a command as allowed; the `--shell-type login` and moved
rows fail. Accepted over-refusal: `wsl ~ -e ./x.sh` (a legacy `~` read as the command).

## Task 5: docs

`docs/security-model.md`:
- Row 171: add `wsl` without `-e`/`--shell-type none` (its command line runs through the Linux shell) and with no
  command, and `deno` with no script (its REPL).
- Row 185:
  - Drop #404 from the gaps, and say instead that a flag built from tokens is checked again after substitution (`pwsh -{{a}} {{b}}`).
  - Drop #405 and #406.
  - Replace "a script path is recognised as stdin in any spelling…" with: a script path under `/dev` or `/proc` (other than `/dev/null` and `/dev/shm`), or a Windows console name (`CON`, `CONIN$`), is refused, because it can read stdin or the terminal. A symbolic link elsewhere is not followed. A relative path resolved in another context (a container's working folder, `wsl --cd`, `sudo -D`, `chroot`) isn't checked, because the command line doesn't show where it resolves.
  - Name the accepted over-refusals in one sentence.

Don't change `TswapCore/Prompt.cs` (its hash is pinned).

## Out of scope

- Redaction and `tocomment` (another brief).
- System32's `bash.exe` (WSL's launcher, `BashMain`: `bash <cmdline>` is `/bin/bash -c <cmdline>`). Worth its own issue.
- `deno x` and `deno task` (they run package binaries and the config's shell tasks).
- Broker templates' argument placeholders (validated by pattern, no secrets in argv).
- 8.3 names, symbolic links, an interpreter entrypoint under another image name.
- The prompt text.
