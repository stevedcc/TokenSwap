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
  value contains characters it interprets (one of " & | < > ^ % ! or a line break; tswap's generated values often do).
  Run a PowerShell script instead ('run powershell -File .\script.ps1 {{<name>}}', read as $args[0]), or pass it in the
  environment ('run --env PW={{<name>}} script.cmd', read with setlocal EnableDelayedExpansion as !PW!).`
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

## Task 2b: prove the recommended way out (owner, 2026-11-22: "Both ps and cmd?")

The refusal recommends a PowerShell script with `-File`; that path is untested on real Windows. In `EndToEndTests.cs`,
next to T46's batch test, a `[WindowsFact]` with the real binary: a script `capture.ps1` that writes `$args[0]` to
`out.txt` exactly (`[IO.File]::WriteAllText("$PSScriptRoot\out.txt", $args[0])`, no newline added), run as
`tswap run powershell -File capture.ps1 {{name}}` **and** `tswap run pwsh -File capture.ps1 {{name}}` (pwsh is on the
runners), on both legs (redirected and ConPTY, as T46's test does), for every T46 batch case value **and** the corpus's
quote and shell-character cases. Assert: `out.txt` holds exactly the value, and `marker.txt` never appears anywhere the
T46 test looks. Each failure names case, leg and host. If either PowerShell re-parses a value, that's a finding to report
at once: the refusal's advice would then be wrong, and the controller decides before the brief goes on.

## Task 2c: generated values and the unquoted case (owner question, 2026-11-22)

`create`'s `Charset` includes `! @ # $ % ^ & * ( ) - _ = +`, and .NET (like WindowsPty's `QuoteWindowsArg`) quotes an
argument only when it holds a space, a tab or a quote. So a value like `aB3&xY9` reaches `cmd.exe` **unquoted**, and
the text after `&` runs as a command. T46's batch cases all contain a space or a quote; add one without either,
`x&echo.>marker.txt`, to `EvilValues.BatchCases`, so T46's test (and the refusal) cover it, and note in the report what
it does today (expected: `marker.txt` appears without the fix).

The refusal's way out names both paths: a PowerShell script with `-File` (Task 2b proves it), or, for an existing batch
script, `--env`: `run --env PW={{name}} script.cmd`, read inside the script with `setlocal EnableDelayedExpansion` and
`!PW!` (delayed expansion never parses the value as command text). Add a Windows E2E case for that pattern
(`capture-env.cmd`: `@echo off`, `setlocal EnableDelayedExpansion`, `>"%~dp0out.txt" echo(!PW!`): `out.txt` holds the
value exactly and `marker.txt` never appears, for every T46 batch case.

## Task 2d: bash and zsh as targets and as the calling shell (owner, 2026-11-22: "part of the same problem")

E2E with the real binary, in `EndToEndTests.cs` (bash on Linux and macOS, zsh where installed: macOS has it, and the
Linux runner may not, so a missing zsh skips that host with a reason, never an early return):

- **Target:** `capture.sh`/`capture.zsh` writing `"$1"` to `out.txt` exactly (`printf '%s' "$1" > out.txt`), run as
  `tswap run bash ./capture.sh {{name}}` and `tswap run zsh -f ./capture.zsh {{name}}`, for every corpus value (T46's
  `EvilValues`, the batch cases included). Assert `out.txt` holds exactly the value and no `marker.txt` appears.
- **Calling shell:** a zsh script (`zsh -f`) that itself runs `tswap run printf %s {{name}}`, written as a literal token
  in the zsh source, once as is and once after `setopt BRACE_CCL`; tswap must receive the token `{{name}}` unchanged
  (assert the masked output or `--verbose`'s "Found tokens: name"). The same in bash, plus bash with `set -B` (the
  default) and `shopt -s extglob`.
- Each failure names the case, the shell and its options.

## Task 3: docs (owner, 2026-11-22: "we'll need docs about this")

**A new guide, `docs/scripts.md`: "Passing secrets to scripts".** What the tests in Tasks 2b-2d and T46 proved, per
shell, each with a short correct example and the one thing that breaks it:

- **How a value reaches a script:** as one argument (`{{name}}`), in the environment (`--env VAR={{name}}`), or in a
  file (`{{@file}}`); when to use which (arguments are visible in the process list while the command runs, see
  security-model.md; the environment isn't, to other users).
- **bash:** read `"$1"` quoted; never `eval`, `source` or unquoted `$1` with the value.
- **zsh:** `"$1"`; unquoted `$1` isn't split by default (unless `SH_WORD_SPLIT`); never `eval`.
- **PowerShell (Windows PowerShell 5.1 and 7):** `-File script.ps1`, read `$args[0]` (or a `param()`); never
  `Invoke-Expression` or `& ([scriptblock]::Create(...))` with it. In PowerShell, quote the token you type: `'{{name}}'`
  (T43).
- **cmd and batch files:** `run` refuses to pass a value `cmd.exe` would re-parse (why: a batch file's arguments are
  parsed again at launch and again by `%1` inside the script; tswap's generated values often contain such characters).
  The way: `--env PW={{name}}` and `setlocal EnableDelayedExpansion` with `!PW!`; never `%PW%` or `%1` with a secret.
- **Files that a shell sources** (`.env`): single-quoted values; a value with `'` breaks even that (T46 Task 4 text,
  moved or linked here).
- **The calling shell doesn't see values:** tokens are substituted inside tswap; only the token's own quoting matters
  (PowerShell braces, T43; zsh `BRACE_CCL`).

Link it from README.md (the docs list), `docs/commands.md` (the `run` section: one paragraph on the refusal, linking
here), `docs/install.md`'s Windows notes and `docs/agent-integration.md`.

**The agent prompt (`TswapCore/Prompt.cs`):** rule 3's example (`run ./deploy.sh {{secret-name}}`, "the script reads it
as $1") says to read `"$1"` quoted, and on Windows to use a PowerShell `-File` script, never a batch file. This changes
`prompt-hash`, which is fine in 0.3.2; keep the prompt ASCII-only (T43's test) and update any prompt test that pins
the changed sentence only with the controller's sanction, listing it in the report.

## Amendments (round 1: GLM and MiMo, both "no")

MiMo's C1 (scope versus #392's comment) is settled: Tasks 2b-2d and the docs task were added after the commit it read.

- **A1 (GLM C1, wrappers).** The check runs on **every program word** `Validation.ProgramWords` yields for the
  **post-substitution** argv (wrappers such as `timeout`, `nohup`, `find -exec`), not only `argv[0]`. Tests:
  `timeout 5 x.cmd {{name}}` and `find . -exec x.cmd {{name}} ;` are refused with `Starts == 0`; break-it-once: check only
  `argv[0]` and see the wrapper rows fail. An unknown wrapper executable (`wrapper.exe x.cmd …`) stays out of reach, as
  for every other check: say so in the report and the docs.
- **A2 (both, `{{@file}}`).** The filled copy keeps the source's base name, and Windows file names may hold `& % ! ^ ( )`.
  So for a batch target the check covers **every substituted argv element**: secret values and `{{@file}}` paths. A
  refused path names the file token, not a secret. Test: `run x.cmd {{@a&b.yaml}}` is refused.
- **A3 (MiMo I1).** The set adds `(` and `)`: `" & | < > ^ % ! ( )`, CR, LF. `'` and backtick matter only inside a
  script's own `for /f`; that is the script's business (docs). The message lists the set exactly as checked.
- **A4 (MiMo I2, names).** Before deciding, normalise the program name as Windows does: strip trailing dots and spaces
  from the last component and a `:stream` suffix (`x.cmd::$DATA`); compare ignoring case. Tests: `x.cmd.`, `"x.cmd "`,
  `x.cmd...`, `x.cmd::$DATA`, `CMD.EXE`, `X.BAT` are batch targets.
- **A5 (MiMo I5).** `powershell`/`pwsh` with `-File <batch>` counts as a batch target (record in the report what each
  edition does with a `.cmd` script; refuse either way). Test row: `run powershell -File x.cmd {{name}}` refused.
- **A6 (MiMo I3; controller ruling).** `--env` values stay allowed for batch targets: read with delayed expansion
  (`!PW!`) they're never parsed as command text, which Task 2c's E2E proves. `%PW%` inside the script is the script's
  re-parse; the docs say never `%PW%` (or `%1`) with a secret.
- **A7 (both, tests).** Task 1's refused rows include one corpus case per character of the set (`double-quote`,
  `ampersand`, `pipe`, `less-than`, `greater-than`, `caret`, `percent`, `bang`, an open and a close parenthesis,
  `cr-inside`, `lf-inside`). Break-it-once: drop `"` and `&` and see the `double-quote` and `ampersand` rows fail; then
  drop `!` and see the `bang` row fail. The message test asserts only that the value as a whole and the word `INJECTED`
  don't appear.
- **A8 (MiMo M2, M3, M4).** The Windows gate is the existing seam `ctx.Os == OSPlatform.Windows` (as
  `RunWindowsWordingTests` uses), never the real OS check. When several tokens trip it, the message names every
  refused secret or file token, in argv order.
- **A9 (MiMo I6, GLM M6).** The `run` paragraph goes **outside** `docs/commands.md`'s generated block (lines between
  `BEGIN GENERATED` and `END GENERATED` are checked by `CommandReferenceTests`): next to the hand-written `## run --env`
  section. Spelling and doc-link guards apply.
- **A10 (GLM M5).** `run powershell {{name}}` with no `-File` runs the value as code today; that's issue #401, not this brief, but `docs/scripts.md` says to always use `-File`.

## Amendments (round 2: both "no"; three Importants each, all brief errors)

Where a task and an amendment differ, the amendment wins (this applies to every amendment in this brief). Superseded
sentences: Task 2's "Only `{{name}}` tokens in argv count; a `{{@file}}` token is … (no metacharacters)" (A2) and
"Only on Windows (`OperatingSystem.IsWindows()`)" (A8: the `ctx.Os` seam); Task 1's message text (A14).

- **A11 (both I1/I2, Task 2d calling shell).** The probe is `tswap -v run true {{name}}` (`printf` is on tswap's
  blocklist and is refused before tokens are read). Assert tswap's `-v` line `Found tokens: name`. Under zsh's
  `BRACE_CCL` the unquoted `{name}` is expanded to its characters (zsh's documentation, Brace Expansion), so assert:
  unquoted, the token does **not** arrive (tswap reports no token, or a different one); quoted `'{{name}}'`, it arrives
  unchanged. Same pair in bash (plain, `set -B`, `extglob`): unquoted arrives unchanged there. `docs/scripts.md` says
  to quote tokens in zsh when `BRACE_CCL` is set.
- **A12 (MiMo I-2, sanction).** Adding `x&echo.>marker.txt` to `EvilValues.BatchCases` changes the expected array in
  `EvilValuesCorpusTests.BatchCases_AreTheBriefsValues`: update it (a test input changed because this brief changed the
  rules; say so in the commit message, AGENTS.md rule 5).
- **A13 (MiMo I-3, API).** The entry point takes the post-substitution argv:
  `BatchArgumentRefusal(IReadOnlyList<string> argv, IReadOnlyList<SubstitutedToken> tokens)` where a token is a secret
  name or a file token with the argv index it went into. It walks `ProgramWords` (make it `internal`) **and** an
  interpreter's script argument: `powershell`/`pwsh` with `-File` matched by PowerShell's unambiguous-prefix rule as
  `IsPowerShellInline` does (`-f`, `-fi`, `-file`, any case). A one-word helper `IsBatchTarget(string program)` (A4's
  normalisation) serves the unit tests. `RunCommand` calls the entry point once, after substitution, when
  `ctx.Os == OSPlatform.Windows`.
- **A14 (MiMo M-1, GLM M3, message).** Final texts (British spelling; each lists the set exactly):
  - one or more secrets: `Refused: tswap won't pass secret(s) 'a', 'b' to a batch file. cmd.exe parses a batch file's
    arguments again, and their values contain characters it interprets (one of " & | < > ^ % ! ( ) or a line break;
    tswap's generated values often do). Use a PowerShell script ('run powershell -File .\script.ps1 {{a}}', read as
    $args[0]), or the environment ('run --env PW={{a}} script.cmd', read with setlocal EnableDelayedExpansion as !PW!).`
  - a file token: `Refused: tswap won't pass the copy of 'name.yaml' to a batch file: its name contains characters
    cmd.exe interprets (one of …). Rename the file.`
  Tests assert the names appear, and that no value as a whole and no `INJECTED` appear.
- **A15 (both, A7's rows).** The per-character values live in `BatchArgumentTests` only (`EvilValues.Cases` stays as
  T46 left it): build them with T46's `Inside(char)` helper for `^`, `(`, `)` and reuse the existing cases for the
  rest. Break-it-once additionally drops `(` and sees the parenthesis rows fail.
- **A16 (MiMo M-4, GLM M4, PATHEXT).** Cite RedactingPty's `FallbackPty.cs` (ProcessStartInfo, CreateProcess rules) and
  `WindowsPty.cs` (`CreateProcessW(null, cmdLine…)`): neither starts a `.cmd`/`.bat` from an extension-less name, so
  checking the given (normalised) name is enough. Fail closed if that ever changes: a comment at the check says so.
- **A17 (MiMo M-5, GLM M2, Task 2c).** The criterion: `WindowsQuoteArg` (RedactingPty `WindowsPty.cs`) and .NET quote an
  argument only for a space, tab or quote (`%PATH%` already rides unquoted). "out.txt holds the value exactly" means
  T46's comparison, `captured == value + "\r\n"` (`echo(` appends CRLF).
- **A18 (MiMo M-6, break-it-once for the E2E tasks; the controller runs them on CI).** Ship each as a commented variant:
  2b, a `capture.ps1` that `Invoke-Expression`s `$args[0]` (must show `marker.txt`); 2c, the batch reading `%PW%`
  instead of `!PW!` (must show `marker.txt`); 2d, a `capture.sh` with `eval "$1"` (must show `marker.txt`).
- **A19 (GLM M5).** Task 3 also adds `docs/scripts.md` to `docs/README.md`'s page list.

## Amendments (round 3: GLM ready; MiMo one Important, Minors)

Also superseded (MiMo M-10, M-11): Task 2d's `printf` probe (A11), Task 1's `BatchArgumentRefusal(string program, …)`
signature (A13), Task 2c's "T46's batch cases all contain a space or a quote" and its `QuoteWindowsArg` (A17: the method
is `WindowsQuoteArg`), Task 2's PATH/PATHEXT resolution step (A16).

- **A20 (MiMo I-4).** `ProgramWords` yields extension-stripped names (`ProgramName`), so the batch check must test the
  **raw** argv word at each position the walk visits: add a sibling walk that yields positions (or raw words), keep
  `ProgramWords`' normalised yields for `GetFileTokenRefusal`, and call `IsBatchTarget(argv[i])` on the raw word.
  Tests: `run x.cmd`, `C:\dir\x.cmd`, `timeout 5 x.cmd`, `find . -exec x.cmd … ;` all reach `IsBatchTarget` with the
  `.cmd` intact.
- **A21 (M-12).** `-File` matches any unambiguous prefix: `-f`, `-fi`, `-fil`, `-file`, any case.
- **A22 (M-13, M-14).** Build the per-character values locally (`"abcdefg" + c + "hijklmno"`); `EvilValues.Inside` stays
  private. Dropping `(` makes the open-parenthesis row fail (singular).
- **A23 (M-15).** 2b's break variant uses its own value, `;New-Item -Path marker.txt;`, with a `capture.ps1` that runs
  `Invoke-Expression "Write-Output $($args[0])"`; that one must create `marker.txt`.
- **A24 (M-16).** A missing zsh: follow T46's leg idiom (leave the zsh leg out and `_output.WriteLine` why), never an
  early return; the test is a `[UnixFact]`.
- **A25 (M-17).** No test pins rule 3's sentence in the prompt (verified by MiMo); if one turns up, stop and ask.
- **A26 (M-18).** A mixed refusal lists every refused token in argv order, uses the secrets clause and appends "Rename
  the file." for the file tokens. The advice interpolates the first refused secret's name (not a literal `{{a}}`).

## Out of scope

- Fixing PowerShell or Unix-shell behaviour (Tasks 2b-2d test and document it; report failures).
- Escaping for `cmd.exe` instead of refusing (owner's option B was refusal; escaping is notoriously error-prone).
- The broker.
- Publishing the advisory and the release notes (the controller and the owner).
