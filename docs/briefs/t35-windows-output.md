# Brief T35: Windows output: PowerShell's eaten braces, Windows wording, UTF-8 console output, ConPTY escape sequences (#348, #349, #294 leftovers)

Issues: https://github.com/stevedcc/TokenSwap/issues/348 (three items, the third in a comment),
https://github.com/stevedcc/TokenSwap/issues/349 (and its comment on sshd's title), and the open parts of
https://github.com/stevedcc/TokenSwap/issues/294: item 4 (garbled banners and glyphs in Windows PowerShell 5's
console) and the T31 review's leftover (`init --yubikey`'s header and closing line print `sudo tswap slot add
--yubikey` on Windows too). Also https://github.com/stevedcc/TokenSwap/issues/355 (non-ASCII values unredacted on a
Windows console; library side stevedcc/RedactingPty#12), closed by Task 3 (amendment A4). Base: `origin/main` at 51b0b37. Read AGENTS.md and CLAUDE.md first, then:
- for Task 1: `TswapCli/Commands/RunCommand.cs` (`Execute` up to `ctx.Storage.LoadConfig()`), `TswapCore/Validation.cs`
  (`TokenRegex`, `FileTokenRegex`, `ValidateFileTokens`, `ExtractTokens`, `ValidNameRegex`, `MaxNameLength`),
  `TswapTests/RunEnvTests.cs` (its `Run` helper and `ErrorLine`), `TswapTests/RecordingPty.cs`,
  `TswapTests/CommandArgumentErrorTests.cs` (a `FleetMachine` with no `init`), `TswapCore/Prompt.cs`, `docs/install.md`
  ("Windows notes"), `docs/agent-integration.md`, `docs/examples.md` (the Helm block).
- for Task 2: `TswapCore/Validation.cs` (`WayOut`, `InlineReason`, `GetBlockedInvocation`, `IsPowerShellInline`),
  `RunCommand.cs` (`ThrowIfBlocked`, the pipe refusal, the after-substitution refusal), `TswapCli/CommandContext.cs`
  (`Os`, `RequireSudo`), `TswapCli/ElevatedCommand.cs`, `TswapCli/Commands/InitCommand.cs` (`ExecuteKeyring`, and
  `ExecuteFido2`'s header and closing line, T31's fix), `TswapTests/InitFido2Tests.cs`
  (`InitFido2_Header_SaysSudoOrAnElevatedPrompt`), `TswapTests/InitKeyringOneKeyTests.cs`,
  `TswapTests/InlineCodeBlockTests.cs`, `TswapTests/FleetMachine.cs` (`Os`).
- for Task 3: `TswapCli/Program.cs`, `TswapCli/SystemConsole.cs`, `TswapCli/CliHost.cs` (the error lines),
  `TswapCli/ControllingTerminal.cs` (`WindowsConsole.IsConsole`, the `GetStdHandle`/`GetConsoleMode` imports),
  `TswapTests/EndToEndTests.cs` (`Run_CompoundCommand_RedactedOutput_WindowsConPty`, `RunTswapInConPty`,
  `RunTswapWithStdin`, `MakePsi`), and, read-only, .NET's `System.Console` on Windows: `Console.OutputEncoding`'s
  setter calls `SetConsoleOutputCP` for every code page but 1200 and fails silently without a console
  (`ConsolePal.Windows.cs`, `SetConsoleOutputEncoding`, `HandleSetConsoleEncodingError`); a writer that `Console.SetOut`
  installed is kept when the encoding changes (`Console.cs`, the `OutputEncoding` setter); the console's default
  encoding is `OSEncoding(<OEM code page>)` when no code-page provider is registered, which tswap doesn't register
  (`EncodingHelper.Windows.cs`, `GetSupportedConsoleEncoding`).
- for Task 4: RedactingPty 1.2.0's `RedactingPty/WindowsPty.cs` (tag `v1.2.0` of stevedcc/RedactingPty; a clone is at
  `~/RiderProjects/redactingpty-wt/main`, `git show v1.2.0:RedactingPty/WindowsPty.cs`), `PtyRunnerFactory.cs`,
  `IStreamMatcher.cs`, `StreamMatch.cs`, `StreamRedactor.Matchers.cs`; tswap's `TswapCli/FingerprintStreamMatcher.cs`
  (an `IStreamMatcher`), `CommandContext.PtyRunner`, `TswapTests/FingerprintStreamMatcherTests.cs`,
  `TswapTests/RunVaultRedactionTests.cs` (`FailingPty`).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `flock ~/.cache/tswap-suite.lock ./runtests.sh --unit` after each task and the full
`flock ~/.cache/tswap-suite.lock ./runtests.sh` at the end (another implementer may run a suite at the same time). No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Tests never use the real clock or sleeps (the existing ConPTY E2E helper's bounded paint wait is
RedactingPty-style plumbing that already exists; add no new sleeps). Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion unless this brief
sanctions it by name (it sanctions one, in Task 2). British spelling in new text.

**Windows-only behaviour, how it is tested.** This machine is Linux. Every Windows decision is behind a seam that the
unit suite drives on Linux (`CommandContext.Os`, which already exists; two new seams below), and the real Windows
calls are covered by tests that run only on CI's `windows-latest` job (unit and E2E legs, `.github/workflows/ci.yml`
lines 25 and 215). You can't run those here: write them, check they compile and skip cleanly on Linux, and say in each
commit and in the report which tests are Windows-only and unverified locally; the controller's PR run is their red/green
check, and for those the break-it-once is done on CI by the controller (list the line to revert for each). What only the
owner can check by hand is in "Owner checks" at the end.

**Review history.** Round 1 (MiMo "no", GLM "yes"): both I1 (redirected output not byte-identical in the mixed
console/redirect case) → A1; both I2 (unsanitised echo of `{@path}`) → A2; MiMo I3 (no end-to-end check of the
sequences-as-text symptom) → A3, partly (the fragments it suggests are emitted by the outer pseudo console too); #355 →
A4; MiMo M1 (EncodingHelper path) → A5 (the file exists, at `src/libraries/Common/...`; full path given); MiMo M2 / GLM
M6b (paragraph placement) → A6; MiMo M3 (the line-686 argv) → A7; MiMo M4 / GLM M6c (sentinels, two captures) → A8;
MiMo M5 (PowerShell 5.1 `-File` and `"`) → A9; MiMo M6 / GLM M4 (PowerShell mechanism stated as fact on bash) → A10;
MiMo M7 (VT left on after Ctrl+C) → A11; MiMo M8 (`IsConsole` is private) → A12; GLM M1 (`print.ps1` doesn't exist) →
A13; GLM M2 (the "63 `.Reason` assertions" figure) → A14; GLM M3 (the seam is live in in-process tests) → A15; GLM M5
(the ingest check shows names, not the value) → A16; GLM M6a (where the braces warning goes) → A17. All folded in
below; none rejected.

**Parallel briefs.** T34 (SlotEnrol*.cs, SlotStage.cs, ProcessSshTransport.cs, SlotCommand.cs's request/accept output,
docs/multi-machine.md's enrolling-over-SSH section), T36 (SlotsCommand's kind labels, vault-file modes,
docs/multi-machine.md's Sync section) and T37 (.github/workflows, the eval, the broker template test, the install-script
upgrade test, SshAgentFramingTests) touch none of T35's code paths. Shared files, said so the merges are expected:
- `TswapCli/CommandContext.cs`: T35 adds one property (`StdoutConsoleMode`, Task 4) next to `PtyRunner`; nothing else.
- `TswapTests/EndToEndTests.cs`: T35 adds three tests at the end of its "Windows ConPTY coverage" section and touches no
  helper; T37's install-script upgrade test may land in the same file.
- `TswapCore/Prompt.cs`: two lines (Task 1), in the `run` bullet and rule 3.
- `docs/install.md`: T35 adds bullets to "Windows notes" only. The sshd-title note of #349's comment goes there, not into
  T34's enrolling-over-SSH section of `docs/multi-machine.md`.

## Why

**#348.1, PowerShell eats the braces.** In PowerShell `{ ... }` is a script block. The owner, Windows PowerShell 5.1,
0.3.1-pre-f7c61b0: `tswap run cmd /c echo {{name}}` reaches tswap as `cmd /c echo {name}` (one pair gone), and tswap says
`No {{tokens}} or {{@file}} tokens found in command` (`RunCommand.Execute`, line 75), with no hint; `'{{name}}'` works.
Every PowerShell user meets this on their first `run`. Worse, with one quoted and one unquoted token, the `{b}` goes to
the child as a literal and nothing is said. `docs/install.md` ("Windows notes") and `docs/examples.md` (line 144) even
say the unquoted `-f {{@values.yaml}}` "works in cmd and PowerShell".

**#348.3, Unix wording on Windows.** `tswap run cmd /c echo '{{name}}'` is refused rightly, but with
`Validation.WayOut` (line 425: "e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1)") and
`RunCommand.ThrowIfBlocked`'s "Use 'sudo ... get <name>' to view a secret." (line 444; the same sudo line at 93 and 239).
Windows has no `./script.sh`, `$1` or `sudo`.

**#294 leftover.** `InitCommand.ExecuteKeyring` prints `sudo tswap slot add --yubikey` in its header (line 330) and closing
text (line 383) on every OS; T31 fixed the same two lines of `ExecuteFido2` (lines 413, 450) with the platform-neutral
"(with sudo, or from an elevated prompt on Windows)".

**#348.2 and #294.4, glyphs.** Nothing in tswap sets the console's output encoding (no `OutputEncoding`, `SetConsoleOutputCP`
or code-page provider anywhere in TswapCli or TswapCore). On Windows .NET then writes in
`OSEncoding(<the console's OEM code page>)`, which best-fits or replaces what the code page lacks: the owner saw `❌` as
`?`, `✓` as `V`, `⚠` as `?`, and the banners as `+---+` and `�` in Windows PowerShell 5's console. The glyphs come from
string literals all over TswapCli (the `❌ Error:` prefix in `CliHost.Run` lines 107 and 112 and `CliRunner` lines 25 and 30;
`✓`, `⚠`, `✅`, `✗` and the `╔═╗║╚╝─` banners in many commands; `—`, `…` and `→` in hundreds of lines), so there is no one
place to swap them.

**A redaction gap found while reading RedactingPty for this brief.** RedactingPty's `WindowsPty.Run` decodes the
pseudo console's output with `Console.OutputEncoding` and re-encodes it the same way (WindowsPty.cs lines 317-331). ConPTY
always writes UTF-8. So on a Windows console today a secret value with a non-ASCII character (an ingested `pässwört`) is
decoded into other characters, doesn't match, and its bytes reach the console unredacted. Task 3 closes it from tswap's
side: with the output encoding UTF-8, the library decodes ConPTY's UTF-8 correctly. (The library fix is a follow-up below.)

**#349, ConPTY's escape sequences as text.** On a Windows console with stdin, stdout and stderr all consoles,
`PtyRunnerFactory.Create` picks `WindowsPty` (Windows 10 1809+), which runs the child on a pseudo console made with flags 0
(WindowsPty.cs line 189) and writes its output, VT sequences included, to tswap's stdout. The classic console shows them
as text unless the writer has `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on its output handle, and tswap doesn't set it: the
owner's `tswap run choice /m '{{name}}' /t 1 /d y` printed `←[?9001h←[?1004h←[?25l←[2J←[m←[H[REDACTED: name] [Y,N]?←]0;C:\WINDOWS\system32\choice.exe←[?25h ←[?9001l←[?1004l`.
Where they are interpreted (Windows Terminal today, or conhost once VT is on), ConPTY's start-up clears the screen and
homes the cursor, and its OSC 0 sets the window title to the child's path, which outlives `run` (the comment's Mac title
stuck at `conhost.exe` after sshd's pseudo console is the same mechanism, in OpenSSH for Windows). The pseudo console
lives in RedactingPty (a separate repository of the owner's), not in tswap; this brief fixes what tswap can from outside
it, with no library change, and lists the library changes as follow-ups.

## The design (decided; rulings marked)

### Task 1: the braces hint (#348.1)

- **What counts.** An argument of the command (after the `--env` pairs, as `ParseOptions` returns it) that is
  *exactly* one of:
  - `{<token>}` where `<token>` matches `^[a-zA-Z0-9_-]{1,64}(?::previous)?$` (a name, as `Validation.ValidNameRegex` and
    `MaxNameLength`, optionally `:previous`), or
  - `{@<path>}` where `<path>` has no `{` or `}` and isn't empty.
  New in `RunCommand`: `internal static IReadOnlyList<string> BracedTokens(IReadOnlyList<string> commandArgs)`: the
  distinct matching arguments, in argument order. A brace pair inside a longer argument (`--x={a}`, `{a}{b}`, `{}`,
  `{a b}`, `{a.b}`, `HEAD@{1}`) never counts.
- **Ruling: by shape only, no vault lookup (controller default; owner may change).** The issue suggests hinting only
  when the name is in the vault. That needs `K_v` (a record vault's names are HMACs), so an unlock (a touch, a password,
  an agent) on an error path, and a failed unlock would replace the plain error with an unlock error. The hint is
  conditional in its wording ("looks like"), and an exact `{word}` argument with no token next to it is almost never
  meant literally. The cost: a deliberate literal `{word}` argument next to a real token gets a needless warning line.
- **No token at all** (`allTokens.Count == 0 && fileTokens.Count == 0`): the refusal stays first, word for word, and
  each braced argument adds a line. `public const string NoTokensText = "No {{tokens}} or {{@file}} tokens found in
  command";` (today's literal, moved into a const). New `internal static string BracesHint(string argument)`:
  `$"The argument {argument} looks like the token {{{argument}}} with one pair of braces removed, which PowerShell does
  to an unquoted token. Quote it: '{{{argument}}}'."` So for `{db-pw}` the person sees
  ``The argument {db-pw} looks like the token {{db-pw}} with one pair of braces removed, which PowerShell does to an
  unquoted token. Quote it: '{{db-pw}}'.``
  and for `{@values.yaml}` the same with `{{@values.yaml}}`. The exception message is `NoTokensText`, then for each braced
  argument `"\n" + BracesHint(arg)`. Exit 1, as today. Nothing is unlocked or read.
- **Tokens found, and a braced argument too:** `run` goes on, and passes the braced argument to the child unchanged, after
  writing to stderr, once per distinct argument, `internal static string BracesWarning(string argument)`:
  `$"Warning: the argument {argument} looks like the token {{{argument}}} with one pair of braces removed, which
  PowerShell does to an unquoted token; it is passed on as it is. Quote it: '{{{argument}}}'."` Written after every
  refusal that comes before the unlock has passed (`ThrowIfBlocked`, the file-token refusal, the pipe check, the root
  check), immediately before `ctx.Storage.LoadConfig()`. Ruling: **warn, not refuse** (the owner's default), because the
  argument may be meant literally and `run` can't tell.
- **Echoing the argument is safe:** it has a name's characters only, or a path, and `run`'s existing errors already name
  tokens (`Secret 'x' not found`). No value is ever looked at.
- **Platform-neutral.** Brace stripping is PowerShell's on every OS (pwsh on Linux and macOS too), so the hint and the
  warning are printed everywhere; on bash and zsh `{name}` is passed as typed, and a hint for a missing brace there is
  just as right.
- **Docs and prompt.**
  - `docs/install.md`, "Windows notes", a new first bullet: "**PowerShell and `{{tokens}}`.** In PowerShell (Windows
    PowerShell 5.1 and PowerShell 7) quote every argument that holds a token: `tswap run psql -h db -U app
    '--password={{db-pw}}'`, `-f '{{@values.yaml}}'`. Unquoted, PowerShell reads `{...}` as a script block and passes
    `{{db-pw}}` on as `{db-pw}`; `run` then finds no token and shows the quoted form. cmd needs no quotes." In the
    existing process-substitution bullet, `tswap run helm upgrade --install app ./chart -f {{@values.yaml}}, which works
    in cmd and PowerShell` becomes `` `tswap run helm upgrade --install app ./chart -f {{@values.yaml}}` (in PowerShell
    `-f '{{@values.yaml}}'`), which works in cmd and PowerShell ``.
  - `docs/examples.md` line 144: "This works in bash, cmd and PowerShell." becomes "This works in bash, cmd and
    PowerShell (in PowerShell quote the token: `-f '{{@values.yaml}}'`)."
  - `docs/agent-integration.md`, after the agent-role table, a new paragraph: "**PowerShell.** An agent whose shell is
    PowerShell quotes every argument that holds a token (`'{{name}}'`, `'{{@file}}'`): unquoted, PowerShell drops a pair
    of braces and `run` finds no token."
  - `TswapCore/Prompt.cs`, the `run` bullet (line 36) gets at its end: `; in PowerShell quote each argument holding a
    token (`'{{name}}'`, `'{{@file}}'`), or PowerShell drops a pair of braces`. Rule 3's last line
    `   (the script reads it as $1)` becomes `   (the script reads it as $1; on Windows: `%CMD% run powershell -File
    .\deploy.ps1 '{{secret-name}}'`, read as $args[0])` (keep it one line, or wrap it at the same indent, as you
    prefer). The prompt hash changes: say so in the commit; no test pins its value.

### Task 2: Windows wording (#348.3, #294 leftover)

- **The way out of an inline-code refusal.** In `Validation`, `WayOut` stays the exact Unix sentence and gets a sibling:
  - `public static string WayOutFor(bool windows)`: `false` returns today's sentence, byte for byte: `"Put the commands in a
    script file and run that instead, e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1)."`; `true`
    returns `"Put the commands in a script file and run that instead, e.g. 'run powershell -File .\\script.ps1 {{secret}}'
    (the script reads the value as $args[0]; in PowerShell quote the token: '{{secret}}')."` (C# escaping shown; the text
    has one backslash).
  - Ruling: **`GetBlockedInvocation` keeps building its reasons with the Unix sentence**; `RunCommand` swaps the sentence
    when `ctx.Os == OSPlatform.Windows`: `blocked.Reason.Replace(Validation.WayOutFor(false), Validation.WayOutFor(true))`,
    in one helper `RunCommand.Reason(BlockedInvocation blocked, bool windows)` used by `ThrowIfBlocked`. Why: the sentence
    is appended in ten places (`InlineReason` and nine direct uses, also inside `find -exec` and wrapper prefixes), always
    as the whole sentence; threading a flag through `CheckWrapper`, `CheckInterpreter`, `CheckSsh` and the others would
    change every signature for wording, and `GetBlockedInvocation` has 63 test assertions on `.Reason`. The cost: the swap
    depends on the sentence being appended whole, which a test pins (below). Comment the helper with that.
  - Ruling: **a `.ps1` run with `powershell -File`, not a `.cmd` (controller default; owner may change).** The issue
    suggests `.ps1` or `.cmd` (`%1`). A `.cmd` is run by `cmd.exe`, which parses its arguments again: a secret with `&`,
    `|`, `^`, `%` or `"` can break the line or run a command (the "BatBadBut" class of bugs), so tswap shouldn't point an
    agent at it. `powershell` (Windows PowerShell 5.1) is on every Windows, unlike `pwsh`. `powershell -File` is allowed
    by `GetBlockedInvocation` (only `IsPowerShellInline` options refuse), which a test pins.
- **The "sudo ... get" lines.** New in `RunCommand`:
  - `internal static string ViewSecretLine(bool windows)`: `false`: `"Use 'sudo ... get <name>' to view a secret."` (today's);
    `true`: `"Use '... get <name>' from an elevated command prompt to view a secret."`
  - `internal static string RetrieveSecretLine(bool windows)`: `false`: `"Use 'sudo ... get <name>' to retrieve a secret
    value."` (today's, line 93); `true`: `"Use '... get <name>' from an elevated command prompt to retrieve a secret value."`
  - Used, with `windows = ctx.Os == OSPlatform.Windows`, by `ThrowIfBlocked` (line 444; it becomes an instance-free
    helper taking `windows`), the pipe refusal (line 93) and the after-substitution refusal (line 239). "elevated command
    prompt" is `ElevatedCommand.WindowsNote`'s wording and `RequireSudo`'s.
  - The `FileTokenWayOut` and `{{@file}}` texts name no Unix tool; unchanged.
- **`init --yubikey`.** `InitCommand.ExecuteKeyring` line 330 becomes `$"slot that opens the vault alone: {ctx.Prefix}
  slot add --yubikey (with sudo, or from an elevated prompt on Windows)\n"` and line 383 `$"  {ctx.Prefix} slot add
  --yubikey (with sudo, or from an elevated prompt on Windows)"`: T31's wording for `--fido2`, on every OS. Ruling:
  **the same neutral wording, not `ElevatedCommand.Line`**, so the two init paths read alike, as T31 decided for FIDO2.
  Lines 184 (classic vault) and 507 (the TPM/Secure Enclave guide naming another machine's `sudo ... slot approve`) are
  out of scope (below).
- **Sanctioned test change.** `RunEnvTests`' refusal table row for `env` (`{ "'env' would expose secret values. ... not
  display them.\nUse 'sudo ... get <name>' to view a secret.", ["--env", "X={{s}}", "--", "env"] }`): its FleetMachine's
  `Os` is the current OS, so on Windows CI the trailer now differs. Its expected text becomes the same first sentence +
  `"\n" + RunCommand.ViewSecretLine(OperatingSystem.IsWindows())`, identical on Linux and macOS. Say so in the commit
  message. No other existing assertion changes (checked: no other test pins `sudo ... get`, `script.sh {{secret}}` or
  `$1)`; `InlineCodeBlockTests.Refusal_NamesTheProgram_AndTheWayOut` checks only "script file").

### Task 3: UTF-8 console output on Windows (#348.2, #294.4)

- **Ruling: set the console's output code page to UTF-8, no ASCII fallback.** Why:
  - It is correct in both consoles: Windows Terminal and conhost both render UTF-8 output once the code page is 65001
    (conhost since Windows 10 1903 at least; ConPTY needs 1809 anyway). An ASCII fallback is only "correct" by giving up
    the glyphs, needs a "can't show it" test that tswap can't make (that depends on the console's font, not on anything
    tswap can query), and would touch hundreds of literals or need an output filter that must never touch a secret
    value printed by `get` or `apply`.
  - It is the only fix that also corrects what tswap's own redaction sees: `WindowsPty` decodes ConPTY's UTF-8 with
    `Console.OutputEncoding` (the gap in "Why").
  - The cost, owner-checked by hand: a symbol the classic console's font lacks (`❌`, `✓`, `⚠` may be among them in
    Consolas) shows as an empty box instead of `?`. If the owner finds that, the next step is replacing those few
    pictographs with words on every OS (owner question 1), not an encoding change.
- **Only console streams change; redirected output stays byte for byte as today.** A pipe or file reader on Windows
  (PowerShell 5's `(& tswap prompt)` in the install script, `tswap names > f`) decodes with its own idea of the code page,
  so changing redirected bytes could turn today's `?` into mojibake (`ΓÇö` for `—`). Rule:
  - Not Windows: nothing (Linux and macOS write UTF-8 already).
  - Windows, and neither stdout nor stderr is a console: nothing.
  - Windows, the console's output code page already 65001: nothing.
  - Otherwise: remember `Console.OutputEncoding` (the original), set `Console.OutputEncoding = new
    UTF8Encoding(encoderShouldEmitUTF8Identifier: false)`, then, for each of stdout and stderr that is **not** a console,
    `Console.SetOut` / `Console.SetError` a `StreamWriter` over `Console.OpenStandardOutput()` /
    `Console.OpenStandardError()` in the original encoding, `AutoFlush = true`. (A redirected stream is written with
    `WriteFile`, so its bytes are the original encoding's, as today; the `SetOut` writer survives later encoding changes,
    per `Console.cs`.)
  - At exit (dispose): flush `Console.Out` and `Console.Error`, then `Console.OutputEncoding = original`, which puts the
    console's code page back. Ruling: **no signal handler for the restore.** A Ctrl+C or a killed tswap leaves the console
    at 65001 for the rest of that window (harmless for display; `chcp` shows it). `RunSignals` and `ControllingTerminal`
    already register signal handlers with their own cancel rules, and mixing a restore into them is more risk than the
    stale code page. Documented.
  - Children inherit the console, so while tswap runs a child (`run` with `FallbackPty`, which needs a redirected
    stream) sees code page 65001 too; one that writes in the console's code page then writes UTF-8, which RedactingPty's
    `FallbackPty` (it also decodes with `Console.OutputEncoding`) decodes correctly. Say it in the docs.
- **Where:** new `TswapCli/ConsoleOutputEncoding.cs`:
  - `internal enum StandardStream { Output, Error }`
  - `internal interface IConsoleEncodingHost { bool IsWindows { get; } bool IsConsole(StandardStream stream); Encoding
    OutputEncoding { get; set; } void UseWriter(StandardStream stream, Encoding encoding); void Flush(); }`
  - `internal static class ConsoleOutputEncoding { public static IDisposable Utf8OnWindows(IConsoleEncodingHost host);
    public static IConsoleEncodingHost System { get; } }`. The system host: `IsConsole` by `GetStdHandle` +
    `GetConsoleMode` (as `ControllingTerminal.WindowsConsole.IsConsole`), `OutputEncoding` is `Console.OutputEncoding`,
    `UseWriter` is the `SetOut`/`SetError` above, `Flush` flushes both. On non-Windows `IsWindows` is false and nothing
    else is called.
  - `TswapCli/Program.cs`: `using var consoleOutput = ConsoleOutputEncoding.Utf8OnWindows(ConsoleOutputEncoding.System);`
    after `ProcessHardening.HardenCli();`, before `return CliHost.Run(...)`. In Program.cs, not CliHost, so the in-process
    tests never change the test host's console (as `ProcessHardening`).
- **Docs.** `docs/install.md`, "Windows notes", a new bullet: "**Console output is UTF-8.** While tswap runs in a console
  window it sets the window's output code page to UTF-8 (65001), so its symbols and box lines show, and puts the old code
  page back when it exits; after a Ctrl+C or a killed tswap the window can stay at UTF-8 (`chcp` shows and sets it).
  Output redirected to a file or pipe is written in the window's code page, as before. A program `tswap run` starts
  inherits the UTF-8 code page. If a symbol shows as an empty box in the classic console window, its font lacks it;
  Windows Terminal shows it."

### Task 4: `run` on a Windows console: VT on for the child, window titles dropped (#349)

- **Ruling: tswap-side only, no RedactingPty change.** The library owns the pseudo console, its copy loop and its
  flags; tswap reaches its output only through `RedactionOptions.Matchers` and `StreamReplacement`s, and it owns its own
  console handle. Two changes:
  1. **VT processing on tswap's stdout while the child runs.** When tswap's stdout is a Windows console without
     `ENABLE_VIRTUAL_TERMINAL_PROCESSING` (0x0004), `run` sets it immediately before `runner.Run` and puts the old mode
     back immediately after it returns or throws. Then conhost interprets ConPTY's sequences instead of printing them. A
     console that has it already (Windows Terminal) is left alone (no `SetConsoleMode` call at all).
  2. **Window-title sequences are dropped** from the child's output on a Windows console: OSC 0, 1 and 2
     (`ESC ] 0|1|2 ; <text> BEL` or `... ESC \`), through a new `IStreamMatcher` whose matches are replaced by `""`. With
     VT on, ConPTY's OSC 0 would otherwise retitle the window to the child's path and outlive `run`. A secret inside a
     title is gone with it (the redactor merges overlapping matches under the longest one's label, here `""`).
- **Ruling: ConPTY's start-up screen clear and home (`ESC[2J`, `ESC[H`) and its mode switches (`?9001`, `?1004`, `?25`)
  pass through (controller default; owner may change).** ConPTY was made with flags 0, so it assumes an empty screen with
  the cursor at the top left and later positions its output with absolute cursor moves when a line isn't simply the next
  one; dropping the clear and home would misplace such output over the user's screen. With them passed through, conhost
  with VT on behaves as Windows Terminal does today: the window is cleared before the child's output. The real fix is in
  the library (start the pseudo console at the user's cursor, follow-up R2). The mode switches come in on/off pairs at
  start and teardown; tswap reads its own stdin as plain text, so focus and win32-input reports don't reach the child.
- **The seam.** New `TswapCli/WindowsVirtualTerminal.cs`:
  - `internal interface IConsoleOutputMode { uint Mode { get; } bool TrySetMode(uint mode); }`
  - `internal static class WindowsVirtualTerminal { public const uint EnableVirtualTerminalProcessing = 0x0004; public
    static IConsoleOutputMode? ForThisProcess(); public static IDisposable AroundChild(IConsoleOutputMode stdout); }`.
    `ForThisProcess`: null unless Windows and `GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE))` succeeds; else the real
    mode over that handle (`SetConsoleMode`). `AroundChild`: if `Mode` has the flag, a dispose that does nothing; else
    `TrySetMode(Mode | flag)` (a failure: a dispose that does nothing) and a dispose that calls `TrySetMode(original)`.
  - `CommandContext`: `internal Func<IConsoleOutputMode?> StdoutConsoleMode { get; init; } =
    WindowsVirtualTerminal.ForThisProcess;` (next to `PtyRunner`). A test host's stdout is never a console, so existing
    tests see null.
- **In `RunCommand.Execute`:** after the options are built and before `ctx.PtyRunner()`: `var stdoutMode =
  ctx.StdoutConsoleMode();`; when non-null, the matcher list is `[fingerprint matcher, new TerminalTitleMatcher()]`
  instead of `[fingerprint matcher]`, and both `runner.Run(...)` calls (plain and inside `files.RunChild`) run inside
  `using (stdoutMode is null ? null : WindowsVirtualTerminal.AroundChild(stdoutMode))`, so the mode is back before the
  second `RunCoverage.Warn`. Nothing changes when the seam is null (Linux, macOS, redirected stdout).
- **The matcher.** New `TswapCli/TerminalTitleMatcher.cs`, `internal sealed class TerminalTitleMatcher : IStreamMatcher`:
  - `public const int MaxTitleLength = 4096;` `MaxMatchLength => MaxTitleLength + 6` (`ESC ] n ;` and `ESC \`).
  - `FindMatches`: every `ESC ] <0|1|2> ; <text> <BEL | ESC \>` lying wholly in the window, `<text>` at most
    `MaxTitleLength` characters with no `BEL` or `ESC`; replacement `""`. Any other OSC (`ESC ] 8 ;` hyperlinks,
    `ESC ] 4 ;` colours) and every CSI sequence is not a match.
  - `PendingFrom` (overridden, never the default hold of `MaxMatchLength - 1`): the index of a trailing incomplete title
    sequence (a final `ESC`, or `ESC ]`, `ESC ] n`, `ESC ] n ;` + text with no terminator yet, still no longer than
    `MaxMatchLength`), else `window.Length`. Why this matters: `WindowsPty` ignores `ReleaseWhenAwaitingInput`, so a
    default hold would keep the last 4 KB of a prompt (`[Y,N]?`) from the user until the child wrote more.
  - Stateless and thread-safe, as `IStreamMatcher` requires. An unterminated or overlong title passes through as text.
- **Docs.** `docs/install.md`, "Windows notes", two new bullets:
  - "**`tswap run` in a console window.** The command runs in a pseudo console (ConPTY). tswap lets the window interpret
    its escape sequences while the command runs and drops the title changes, so the window keeps its title. The pseudo
    console clears the window before the command's output, as in Windows Terminal."
  - "**A Windows machine as an SSH host.** OpenSSH for Windows runs each `ssh -t` session in its own pseudo console, which
    sets the title of the terminal window you connect from (for example to `C:\WINDOWS\system32\conhost.exe`) and leaves
    it after the session, as after `slot enrol --via <windows-host>`'s approve and merge steps. That is OpenSSH's
    behaviour, not tswap's; the title comes back the next time your shell or terminal sets one."

## Task 1: the braces hint (#348.1)

Tests in a new `TswapTests/RunPowerShellBracesTests.cs` (`FleetMachine`; `ErrorLine` as in `RunEnvTests`; the run helper
as `RunEnvTests.Run`, with `PtyRunner = () => _pty`, a `RecordingPty`):
- `NoToken_BracedName_HintsTheQuotedForm`: on a machine with **no `init`**, `run tool {db-pw}`: exit 1, stdout `""`,
  stderr == `ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.BracesHint("{db-pw}"))`, and that text, spelled out
  once in the test, is ``No {{tokens}} or {{@file}} tokens found in command\nThe argument {db-pw} looks like the token
  {{db-pw}} with one pair of braces removed, which PowerShell does to an unquoted token. Quote it: '{{db-pw}}'.``
  Without `init`, any read of the vault would fail with another text, which proves nothing was opened.
- `NoToken_BracedPrevious_And_FileToken`: `run helm upgrade app ./chart -f {@values.yaml} --set {db-pw:previous}`: the
  two hint lines, in argument order, naming `{{@values.yaml}}` and `{{db-pw:previous}}`.
- `NoToken_SameBracedArgumentTwice_OneLine`: `run tool {a} {a}`: one hint line.
- `NoToken_NothingBraced_PlainErrorUnchanged` (Theory: `plain`, `--x={a}`, `{a}{b}`, `{}`, `{a b}`, `{a.b}`, `HEAD@{1}`,
  a 65-character name in braces): stderr == `ErrorLine(RunCommand.NoTokensText)` exactly.
- `Token_PlusBracedArgument_WarnsAndPassesItOn`: `init` (record vault, as `RunEnvTests.RecordVault`), `ingest db-pw`,
  `run tool {{db-pw}} {other}`: exit 0; the child's argv (`_pty.Argv`) is `["tool", <value>, "{other}"]`; stderr contains
  `RunCommand.BracesWarning("{other}")` exactly once; the stored value appears in neither stdout nor stderr.
- `Token_PlusBracedArgument_RefusedCommand_NoWarning`: `run echo {{db-pw}} {other}`: the blocklist refusal, and stderr
  has no `looks like the token`.
- `Prompt_TellsPowerShellToQuote`: `Prompt` output (as `PromptTests` gets it) contains `in PowerShell quote each argument
  holding a token` and `.\deploy.ps1 '{{secret-name}}'`.
- Break-it-once: drop the hint lines from the no-token refusal: `NoToken_BracedName_HintsTheQuotedForm` fails (plain
  error). Drop the warning: `Token_PlusBracedArgument_WarnsAndPassesItOn` fails. Make the shape check a `Contains`
  instead of whole-argument: `NoToken_NothingBraced_PlainErrorUnchanged` fails.
- Existing tests pass unchanged, among them `CommandTests.Run_NoTokensFails` (`Contains("No {{tokens}}")`).

Files: `TswapCli/Commands/RunCommand.cs`, `TswapCore/Prompt.cs` (the two lines), `docs/install.md`,
`docs/examples.md` (one sentence), `docs/agent-integration.md` (one paragraph),
`TswapTests/RunPowerShellBracesTests.cs` (new).

## Task 2: Windows wording (#348.3, #294 leftover)

Tests in a new `TswapTests/RunWindowsWordingTests.cs` (`FleetMachine` with `Os = OSPlatform.Windows`, `Linux` or `OSX`;
the refusals come before the unlock, so no `init` except where said):
- `InlineCode_OnWindows_PowerShellScriptAndElevatedPrompt`: Os Windows, `run cmd /c echo {{name}}`: stderr ==
  `ErrorLine("'cmd /c' runs inline code, which can transform and print secrets past redaction. " +
  Validation.WayOutFor(true) + "\n" + RunCommand.ViewSecretLine(true))`, and stderr contains none of `sudo`,
  `./script.sh`, `$1`.
- `InlineCode_OnUnix_Unchanged` (Theory: Linux, OSX): the same command: stderr == the full old text spelled out as a
  literal in the test (`'cmd /c' runs inline code, ... e.g. 'run ./script.sh {{secret}}' (the script reads the value as
  $1).\nUse 'sudo ... get <name>' to view a secret.`), so the Unix wording is pinned byte for byte, not through the helpers.
- `Wrapped_OnWindows_TheSentenceIsSwappedInside`: Os Windows, `run find . -exec sh -c x {{name}} ;` (a reason with the
  `'find -exec' runs ...` prefix): stderr contains `WayOutFor(true)` and not `WayOutFor(false)`.
- `EveryWayOutReason_EndsWithTheWholeSentence` (Theory): one refused argv per place in `Validation.cs` at 51b0b37 that
  appends `WayOut`: `InlineReason` (line 861; e.g. `sh -c x`, `cmd /c x`, `pwsh -Command x`), and the nine direct uses at
  lines 464 (`su`), 468 (`xargs x`), 618 (`sudo -s`), 629 (`docker run --entrypoint python img`), 636
  (`machinectl shell`), 686 (a wrapper with no command, from `ShellWhenNoCommand`), 812 (`python3 -`), 839
  (`expect -f -`) and 857 (`python3` with no script); derive each argv from the code at that line. For each,
  `GetBlockedInvocation(argv)!.Reason` ends with `Validation.WayOutFor(false)`. This pins what the swap relies on.
- `Blocklisted_And_Pipe_OnWindows_ElevatedPrompt`: Os Windows: `run echo {{name}}` ends with `ViewSecretLine(true)`;
  `run tool {{name}} '|' more` ends with `RetrieveSecretLine(true)`; on Linux both end with today's sudo lines.
- `AfterSubstitution_OnWindows_ElevatedPrompt`: Os Windows, `init`, a secret `cmd` whose value is `echo` (`add` with the
  sudo bypass), `run {{cmd}} x`: the after-substitution refusal ends with `ViewSecretLine(true)` and stderr has no `sudo`.
- `WindowsWayOut_IsRunnable`: `Validation.GetBlockedInvocation(["powershell", "-File", @".\script.ps1", "{{secret}}"])`
  is null.
- In `TswapTests/InitKeyringOneKeyTests.cs`, new test `InitYubiKey_HeaderAndClosingLine_SaySudoOrAnElevatedPrompt`:
  `init --yubikey`: stdout contains `slot that opens the vault alone: tswap slot add --yubikey (with sudo, or from an
  elevated prompt on Windows)` and `  tswap slot add --yubikey (with sudo, or from an elevated prompt on Windows)`, and
  not `alone: sudo tswap` (as `InitFido2_Header_SaysSudoOrAnElevatedPrompt`).
- Break-it-once: make `Reason`'s swap a no-op: `InlineCode_OnWindows_PowerShellScriptAndElevatedPrompt` fails. Make
  `ViewSecretLine` ignore `windows`: the same test and `Blocklisted_And_Pipe_OnWindows_ElevatedPrompt` fail. Restore
  line 330's `sudo`: the init test fails.
- The sanctioned `RunEnvTests` row change (above).

Files: `TswapCore/Validation.cs` (`WayOutFor`; `WayOut` becomes `WayOutFor(false)`'s text), `TswapCli/Commands/RunCommand.cs`,
`TswapCli/Commands/InitCommand.cs` (lines 330 and 383 only), `TswapTests/RunWindowsWordingTests.cs` (new),
`TswapTests/InitKeyringOneKeyTests.cs` (one test), `TswapTests/RunEnvTests.cs` (the one sanctioned row).

## Task 3: UTF-8 console output on Windows (#348.2, #294.4)

Unit tests, all OSes, in a new `TswapTests/ConsoleOutputEncodingTests.cs`, over a fake `IConsoleEncodingHost` that
records every `OutputEncoding` set and `UseWriter` call (the "original" a stand-in such as `Encoding.Latin1`):
- `Windows_BothConsoles_Utf8WhileRunning_OriginalAfter`: after `Utf8OnWindows`, `OutputEncoding.CodePage == 65001` and
  its `GetPreamble()` is empty; no `UseWriter`; after dispose, `OutputEncoding` is the original, and `Flush` ran before
  that set.
- `Windows_StdoutRedirected_KeepsTheOriginalForIt`: `UseWriter(Output, original)` once, no `UseWriter(Error, ...)`; the
  mirror test for stderr redirected.
- `Windows_NeitherIsAConsole_NothingSet` and `Windows_AlreadyUtf8_NothingSet`: no set, no `UseWriter`, and dispose sets
  nothing.
- `NotWindows_NothingTouched`: the fake throws on any member but `IsWindows`; no exception.
- Break-it-once: remove the `UseWriter` loop: `Windows_StdoutRedirected_KeepsTheOriginalForIt` fails. Remove the restore:
  `Windows_BothConsoles_Utf8WhileRunning_OriginalAfter` fails.

Windows-only (CI), in `TswapTests/EndToEndTests.cs` at the end of its ConPTY section, each returning early as
`Run_CompoundCommand_RedactedOutput_WindowsConPty` does off Windows 10 1809+:
- `Glyphs_ReachTheConsole_WindowsConPty`: `RunTswapInConPty` of `run tool {x}` (no token; nothing is opened): the capture
  contains `❌` and `Error: No {{tokens}}`, and not `? Error`. Then `init --yubikey --no-recovery --no-password` in the
  outer ConPTY: the capture contains `✓ INITIALIZATION COMPLETE` and `╔═`. (Before the change tswap writes the OEM code
  page's best fit, which the outer pseudo console renders as `?` and `V`.) Assert with the `EscapeVt` dump as the existing
  test does, short fragments only (ConPTY may wrap long lines).
- `NonAsciiValue_Redacted_WindowsConPty`: `ingest umlaut` with stdin `pässwört-conpty` (`RunTswapWithStdin`: .NET's
  `Process` writes stdin in the console's input code page and tswap reads it in the same one; `ä` and `ö` exist in
  code pages 437, 850 and 1252, so the value arrives intact; check that once with `-v`'s `Found tokens` line or a
  `names` listing if in doubt), then `run pwsh -NoProfile -File print.ps1 {{umlaut}}` (the existing test's script shape):
  the capture contains `[REDACTED: umlaut]` and not `pässwört`. (Before the change `WindowsPty` decodes ConPTY's UTF-8 in
  the OEM code page, the value doesn't match and is not redacted.)
- Break-it-once (on CI, by the controller): remove the `using var consoleOutput` line in Program.cs; both tests fail.

Files: `TswapCli/ConsoleOutputEncoding.cs` (new), `TswapCli/Program.cs`, `docs/install.md` (one bullet),
`TswapTests/ConsoleOutputEncodingTests.cs` (new), `TswapTests/EndToEndTests.cs` (two tests).

## Task 4: `run` on a Windows console (#349)

Unit tests, all OSes:
- New `TswapTests/TerminalTitleMatcherTests.cs`, through the real `StreamRedactor([], [new TerminalTitleMatcher()])` (as
  `FingerprintStreamMatcherTests` drives its matcher):
  - `OwnersCapture_TitleGone_RestByteForByte`: input `"\x1b[?9001h\x1b[?1004h\x1b[?25l\x1b[2J\x1b[m\x1b[H[REDACTED: name]
    [Y,N]?\x1b]0;C:\\WINDOWS\\system32\\choice.exe\x07\x1b[?25h\r\n\x1b[?9001l\x1b[?1004l"` gives the same string without
    `"\x1b]0;C:\\WINDOWS\\system32\\choice.exe\x07"`, for chunk sizes 1, 3, 7 and whole.
  - `BothTerminators_AndOsc1And2`: `ESC ] 0 ; t BEL`, `ESC ] 2 ; t ESC \`, `ESC ] 1 ; t BEL` are removed;
    `ESC ] 8 ; ; https://x ESC \` and `ESC ] 4 ; 1 ; rgb:ff/00/00 BEL` stay.
  - `UnterminatedOrOverlong_PassesThrough`: a title of `MaxTitleLength + 1` characters, and one never terminated before
    `Flush`, come out unchanged.
  - `Prompt_IsNotHeld`: after `ProcessChunk("Overwrite? [Y,N]?")` the whole text is emitted (nothing held);
    `ProcessChunk("abc\x1b]0;par")` emits `"abc"` and holds the rest; `ProcessChunk("abc\x1b[2J")` emits it all.
  - `TitleHoldingASecret_NeitherSurvives`: with a `StreamReplacement("s3cret-title", "[REDACTED: t]")` too, input
    `"a\x1b]0;s3cret-title\x07b"` gives `"ab"`.
- New `TswapTests/RunWindowsConsoleTests.cs` (the `RunEnvTests` setup: record vault, `ingest db-pw`, `RecordingPty`, and
  `StdoutConsoleMode = () => fake`, a fake `IConsoleOutputMode` recording every `TrySetMode`):
  - `WindowsConsole_VtOnWhileTheChildRuns_RestoredAfter`: fake mode `0x3`; `_pty.During` records the fake's mode;
    `run tool {{db-pw}}`: the recorded mode is `0x7`, the sets are exactly `[0x7, 0x3]`, and the final mode is `0x3`.
  - `WindowsConsole_VtAlreadyOn_NoModeChange`: fake mode `0x7`: no sets.
  - `WindowsConsole_ChildThrows_ModeRestored`: a runner that throws after starting (as `RunVaultRedactionTests.FailingPty`;
    a local copy): exit non-zero, sets `[0x7, 0x3]`.
  - `WindowsConsole_TitleDroppedFromChildOutput`: the child writes the owner's capture with the value in place of
    `[REDACTED: name]`: `_pty.Output` is the capture with `[REDACTED: db-pw]` and without the title sequence; no value in
    stdout, stderr or `_pty.Output`.
  - `NoConsole_TitleUntouched_NoMatcherAdded`: seam returning null: `_pty.Options!.Matchers` has one entry (the fingerprint
    matcher) and `_pty.Output` keeps the title sequence.
  - `Refused_ModeNeverTouched`: `run echo {{db-pw}}`: no sets.
- Windows-only: in `RunWindowsConsoleTests`, `ForThisProcess_FollowsStdout`: on Windows,
  `(WindowsVirtualTerminal.ForThisProcess() is null) == Console.IsOutputRedirected`; elsewhere it is null.
- Windows-only (CI), in `EndToEndTests.cs` after Task 3's: `Run_NoChildTitle_WindowsConPty`: `RunTswapInConPty` of
  `run pwsh -NoProfile -File print3.ps1 {{my-secret}}` (the existing script): the capture contains the redaction marker
  and does not match `\]0;[^\x07\x1b\r\n]*pwsh` (case-insensitive). Without the matcher the inner pseudo console's title
  (pwsh's path) reaches the capture, as text (VT off) or re-emitted by the outer one (VT on). If on CI the outer pseudo
  console turns out to emit a title naming pwsh by itself, stop and report the dump rather than loosen the pattern.
- Break-it-once: remove the `using (... AroundChild ...)`: `WindowsConsole_VtOnWhileTheChildRuns_RestoredAfter` fails.
  Make `PendingFrom` the interface default: `Prompt_IsNotHeld` fails. Drop `'2'` from the accepted OSC numbers:
  `BothTerminators_AndOsc1And2` fails. Don't add the matcher: `WindowsConsole_TitleDroppedFromChildOutput` fails (and, on
  CI, `Run_NoChildTitle_WindowsConPty`).

Files: `TswapCli/WindowsVirtualTerminal.cs` (new), `TswapCli/TerminalTitleMatcher.cs` (new), `TswapCli/CommandContext.cs`
(one property), `TswapCli/Commands/RunCommand.cs`, `docs/install.md` (two bullets),
`TswapTests/TerminalTitleMatcherTests.cs` (new), `TswapTests/RunWindowsConsoleTests.cs` (new),
`TswapTests/EndToEndTests.cs` (one test).

## Report

Write `../t35-report.md` (next to the worktree): per task the commit sha, the tests added, each break-it-once (line
reverted, test that failed), the Windows-only tests that you could not run here with the line the controller should
revert for each on CI, the sanctioned `RunEnvTests` change, the prompt-hash change, and the full `./runtests.sh`
summary lines. List anything in this brief that turned out wrong in the code.

## Owner checks (by hand, Windows; only the owner can make these)

In the classic console window (conhost) with Windows PowerShell 5.1, then in Windows Terminal with PowerShell 7:
1. `tswap run cmd /c echo {{name}}` (unquoted): the hint names `'{{name}}'`; the error's `❌` shows as itself or as a box,
   never `?`. Note which.
2. `tswap run cmd /c echo '{{name}}'`: the refusal suggests `powershell -File .\script.ps1` and an elevated prompt, no
   `sudo` or `$1`.
3. `tswap run choice /m '{{name}}' /t 1 /d y`: no `←[` text, the prompt shows while it waits, and after it the window
   title is the shell's own. Note whether the window was cleared first (expected with this brief; owner question 2).
4. `chcp`, then `tswap names`, then `chcp` again: the same code page. `tswap init --yubikey` (on a spare config folder):
   banners and `✓` readable.
5. `tswap prompt > a.md` and `[IO.File]::WriteAllLines("b.md", (tswap prompt))`: the same bytes as with 0.3.1-pre-f7c61b0
   (redirected output unchanged).
6. What PowerShell passes for an unquoted `{{@values.yaml}}` and for `'--password={{db-pw}}'` vs `--password={{db-pw}}`
   (this brief assumes `{@values.yaml}`; a parse error from PowerShell is fine too).
7. A `run` of a child with a non-ASCII secret value (`pässwört`): redacted.

## RedactingPty follow-ups (not in this brief; for the library)

- R1: `WindowsPty.Run` decodes and re-encodes ConPTY's output with `Console.OutputEncoding` (WindowsPty.cs lines 317-331),
  but ConPTY always writes UTF-8: decode it as UTF-8, and write to stdout in the console's encoding (or UTF-16 through
  `WriteConsoleW`), so redaction doesn't depend on the host process setting the code page (Task 3 does it from outside).
  `FallbackPty` decodes child pipes with `Console.OutputEncoding` too; that one is right for children that follow the
  console's code page.
- R2: `CreatePseudoConsole(size, ..., 0, ...)` (line 189): `PSEUDOCONSOLE_INHERIT_CURSOR` (0x1), answering ConPTY's
  cursor-position request on the input pipe with the real cursor position, so the pseudo console starts at the user's
  cursor and no longer clears the screen and homes the cursor.
- R3: enable `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on a console stdout itself for the child's run, and offer an option to
  drop title sequences, so every user of the library gets what Task 4 gives tswap.
- R4 (note only): `WindowsPty` ignores `ReleaseWhenAwaitingInput`; any matcher with a long default hold delays prompts there.

## Out of scope

- An ASCII fallback for glyphs, or replacing `❌ ✓ ⚠ ✅ ✗` with words (owner question 1).
- Console *input* encoding (`Console.InputEncoding`, piping non-ASCII into `ingest` from PowerShell 5, whose
  `$OutputEncoding` is ASCII by default).
- `InitCommand` line 184 (classic-vault refusal, `sudo ... migrate`) and line 507 (the TPM/Secure Enclave guide naming
  `sudo tswap slot approve` on the enrolled machine, which may be Unix); other `sudo` wording on Windows outside `run` and
  `init --yubikey`.
- A hint for `--env X={a}` (PowerShell's braces in an `--env` value): `EnvToken`'s refusal stays as it is.
- Restoring the code page or the console mode on Ctrl+C or kill.
- Any RedactingPty change (R1-R4).
- OpenSSH for Windows' title (documented only).

## Owner questions

1. If the classic console shows boxes for `❌`, `✓` and `⚠` after this brief: replace those pictographs with words on every
   OS (for example `Error:` alone, `[ok]`, `Warning:`), or keep them for the terminals that show them?
2. With VT on, `tswap run` in the classic console clears the window before the child's output, as Windows Terminal already
   does. Is that acceptable until RedactingPty starts the pseudo console at the cursor (R2), or should tswap drop the clear
   and home now, accepting misplaced output for children that move the cursor?
3. `.cmd` scripts in the Windows advice: left out because `cmd.exe` re-parses a secret's `&`, `|`, `^`, `%` and `"`. Keep it
   PowerShell-only?


## Amendments after brief review round 1 (binding; they win over the text above)

Round 1 (MiMo, GLM-5.3): MiMo "no", GLM "yes". Both found that the design is sound and buildable, and both asked for A1
and A2. The rulings on shape-only hints, `.ps1` over `.cmd`, passing the clear through, and dropping titles stand.

**A1. Task 3: UTF-8 only when both stdout and stderr are consoles; the `SetOut`/`SetError` writers are dropped.** RedactingPty's
`FallbackPty` and `WindowsPty` write the child's output straight to `Console.OpenStandardOutput()` /
`OpenStandardError()` in `Console.OutputEncoding`, bypassing any `Console.SetOut` writer. So with one of the two streams
redirected (`tswap run tool > out.txt` from a console), the brief's rule would put tswap's own lines in the OEM code page
and the child's output in UTF-8 into the same file. The rule becomes:
- not Windows; or Windows and stdout **or** stderr is not a console; or the output code page is already 65001: nothing
  changes, and every byte stays as in 0.3.1;
- otherwise (both are consoles): remember `Console.OutputEncoding`, set it to `new UTF8Encoding(false)`, and on dispose
  flush both writers and set it back.
This is the case `WindowsPty` needs. The ConPTY path also needs stdin to be a console, which this rule doesn't ask for,
so the closing of #355 is unaffected. The mixed case keeps today's `?` glyphs. The cost: `tswap names > f` from a
console still shows a garbled `❌` on stderr when it fails; that is the price of never mixing encodings in one stream.
- `IConsoleEncodingHost` loses `UseWriter`. Its members are `IsWindows`, `IsConsole(StandardStream)`, `OutputEncoding`
  and `Flush()`.
- Tests: `Windows_StdoutRedirected_KeepsTheOriginalForIt` and its stderr mirror become
  `Windows_StdoutRedirected_NothingSet` and `Windows_StderrRedirected_NothingSet` (no set, and dispose sets nothing). The
  break-it-once for them: make the rule "either is a console", and both fail.
- The docs bullet: replace "Output redirected to a file or pipe is written in the window's code page, as before." with
  "When stdout or stderr is redirected to a file or pipe, nothing changes: tswap and the programs `tswap run` starts
  write in the window's code page, as before." Add: "A long-running `tswap agent serve` in a console window keeps it at
  UTF-8 until it exits."
- Owner check 5 gains: `tswap run <a child that prints non-ASCII> > f` gives the same bytes in `f` as
  0.3.1-pre-f7c61b0.

**A2. The braces texts echo `Validation.Printable(argument)`.** A `{@path}` argument can carry control characters
(ESC, CR, BEL), and the code's rule for echoed text is `Validation.Printable` (Validation.cs line 52: everything outside
printable ASCII becomes `?`). `BracesHint` and `BracesWarning` use `var shown = Validation.Printable(argument)` for both
places they quote it (`{shown}` and `{{{shown}}}`). The name shape is ASCII already, so its texts don't change. New Theory
case in `NoToken_BracedName_HintsTheQuotedForm`'s file, `NoToken_ControlCharactersInAFileToken_ShownAsQuestionMarks`:
`run tool "{@x\u001b[31my}"` gives a stderr that contains `{@x?[31my}` and `'{{@x?[31my}}'`, and contains no
`\u001b`. Break-it-once: echo the raw argument, and this test fails. Remove the sentence "Echoing the argument is safe"
and replace it with this ruling.

**A3. Task 4's E2E: what it can and can't show.** MiMo asked for a check that the capture holds no literal `?9001h` or
`[2J`. That can't be asserted. The *outer* pseudo console of `RunTswapInConPty` emits its own `ESC[?9001h`, `ESC[2J` and
`ESC[H` at start, so those fragments are in every capture. Whether a VT-off ESC shows in the outer capture as a real ESC
or as a `←` glyph can't be known from here. So:
- `Run_NoChildTitle_WindowsConPty` also asserts that the capture has no `\u2190[` (the arrow form the owner saw).
- In the report, give the `EscapeVt` dump of this test from the CI run with and without the `using (... AroundChild ...)`
  line (the controller's break-it-once for it on CI). If the two dumps don't differ, say so. Then the unit test
  `WindowsConsole_VtOnWhileTheChildRuns_RestoredAfter` and owner check 3 are the evidence for VT, and the E2E proves the
  title drop only. Never loosen an assertion to make it pass.

**A4. #355.** Add `#355` to the Task 3 commit's subject and body ("Fixes #355 on the ConPTY path"). Name
`NonAsciiValue_Redacted_WindowsConPty` as the test that closes it. Its CI break-it-once (Program.cs's `using var
consoleOutput` removed, the test fails) is the evidence the controller records on #355. Wording in "Why": Task 3 closes the
gap on the ConPTY path, the only path where it exists. `FallbackPty` decodes and re-encodes in the console's code page,
which is consistent for children that follow that code page. RedactingPty#12 (R1) is the library side.

**A5. The .NET citation:** `EncodingHelper.GetSupportedConsoleEncoding` is in
`src/libraries/Common/src/System/Text/EncodingHelper.Windows.cs` of dotnet/runtime, called from
`src/libraries/System.Console/src/System/ConsolePal.Windows.cs` (`OutputEncoding`).

**A6. `docs/agent-integration.md`:** the PowerShell paragraph goes immediately after the agent-role table, before the
paragraph that starts "`init` needs no sudo either".

**A7. `EveryWayOutReason_EndsWithTheWholeSentence`, line 686:** use `["nsenter"]` (from `ShellWhenNoCommand`; it holds
`nsenter`, `runuser`, `doas`, `chroot`, `unshare`).

**A8. `Glyphs_ReachTheConsole_WindowsConPty` makes two captures**, each its own `RunTswapInConPty` call with its own
sentinel, which is ASCII and printed both before and after the change: the refused `run` waits for `No {{tokens}}`; the
`init` waits for `INITIALIZATION COMPLETE`. The assertions about `❌` apply to the first capture, and those about `✓` and
`╔═` to the second.

**A9. Owner question 3 gains:** "Windows PowerShell 5.1's `-File` builds the script's arguments from the raw command
line, so a secret containing `"` can reach the script altered. That is wrong data, not a command run; `cmd` is worse."

**A10. The braces wording** doesn't state PowerShell's mechanism as fact on every shell. `BracesHint`:
`$"The argument {shown} looks like the token {{{shown}}} with one pair of braces removed, as PowerShell does to an
unquoted token. Quote it: '{{{shown}}}'."` `BracesWarning`: the same change (", as PowerShell does to an unquoted token;
it is passed on as it is."). The exact text in `NoToken_BracedName_HintsTheQuotedForm` follows ("... with one pair of
braces removed, as PowerShell does to an unquoted token. Quote it: '{{db-pw}}'.").

**A11. Task 4's console-window bullet gains:** "After a Ctrl+C or a killed tswap the window may keep interpreting escape
sequences; that is harmless." It is the same ruling as for the code page: no signal handler.

**A12. `ControllingTerminal.WindowsConsole.IsConsole` is private.** `ConsoleOutputEncoding` and `WindowsVirtualTerminal`
declare their own `GetStdHandle`/`GetConsoleMode` (`SetConsoleMode` for the second) `LibraryImport`s. Leave
`ControllingTerminal` unchanged.

**A13. The umlaut test reuses `print3.ps1` as it is**, written the way `Run_CompoundCommand_RedactedOutput_WindowsConPty`
writes it, with its trailing `Start-Sleep`. That sleep is load-bearing: a child that exits at once can render as a blank
session. It is existing child behaviour, not a test wait.

**A14. Task 2's ruling:** replace "and `GetBlockedInvocation` has 63 test assertions on `.Reason`" with "and threading a
flag would change every helper's signature for wording only". There is one `.Reason` assertion on it
(`InlineCodeBlockTests.cs` line 255).

**A15. `FleetMachine.Context` sets `StdoutConsoleMode = () => null`**, so no in-process test ever reaches a real console,
also in a suite run from a Windows console. Today's `RunVaultRedactionTests` line 60 (`Assert.Single(_pty.Options!.Matchers)`)
relies on this. The Task 4 tests set the seam themselves. `TswapTests/FleetMachine.cs` joins Task 4's files.

**A16. The umlaut test checks the stored value**, not only the name. After `ingest`, `RunTswap("get", "umlaut")` (the E2E
environment sets `TSWAP_TEST_SUDO_BYPASS=1`) prints `pässwört-conpty`. If that fails, the ingest leg is what to fix, not
the redaction. Also, in the report, the CI revert of A4 failing is the proof that the test exercises the non-ASCII path.

**A17. Where the braces warning goes:** immediately after the root check for `{{@file}}` (line 100), before the
`if (ctx.Verbose)` block, so it comes after every refusal made before the vault opens and before any verbose line.
