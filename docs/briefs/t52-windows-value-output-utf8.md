# Brief T52: on Windows, `get` and `apply` write UTF-8 to a redirected stdout (#403)

Milestone 0.3.3. Base: `origin/main` at 3e22bcb (this brief's branch, `brief/t52`, starts there). Read AGENTS.md and
CLAUDE.md first, then `TswapCli/ConsoleOutputEncoding.cs` (all of it), `TswapCli/Program.cs`, `TswapCli/SystemConsole.cs`,
`TswapCli/ICliCommand.cs`, `TswapCli/CommandRegistry.cs` (`Dispatch`), `TswapCli/CliEnvironment.cs` (`SplitGlobalFlags`),
`TswapCli/Commands/GetCommand.cs`, `TswapCli/Commands/ApplyCommand.cs`, `docs/briefs/t35-windows-output.md` (the "Ruling"
under Task 3 and amendment A1), `TswapTests/ConsoleOutputEncodingTests.cs`, `TswapTests/SystemConsoleTests.cs`,
`TswapTests/EvilValues.cs`, and in `TswapTests/EndToEndTests.cs`: `MakePsi`, `RunTswapWithStdinBytes`,
`NonAsciiValue_Redacted_WindowsConPty` and `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits (`git commit -F msg -- <paths>`), no
push, merge or rebase; stop and report when the brief can't be built as written. **No existing test's assertions
change.** Task 3 changes how one existing test reads `get`'s stdout (named there; its expected value stays); any other
existing test that would need a different assertion: stop and list it.

## What is wrong (evidence)

On Windows, `sudo tswap get <name> | …` or `> file` writes the value in the console's code page (437 on the GitHub
runner): `é` becomes a 437 byte (a UTF-8 reader sees `�`), and what 437 lacks (zero-width space, U+202E, Cyrillic `а`,
emoji, U+2028) becomes `?`. T48's Windows CI (run 45053659672): an extra `get` check read as UTF-8 failed for 15 of 16
non-ASCII corpus values (`expected [café-secret-value], got [caf�-secret-value]`). The stored value is right: the same
values arrive exactly through `run` (`Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows`, EndToEndTests.cs:1884).

Why, in the code:
- `GetCommand.cs:26` writes `ctx.Console.Out.WriteLine(view.ResolveToken(name))`; `ApplyCommand.cs:31` writes
  `ctx.Console.Out.Write(applied)`. `SystemConsole.Out` is `Console.Out` (`SystemConsole.cs:16`).
- `ConsoleOutputEncoding.Utf8OnWindows` (`ConsoleOutputEncoding.cs:45-48`) sets UTF-8 only when stdout **and** stderr are
  consoles (T35 A1). With stdout redirected, `Console.Out` keeps .NET's default console encoding, the OEM code page.
- T35 A1 keeps it that way on purpose: RedactingPty writes a `run` child's output to `Console.OpenStandardOutput()` in
  `Console.OutputEncoding`, so changing the encoding for a redirected stream would put two encodings in one file. That
  reasoning is about `run`; `get` and `apply` print only tswap's own text.

Owner decision (2026-11-23, #403): on Windows every command that prints a secret value or a filled file writes UTF-8
when its stdout is redirected (pipe or file), whatever the console code page; the docs tell PowerShell users how to read
it. Linux and macOS are unchanged.

Which commands print a secret value or a filled file (checked: every `ResolveToken`/`ApplySecrets` caller in
`TswapCli`): `get` (GetCommand.cs:26) and `apply` (ApplyCommand.cs:30-31). `run` substitutes into a child (out of scope,
below); `field adopt` (FieldCommand.cs:225) moves a value into a field and prints only a confirmation; `field show`
prints visible fields, never a secret. No other command prints a value.

## The design (decided)

- **Rule.** Windows, the command is `get` or `apply`, and stdout is not a console (`IConsoleEncodingHost.IsConsole(Output)`
  false: a pipe, a file, NUL): tswap's whole stdout for that run is a UTF-8 writer (no BOM) over the raw stdout stream
  (`Console.OpenStandardOutput()`). Everything tswap writes on stdout in that run goes through it (the value, a filled
  file, `-v` diagnostic lines, the Debug test-mode line, help text for `get --help`), so the stream has **one
  encoding**. Anything else: nothing changes.
- **`Console.OutputEncoding` is never set by this change, and `Console.InputEncoding` never.** Setting the output
  encoding calls `SetConsoleOutputCP`, which changes the code page of the console window tswap shares with its parent
  (T35's sources); a private writer changes only tswap's own bytes.
- **stderr is unchanged** (console code page when redirected, as today): one encoding per stream, and the warnings
  `get`/`apply` print there are ASCII apart from glyphs T35 already accepts as `?` in that case.
- **Decided in `Program.cs`, not in `CliHost`**, as T35 did: in-process tests must never write to the test host's real
  stdout. The decision needs the command name before anything is written, so it is computed from `args` with the same
  rules as `Dispatch` (global flags skipped, name lowercased).
- **`run` is untouched**: it is not a value-printing command, so its stdout stays `Console.Out` and RedactingPty's
  `Console.OutputEncoding` rule (T35 A1) still holds for every byte of a `run` file.
- **Newline:** the writer's `NewLine` is `Environment.NewLine` (`"\r\n"` on Windows), as `Console.Out`'s, so `get`'s
  bytes are `UTF-8(value) 0D 0A`. Encoder: `new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)` (replacement
  fallback, as `Console.Out` on Linux; a stored value can't hold a lone surrogate after T48's strict reader).

Rejected: setting `Console.OutputEncoding` for redirected stdout (changes the parent window's code page and stderr's
encoding with it); a per-call raw write of the value only (a `-v` line before it would be in another encoding).

## Task 1: which commands print secret values

- `ICliCommand` gains, after `WorksOnClassicVault`:
  ```csharp
  /// <summary>
  /// Brief T52 (#403): true for a command that prints a secret value or a filled file on stdout (<c>get</c>, <c>apply</c>).
  /// On Windows such a command writes a redirected stdout as UTF-8 (<see cref="ConsoleOutputEncoding.Utf8StdoutForSecretValues"/>).
  /// </summary>
  bool PrintsSecretValues => false;
  ```
  `GetCommand` and `ApplyCommand`: `public bool PrintsSecretValues => true;`.
- `CommandRegistry` gains
  `public static bool PrintsSecretValues(string[] args)`: `CliEnvironment.SplitGlobalFlags(args)`, then the first
  remaining argument lowercased (`ToLower()`, as `Dispatch` line 62) looked up by `Name`; false for no argument or an
  unknown name. (`--version` maps to `version`, which prints no value, so it needs no special case.)

Tests (new `TswapTests/SecretValueOutputTests.cs`, all OSes):

| Input `args` | `PrintsSecretValues` |
|---|---|
| `["get", "x"]`, `["apply", "f.yaml"]`, `["-v", "get", "x"]`, `["--verbose", "-v", "apply", "f"]`, `["GET", "x"]`, `["get", "--help"]` | true |
| `[]`, `["-v"]`, `["run", "get"]`, `["run", "tswap", "get", "x"]`, `["names"]`, `["field", "show", "x"]`, `["nosuch"]`, `["--version"]` | false |

and `OnlyGetAndApplyPrintSecretValues`: the names of `CommandRegistry.All` with `PrintsSecretValues` true, ordered, equal
`["apply", "get"]` (a new value-printing command must decide). Break-it-once: drop `PrintsSecretValues => true` from
`ApplyCommand`; the guard test and the `apply` rows fail.

## Task 2: the UTF-8 writer and its wiring

- `IConsoleEncodingHost` gains `Stream OpenStandardOutput();` (the system host: `Console.OpenStandardOutput()`).
- `ConsoleOutputEncoding` gains:
  ```csharp
  /// <summary>
  /// Brief T52 (#403): for a command that prints secret values, on Windows with stdout not a console, a UTF-8 writer
  /// (no byte order mark, AutoFlush) over the raw stdout stream; null otherwise (stdout stays Console.Out). Never sets
  /// the console's encodings.
  /// </summary>
  public static TextWriter? Utf8StdoutForSecretValues(IConsoleEncodingHost host, bool printsSecretValues)
  ```
  Order of checks: `printsSecretValues`, then `host.IsWindows`, then `host.IsConsole(StandardStream.Output)`; only then
  `OpenStandardOutput()`. Returns
  `new StreamWriter(host.OpenStandardOutput(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)) { AutoFlush = true }`.
  The class summary gets one sentence pointing to it.
- `SystemConsole`: `public SystemConsole(TextWriter? stdout = null) : this(new ConsoleInput(), stdout)` and
  `internal SystemConsole(IConsoleInput input, TextWriter? stdout = null)`; `Out => _stdout ?? Console.Out`.
  `ReadPassword`'s default echo becomes `Out` instead of `Console.Out` (`SystemConsole.cs:91`), so it follows the same
  stream.
- `Program.cs`, after the `Utf8OnWindows` line (the two never both act: one needs stdout a console, the other not):
  ```csharp
  // Brief T52 (#403): on Windows, get and apply write a redirected stdout as UTF-8 (one encoding for the whole stream).
  var stdout = ConsoleOutputEncoding.Utf8StdoutForSecretValues(ConsoleOutputEncoding.System, CommandRegistry.PrintsSecretValues(args));
  return CliHost.Run(args, new SystemConsole(stdout), …as today…);
  ```

Tests, all OSes, over a fake host (a `FakeHost` like `ConsoleOutputEncodingTests`', with `OpenStandardOutput` returning
a `MemoryStream` and counting calls), in `SecretValueOutputTests.cs`:

| Host (windows, stdout console) | `printsSecretValues` | Outcome |
|---|---|---|
| (true, false) | true | a writer; `OutputEncoding` never set; `OpenStandardOutput` called once |
| (true, true) | true | null; `OpenStandardOutput` not called |
| (false, false) | true | null; only `IsWindows` read (a host whose other members throw, as `NotWindowsHost`) |
| (true, false) | false | null; no host member read (a host whose members all throw) |

- `Utf8Writer_EveryNonAsciiCorpusValue_IsItsUtf8Bytes`: for each `EvilValues.Cases` value with a character above U+007F,
  `writer.WriteLine(value)` into a fresh `MemoryStream`; the bytes equal
  `new UTF8Encoding(false, throwOnInvalidBytes: true).GetBytes(value + Environment.NewLine)` (so no BOM). Failure text:
  the case name, both lengths and the first differing byte offset, never the value.
- `SystemConsoleTests`: `Out_GivenStdout_IsThatWriter` (`new SystemConsole(input, writer).Out` is `writer`) and
  `ReadPassword_Redirected_EchoesToGivenStdout` (the newline goes to the given writer). With no writer, `Out` is
  `Console.Out` (`Assert.Same`).
- The existing fakes in `ConsoleOutputEncodingTests` gain `OpenStandardOutput` (`FakeHost`: a `MemoryStream`;
  `NotWindowsHost`: throws, as its other members); no assertion there changes.

Break-it-once: in `Utf8StdoutForSecretValues` drop the `IsConsole` check; the (true, true) row fails. Use
`Encoding.UTF8` (which emits a BOM through `StreamWriter`) instead of the `UTF8Encoding(false)`; the corpus test fails at
byte 0.

## Task 3: the end-to-end proof (Windows)

The implementer runs on Linux, so these run on Windows CI; the break-it-once runs are the controller's there, as in
T48. On Linux and macOS the `[WindowsFact]` tests skip; `./runtests.sh` must stay green there.

- Helper in `EndToEndTests.cs`: `RunTswapStdoutBytes(params ReadOnlySpan<string> args)` →
  `(int exitCode, byte[] stdout, string stderr)`: `MakePsi()`, stdout copied from `process.StandardOutput.BaseStream`
  into a `MemoryStream` (no decoder involved), stderr read with `ReadToEndAsync` started first (no pipe deadlock).
- **`Get_RedirectedStdout_IsUtf8_EveryNonAsciiCorpusValue_Windows`** (`[WindowsFact]`): `init --yubikey --no-recovery`,
  then for every `EvilValues.Cases` value with a character above U+007F (as the ingest test selects them; names
  `g1`, `g2`, … checked with `EvilValues.NameIsSafeFor`): ingest its UTF-8 bytes with `RunTswapWithStdinBytes`, then
  `RunTswapStdoutBytes("get", name)`. Expected: exit 0 and stdout equal to
  `new UTF8Encoding(false).GetBytes(c.Value.TrimEnd() + "\r\n")`. Collect failures (case name, exit code, expected and
  actual byte counts, first differing offset; never a value or its bytes) and assert none.
- **`Apply_RedirectedStdout_IsUtf8_Windows`** (`[WindowsFact]`): ingest `café-Grüße-а-🔒` (the `а` is Cyrillic
  U+0430; written in the source as `а`) as `a1`; a template written as UTF-8 without BOM:
  `"# Grüße\npassword: \"\"  # tswap: a1\n"`; `RunTswapStdoutBytes("apply", template)`: exit 0 and stdout equal to the
  UTF-8 bytes of `"# Grüße\npassword: \"café-Grüße-а-🔒\"  # tswap: a1\n"` (the template's own non-ASCII text is UTF-8
  too: one encoding). Same failure-text rule.
- **`Get_CapturedInPowerShell_WithUtf8ConsoleEncoding_IsExact_Windows`** (`[WindowsFact]`), the docs line's proof.
  PowerShell decodes a native program's output with `[Console]::OutputEncoding`, in Windows PowerShell 5.1 and in
  PowerShell 7 alike, and both default it to the OEM code page (PowerShell/PowerShell#14945; about_Character_Encoding
  covers only `$OutputEncoding`, which is the other direction). Ingest the value above as `p1`. Write `capture.ps1`
  (ASCII):
  ```powershell
  param($tswap, $name, $out)
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  $v = & $tswap get $name
  [System.IO.File]::WriteAllText($out, $v, [System.Text.UTF8Encoding]::new($false))
  ```
  For each of `powershell.exe` (5.1) and `pwsh` (both on every GitHub Windows runner; missing: fail with a message
  saying which), start `<shell> -NoProfile -NonInteractive -ExecutionPolicy Bypass -File capture.ps1 <binary> p1 <out>`
  with `MakePsi()`'s environment and **`CreateNoWindow = false`**: Windows PowerShell 5.1 runs on .NET Framework, whose
  `Console.OutputEncoding` setter raises an error when the process has no console (.NET's ignores it, T35's sources),
  and the documented case is a console window anyway. Expected: shell exit 0 and the out file, read as UTF-8, equal to
  the value. Failure text: the shell, its exit code and stderr (which holds no value), the two lengths.
  Break-it-once (controller, CI): remove the `[Console]::OutputEncoding` line; both legs must fail (the runner's 437).
- **`NonAsciiValue_Redacted_WindowsConPty`** (EndToEndTests.cs:1412-1419) reads `get`'s stdout with the default decoder,
  the console code page, which matched today's output; after Task 2 it would see `p├ñ…`-style text (UTF-8 bytes read as 437). Change only that
  call: `var get = RunTswapStdoutBytes("get", "umlaut");` and `Assert.Equal(value, Encoding.UTF8.GetString(get.stdout).Trim());`
  (the expected value and what it checks are unchanged; the A16 comment gains "read as UTF-8 since T52").
- `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows`: in its summary, replace the sentence "No <c>tswap get</c> check
  (A12/A20 withdrawn): get's redirected stdout on Windows is the console code page (T35 A1)." with "The `get` side is
  `Get_RedirectedStdout_IsUtf8_EveryNonAsciiCorpusValue_Windows` (T52)." No code change.

Break-it-once (controller, Windows CI): in `Program.cs` pass `false` instead of `CommandRegistry.PrintsSecretValues(args)`;
the `get` corpus test, the `apply` test and the PowerShell test fail (15 or 16 corpus cases, as in #403).

## Task 4: docs and release note

- `docs/commands.md`, the paragraph after the stdin one (line 242-246, outside the generated command blocks):
  "On Windows, `get` and `apply` write UTF-8 (no BOM) when their output is redirected to a file or pipe, whatever the
  console code page, so `tswap get n > f` and `| other-program` get the value exactly; their messages on stderr stay in
  the console's code page. PowerShell (Windows PowerShell 5.1 and PowerShell 7) decodes a program's output with
  `[Console]::OutputEncoding`, the OEM code page by default: before `$v = sudo tswap get n` or piping `get`/`apply` into a
  cmdlet, run `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)`. (Windows PowerShell 5.1's `>`
  re-encodes what it decoded as UTF-16; use `cmd /c "tswap get n > f"` or PowerShell 7.4 or later, whose `>` keeps a
  program's bytes, to write the file as tswap wrote it.)"
  Before writing the PowerShell 7.4 clause, check it against Microsoft's docs (about_Redirection, "native command"
  byte preservation, `PSNativeCommandPreserveBytePipe`); if you can't confirm it, leave that clause out and say so.
- `docs/install.md`, the "Console output is UTF-8" bullet (lines 300-307): after "write in the window's code page, as
  before." add "Except `get` and `apply`: they write UTF-8 to a redirected stdout (see the Commands section of `commands.md`)."
- `docs/release-notes/v0.3.2.md` stays as it is. In your report, the text of a 0.3.3 release-note entry: on Windows,
  `get` and `apply` write UTF-8 when their output is redirected (before, non-ASCII characters came out in the console
  code page or as `?`); in PowerShell set `[Console]::OutputEncoding` to UTF-8 to capture it (#403).

## Out of scope

- `run`'s output and RedactingPty's use of `Console.OutputEncoding` (T35 A1 stands).
- stderr's encoding; the output of every other command (`names > f`, `check > f` keep the console code page).
- Setting `Console.OutputEncoding` or `Console.InputEncoding` anywhere.
- Linux and macOS (already UTF-8; the new code returns null there).
- Unicode normalisation (#400), Git Bash argument changes (#402).
