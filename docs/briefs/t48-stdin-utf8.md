# Brief T48: piped stdin is read as UTF-8 on every OS (Windows stored non-ASCII secrets wrongly)

Milestone 0.3.2. Base: `brief/t47` at ed9562f (this brief's branch, `brief/t48`, starts there: it needs T47's Git Bash
tests). Read AGENTS.md and CLAUDE.md first, then `TswapCli/SystemConsole.cs` (all of it, including `IConsoleInput` and
`ConsoleInput` at the end), `TswapCli/IConsole.cs`, `TswapCli/CliHost.cs` (the console it builds and its two catches),
`TswapCli/CommandContext.cs` (the two `Console.ReadLine()` calls, near lines 331 and 411), `TswapCore/Validation.cs`
(`ReadBoundedStdin`), `TswapCli/Commands/IngestCommand.cs`, `TswapTests/SystemConsoleTests.cs`, `TswapTests/FakeConsole.cs`,
and in `TswapTests/EndToEndTests.cs`: `RunTswapWithStdin`, `MakePsi`, `Run_GitBashScript_EvilValues_ArriveExactly_Windows`
and `Run_GitBashScript_EnvValue_EvilValues_ArriveExactly_Windows`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change.** If an existing test expects
invalid UTF-8 on stdin to be accepted (stored with U+FFFD, say), stop and list it: that needs the owner's sanction.

## What is wrong (evidence)

`SystemConsole.In` is `Console.In`, and `ConsoleInput.ReadLine` is `Console.ReadLine()`. Neither sets an encoding, so on
Windows piped stdin is decoded with the console's code page (437 on the GitHub runner), not UTF-8. A Windows CI spike
(branch `msys-spike`, run 45036890285, `Spike_IngestStdinEncoding_Windows`) ingested values as raw UTF-8 bytes, the way
`kubectl … | jq … | tswap ingest` delivers them, and read them back through `tswap run <Git Bash> ./capture.sh`:

```
test host: Console.InputEncoding=437 OEM=437 ANSI=1252
raw-utf8-bytes [café-value]: got [caf├⌐-value]
raw-utf8-bytes [correct horse-value]: got [correctΓÇâhorse-value]
raw-utf8-bytes [abc\U0001F600def-value]: got [abc≡ƒÿÇdef-value]
```

So on Windows a piped secret with any non-ASCII character is **stored as a different value** (the owner's requirement,
#400: a value with é must work across Mac, PC and Linux). The test helper `RunTswapWithStdin` hid it: it writes with the
same code page, so `café` survives and ` ` becomes a plain space before tswap sees it. Linux and macOS decode stdin
as UTF-8 already, but leniently: invalid bytes become U+FFFD and are stored silently.

Interactive input is not affected: `ReadPassword` and `ReadLineWithoutEcho` on a terminal read keys with `ReadKey`
(UTF-16 from the console), and on Unix a terminal is UTF-8. Out of scope: Unicode normalisation (NFC/NFD), #400.

## Task 1: one strict UTF-8 reader for redirected stdin

When stdin is redirected, every read of it in `TswapCli` goes through **one** shared `TextReader` (created on first use,
for the life of the process):

- a `StreamReader` over `Console.OpenStandardInput()`, UTF-8, `detectEncodingFromByteOrderMarks: true` (a leading UTF-8
  BOM is dropped; a UTF-16 or UTF-32 BOM switches to that encoding, which is what Windows PowerShell sends when its
  `$OutputEncoding` is Unicode);
- invalid bytes are **refused**, never replaced: the read throws a `TswapException` with exactly this message (exit
  code 1):

  ```
  stdin is not valid UTF-8 (tswap reads piped input as UTF-8). Nothing was changed. In Windows PowerShell 5.1, run $OutputEncoding = [System.Text.UTF8Encoding]::new($false) first, or use PowerShell 7.
  ```

  The message must never contain any byte or character of the input. .NET's own `DecoderFallbackException` message
  names the bytes ("Unable to translate bytes [C3] at index 3"), and `CliHost`'s generic catch prints `ex.Message`: so the
  `TswapException` must be thrown from the decoding itself (a custom `DecoderFallback`, or a wrapper that catches
  `DecoderFallbackException` and throws without it as the inner exception's message), never left to the generic catch.
  A U+FEFF that is not the first character is data and is kept.

Wire it in:
- `SystemConsole.In` returns the shared reader when `_input.IsInputRedirected`, else `Console.In` (a terminal);
- `ConsoleInput.ReadLine()` reads from the shared reader when stdin is redirected, else `Console.ReadLine()`;
- the two `Console.ReadLine()` calls in `CommandContext.cs` go through `ctx.Console.ReadLine()` (or the shared reader),
  so a piped answer is decoded the same way. Read the surrounding code first: if either call deliberately bypasses the
  console seam, say so in the report and use the shared reader directly instead;
- `AgentCommand`'s `Console.OpenStandardInput()` (the agent's own byte protocol) stays as it is.

All OSes, not only Windows: on Linux and macOS this changes only invalid bytes (refused instead of U+FFFD).

Unit tests (new class `StdinUtf8ReaderTests`, or in `SystemConsoleTests.cs`; build the reader over a `Stream` you
control, through whatever internal factory Task 1 adds):

| Input bytes | Result |
|---|---|
| UTF-8 of every non-ASCII `EvilValues.Cases` value | that value exactly |
| `EF BB BF` + UTF-8 of `café-value` | `café-value` (BOM dropped) |
| UTF-8 of `abcdefg﻿hijklmno` | the same, U+FEFF kept |
| `FF FE` + UTF-16LE of `café-value` | `café-value` |
| `63 61 66 C3 28` (invalid continuation) | the exact `TswapException` message |
| `61 FF 62` (byte never valid in UTF-8) | the exact message |
| `61 F0 9F 98` then end of stream (truncated 4-byte sequence) | the exact message |
| UTF-8 of `abc\U0001F600def-value` from a stream that returns **one byte per `Read`** | the value exactly |

For every refused row also assert the message contains none of `C3`, `FF`, `F0`, `9F`, `98` and no character of the
input other than those in the fixed message. Break-it-once: make the reader lenient (replacement fallback); the
`63 61 66 C3 28` row must fail.

Source guard (a test in the same class): no file under `TswapCli/` except the one that holds the shared reader and
`SystemConsole.cs` contains `Console.ReadLine(`, `Console.In` (as a member access, not `Console.IsInputRedirected`) or
`Console.Read(`; `AgentCommand.cs`'s `Console.OpenStandardInput()` is allowed by name. Break-it-once: put a
`Console.ReadLine()` back in `CommandContext.cs`; the guard must fail.

## Task 2: the end-to-end proof, and the test helper

- `RunTswapWithStdin` (and any other E2E helper that writes a child's stdin) writes **UTF-8 bytes**: set
  `StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)` on the `ProcessStartInfo` from
  `MakePsi(redirectStdin: true)`. This changes a test input, not an assertion; say so in the commit message.
- The two Git Bash tests from T47 (Tasks 2e and 2f) left every non-ASCII value out with an output line ("wait on the
  stdin-encoding question"). Remove that exclusion: they now run every corpus value that is not a registered finding.
  They must pass on Windows CI (the controller runs it). If a non-ASCII value still arrives altered, report it with the
  log line; don't register it.
- New `[WindowsFact]` `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows`: for every non-ASCII corpus value, write its
  UTF-8 bytes to `tswap ingest <name>`'s stdin through `StandardInput.BaseStream` (not the helper: the test must not
  depend on the helper's encoding), then `tswap run <Git Bash> ./capture.sh {{name}}` with `capture.sh` =
  `printf '%s' "$1" > out.txt`; `out.txt` read as UTF-8 equals the value (trimmed at the end as ingest does). Use the
  same Git Bash lookup as T47 (`FindGitBash`); without Git Bash on PATH the test fails with a message saying so (it is
  on every GitHub Windows runner).
- New `[Fact]` (all OSes) `Ingest_InvalidUtf8_IsRefused_AndStoresNothing`: raw bytes `63 61 66 C3 28` into
  `tswap ingest bad1`; exit code 1, stderr contains the exact message, and `tswap names` does not list `bad1`.

Break-it-once (the controller's, on Windows CI): `SystemConsole.In` back to `Console.In`; the new Windows test must
fail with the mangled values. Name in your report the line to revert.

## Task 3: docs and release note

- `docs/commands.md`, the `ingest` entry (outside any generated block): stdin is read as UTF-8 on every OS; a leading
  BOM is ignored; invalid UTF-8 is refused and nothing is stored. Windows PowerShell 5.1 pipes text to programs as ASCII
  by default (é arrives as `?`, which tswap can't detect): set `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`
  first, or use PowerShell 7, which pipes UTF-8.
- `docs/scripts.md`'s Git Bash paragraph: if T47 says non-ASCII values are left out pending this question, remove that
  sentence.
- In your report, the text of a release-note entry: on Windows, secrets piped into `ingest` (or `ingest --rotate`) with
  non-ASCII characters were stored wrongly before 0.3.2; re-ingest them.
- `TswapCore/Prompt.cs` stays as it is.

## Out of scope

- NFC/NFD normalisation (#400), Git Bash quoting (#402), the agent's stdin protocol.
- Changing the console's code page (`Console.InputEncoding`): on Windows that changes the whole console window, also
  after tswap exits. Never set it.

## Amendments (round 1)

These replace the brief text they name; where they conflict with it, they win.

- **A1 (both reviewers; replaces Task 1's third wiring bullet, the source guard and its break-it-once).** The two
  `Console.ReadLine()` calls in `CommandContext.cs` (`AskWhichKey`, `ChooseSerial`) already go through the seam: inside
  the record, `Console` is its `IConsole Console` property, so they reach `ConsoleInput.ReadLine()`, which the second
  bullet fixes. **Leave them unchanged**, and never route a prompt past `SystemConsole.ReadLine()` (that would drop the
  #293 typeahead discard). The source guard bans **static `System.Console` input access** only: in every file under
  `TswapCli/` except the shared reader's file and `SystemConsole.cs`, the regex `(?<![.\w])Console\.(ReadLine|Read|In)\b`
  (not preceded by `.` or a word character, so `ctx.Console.In`, `this.Console.ReadLine()` and `Console.InputEncoding`
  don't match) must match only where the identifier `Console` is the `IConsole` property, which the guard can't tell
  apart textually; so the guard also allows exactly the two `CommandContext.cs` lines by their content (trimmed, listed
  in the test) and nothing else. The four `ctx.Console.In` uses (`IngestCommand`, `BrokerCommand`, `SlotCommand` twice)
  don't match. `System.Console.ReadLine(`, `System.Console.In` and `System.Console.Read(` are banned everywhere outside
  those two files too. Break-it-once: add `var x = System.Console.ReadLine();` (or a bare `Console.ReadLine()` in a
  `TswapCli/Commands/` file with no `Console` property in scope); the guard must fail.
- **A2 (both; replaces "detectEncodingFromByteOrderMarks: true").** StreamReader's BOM detection swaps in
  `Encoding.UTF8` / `Encoding.Unicode` / `Encoding.UTF32`, which **replace** invalid input instead of throwing. Don't
  use it: `detectEncodingFromByteOrderMarks: false`, and the factory peeks the leading bytes itself (with a stream that
  returns one byte per `Read`, too) and builds the strict encoding: `EF BB BF` → UTF-8 (BOM dropped), `FF FE 00 00` →
  `new UTF32Encoding(false, false, throwOnInvalidCharacters: true)`, `FF FE` → `new UnicodeEncoding(false, false,
  throwOnInvalidBytes: true)`, `FE FF` → big-endian UTF-16 the same way, otherwise UTF-8 from the first byte (the peeked
  bytes are not lost). The owner confirmed (2026-11-22): invalid input is refused, not stored with U+FFFD, on every OS
  and in every encoding; the message is the same fixed text (it says UTF-8 also for a broken UTF-16 stream; accepted).
  New table rows: `EF BB BF` + `63 61 66 C3 28` → the exact message; `FF FE` + UTF-16LE `61 00` + lone high surrogate
  `3D D8` + `62 00` → the exact message; `FE FF` + UTF-16BE of `café-value` → `café-value`.
- **A3 (both; preferred shape).** Prefer a custom `DecoderFallback` whose buffer throws the `TswapException` directly,
  so `Read`, `ReadLine`, `ReadBlock` and the end-of-stream flush are all covered at the source. If you wrap instead, the
  `TswapException` has **no inner exception** (`DecoderFallbackException`'s message names the bytes). A test asserts
  `InnerException` is null on a refused row.
- **A4 (MiMo; replaces "and any other E2E helper that writes a child's stdin").** The helpers that feed tswap's own
  **text** stdin get `StandardInputEncoding = new UTF8Encoding(false)`: `EndToEndTests.RunTswapWithStdin` /
  `MakePsi(redirectStdin: true)`, `VaultPasswordEndToEndTests.Run` (near line 42) and `RunFileTokenTests.RunToEnd`'s
  `ProcessStartInfo` (near line 1375). The protocol and script helpers stay as they are: `AgentEndToEndTests`,
  `BrokerServeEndToEndTests`, `SshAgentServeEndToEndTests`, `TpmTestTools` (bytes of their own protocols) and
  `InstallScriptUpgradeTests` (a script fed to bash).
- **A5 (MiMo; task order).** The helper change (A4) goes in **Task 1's commit**, before or with the strict reader, so no
  commit has Windows E2E red (a code-page-writing helper would be refused by the strict reader). Say so in the commit
  message.
- **A6 (GLM F3, MiMo M1; replaces "they now run every corpus value that is not a registered finding").** The only change
  in the two Git Bash tests is deleting the non-ASCII exclusion inside the shared `RunGitBashCases` (near lines
  1921–1927). `max-length` stays left out, the argument test keeps its `KnownFindings` filter, and the `--env` test gets
  no new filter.
- **A7 (both).** The refusal message is **identical on every OS** (the PowerShell advice included): one fixed string,
  asserted exactly. Don't make it per-OS.
- **A8 (both).** Task 2 rewords the `EvilValues.KnownFindings` comment (`EvilValues.cs` near line 182, "ASCII cases only:
  the non-ASCII values wait on the stdin-encoding question") to say the findings are all ASCII cases, without the
  waiting. Task 3 changes `docs/scripts.md:52`'s "That way is tested with every ASCII test value." to "That way is tested
  with every test value."
- **A9 (MiMo M4; replaces "the `ingest` entry (outside any generated block)").** The `### ingest` heading is inside the
  generated reference block (checked by `CommandReferenceTests`); don't edit it. Put the new paragraph in the
  hand-written text under `## Commands`, after the paragraph ending "(`ingest` trims trailing whitespace, and refuses an
  input of whitespace only.)".
- **A10 (MiMo M6).** Drop "no character of the input other than those in the fixed message"; keep the exact-message
  equality and the hex-fragment check (`C3`, `FF`, `F0`, `9F`, `98`, `D8`, `3D`).
- **A11 (both).** `Ingest_InvalidUtf8_IsRefused_AndStoresNothing` gets a local break-it-once: make the reader lenient
  again; the test must fail on Linux (exit 0, `bad1` stored). Record it in the commit message.
- **A12 (MiMo M8).** `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows` also checks the stored value without Git Bash:
  `tswap get <name>` (the tests' sudo bypass) with `StandardOutputEncoding = new UTF8Encoding(false)` equals the value.
  If `get` matches but `out.txt` doesn't, report it as a Git Bash finding (#402); don't register it.
- **A13 (MiMo M10).** One comment at the shared reader: `agent serve` never reads stdin through the seam (after
  `ProcessDetach` the agent's own protocol owns fd 0). No code change for it.
- **A14 (MiMo).** The release note also says: on every OS, piped input that is not valid UTF-8 (also a recovery key
  piped into `recover` or `slot add --recovery`) is now refused instead of stored with replacement characters.
