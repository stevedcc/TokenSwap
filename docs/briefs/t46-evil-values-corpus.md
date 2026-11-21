# Brief T46: an evil-values test corpus through every command that stores, substitutes or masks (#392)

Issue: https://github.com/stevedcc/TokenSwap/issues/392 (read both comments). Milestone 0.3.2. Base: `origin/main` at
0299bd9. Read AGENTS.md and CLAUDE.md first, then: `TswapTests/CommandTests.cs` (the in-process harness at the top,
`RunTswap`/`RunTswapWithStdin`/`Execute`), `TswapTests/RecordingPty.cs`, `TswapTests/RunFileTokenTests.cs`,
`TswapTests/ApplyMultiLineTests.cs`, `TswapTests/RecordStoreExportImportTests.cs`, `TswapTests/EndToEndTests.cs` (the
fixture and the Windows ConPTY section), `TswapCore/Validation.cs` (`ReadBoundedStdin`: values are trimmed at the end,
NUL is refused, the maximum is 65,536 characters), `TswapCore/Redact.cs` and `docs/commands.md`.

**This is a test-only brief.** No product code changes. One commit per task, `./runtests.sh --unit` after each task,
the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits
end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase. No
existing test changes.

**Review history.** Round 1 (GLM ready, MiMo not ready; brief 1st commit): the per-row skip can't be built in xunit 2
(both), the BatBadBut batch file was itself injectable (both), and scope gaps (`run --env`, `ingest --rotate`, trailing
whitespace, NUL, surrogates across chunks, the ConPTY path, docs anchors). Amendments A1-A8; where a task and an
amendment differ, the amendment wins.

**Findings protocol.** The tests state what tswap **should** do (the invariants below). Where tswap doesn't, that's a
finding, not a test to bend: mark exactly that case `Skip = "T46 finding N: <one line>"` (one finding number per
distinct cause), list every finding in the report with the input class, the command and what happened (never a
secret value: the corpus values are test data, but describe them by their name in the corpus), and carry on with the
rest. Never weaken an assertion or drop a case to make it pass. The controller files an issue per finding and rules on
each.

## The corpus: `TswapTests/EvilValues.cs`

A static class with one `TheoryData<string, string>` of `(caseName, value)`: a stable, readable case name (used in test
names and findings) and the value. The values, each as a literal built from escapes where it isn't printable:

| Class | Cases |
|---|---|
| Quotes and shell characters | `'`, `"`, `&`, `#`, `$`, backtick, `%`, `!`, `\`, `;`, `\|`, `<`, `>` each inside a 16-character value (e.g. `abcdefg'hijklmno`); plus all of them in one value |
| The owner's escaping set | `CorrectHorse'Battery#Staple&x` |
| Spaces | leading space; a space inside (`correct horse battery staple`); U+00A0, U+2003, U+3000 inside |
| A leading dash | `-oProxyCommand=touch x` |
| tswap's own syntax | `{{other-secret}}` (another secret in the vault named `other-secret` exists), `{{@file.yaml}}`, `# tswap: other-secret`, `abc{{other-secret}}xyz` |
| Bidi and invisible | U+202E inside; U+2066…U+2069 inside; U+200B, U+200C, U+200D, U+FEFF inside |
| Normalisation | `café-secret-value` with U+00E9 (NFC) |
| Homoglyphs | `pаssword-value-1` with Cyrillic U+0430 for the first `a` |
| Line endings | LF, CRLF, a lone CR, U+2028, U+2029, U+0085 inside a value (not at the end) |
| Terminal control | ESC `[31m` inside; BEL inside |
| Emoji | a value with U+1F512 (a surrogate pair) at position 7, so an 8-character cut would split it |
| Length | 1 character (`x`); exactly 65,536 characters; 8 characters (the short-value threshold) |

## Task 1: storage and substitution (in-process, every OS)

Using `CommandTests`' harness pattern (its own test class, `EvilValuesTests`, with the same `Execute` set-up), for every
corpus value:

1. **Stored exactly.** `ingest` from stdin, then `get` (the harness has `SudoBypass: true`) returns the value with
   trailing whitespace trimmed (`ReadBoundedStdin`'s documented rule) and **every other character unchanged**. The
   65,536-character value is accepted; a 65,537-character one is refused with the documented message.
2. **Substituted as one argument.** `run tool {{name}}` through a `RecordingPty`: the runner gets exactly the stored
   value as **one** argv element, and no other element contains any of it.
3. **Never expanded twice.** For the tswap-syntax cases: the argv element is the literal text (`{{other-secret}}`), never
   `other-secret`'s value, and `other-secret`'s value appears in no argv element.
4. **Masked in the child's output.** The `RecordingPty` child prints the stored value inside a line
   (`before <value> after`). The output contains `[REDACTED: name]` and, for values of 8 or more characters, the value
   does not appear and no 8-character substring of it appears. For the 1-character value, the T30 whole-word rule
   applies (`x` alone on a line is masked; `xylophone` is not); assert both.

Break-it-once: make `RecordingPty`'s recorded argv drop the last character of each element; invariant 2 must fail.

## Task 2: files and masking commands (in-process, every OS)

For every corpus value:

1. **`{{@file}}` fill.** A YAML file `key: ""  # tswap: name` given as `{{@file.yaml}}` to `run tool`: the filled copy
   the runner sees parses (with the repo's own YAML reading if there is one, otherwise by the documented quoting rule in
   `docs/commands.md`) back to exactly the stored value. If tswap has no documented quoting rule for such a value, that's
   a finding.
2. **`redact`.** A file with the value inside a line (`token: <value>`): the output contains `[REDACTED: name]` and,
   for values of 8 or more characters, neither the value nor any 8-character substring of it.
3. **`tocomment --dry-run`.** The same file: the reported change names the right secret, and neither stdout nor stderr
   contains the value or an 8-character substring of it.
4. **`export` then `import`** into a fresh vault (the existing export tests show the passphrase handling): `get` returns
   exactly the stored value.

Also, for the normalisation case only: put the **NFD** form (`e` + U+0301) in the child's output and in the `redact`
file. Assert nothing about masking; record what happens (masked or not) in the report as a decision for the owner
(#392 asks whether redact should recognise both forms).

Break-it-once: make the fill write the value with its last character dropped; invariant 1 must fail.

## Task 3: Windows batch files, "BatBadBut" (E2E, Windows only)

In `EndToEndTests.cs`, a Windows-only test (early return elsewhere, like its neighbours), with the real binary:

- a batch file `echo-arg.cmd` that writes its first argument to `out.txt` (`>"%~dp0out.txt" echo(%~1`, or the safest
  form you can justify in a comment);
- values: `"&echo INJECTED>marker.txt&"`, `a" & echo INJECTED>marker.txt & "`, `%PATH%`, `^&echo INJECTED>marker.txt`;
- `tswap run <echo-arg.cmd> {{name}}` for each.

Assert: **`marker.txt` never exists** in the test folder, and `out.txt` holds the value (or tswap refused the run with
a message naming batch files). Either outcome passes this test; which one happened goes in the report. An existing
`marker.txt` is a finding with the highest priority: report it at once, even mid-task.

Break-it-once: in the test only, start the batch file with `cmd /c` and the argument concatenated unquoted, and see
`marker.txt` appear, so the test can detect an injection on this runner (then revert).

This test can only run on Windows CI: the controller runs it and gives you the log. Write it so that its failure
message names the case and whether `marker.txt` appeared.

## Task 4: the sourced `.env` case (docs)

`docs/commands.md`, at the `{{@file}}` section: two sentences. A filled file is written literally; if a shell sources
it, a value containing `$(...)`, a backtick or a `"` runs or breaks there, so a shell-sourced file needs single-quoted
values, and a value containing `'` breaks even that. Task 2's fill tests already prove the literal write; no new test.

## Amendments (round 1)

- **A1 (findings mechanism; both).** xunit 2.9.3 has no per-row skip, and an early `return` that reports Passed is
  forbidden (#181, `PlatformFacts.cs`). So: `EvilValues.KnownFindings` maps `(caseName, invariant)` to a finding
  number and one line; each theory's data **leaves those pairs out**, and for each one there is a separate
  `[Fact(Skip = "T46 finding N: <line>")]` named for the case and invariant, containing the full assertion (so
  un-skipping later is deleting `Skip`). Never an early return.
- **A2 (scope; both).** Add to Task 1: **invariant 2b**, `run --env X={{name}} tool` (see `RunEnvTests`): the recorded
  environment holds exactly the stored value in `X` and in no other variable, no argv element contains it, and the
  output is masked as in invariant 4; and **`ingest --rotate`** for every case: `get` returns the new value,
  `{{name:previous}}` substitutes the old one exactly. `create` and `rotate` generate their values, so they take no
  corpus values. `tocomment`'s real write is out of scope here (#394 changes its matching). The question whether `run`
  should warn when the command is `sh`, `bash` or `.` with a `{{@file}}` argument goes in the report as an owner
  decision.
- **A3 (trailing whitespace, NUL; both).** Add cases ending in a space, a tab and a newline, and with a trailing
  U+2028: `get` returns them with `TrimEnd()` applied (the documented `ingest` rule; note it also trims U+2028/2029/0085).
  A whitespace-only input and a NUL inside a value: `ingest` refuses with the documented messages. Invariant 1 reads
  "stored exactly as read, after the documented trailing-whitespace trim"; the issue's "byte for byte" versus the
  trim goes in the report as an owner decision.
- **A4 (short values; MiMo).** Task 2.3 gets the same qualifier as 2.2 (8 or more characters), and 2.2 and 2.3 get the
  T30 whole-word pair as in 1.4. Secret names and file names used for a case must not contain any character of that
  case's value.
- **A5 (surrogates; MiMo).** The emoji case states its invariant: **no unpaired surrogate** appears in any output, and
  "8-character substring" means 8 **code points** (no window, and no half of a pair, appears). Run it a second time
  with `RecordingPty`'s `ChunkSize` set so the pair is split across two chunks.
- **A6 (BatBadBut; both).** Replace Task 3's batch design:
  - **Attribution batch** `inert.cmd`: `@exit /b 0`. It never expands an argument, so any `marker.txt` comes from how
    the batch was **launched** (the BatBadBut case), not from the batch. All four values, plus a `.bat` twin.
    Invariant: `marker.txt` never exists.
  - **Round-trip batch** `capture.cmd`, only for values without `"`: `@echo off`, `setlocal DisableDelayedExpansion`,
    `set "arg=%~1"`, `setlocal EnableDelayedExpansion`, `>"%~dp0out.txt" echo(!arg!`. Invariant: `out.txt` holds the
    value. A value with `"` can't be captured safely by any batch, so it's in `inert.cmd` only.
  - Set the child's working directory to the test folder explicitly.
  - **Two legs:** through the redirected harness (FallbackPty, .NET's process start) and through
    `RunTswapInConPty` (WindowsPty's own command line). Name the leg in each failure message.
  - **Break-it-once** is the controller's, on Windows CI: ship, as a comment in the test, a variant that starts the
    batch with `Process.Start("cmd.exe", "/c inert.cmd " + value)` (unquoted, outside tswap), which must create
    `marker.txt` and so proves the detector works on the runner.
- **A7 (docs anchors; GLM).** The `{{@file}}` section and its quoting rule are in `docs/security-model.md` ("Files with
  secrets: `run` with `{{@file}}`"), not commands.md: Task 2.1 reads the rule there, and Task 4's two sentences go
  beside that section's `KEY=` paragraph.
- **A8.** The broker stays out of scope; say so in the report for the owner.

## Out of scope

- Fixing any finding (the controller files and rules on each).
- The broker (its header refusal of CR, LF and NUL is tested already).
- Changing the redaction heuristic (#391) or `tocomment`'s matching (#394).
