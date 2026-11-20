# Brief T43: recognise PowerShell's `-encodedCommand` form of an unquoted token; ASCII-only prompt text (#348, #375)

Issues: https://github.com/stevedcc/TokenSwap/issues/348 (follow-up), https://github.com/stevedcc/TokenSwap/issues/375
(milestone 0.3.1). Base: `origin/main` at 9b7f943. Read AGENTS.md and CLAUDE.md first, then
`TswapCli/Commands/RunCommand.cs` (lines 60-115 and the T35 block from `NoTokensText` to `BracesWarning`),
`TswapTests/RunPowerShellBracesTests.cs` (whole file), `TswapCore/Prompt.cs`, `TswapTests/PromptTests.cs`,
`docs/install.md` ("Windows notes") and `docs/agent-integration.md` (the "**PowerShell.**" paragraph).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. No existing test's assertions change, with one exception the owner
sanctioned (A1).

**Review history.** Round 1 (GLM and MiMo, 7593c92): both "no", one shared Critical (two `PromptTests`
assertions pin the characters Task 2 removes) → A1, owner-sanctioned 2026-11-20. MiMo I1 (`Encoding.Unicode` never
throws) → A2. Minors → A3-A8. Where a task and an amendment differ, the amendment wins.

## Why (evidence from the rc.1 owner checks, #367, 2026-11-20)

T35 added a hint for an unquoted token in PowerShell, assuming PowerShell passes `{{name}}` on as `{name}`. On the
owner's laptop (Windows PowerShell 5.1.26100, classic console) the hint never fired. `cmd /c echo` shows what
PowerShell really passes to a native program when an argument is a script block:

```
PS> cmd /c echo {{name}}
-encodedCommand ewBuAGEAbQBlAH0A -inputFormat xml -outputFormat text
PS> cmd /c echo {{name}} END
-encodedCommand ewBuAGEAbQBlAH0A END -inputFormat xml -outputFormat text
PS> cmd /c echo --password={{db-pw}}
--password= -encodedCommand ewBkAGIALQBwAHcAfQA= -inputFormat xml -outputFormat text
```

`ewBuAGEAbQBlAH0A` is Base64 of the UTF-16LE text `{name}` (the script block's body), `ewBkAGIALQBwAHcAfQA=` of
`{db-pw}`. So:
- the script block becomes **two arguments**, `-encodedCommand` and the Base64 of its body, in its place;
- `-inputFormat xml -outputFormat text` are **appended as the last four arguments** (after `END`, not after the
  Base64);
- in `--password={{db-pw}}` the bareword splits: `--password=` is its own argument, then the pair.

(An unquoted `{{@values.yaml}}` doesn't reach tswap at all: 5.1 refuses to parse it, "The splatting operator '@'
cannot be used ...". Nothing to do there.) The T35 `{name}` detection stays: another shell, or PowerShell 7, may pass
that form; the owner's PowerShell 7 run follows.

The same run showed (#375): `tswap prompt`, redirected on Windows, is written in the console code page (850 there),
and the prompt's 37 em dashes and 5 ellipses don't survive; the install script writes the agent instructions exactly
that way.

## Task 1: detect the `-encodedCommand` form

In `RunCommand.cs`, next to `BracedTokens`:

- `internal static IReadOnlyList<EncodedToken> EncodedTokens(IReadOnlyList<string> commandArgs)`, with
  `internal readonly record struct EncodedToken(string Braced, string? Prefix)`. Rules:
  1. Only when the **last four** arguments are exactly `-inputFormat`, `xml`, `-outputFormat`, `text`
     (`StringComparison.OrdinalIgnoreCase`). Otherwise the result is empty.
  2. For every index `i` (not inside those last four) where `commandArgs[i]` equals `-encodedCommand` (ignore case)
     and `i + 1` is before the last four: decode `commandArgs[i + 1]` with `Convert.TryFromBase64String`, then
     `Encoding.Unicode` (strict: a decoder that throws on invalid bytes, caught as "not ours"). Keep it when the text
     matches `BracedNameRegex` or `BracedFileRegex` (T35's two, unchanged).
  3. `Prefix` is `commandArgs[i - 1]` when `i > 0` and that argument ends with `=`; otherwise null.
  4. Distinct by `(Braced, Prefix)`, in argument order.
  Nothing is opened or resolved: shape only, as T35.
- `internal static string EncodedHint(EncodedToken t)`: with `shown = Validation.Printable(t.Braced)` and
  `quoted = $"'{Validation.Printable(t.Prefix ?? "")}{{{shown}}}'"`, exactly:
  `$"PowerShell passed an unquoted token {{{shown}}} on as a script block (-encodedCommand ...). Quote it: {quoted}."`
- `internal static string EncodedWarning(EncodedToken t)`: exactly
  `$"Warning: PowerShell passed an unquoted token {{{shown}}} on as a script block (-encodedCommand ...); it is passed on as it is. Quote it: {quoted}."`
- Wire both where T35 wires its pair: the no-token refusal appends one `"\n" + EncodedHint(t)` per encoded token
  **after** T35's braced hints; the warning loop writes one `EncodedWarning` per encoded token after T35's warnings,
  at the same point (after every refusal made before the vault opens).

Tests: a new class `TswapTests/RunPowerShellEncodedTests.cs`, same fixture pattern as `RunPowerShellBracesTests`
(`FleetMachine`, `RecordingPty`, `ErrorLine`). A helper `Enc(string body) => Convert.ToBase64String(Encoding.Unicode.GetBytes(body))`,
and the tail `string[] Tail = ["-inputFormat", "xml", "-outputFormat", "text"]`.

- `Laptop_EchoName_HintsTheQuotedForm`: the literal laptop arguments `cmd /c echo -encodedCommand ewBuAGEAbQBlAH0A -inputFormat xml -outputFormat text`
  (literal Base64, not `Enc`): exit 1, stdout empty, stderr equals
  `ErrorLine(NoTokensText + "\nPowerShell passed an unquoted token {{name}} on as a script block (-encodedCommand ...). Quote it: '{{name}}'.")`
  spelt out in full once, and `EncodedHint(...)` equality too; no PTY start; no config file written.
- `Laptop_WordAfterToken_StillHinted`: `cmd /c echo -encodedCommand ewBuAGEAbQBlAH0A END` + tail: the same hint.
- `Laptop_PasswordPrefix_QuotesTheWholeArgument`: `cmd /c echo --password= -encodedCommand ewBkAGIALQBwAHcAfQA=` +
  tail: stderr contains `Quote it: '--password={{db-pw}}'.`
- `Previous_And_File`: `Enc("{db-pw:previous}")` and `Enc("{@values.yaml}")` in two pairs, one tail: two hint lines,
  in argument order.
- `NotOurs_NoHint` (Theory): no tail; tail incomplete (three of four); `-encodedCommand` as the last argument before
  the tail with nothing after it; invalid Base64 (`"!!!"`); Base64 of an odd byte count; decoded text not a token
  (`Enc("Get-Date")`, `Enc("{a b}")`, `Enc("{name}x")`): each gives exactly `ErrorLine(NoTokensText)`.
- `CaseInsensitiveSwitches`: `-EncodedCommand` and `-INPUTFORMAT XML -OUTPUTFORMAT TEXT` still hinted.
- `ControlCharacters_ArePrintedSafely`: `Enc("{@a\u001bb}")` (BracedFileRegex allows it): the hint contains
  `Validation.Printable`'s form and no `\u001b`.
- `WithRealToken_WarnsAndRuns`: `DbVault()`, then `tool {{db-pw}} -encodedCommand <Enc("{other}")>` + tail: exit 0,
  stderr contains `EncodedWarning(...)` exactly once, the PTY started once, and `_pty.Argv` still contains `-encodedCommand` and the Base64 unchanged.
- `BothForms_TogetherInOrder`: a T35 `{a}` argument and an encoded `{b}` pair, no real token: the refusal has
  `BracesHint("{a}")` then `EncodedHint(b)`.
- Break-it-once: drop rule 1's tail check → `NotOurs_NoHint`'s "no tail" case fails; drop the prefix in
  `EncodedHint` → `Laptop_PasswordPrefix_QuotesTheWholeArgument` fails.

## Task 2: ASCII-only prompt text (#375)

- `TswapCore/Prompt.cs`: every `—` becomes ` - ` (spaces as the sentence needs: where `—` already has a space on each
  side, replace just the character with `-`), every `…` becomes `...`. No other wording changes. After it, the file's
  prompt text has no character above 0x7F.
- The `run` bullet (line 36) ends `or PowerShell drops a pair of braces`; make it
  `or PowerShell mangles it (a script block) and run finds no token` (ASCII).
- Test in `PromptTests.cs`: `Prompt_IsAsciiOnly`: `Prompt.GetText("tswap")` has every `char` `< 0x80`; on failure the
  message names the first offending character's index and code point. Break-it-once: put one `—` back → it fails.
- The prompt hash changes: say so in the commit. No test pins its value.

## Task 3: docs

- `docs/install.md`, "Windows notes", first bullet: replace "Unquoted, PowerShell reads `{...}` as a script block and
  passes `{{db-pw}}` on as `{db-pw}`; `run` then finds no token and shows the quoted form." with: "Unquoted, PowerShell
  reads `{...}` as a script block: Windows PowerShell 5.1 passes it on as `-encodedCommand <Base64>` (and an unquoted
  `{{@file}}` doesn't parse at all); `run` then finds no token and shows the quoted form."
- `docs/agent-integration.md`, the "**PowerShell.**" paragraph: "unquoted, PowerShell drops a pair of braces and `run`
  finds no token" → "unquoted, PowerShell turns it into a script block and `run` finds no token".
- No other doc changes.

## Out of scope

- Changing how redirected output is encoded (T35's rule stays).
- PowerShell 7's form: if the owner's PowerShell 7 run shows a third form, that is a follow-up.
- Any change to `BracedTokens`, `BracesHint` or `BracesWarning`.

## Amendments (round 1)

- **A1 (owner sanction, 2026-11-20: "Yes, the implementer may modify the assertions, it's necessary since we're going
  to ASCII").** Task 2 updates exactly two existing assertions in `TswapTests/PromptTests.cs`, and only their
  characters: `Template_ListsSlotEnrolUnderNever` (line 76: the `—` in the expected slot-enrol line becomes `-`) and
  `Prompt_NeverSuggestsApplyForAgents` (line 149: `"run … {{@file}}"` becomes `"run ... {{@file}}"`). What they check
  is unchanged. Name both in the commit message. No other existing assertion changes.
- **A2 (strict decoding).** Rule 2 rejects an odd byte count before decoding, then decodes with
  `new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true)`, catching
  `DecoderFallbackException` as "not ours". The test case that pins it (in `NotOurs_NoHint`): the UTF-16LE bytes of
  `{@a`, then a lone high surrogate `0x00 0xD8`, then the bytes of `b}`, Base64-encoded. A lax decoder turns the
  surrogate into U+FFFD, and `{@a\uFFFDb}` matches `BracedFileRegex`, so the case fails if strictness is lost.
  Break-it-once: swap in `Encoding.Unicode` → this case fails. (The plain "odd byte count" case stays, for the
  pre-check.)
- **A3 (whole text).** A decoded text counts only if, besides matching the regex, it contains no `\n` (the regexes'
  `$` matches before a final newline).
- **A4 (de-duplication test).** `SamePairTwice_OneLine`: the same `{name}` pair twice, one tail → one hint line; the
  same `Braced` once with prefix `--password=` and once without → two lines.
- **A5 (one wording).** The prompt's run bullet ends `or PowerShell turns it into a script block and run finds no
  token` (not "mangles it"), the same words as the `agent-integration.md` change. Task 2's "no other wording changes"
  means: apart from the character swaps and this one clause.
- **A6 (PowerShell 7).** Confirmed on the owner's laptop (PowerShell 7.7.0, #348 comment): the same encoded form, and
  `{{@file}}` doesn't parse in 7 either. In the Why section, drop "the owner's PowerShell 7 run follows"; the T35
  `{name}` detection stays for other shells. Task 3's install.md sentence reads "Windows PowerShell 5.1 and
  PowerShell 7 pass it on as `-encodedCommand <Base64>`" (rest unchanged); note the original sentence wraps across
  lines 273-274.
- **A7 (count).** `Prompt.cs` has 37 `—` and **5** `…` (lines 50, 53, 95, 139, 143); 42 characters in all.
- **A8 (out of scope, named).** `--env NAME={{x}}` unquoted splits the same way, but `--env` parsing refuses before
  `EncodedTokens` runs (T35 has the same gap for `{name}`). Not in this brief.
