# Brief T63: tocomment never deletes a stored value; the broker and the field check match any line break (#419, #417, #412)

Issues: #419, #417, #412 (read each). Milestone 0.3.3. Base: `origin/main` **after T58 (PR #433) merges**. The
brief's line numbers are checked at dcc4c04 (this branch, `brief/t63`, starts there); T58 changes one line of
`SecretMatcher.cs` (`ConsumedMarker`, `:290`) and `ToCommentProcessor.cs:16`, nothing this brief cites. Sharing
`SecretMatcher.cs` with T58 is allowed: leave `:290` and its neighbours alone. If a cited line moved, find it by content.

Read AGENTS.md and CLAUDE.md first, then: `TswapCore/Fingerprints/LineEndingViews.cs` (all);
`TswapCore/SecretMatcher.cs` (`ToComment`'s summary `:90-100`, `RawHits`, `ViewHits` `:52-69`, `ToCommentReport`
`:110-252`); `TswapCore/ToCommentProcessor.cs` (`ContinuationLines` `:128-138`, `IsLikelyBase64` `:263-269`,
`BlockScalarContent`); `TswapCore/SecretProcessor.cs` (`LineDiff`, `SkippedReason`, `SkippedValue`, `ToCommentReport`,
`:7-50`); `TswapCli/Commands/ToCommentCommand.cs` (the diff printing `:51-84`, `WriteWarnings` `:100-116`);
`TswapCore/Broker/BrokerRedactor.cs` (all); `TswapCore/Broker/Templates/BrokerTemplateOutput.cs` (all);
`TswapCore/Fields/FieldSecretCheck.cs` (all); `TswapCore/Fields/FieldRules.cs` (`ValidateValue`, `:45-62`: a field holds
LF but never CR); and the tests `RedactBehaviourPinTests.ContinuationLines_RemovedAfterAReplacement`,
`ToCommentBlockScalarTests` (`ContinuationLineHoldingAnEncodedValue_KeptAndReported`,
`ContinuationRun_StopsAtTheKeptLine_LaterLinesSurvive`, its `ToCommentReport` helper),
`CommandTests.ToComment_ContinuationLine_DoesNotLeakFragmentInOutput`, `ToCommentRoundTrip`,
`RedactEngineTests.Engine_MatchesOracle_OnRandomCorpus` with `TswapTests/PlaintextRedactOracle.cs`,
`BrokerRedactorTests`, `BrokerShortSecretRedactionTests` (`ThroughTemplateOutput`), `BrokerTemplateFixRound1Tests`
(`TheSharedRedactor_CatchesWrappedBase64AndSpacedHex_InStreamAndHeaders`), `FieldSecretCheckTests` (its fixture),
`FieldCommandTests` (`Field`, `Bytes`, `Lf`, `FieldSet_SecretValue_Refused`) and `FieldAdoptTests` (the holder refusal).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change, and no existing test file
changes:** every new test goes in a new file, under the name this brief gives it. The one exception is Task 1's oracle
rule, **sanctioned by the owner on 2026-11-27** (an owner-sanctioned rule change to an otherwise frozen file, as for T50b and T54),
and only if the corpus needs it. If any existing test fails on an assertion, stop and list it. No production message
and no custom test failure text contains a value or the text of a line that holds one.

The three tasks are independent: any order, no shared code. **Files this brief may change:**
`TswapCore/SecretMatcher.cs` (`ToComment`'s and `ToCommentReport`'s summaries, the continuation loop in
`ToCommentReport` and the main loop's skip of kept lines), `TswapCore/SecretProcessor.cs` (the enum and one new
record), `TswapCli/Commands/ToCommentCommand.cs`, `TswapCore/Broker/BrokerRedactor.cs`,
`TswapCore/Broker/Templates/BrokerTemplateOutput.cs`, `TswapCore/Fields/FieldSecretCheck.cs`,
`TswapCore/Fingerprints/LineEndingViews.cs` (one new helper), `TswapTests/PlaintextRedactOracle.cs` (Task 1's conditional
rule only), the new test files named below, and `docs/broker-threat-model.md`. Do not touch `ToCommentProcessor.cs`,
`Validation.cs`, `Apply.cs`, `VaultView.cs`, `RecordVaultStore.cs`, `Prompt.cs`, `FieldEdits.cs`, `FieldSet.cs`,
`docs/commands.md`, `docs/security-model.md` or any csproj (other briefs own them).

## What is wrong (evidence)

All three reproduced at dcc4c04 in a scratch copy with throwaway tests (each passed, which is the bug).

- **#419: tocomment removes a continuation line that holds another stored value.** After replacing a value on line
  `i`, `ToCommentReport` removes every following line that `ContinuationLines` yields: indented deeper than line `i`,
  not blank, and 95% base64 characters, 16 or more (`SecretMatcher.cs:231-241`, `ToCommentProcessor.cs:128-138`,
  `:263-269`). It keeps a line only when it is part of a multi-line occurrence (`:234`) or is block-scalar content
  holding an *encoded* occurrence (`:236`, T22). Any other line holding a stored value goes, with a diff line that
  `--dry-run` prints as `[removed continuation line]` (`ToCommentCommand.cs:75`) and no warning. Repro: stored
  `a = Aaaaaaaaaaaaaaaaaaaa1` and `b = Bbbbbbbbbbbbbbbbbbbb2`;
  `Redact.ToCommentReport("key: Aaaaaaaaaaaaaaaaaaaa1\n    Bbbbbbbbbbbbbbbbbbbb2\nnext: x\n", db)`: `b`'s value is
  gone from `Content`, and `Skipped` and `Unreplaced` are empty. (The issue says "adopting a block"; T20's block
  adoption, `:186-201`, takes a block only when the whole block is one stored value, so the loss is in this loop.)
- **#417: the broker misses a multi-line value printed with other line breaks.** `BrokerRedactor.FormsOf`
  (`BrokerRedactor.cs:106-205`) lists byte forms and `MatchAt` (`:243-249`) compares bytes exactly. No form swaps
  `\r\n` and `\n` (only the wrapped base64 has both, `:174-175`). `BrokerTemplateOutput` takes `ForSecret`'s forms
  (`BrokerTemplateOutput.cs:37`) and repeats the exact compare (`MatchAt`, `:145-151`) and the window (`:47`). Repro:
  `ForSecret("line-one-secret\r\nline-two-secret")` passes `"x line-one-secret\nline-two-secret y"` through unchanged,
  and the other way round.
- **#412: the no-secret-in-a-field check misses a CRLF secret given with LF.** `FieldSecretCheck.Contains` (`:109-114`)
  and `Holders` (`:48-63`) scan with `FingerprintIndex.Scan`, which has no line-ending views
  (`FingerprintIndex.cs:83-112`; only `SecretMatcher.ViewHits` and `FingerprintScanner`, `:285-288`, use
  `LineEndingViews`). A field value may hold LF but not CR (`FieldRules.cs:45-62`), so a CRLF secret pasted into a field
  always arrives in its LF spelling. Repro: an index of `"line-one-secret\r\nline-two-secret"`;
  `FieldSecretCheck.Refusal(index, null, "grafana", "note", "line-one-secret\nline-two-secret")` is null.

## The rules being matched (parser-first)

**Line breaks (Tasks 2 and 3).** Programs print a line break as LF (Unix tools), CRLF (Windows tools, HTTP and SMTP
bodies) or a lone CR (`\r`-redrawn progress output, classic Mac text, serial consoles), and a value can pass through
layers that convert some breaks and not others. Fail closed: in the broker's output matching and in the field check,
**`\r\n`, `\n` and a lone `\r` are all line breaks, in any mix**, and any break in a stored value matches any break in
the text. A lone `\r` inside a value (`10\r20`) then also matches `10\n20`: over-masking and over-refusal are the
fail-closed side. This is broader than T50a's line-ending views (`LineEndingViews.cs:3-18`: `\r\n` and `\n` only, a lone
`\r` is not a line ending), which `redact` and `run` keep (out of scope, below).

**YAML (Task 1).** A line indented deeper than a plain scalar's line continues that scalar (YAML 1.2.2, 7.3.3
"Plain Style", `ns-plain-multi-line`), which is why tocomment removes such lines after a replacement. A double-quoted
scalar ends at its closing quote (7.3.1), so after tocomment writes `key: ""  # tswap: a`, a kept deeper line
`    B` can continue nothing, is no implicit key and no entry of the enclosing block mapping (8.2.2): **keeping the line
as it is makes the file a YAML syntax error** (libyaml, go-yaml, SnakeYAML and YamlDotNet all reject it). What does
parse: "Outside scalar content, comments may appear on a line of their own, independent of the indentation level"
(6.6, "Comments"). A comment line after the complete entry `key: ""  # tswap: a` is valid at any indentation, and the
mapping continues with the next key. So a kept line is **commented out**: its own indentation, then `# `, then its
original text. Inside block-scalar content (8.1) every line is text, so a `#` there would change the content; such a line
is kept exactly as it is, which leaves the block (and the file) valid. A `KEY=value` file (dotenv) reads a line whose
first non-blank character is `#` as a comment too.

## Task 1 (#419): a continuation line holding a stored value is commented out, never removed

**Design.**
- `SkippedReason` (`SecretProcessor.cs:26-34`) gets a third member, `ContinuationLine`: "A continuation line of a
  replaced value (indented deeper, base64-like) that tocomment would have removed; it holds a stored value, so it was
  commented out instead."
- `SecretProcessor.cs` gets `public sealed record CommentedLineDiff(int LineNumber, string Before, string After) :
  LineDiff(LineNumber, Before, After);` (next to `MultiLineDiff`, with a summary: a continuation line commented out
  because it holds a stored value; its text is never printed).
- In `ToCommentReport`'s continuation loop (`SecretMatcher.cs:231-241`) the order is:
  1. a line of a multi-line occurrence: `break` (as today, `:234`);
  2. block content holding an encoded occurrence: `break` (as today, T22, `:236`; still reported in its turn as an
     `UnreplacedLine`);
  3. **new:** when `index.Scan(lines[j])` has any hit (every variant kind, current and previous, burned included, **no**
     token-boundary or whole-value rule, so a value inside a longer base64 run counts; one line has no line break in
     it, so the raw scan is all its views):
     - block content (`blockContent[j]`): add `j` to a new `HashSet<int> keptContinuations`, add one
       `SkippedValue(j + 1, j + 1, token, SkippedReason.InBlockScalar)` per distinct token, and `break` (the line stays
       exactly as it is);
     - otherwise: `var at = Indentation.LeadingWhitespace(lines[j]); var commented = lines[j][..at] + "# " + lines[j][at..];`,
       add `new CommentedLineDiff(j + 1, lines[j], commented)` to `diffs`, set `lines[j] = commented`, add `j` to
       `keptContinuations`, add one `SkippedValue(j + 1, j + 1, token, SkippedReason.ContinuationLine)` per distinct
       token, and **continue** with the next continuation line (so a filler line after it is still removed and the file
       still parses);
  4. otherwise: removed, as today.

  This deviates from #419's sketch ("stop the adoption at that line and report it"): the run goes on past a commented
  line instead of stopping there, because a stop would leave the later filler lines of the same plain scalar in place,
  and those make the file a YAML syntax error again (row 7). The issue's fail-closed core, never deleting a value
  silently, holds either way.

  A token is `hit.IsPrevious ? hit.Name + SecretsDb.PreviousSuffix : hit.Name` (as at `:394`); several distinct tokens
  on one line give one entry each (the final ordering already sorts by line, then token). `ContinuationLines` is lazy
  over `lines` (`ToCommentProcessor.cs:128-138`), and it has already tested line `j` when it yields it, so writing
  `lines[j]` then is safe.
- The main loop skips a line in `keptContinuations` (`continue` straight after the `linesToRemove` check, `:156-163`):
  it gets no other change and no other report.
- `ToComment`'s summary (`:90-95`) and `ToCommentReport`'s summary say "removed, or commented out when it holds a
  stored value (brief T63, #419)".
- `ToCommentCommand`:
  - the diff printing (`:51-84`) prints a `CommentedLineDiff` as `  line N:`, `  - [continuation line holding a stored value]`,
    `  + (commented out)`, never its text (it can hold a fragment of the replaced value, as a removed line can);
  - `WriteWarnings` (`:107-115`) writes a `ContinuationLine` entry as its own line:
    `Warning: line N: the value of 'TOKEN' (or an encoded form of it) is on a continuation line of a replaced value; tocomment commented that line out ('# ' after its indentation) instead of removing it, because it holds a stored value. Move the value out by hand.`
    The other reasons keep today's text. Exit code stays 0.
- **A second run** over the written file reports the commented line as `NotWholeValue` (line 1 holds a marker, so
  nothing is replaced and the continuation loop doesn't run; the main loop then finds the value after a `#`). The file
  content is the same; both warnings are fail-closed. Accepted, and pinned by row 12.

**Tests** (new file `TswapTests/ToCommentContinuationTests.cs`, class `ToCommentContinuationTests`, through
`Redact.ToCommentReport` and `ToCommentRoundTrip.Check`, with `Db(...)` as in `ToCommentBlockScalarTests`; row 6 builds
its `Secret` with `PreviousValue` set, as `RedactEngineTests.S` does, since that `Db` helper can't).
`A = Aaaaaaaaaaaaaaaaaaaa1`, `B = Bbbbbbbbbbbbbbbbbbbb2`, `C = Cccccccccccccccccccc3`, `F = QUJDREVGR0hJSktMTU5PUA==`
(filler: base64-like, no stored value); stored `a = A`, `b = B` unless the row says otherwise. `L1` is
`LineDiff(1, "key: " + A, "key: \"\"  # tswap: a")`; `Cm(n, text)` is `CommentedLineDiff(n, "    " + text, "    # " + text)`.

`ContinuationLine_HoldingAValue_IsCommentedOut_AndReported(int row)`, rows 1-8 and 8a:

| # | Content | `Content` after | `Changes` | `Skipped` |
|---|---|---|---|---|
| 1 | `key: A\n    B\nnext: x\n` | `key: ""  # tswap: a\n    # B\nnext: x\n` | `L1`, `Cm(2, B)` | `(2, 2, "b", ContinuationLine)` |
| 2 | `key: A\n    ` + base64(B) + `\n` | line 2 → `    # ` + base64(B) | `L1`, `Cm(2, base64(B))` | `(2, 2, "b", ContinuationLine)` |
| 3 | `key: A\n    F\n    B\n` | `key: ""  # tswap: a\n    # B\n` | `L1`, `LineDiff(2, "    " + F, "")` (removed), `Cm(3, B)` | `(3, 3, "b", ContinuationLine)` |
| 4 | `key: A\n    XXXX` + B + `YYYY\n` (B inside a longer run) | line 2 commented out | `L1`, `Cm(2, "XXXX" + B + "YYYY")` | `(2, 2, "b", ContinuationLine)` |
| 5 | `key: A\n    ` + base64(A) + `\n` (A's own encoded form) | line 2 commented out | `L1`, `Cm(2, base64(A))` | `(2, 2, "a", ContinuationLine)` |
| 6 | as 1, `b` rotated so B is its previous value | as 1 | as 1 | `(2, 2, "b:previous", ContinuationLine)` |
| 7 | `key: A\n    B\n    F\n` | `key: ""  # tswap: a\n    # B\n` | `L1`, `Cm(2, B)`, `LineDiff(3, "    " + F, "")` (removed) | `(2, 2, "b", ContinuationLine)` |
| 8 | `key: A\n    B` + base64(C) + `\n`, stored `c = C` too | line 2 commented out | `L1`, `Cm(2, B + base64(C))` | `(2, 2, "b", …)`, `(2, 2, "c", …)` |
| 8a | `key: A\n    B\n    C\n`, stored `c = C` too (a value on each of two continuation lines) | `key: ""  # tswap: a\n    # B\n    # C\n` | `L1`, `Cm(2, B)`, `Cm(3, C)` | `(2, 2, "b", ContinuationLine)`, `(3, 3, "c", ContinuationLine)` |

Facts:
- `ContinuationLine_WithNoValue_IsRemovedAsBefore` (row 9): `key: A\n    F\n` → `key: ""  # tswap: a\n`, `L1` and
  `LineDiff(2, "    " + F, "")`, `Skipped` empty (today's behaviour; `RedactBehaviourPinTests.ContinuationLines_RemovedAfterAReplacement`
  pins it too and stays unchanged).
- `ContinuationLine_InBlockContent_HoldingAPlainValue_KeptAsItIs` (row 10): `script: |\n  export A=` + A + `\n    B\n`
  → line 3 unchanged, `Changes` is line 2's replacement only, `Skipped` `(3, 3, "b", InBlockScalar)`.
  (`ToCommentBlockScalarTests.ContinuationLineHoldingAnEncodedValue_KeptAndReported` stays an `UnreplacedLine` with no
  `Skipped` entry.)
- `ContinuationLine_CommentedOut_EveryLineIsAKeyOrAComment` (row 11). There is no YAML parser among the test
  dependencies (no YamlDotNet in any csproj), so this is a structural assertion: for each of rows 1-8 and 8a, every line of
  `Content` after is empty, or matches `^[A-Za-z]\w*: ` at column 0, or has `#` as its first non-blank character.
- `ToComment_SecondRun_OverACommentedLine_ReportsItAsNotAWholeValue` (row 12): row 1's `Content` after, run again →
  `Content` unchanged, `Changes` empty, `Skipped` `(2, 2, "b", NotWholeValue)`.

**Command test** (new file `TswapTests/ToCommentContinuationCommandTests.cs`, class
`ToCommentContinuationCommandTests`, with a `FleetMachine` as `FieldCommandTests` has: `_m.Ok(value, "ingest", name)`,
`_m.Run("", ["tocomment", path, ...])`, stdout and stderr through `Lf`, CRLF to LF, so Windows passes):
`ToCommentCommand_ContinuationLineHoldingAValue_CommentedOut_Warned_NoLeak`. A file with row 1's content;
`tocomment FILE --dry-run` exits 0, leaves the file, prints `  - [continuation line holding a stored value]` and
`  + (commented out)` and not `[removed continuation line]`; then `tocomment FILE` exits 0, the file is row 1's
`Content` after, and stderr holds the full warning for `line 2` and `'b'` exactly; neither A nor B is in stdout or stderr
of either run.

**Oracle (sanctioned by the owner on 2026-11-27).** Run `Engine_MatchesOracle_OnRandomCorpus` and the other tests that compare with the oracle (`ToCommentWholeValueTests`,
`ToCommentLineBreakTests`, `RedactBehaviourPinTests`) after the change. If every oracle comparison passes, leave
`PlaintextRedactOracle.cs` alone and say so in the report. If it differs on a continuation line, this rule mirrors
production and is the only change: in the `ToCommenter` loop (`PlaintextRedactOracle.cs:90-108`, after the
`IsLikelyBase64` check), when any entry's `SearchText` of the match list occurs in `nextLine` (ordinal `Contains`, every
kind, no boundary or whole-value rule: what `FingerprintIndex.Scan` sees), the line is kept: in block content
(`ToCommentProcessor.BlockScalarContent` of the LF-split lines) the loop breaks; otherwise the line is commented out as
production does (a `CommentedLineDiff` in `diffs`) and the loop goes on. Kept lines go into a set that the outer loop
in `Processor.Process` skips unchanged; only `ToCommenter` fills it (gated on `ShouldRemoveContinuationLines()`), so
`Redactor` is unaffected. The class summary's list of sanctioned changes gets "T63, 2026-11-27: a continuation
candidate that holds a value is commented out (or kept in block content), never removed". The owner sanctioned this
oracle change on 2026-11-27; commit it with that line in the message. Any other difference: stop
and report; don't change the seed or the generator.

**Break it once:** delete step 3 (the new `index.Scan(lines[j])` branch): rows 1-8, 8a, 10 and the command test must
fail. (Row 11 pins where the `#` goes, not the branch: without step 3 the lines are removed and the file is still keys
only.)

## Task 2 (#417): the broker matches any line break as any line break

**Design.**
- `BrokerRedactor` gets three `internal static` helpers, used by both redactors. A **break** is `\r\n`, or a lone `\r`
  (not followed by `\n`), or a `\n` (not preceded by `\r`).
  - `int MatchLength(ReadOnlySpan<byte> form, ReadOnlySpan<byte> data, int at)`: walks `form` from 0 and `data` from
    `at`. A break in the form matches a break in the data, consuming two or one bytes on each side as found (in the
    data, `\r\n` is taken whole when both bytes are there); every other byte matches only itself. Returns the data
    bytes consumed, or 0 when the form doesn't match there or runs past `data`'s end.
  - `int MaxMatchLength(ReadOnlySpan<byte> form)`: `form.Length` plus the number of one-byte breaks in it (each can
    match `\r\n`).
  - `void MarkFirstBytes(ReadOnlySpan<byte> form, bool[] table)`: marks `form[0]`; a form starting with a break marks
    both `\r` and `\n`.
- `FormsOf` ends by adding, for every form so far that holds a one-byte break, its **CRLF spelling** (every break
  written `\r\n`), deduplicated as `Add` does. That spelling is never needed to match (the tolerant compare covers it);
  it is listed so the longest form is the longest possible match. **The window rule stays exactly "longest form − 1"**
  (`Window`, `:41`, `:48-49`), which `Window_IsLongestFormMinusOne_AndProcessNeverHoldsMore` and
  `TheSharedRedactor_CatchesWrappedBase64AndSpacedHex_InStreamAndHeaders` assert unchanged. The arithmetic: a form `f`
  with `o` other bytes, `c` `\r\n` breaks, `n` bare `\n` and `r` lone `\r` has `|f| = o + 2c + n + r`. Each break
  consumes at most two data bytes, so the longest match of `f` is `o + 2(c + n + r) = |f| + n + r = MaxMatchLength(f)`,
  which is the length of its CRLF spelling `U(f)` (`o` bytes plus `c + n + r` two-byte breaks). `U(f)` has no one-byte
  break, so its own longest match is `|U(f)|`. Hence the longest possible match over all forms is the longest form in the
  list, and with `Window = longest − 1` every match starting before `safeEnd = data.Length − Window` fits in the
  buffer (`L ≤ Window + 1`). The same bound covers the byte after a `\r` that ends a form's break: it lies inside
  `MaxMatchLength`, so whether a data `\r` is followed by `\n` is always known when the match is decided (no
  dependence on chunking). This relies on both constructors sorting the forms longest first **after** the CRLF
  spellings are added (`BrokerRedactor` `:76`, `:97`; `BrokerTemplateOutput` `:44`).
- `BrokerRedactor.MatchAt` (`:243-249`) and `BrokerTemplateOutput.MatchAt` (`:145-151`) return the first
  `MatchLength(form, data, i) > 0` over the forms in their order (longest form first, as today). Both constructors fill
  their first-byte tables with `MarkFirstBytes`. `BrokerTemplateOutput` keeps its window as `_forms[0].Length - 1`
  (`:47`). `Contains` (header values) is unchanged: it goes through `MatchAt`.
- `ForSecret`'s NFC/NFD spellings (`:78-95`) go through `FormsOf`, so they get the CRLF spellings too.
- The class summary and `FormsOf`'s doc say: "Brief T63 (#417): each break in a form (`\r\n`, `\n` or a lone `\r`)
  matches any break in the output, in any mix, at least as broadly as `redact` and `run` match line endings."

**Tests** (new file `TswapTests/BrokerLineEndingRedactionTests.cs`, class `BrokerLineEndingRedactionTests`, every test
`[UnixFact("the broker is Unix only")]`/`[UnixTheory(...)]` like `BrokerRedactorTests`).
`V2(eol) = "line-one-secret" + eol + "line-two-secret"`,
`V3(e1, e2) = "first-line-value" + e1 + "second-line-value" + e2 + "third-line-value"`.

`Redactor_MasksAValue_PrintedWithOtherLineBreaks(int row)` runs each row through `BrokerRedactor` (`Process` in one
chunk, then split at every byte position, then one byte per chunk; `Flush`);
`TemplateOutput_MasksAValue_PrintedWithOtherLineBreaks(int row)` runs it through `BrokerTemplateOutput` (one chunk and
one byte per chunk; stdout). Printed text is between `x ` and ` y`.

| # | Stored | Printed | Output |
|---|---|---|---|
| 1 | `V2("\r\n")` | `V2("\n")` | `x [REDACTED] y` |
| 2 | `V2("\n")` | `V2("\r\n")` | `x [REDACTED] y` |
| 3 | `V3("\r\n", "\r\n")` | `V3("\r\n", "\n")` | `x [REDACTED] y` |
| 4 | `V3("\n", "\n")` | `V3("\n", "\r\n")` | `x [REDACTED] y` |
| 5 | `V2("\r\n")` | `V2("\r")` (a lone CR) | `x [REDACTED] y` |
| 6 | `V2("\r")` | `V2("\n")` | `x [REDACTED] y` |
| 7 | `V3("\n", "\n")` | `V3("\r", "\r\n")` | `x [REDACTED] y` |
| 8 | `V2("\n")` | `V2("\n\n")` (two breaks) | unchanged |
| 9 | NFC `"café-line-one\r\ncafé-line-two"` | its NFD spelling with `\n` | `x [REDACTED] y` |
| 10 | the 120 ASCII bytes `string.Concat(Enumerable.Repeat("abcdefghij", 12))` | its base64 wrapped at 64 with `\r\n` | `x [REDACTED] y` |

Facts:
- `Forms_LongestFormMinusOne_CoversEveryMatch`: for each stored value above, `Window == Forms.Max(f => f.Length) - 1`;
  for every form, `MaxMatchLength(form) - 1 <= Window`; and, structurally, **for every form holding a one-byte break,
  its CRLF spelling is in `Forms`**. The first two hold even without the CRLF spellings for these values (the longest
  form is the break-free spaced hex, `3L − 1` bytes), so the third is the one that pins them. Row 10's value is the
  concrete case: its base64 (160 characters) wrapped at 64 with `\n` has two breaks, and its CRLF spelling (`160 + 2·2`
  = 164 bytes) must be in `Forms`.
- `Forms_OfAValueWithNoLineBreak_HoldNoLineBreak`: no form of `FormsOf(UTF-8 of "s3cr3t-Value_+/=é", null)` holds `\r`
  or `\n` (it is too short to wrap).
- `TemplateOutput_MatchStartingOnStdout_ReplacedOnStdout`: row 1 through `BrokerTemplateOutput` with the first half of
  the printed text on stdout and the rest on stderr puts one `[REDACTED]` on stdout (the stream the match started in),
  as T9 decided.

**Break it once:** (1) in `MatchLength`, compare a form's break byte for byte: rows 1, 3, 4, 5, 6, 7 and 9 must fail
(rows 2 and 10 still pass then, because the CRLF spellings match them byte for byte; they pin the spellings only under
this mutated compare, since the shipped tolerant compare matches them without); (2) drop the CRLF spellings from
`FormsOf`: the structural assertion of `Forms_LongestFormMinusOne_CoversEveryMatch` (every form with a one-byte break
has its CRLF spelling in `Forms`; row 10's 164-byte spelling) must fail; (3) put `BrokerTemplateOutput.MatchAt` back to its
exact compare: `TemplateOutput_MasksAValue_PrintedWithOtherLineBreaks` rows 1, 3-7 and 9 must fail.

## Task 3 (#412): the field check scans every line-break spelling

**Design.**
- `LineEndingViews` gets `internal static string WithLineBreaks(string text, string lineBreak)`: `text` with every
  break (`\r\n`, a lone `\r`, a bare `\n`, in any mix; the same definition as Task 2) written as `lineBreak`. Its
  summary says it is for checks that compare whole spellings (the field check), not for the views, which keep their
  span maps and T50a's two endings.
- `FieldSecretCheck` gets `private static IEnumerable<string> Spellings(string text)`: for the NFC form
  (`FieldRules.NormaliseValue`) and for the text as given (when it differs), the text itself and
  `WithLineBreaks(…, "\n")`, `WithLineBreaks(…, "\r\n")` and `WithLineBreaks(…, "\r")`; distinct (ordinal). `Contains`
  is true when any spelling's `Scan` has a hit; `Holders` takes the hits of every spelling. The refusal text does not
  change. The summaries (`:7-16`, `:26-31`, `:42-47`, `:104-108`) say "in its NFC form and as given, each also with its
  line breaks written as LF, CRLF and CR (brief T63, #412)".
- This finds a stored value whose breaks are all one kind, whatever mix the field value has. A stored value with mixed
  breaks of its own is found only in its own spelling or when the field's breaks happen to match it (out of scope, as
  for `redact`).
- `FieldsContaining` goes through `Contains`, so the value commands' warning gets the same spellings.

**Tests** (new file `TswapTests/FieldSecretCheckLineBreakTests.cs`, class `FieldSecretCheckLineBreakTests`, with its
own copy of `FieldSecretCheckTests`' fixture: constructor, `Dispose`, `NewStore`, `View`, `Stored`, `SameWrite`, `Check`,
`SetFields`, `Expected`; the stored secret ingested with `_m.Ok(value, "ingest", name)`).

`Refusal_FindsAStoredValue_WhateverItsLineBreaks(int row)`:

| # | Stored | Field value checked | Outcome |
|---|---|---|---|
| 1 | `pem = "line-one-secret\r\nline-two-secret"` | `"line-one-secret\nline-two-secret"` | `Expected` (refused) |
| 2 | as 1 | `"note: line-one-secret\nline-two-secret, see vault"` | refused |
| 3 | as 1 | `"line-one-secret\nline-two-secreT"` | null |
| 4 | `pem = "line-one-secret\nline-two-secret"` | `"line-one-secret\r\nline-two-secret"` (a CR, as a caller can pass before validation) | refused |
| 5 | `pem = "line-one-secret\rline-two-secret"` (lone CR) | `"line-one-secret\nline-two-secret"` | refused |
| 6 | `pem = "café-line-one\r\ncafé-line-two"` (NFC) | its NFD spelling with `\n` | refused |

Facts:
- `Holders_FindAStoredValue_WhateverItsLineBreaks`: stored as row 1;
  `Holders(Stored(), "line-one-secret\nline-two-secret")` is `[("pem", false)]`.
- `FieldsContaining_FindsAFieldValue_WhateverItsLineBreaks`: a field `note = "line-one-secret\nline-two-secret"` on `s`
  (set with `SetFields`); `FieldsContaining(view, SameWrite("line-one-secret\r\nline-two-secret"))` is `["s.note"]`.

**Command test** (new file `TswapTests/FieldSecretLineBreakCommandTests.cs`, class
`FieldSecretLineBreakCommandTests`, with `FieldCommandTests`' `FleetMachine`, `Field`, `Bytes` and `Lf` helpers copied):
`FieldSet_MultiLineSecretWithOtherLineBreaks_Refused`. `pem` ingested as row 1's stored value and `s` ingested;
`Field("set", "s", "note=line-one-secret\nline-two-secret")` exits 1 with the refusal for `s.note`, names neither `pem`
nor the value, and leaves `s`'s bytes unchanged.

**Break it once:** drop the `"\r\n"` spelling from `Spellings`: rows 1, 2 and 6, `Holders_…`, `FieldsContaining_…` and
the command test must fail; drop the `"\n"` spelling: row 4 must fail; drop the `"\r"` spelling: row 5 must fail.

## Task 4: docs

- `docs/broker-threat-model.md`, the list of forms (`:27-39`): one bullet, "since 0.3.3, each line break in any of these
  (`\r\n`, `\n` or a lone `\r`) matches any line break in the output, in any mix". The window paragraph (`:51-55`) is
  still true ("longest form − 1"), but its parenthetical names the wrong form: correct "the wrapped base64 form of a
  long value is the longest" to "the spaced-hex form of a long value is the longest" (`3L − 1` bytes against about
  `1.37L` for wrapped base64; `BrokerRedactor.cs:180-181`), and after it add "each form's spelling with every line break
  as `\r\n` is listed as a form".
- No other doc changes: `docs/commands.md` (the field bullet, `:227-234`) already promises that every value is checked
  against every stored value, and neither it nor any other doc describes the continuation-line removal.
  (`docs/commands.md` and `docs/security-model.md` are T58's and T62's.)
- In your report, one 0.3.3 release-note line per issue. #419's says: tocomment no longer deletes a continuation line
  that holds a stored value; it comments the line out (`# ` after its indentation), so the file still parses, and warns
  that the value is to be moved out by hand.

## Out of scope

- tocomment's YAML model (continuation lines are still removed when they hold no value; #171 is the long-term answer).
- A lone `\r` as a line ending in `redact` and `run` (T50a's views): they keep `\r\n` and `\n` only. Propose a follow-up
  issue in the report.
- A break doubled by a converting layer (`\r\r\n`) is two breaks and does not match a value's one.
- A matcher shared between the broker (bytes) and `redact` (text): the broker keeps its byte forms.
- #411 and #413 (they need `Validation.cs`, `RunCommand.cs` and `EndToEndTests.cs`, which T58 changes; a later brief).
- Field values with a CR (refused by `FieldRules.ValidateValue` anyway).

## Amendment history

- **Round 1 (MiMo r1, 2026-11-27; controller rulings).**
  - I-1: the claim that keeping the line still parses was false. A kept line is now commented out (its indentation,
    `# `, its text), or kept as it is in block content; the YAML rules are cited, rows 1-8 updated, the run continues
    past a commented line, and row 11 checks the structure (no YAML parser is a test dependency). There is a new
    `CommentedLineDiff`, exact warning and dry-run texts, and a release-note line.
  - I-2: the oracle rule now mirrors production (any occurrence over the match list, no boundary or whole-value rule;
    the outer loop skips kept lines, gated on `ToCommenter`). Sanctioned by the owner on 2026-11-27.
  - I-3: every new test has its own name in a new file; no existing test file changes.
  - I-4: a lone CR is a line break, in any mix, for the broker and the field check. Row 5 now expects masking, rows 6, 7
    and field row 5 were added, and the window arithmetic is shown. The field check now scans whole spellings
    (`WithLineBreaks` to LF, CRLF and CR) instead of T50a's two views.
  - M-1: break-it-once lists corrected (rows 2 and 10 pin the CRLF spellings).
  - M-2: the wording is now "at least as broadly as `redact` and `run`"; the field side's mixed-stored-value gap is stated.
  - M-3: the second-run reason flip is accepted and pinned (row 12).
  - M-4: `SecretMatcher.cs` summaries updated in Task 1; row 10 has ASCII bytes; removals are written as
    `LineDiff(n, before, "")`; command tests normalise CRLF.
  - Header: the base is main after T58 merges; sharing `SecretMatcher.cs` with T58 is allowed.
- **Round 2 (MiMo r2, 2026-11-27; controller rulings).** I-A: the CRLF spellings are pinned by a structural assertion
  in `Forms_LongestFormMinusOne_CoversEveryMatch` (row 10's 64-wrap spelling; MiMo's 166 bytes recomputed as
  164: 160 base64 characters plus two `\r`), cited in break-it-once (2); the rows 2/10 parenthetical is corrected.
  M-1: row 11 dropped from Task 1's break-it-once. M-2: row 6 builds its `Secret` with `PreviousValue`. M-3: the
  deviation from #419's "stop the adoption" sketch is stated, with the reason. M-4: Task 4 corrects the threat model's
  "longest form" parenthetical (spaced hex). M-5: the stale #412 milestone note is dropped (it has 0.3.3). M-6: row 8a
  (a value on each of two continuation lines). Also from the review: every oracle comparison is named, and two
  off-by-one citations are fixed (`SecretMatcher.cs:156-163`, `BrokerTemplateOutput.cs:44`).
