# Brief T63: no stored value is lost or missed for its line endings (#419, #417, #412)

Issues: #419, #417, #412 (read each). Milestone 0.3.3. Base: `origin/main` at dcc4c04 (this brief's branch,
`brief/t63`, starts there). Read AGENTS.md and CLAUDE.md first, then: `TswapCore/Fingerprints/LineEndingViews.cs`
(all); `TswapCore/SecretMatcher.cs` (`RawHits`, `ViewHits` `:52-69`, `ToCommentReport` `:134-252`);
`TswapCore/ToCommentProcessor.cs` (`ContinuationLines` `:128-138`, `IsLikelyBase64` `:263-269`);
`TswapCore/SecretProcessor.cs` (`SkippedReason`, `SkippedValue`, `ToCommentReport`, `:25-50`);
`TswapCli/Commands/ToCommentCommand.cs` (`WriteWarnings`, `:100-116`); `TswapCore/Broker/BrokerRedactor.cs` (all);
`TswapCore/Broker/Templates/BrokerTemplateOutput.cs` (all); `TswapCore/Fields/FieldSecretCheck.cs` (all);
`TswapCore/Fields/FieldRules.cs` (`ValidateValue`, `:45-62`: a field holds LF but never CR); and the tests
`RedactBehaviourPinTests.ContinuationLines_RemovedAfterAReplacement`,
`ToCommentBlockScalarTests.ContinuationLineHoldingAnEncodedValue_KeptAndReported` and
`ContinuationRun_StopsAtTheKeptLine_LaterLinesSurvive`, `CommandTests.ToComment_ContinuationLine_DoesNotLeakFragmentInOutput`,
`RedactEngineTests.Engine_MatchesOracle_OnRandomCorpus` with `TswapTests/PlaintextRedactOracle.cs`,
`BrokerRedactorTests`, `BrokerShortSecretRedactionTests` (`ThroughTemplateOutput`), `BrokerTemplateFixRound1Tests`
(`TheSharedRedactor_CatchesWrappedBase64AndSpacedHex_InStreamAndHeaders`), `FieldSecretCheckTests`,
`FieldCommandTests.FieldSet_SecretValue_Refused` and `FieldAdoptTests` (the holder refusal).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change.** The one pre-sanctioned
exception is the oracle rule in Task 1 (an owner-sanctioned rule change to an otherwise frozen file, as T50b and T54
did), and only if the corpus needs it. If any other existing test fails on an assertion, stop and list it. No
production message and no custom test failure text contains a value or the text of a line that holds one.

The three tasks are independent: any order, no shared code. **Files this brief may change:**
`TswapCore/SecretMatcher.cs` (only the continuation loop in `ToCommentReport` and the main loop's skip of kept lines),
`TswapCore/SecretProcessor.cs` (the enum), `TswapCli/Commands/ToCommentCommand.cs`, `TswapCore/Broker/BrokerRedactor.cs`,
`TswapCore/Broker/Templates/BrokerTemplateOutput.cs`, `TswapCore/Fields/FieldSecretCheck.cs`,
`TswapCore/Fingerprints/LineEndingViews.cs`, `TswapTests/PlaintextRedactOracle.cs` (Task 1's conditional rule only), new
test files, and `docs/broker-threat-model.md`. Do not touch `ToCommentProcessor.cs`, `Validation.cs`, `Apply.cs`,
`VaultView.cs`, `RecordVaultStore.cs`, `Prompt.cs`, `FieldEdits.cs`, `FieldSet.cs`, `docs/commands.md`,
`docs/security-model.md` or any csproj (other briefs own them). T58 (PR #433, unmerged) changes one line of
`SecretMatcher.cs` (`ConsumedMarker`, `:290`); leave that line and its neighbours alone.

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
- **#417: the broker misses a multi-line value printed with the other line endings.** `BrokerRedactor.FormsOf`
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

**The rules being matched** (parser-first). Line endings are T50a's line-ending views (`LineEndingViews.cs:3-18`):
`\r\n` and `\n` are the two line endings, a lone `\r` is not one, and a value is found in the text as it is, with
every `\r\n` read as `\n` (folded), and with every bare `\n` read as `\r\n` (unfolded). A single line of a file split
on LF has no line ending in it, so for one line the raw scan is all its views. For YAML (#419): a line indented deeper
than a plain scalar's key line continues that scalar (YAML 1.2.2, 7.3.3 "Plain Style", multi-line plain scalars), which
is why tocomment removes such lines after a replacement. Keeping one changes the YAML the file parses to, but loses no
value: that is the fail-closed side.

## Task 1 (#419): a continuation line holding a stored value stays, with a warning

**Design.**
- `SkippedReason` (`SecretProcessor.cs:26-34`) gets a third member, `ContinuationLine`: "A line tocomment would have
  removed as a continuation of a replaced value (indented deeper, base64-like), kept because it holds a stored value."
- In `ToCommentReport`'s continuation loop (`SecretMatcher.cs:231-241`), after the two existing `break`s and before
  `linesToRemove.Add(j)`: when `index.Scan(lines[j])` has any hit (every variant kind, current and previous, burned
  included, **no** token-boundary rule, so a value inside a longer base64 run counts), the loop breaks. Line `j` is
  added to a new `HashSet<int> keptContinuations`, and one `SkippedValue(j + 1, j + 1, token, SkippedReason.ContinuationLine)`
  per distinct token among those hits (`hit.IsPrevious ? hit.Name + SecretsDb.PreviousSuffix : hit.Name`, as at
  `:394`) goes into `skipped`. The existing checks keep their order: a line T22 keeps (block content with an encoded
  occurrence) is still reported in its turn as an `UnreplacedLine`, not as `ContinuationLine`.
- The main loop skips a line in `keptContinuations` (`continue` straight after the `linesToRemove` check, `:155-162`):
  it stays exactly as it is, is not replaced and gets no other report. Lines after it go through the main loop as
  usual (the removal stopped, as in `ContinuationRun_StopsAtTheKeptLine_LaterLinesSurvive`).
- `ToCommentCommand.WriteWarnings` (`:110-112`) gets the third reason text:
  `it is on a line after a replaced value that tocomment removes as a continuation only when it holds no stored value`.
  The full warning is then
  `Warning: line 2: the value of 'b' (or an encoded form of it) was left in place: it is on a line after a replaced value that tocomment removes as a continuation only when it holds no stored value. If it is the secret there, move it out by hand.`
  Exit code stays 0.

**Tests** (new file `TswapTests/ToCommentContinuationTests.cs`, through `Redact.ToCommentReport` with
`ToCommentRoundTrip.Check`, as `ToCommentBlockScalarTests` does). `A = Aaaaaaaaaaaaaaaaaaaa1`,
`B = Bbbbbbbbbbbbbbbbbbbb2`, `F = QUJDREVGR0hJSktMTU5PUA==` (filler: base64-like, no stored value), stored `a = A`,
`b = B` unless the row says otherwise.

| # | Content | `Content` after | `Changes` | `Skipped` |
|---|---|---|---|---|
| 1 | `key: A\n    B\nnext: x\n` | `key: ""  # tswap: a\n    B\nnext: x\n` | line 1 only | `(2, 2, "b", ContinuationLine)` |
| 2 | `key: A\n    ` + base64(B) + `\n` | line 2 kept | line 1 only | `(2, 2, "b", ContinuationLine)` |
| 3 | `key: A\n    F\n    B\n` | `key: ""  # tswap: a\n    B\n` | line 1; line 2 → `""` | `(3, 3, "b", ContinuationLine)` |
| 4 | `key: A\n    XXXX` + B + `YYYY\n` (B inside a longer run) | line 2 kept | line 1 only | `(2, 2, "b", ContinuationLine)` |
| 5 | `key: A\n    ` + base64(A) + `\n` (A's own encoded form) | line 2 kept | line 1 only | `(2, 2, "a", ContinuationLine)` |
| 6 | as 1, `b` rotated so B is its previous value | line 2 kept | line 1 only | `(2, 2, "b:previous", ContinuationLine)` |
| 7 | `key: A\n    B\n    F\n` | lines 2 and 3 kept | line 1 only | `(2, 2, "b", ContinuationLine)` |
| 8 | `key: A\n    B` + base64(C) + `\n`, stored `c = Cccccccccccccccccccc3` too | line 2 kept | line 1 only | `(2, 2, "b", …)`, `(2, 2, "c", …)` (ordinal) |
| 9 | `key: A\n    F\n` (control: no stored value) | `key: ""  # tswap: a\n` | line 1; line 2 → `""` | empty |
| 10 | `script: \|\n  export A=` + A + `\n    B\n` (block content, plain B) | line 3 kept | line 2 only | `(3, 3, "b", ContinuationLine)` |

Row 9 is today's behaviour (`RedactBehaviourPinTests.ContinuationLines_RemovedAfterAReplacement` pins it too and stays
unchanged). `ToCommentBlockScalarTests.ContinuationLineHoldingAnEncodedValue_KeptAndReported` stays unchanged: its
line is still an `UnreplacedLine`, with no `ContinuationLine` entry.

**Command test** (in the new file or `CommandTests`, as `ToComment_ContinuationLine_DoesNotLeakFragmentInOutput`): a
file with row 1, `tocomment FILE` exits 0, the file is row 1's `Content after`, stderr holds the full warning text above
for line 2 and `'b'`; `tocomment FILE --dry-run` on the original prints no `[removed continuation line]`; neither A nor
B appears in stdout or stderr.

**Oracle.** Run `Engine_MatchesOracle_OnRandomCorpus` after the change. If it passes, leave
`PlaintextRedactOracle.cs` alone. If it shows a difference on a continuation line, this rule is pre-sanctioned for the
oracle's `ToCommenter` loop (`PlaintextRedactOracle.cs:90-108`), and only it: a candidate line on which
`ReplaceLine(nextLine, matchList)` would change anything stops the removal (`break`), and the outer loop then skips
that line unchanged. Add it to the class summary's list of sanctioned changes ("T63, 2026-11-27: a continuation
candidate that holds a value stops the removal and stays"). Any other difference: stop and report; don't change the
seed or the generator.

**Break it once:** delete the new `index.Scan(lines[j])` break; rows 1-8 and 10 and the command test must fail.

## Task 2 (#417): the broker matches a line break in either spelling

**Design.**
- `BrokerRedactor` gets three `internal static` helpers, used by both redactors:
  - `int MatchLength(ReadOnlySpan<byte> form, ReadOnlySpan<byte> data, int at)`: walks `form` from 0 and `data` from
    `at`. A line break in the form (`\r\n`, or a `\n` not preceded by `\r`) matches a line break in the data (`\r\n`,
    else `\n`), consuming two or one bytes on each side as found; every other byte, a lone `\r` included, matches only
    itself. Returns the data bytes consumed, or 0 when the form doesn't match there or runs past `data`'s end.
  - `int MaxMatchLength(ReadOnlySpan<byte> form)`: `form.Length` plus the number of bare `\n` in it (each can match
    `\r\n`).
  - `void MarkFirstBytes(ReadOnlySpan<byte> form, bool[] table)`: marks `form[0]`; a form starting with a line break
    also marks the other spelling's first byte (`\r` for a bare `\n`, `\n` for `\r\n`).
- `FormsOf` ends by adding, for every form so far that holds a bare `\n`, its unfolded spelling (every bare `\n` as
  `\r\n`), deduplicated as `Add` does. That spelling is never needed to match (the tolerant compare already covers it);
  it is listed so the longest form is the longest possible match, and **the window rule stays exactly "longest form −
  1"** (`Window`, `:41`, `:48-49`), which `Window_IsLongestFormMinusOne_AndProcessNeverHoldsMore` and
  `TheSharedRedactor_CatchesWrappedBase64AndSpacedHex_InStreamAndHeaders` assert unchanged.
- `BrokerRedactor.MatchAt` (`:243-249`) and `BrokerTemplateOutput.MatchAt` (`:145-151`) return the first
  `MatchLength(form, data, i) > 0` over the forms in their order (longest form first, as today). Both constructors fill
  their first-byte tables with `MarkFirstBytes`. `BrokerTemplateOutput` keeps its window as `_forms[0].Length - 1`
  (`:47`), now equal to the longest possible match for the same reason. `Contains` (header values) is unchanged: it
  goes through `MatchAt`.
- `ForSecret`'s NFC/NFD spellings (`:78-95`) go through `FormsOf`, so they get the unfolded spellings too.
- The class summary and `FormsOf`'s doc say what was added ("Brief T63 (#417): a line break in a form matches `\n` or
  `\r\n` in the output, mixed too, as `redact`'s line-ending views do; a lone `\r` is not a line ending").

**Tests** (new file `TswapTests/BrokerLineEndingRedactionTests.cs`, `[UnixFact("the broker is Unix only")]` like
`BrokerRedactorTests`). `V2(eol) = "line-one-secret" + eol + "line-two-secret"`,
`V3(e1, e2) = "first-line-value" + e1 + "second-line-value" + e2 + "third-line-value"`. Each row runs through
`BrokerRedactor` (`Process` in one chunk, then split at every byte position, then one byte per chunk; `Flush`) and
through `BrokerTemplateOutput` (one chunk and one byte per chunk; stdout), and expects the output shown.

| # | Stored | Printed (between `x ` and ` y`) | Output |
|---|---|---|---|
| 1 | `V2("\r\n")` | `V2("\n")` | `x [REDACTED] y` |
| 2 | `V2("\n")` | `V2("\r\n")` | `x [REDACTED] y` |
| 3 | `V3("\r\n", "\r\n")` | `V3("\r\n", "\n")` | `x [REDACTED] y` |
| 4 | `V3("\n", "\n")` | `V3("\n", "\r\n")` | `x [REDACTED] y` |
| 5 | `V2("\r\n")` | `V2("\r")` (a lone CR) | unchanged |
| 6 | `V2("\n")` | `V2("\n\n")` (two breaks) | unchanged |
| 7 | NFC `"café-line-one\r\ncafé-line-two"` | its NFD spelling with `\n` | `x [REDACTED] y` |
| 8 | a 120-byte value | its base64 wrapped at 64 with `\r\n` | `x [REDACTED] y` |

Two more facts: (a) for each stored value above, `Window == Forms.Max(f => f.Length) - 1` and, for every form,
`MaxMatchLength(form) - 1 <= Window`; (b) a value whose forms hold no line break gets no new form: no form of
`FormsOf(UTF-8 of "s3cr3t-Value_+/=é", null)` holds `\r` or `\n` (it is too short to wrap). Row 1 through
`BrokerTemplateOutput` with the first half on stdout and the rest on stderr puts one `[REDACTED]` on stdout (the stream
the match started in), as T9 decided.

**Break it once:** (1) in `MatchLength`, compare a form's line break byte for byte; rows 1-4, 7 and 8 must fail; (2)
drop the unfolded spellings from `FormsOf`; fact (a) must fail; (3) put `BrokerTemplateOutput.MatchAt` back to its exact
compare; the template half of rows 1-4 must fail.

## Task 3 (#412): the field check scans every line-ending spelling

**Design.**
- `LineEndingViews` gets `internal static string? FoldedText(string text)` (the folded view as a string, or null when
  `HasCrLf` is false) and `internal static string? UnfoldedText(string text)` (the unfolded view, or null when
  `HasBareLf` is false), built with `Fold`/`Unfold` so there is still one definition of the views.
- `FieldSecretCheck` gets `private static IEnumerable<string> Spellings(string text)`: the NFC form
  (`FieldRules.NormaliseValue`) and the text as given (when it differs), and for each of them its `FoldedText` and
  `UnfoldedText` when not null; distinct (ordinal). `Contains` is true when any spelling's `Scan` has a hit; `Holders`
  takes the hits of every spelling. The refusal text does not change. The summaries (`:7-16`, `:26-31`, `:42-47`,
  `:104-108`) say "in its NFC form and as given, each also with its line endings read either way (brief T63, #412)".
- `FieldsContaining` goes through `Contains`, so the value commands' warning gets the same spellings.

**Tests** (in `FieldSecretCheckTests`, new facts; the stored secret ingested with `_m.Ok(value, "ingest", name)`).

| # | Stored | Field value checked | Outcome |
|---|---|---|---|
| 1 | `pem = "line-one-secret\r\nline-two-secret"` | `"line-one-secret\nline-two-secret"` | `Expected` (refused) |
| 2 | as 1 | `"note: line-one-secret\nline-two-secret, see vault"` | refused |
| 3 | as 1 | `"line-one-secret\nline-two-secreT"` | null |
| 4 | `pem = "line-one-secret\nline-two-secret"` | `"line-one-secret\r\nline-two-secret"` (a CR, as a caller can pass before validation) | refused |
| 5 | `pem = "café-line-one\r\ncafé-line-two"` (NFC) | its NFD spelling with `\n` | refused |
| 6 | as 1 | `Holders(Stored(), "line-one-secret\nline-two-secret")` | `[("pem", false)]` |
| 7 | a field `note = "line-one-secret\nline-two-secret"` on `s` (set with `SetFields`) | `FieldsContaining(view, index of "line-one-secret\r\nline-two-secret")` | `["s.note"]` |

**Command test** (in `FieldCommandTests`, as `FieldSet_SecretValue_Refused`): `pem` ingested as row 1's stored value and
`s` ingested as there; `Field("set", "s", "note=line-one-secret\nline-two-secret")` exits 1 with the refusal for `s.note`, names neither `pem` nor
the value, and leaves `s`'s bytes unchanged.

**Break it once:** drop `UnfoldedText` from `Spellings`; rows 1, 2, 5, 6 and 7 and the command test must fail.

## Task 4: docs

- `docs/broker-threat-model.md`, the list of forms (`:27-39`): one bullet, "since 0.3.3, a line break in any of these
  matches `\n` or `\r\n` in the output, mixed too (a lone `\r` is not a line ending), as `redact` and `run` match
  them". The window paragraph (`:51-55`) is still true ("longest form − 1"); add "a form's `\r\n` spelling counts as a
  form" after "the wrapped base64 form of a long value is the longest".
- No other doc changes: `docs/commands.md` (the field bullet, `:227-234`) already promises that every value is checked
  against every stored value, and its tocomment paragraph (`:138-151`) already says each occurrence left in place is
  warned about; neither documents the continuation-line removal. (`docs/commands.md` and `docs/security-model.md` are
  T58's and T62's.)
- In your report, one 0.3.3 release-note line per issue.

## Out of scope

- tocomment's YAML model (continuation lines are still removed when they hold no value; #171 is the long-term answer).
- A matcher shared between the broker (bytes) and `redact` (text): the broker keeps its byte forms.
- #411 and #413 (they need `Validation.cs`, `RunCommand.cs` and `EndToEndTests.cs`, which T58 changes; a later brief).
- Field values with a lone `\r` (refused by `FieldRules.ValidateValue` anyway).
