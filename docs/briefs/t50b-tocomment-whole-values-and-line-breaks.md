# Brief T50b: `tocomment` replaces only values `apply` can fill back exactly, and finds values with a line break (#394, #399)

Issues: #394, #399 (read each with its comments). Milestone 0.3.3. Base: branch `brief/t50` at 81759bb, where T50a
(`docs/briefs/t50a-redact-line-endings-and-quotes.md`, commits ce4ce8f..81759bb after the main merge ffa58c5) is
implemented: Task 3 uses its line-ending views in `SecretMatcher`. Read AGENTS.md and CLAUDE.md first, then T50a's
"line-ending views" section, `TswapCore/Fingerprints/LineEndingViews.cs`, `TswapCore/SecretMatcher.cs` (`ViewHits`,
`RawHits`, `Entries`, `Select`, `SelectToComment`), `TswapCore/ToCommentProcessor.cs`, `TswapCore/SecretProcessor.cs`,
`TswapCli/Commands/ToCommentCommand.cs`, `TswapCore/Apply.cs` (lines 1-30 and 95-200: how a marker is filled, and
`RefuseControlCharactersOnEnvLine`), `TswapTests/PlaintextRedactOracle.cs`, `TswapTests/RedactEngineTests.cs`
(`Engine_MatchesOracle_OnRandomCorpus`), `TswapTests/ToCommentBlockScalarTests.cs`, `TswapTests/ApplyMultiLineTests.cs`
(`QuotedPart`, `DoubleQuotedTestDecoder`), `TswapTests/EvilValues.cs` (`KnownFindings`) and `TswapTests/EvilValuesTests.cs`
(the tocomment invariant and the skipped `Finding2` facts).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and report
when the brief can't be built as written. **No existing test's assertions change except the ones listed under "Owner
decisions"**; if any other existing test fails because of a rule here, stop and list it. Do not touch
`TswapCore/Validation.cs` or `run`'s guards (another brief owns them); in `Apply.cs` only the visibility of
`IsControlCharacter`/`HasControlCharacter` changes (to `internal`). No production message and no custom test failure text
contains a value or the text of a line that holds one (expected values inside `Assert.Equal` of engine tests are fine).
Line numbers are at 81759bb; find anchors by content if they drifted.

## Owner decisions (2026-11-23)

1. **Sanctioned assertion changes** (each test keeps its name and purpose; the commit that changes it lists it):

   | Test | Today | After |
   |---|---|---|
   | `RedactTests.ToComment_YamlFlowMapping_UnquotedValueAdjacentToComma` | replaced (the closing `}` lands in the comment) | content unchanged |
   | `RedactTests.ToComment_YamlFlowMapping_DoubleQuotedValueAdjacentToComma` | replaced (same) | content unchanged |
   | `RedactTests.ToComment_YamlFlowSequence_ValueAdjacentToBracket` | replaced (`]` in the comment) | content unchanged |

   The three flow tests go through `Redact.ToComment`, which has no `Skipped`; they assert the content only (rows 12-13
   of Task 1 pin the skipped occurrences).
   | `RedactBehaviourPinTests.OverlappingSecrets_TheOrdinallySmallerTextWins` (tocomment half) | `AssertToComment("k: foo \"\"  # tswap: s2", "k: foo bar baz", db, new LineDiff(…))` | `AssertToComment("k: foo bar baz", "k: foo bar baz", db)` (no change; `foo bar` fails rule (b), `bar baz` rule (a)), plus `Redact.ToCommentReport("k: foo bar baz", db).Skipped` is `[(1, 1, "s1"), (1, 1, "s2")]` |
   | `RedactBehaviourPinTests.EqualLengthTies_DecidedByText_NotPosition` (tocomment half) | `AssertToComment("k: x \"\"  # tswap: z-abz-secret", "k: x ab z", spaced, new LineDiff(…))` | `AssertToComment("k: x ab z", "k: x ab z", spaced)`, plus `Skipped` `[(1, 1, "a-xab-secret"), (1, 1, "z-abz-secret")]` |
   | `RedactEngineTests.ToComment_AdjacentSecrets_UseOriginalNeighbours` (lines 69-70, oracle and engine) | `k: ""  # tswap: b""  # tswap: a` / `k: beta2.""  # tswap: a` | `k: beta2.alpha12` for both |
   | `RedactEngineTests.ToComment_SecretInsideAnInsertedMarker_NotReplaced` (line 59, oracle) | `k: ""  # ""  # tswap: s2: s1` | `k: ""  # tswap: s1` |
   | `ToCommentDryRunPinTests.DryRun_ReportsRedactedBeforeLines_AndLeavesTheFile` | `+ db: ""  # tswap: db  # note ""  # tswap: api` | `+ db: ""  # tswap: db  # note [REDACTED: api]`, then the full R1 warning line for line 1 and `'api'` (exact text) before the summary |
   | `ToCommentBlockScalarTests.QuotedPipe_NotABlock` | `    ""  # tswap: pem` (a marker `apply` can never fill: nothing before it) | content unchanged, no change, and `ToCommentReport(…).Skipped` is `[(2, 2, "pem")]`; its comment says what it pins now |

   The comments of the changed `RedactEngineTests` lines say what the old engine did ("Before T50: …").
2. **The oracle keeps comparing.** `Engine_MatchesOracle_OnRandomCorpus` keeps its tocomment comparison; instead the
   frozen oracle gets T50b's rules (Task 1 and Task 3 say exactly what), an owner-sanctioned rule change to an otherwise
   frozen file. Pre-decided so the corpus can't block the brief: the rule makes replacements rare in the corpus (most
   placements are followed by more text), so the `tocomment-hits` counter now counts rounds in which the engine **found
   an occurrence**, replaced or skipped (`ToCommentReport(…).Changes.Count + Skipped.Count > 0`, computed with the
   internal facade), and keeps the common `> 20` bar; every placement with `[-\w]` boundaries is such an occurrence, so
   this counts at least the rounds today's counter counts. The number of rounds with a replacement is not asserted (the
   Task 1 and Task 3 tables compare the oracle on replaced rows). This counter change is sanctioned. If the corpus shows
   any engine/oracle difference, stop and report; don't change the seed or the generator.
3. **Found but not replaced:** exit 0, one warning per occurrence, ending with `File unchanged.` when nothing was replaced
   (as T22), never `No secrets found.`.
4. **One multi-line value counts as one change** in the summary.
5. **Every marker a pin test locks in must fill back** (owner: "that test should never have passed"): Task 2's guard.

## What is wrong (evidence)

1. **#394.** A value is replaced wherever it stands between `[-\w]` boundaries (`ToCommentProcessor.AnchoredPatterns`,
   `ToCommentProcessor.cs:30-39`; its doc comment, lines 24-27, accepts prose as a known limitation). `.` is not in
   `[-\w]`, so `authentik` matches in `- authentik.sources.ldap.auth.LDAPBackend` and in `python -m authentik.core…`, and
   the marker breaks the line. A marker is only useful where `apply` and `run {{@file}}` fill it: `Apply` fills one only
   when the text before the empty `""` ends in `:` or `=` and optional whitespace (`EmptyValueRegex`, `UnquotedRegex`,
   `Apply.cs:18`, `21`); anywhere else it warns "value appears already populated" and skips (`Apply.cs:156-157`); and on a
   line whose prefix ends in `=` it refuses a value holding a control character (`RefuseControlCharactersOnEnvLine`,
   `Apply.cs:172`). In each of these cases the secret is gone from the file. YAML needs whitespace before a `#` comment
   (YAML 1.2.2, §6.6), so a marker inside a flow collection (`{user: x, host: y}`, `[x]`) also turns the closing `}` or
   `]` into comment text.
2. **#399.** `ToCommentReporting` normalises CRLF, splits on `\n` and matches line by line (`SecretMatcher.cs:112`,
   `SelectToComment` called at 135, on `RawHits(line)`), so a value with a line break inside is never found, and the command prints
   `No secrets found. File unchanged.` (`ToCommentCommand.cs:35-38`) while the value stays in the file. T46 finding 2
   (`EvilValues.cs:178-179`, skipped facts `EvilValuesTests.cs:471-475`).
3. **The dry-run listing.** `ToCommentCommand` redacts the `-` texts by joining them with `\n` and splitting the result
   (`ToCommentCommand.cs:46-51`), so a value that spans two joined texts shifts or breaks the listing, and it prints the
   `+` texts unredacted (line 74), which is safe today only because every occurrence on a changed line is replaced.

## The rule (Tasks 1 and 3 apply it; the engine and the oracle alike)

An **occurrence** is what the line path finds today: the value, double-quoted, single-quoted or bare, between `[-\w]`
boundaries, with a following `# tswap:` marker consumed (`AnchoredPatterns`); its opening and closing quotes and the
consumed marker are part of it. It is replaced only when all of these hold, **evaluated once, on the original line** (the
file's text, never text `tocomment` has inserted):

- **(a) Before it** (from the line's start to the occurrence), scanned left to right with quote regions: `"` opens a
  region closed by the next `"` not preceded by `\`; `'` opens one closed by the next `'` that isn't part of `''`; a
  quote of the other kind inside an open region is ordinary text; YAML's `\\` before a closing `"` is not modelled (the
  region stays open, so the rule fails: fail closed); an empty `''` reads as an escaped quote, so its region stays open
  too (fail closed). The text has no `#` outside a region, ends outside every region, and, with trailing spaces and tabs
  removed, is not empty and ends in `:` or `=`.
- **(m) No other marker text on the line.** Neither the text before the occurrence nor the text after it holds
  marker-shaped text (`#`, optional whitespace, `tswap`, optional whitespace, `:`, as `Apply`'s `AnyMarkerRegex`
  finds it), **inside a quote region or not**; a `# tswap:` marker the occurrence consumes is part of the occurrence.
  `apply` reads markers textually and quote-blind: it fills only the first marker on a line (`MarkerRegex`), so marker
  text before ours would be filled instead of ours (or throw "not found"), and it refuses a whole line on which any
  marker-shaped text is not `NAME` or `NAME:previous` (`DottedMarkerRegex`, `AnyMarkerRegex`), so marker text after ours
  can make ours unfillable. Fail closed.
- **(a′) On an `=` line** (the text before ends in `=`) the occurrence must be the **plain** form of the value (not its
  whitespace-stripped, base64 or base64url form) and hold no control character (`Apply.HasControlCharacter`): only then
  does `apply` write it back on a `KEY=` line. On a `:` line every form qualifies (`apply` writes the plain value
  double-quoted and escaped).
- **(b) After it** is empty, only spaces and tabs, or spaces/tabs followed by `#` (a YAML comment). A consumed
  `# tswap:` marker counts only when at least one space or tab stands before its `#` (without it the `#` is no comment
  in YAML, and the `: ` after `tswap` makes such a line invalid YAML), so `k: val-12345# tswap: note` is rejected (fail
  closed; `AnchoredPatterns` itself doesn't change).

(a), (a′), (b) and (m) admit exactly the shapes that `apply` fills and decodes back to the stored value; (b) also keeps a
marker out of a flow collection, where `apply` would fill it but the marker's `#` turns the closing `}` or `]` into
comment text. So `tocomment` never writes a marker that loses the secret or breaks the line. Accepted consequences: `namespace: authentik` **is** replaced (a whole value can't be told from a
credential by its shape; usernames belong in fields, #311); `apply` writes the value double-quoted, so the file's YAML
meaning can change where it wasn't a plain mapping value before (`user:authentik` is one plain scalar in YAML, and a
double-quoted scalar broken over lines folds its line break); `k#1: v` is left (a `#` outside quotes, fail closed); a
value at the end of a line inside a multi-line flow collection or JSON object (`{"password": "v"` then `}` on the next
line) is replaced as today: YAML reads the comment, JSON doesn't (markers are not for JSON).

**Rejected occurrences.** In the engine, every attempt `SelectToComment` makes whose pattern matches is an occurrence;
one the rule rejects is not replaced, and it reserves its span against later attempts **of the same entry** exactly as
a taken one does (so the bare attempt at `s` after a rejected quoted attempt at `s − 1` is not tried, as `Regex.Replace`
in the oracle never revisits a match it kept); it doesn't reserve against other entries, so a lower-priority entry can
still take an overlapping span that passes the rule. Each rejected occurrence stays in the file and is reported as a
`SkippedValue`, unless any replacement overlaps its span (then it is not reported, even if a fragment of it stays). One report per occurrence: two
occurrences of one token on one line give two lines.

The command prints them after T22's warnings, ordered by first line, then last line, then token ordinally; `{where}` is
`line {n}`, or `lines {a}-{b}` for a value over several lines; `{token}` is `name` or `name:previous`. This is the only
new warning, with exactly one of two reasons:

```
Warning: {where}: the value of '{token}' (or an encoded form of it) was left in place: {reason}. If it is the secret there, move it out by hand.
```

- `{reason}` R1, for an occurrence rule (a), (a′), (b) or (m) rejects, or a multi-line one Task 3 leaves: `it is not a whole value that apply fills back ('key: value', or 'KEY=value' without control characters)`
- `{reason}` R2, for a plain occurrence on a line T22 leaves whole (Task 1) and a multi-line value inside block-scalar
  content (Task 3): `it is inside a YAML block scalar`

## Task 1: whole values only (#394)

**Engine.** `SelectToComment`'s occurrences go through the rule; the rejected ones are not replaced and are collected.
On a block-content line, T22's encoded check (`EncodedTokens`) sees every occurrence the line's attempts found, the
rule's rejected ones included (nearly every such line also fails rule (a)), so T22 decides the line exactly as today and
its pinned warnings don't change; rejected **encoded** occurrences there are T22's (`UnreplacedLine`), never
`SkippedValue`s. On a line T22 leaves whole, every plain occurrence is reported as a `SkippedValue` with reason R2, one
per occurrence, even when T22 reports the same
token for an encoded form on that line (so none is left silently). `SkippedValue` therefore carries the reason
(`SkippedReason.NotWholeValue` or `SkippedReason.InBlockScalar`, an enum beside it).

**API.** In `TswapCore/SecretProcessor.cs`:

```csharp
public enum SkippedReason { NotWholeValue, InBlockScalar }
public sealed record SkippedValue(int FirstLine, int LastLine, string Token, SkippedReason Reason);
public sealed record ToCommentReport(string Content, IReadOnlyList<LineDiff> Changes,
    IReadOnlyList<UnreplacedLine> Unreplaced, IReadOnlyList<SkippedValue> Skipped);
```

`SkippedValue` carries no text; line numbers are the input file's. `SecretMatcher.ToCommentReport(string content)` does
the work; `ToCommentReporting` and `ToComment` keep their signatures and return its parts. `Redact` gets the public
`ToCommentReport(string, SecretMatcher)` and the internal `ToCommentReport(string, SecretsDb)` facades. Update
`AnchoredPatterns`' doc comment: the prose limitation is gone; the caller applies the rule.

**Command.** `ToCommentCommand` uses `ToCommentReport`. It redacts **each** `-` text and **each** `+` text on its own
(`Redact.RedactContent` per text; no join and split), because a changed line can now keep an occurrence (a second value in
its comment). It prints the warnings after T22's. With no change and at least one warning it ends `File unchanged.`;
`No secrets found. File unchanged.` only when there is neither a change nor a warning. Exit code 0 in every case.

**Oracle** (`PlaintextRedactOracle.ToCommenter` only; its redact path is not changed, so the corpus test's redact
comparison pins it as before). Its match list carries each search text's `VariantKind` (from `SecretVariants.For`, as it
already reads it; the labels don't change). Per line, keep the original line and a map from each character of `current`
to its index in the original line (characters a replacement inserted map to none), rebuilt after each entry's
`Regex.Replace`. In the replace evaluator, a match that contains an inserted character is kept as it is; otherwise its
original span is read from the map and the rule is evaluated on the original line, with the same rules as the engine
but its own code (the oracle never calls `SecretMatcher` or the engine's rule helper, so the comparison can fail); a rejected
match is kept as it is (`m.Value`). The oracle reports no warnings. Update its summary: "frozen at 65b41ed, plus T50b's
whole-value rule and line-break pass (owner decision 2026-11-23)".

Tests, engine level (`Redact.ToCommentReport(content, db)`; each row also asserts that the oracle's `Content` and
`Changes` equal the engine's, and runs Task 2's guard once it exists). One secret `app-user` = `authentik`, and for rows 24-25
`cr` = `line-one\rline-two` (a lone CR inside a line), for row 26 `v` = `val-12345`, and row 30 names its own. `Skipped` tuples here and in Task 3
leave out the reason, which is R1 (`NotWholeValue`) unless the row says R2:

| # | Line | `Content` | `Skipped` |
|---|---|---|---|
| 1 | `namespace: authentik` | `namespace: ""  # tswap: app-user` | empty |
| 2 | `  - authentik.sources.ldap.auth.LDAPBackend` | unchanged | `(1, 1, "app-user")` |
| 3 | `  command: python -m authentik.core.management.commands.import_flow /f.yaml` | unchanged | `(1, 1, "app-user")` |
| 4 | `- authentik` | unchanged | `(1, 1, "app-user")` |
| 5 | `args: --user=authentik --verbose` | unchanged | `(1, 1, "app-user")` |
| 6 | `KEY=authentik` | `KEY=""  # tswap: app-user` | empty |
| 7 | `export APP_USER="authentik"` | `export APP_USER=""  # tswap: app-user` | empty |
| 8 | `user:authentik` | `user:""  # tswap: app-user` | empty |
| 9 | `user: authentik  # owner` | `user: ""  # tswap: app-user  # owner` | empty |
| 10 | `user: 'authentik'  # tswap: old-name` | `user: ""  # tswap: app-user` | empty |
| 11 | `user: authentik#x` | unchanged | `(1, 1, "app-user")` |
| 12 | `{user: authentik, host: db}` | unchanged | `(1, 1, "app-user")` |
| 13 | `users: [authentik]` | unchanged | `(1, 1, "app-user")` |
| 14 | `url: https://authentik:pw@db` | unchanged | `(1, 1, "app-user")` |
| 15 | `# the authentik user` | unchanged | `(1, 1, "app-user")` |
| 16 | `# deprecated: authentik` | unchanged | `(1, 1, "app-user")` |
| 17 | `"k#1": authentik` | `"k#1": ""  # tswap: app-user` | empty |
| 18 | `k#1: authentik` | unchanged | `(1, 1, "app-user")` |
| 19 | `user: authentik-admin` | unchanged | empty (no `[-\w]` boundary: no occurrence) |
| 20 | `user: authentik  # also authentik` | `user: ""  # tswap: app-user  # also authentik` | `(1, 1, "app-user")` |
| 21 | `user: authentik authentik` | unchanged | `(1, 1, "app-user")` twice |
| 22 | `TOKEN=YXV0aGVudGlr` (base64 of `authentik`) | unchanged | `(1, 1, "app-user")` |
| 23 | `token: YXV0aGVudGlr` | `token: ""  # tswap: app-user` | empty |
| 24 | `TOKEN=line-one\rline-two` | unchanged | `(1, 1, "cr")` |
| 25 | `token: line-one\rline-two` | `token: ""  # tswap: cr` | empty |
| 26 | `k: val-12345# tswap: note` | unchanged | `(1, 1, "v")` |
| 27 | `k: "#tswap: x" v: authentik` | unchanged | `(1, 1, "app-user")` |
| 28 | `k: '""  # tswap: x': authentik` | unchanged | `(1, 1, "app-user")` |
| 29 | `user: authentik  # was # tswap: old.field` | unchanged | `(1, 1, "app-user")` |
| 30 | `k: foo bar baz` with `fb` = `foo bar baz`, `bb` = `bar baz` | `k: ""  # tswap: fb` | empty (`bar baz` is rejected but lies inside the replaced span) |

Two more engine tests: (i) `a-1` = `alpha-value-1`, `b-2` = `beta-value-22`; `k: alpha-value-1  # beta-value-22` gives
`k: ""  # tswap: a-1  # beta-value-22` and `Skipped` `[(1, 1, "b-2")]`, the oracle the same content (the gate on the
original line, whichever entry the oracle tries first); (ii) `v-1` = `v1-value-aaaa`, `v-2` = `v2-value-bbbb`,
`m` = `x: v1-value-aaaa\ny: v2-value-bbbb`, content `x: v1-value-aaaa\nother: 1\ny: v2-value-bbbb\n`: `Content`
`x: ""  # tswap: v-1\nother: 1\ny: ""  # tswap: v-2\n`, `Changes` `[LineDiff(1, "x: v1-value-aaaa", "x: \"\"  # tswap: v-1"),
LineDiff(3, "y: v2-value-bbbb", "y: \"\"  # tswap: v-2")]`, `Skipped` empty, the oracle the same `Content` and `Changes`
(`m` is not in the file as one text, so the multi-line pass finds nothing).

Command tests (`TswapTests/CommandTests.cs`, beside the redact tests, `RunTswap` style):

- `authentik` ingested as `app-user`, the file

  ```
  metadata:
    name: ldap-flow
    namespace: authentik
  spec:
    backends:
      - authentik.sources.ldap.auth.LDAPBackend
    command: python -m authentik.core.management.commands.import_flow /flows/x.yaml
    user: authentik
  ```

  `tocomment --dry-run`: exit 0; stderr (LF-normalised) lists `  line 3:` and `  line 8:` with their redacted `-` and `+`
  texts, then exactly two full warning lines, the template with `{where}` = `line 6`, `'app-user'` and R1, then the same
  for `line 7`, and ends
  `(dry run) 2 line(s) would be modified.`; it doesn't contain `authentik`. Then the live run: lines 3 and 8 become
  markers, lines 1-2 and 4-7 are byte for byte as before. (The manifest lives only here, not in the T46 corpus, which
  holds values, not files; say so in the commit.)
- Listing without a join: `v-1` = `v1-value-aaaa`, `v-2` = `v2-value-bbbb`, `m` = `x: v1-value-aaaa\ny: v2-value-bbbb`;
  the file `x: v1-value-aaaa\nother: 1\ny: v2-value-bbbb\n`; `tocomment --dry-run` exits 0 and stderr holds
  `  line 1:\n  - x: [REDACTED: v-1]\n` and `  line 3:\n  - y: [REDACTED: v-2]\n` (LF-normalised).

Break-it-once (seven runs): (a) make rules (a), (a′) and (b) always true: rows 2, 12, 13 and the manifest test must fail;
(b) drop (a′)'s control-character and plain-form conditions: rows 22 and 24 must fail; (c) print the `+` text unredacted:
`ToCommentDryRunPinTests` must fail; (d) put the join back: the listing test must fail; (e) take the rule out of the oracle
only: row 2's oracle comparison must fail; (g) drop rule (m): rows 27-29 must fail; (f) drop the whitespace requirement before a consumed marker: row 26 must
fail.

## Task 2: the round-trip guard (owner decision 5)

Add `TswapTests/ToCommentRoundTrip.cs`:

```csharp
internal static class ToCommentRoundTrip
{
    /// Every marker tocomment wrote in changes is filled back by Apply to exactly the vault's value.
    public static void Check(IReadOnlyList<LineDiff> changes, SecretsDb db);
}
```

For each change that is not a `BlockLineDiff`, whose `After` is not empty and holds `""  # tswap: {token}`
(`{token}` matched as `[a-zA-Z0-9_-]+(?::previous)?`; rule (m) keeps marker text out of the before-text, so the first
such marker is the one `tocomment` wrote): take
`prefix = After[..After.IndexOf("\"\"  # tswap: ")]` and run `Apply.ApplySecrets(prefix + "\"\"  # tswap: " + token,
db, warnings)`, that marker alone without the rest of the line (so kept comment text shaped like a marker, or markers
elsewhere in the file, can't interfere); assert it doesn't throw and `warnings` holds no `value appears already
populated`; and assert `DoubleQuotedTestDecoder.Decode(ApplyMultiLineTests.QuotedPart(filled, prefix + "\""))` equals
the token's value in `db`
(`Secrets[name].Value`, or `.PreviousValue` for `name:previous`), exactly. It compares with the vault's value, not with the
file's text: an encoded occurrence (`a: Pz8+`) is filled with the plain value (`??>`) by design.

Call it from every existing and new engine-level tocomment test whose changes hold a marker: `RedactTests`' tocomment
tests, `RedactBehaviourPinTests.AssertToComment`, the tocomment tests of `RedactEngineTests` (not
`Engine_MatchesOracle_OnRandomCorpus`, whose filler holds a marker naming `mm`, a secret the corpus vault doesn't have),
`ShortValueRedactTests.ToComment_ShortValue_Unchanged`, the `ToCommentBlockScalarTests` engine tests (through their
helpers where they have them) and the tables of Tasks 1 and 3. Adding the call is an added assertion. If an existing test
then fails, stop and list it: it locks in a marker that loses its secret.

Break-it-once: in `ToCommentRoundTrip.Check`, compare with the value's base64 instead: `RedactTests.
ToComment_UnquotedValue_ReplacedWithMarker` must fail; and, as a one-off check, feed `Check` the change
`QuotedPipe_NotABlock` pinned before T50b (`LineDiff(2, …, "    \"\"  # tswap: pem")`): it must fail (apply reports
"already populated").

## Task 3: values with a line break (#399)

**Finding them.** Before the line loop, `ToCommentReport` takes `ViewHits(content)` on the **raw** content (T50a: the
raw, folded and unfolded views through `LineEndingViews.Fold`/`Unfold`, each a `ViewHit(Hit, Text, RawStart, RawEnd)`),
keeps the hits whose raw span holds a `\n` (only plain forms can), and selects them as `Select` does
(`Entries(content, hits, wholeTokenShortValues: true)`: priority order, no overlap, short-value hits only where
`TokenBoundary.IsDelimited` on the raw text). Lines are numbered by `\n` in the raw text, a line break belonging to the
line it ends; `a` is the line holding the span's first raw character and `b` the line holding its last.

**Spans that start or end at a line break.** An occurrence whose raw span starts with a line break (`\n`, or the `\r`
of a `\r\n`) or ends with one (`\n`) is never replaced (replacing it would consume a line break and glue two lines, or
start the marker on the wrong line): it is left and reported R1 as `SkippedValue(a, b, token, NotWholeValue)`. Its lines
go through the line path as any lines; there a whitespace-stripped form on one line may still be replaced (the plain
value is filled back), and a line-path occurrence lying inside a left multi-line span is not reported again. An opening quote right before it and the matching
closing quote right after it (and a following `# tswap:` marker) belong to the occurrence, as on the line path. The
occurrence is decided when the line loop reaches line `a`:

- **Dropped silently** if line `a` was already removed by a T20 adoption above it (the adoption replaced that block).
  Continuation-line removal (`ToCommentProcessor.ContinuationLines` after a replacement) stops before a line that holds
  part of a multi-line occurrence, as it stops before T22's content lines, so it never deletes one.
- **Replaced** if the rule holds on line `a` (before it) and line `b` (after it, without a final `\r`) — a line break is a
  control character, so (a′) admits only `:` — and none of lines `a`..`b` is block-scalar content
  (`ToCommentProcessor.BlockScalarContent`). Lines `a`..`b` become one line, `{before}""  # tswap: {token}{after}`,
  recorded as **one** change,

  ```csharp
  public sealed record MultiLineDiff(int LineNumber, int LastLineNumber, string Before, string After)
      : LineDiff(LineNumber, Before, After);
  ```

  in `SecretProcessor.cs` (`Before` is lines `a`..`b` joined with `\n`, without `\r`; it is never printed). Lines `a`..`b`
  don't go through the line path, and continuation-line removal doesn't run after it. Every occurrence the line path's
  finder sees on line `a`'s original text before the span or on line `b`'s after it is reported as a `SkippedValue` on its
  own line (rules (a) and (b) can't hold there: one is followed by the multi-line value, the other sits in a comment).
- **Left** otherwise: reported as `SkippedValue(a, b, token, reason)`, with R2 when any of lines `a`..`b` is
  block-scalar content and R1 otherwise, and lines `a`..`b` go through the line path as any other lines (an occurrence
  there lying inside the left span is not reported again; a replacement overlapping the span suppresses the multi-line
  report, as on the line path).

**Command.** A `MultiLineDiff` prints as

```
  lines {a}-{b}:
  - [value over {b-a+1} lines]
  + {After, redacted on its own}
```

The summary counts it as one change (`(dry run) 1 line(s) would be modified.` for one such value; T20's adopted blocks
keep counting their removed lines). The output file is LF, as for every change today.

**Oracle.** Before its CRLF normalisation, `ToCommenter` runs the same pass on the raw content with plaintext: for every
value version (current and previous) whose plain form holds a `\n`, longest first, then in match-list order, its forms
(as stored, each `\r\n` as `\n`, each lone `\n` as `\r\n`; duplicates removed) are searched leftmost first, never
overlapping an occurrence already taken; each is replaced or left by the bullets above (block content read with
`ToCommentProcessor.BlockScalarContent`), the replaced ones as one `MultiLineDiff`; the line loop then skips the lines of
replaced ones. The corpus holds no value with a line break, so the table rows below are what compare this pass.

Tests (engine, `Redact.ToCommentReport`, secret `s` unless the row names others; "unchanged" means the input with `\r\n`
turned into `\n` and no change; rows 1-13, 16 and 17 also assert the oracle gives the same `Content` and `Changes`; every row runs
the Task 2 guard):

| # | Stored | Content | `Content` | `Changes` | `Skipped` |
|---|---|---|---|---|---|
| 1 | `line-one\nline-two` | `token: line-one\nline-two\nnext: 1\n` | `token: ""  # tswap: s\nnext: 1\n` | `MultiLineDiff(1, 2, "token: line-one\nline-two", "token: \"\"  # tswap: s")` | empty |
| 2 | `line-one\r\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | as row 1 | as row 1 | empty |
| 3 | `line-one\r\nline-two` | `token: line-one\nline-two\nnext: 1\n` | as row 1 | as row 1 | empty |
| 4 | `line-one\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | as row 1 | as row 1 | empty |
| 5 | `line-one\nline-two` | `a: 1\ntoken: line-one\nline-two\nb: 2\n` | `a: 1\ntoken: ""  # tswap: s\nb: 2\n` | `MultiLineDiff(2, 3, …)` | empty |
| 6 | `line-one\nline-two\nline-three` | `token: line-one\nline-two\nline-three\n` | `token: ""  # tswap: s\n` | `MultiLineDiff(1, 3, …)` | empty |
| 7 | `line-one\nline-two` | `token: "line-one\nline-two"  # note\n` | `token: ""  # tswap: s  # note\n` | `MultiLineDiff(1, 2, …)` | empty |
| 8 | `line-one\nline-two` | `cmd: echo line-one\nline-two \| tee x\n` | unchanged | empty | `(1, 2, "s")` |
| 9 | `line-one\nline-two` | `TOKEN=line-one\nline-two\n` | unchanged | empty | `(1, 2, "s")` |
| 10 | `line-one\nline-two` | `token: line-one\nline-two more\n` | unchanged | empty | `(1, 2, "s")` |
| 11 | `s` as row 1, `p` = `xyz-12345` | `password: xyz-12345 token: line-one\nline-two\n` | `password: xyz-12345 token: ""  # tswap: s\n` | `MultiLineDiff(1, 2, …)` | `(1, 1, "p")` |
| 12 | `s` as row 1, `t` = `tee-cmd-x` | `cmd: echo line-one\nline-two \| tee-cmd-x\n` | unchanged | empty | `(1, 2, "s")`, `(2, 2, "t")` |
| 13 | `s` as row 1, `y` = `y-value-123` | `token: line-one\nline-two  # key: y-value-123\n` | `token: ""  # tswap: s  # key: y-value-123\n` | `MultiLineDiff(1, 2, …)` | `(2, 2, "y")` |
| 14 | `line-one\n  line-two` | `script: \|\n  echo line-one\n  line-two\n` | unchanged | empty | `(2, 3, "s")`, R2 |
| 15 | `pem` = `line-one\nline-two`, `frag` = `line-one\n  line-two` | `key: \|\n  line-one\n  line-two\n` | `key: ""  # tswap: pem\n` | the T20 adoption's changes | empty |
| 16 | `\nline-two-x` (starts with a line break) | `x: a\nline-two-x\n` | unchanged | empty | `(1, 2, "s")` |
| 17 | `line-one-x\n` (ends with a line break) | `token: line-one-x\nnext: 1\n` | `token: ""  # tswap: s\nnext: 1\n` | `[LineDiff(1, "token: line-one-x", "token: \"\"  # tswap: s")]` (the line path's whitespace-stripped form) | empty (the replacement overlaps the left span) |

Command tests:

- Delete the two skipped facts `Finding2_LfInside_TocommentDryrun` and `Finding2_CrlfInside_TocommentDryrun`, their two
  `KnownFindings` entries and the `Finding2` constant: the `TocommentDryrun` theory now runs `lf-inside` and
  `crlf-inside` with its full assertion (the acceptance test; `CheckTocommentDryrun` is not changed).
- `EvilValuesTests.Tocomment_MultiLineValue_RoundTripsThroughRun` (a theory over `lf-inside` and `crlf-inside`): the file
  `key: {value}\n`, `tocomment` (live), then `run tool {{@file}}` with a `RecordingPty` child reading the copy, as
  `CheckFillRoundtrip` does (file name by `FileNameFor`): `DecodeFilledLine` of the copy equals the stored value; no stream
  holds an 8-character window of it.
- `ToCommentBlockScalarTests`, next to `NoSecrets_SaysSoExactly`: `line-one\nline-two` ingested as `s`, the file
  `cmd: echo line-one\nline-two | tee x\n`; `tocomment` exits 0; stderr (LF-normalised) is exactly the warning with
  `{where}` = `lines 1-2`, `'s'` and R1, then `File unchanged.\n`; the file is byte for byte as before.

Break-it-once (four runs): (a) skip the multi-line pass: the `TocommentDryrun` cases for `lf-inside` and `crlf-inside`
must fail; (b) admit `=` for a value with a line break: row 9 must fail; (c) don't report the occurrences in the kept
text: rows 11 and 13 must fail; (d) let a span that ends at a line break be replaced: row 17 must fail.

## Task 4: docs

- `docs/commands.md`, the "Other changes in 0.3" paragraph (line 107): replace "`tocomment --dry-run` redacts its
  "before" lines in one pass, so a value spanning two changed lines is masked there too" with: `--dry-run` redacts each
  changed line's "before" and "after" text on its own, and lists a replaced multi-line value as `[value over N lines]`,
  never its text.
- `docs/commands.md`, the `tocomment` paragraph (from line 112): `tocomment` replaces a value only where `apply` fills it
  back, double-quoted (`key: value`, or `KEY=value` holding no control character; nothing but a `#` comment after it,
  with whitespace before the `#`; no `#` before it outside quotes; no other `# tswap:` text anywhere on the line), with `namespace: authentik`
  replaced and `- authentik.sources…`, a command line, a URL, a comment and a flow collection not, and warns, naming the
  line and the secret, for each occurrence it leaves; a value with a line break is replaced when it is such a value after
  `key:` (one change, shown as `[value over N lines]`), and warned about otherwise. Say that `apply` writes the value
  double-quoted, so the YAML meaning of `user:authentik` or of a quoted scalar broken over lines can change. Replace "A
  plain value inside a block is still replaced by a marker, whose `#` then becomes part of the block's text: right for
  shell scripts and YAML kept in a block, not for JSON" with the same rule applied inside a block (`export TOKEN=…` is
  replaced, `run --user …` is not), keeping one sentence that markers are not for JSON. On `KEY=` lines say only what
  `apply` does: it writes `KEY="value"` and keeps the rest of the line; a reader that takes quotes and a ` # …`
  literally (`docker run --env-file`) sees them as part of the value, as for any marker on such a line since T20. Don't claim dotenv needs whitespace before `#`, or that ` # …` is a comment on a `KEY=` line.
- `docs/security-model.md` line 338: `tocomment` replaces a value only between `[-\w]` boundaries and, since 0.3.3, only
  where `apply` can fill it back.
- `TswapCore/Prompt.cs` and `ToCommentCommand.Description` stay as they are.

## Out of scope

- `redact` and `run` (T50a), `TswapCore/Validation.cs` and `run`'s guards.
- `tocomment` on folded (`>`) or plain multi-line YAML scalars as YAML parses them (#171, AST-based rewriting); values made
  only of whitespace.
- Skipping secrets a vault entry marks as non-secret; moving username secrets to fields (#311 `field adopt`); `field set`'s
  secret-in-field refusal and its line-ending gap (the controller files it).
