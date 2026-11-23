# Brief T50: `redact` and `tocomment` find every value whatever its line endings, and `tocomment` replaces only whole values (#398, #399, #394, #391)

Issues: #398, #399, #394, #391 (read each with its comments). Milestone 0.3.3. Base: `origin/main` at 3e22bcb. Read
AGENTS.md and CLAUDE.md first, then `TswapCore/SecretMatcher.cs`, `TswapCore/ToCommentProcessor.cs`,
`TswapCore/Redact.cs`, `TswapCli/Commands/ToCommentCommand.cs`, `TswapCli/Commands/RedactCommand.cs`, `TswapCore/Apply.cs`
(lines 1-30 and 95-160: how a marker is filled), `TswapCore/Fingerprints/FingerprintScanner.cs` (`Scan`, `ScanFolded`,
`ScanFree`), `TswapTests/EvilValues.cs` (`KnownFindings`) and `TswapTests/EvilValuesTests.cs` (the redact and tocomment
invariants and the skipped `Finding*` facts), and `docs/briefs/t45-redact-mask-suspected.md` (amendment A7: the run rule).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and report
when the brief can't be built as written. **No existing test's assertions change except the ones this brief names**
(Task 2, Task 4, Owner decision 1); if any other existing test fails because of a rule here, stop and list it. Do not touch
`TswapCore/Validation.cs` or `run`'s guards (another brief owns them); `Validation.ShortValueLength` is only read.
No message, warning or test failure text ever contains a value or the text of a line that holds one.

## What is wrong (evidence)

1. **#398, `redact`.** `SecretMatcher.Redact` turns every `\r\n` into `\n` before matching (`SecretMatcher.cs:39`). A
   stored value holding `\r\n` (a PEM ingested from a Windows file) then never matches: in a CRLF file its `\r\n` is gone,
   in an LF file it was never there. `redact` exits 0 and prints the value in clear. T46's corpus records this as finding
   1 (`EvilValues.cs:178`, skipped fact `EvilValuesTests.cs:471`). A stored LF value in a CRLF file is found today (the
   normalised text holds it, pinned by `RedactEngineTests.cs:81`).
2. **#398, `run`.** `run` masks its own tokens' values in their `\n` form too (`Redaction.Variants`, `Redaction.cs:24-27`),
   but every other vault value only through `FingerprintScanner`, which tries the raw text and a view with each `\r\n`
   folded to `\n` (`FingerprintScanner.cs:270-274`, `ScanFolded` at 495), never one with `\n` unfolded to `\r\n`. So a
   stored `\r\n` value that the child prints with `\n` only is not masked when no PTY adds the `\r` (a child in raw mode,
   `stty -onlcr`, or a runner without ONLCR). This is pinned as a documented gap
   (`FingerprintScannerTests.Scan_CrLfValue_LfOutput_NotFound`, `FingerprintScannerTests.cs:183`;
   `docs/security-model.md:298`).
3. **#399, `tocomment`.** `ToCommentReporting` normalises CRLF, splits on `\n` and matches line by line
   (`SecretMatcher.cs:66`, `SelectToComment` at 89), so a value with a line break inside is never found, and the command
   prints `No secrets found. File unchanged.` (`ToCommentCommand.cs:35-38`) while the value stays in the file. Finding 2
   (`EvilValues.cs:179-180`, skipped facts `EvilValuesTests.cs:474-478`).
4. **#394, `tocomment`.** A value is replaced wherever it stands between `[-\w]` boundaries
   (`ToCommentProcessor.AnchoredPatterns`, `ToCommentProcessor.cs:30-39`; its doc comment, lines 24-27, accepts prose as a
   known limitation). `.` is not in `[-\w]`, so `authentik` matches in `- authentik.sources.ldap.auth.LDAPBackend` and in
   `python -m authentik.core…`, and the marker breaks the line. The marker that replaces it is useful only where `apply`
   and `run` can fill it: `Apply` fills a marker only when the text before the empty `""` ends in `:` or `=` and optional
   whitespace (`EmptyValueRegex` and `UnquotedRegex`, `Apply.cs:18` and `21`); anywhere else the fill warns "value appears
   already populated" and skips (`Apply.cs:156-157`), so the secret is simply gone from the file. And because YAML needs
   whitespace before a `#` comment (YAML 1.2.2, §6.6), a marker inside a flow collection (`{user: x, host: y}`,
   `[x]`) turns the closing `}` or `]` into comment text: the file no longer parses.
5. **#391, `redact`.** `Redact.CredentialHeuristic` (`Redact.cs:16-18`) needs 12 unbroken `[A-Za-z0-9+/\-_]`
   characters, so a quoted passphrase (`password: "correct horse battery staple"`) is neither flagged nor masked.

## Owner decisions (2026-11-23)

1. **Assertion changes.** The changes this brief names (Task 2, Task 4) are sanctioned by the owner, with one exception:
   the tocomment-vs-oracle comparison in `RedactEngineTests.Engine_MatchesOracle_OnRandomCorpus` is **kept**. Instead the
   frozen oracle (`TswapTests/PlaintextRedactOracle.cs`) gets the same rules, an owner-sanctioned rule change to a file
   that otherwise stays frozen (update its summary: "frozen at 65b41ed, plus T50's whole-value rule and line-break pass,
   owner decision 2026-11-23"). Exactly this changes in its tocomment path (`ToCommenter`), nothing in its redact path:
   - **Whole-value rule.** Each `Regex.Replace` match is replaced only when Task 4's rules (a) and (b) hold for it,
     checked on the line as it stands when that match is tried (the oracle replaces sequentially); otherwise the match
     is kept as it is (`m => WholeValue(current, m) ? replacement : m.Value`). Only one place on a line can satisfy both
     rules, so the sequential order doesn't change the result.
   - **Line-break pass.** Before its CRLF normalisation, for every plaintext value version holding a `\n` (the plain
     form, current and previous), longest first, then as its match list sorts: its three forms (as stored, `\r\n` as
     `\n`, lone `\n` as `\r\n`) are searched in the raw content, leftmost first, never overlapping an occurrence already
     taken; each occurrence follows Task 5's rules and becomes one `MultiLineDiff` or is left as it is. The line loop
     then skips those lines.

   The oracle returns no warnings (`Skipped` is the engine's alone). Consequences, sanctioned with the rest: the corpus
   test's tocomment comparison and its `tocomment-hits` counter stay (if the fixed seed now gives fewer than 21 tocomment
   hits, stop and report; don't change the seed or the generator); `RedactBehaviourPinTests`' `AssertToComment` keeps
   comparing with the oracle, so its two changed rows just get the new expected result; in `RedactEngineTests` the
   oracle lines 58 (`ToComment_SecretInsideAnInsertedMarker_NotReplaced`: now `k: ""  # tswap: s1`) and 69
   (`ToComment_AdjacentSecrets_UseOriginalNeighbours`: now `k: beta2.alpha12`) change with line 70, and their "Today"
   comments say what the old engine did. Task 5's table rows also assert that the oracle gives the same `Content` and
   `Changes`. If the corpus test shows any other engine/oracle difference, stop and report it.
2. **Found but not replaced:** exit 0, one warning per occurrence, ending with `File unchanged.` (as T22), as Tasks 4 and
   5 say.
3. **Task 2 stays** (controller): masking must not depend on the PTY's ONLCR.
4. **One multi-line value counts as one change** (controller), as Task 5 says.

## Task 1: `redact` matches on every line-ending form of the text (#398)

In `SecretMatcher`, add one private helper that scans a text in three views and reports every hit on the **raw** text:

- the raw text itself;
- when the text holds a `\r\n`: the **folded** view, each `\r\n` as `\n`;
- when the text holds a `\n` not preceded by `\r`: the **unfolded** view, each such `\n` as `\r\n`.

Each view character maps back to the raw characters it stands for: a folded `\n` to the raw `\r\n`; an inserted `\r` to
the raw `\n` after it (as that `\n` itself does); every other character to itself. A hit's raw span runs from the first
raw character of its first view character to the last raw character of its last view character. From the folded and
unfolded views keep only hits whose raw span length differs from the hit's length (the others are the raw view's hits
again). The hit keeps its own length (the variant's length) and text (the view's characters) for `Compare`'s priority, so
the selection order is today's; the span that is replaced is the raw one. T30's `TokenBoundary.IsDelimited` check reads
the raw text and the raw span.

`Redact(content)` uses it on the raw content, selects as today, replaces the raw spans by their labels, and turns each
`\r\n` left in the text between replaced spans into `\n`, so the output is LF as today (`RedactBehaviourPinTests`
`CrlfInput_ComesOutLfOnly` and `RedactEngineTests.Redact_MultiLineValue_MaskedAcrossLines` stay as they are).
`tocomment`'s line path is not changed by this task (a line holds no line break; Task 5 uses the helper for values that
do). No variant, fingerprint or `SecretVariants.CurrentSetVersion` changes: no reindex is needed.

Tests (a new `LineEndingRedactTests.cs`, engine level through `Redact.RedactContent(content, db)` with the `Db`/`S`
helpers the engine tests use; secret `s`):

| Stored value | Content | `RedactContent` |
|---|---|---|
| `line-one\r\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | `token: [REDACTED: s]\nnext: 1\n` |
| `line-one\r\nline-two` | `token: line-one\nline-two\nnext: 1\n` | `token: [REDACTED: s]\nnext: 1\n` |
| `line-one\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | `token: [REDACTED: s]\nnext: 1\n` |
| `line-one\nline-two` | `token: line-one\nline-two\nnext: 1\n` | `token: [REDACTED: s]\nnext: 1\n` |
| `line-one\r\nline-two` | `a: line-one\r\nline-two\nb: line-one\nline-two\n` | `a: [REDACTED: s]\nb: [REDACTED: s]\n` |
| `single-line-value` | `k: single-line-value\r\n` | `k: [REDACTED: s]\n` |
| `line-one\r\nline-two` | `x line-one\r\ny\r\n` | `x line-one\ny\n` |

Each row also asserts `EvilValues.FirstWindowOf(value, output) < 0` for the stored value (no 8-character window of it
in the output). Then delete the skipped fact `Finding1_CrlfInside_RedactMasks`, the `("crlf-inside", RedactMasks)` entry
of `KnownFindings` and the `Finding1` constant: the `RedactMasks` theory now runs `crlf-inside` with its full assertion
(this is the acceptance test; `KnownFindings_NameRealCasesAndInvariants_AndEachHasItsSkippedFact` stays green because
table and facts change together). Add one command test in `CommandTests.cs` next to `Redact_IncludesBurnedSecretValues`:
a `\r\n` value ingested as `pem`, a file holding it with `\n` only; `tswap redact` exits 0, stdout contains
`[REDACTED: pem]`, neither stream contains an 8-character window of the value.

Break-it-once (two runs): (a) leave out the unfolded view: row 2 must fail; (b) leave out the raw view: row 1 and the
`crlf-inside` theory case must fail.

## Task 2: `run` masks a `\r\n` value printed with `\n` only (#398, the output path)

In `FingerprintScanner`, add `ScanUnfolded`, the mirror of `ScanFolded`: free entries tried on the view with each `\n`
not preceded by `\r` unfolded to `\r\n`, through `ScanFree` with `rawStart`/`rawEnd` mapping each inserted `\r` and its
`\n` to the raw `\n` (both `rawStart = i`, `rawEnd = i + 1`). `Scan` calls it right after `ScanFolded`'s condition block,
when the text holds a `\n` not preceded by `\r` (a `\n` at index 0 counts). Hits are recorded with their raw spans and
deduplicated as folded ones are (the `(Start, Length)` dedupe at the end of `Scan`). A raw span here is never longer than
its entry, so `MaxRawLength`, the caps and `PendingFrom` don't change (state this in `ScanUnfolded`'s summary and in the
class summary's paragraph on the folded view). The array sizes are up to `2 * text.Length`.

Existing assertions this changes (sanctioned: they pinned the gap this task closes):

- `FingerprintScannerTests.Scan_CrLfValue_LfOutput_NotFound` becomes `Scan_CrLfValue_LfOutput_Found`: one hit,
  `new FingerprintHit("crlf", false, VariantKind.Plain, 2, value.Replace("\r\n", "\n").Length)`; its summary loses
  "A documented gap".
- `Scan_RawHits_EqualFingerprintIndexScan`: the extra-hit assertion (line 136) accepts a span holding `\r\n` **or** `\n`
  (folded or unfolded hits); its summary says so.

New tests (`FingerprintScannerTests.cs`):

| Stored | Text | Hits |
|---|---|---|
| `a1 x\r\nb2 y\r\nc3` | `> a1 x\nb2 y\r\nc3\n` (mixed) | one, start 2, the raw span's length |
| `a1 x\r\nb2 y\r\nc3` | `> a1 x\r\nb2 y\r\nc3\n` (as stored) | exactly one (not doubled by the unfolded view) |
| `a1 x\nb2 y\nc3` | `> a1 x\nb2 y\nc3\n` | exactly one |

And in `RunVaultRedactionTests.cs` (same set-up as the PEM test there, `_pty.Onlcr` left false): a vault value
`line-one\r\nline-two` ingested as `pem`, not named in the command; the child prints `before line-one\nline-two after\n`;
`run curl {{token}}` (the `token` secret as that test sets it up) gives the output `before [REDACTED: pem] after\n`.

Break-it-once: drop the `ScanUnfolded` call: `Scan_CrLfValue_LfOutput_Found` and the run test must fail.

## Task 3: `redact` masks a quoted value with spaces after a credential keyword (#391)

Owner decision (2026-11-23, #391): a quoted value after a credential keyword counts as one value, spaces included, when
it is 12 characters or more, and is masked to its closing quote; false positives such as `secret: "see the README file"`
are accepted.

`CredentialHeuristic` gets a second alternative after the separator, tried **first**: an opening `"` or `'`, then 12 or
more characters (UTF-16 code units, as the existing rule counts) none of which is that quote, `\r` or `\n`, then the same
quote. The keyword group, the keyword list and the separator don't change; the existing unquoted/optionally-quoted
alternative stays as it is, second. For example:

```
(?<keyword>password|passwd|token|secret|key|apikey|api_key|pass)\s*[:=]\s*(?:(?<q>["'])(?<value>(?:(?!\k<q>)[^\r\n]){12,})\k<q>|["']?(?<value>[A-Za-z0-9+/\-_]{12,}=*)["']?)
```

A quoted value that is exactly one fingerprint label (`^\[REDACTED: [^\]]*\]$`) is not a hit (redact has already masked
it; the label must stay). `MaskUnknownSecrets`' run rule (T45 A7) already ends a run that a quote precedes at the matching
quote, so masking needs no other change. Without a closing quote on the line, the new alternative doesn't match (an
apostrophe in prose is no opening quote); unquoted spaced values stay out of reach, as T45 A8 says.

Tests (`RedactTests.cs`, the `MaskUnknownSecrets` table; T45's rows keep their results):

| Input | `Masked` | `Hits` |
|---|---|---|
| `password: "correct horse battery staple"` | `password: "[POSSIBLE SECRET]"` | `(1, "password")` |
| `password='correct horse battery staple' next` | `password='[POSSIBLE SECRET]' next` | `(1, "password")` |
| `password: "it's a long phrase here"` | `password: "[POSSIBLE SECRET]"` | `(1, "password")` |
| `secret: "see the README file"` | `secret: "[POSSIBLE SECRET]"` | `(1, "secret")` |
| `api_key: "abc!def$ghi&jkl"` | `api_key: "[POSSIBLE SECRET]"` | `(1, "api_key")` |
| `token: "two words"` (9 characters) | unchanged | empty |
| `password: correct horse battery staple` | unchanged | empty |
| `password: "no close quote` | unchanged | empty |
| `password: "[REDACTED: db-pw]"` | unchanged | empty |

Each row asserts, as T45 A2 does, that the replaced text appears nowhere in `Masked` or in a `Hits` keyword. Command test
(`CommandTests.cs`, next to `Redact_MasksSuspectedUnknownSecret_WarningShowsNoValue`): `db-pw` = `known-secret-value-42`;
the file `password: "known-secret-value-42"\nphrase: x\ntoken: "correct horse battery staple"\n`; stdout is exactly
`password: "[REDACTED: db-pw]"\nphrase: x\ntoken: "[POSSIBLE SECRET]"\n`; stderr is exactly the one T45 warning for
line 3 and `'token'`; neither stream contains `known-secret-value-42` or `correct horse`.

Break-it-once (two runs): (a) remove the quoted alternative: row 1 must fail; (b) remove the label exclusion: the last row
and the command test must fail.

## Task 4: `tocomment` replaces a value only where it is a whole value (#394)

**The rule.** An occurrence the line path finds today (`SelectToComment`: the value, quoted or bare, between `[-\w]`
boundaries, with a following `# tswap:` marker consumed) is replaced only when both hold, on the original line:

- (a) **before it** (the text from the line's start to the occurrence, its opening quote included in the occurrence),
  with trailing spaces and tabs removed, is not empty and ends in `:` or `=`. That is exactly the shape `Apply` fills
  (`^(.*[:=]\s*)`, `Apply.cs:18` and `21`), so every marker `tocomment` writes can be filled by `apply` and `run`.
- (b) **after it** (after its closing quote and a consumed marker) is empty, only spaces and tabs, or spaces/tabs followed
  by `#` (a comment: YAML and dotenv need whitespace before it).

So `key: value`, `key:value`, `KEY=value`, `export KEY="value"`, `key: "value"  # note` and `key: 'value'  # tswap: old`
are replaced; a value inside a dotted name, a path, a URL, a command line, a comment, a block sequence item (`- value`:
`Apply` can't fill `- ""`), a flow collection (`{k: value, …}`, `[value]`) or after other text is not. `namespace:
authentik` **is** replaced (a whole value can't be told from a credential by its shape; usernames belong in fields, #311).

**What happens to an occurrence the rule rejects.** It stays in the file, and `tocomment` warns, one line per
(line, token), after T22's warnings, ordered by line then token ordinally:

```
Warning: line {n} holds the value of '{token}' (or an encoded form of it) inside a longer value, a comment or a command, not as a whole value after 'key:' or 'KEY=', so it was not replaced. If it is the secret there, move it out by hand.
```

`{token}` is `name` or `name:previous`. Not on a line T22 leaves whole (block content with an encoded form: T22's
warning covers that line). When nothing is replaced but a warning was written, the command ends with `File unchanged.`
(the T22 path), never `No secrets found.`; exit code 0 (warnings, as T22's).

**The `+` lines are redacted.** A changed line can now keep an occurrence (a second value in its comment), so
`--dry-run` and the live run print each `+` line redacted with the same matcher, in the same single
`Redact.RedactContent` pass as the `-` lines (join every `-` then every `+` text with `\n`, split back). The file itself
keeps the occurrence, as the warning says.

**API.** In `TswapCore/SecretProcessor.cs` add

```csharp
public sealed record SkippedValue(int FirstLine, int LastLine, string Token);
public sealed record ToCommentReport(string Content, IReadOnlyList<LineDiff> Changes,
    IReadOnlyList<UnreplacedLine> Unreplaced, IReadOnlyList<SkippedValue> Skipped);
```

(`SkippedValue` carries no text; `FirstLine == LastLine` for a one-line occurrence). `SecretMatcher.ToCommentReport(string
content)` does the work; `ToCommentReporting` and `ToComment` keep their signatures and return its parts. `Redact` gets
the public `ToCommentReport(string, SecretMatcher)` and the internal `ToCommentReport(string, SecretsDb)` facades.
`ToCommentCommand` uses `ToCommentReport`. Update `AnchoredPatterns`' doc comment: the prose limitation is gone; the
whole-value rule is checked by the caller.

Existing assertions this changes (sanctioned by the owner's #394 decision; each test keeps its name and purpose, and the
commit message lists them):

| Test | Today | After |
|---|---|---|
| `RedactTests.ToComment_YamlFlowMapping_UnquotedValueAdjacentToComma` | replaced (closing `}` lands in the comment) | content unchanged |
| `RedactTests.ToComment_YamlFlowMapping_DoubleQuotedValueAdjacentToComma` | replaced (same) | content unchanged |
| `RedactTests.ToComment_YamlFlowSequence_ValueAdjacentToBracket` | replaced (`]` in the comment) | content unchanged |
| `RedactBehaviourPinTests.OverlappingSecrets_TheOrdinallySmallerTextWins` (tocomment half) | `k: foo ""  # tswap: s2` | unchanged, no change (engine and the updated oracle, through `AssertToComment`) |
| `RedactBehaviourPinTests.EqualLengthTies_DecidedByText_NotPosition` (tocomment half) | `k: x ""  # tswap: z-abz-secret` | unchanged, no change (the same) |
| `RedactEngineTests.ToComment_AdjacentSecrets_UseOriginalNeighbours` (lines 69-70, oracle and engine) | `k: ""  # tswap: b""  # tswap: a` / `k: beta2.""  # tswap: a` | `k: beta2.alpha12` for both |
| `RedactEngineTests.ToComment_SecretInsideAnInsertedMarker_NotReplaced` (line 58, oracle) | `k: ""  # ""  # tswap: s2: s1` | `k: ""  # tswap: s1` |
| `RedactEngineTests.Engine_MatchesOracle_OnRandomCorpus` | — | no assertion changes: it keeps comparing tocomment, against the updated oracle (Owner decision 1) |
| `ToCommentDryRunPinTests.DryRun_ReportsRedactedBeforeLines_AndLeavesTheFile` | `+ db: ""  # tswap: db  # note ""  # tswap: api` | `+ db: ""  # tswap: db  # note [REDACTED: api]`, then the warning for line 1 and `'api'` before the summary |

Tests (engine, `Redact.ToCommentReport(content, db)`, one secret `app-user` = `authentik`, one line each):

| Line | `Content` | `Skipped` |
|---|---|---|
| `namespace: authentik` | `namespace: ""  # tswap: app-user` | empty |
| `  - authentik.sources.ldap.auth.LDAPBackend` | unchanged | `(1, 1, "app-user")` |
| `  command: python -m authentik.core.management.commands.import_flow /f.yaml` | unchanged | `(1, 1, "app-user")` |
| `- authentik` | unchanged | `(1, 1, "app-user")` |
| `args: --user=authentik --verbose` | unchanged | `(1, 1, "app-user")` |
| `KEY=authentik` | `KEY=""  # tswap: app-user` | empty |
| `export APP_USER="authentik"` | `export APP_USER=""  # tswap: app-user` | empty |
| `user:authentik` | `user:""  # tswap: app-user` | empty |
| `user: authentik  # owner` | `user: ""  # tswap: app-user  # owner` | empty |
| `user: 'authentik'  # tswap: old-name` | `user: ""  # tswap: app-user` | empty |
| `user: authentik#x` | unchanged | `(1, 1, "app-user")` |
| `{user: authentik, host: db}` | unchanged | `(1, 1, "app-user")` |
| `users: [authentik]` | unchanged | `(1, 1, "app-user")` |
| `url: https://authentik:pw@db` | unchanged | `(1, 1, "app-user")` |
| `# the authentik user` | unchanged | `(1, 1, "app-user")` |
| `user: authentik-admin` | unchanged | empty (no `[-\w]` boundary: not an occurrence) |
| `user: authentik  # also authentik` | `user: ""  # tswap: app-user  # also authentik` | `(1, 1, "app-user")` |

Command test (`ToCommentBlockScalarTests.cs` style, `FleetMachine`): `authentik` ingested as `app-user`, the file

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

`tocomment --dry-run`: exit 0; stderr (LF-normalised) shows `  line 3:` and `  line 8:` with their redacted `-` and `+`
lines, the warning for line 6 then line 7 (both `'app-user'`), and ends `(dry run) 2 line(s) would be modified.`; it does
not contain `authentik`. Then the live run: lines 3 and 8 become markers, lines 1-2 and 4-7 are byte for byte as before.

Break-it-once (two runs): (a) make rule (a) always true: the `- authentik.sources…` row and the command test must fail;
(b) print the `+` line unredacted: `ToCommentDryRunPinTests` must fail.

## Task 5: `tocomment` finds a value with a line break inside it (#399)

The multi-line marker form from T20 (#315/#318) is sound for a whole value after `key:`: `Apply` writes the value
double-quoted with `\n`, `\r` escaped, which YAML and JSON decode back to exactly the stored value
(`EvilValuesTests.DecodeFilledLine` checks this). So `tocomment` replaces such a value; it is not sound on a `KEY=` line
(`Apply.RefuseControlCharactersOnEnvLine` refuses to fill it) or anywhere the whole-value rule fails, so there it warns.

Before the line loop, `ToCommentReport` scans the **raw** content with Task 1's helper and keeps the hits whose raw span
holds a `\n` (only plain variants can: the stripped and encoded ones hold no line break), selected as `Select` selects
(priority order, no overlap; short-value hits need `TokenBoundary.IsDelimited` on the raw text, as in `redact`). Line
numbers are counted by `\n` in the raw text. For each such occurrence, from its first line `a` to its last line `b`:

- It is **replaced** when: (a) the text before it on line `a` (an opening `"` or `'` right before it counts as part of
  the occurrence, as on the line path) ends, after trailing spaces and tabs, in `:` (not `=`); (b) the text after it on
  line `b` (after the matching closing quote, if it was quoted, and a `# tswap:` marker it consumes, and without a final
  `\r`) passes Task 4's rule (b); (c) none of lines `a`..`b` is block-scalar content
  (`ToCommentProcessor.BlockScalarContent`) or removed by a T20 adoption. Lines `a`..`b` become one line,
  `{text before}""  # tswap: {token}{text after}`, recorded as **one** change:

  ```csharp
  public sealed record MultiLineDiff(int LineNumber, int LastLineNumber, string Before, string After)
      : LineDiff(LineNumber, Before, After);
  ```

  (`Before` is lines `a`..`b` joined with `\n`, without `\r`; it is never printed). Lines `a+1`..`b` are removed from the
  output; continuation-line removal does not run after it.
- Otherwise it is **left** and reported as `SkippedValue(a, b, token)`, and the command prints

  ```
  Warning: lines {a}-{b} hold the value of '{token}' across a line break, but not as a whole value after 'key:', so it was not replaced. If it is the secret there, move it out by hand.
  ```

  (with Task 4's warnings, ordered by first line then token).
- Lines `a`..`b` of either kind are not run through the line path.

`ToCommentCommand` prints a `MultiLineDiff` as

```
  lines {a}-{b}:
  - [value over {b-a+1} lines]
  + {After, redacted as in Task 4}
```

and leaves it out of the joined `-` redaction pass. The summary counts it as one change: `(dry run) 1 line(s) would be
modified.` for one multi-line value (the count is of changes, as the T46 acceptance test requires; T20's adopted blocks
keep counting their removed lines). The output file is LF, as for every change today.

Tests (engine, `Redact.ToCommentReport`, secret `s`; "unchanged" means the input with `\r\n` turned into `\n`, no change):

| Stored | Content | `Content` | `Changes` | `Skipped` |
|---|---|---|---|---|
| `line-one\nline-two` | `token: line-one\nline-two\nnext: 1\n` | `token: ""  # tswap: s\nnext: 1\n` | `MultiLineDiff(1, 2, "token: line-one\nline-two", "token: \"\"  # tswap: s")` | empty |
| `line-one\r\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | the same | the same | empty |
| `line-one\r\nline-two` | `token: line-one\nline-two\nnext: 1\n` | the same | the same | empty |
| `line-one\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | the same | the same | empty |
| `line-one\nline-two` | `a: 1\ntoken: line-one\nline-two\nb: 2\n` | `a: 1\ntoken: ""  # tswap: s\nb: 2\n` | `MultiLineDiff(2, 3, …)` | empty |
| `line-one\nline-two\nline-three` | `token: line-one\nline-two\nline-three\n` | `token: ""  # tswap: s\n` | `MultiLineDiff(1, 3, …)` | empty |
| `line-one\nline-two` | `token: "line-one\nline-two"  # note\n` | `token: ""  # tswap: s  # note\n` | `MultiLineDiff(1, 2, …)` | empty |
| `line-one\nline-two` | `cmd: echo line-one\nline-two \| tee x\n` | unchanged | empty | `(1, 2, "s")` |
| `line-one\nline-two` | `TOKEN=line-one\nline-two\n` | unchanged | empty | `(1, 2, "s")` |
| `line-one\nline-two` | `token: line-one\nline-two more\n` | unchanged | empty | `(1, 2, "s")` |

Command tests:

- Delete the two skipped facts `Finding2_LfInside_TocommentDryrun` and `Finding2_CrlfInside_TocommentDryrun`, their two
  `KnownFindings` entries and the `Finding2` constant: the `TocommentDryrun` theory now runs `lf-inside` and
  `crlf-inside` with its full assertion (the acceptance test; `CheckTocommentDryrun` is not changed).
- In `EvilValuesTests.cs`, `Tocomment_MultiLineValue_RoundTripsThroughRun` (a theory over `lf-inside` and `crlf-inside`):
  the file `key: {value}\n`, `tocomment` (live), then `run tool {{@file}}` with a `RecordingPty` child reading the copy, as `CheckFillRoundtrip` does (file name by `FileNameFor`):
  `DecodeFilledLine` of the copy equals the stored value; no stream holds an 8-character window of it.
- In `ToCommentBlockScalarTests.cs`, next to `NoSecrets_SaysSoExactly`: `line-one\nline-two` ingested as `s`, the file
  `cmd: echo line-one\nline-two | tee x\n`; `tocomment` exits 0, stderr (LF-normalised) is exactly the warning for lines
  1-2 and `'s'` then `File unchanged.\n`, the file is byte for byte as before.

Break-it-once (two runs): (a) skip the multi-line pass: the two `TocommentDryrun` cases for `lf-inside` and `crlf-inside`
must fail; (b) accept `=` in check (a): the `TOKEN=` row must fail.

## Task 6: docs

- `docs/commands.md`, the "Fingerprints" section: one sentence that `redact` masks a value with line breaks whatever the
  line endings of the value and of the file (`\r\n` or `\n`). In the T45 paragraph, the spaced-value example becomes: a
  quoted value of 12 or more characters after such a keyword is masked whole, spaces included (`password: "correct horse
  battery staple"`), which also masks a quoted description (`secret: "see the README file"`); an unquoted one with spaces
  still slips through.
- `docs/commands.md`, the `tocomment` paragraph (from line 107): `--dry-run` redacts its `+` lines as well as its `-`
  lines; `tocomment` replaces a value only where it is a whole value after `key:` or `KEY=` (rule (a) and (b) of Task 4,
  in words, with `namespace: authentik` replaced and `- authentik.sources…`, a command line, a URL, a comment and a flow
  collection not), and warns, naming the line and the secret, for each occurrence it leaves; a value with a line break is
  replaced when it is a whole value after `key:` (one change, shown as `[value over N lines]`) and warned about
  otherwise. Replace "A plain value inside a block is still replaced by a marker, whose `#` then becomes part of the
  block's text: right for shell scripts and YAML kept in a block, not for JSON" with the same rule applied inside a block
  (`export TOKEN=…` is replaced, `run --user …` is not).
- `docs/security-model.md`, the "what `run` masks" table (line 298): remove "a `\r\n` value printed with `\n` only" from
  the "no" row and add "or printed with `\n` only" to the multi-line row (line 299). Line 338: `tocomment` replaces a value
  only between `[-\w]` boundaries and, since 0.3.3, only where it is a whole value.
- `TswapCore/Prompt.cs`, the command descriptions and `RedactCommand`/`ToCommentCommand.Description` stay as they are.

## Out of scope

- `TswapCore/Validation.cs` and `run`'s guards (substitution, blocked invocations, batch files).
- A new fingerprint variant or variant-set version (the views make it unnecessary).
- `tocomment` on folded (`>`) or plain multi-line YAML scalars as YAML parses them (#171, AST-based rewriting); values
  that are only whitespace; the guessing-oracle rate limit (#252).
- Skipping secrets a vault entry marks as non-secret, and moving username secrets to fields (#311 `field adopt`).

## Amendments (round 1; GLM and MiMo)

- **A1 (both, owner sanctioned 2026-11-23): `ToCommentBlockScalarTests.QuotedPipe_NotABlock`** changes under Task 4's rule:
  new expectation, content unchanged, no `LineDiff`, and `ToCommentReport(...).Skipped` holds `(2, 2, "pem")` (the bare
  value line is left alone, because `apply` could never fill its marker). The test keeps its name; its comment says what
  it now pins. Name it in Task 4's commit.
- **A2 (MiMo I1): no join for redacting the diff texts.** In `ToCommentCommand`, redact each `-` and each `+` text
  separately (never `string.Join('\n', …)` then `Split('\n')`), so a multi-line value can't match across a joined
  boundary and shift or crash the listing. Test: two changed lines whose texts concatenate (with `\n`) to a stored
  multi-line value; the command exits 0 and each line's redaction is under its own header. Break-it-once: restore the
  join; the test fails (exception or wrong line).
- **A3 (MiMo I2): quoted values with escapes, fail closed.** Task 3's quoted alternative treats `\\.` as one character
  inside double quotes and `''` as an escaped quote inside single quotes; the matching quote is the first unescaped one.
  Rows: `password: "aaaa\"bbbbbbbbbbbb"` → masked to the closing quote; `password: 'it''s a long passphrase'` → masked;
  existing rows unchanged.
- **A4 (GLM I2): Task 4's break-it-once (a).** Disable the whole-value check entirely (rules (a) and (b) always true):
  the `- authentik.sources…` row, the command test and the flow rows must fail.
- **A5 (GLM I3): a comment after a replaced multi-line value.** After a multi-line replacement, scan the retained
  after-text on line `b` with the line path; any occurrence there is reported as `SkippedValue` on line `b` (never kept
  silently). Row: stored `s` = `line-one\nline-two` and `y`; file `token: line-one\nline-two  # key: y\n` → `s` replaced,
  `y` warned.
- **A6 (MiMo M1).** A whole value on a commented-out line (`# deprecated: authentik`) is not replaced: rule (a) also
  requires that the text before the occurrence contains no `#` outside quotes. Row added; Task 4's warning text and Task
  6's docs say "the shape `apply` fills (`key: value` or `KEY=value`)", not "a YAML whole value" (MiMo M4).
- **A7 (MiMo M2).** Rule (b)'s rationale: drop the claim that dotenv needs whitespace before `#` (it doesn't); the
  behaviour (skip and warn) stays, and the docs don't make the claim.
- **A8 (MiMo M3).** Task 6 keeps one sentence: markers are not for JSON.
- **A9 (GLM M3).** `MultiLineDiff` lives in `SecretProcessor.cs` beside `LineDiff`; its `After` is redacted with its own
  `RedactContent` call; the oracle's three forms are de-duplicated; the whole-value gate and line-break pass are virtual
  seams on `Processor` whose `Redactor` defaults keep today's redact behaviour exactly (a test pins redact unchanged on
  the corpus).
- **A10 (GLM M2).** Task 5's skipped branch has the same exemptions as rule (c): no "move it out by hand" warning for
  block-scalar content or T20-adopted lines.
- **A11 (MiMo M5, M6).** Comments only: record in the hit-filter helper that a hit ending or starting at an inserted `\r`
  is dropped on purpose; don't write "only one place on a line can satisfy both rules" anywhere.
- **A12 (MiMo M9).** "No value in failure text" covers production messages and custom failure strings; expected values in
  `Assert.Equal` of engine tests (as `RedactEngineTests` does today) are allowed.
- **A13 (GLM M4, M1).** Task 2's first new row: expected length 13. Line numbers in the brief may drift; find anchors by
  content.
- **A14 (MiMo M7, M8).** The #394 manifest shape goes into the new command test only (the corpus holds values, not
  files): say so in the commit. `field set`'s secret-in-field refusal and its line-ending gap are out of scope; the
  controller files it.
- **A15 (owner, 2026-11-23: "that test should never have passed").** `QuotedPipe_NotABlock` pinned today's output
  without checking that `apply` could fill it back. Add one guard so a pin can't lock in a lost secret again: a test
  helper `AssertRoundTrips(original, tocommentOutput, vault)` that runs `Apply` on the output and asserts it equals the
  original for every replaced line, and call it from every existing and new tocomment pin test whose output contains a
  marker (`ToCommentBlockScalarTests`, `RedactBehaviourPinTests`, `ToCommentDryRunPinTests`, `RedactEngineTests`'
  tocomment rows, Task 4/5's tables). Adding this call is an added assertion, not a changed one. If any existing pin
  then fails (a marker apply can't fill), stop and list it: that is another test that should never have passed.
