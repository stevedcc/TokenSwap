# Brief T50a: `redact` and `run` mask a stored value whatever its line endings, and `redact` masks quoted passphrases (#398, #391)

Issues: #398, #391 (read each with its comments). Milestone 0.3.3. Base: `origin/main` at 3e22bcb. T50b (`tocomment`) builds
on this brief and starts after it is merged. Read AGENTS.md and CLAUDE.md first, then `TswapCore/SecretMatcher.cs`,
`TswapCore/Redact.cs` (`CredentialHeuristic`, `MaskUnknownSecrets`, `RunEnd`), `TswapCore/Fingerprints/FingerprintScanner.cs`
(`Scan`, `ScanFolded`, `ScanFree`), `TswapCore/Fingerprints/SecretVariants.cs`, `TswapTests/EvilValues.cs`
(`KnownFindings`), `TswapTests/EvilValuesTests.cs` (the redact invariant and the skipped `Finding1` fact) and
`docs/briefs/t45-redact-mask-suspected.md` (amendments A1, A7, A8: the mask run).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and report
when the brief can't be built as written. **No existing test's assertions change except the two Task 2 names**; if any
other existing test fails because of a rule here (for example a T45 row or a test that expects a quoted 12-character
value after a credential keyword to come out of `redact` unchanged), stop and list it. Do not touch
`TswapCore/Validation.cs` or `run`'s guards (another brief owns them). No production message and no custom test failure
text contains a value or the text of a line that holds one (expected values inside `Assert.Equal` of engine tests are
fine, as in `RedactEngineTests`). Line numbers below are at 3e22bcb; find anchors by content if they drifted.

## Owner and controller decisions

- **#391 (owner, 2026-11-23):** a quoted value after a credential keyword counts as one value, spaces included, when it
  is 12 characters or more, and is masked to its closing quote. False positives such as `secret: "see the README file"`
  are accepted: for `redact`, masking too much is the safe side.
- **Task 2 stays (controller):** masking must not depend on the PTY's ONLCR.
- **Sanctioned assertion changes:** the two scanner tests Task 2 names, which pinned the gap it closes.

## What is wrong (evidence)

1. **`redact`.** `SecretMatcher.Redact` turns every `\r\n` into `\n` before matching (`SecretMatcher.cs:39`). A stored value
   holding `\r\n` (a PEM ingested from a Windows file) then never matches: in a CRLF file its `\r\n` is gone, in an LF
   file it was never there. `redact` exits 0 and prints the value in clear. T46 finding 1 (`EvilValues.cs:178`, skipped
   fact `EvilValuesTests.cs:471`). A stored LF value in a CRLF file is found today (pinned by `RedactEngineTests.cs:81`).
2. **`run`.** `run` masks its own tokens' values in their `\n` form too (`Redaction.Variants`, `Redaction.cs:24-27`), but
   every other vault value only through `FingerprintScanner`, which tries the raw text and a view with each `\r\n` folded
   to `\n` (`FingerprintScanner.cs:270-274`, `ScanFolded` at 495), never one with `\n` unfolded to `\r\n`. A stored `\r\n`
   value printed with `\n` only is therefore not masked unless a PTY's ONLCR adds the `\r` (not in raw mode, after
   `stty -onlcr`, or with a runner without ONLCR). Pinned as a documented gap:
   `FingerprintScannerTests.Scan_CrLfValue_LfOutput_NotFound` (line 183), `docs/security-model.md:298`.
3. **#391.** `Redact.CredentialHeuristic` (`Redact.cs:16-18`) needs 12 unbroken `[A-Za-z0-9+/\-_]` characters, so a quoted
   passphrase (`password: "correct horse battery staple"`) is neither flagged nor masked.

## The line-ending views (used by Task 1 here, and by `run`'s scanner in Task 2)

A text is scanned in up to three **views**:

- the **raw** text;
- when it holds a `\r\n`: the **folded** view, each `\r\n` as `\n`;
- when it holds a `\n` not preceded by `\r` (a `\n` at index 0 counts): the **unfolded** view, each such `\n` as `\r\n`.

Each view character maps to the raw text: an ordinary character to itself; a folded `\n` to the raw `\r\n` (two raw
characters); an **inserted `\r`** to the empty position just before its raw `\n` (zero raw characters); the `\n` after
it to itself. A hit's raw span runs from where its first view character maps to the end of where its last view
character maps. So a hit that ends on an inserted `\r` stops before the raw `\n` (the line break stays), and a hit that
starts on one starts at the raw `\n`. A hit whose raw span would be empty is dropped.

From the folded and unfolded views only hits that contain at least one folded `\n` or inserted `\r` are kept; every other
hit there is the raw view's hit again. Raw spans are never longer than the hit in the unfolded view, and at most one
character per folded `\n` longer in the folded view (as today).

## Task 1: `redact` matches on every line-ending form of the text (#398)

In `SecretMatcher`, add a private helper that scans a text with `FingerprintIndex.Scan` in the three views above and
returns each kept hit with its raw span. The hit keeps its own length (the variant's length) and its view text for
`Compare`'s priority, so the selection order is today's; the span that is selected and replaced is the raw one (overlap
and the "previous taken occurrence" checks use raw positions). T30's `TokenBoundary.IsDelimited` reads the raw text and
the raw span. Two hits of the same entry (same variant length, text, token, kind) at different raw starts are two starts
of that entry, taken leftmost first as today; no other tie rule is added.

`Redact(content)` uses it on the raw content, selects as today, replaces the raw spans by their labels, and turns each
`\r\n` left in the text between replaced spans into `\n`, so the output is LF as today (`RedactBehaviourPinTests.
CrlfInput_ComesOutLfOnly` and `RedactEngineTests.Redact_MultiLineValue_MaskedAcrossLines` stay as they are). A value that
starts with `\n` in a CRLF file is found both in the raw view (at the `\n`) and in the folded view (at the `\r`); the
folded start is leftmost and wins, so no stray `\r` is left (row 9 pins it). `tocomment`'s line path doesn't change here.
No variant, fingerprint or `SecretVariants.CurrentSetVersion` changes: no reindex.

Tests (a new `TswapTests/LineEndingRedactTests.cs`, engine level through `Redact.RedactContent(content, db)` with the
`Db`/`S` helpers the engine tests use; one secret `s`):

| # | Stored value | Content | `RedactContent` |
|---|---|---|---|
| 1 | `line-one\r\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | `token: [REDACTED: s]\nnext: 1\n` |
| 2 | `line-one\r\nline-two` | `token: line-one\nline-two\nnext: 1\n` | `token: [REDACTED: s]\nnext: 1\n` |
| 3 | `line-one\nline-two` | `token: line-one\r\nline-two\r\nnext: 1\r\n` | `token: [REDACTED: s]\nnext: 1\n` |
| 4 | `line-one\nline-two` | `token: line-one\nline-two\nnext: 1\n` | `token: [REDACTED: s]\nnext: 1\n` |
| 5 | `line-one\r\nline-two` | `a: line-one\r\nline-two\nb: line-one\nline-two\n` | `a: [REDACTED: s]\nb: [REDACTED: s]\n` |
| 6 | `single-line-value` | `k: single-line-value\r\n` | `k: [REDACTED: s]\n` |
| 7 | `\r\nline-one\r\nline-two` | `x:\nline-one\nline-two\n` | `x:[REDACTED: s]\n` |
| 8 | `abc def-gh\r` | `x: abc def-gh\n` | `x: [REDACTED: s]\n` |
| 9 | `\nline-two-x` | `x: a\r\nline-two-x\r\n` | `x: a[REDACTED: s]\n` |
| 10 | `line-one\r\nline-two` | `x line-one\r\ny\r\n` | `x line-one\ny\n` |

Rows 1-9 also assert `EvilValues.FirstWindowOf(value, output) < 0` (no 8-character window of the value in the output).
Row 10 leaves the value's first line in place on purpose (only part of the value is there) and asserts the output only.
Row 7 is a value starting at an inserted `\r`; row 8 a value ending in one (its whitespace-stripped variant `abcdef-gh` is
not in the text, so only the unfolded view finds it, and the line break stays).

Then delete the skipped fact `Finding1_CrlfInside_RedactMasks`, the `("crlf-inside", RedactMasks)` entry of
`KnownFindings` and the `Finding1` constant: the `RedactMasks` theory now runs `crlf-inside` with its full assertion (the
acceptance test; `KnownFindings_NameRealCasesAndInvariants_AndEachHasItsSkippedFact` stays green because table and facts
change together). Add one command test in `CommandTests.cs` next to `Redact_IncludesBurnedSecretValues`: a `\r\n` value
ingested as `pem`, a file holding it with `\n` only; `tswap redact` exits 0, stdout contains `[REDACTED: pem]`, neither
stream holds an 8-character window of the value.

Break-it-once (three runs): (a) leave out the unfolded view: row 2 must fail; (b) leave out the raw view: row 1 and the
`crlf-inside` theory case must fail; (c) map an inserted `\r` to its raw `\n` instead of the empty position: row 8 must
fail.

## Task 2: `run` masks a `\r\n` value printed with `\n` only (#398, the output path)

In `FingerprintScanner`, add `ScanUnfolded`, the mirror of `ScanFolded`: free entries tried on the unfolded view through
`ScanFree`, with `rawStart`/`rawEnd` mapping as the views section says (an inserted `\r` before raw index `i`:
`rawStart = rawEnd = i`; its `\n`: `rawStart = i`, `rawEnd = i + 1`). `Scan` calls it right after `ScanFolded`'s condition
block, when the text holds a `\n` not preceded by `\r`. Hits are recorded with their raw spans and deduplicated as folded
ones are (the `(Start, Length)` dedupe at the end of `Scan`, first in the existing tie order; no view key is added). An
unfolded raw span is never longer than its entry, so `MaxRawLength`, the caps and `PendingFrom` don't change: say so in
`ScanUnfolded`'s summary and in the class summary's paragraph on the folded view. Arrays are rented for up to
`2 * text.Length` characters and cleared on return as `ScanFolded`'s are.

Existing assertions this changes (sanctioned):

- `FingerprintScannerTests.Scan_CrLfValue_LfOutput_NotFound` becomes `Scan_CrLfValue_LfOutput_Found`: one hit,
  `new FingerprintHit("crlf", false, VariantKind.Plain, 2, 12)` (12 = `value.Replace("\r\n", "\n").Length`); its summary
  loses "A documented gap".
- `Scan_RawHits_EqualFingerprintIndexScan`: the extra-hit assertion (line 136) accepts a span holding `\r\n` or `\n`, or
  one that ends right before a `\n` (an unfolded hit ending on an inserted `\r`); its summary says so.

New tests (`FingerprintScannerTests.cs`):

| Stored | Text | Hits |
|---|---|---|
| `a1 x\r\nb2 y\r\nc3` | `> a1 x\nb2 y\r\nc3\n` (mixed) | exactly one: start 2, length 13 |
| `a1 x\r\nb2 y\r\nc3` | `> a1 x\r\nb2 y\r\nc3\n` (as stored) | exactly one: start 2, length 14 |
| `a1 x\nb2 y\nc3` | `> a1 x\nb2 y\nc3\n` | exactly one: start 2, length 12 |
| `abc def-gh\r` | `x: abc def-gh\n` | exactly one: start 3, length 10 |

And in `RunVaultRedactionTests.cs` (the PEM test's set-up, `_pty.Onlcr` left false): a vault value `line-one\r\nline-two`
ingested as `pem`, not named in the command; the child prints `before line-one\nline-two after\n`; `run curl {{token}}`
(the `token` secret as that test sets it up) gives the output `before [REDACTED: pem] after\n`.

Break-it-once: drop the `ScanUnfolded` call: `Scan_CrLfValue_LfOutput_Found` and the run test must fail.

## Task 3: `redact` masks a quoted value after a credential keyword (#391)

`CredentialHeuristic` gets a quoted alternative after the separator, tried **first**; the keyword group, the keyword list,
the separator and the existing unquoted/optionally-quoted alternative (second) don't change:

- double quotes: `"`, then 12 or more **items**, each either `\` followed by any character except `\r` and `\n` (an
  escape: one item) or one character other than `"`, `\`, `\r`, `\n`; then `"`;
- single quotes: `'`, then 12 or more items, each either `''` (an escaped quote: one item) or one character other than
  `'`, `\r`, `\n`; then `'`;
- not a hit when the quoted text is exactly a fingerprint label (`[REDACTED: …]`, no `]` inside) or exactly
  `[POSSIBLE SECRET]`: `redact`'s own labels stay, and running `redact` over its own output adds no warning.

For example:

```
(?<keyword>password|passwd|token|secret|key|apikey|api_key|pass)\s*[:=]\s*(?:"(?!(?:\[REDACTED: [^\]]*\]|\[POSSIBLE SECRET\])")(?<value>(?:\\[^\r\n]|[^"\\\r\n]){12,})"|'(?!(?:\[REDACTED: [^\]]*\]|\[POSSIBLE SECRET\])')(?<value>(?:''|[^'\r\n]){12,})'|["']?(?<value>[A-Za-z0-9+/\-_]{12,}=*)["']?)
```

`RunEnd`'s matching-quote search learns the same escapes: after `"` it skips `\` and the character after it, after `'`
it skips `''`, and the run ends at the first unescaped matching quote (or the end of the line, as today). Without a
closing quote on the line the quoted alternative doesn't match (an apostrophe in prose opens nothing); unquoted spaced
values stay out of reach (T45 A8). The trade-off of the label exclusion: an unknown value shaped exactly like
`[REDACTED: x]` after a keyword stays in clear; that's accepted, since such text is what `redact` writes.

Tests (`RedactTests.cs`, the `MaskUnknownSecrets` table; T45's rows keep their results):

| Input | `Masked` | `Hits` |
|---|---|---|
| `password: "correct horse battery staple"` | `password: "[POSSIBLE SECRET]"` | `(1, "password")` |
| `password='correct horse battery staple' next` | `password='[POSSIBLE SECRET]' next` | `(1, "password")` |
| `password: "it's a long phrase here"` | `password: "[POSSIBLE SECRET]"` | `(1, "password")` |
| `secret: "see the README file"` | `secret: "[POSSIBLE SECRET]"` | `(1, "secret")` |
| `api_key: "abc!def$ghi&jkl"` | `api_key: "[POSSIBLE SECRET]"` | `(1, "api_key")` |
| `password: "aaaa\"bbbbbbbbbbbb"` | `password: "[POSSIBLE SECRET]"` | `(1, "password")` |
| `password: 'it''s a long passphrase'` | `password: '[POSSIBLE SECRET]'` | `(1, "password")` |
| `token: "abcdefghij\"k"` (12 items) | `token: "[POSSIBLE SECRET]"` | `(1, "token")` |
| `token: "abcdefghi\"k"` (11 items) | unchanged | empty |
| `token: "two words"` | unchanged | empty |
| `password: correct horse battery staple` | unchanged | empty |
| `password: "no close quote` | unchanged | empty |
| `password: "[REDACTED: db-pw]"` | unchanged | empty |
| `password: "[POSSIBLE SECRET]"` | unchanged | empty |

Each row asserts, as T45 A2 does, that the replaced text appears nowhere in `Masked` or in a `Hits` keyword. Command test
(`CommandTests.cs`, next to `Redact_MasksSuspectedUnknownSecret_WarningShowsNoValue`): `db-pw` = `known-secret-value-42`;
the file `password: "known-secret-value-42"\nphrase: x\ntoken: "correct horse battery staple"\n`; stdout is exactly
`password: "[REDACTED: db-pw]"\nphrase: x\ntoken: "[POSSIBLE SECRET]"\n`; stderr is exactly the one T45 warning for
line 3 and `'token'`; neither stream contains `known-secret-value-42` or `correct horse`.

Break-it-once (three runs): (a) remove the quoted alternative: row 1 must fail; (b) remove the label exclusion: the last
two rows and the command test must fail; (c) make `RunEnd` stop at the first quote character again: the two escape rows
(`aaaa\"…`, `it''s…`) must fail.

## Task 4: docs

- `docs/commands.md`, the "Fingerprints" section: one sentence that `redact` masks a value with line breaks whatever the
  line endings of the value and of the file (`\r\n` or `\n`). In the T45 paragraph, the spaced-value example becomes: a
  quoted value of 12 or more characters after such a keyword is masked whole, spaces and escaped quotes included
  (`password: "correct horse battery staple"`), which also masks a quoted description (`secret: "see the README file"`);
  an unquoted one with spaces still slips through.
- `docs/security-model.md`, the "what `run` masks" table: remove "a `\r\n` value printed with `\n` only" from the "no" row
  (line 298) and add "or printed with `\n` only" to the multi-line row (line 299).
- `TswapCore/Prompt.cs`, the command descriptions and `RedactCommand.Description` stay as they are.

## Out of scope

- `tocomment` (T50b), `TswapCore/Validation.cs` and `run`'s guards.
- A new fingerprint variant or variant-set version (the views make it unnecessary).
- Values made only of whitespace; the guessing-oracle rate limit (#252).
