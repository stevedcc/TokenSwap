# Brief T30: short values are masked only as whole words, in `redact` and `run`

Issue: https://github.com/stevedcc/TokenSwap/issues/314 (the matching part; T21 shipped the warning part as PR #317,
and the fields of #311 shipped as PR #325, which T21 named as the precondition). Base: `origin/main` at c6d2ee3.
Read AGENTS.md and CLAUDE.md first, then the issue and its comments (`gh issue view 314 --repo stevedcc/TokenSwap
--comments`; the owner's design decision is the last comment), `docs/briefs/t21-short-value-warning.md`, and:
- `TswapCore/SecretMatcher.cs` (`Redact`, `Entries`, `Select`, `SelectToComment`, `WholeValueToken`) and
  `TswapCore/ToCommentProcessor.cs` (`AnchoredPatterns`: tocomment's own `(?<![-\w])…(?![-\w])` boundary);
- `TswapCore/Fingerprints/FingerprintIndex.cs` (`Build`, `Scan`), `FingerprintScanner.cs` (`Build`, `Scan` with its
  `ScanState` carry and the dedupe loop at :287, `PendingFromCore` at :318 and the timing rule in the class comment),
  `FingerprintSet.cs`, `SecretVariants.cs`;
- `TswapCli/FingerprintStreamMatcher.cs` and `TswapCli/Commands/RunCommand.cs` (the `Redact` local function at :156,
  `replacements` at :250, `FingerprintStreamMatcher.For` at :261); RedactingPty 1.2.0's `StreamRedactor`
  (`ProcessWithMatchers`: the hold is the minimum of the plaintext pending point and every matcher's `PendingFrom`,
  pulled back over straddling occurrences and surrogate pairs; `Mask` drops occurrences ending past the hold;
  `ResolveTail` on `Flush`/`Release`), source at `~/RiderProjects/redactingpty-wt/main` (`git show
  v1.2.0:RedactingPty/StreamRedactor.Matchers.cs`);
- `TswapCore/Redaction.cs`, `TswapCore/Validation.cs` (`ShortValueLength`, `IsShortValue`), `TswapCli/ValueWarnings.cs`,
  `TswapCore/Fields/FieldSecretCheck.cs`, `TswapCore/Broker/BrokerRedactor.cs`;
- tests: `RedactBehaviourPinTests`, `RedactEngineTests` (and `PlaintextRedactOracle`, frozen), `FingerprintScannerTests`,
  `FingerprintStreamMatcherTests`, `RunVaultRedactionTests` (and `RecordingPty`, whose `ChunkSize` feeds the real
  `StreamRedactor`), `ShortValueWarningTests`, `BrokerShortSecretRedactionTests`;
- `docs/security-model.md` "What `run` masks" (the "Values are matched anywhere" limit at :282) and
  `docs/commands.md:231-240` (the short-value paragraph).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services,
`TSWAP_CONFIG_DIR` and temp folders only. No test uses the real clock or a sleep. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion except where this brief
sanctions it by name (say so in the commit). If an existing test not named below fails because it expected a value
shorter than 8 characters to be masked inside a longer word or number, stop and report it with the test's name; don't
change it. British spelling in new text.

**Parallel briefs.** T29 (YubiKey service and locking), T31 (reading input at prompts, FIDO2 messages) and T32
(vault-password-file logic, `names`) run at the same time. T30 touches none of their files. Two shared files, by part:
`TswapCore/Prompt.cs` is the agent skill text (not prompt input), and T30 edits only key rule 12's last sentence;
`TswapCore/Validation.cs`: only the doc comment of `ShortValueLength`. In the docs T30 edits only the two passages
named in Task 3.

**Review history.** None yet: drafted 2026-11-16 for review round 1.

## Why

`run` and `redact` mask a stored value wherever it occurs, also inside longer words and numbers, with no lower bound
on length. The issue (dogfooding 0.3.0, 2026-11-15):

- "Chargehand calls the OpenCode server's API through `tswap run curl …`. The vault held an SMTP port (3 digits). A
  token count such as `65465` in the session list came out as `65[REDACTED: k8s-…-email-port]`: 66 replacements,
  invalid JSON, and Chargehand's watcher went blind (exit 10)".
- "A database name equal to the product name hid that word everywhere in `redact`'s output of a Helm values file
  (`[REDACTED: …]-[REDACTED: …]-secret-key`), and a username equal to part of `postgresql` cut that word in half";
  in a comment: "a username that equals the first part of a Kubernetes namespace hid that part in every `redact` of the
  namespace's manifests (`namespace: [REDACTED: …]-ngx`)". "A username equal to a common first name replaced that name
  inside a home directory path."
- "False burns. Each of those reveals the value (the reader sees which word disappeared), so the agent has to burn
  the secret: 7 of the 13 entries still burned in my vault are usernames or flags burned this way."

The owner's decision (issue comment, 2026-11-15): "**whole-token matching only for short values** (stored length under
8 characters), in `redact`, `tocomment` and `run`; longer values keep substring matching. Reason: `run` and the broker
redact output that may be hostile, and whole-token matching for every value would let a command leak a secret by
gluing it to letters (`echo x{{pw}}x`); the broker's guarantee ("never emits a known form", pinned by
BrokerShortSecretRedactionTests) stays unchanged. Short values are exactly where in-word matching does harm (ports,
usernames, `False`) and where hiding can't be reliable anyway, hence the warning at create/ingest/add/rotate naming
the threshold." T21 shipped that warning and left the matching until fields (#311) existed; they do now.

What this fixes and what it doesn't: `65465`, `1465`, `postgresql`, `web-ngx` and `/home/webster` stop being cut. A
short value that stands as a word of its own (`False` in `x is False`, `465` in `"port": 465`) is still masked: it
can't be told from the secret itself. Such a value belongs in a field (#311), which the warning and prompt rule 12
already say.

## The design (decided; rulings marked)

### The boundary rule

A **word character** is what tocomment's `[-\w]` matches: a letter (Unicode categories Lu, Ll, Lt, Lm, Lo), a
non-spacing mark (Mn), a decimal digit (Nd), connector punctuation (Pc, `_` among them), or `-`. (Checked against
.NET 11: `^[-\w]$` matches exactly those categories plus U+002D; not Mc, not U+200C/U+200D.)

An occurrence `text[start, start + length)` is **delimited** when, at each of its two ends whose character is a word
character, the character beyond that end is not a word character. The start and the end of the text count as
non-word neighbours. An end whose character is not a word character constrains nothing (`#42` is found in `x#42`).

| Text | Value | Delimited |
|---|---|---|
| `65465`, `1465`, `4650` | `465` | no |
| `port=465`, `"465"`, `:465/`, `465` (whole text) | `465` | yes |
| `web-ngx`, `webster`, `user_web`, `éweb` | `web` | no |
| `web.example`, `host: web` | `web` | yes |
| `x#42` | `#42` | yes (its left end is `#`) |
| `142!` | `42!` | no (`4` after `1`); `a 42!b`: yes (its right end is `!`) |
| `😀465😀` | `465` | yes (surrogate halves are not word characters) |

- Ruling: the word class is tocomment's `[-\w]`, `-` included — one definition in tswap, and kebab-case names
  (Kubernetes, Helm: the issue's `…-ngx` and `…-secret-key` cases) are the owner's main `redact` input; base64url's
  alphabet is exactly this class — cost if wrong: a short secret glued to a `-` (`--pw-x`) is not masked.
- Ruling: no decimal-number rule: `.` is a delimiter, so `465` is masked in `1.465` and `465.5` — one class, no
  look-ahead of two characters — cost if wrong: a JSON decimal whose integer or fraction digits equal a short value is
  still corrupted (owner question 2).
- Ruling: neighbours are read in the **input**, never in the output: `<long secret>465` gives `[REDACTED: long]465` —
  the rule stays a property of the text, independent of which other values were masked first — cost: a short value
  glued to another masked value shows (the same class as gluing it to a letter, which the owner accepted).
- Ruling: astral characters (surrogate pairs) and lone surrogates are non-word, combining marks (Mn) are word
  characters, as in .NET's `\w` — cost: an astral letter next to a short value doesn't protect it from masking
  (masks more, never less).

### Which values, and which of their forms

- A value version is **short** when its plain fingerprint entry (`VariantKind.Plain`, whose `Length` is the value's
  length in UTF-16 code units) is shorter than `Validation.ShortValueLength` (8). In `run`, a substituted value is
  short when `Validation.IsShortValue(raw)` (the same unit), checked only for a non-empty raw value.
- Ruling: one threshold, T21's 8, in one place (`Validation.ShortValueLength`) — the owner's decision names it, and the
  store-time warning then describes exactly the values the rule applies to — cost: an 8-to-10-character non-secret
  (a long username) still cuts words; the remedy is a field.
- Ruling: shortness belongs to the value version and applies to **every form** of it (plain, whitespace-stripped,
  base64, base64url; in `run` also its escaped file forms and their encodings), each checked by the rule above on its
  own ends — a short value's base64 is at most 28 characters (12 for ASCII) and as likely to occur inside an unrelated word as the
  value — cost: a short secret's base64 glued inside a longer base64 run isn't masked (a base64 inside a larger blob is
  already a pinned gap in "What `run` masks").
- `name` and `name:previous` are separate versions: a long current value with a short previous one is matched
  anywhere as `name` and whole-word as `name:previous`.
- Ruling (owner): values of 8 characters or more keep matching anywhere, in every form.

### Where values are matched, command by command

| Place | Today | After T30 |
|---|---|---|
| `redact` (`SecretMatcher.Redact`), and `tocomment --dry-run`'s redacted "before" lines (which use it) | anywhere | short: delimited only |
| `tocomment`'s replacements (`SelectToComment`, `AnchoredPatterns`), literal-block adoption (`WholeValueToken`, T20), the block-scalar report (T22) | `[-\w]` boundary for every value | unchanged (already stricter than the rule: it rejects every hit the rule rejects) |
| `run`: every fingerprinted vault value (`FingerprintStreamMatcher` over `FingerprintScanner`) | anywhere | short: delimited only, across chunk boundaries (below) |
| `run`: its own substituted and `--env` values and their written forms (`StreamReplacement`s to RedactingPty) | anywhere | long: unchanged; short: moved into the matcher, delimited only |
| `check` | matches no values (markers only) | unchanged |
| The fields guards (`FieldSecretCheck.Refusal`, `FieldsContaining`) | anywhere | unchanged |
| The broker (`BrokerRedactor`, `BrokerTemplateOutput`) | every known form anywhere | unchanged |

- Ruling: the fields guards stay substring — they keep secrets out of text that is shown in clear, so finding more is
  the safe side, and they act at write time where a false hit costs one retry, not corrupted output — cost: a field
  value that merely contains a short secret is refused (#311's rule, unchanged).
- Ruling (owner): the broker is unchanged; `BrokerShortSecretRedactionTests` must pass untouched.
- Ruling: no JSON mode (issue proposal 2) — the owner's decision doesn't include it, and whole-word matching already
  removes the in-number case — cost: a short value standing as a JSON number (`"port": 465`) is still masked, which
  breaks that JSON (owner question 4).

### Streaming (`run`)

RedactingPty calls the matcher with windows (held tail + new chunk) and doesn't say what came before a window or
whether more follows.

- **The window's edges count as boundaries**, so an occurrence touching either edge is reported. That is never the
  unsafe side: at a true end of output (`Flush`) or a released prompt (`Release`) it is correct, and otherwise it
  only masks more.
- **The right edge is decided later, not guessed.** A short occurrence ending at the window's end lies inside the
  held tail (the scanner's `PendingFrom` holds the trailing run of each indexed class's characters, non-whitespace
  among them, up to at least 255 characters, and a short version's longest form, the base64 of 7 UTF-16 code units, is
  at most 28): the redactor drops it from the emitted part and the next window decides it with its right neighbour.
  Pinned by tests, not new code.
- **The left edge: the pending point never splits a word when it can help it.** New
  `TokenBoundary.HoldOutsideWord(text, pending)`: when `0 < pending`, `text[pending − 1]` is a word character and
  either `pending == text.Length` or `text[pending]` is a word character, it returns the start of the run of word
  characters that ends at `pending − 1`, if that start is at most `TokenBoundary.WordHoldLimit` (256) characters
  before `pending`; otherwise `pending` unchanged. The next window then starts on a word's first character, where "the
  window's start is a boundary" is true. The scanner applies it at the end of `PendingFromCore` in `WholeToken` mode
  when its index is not empty (`_candidates.Count > 0`), and `FingerprintStreamMatcher.PendingFrom` applies it again to
  its own minimum when the scanner's index or the short forms are not empty (idempotent; a matcher with neither
  holds nothing extra). It reads the text and a constant only, so the class
  comment's timing rule still holds.
- Ruling: no left context is carried in `ScanState` — RedactingPty's hold can be earlier than the matcher's pending
  point (another matcher, plaintext prefixes, pull-backs), so a carried "previous character" can be the wrong one, and
  a wrong one could hide a real hit; treating an unknown start as a boundary can only mask more — cost: an in-word
  false mask remains possible in three rare cases, each masking more and never less: a run of word characters longer
  than 256 split at a chunk boundary with a short value exactly at the split; a chunk ending in a held proper prefix of
  a long substituted value's form (RedactingPty's own plaintext hold); output released at a prompt in mid-word.
- `ScanState.Hits` keeps the **raw** hits (unfiltered): a hit carried from the previous window is filtered again
  against the new window, where its right neighbour may now be known.

### `run`'s own short values

`RunCommand`'s `Redact(name, raw, written)` puts every variant of every form of a short `raw` into a new
`shortForms` dictionary (text → `[REDACTED: {name}]`, `TryAdd`) instead of `redactions`; long values go to
`redactions` as today. A text present in both keeps only its `redactions` entry (anywhere wins). `replacements` is
built from `redactions` only, and the matcher is `FingerprintStreamMatcher.For(metadata, fingerprintKeys,
shortForms)`. The matcher reports every occurrence of every short form (overlapping ones included) that is delimited
in the window, holds back at least as many characters as its longest short form has (`PendingFrom` ≤
`window.Length − longest short form`, clamped at 0), and its `MaxMatchLength` is at least the longest short form. Ruling: the short
forms are matched in the matcher, not by fingerprints computed in memory — `Redaction.Variants` and `Apply`'s escaped
forms are more forms than a fingerprint set holds, and dropping any would be a leak — cost: a few plaintext
`IndexOf`s per window, for values `run` already holds in plaintext.

### Burns, warnings, refusals

- Ruling: an occurrence the rule rejects is left as it is, silently: no note, no count, no burn — tswap never burns on
  its own, and a note saying "a short value occurred inside a word" would confirm guesses (a command printing
  candidates and reading the note) and bring back the false burns this brief removes — cost: a real short secret
  printed inside a longer word shows unmasked with nothing pointing at it; the store-time warning is the defence.
- Nothing new refuses (the owner prefers warnings). The T21 warning stays where it is (`add`, `ingest`,
  `ingest --rotate`, `create`, `rotate`; stderr after the success line, exit code unchanged) with its text changed to
  the new behaviour, exactly:

  `Warning: the value of 'NAME' is shorter than 8 characters. 'run', 'redact' and 'tocomment' hide a value this short only where it stands as a whole word or number, not inside a longer one, so a secret this short can show unmasked there. If it isn't a secret (a username, a port, a setting), store it as a field of the secret it belongs to.`

  (`8` from `Validation.ShortValueLength`; it still names the secret and the reason only, never the value or its
  length.)
- Prompt key rule 12 keeps its number, its first sentence and its last words; its second sentence becomes exactly:
  `tswap hides a short value wherever it stands as a whole word or number, so they get hidden in unrelated output and get burned for no reason`
  (an agent that sees `[REDACTED: x]` still burns as rule 4 says; what goes away is the in-word mask that gave a
  value away).

### Types (new or changed)

- New `TswapCore/Fingerprints/TokenBoundary.cs`: `public static class TokenBoundary` with `public const int
  WordHoldLimit = 256`, `public static bool IsWordChar(char c)`, `public static bool IsDelimited(ReadOnlySpan<char>
  text, int start, int length)`, `public static int HoldOutsideWord(ReadOnlySpan<char> text, int pending)`,
  `public static bool IsShort(FingerprintSet set)`; and `public enum ShortValueMatching { Anywhere, WholeToken }`.
- `FingerprintIndex`: new `public bool IsShortValue(FingerprintHit hit)` (true when the set the hit came from, keyed
  by `(Name, IsPrevious)`, `IsShort`). `Scan` is unchanged (the fields guards use it).
- `FingerprintScanner.Build(sets, keys, ShortValueMatching shortValues = ShortValueMatching.Anywhere)`. `FingerprintHit`
  is unchanged (tests compare hits by record equality).
- `FingerprintStreamMatcher.For(VaultMetadata metadata, FingerprintKeys keys, IReadOnlyDictionary<string, string>?
  shortForms = null)`, always building its scanner with `WholeToken`.

## Task 1: the rule, and `redact`

`TokenBoundary` as above. `FingerprintIndex.Build` records the short sets; `IsShortValue(hit)` answers from them.
`SecretMatcher.Entries` gains a `bool wholeTokenShortValues` parameter: when true, a hit with
`index.IsShortValue(hit) && !TokenBoundary.IsDelimited(text, hit.Start, hit.Length)` is skipped before it is grouped.
`Select` (used only by `Redact`) passes true; `SelectToComment` passes false. `Redact.RedactContent(string, SecretsDb)`
(the test facade) goes through the same matcher, so it follows the rule.

Tests, `TswapTests/TokenBoundaryTests.cs`:
- `IsWordChar_EqualsToCommentsClass`: for every UTF-16 code unit 0 to 0xFFFF, `IsWordChar(c) ==
  Regex.IsMatch(c.ToString(), @"^[-\w]$")`.
- `IsDelimited` theory: every row of the table above, as `(text, start, length, expected)`.
- `HoldOutsideWord` theory: `("ab 65465", 5)` → 3; `("ab 65465", 8)` → 3; `("ab 65465", 2)` → 2 (`text[2]` is a
  space); `("ab cd", 3)` → 3; `(" " + 256 × 'x', 257)` → 1 (exactly 256 back); `(" " + 257 × 'x', 258)` → 258 (one
  further: unchanged); `("", 0)` → 0.
- `IsShort`: the set of a 7-character value is short, of an 8-character value not.

Tests, `TswapTests/ShortValueRedactTests.cs` (through `Redact.RedactContent(content, db)` with `SecretsDb`s as
`RedactBehaviourPinTests` builds them; `p` holds `465` unless said otherwise):
- `Redact_IssueExamples`: `65465` and `1465` come back unchanged; `port=465` gives `port=[REDACTED: p]`, `"465"` gives
  `"[REDACTED: p]"`.
- `Redact_ShortValue_EveryDelimiter`: theory over `d` in ` `, `"`, `'`, `=`, `:`, `@`, `/`, `.`, `,`, `(`, `)`, `[`,
  `]`, `{`, `}`, `;`, `+`, `\n`, `\t`, `😀`: `a{d}465{d}b` gives `a{d}[REDACTED: p]{d}b`; also `465` alone, `465 x` and
  `x 465` (the text's edges).
- `Redact_ShortValue_WordNeighbours_Unchanged`: theory over `w` in `x`, `Z`, `5`, `_`, `-`, `é`: `{w}465`, `465{w}`
  and `{w}465{w}` come back unchanged.
- `Redact_JsonWithShortNumericValue_StillParses`: `{"in":65465,"out":1465,"sum":4650,"id":"x465"}` comes back
  byte-identical and `JsonDocument.Parse` accepts it; `{"port":"465"}` gives `{"port":"[REDACTED: p]"}`, which parses,
  and its `port` property's string is `[REDACTED: p]`.
- `Redact_ShortWord_InsideLongerWords` (`u` holds `post`, `w` holds `web`): `postgresql`, `repost`,
  `namespace: web-ngx`, `/home/webster` unchanged; `user=post` gives `user=[REDACTED: u]`, `host: web.example` gives
  `host: [REDACTED: w].example`.
- `Redact_PasswordInUrl_StillMasked` (`pw` holds `pw1`): `https://user:pw1@host/` gives
  `https://user:[REDACTED: pw]@host/`.
- `Redact_LongValueInsideWord_StillMasked`: `long` holds `s3cr3t-long-value`; `abcs3cr3t-long-valuexyz` gives
  `abc[REDACTED: long]xyz`.
- `Redact_Threshold_SevenAndEight`: `abcdefg` is not masked in `xabcdefgx`; `abcdefgh` gives `x[REDACTED: s]x` in
  `xabcdefghx`.
- `Redact_ShortValueEncodedForms_WholeTokenOnly`: `b64=NDY1 xNDY1` gives `b64=[REDACTED: p (base64)] xNDY1`.
- `Redact_ShortPrevious_LongCurrent_EachByItsOwnLength`: `p` current `long-value-12`, previous `465`:
  `x465x 465 xlong-value-12x` gives `x465x [REDACTED: p:previous] x[REDACTED: p]x`.
- `Redact_ShortTwinOfALongValue_LongStillMasked`: `a-short` holds `1234567` (base64 `MTIzNDU2Nw==`), `b-long` holds
  `MTIzNDU2Nw==`: `xMTIzNDU2Nw==` gives `x[REDACTED: b-long]` (the rejected short twin, first in tie order, doesn't
  block the long value).
- `Redact_SymbolEdges_Unconstrained`: `#42` in `x#42` gives `x[REDACTED: s]`; `42!` is not masked in `142!` and gives
  `a [REDACTED: s]b` in `a 42!b`.
- `ToComment_ShortValue_Unchanged` (a pin: passes before and after; say so): `port: 465` gives
  `port: ""  # tswap: p`, `n: 65465` stays.
- `Redact_Command_JsonFile` (a record vault through `FleetMachine`, as `RedactWithoutDecryptingTests` runs `redact`):
  `ingest` `k8s-mail-email-port` = `465` and `db-pw` = `long-db-password-1`; the file
  `{"in":65465,"pw":"long-db-password-1","port":"465"}` gives exactly
  `{"in":65465,"pw":"[REDACTED: db-pw]","port":"[REDACTED: k8s-mail-email-port]"}` on stdout, which parses.

Break-it-once:
- `IsDelimited` returning true always: `Redact_IssueExamples` fails.
- Skipping the `index.IsShortValue(hit)` check (every value whole-word): `Redact_LongValueInsideWord_StillMasked` fails.
- `IsWordChar` without `-`: `Redact_ShortWord_InsideLongerWords` (`web-ngx`) fails.
- `IsShort` with `<=`: `Redact_Threshold_SevenAndEight` fails.
- Keying short sets by name only (not `(Name, IsPrevious)`): `Redact_ShortPrevious_LongCurrent_EachByItsOwnLength`
  fails.

**Sanctioned changes (inputs only; every expected output literal stays, except where it repeats the input).** These
pin behaviour unrelated to short values with values shorter than 8; their values get 8 or more characters:
- `RedactBehaviourPinTests.EqualLengthTies_DecidedByText_NotPosition`: the `db` values `xab` → `xabcdefg`, `abz` →
  `abcdefgz`, its content `xabz` → `xabcdefgz` (expected `x[REDACTED: z-abz-secret]` unchanged); the `spaced`
  tocomment part unchanged.
- `RedactBehaviourPinTests.SelfOverlappingValue_LeftmostNonOverlapping`: the value `aa` → 8 × `a`; `x aaa` → `x ` +
  9 × `a`; `aaaa` → 16 × `a`; the tocomment line `k: aaa` (input and expected) → `k: ` + 9 × `a`. Expected redact
  outputs unchanged.
- `RedactBehaviourPinTests.QuotesBoundariesAndAnExistingMarker`: every `val123` in the test → `val12345` (the
  tocomment expectations and `LineDiff`s repeat the input).
- `RedactEngineTests.Redact_SecretAcrossAnInsertedLabel_NotReplaced`: `a`'s value `hello` → `hello123`, both contents
  `hellox` → `hello123x`; both expected literals unchanged.
- `RedactEngineTests.Engine_MatchesOracle_OnRandomCorpus` (the frozen oracle matches anywhere, so it can only judge long
  values): `Value(2, 12)` → `Value(8, 16)` and the previous value's `Value(2, 10)` → `Value(8, 14)`. If a generator
  counter then ends at 20 or less, or the seed produces a T20/T22 case, change the seed `16_26` (and only it) and name
  both in the commit.

Files: `TswapCore/Fingerprints/TokenBoundary.cs` (new), `TswapCore/Fingerprints/FingerprintIndex.cs`,
`TswapCore/SecretMatcher.cs`, `TswapTests/TokenBoundaryTests.cs` (new), `TswapTests/ShortValueRedactTests.cs` (new),
`TswapTests/RedactBehaviourPinTests.cs`, `TswapTests/RedactEngineTests.cs`.

## Task 2: `run`

`FingerprintScanner.Build` records the short sets (as the index). In `WholeToken` mode `Scan` filters `found` into a
new list (a short hit not delimited in this window is dropped), **then** dedupes that list as today; `state.Hits`
stays the raw list. `PendingFromCore` ends with `HoldOutsideWord` in `WholeToken` mode when `_candidates.Count > 0`.
`FingerprintStreamMatcher` takes the scanner and the short forms; `FindMatches` adds the scanner's hits and every
delimited short-form occurrence; `PendingFrom` is `Math.Min(scanner.PendingFrom(window, state), Math.Max(0,
window.Length − longest short form))` (the second term only with short forms), passed through `HoldOutsideWord` when
`scanner.MaxRawLength > 0` or there are short forms; `MaxMatchLength`
is `Math.Max(1, Math.Max(scanner.MaxRawLength, longest short form))`. `RunCommand` splits its forms as described.

Tests, `TswapTests/ShortValueStreamTests.cs` (through RedactingPty's real `StreamRedactor([], [matcher])`, as
`FingerprintStreamMatcherTests.Pieces` does; `p` holds `465`, the vault also holds `long-secret-value-1`):
- `Scanner_WholeToken_DropsShortHitsInsideWords`: `65465 465 xlong-secret-value-1x` gives exactly two hits, `p` at 6
  and the long value at 11; the same sets built with the default (`Anywhere`) also give `p` at 2 (the default is
  unchanged).
- `Scanner_WholeToken_ShortTwinOfALongValue_LongStillFound`: the twin pair of Task 1 in `xMTIzNDU2Nw== `: one hit,
  `b-long`.
- `Matcher_ShortValue_EveryCut`: theory of (input, expected): `65465 1465 4650` → unchanged; `port=465` →
  `port=[REDACTED: p]` (the value ends the output); `465 ok` → `[REDACTED: p] ok` (it starts it); `port=4655\n` →
  unchanged; `{"port":"465"}` → `{"port":"[REDACTED: p]"}`. Each fed as two chunks cut at every position, and one
  character at a time: the joined pieces equal the expected text.
- `Matcher_LongJsonLine_EveryChunkSize_Unchanged`: `{"n":[` + 1200 × `65465` joined by `,` + `]}` (no whitespace, so
  the hold is capped inside the line), chunk sizes 1 to 300: the output equals the line and parses. If removing
  `HoldOutsideWord` doesn't make it fail, widen the size range until it does and name the range in the commit.
- `Matcher_ShortForms_WholeTokenOnly`: no vault records, short forms `web` and `d2Vi` → `[REDACTED: user]` and
  `a"b` → `[REDACTED: q]`: `web-ngx /home/webster user=web b64=d2Vi xd2Vi q=a"b ok` gives `web-ngx /home/webster
  user=[REDACTED: user] b64=[REDACTED: user] xd2Vi q=[REDACTED: q] ok`, at every two-chunk cut and one character at a
  time; `MaxMatchLength` is at least 4. (`a"b` has a non-word character inside, so only the short forms' own hold keeps
  its first two characters back after a cut at `a"`.)
- `Matcher_RandomText_ChunkedEqualsWhole` (fixed seed): vaults of short values (1 to 7 characters of letters, digits,
  `-` and `_`) and long ones, current and previous, plus short forms; texts from the short values' forms, the long
  values in plain form only, digits, letters, `-`, `_` and separators, with no run of word characters longer than 200,
  no astral character, and every long value starting with `!` (no short form holds one, so no short form can start
  where a long occurrence starts: the pull-back case of the streaming ruling can't arise); for chunk sizes 1 to 64 and 20 random cut lists each, the joined chunked output equals the
  one-chunk output. Counters (each over 20, as `Engine_MatchesOracle_OnRandomCorpus` does): rounds whose one-chunk
  output holds a short value's label, and rounds where it still holds a short value's plain text inside a word.
- `PendingFrom_WholeToken_DependsOnTextOnly`: `PendingFrom_IndependentOfValues`' method with a short template
  (`p465`) added, both scanners in `WholeToken` mode: equal pending points on every text.
- `PendingFrom_WholeToken_NeverSplitsAWordItCanHold`: for random texts, the returned `p` is never such that
  `0 < p < n`, `text[p − 1]` and `text[p]` are word characters and that word run starts at most 256 before `p`.

Tests, `TswapTests/RunShortValueTests.cs` (command level, `FleetMachine` and `RecordingPty` as
`RunVaultRedactionTests`; `token` = `token-value-1` is the substituted value unless said otherwise):
- `Run_VaultShortValue_InsideNumbers_OutputUnchangedAndParses`: theory over `RecordingPty.ChunkSize` 1, 7, 4096; the
  vault holds `k8s-mail-email-port` = `465`; the child prints `{"in":65465,"out":1465,"sum":4650}\n`; the output is
  byte-identical and parses. (No digit is a first character of the token's forms, `t` and `d`, so RedactingPty's
  plaintext hold never starts a window inside a number.)
- `Run_VaultShortValue_Delimited_Masked`: the child prints `smtp: 465\nurl=mail:465/\n"465"\n`; each `465` becomes
  `[REDACTED: k8s-mail-email-port]`.
- `Run_ShortToken_WholeTokenOnly`: `user` = `web`, `run curl {{user}}`, the child prints
  `web-ngx /home/webster user=web b64=d2Vi\n`; the output is `web-ngx /home/webster user=[REDACTED: user]
  b64=[REDACTED: user]\n`, with `ChunkSize` 1 and 4096.
- `Run_LongToken_InsideWord_StillMasked`: the child prints `xtoken-value-1x\n`; the output is `x[REDACTED: token]x\n`.
- `Run_ShortEnvValue_WholeTokenOnly`: `pin` = `4711`, `run --env PIN={{pin}} curl x`, the child prints
  `pin 4711 and 147110\n`; the output is `pin [REDACTED: pin] and 147110\n`.
- `RunFileToken_ShortValue_WholeTokenOnly`: `q` = `a"b`; a values file `p: ""  # tswap: q`; the child prints the
  filled copy and `glued: za"bz\n`; the output holds `p: "[REDACTED: q]"` (the escaped form `a\"b` inside quotes) and
  `glued: za"bz` unchanged.

Break-it-once:
- `FingerprintStreamMatcher.For` building with `Anywhere`: `Run_VaultShortValue_InsideNumbers_OutputUnchangedAndParses`
  fails.
- Dropping a rejected hit inside the dedupe loop (comparing with the previous raw element): the twin test fails.
- Treating the window's end as a word neighbour: `Matcher_ShortValue_EveryCut` (`port=465`) fails; its start:
  (`465 ok`) fails.
- Removing `HoldOutsideWord` from both places: `Matcher_LongJsonLine_EveryChunkSize_Unchanged` fails.
- Keeping short values in `redactions`: `Run_ShortToken_WholeTokenOnly` fails.
- Leaving out the short forms' hold in `PendingFrom`: `Matcher_ShortForms_WholeTokenOnly` fails at some cut.

No existing test changes in this task: `FingerprintScannerTests` build with the default; `FingerprintStreamMatcherTests`
and `RunVaultRedactionTests` use values of 8 or more, or delimited ones (`Run_OtherSecretBase64UrlPadded_…`: `w7_Dv3g`
is followed by `=`), checked in drafting.

Files: `TswapCore/Fingerprints/FingerprintScanner.cs`, `TswapCli/FingerprintStreamMatcher.cs`,
`TswapCli/Commands/RunCommand.cs`, `TswapTests/ShortValueStreamTests.cs` (new), `TswapTests/RunShortValueTests.cs`
(new).

## Task 3: the warning, the prompt, the docs

- `ValueWarnings.ShortValue`: the text above; its doc comment and `Validation.ShortValueLength`'s say what the rule
  now is.
- `Prompt.cs` key rule 12: the second sentence above. `ShortValueWarningTests.Prompt_LastKeyRule_NeverStoreNonSecretSettings`
  and `PromptTests.Prompt_FieldRules` keep passing unchanged. New test in `ShortValueWarningTests`:
  `Prompt_Rule12_SaysWholeWord` (rule 12, with whitespace collapsed as `Prompt_FieldRules` does, holds `wherever it
  stands as a whole word or number` and not `also inside longer words`).
- `docs/security-model.md`, "What `run` masks", Limits: the "Values are matched anywhere" bullet becomes "**Short values
  are matched as whole words only**": the rule and its word class, the 8-character threshold, all forms of a short
  version, examples (`465` in `port=465` and `"465"`, not in `65465`; `web` not in `web-ngx`), why long values match
  anywhere (hostile output, `x{{pw}}x`), what that costs (a short secret inside a longer word or next to another masked
  value shows, with no notice, and why there is none), tocomment's boundary for every value, the fields guards and the
  broker unchanged, and the streaming residual (rare extra masks at chunk boundaries, never fewer). The "Held output at
  a prompt" bullet: the trailing word may be held up to 256 characters further back. Nothing else in the file.
- `docs/commands.md:231-240`: the reason in the short-value paragraph becomes the new behaviour (as the warning
  says); nothing else, and no command `Description` changes, so the generated reference is untouched.

Tests: `ShortValueWarningTests.Warning` (the private helper every warning assertion uses) gets the new text.
**Sanctioned change:** that helper's literal (the pinned message changes by design); every assertion keeps its exact
form. Break-it-once: restore the old text in `ValueWarnings.ShortValue`; `Add_SevenCharacters_Warns_StoresTheValue`
fails. Restore rule 12; `Prompt_Rule12_SaysWholeWord` fails.

Files: `TswapCli/ValueWarnings.cs`, `TswapCore/Validation.cs` (doc comment), `TswapCore/Prompt.cs`,
`TswapTests/ShortValueWarningTests.cs`, `docs/security-model.md`, `docs/commands.md`.

## Questions only the owner can answer

1. `-` as a word character (ruling above): kebab-case names stop being cut, and a short secret glued to a `-` is not
   masked. Keep it, or use `\w` alone (then the issue's `…-ngx` and `…-secret-key` cases stay as they are)?
2. Decimals: with `.` a delimiter, `465` is still masked in `1.465` and `465.5`. Add a rule that a digit next to `.`
   followed by a digit continues the number?
3. #314 proposal 4: flag existing short values in `check` or `names` (a follow-up after T32, which owns `names`)?
4. #314 proposal 2: a JSON mode is not built. Close it, or a follow-up?
5. The fields guards stay substring (a field value containing a short secret is refused). Keep, or make that refusal a
   warning for short secrets?

## Out of scope

The broker; a JSON mode (#314 proposal 2); a decimal-number rule; flagging existing short values in `check` or `names`
(#314 proposal 4; `names` is T32's); any change to the fields guards, `Redaction.Variants`, `SecretVariants` or the
fingerprint format (no reindex); carrying left context through `ScanState` or a RedactingPty API change for it;
`Redact.RedactLine` (used by tests only); entropy checks (#9). Owner, before release: `TSWAP_PERF=1 ./runtests.sh
--perf` (the redaction throughput budget, now with `HoldOutsideWord` and the short forms in the matcher).

## Owner answers (2026-11-16)

- `-` counts as a word character: yes (the ruling above stands).
- A decimal-number rule: no (`.` stays a boundary; `465` is still masked in `1.465`).
- `check`/`names` flagging existing short values (#314 proposal 4) and the JSON mode (#314 proposal 2): follow-up issues, not T30.
- The fields guard's refusal for short secrets stays as it is (out of scope).
