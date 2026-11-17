# Brief T39: `run` streams short substituted values line by line again (#341); a fresh matcher per run in `ShortValueStreamTests` (#343)

Issues: https://github.com/stevedcc/TokenSwap/issues/341 (a T30 follow-up; owner, 2026-11-16: "It does need fixing,
but can wait a little", now scheduled for 0.3.1) and https://github.com/stevedcc/TokenSwap/issues/343 (MiMo's T30
review, minor 3; #341 repeats it). Neither has comments. Base: `origin/main` at 51b0b37. Read AGENTS.md and CLAUDE.md
first, then:
- `docs/briefs/t30-redaction-boundaries.md`: "Streaming (`run`)", "`run`'s own short values", Task 2, and amendment
  **A2**, whose flat short-forms hold this brief replaces (the owner accepted that by asking for #341);
- `TswapCli/FingerprintStreamMatcher.cs` (the whole file: `_shortHold`, the constructor, `PendingFrom`, the class
  comment);
- `TswapCore/Fingerprints/FingerprintScanner.cs`: `PendingFromCore` (:352), `RoundUp` (:622), `IsWhitespace`,
  `TrailingRun` (:600-620) and the class comment's timing rule (:26-31); `ScanState` and the carry check in `Scan`
  (:233-238), for the perf note;
- `TswapCore/Fingerprints/TokenBoundary.cs` (`HoldOutsideWord`, `IsDelimited`), `TswapCore/Redaction.cs` (`Variants`:
  the forms `run` builds for a value);
- `TswapCli/Commands/RunCommand.cs:153-167` and `:252-270` (how `shortForms` is filled and handed to
  `FingerprintStreamMatcher.For`; T39 does not change this file);
- RedactingPty 1.2.0's `StreamRedactor.ProcessWithMatchers` (`git show v1.2.0:RedactingPty/StreamRedactor.Matchers.cs`
  in `~/RiderProjects/redactingpty-wt/main`, :85-121): the hold is the minimum of the plaintext pending point and
  every matcher's `PendingFrom`, then pulled back over straddling occurrences and split surrogate pairs; nothing else
  holds (A6);
- tests: `TswapTests/ShortValueStreamTests.cs` (all of it), `TswapTests/RunShortValueTests.cs`,
  `TswapTests/RecordingPty.cs`, `TswapTests/RunRedactionThroughputTests.cs` (`Matcher`, `Throughput_BeforeAndAfter`);
- `docs/security-model.md:347-367`: the "Held output at a prompt" and "The hold-back is observable" bullets.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task and the full `./runtests.sh` at the end, run
as `flock ~/.cache/tswap-suite.lock ./runtests.sh` (another implementer may run a suite at the same time). No hardware
suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders
only. Tests never use the real clock or sleeps. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion; the sanctioned
changes to existing tests are Task 1's (how the matcher reaches `StreamRedactor`) and Task 2's additions to existing test
files (`RecordingPty.Pieces`, `RunRedactionThroughputTests.Matcher`'s optional parameter and its new last `cases` entry,
the private `Forms` helper and the new tests in `ShortValueStreamTests`, the new tests in `RunShortValueTests`); no assertion expression changes anywhere (A2). If
an existing test not named here fails after Task 2, stop and report it with its name. British spelling in new text.

**Review history.** Round 1: GLM "yes", MiMo "no", folded A1-A6. MiMo I-1, `Run_ShortTokenWithWhitespace_Masked`
cannot fail (the vault record `a b` puts its own plain form in the free class, whose hold shadows the matcher's) and
`Matcher_PendingFrom_NeverSplitsAWordItCanHold` had no break: the first is marked a run-level outcome pin, the second
gets a break-it (A1). MiMo M-2 / GLM M1, the sanction sentence vs Task 2's additions to existing test files (A2). MiMo
M-1, the security property overstated a prompt release: "complete occurrence", the documented Limit kept (A3). MiMo M-3
/ GLM M2, the class-and-bucket test's vault and "middle" of a 1-character value (A4). GLM M3 (its first half), the perf run's command
(A5). MiMo M-4 / GLM M3 (its second half), line references re-anchored and the surrogate-pair half of the pull-back named (A6).
Round 2 (MiMo, scoped, "no"), folded A7: I-1, A5's command printed nothing (the console logger hides a passing test's
output): `--logger "console;verbosity=detailed"` added. M-1, four anchors corrected. M-2, the private `Forms` helper
named in A2's list. M-3, GLM M3 had two halves (the command and the anchors): the history now says which.

**Parallel briefs.** T35 (PR #356, Windows output) changes `TswapCli/Commands/RunCommand.cs` around the matcher list
(it builds `matcher = FingerprintStreamMatcher.For(...)` on its own line and adds a `TerminalTitleMatcher` on Windows
consoles) and adds `TswapCli/TerminalTitleMatcher.cs`. **T39 does not touch `RunCommand.cs`** and does not change
`FingerprintStreamMatcher.For`'s signature, so the two merge cleanly; RedactingPty takes the minimum hold over all
matchers, and `TerminalTitleMatcher.PendingFrom` holds only an incomplete title sequence, so T39's streaming outcome
holds on Windows too. T36 (PR #357) edits `docs/security-model.md` in the sharing section (around :831); T39 edits only
the two bullets at :347-367 of the same file. T37 (PR #358, CI) and T34 (enrol follow-ups) touch none of T39's files.
Files T39 changes: `TswapCli/FingerprintStreamMatcher.cs`, `TswapTests/ShortValueStreamTests.cs`,
`TswapTests/RunShortValueTests.cs`, `TswapTests/RecordingPty.cs`, `TswapTests/RunRedactionThroughputTests.cs`,
`docs/security-model.md`.

## Why

**#341.** Since T30, `run`'s own short values (a substituted argument, `--env` value or `{{@file}}` value under 8
characters) are plaintext *short forms* matched in `FingerprintStreamMatcher`. Their hold is flat: `PendingFrom`
returns at most `window.Length − _shortHold`, with `_shortHold = RoundUp(longest + 1) − 1` = 255 for every realistic
short form (`FingerprintStreamMatcher.cs:45`, `:89-90`; amendment A2 quantised it). RedactingPty's hold is the
minimum over matchers, so whenever a short value is substituted the last 255 characters are held on every pause,
whatever they are: `tswap run kubectl logs -f ... {{short}}` shows output in ~255-character batches, and a short
line waits until more output, a prompt release or exit. The scanner's vault values don't have this: `PendingFromCore`
holds per character class, `max(trailing run of the class, n − (cap − 1))`, so a window ending in a line break holds
nothing for whitespace-free values. `docs/security-model.md:349-351` documents the batching as a known cost.

**#343.** `ShortValueStreamTests.Redacted` (:36-43) runs a `StreamRedactor` over a matcher the caller built once, and
`AssertEveryCut` (:52-57), `Matcher_LongJsonLine_EveryChunkSize_Unchanged` (:118-122) and
`Matcher_RandomText_ChunkedEqualsWhole` (its `Redacted` calls, :243-251) call it many times with the same matcher. The matcher's
`ThreadLocal<ScanState>` survives between runs (only `Dispose` clears it) and the scanner's carry check compares text
only (`FingerprintScanner.cs:233-238`), so a run whose first window starts with the previous run's held tail reuses
that run's state. That can only make a test fail spuriously (the one-chunk `whole` is computed the same way), never
pass falsely, but it makes the property test fragile to new seeds and generators, and T39 adds more such tests.

## The design (decided; rulings marked)

**The security property that must not weaken:** no complete occurrence of a real secret value, or of a whole-word
short form, is ever released unmasked across a chunk boundary, a word hold, a window edge or a prompt release (a
partial occurrence released at a prompt and completed later is released as it is: the documented Limit in
`docs/security-model.md`, unchanged by this brief) (A3); the hold depends only on the text and
on quantised aggregates (the leak profile "The hold-back is observable" admits).

**The short forms' hold, by class.** Each short form (a key of the matcher's `shortForms`) falls in one of two classes:
- **whitespace-free**: it contains none of CR, LF, space, tab (the whitespace `SecretVariants` strips, the scanner's
  `IsWhitespace`);
- **with whitespace**: it contains at least one of them.

Per class, `hold = longest == 0 ? 0 : RoundUp(longest + 1) − 1` over that class's forms (today's formula, per class:
never less than the longest form, a multiple of 256 minus 1). `PendingFrom(window)`, `n = window.Length`:
1. `pending = _scanner.PendingFrom(window, _state.Value)` (unchanged);
2. whitespace-free forms present: `pending = Math.Min(pending, Math.Max(TrailingNonWhitespace(window), n − holdWhitespaceFree))`,
   where `TrailingNonWhitespace` returns the start of the trailing run of characters that are not CR, LF, space or tab
   (`n` when the window ends in one of them);
3. forms with whitespace present: `pending = Math.Min(pending, Math.Max(0, n − holdWithWhitespace))` (the flat hold of
   today, for this class only);
4. `pending = TokenBoundary.HoldOutsideWord(window, pending)` when `_scanner.MaxRawLength > 0 || _shortForms.Length > 0`
   (the condition's second half replaces `_shortHold > 0`; same meaning).

Why it is safe: an occurrence of a whitespace-free form that reaches the window's end (complete, so its right
neighbour is still unknown, or a prefix of it) consists of non-whitespace characters, so it lies inside the trailing
non-whitespace run; the pending point is at or before that run's start, or, when the run is longer than the hold, at
`n − hold ≤ n − longest`, at or before the occurrence's start either way. RedactingPty pulls the hold back over any
occurrence that straddles it. A form with whitespace keeps the flat hold, which is today's proven behaviour. Step 4 is
unchanged from T30, so the next window still starts on a word's first character when the word is at most 256 long.

- Ruling: **two classes, not the issue's four** (whitespace-free / base64 / base64url / free). Every short value
  contributes its plain form, and `PendingFrom` takes the minimum over classes; the trailing base64 or base64url run is
  always inside the trailing whitespace-free run, so those classes could never lower the hold below what the plain
  form's class already gives — they would only add code. Classifying a plain form by its exact characters (base64 or
  not) would also make the hold depend on whether the substituted value has punctuation, a finer aggregate than the
  scanner reveals (it classes entries by kind, never by content) — cost: none in held output; the issue's wording is
  not followed to the letter, so say so in the commit.
- Ruling: **a short form with whitespace keeps the flat hold**, as the scanner's free class effectively does for these
  lengths (its whitespace bound, `RoundUp(W)` ≥ 256, is never reached inside 255 characters) — cost: a substituted
  short value containing a space, tab or line break (rare; T21 already warns on short values) still streams in
  batches. Documented in the "Held output" bullet.
- Ruling: **the whitespace test is a private static `IsWhitespace(char c) => c is '\r' or '\n' or ' ' or '\t'` in
  `FingerprintStreamMatcher`**, not a new public member of `FingerprintScanner` (controller default; owner may change).
  Safety needs only that the classification and the trailing run use the same set, which one private member
  guarantees; the comment names `FingerprintScanner.IsWhitespace` as its twin.
- Ruling: **the leak profile changes by one bit**: whether a substituted short value has whitespace (now visible, as
  "whether the vault holds a secret with whitespace" already is for vault values). Both holds are 256-quantised, so
  A2's test (`Matcher_ShortFormsHold_DependsOnTextOnly`) passes unchanged: its two matchers hold only whitespace-free
  forms.
- Line ends flush again: a window ending in `\n` (or `\r\n`) holds nothing for whitespace-free short forms, exactly as
  for the vault's whitespace-free values. A vault that holds a multi-line value (the scanner's free class) still holds
  as today; not this brief.
- **Perf.** With the flat hold, RedactingPty's hold was usually earlier than the scanner's pending point, so the next
  window did not start with the scanner's carried text and its `ScanState` was rarely reused (`FingerprintScanner.cs`
  :233-238). With the class-based hold the two usually agree, so reuse should come back; expected neutral or better.
  Measured by a new case in the owner's perf run (Task 2), not asserted.

**Members, `TswapCli/FingerprintStreamMatcher.cs`.** `_shortHold` is replaced by `private readonly int
_shortHoldWhitespaceFree, _shortHoldWithWhitespace;` (each 0 when its class is empty), computed in the constructor;
new `private static bool IsWhitespace(char c)` and `private static int TrailingNonWhitespace(ReadOnlySpan<char>
text)`. `For`, `FindMatches`, `MaxMatchLength`, `Dispose` and `Label` are unchanged. The class comment's T30
paragraph gains one sentence: "The short forms are held by class as the scanner holds its entries: the trailing run of
non-whitespace characters (at most a 256-quantised bound) for forms without whitespace, the 256-quantised bound itself
for forms with it (brief T39, #341)." Replace the `_shortHold` comment (:32-33, :42-44) to match.

## Task 1: a fresh matcher per `StreamRedactor` run (#343)

In `TswapTests/ShortValueStreamTests.cs`:
- `Redacted(IStreamMatcher matcher, IEnumerable<string> chunks)` becomes `Redacted(Func<FingerprintStreamMatcher>
  newMatcher, IEnumerable<string> chunks)`: it builds the matcher with `using var matcher = newMatcher();` and runs a
  new `StreamRedactor([], [matcher])` over the chunks exactly as today.
- `AssertEveryCut(IStreamMatcher matcher, ...)` becomes `AssertEveryCut(Func<FingerprintStreamMatcher> newMatcher,
  string text, string expected)` and passes the factory to every `Redacted` call (the failure message's second call
  too).
- Call sites: `Matcher_ShortValue_EveryCut` and `Matcher_LongJsonLine_EveryChunkSize_Unchanged` replace `var matcher
  = FingerprintStreamMatcher.For(...)` with a local function `FingerprintStreamMatcher NewMatcher() =>
  FingerprintStreamMatcher.For(...)` (same arguments) and pass `NewMatcher`. `Matcher_ShortForms_WholeTokenOnly` does
  the same, and its `Assert.True(matcher.MaxMatchLength >= 4)` reads it from `using var matcher = NewMatcher();`.
  `Matcher_RandomText_ChunkedEqualsWhole` builds a `NewMatcher` local over the round's `records`, `keys` and
  `shortForms` and passes it to all three `Redacted` calls (`whole`, every size, every cut list).
- `Matcher_ShortFormsHold_DependsOnTextOnly` and the `PendingFrom_*` tests call `PendingFrom` directly, with no
  `StreamRedactor`; unchanged.

**Sanctioned:** these signature and call-site changes in existing tests; no assertion expression changes. Say so in the
commit message. No behaviour changes, so there is no key test and no break-it-once; the evidence is
`ShortValueStreamTests` passing before and after (record both runs' counts in the commit message) and the
`short-labelled` / `short-inside-a-word` counters the random property prints (they must be unchanged, since the fixed
seed and generator are unchanged; quote them).

Files: `TswapTests/ShortValueStreamTests.cs`.

## Task 2: the class-based hold for short forms (#341)

The members above, in `TswapCli/FingerprintStreamMatcher.cs`. All new matcher-level tests use Task 1's factory
helpers.

Tests, `TswapTests/ShortValueStreamTests.cs` (`Forms(string value, string label)`: a new private helper returning a
`Dictionary<string, string>` of every `Redaction.Variants(value)` text to `label`, merged with `TryAdd` when several
values are combined):
- `Matcher_ShortForm_LineEmittedInTheSameChunk` (the issue's test): matcher over `Vault(Record("p", Set("465", keys)),
  Record("long", Set(LongValue, keys)))` with `Forms("web", "[REDACTED: user]")`; **one** `StreamRedactor([],
  [matcher])` (a single run, one matcher). Assert, in order: `ProcessChunk("user=web port=465\n")` ==
  `"user=[REDACTED: user] port=[REDACTED: p]\n"`; `ProcessChunk("a=web\r\n")` == `"a=[REDACTED: user]\r\n"`;
  `ProcessChunk("ok web")` == `"ok "` (the trailing word is held: its right neighbour is unknown); `Flush()` ==
  `"[REDACTED: user]"`.
- `Matcher_ShortFormWithWhitespace_EveryCut`: `Forms("a b", "[REDACTED: s]")` merged with `Forms("x\ny",
  "[REDACTED: m]")`, empty vault; `AssertEveryCut` of `q=a b, z a bc\nv=x\ny ok` gives `q=[REDACTED: s], z a bc\nv=[REDACTED: m] ok`
  (`a bc` is inside a word on its right, so unchanged).
- `Matcher_ShortFormWithWhitespace_KeepsTheFlatHold`: with `Forms("a b", ...)`, `PendingFrom("ok\n")` == 0 and
  `PendingFrom(new string('.', 300) + "\n")` == 46 (301 − 255; dots, so `HoldOutsideWord` does not move it); with
  `Forms("ab", ...)` the same two texts give 3 and 301. (Pins the ruling's cost and the class split.)
- `Matcher_ShortForm_LongNonWhitespaceRun_EveryChunkSize`: `Forms("a\"b", "[REDACTED: q]")`, empty vault; text =
  200 × `x,` + `a"b` + 150 × `,y` + `\n` (one non-whitespace run of 703 characters, longer than the hold); for every
  chunk size 1 to 300 the output equals the text with that `a"b` replaced by `[REDACTED: q]`; and the same text with
  `a"bc` in place of `a"b` comes out unchanged at every size. (The form has a non-word character inside, so
  `HoldOutsideWord` cannot rescue a cut inside it: only step 2's bound keeps it whole.)
- `Matcher_ShortFormsHold_DependsOnClassAndBucketOnly` (fixed seed, `new Random(39_341)`): 200 pairs; each side gets
  1 to 3 random short values (1 to 7 characters of `ShortAlphabet`), and for half the pairs **both** sides also get one
  2-to-7-character value with a space inserted at a random position inside it (neither side otherwise); each side's
  matcher is `FingerprintStreamMatcher.For(Vault(), keys, …)` (an empty vault) over the merged `Forms` of its values (A4).
  For 50 random texts per pair (`RandomString(rng, rng.Next(0, 700), Filler + Word)`), both matchers' `PendingFrom`
  are equal. (A2's property generalised: the hold says nothing about the values beyond their classes' 256-buckets.)
- `Matcher_PendingFrom_NeverSplitsAWordItCanHold`: `PendingFrom_WholeToken_NeverSplitsAWordItCanHold`'s loop and
  assertion over a matcher with an empty vault and `Forms("465", ...)` merged with `Forms("a\"b", ...)`.
- Unchanged and must pass: every existing `ShortValueStreamTests` test (in particular
  `Matcher_ShortFormsHold_DependsOnTextOnly`, A2's equal-hold test; `Matcher_ShortForms_WholeTokenOnly`;
  `Matcher_RandomText_ChunkedEqualsWhole` with its counters still over 20), `RunShortValueTests`,
  `FingerprintStreamMatcherTests`, `RunVaultRedactionTests`, `FingerprintScannerTests`.

Tests, `TswapTests/RunShortValueTests.cs`, with a new `RecordingPty.Pieces` (`public List<string> Pieces { get; } =
[];`: each `ProcessChunk` result in order, then the `Flush` result; `Output` unchanged):
- `Run_ShortToken_LineShownBeforeMoreOutput`: `_m.Ok("web", "ingest", "user")`; `_pty.ChunkSize = 9`; the child
  prints `user=web\nstill running`; `Run("curl", "{{user}}")`: exit 0, `_pty.Pieces[0]` == `"user=[REDACTED: user]\n"`
  (the first line is shown when it is read, before the rest), and `Output` == `"user=[REDACTED: user]\nstill running"`.
- `Run_ShortTokenWithWhitespace_Masked` (theory over `ChunkSize` 1 and 4096): `_m.Ok("a b", "ingest", "s")`; the child
  prints `v=a b\nza bz\n`; `Run("curl", "{{s}}")`: `Output` == `"v=[REDACTED: s]\nza bz\n"`. This is a run-level
  **outcome pin**, not a pin of the class split: every value `run` substitutes is a vault record, and the record's own
  free-class hold covers the same text, so no change to Task 2's classification can make it fail. The class split is
  pinned at the matcher level (`Matcher_ShortFormWithWhitespace_EveryCut`, `..._KeepsTheFlatHold`). It has no
  break-it-once; say so in the commit message (A1).

Break-it-once:
- Replace step 2's term with today's flat `Math.Max(0, n − _shortHoldWhitespaceFree)`:
  `Matcher_ShortForm_LineEmittedInTheSameChunk` and `Run_ShortToken_LineShownBeforeMoreOutput` fail (the line is held).
- Put every form in the whitespace-free class (drop the classification): `Matcher_ShortFormWithWhitespace_EveryCut`
  fails at a cut inside `a b`.
- Compute step 2's trailing run with `TokenBoundary.IsWordChar` instead of non-whitespace:
  `Matcher_ShortForms_WholeTokenOnly` (existing; `q=a"b` cut after `a"`) fails.
- Use `n − 1` as step 2's bound instead of `n − _shortHoldWhitespaceFree`:
  `Matcher_ShortForm_LongNonWhitespaceRun_EveryChunkSize` fails.
- Delete step 4's `HoldOutsideWord` call: `Matcher_PendingFrom_NeverSplitsAWordItCanHold` fails (A1).
- Use each class's exact longest length instead of the 256-rounded hold: `Matcher_ShortFormsHold_DependsOnClassAndBucketOnly`
  and `Matcher_ShortFormsHold_DependsOnTextOnly` fail.

**Perf case.** In `RunRedactionThroughputTests`, `Matcher` gets an optional `IReadOnlyDictionary<string, string>?
shortForms = null` passed to `FingerprintStreamMatcher.For`, and `Throughput_BeforeAndAfter`'s `cases` gets a **last**
entry (last, so the earlier cases draw the same random numbers): `("after D (A + a 5-character token's forms)",
Matcher(Values(rng, 200, 16, 64, 10), keys, <every Redaction.Variants of RandomString(rng, 5, Word)> → "[REDACTED:
short]"))`. Not asserted (the test only prints). Run it once to show it runs:
`TSWAP_PERF=1 TSWAP_PERF_MB=4 flock ~/.cache/tswap-suite.lock dotnet test TswapTests --filter
FullyQualifiedName~RunRedactionThroughputTests --logger "console;verbosity=detailed"` (without the logger a passing test's output is not printed; `RunRedactionThroughputTests.cs:18` uses the same flag) (a Debug build, so the numbers are indicative only) (A5), and quote its lines in the report without judging the numbers (this machine is not the owner's).

**Docs, `docs/security-model.md`** (nothing else in the file):
- "Held output at a prompt": replace the sentence beginning "When `run` substitutes a value under 8 characters" (it
  ends "then arrives in batches.") with exactly: "When `run` substitutes a value under 8 characters (in an argument,
  `--env` or a `{{@file}}`), the trailing run of characters other than whitespace is held as for a vault value (up to
  255 characters), so a line that ends in a line break still shows at once; only when such a value contains a space,
  tab or line break are at least the last 255 characters held on every pause, whatever they are, so streamed output
  (`logs -f`) then arrives in batches."
- "The hold-back is observable": "and, when `run` substitutes a value under 8 characters, one bucket that says only
  that such a value was substituted" becomes "and, when `run` substitutes values under 8 characters, one bucket for
  their forms without whitespace and one for their forms with it, each saying only that such a form exists"; and
  "and whether this run substituted a short value" becomes "and whether this run substituted a short value, and one
  with whitespace". The rest of the bullet stays.

Files: `TswapCli/FingerprintStreamMatcher.cs`, `TswapTests/ShortValueStreamTests.cs`, `TswapTests/RunShortValueTests.cs`,
`TswapTests/RecordingPty.cs`, `TswapTests/RunRedactionThroughputTests.cs`, `docs/security-model.md`.

## Report

Write `t39-report.md` at the worktree's parent folder (`../t39-report.md`). It contains:
- the commits;
- for each break-it-once, the line reverted and the tests that failed;
- Task 1's before/after `ShortValueStreamTests` counts and the random property's counter line;
- the perf case's output lines (quick run, `TSWAP_PERF_MB=4`), marked as not the owner's measurement;
- the full `./runtests.sh` summary lines;
- anything left undone.

## Out of scope

- The scanner's own holds (`PendingFromCore`), including the free class's hold for a vault with multi-line values.
- Narrower classes (base64, base64url) for short forms, and a whitespace-count rule for forms with whitespace (rulings
  above).
- `RunCommand.cs`, `Redaction.Variants`, which forms count as short, and anything in RedactingPty.
- `FingerprintStreamMatcherTests`' own helpers (#343 names `ShortValueStreamTests` only).
- **Owner, before the 0.3.1 release:** `TSWAP_PERF=1 ./runtests.sh --perf` on the owner's machines; compare case D's
  log rate and mean held with case A's.
