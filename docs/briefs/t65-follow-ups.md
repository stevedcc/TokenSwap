# Brief T65: the remaining 0.3.3 follow-ups: a lone CR in redact and run, T58's and T62's loose ends, export links refused, wslg guarded (#434, #435, #436, #440, #448)

This body is authoritative; the amendment history at the end is a record only.

Milestone 0.3.3. Base: `origin/main` at 66c3620 (T58, T62 and T63 merged; this brief's branch, `brief/t65`, starts
there), with `origin/main` at f2e3a5a (T64 merged) merged into it. T64 moved `TswapCore/Validation.cs` (16 lines down
from `:316`) and `TswapCli/Commands/RunCommand.cs` (6 lines down from `:91`): citations in those two files are at
f2e3a5a, every other citation at 66c3620 (no other cited file changed). Read AGENTS.md and CLAUDE.md first, then the
five issues with their comments
(`gh issue view <n> -R stevedcc/TokenSwap --comments`), and: `TswapCore/Fingerprints/LineEndingViews.cs` (all);
`TswapCore/SecretMatcher.cs` (`ViewHits`, `AddViewHits` `:52-88`, `SelectMultiLine` `:334-375`, `Select` `:496-512`);
`TswapCore/Fingerprints/FingerprintScanner.cs` (the summary `:5-41`, `RawLength`/`MaxRawLength` `:96-117`, `Scan`
`:236-330`, `PendingFromCore` `:366-395`, `ScanFree`, `ScanFolded`, `ScanUnfolded` `:478-574`); `TswapCore/Redaction.cs`;
`TswapCli/FingerprintStreamMatcher.cs` (`:41-110`); `TswapCore/Totp/OtpAuthUri.cs`, `TotpSeed.cs` (`:23-60`,
`FromUri` `:91-141`), `TotpCodes.cs`, `CommandValues.cs`, `ValueKind.cs`, `ValueKinds.cs`; the tests
`FingerprintScannerTests` (`Scan_CarriedState_SameHitsAsFreshScan`, `Matcher_CarriedState_SameOutputForEveryChunkSize`
and their helpers), `RunVaultRedactionTests` (the fixture), `RunTotpTests` (the fixture, `Refusal`, `AssertNoSeed`,
`R0Value_InEveryForm_IsRefused`), `TotpParseTests.Classify`, `BrokerTotpTests`, `ValueKindsTests` (the fixture,
`RecordAsOldBuildsWriteIt_IsUnmarked_UntilReindex_WhichRewritesOnlyIt`), `VaultReindexTests` (the fixture). For Task 5:
`TswapCore/Validation.cs` (`ProgramPositions`, `WrappedCommand` `:269-327`, `Wrappers` `:541-550`, `BashLauncherRefusal`
to `BashLauncherWalk` `:821-1031`, `WrapperValued` `:1057-1080`, `CheckWrapper` `:1102-1194`, `WslValued` to
`NoCommandShell` `:1196-1300`), `TswapTests/BashLauncherRefusalTests.cs`, `InlineCodeBlockTests.cs` (`Wsl_…`, `:960-1100`),
`RunBashLauncherTests.cs`, `RunuserWalkTests.cs` and `docs/briefs/t64-wsl-bash-and-enrol-flake.md`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertion changes.** This brief adds test
methods and rows to existing test files, and these named additions to existing tests, none of which changes an
assertion: new `InlineData` rows in `BrokerTotpTests.IsOtpAuth_OnBytes_AgreesWithTheStringForm` and
`TotpParseTests.Classify` (Task 3); one added assertion in `TotpCommandTests.Period1_PrintsEverySecond` (Task 2) and
two in `ToCommentContinuationCommandTests.ToCommentCommand_ContinuationLineHoldingAValue_CommentedOut_Warned_NoLeak`
(Task 4); new test methods in `RunBashLauncherTests` (Task 5); `[Fact]` to `[IcuFact]` on `VaultReindexTests.Reindex_AVersionTwoSetWithoutItsFormEntries_IsRecomputed`
(Task 1). Task 4's deduplication exists so that `FingerprintScannerTests.Scan_LineEndings_ExactlyOneHit` keeps its
assertion (see Task 4). If any other existing test fails on an assertion, stop and list it. No production message and no custom
test failure text contains a value, a seed or an export link's data.

**Test first, every task:** for each test below, write the test, run it and quote the failure, then write the code.
Where a task changes only comments or docs, say so in the commit message and show the grep or test run that proves
the result instead. Where a test pins behaviour that already exists (Task 2's gap tests), it passes as soon as it is
written; then its break-it-once mutation is the evidence: quote the failure under the mutation instead.

**One task per issue; each commit closes its issue** (`Closes #n` in the message), except Task 2, which says
`Part of #435` (one item moves after T60, see Task 2). The tasks are independent: any order; the suggested order is 1,
2, 3, 4, 5. Task 2 and Task 5 both touch `Validation.cs`, in places 500 lines apart (Task 2 one comment at `:332`,
Task 5 the members at `:269-327` and `:541-1300`); neither depends on the other.

**File ownership and merge order.** T60 and T61 (briefs in review) will own `RecordMerge`, `RecordWrites`,
`RecordVaultStore`, `SecretRecordCodec`, `VaultWriter`, `SecretEntry`, `PendingWrite`, `FieldCommand`, `VaultCommand`,
`ConflictsCommand`, `RestoreCommand`, `CommandValues`, `VaultView`, `SecretsDb`, `NamesCommand`, `Validation`,
`Prompt.cs`, `docs/commands.md`, `docs/multi-machine.md` and `docs/security-model.md`. T64 is merged (f2e3a5a). This
brief changes no code in any of them **except Task 5's in `Validation.cs`**, which T60 also edits (its token grammar:
`TokenRegex` and `Validation.cs:1-60`, `:160-180` at its base; T60 brief, "Grammar"), far from Task 5's members, so a
plain text merge is expected. Everything else it changes there is a comment or a doc sentence:

| File | Lines (at 66c3620) | Task | What |
|---|---|---|---|
| `TswapCore/RecordVaultStore.cs` | `:1602-1605` (the `Tombstone` summary) | 2 | comment |
| `TswapCore/Validation.cs` | `:332` at f2e3a5a (`SubstitutedToken`'s summary) | 2 | comment |
| `TswapCore/Validation.cs` | at f2e3a5a: `:541-550` (`Wrappers`), `:821-1031` (the bash launcher walk), `:1057-1080` (`WrapperValued`), `:1113-1115` (`CheckWrapper`'s wsl branch), `:1196-1300` (the wsl walk) | 5 | code |
| `TswapCli/Commands/RunCommand.cs` | `:533-534` at f2e3a5a (`EncodedToken`'s summary) | 2 | comment |
| `AGENTS.md` | `:284-291` | 2 | two phrases |
| `docs/commands.md` | `:84-85` (Task 4), `:629` (Task 3) | 3, 4 | one sentence each |
| `docs/security-model.md` | `:298`, `:302` (Task 4), `:385` (Task 3), `:172`, `:186` (Task 5) | 3, 4, 5 | a few words or a clause each |

Task 5 also changes `docs/broker-threat-model.md:530-531` (no other brief's). Expected order: T64 (merged), then T65,
then T60/T61. Whichever lands second gets a text merge of a comment or a sentence;
if a cited line moved, find it by content. No change here depends on the order, except Task 2's moved item, which
goes after T60. `CommandValues.cs` and `NamesCommand.cs` are **not** touched: Task 3 works through `OtpAuthUri` and
`TotpSeed`, which both already call.

## Checked at 66c3620: what is still open

| Item | State | Evidence |
|---|---|---|
| #434 main (lone CR) | open | `SecretMatcher.ViewHits` builds only the folded and unfolded views (`SecretMatcher.cs:61-68`); so does `run`'s scanner (`FingerprintScanner.cs:282-289`); `LineEndingViews.cs:17` says "A lone `\r` used as a line ending is not a view"; `Redaction.Variants` adds line-break forms only when the spelling holds a `\n` (`Redaction.cs:38`); `docs/commands.md:84-85` says "a lone `\r` as a line ending is not handled" |
| #434 comment 1 | open | `RedactEngineTests`' summary (`:8-18`) lists T20 and T22 as the engine-only `tocomment` differences, not T63 |
| #434 comment 2 | no change now | `PlaintextRedactOracle.cs` was last changed by T54 (`git log`); the fixed seed produces no continuation line holding a value; this brief changes no seed or corpus. Carried into the summary text of comment 1 |
| #434 comment 3 | open | `FieldSecretCheck.cs:15` is 139 columns |
| #434 comment 4 | open | the test asserts the warning with `Assert.Contains` only (`ToCommentContinuationCommandTests.cs:50-53`); the warning is written on the dry run too (`ToCommentCommand.cs:94`) |
| #434 comment 5 | **dropped** | bounded and fail-closed, as the comment says; a value without a line break gives one or two scans (`WithLineBreaks` returns the text itself, `LineEndingViews.cs:88-89`, and `Spellings` is distinct, `FieldSecretCheck.cs:132`); no profile shows it |
| #435.1 AGENTS.md | open | `AGENTS.md:286-287` names `get` and `apply` only; `:288-289` lists `rotate` among the commands that decrypt no value, but `RotateCommand.cs:34-40` decrypts the current value once (`RefuseTotpSeed`) |
| #435.2 stale comments | open | `SecretRecord.cs:35-38` ("one extension type, `Fields`"; `ValueKinds` is `0x0101`, `ValueKinds.cs:20`); `RecordVaultStore.cs:1602-1605` ("every other extension kept"; `FieldEdits.ForTombstone`, `FieldEdits.cs:116-117`, drops `ValueKinds` too); `Apply.cs:41` (`name` or `name:previous`); `RunCommand.cs:526-527` (the issue's `:528`: `{name}`, `{name:previous}` or `{@path}`); `Validation.cs:316` (`name` or `name:previous`) |
| #435.3 | open | the ASCII-spellings comment is at `TotpSeed.cs:153-154`, above `OutsideTheSecret`; `ParseAlgorithm` is at `:166` |
| #435.4 | **dropped** | "This is the record only" (the issue): T58 is merged; the rulings are in PR #433's reviews and in this issue |
| #435.5 | open | `docs/agent-integration.md:20-36` has no `totp` row |
| #435.6 tests | open | no test runs `vault reindex` twice on a TOTP record; no test reaches the `:totp` alternative of `ToCommentProcessor.cs:16`, `SecretMatcher.cs:327` (the issue's `:290`) or `RunCommand.cs:512`; no test reindexes a format 2 TOTP record; `Period1_PrintsEverySecond` asserts `^[0-9]{6}\n$` (`TotpCommandTests.cs:142-151`); `TotpMarker_WithoutAPreviousValue_GivesTheCode_DecryptingOnce` (`RunTotpTests.cs:187-200`) passes without the `previous &&` of `Apply.cs:98` |
| #435.6 the pinned code | **corrected** | GLM proposed `308143`. That is the code for counter 1111111110. At 1111111111 with period 1 the counter is 1111111111 and the code is **`073950`**: checked with Python's `hmac` (RFC 6238 SHA1, key `12345678901234567890`; the same function gives RFC 6238's `287082`/`94287082` at counter 1) and with Otp.NET 1.4.1 itself (`new Totp(key, 1, Sha1, 6).ComputeTotp` at 1111111111000 ms prints `073950`) |
| #435.7 | **moved after T60** | `RecordVaultStore.cs:882` passes `ValueKinds.Classify(v.Value)` to `RecordWrites.Next`; computing it lazily changes `RecordWrites.Next`'s signature, and both files are T60's |
| #435.8 `*.rsp` | **dropped** | a response file can't exist: `DependencyPinningTests.cs:120-127` fails when any `.rsp` (tracked or untracked, `MarkdownLinks.AllTracked` lists both) is in the repository. Task 2 says so in `AotWarningTests`' summary |
| #435.8 csproj note | open | `TswapCli/TswapCli.csproj:25-31` doesn't say the check must be redone after an SDK bump |
| #435.9 | open | `ValueKinds.cs:22` (`Format`) has no comment |
| #436 | open | `OtpAuthUri.IsOtpAuth` (`OtpAuthUri.cs:7`, `:13-25`) looks for `otpauth:` only; `otpauth-migration:` doesn't contain it, so `TotpCodes.Classify` gives `None` and `CommandValues.Resolve` (`CommandValues.cs:80-82`) passes the value on as stored |
| #440.1 | open | `MsysTarget.cs:199-204` |
| #440.2 | open | `PlatformFacts.cs:139` writes `"José"` with a literal `é` |
| #440.3 | open | `VaultReindexTests.cs:188` is `[Fact]`; its NFD assertion can't hold where `Normalize` is a no-op |
| #448 (at f2e3a5a) | open | `wslg` is in no set: `Wrappers` (`Validation.cs:541-550`) and `NameBashWord.Names` (`:887-898`, `wsl` only) don't know it, so `GetBlockedInvocation(["wslg", "./deploy.sh", "{{x}}"])` and `BashLauncherRefusal` give null; `docs/security-model.md:186` names `wsl.exe` only. Also open, found reading WSL's parser: `WalkWsl` (`:1251-1296`) skips a valued option's value as one word, which wsl.exe splits at a space (Task 5, "The parser") |

## Task 1 (#440): three T62 Minors

- **`MsysTarget.cs:199-204`.** Replace the sentence from "A run s[a..b] (a and b boundaries) changes the option
  exactly when," to "so only a run's start matters." with:

  > Some run starting at a boundary a changes the option exactly when, with g = a + P[a], s[g..g+4] "glob" (case
  > ignored) and e = g + 4, either P[a] > 0 and (boundary[e] or s[e] is ':' or '='), or P[a] == 0, s[e] is ':' or '=' and
  > boundary[e + 1]; the word changes it when that holds for some a. The condition is about a start, not one run: in
  > -"glob:x (s = -glob:x, boundaries 0, 1 and 7) it holds at a = 0 through the run s[0..7], while the run s[0..1]
  > ("-") changes nothing. Greedy stripping is deterministic, "glob" starts with neither 'n' nor '-', and a prefixed
  > run with a separator can always be extended to the word's end, so only the start matters.

  Comment only; no test. Evidence: `MsysQuotingTests` and `MsysTargetTests` pass unchanged.
- **`PlatformFacts.cs:139`.** `"Jos\u00e9"`. Evidence: `grep -nP '[^\x00-\x7F]' TswapTests/PlatformFacts.cs` prints
  nothing.
- **`VaultReindexTests.cs:188`.** `[IcuFact]` instead of `[Fact]`, nothing else. Evidence, in the commit message:
  before the change, `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 dotnet test TswapTests --filter
  FullyQualifiedName~Reindex_AVersionTwoSetWithoutItsFormEntries_IsRecomputed` fails; after it, the same run reports it
  skipped, and without the variable it passes.

No docs. Release note: none (tests and comments).

## Task 2 (#435): T58's docs, comments and test gaps

**Docs and comments** (no behaviour change):
- `AGENTS.md:286-287`: "and `get`, `apply` and `totp` decrypt only the records they name (`VaultView`,
  `RecordVaultStore.OpenSecret`; `totp` only the current value's section)". `:288-290`: take `rotate` out of the list
  that decrypts no value and add after it ", `rotate` only the current value, once, to refuse a TOTP seed (brief
  T58)", before "and `restore` only the previous value it puts back".
- `SecretRecord.cs:35-38`: "This build defines two extension types, `Fields` (issue #311;
  `FieldsExtension`, which also lists the types taken) and `ValueKinds` (`0x0101`, brief T58)".
- `RecordVaultStore.cs:1602-1605`: "(burns kept as history; no `Fields` extension, issue #311, and no `ValueKinds`
  one, brief T58; every other extension kept)", as `RecordWrites.Tombstone`'s summary (`RecordWrites.cs:118-119`) says.
- `Apply.cs:41`: "`name`, `name:previous` or `name:totp`". `RunCommand.cs:533-534` (at f2e3a5a): "(`{name}`,
  `{name:previous}`, `{name:totp}` or `{@path}`)". `Validation.cs:332` (at f2e3a5a): "(`name`, `name:previous` or
  `name:totp`)".
- `TotpSeed.cs:153-154`: move the two comment lines to directly above `ParseAlgorithm` (`:166`).
- `docs/agent-integration.md`, after the `run <cmd>` row: `| \`totp <name>\` | Print a TOTP secret's current code
  (stdout) and how long it stays valid (stderr) | The code is a live credential for one period (30 s by default); the
  seed is never shown |`.
- `TswapCli/TswapCli.csproj`, the `IlcTreatWarningsAsErrors` comment (`:25-31`), one more sentence: "After a .NET SDK
  update (global.json), redo T58's check by hand: a throwaway call of a `[RequiresUnreferencedCode]` method in
  Program.cs must fail the Release publish with error IL2026. AotWarningTests can't show that the SDK still honours
  the setting."
- `AotWarningTests`' summary, one sentence: "A response file (`.rsp`) can't carry a setting: `DependencyPinningTests`
  refuses any in the repository."
- `ValueKinds.cs:22`, above `Format`: "// A new format byte needs a `KeyringFormat.RecordFormatVersion` bump, so that
  builds that can't read it refuse the folder: `Decode` gives null for an unknown format, and a write or a reindex
  would then replace the extension with this build's entries."

**Tests.**

| Test (file) | Setup | Outcome |
|---|---|---|
| `Reindex_Twice_TheSecondRewritesNothing` (`ValueKindsTests`) | as `RecordAsOldBuildsWriteIt_…`: ingest `t` = `Sha1Uri`, `p1`, `p2`; `Unmark("t")`; `Reindex()`; then read the bytes of every record file; `Reindex()` again | the second output contains `✓ Reindexed: 0 record(s) rewritten`; every record file's bytes are unchanged; `NamesTail("t")` is ` [TOTP]` |
| `Reindex_AFormatTwoTotpRecord_IsMarked` (`VaultReindexTests`, its format 2 fixture; add `using static TswapTests.Totp.OtpNetContractTests;` for `Sha1Uri` and `using TswapCore.Totp;` for `ValueKinds`) | `_m.Ok(Sha1Uri, "ingest", "t")`; assert the file is format 2 (`SecretRecordCodec.FormatVersionOf`) and `ValueKinds.Entries(ReadRecord(_m, _key, "t").Extensions)` is null; `vault reindex` | the file is format 3 and `ValueKinds.Entries(...)` is `[new Entry(record.Version, 1)]` |
| `Period1_PrintsEverySecond` (`TotpCommandTests`, existing) | unchanged | **add** `Assert.Equal("073950\n", outText);` after the existing `Assert.Matches` (kept) |
| `ToComment_AnExistingTotpMarker_IsConsumed` (new file `TswapTests/Totp/TotpMarkerRegexTests.cs`) | a `SecretsDb` as `RedactEngineTests.Db` builds it, `pw` = `s3cr3t-value1`; `Redact.ToComment("password: \"s3cr3t-value1\"  # tswap: other:totp", db)` | content `password: ""  # tswap: pw`, one change |
| `ToComment_AMultiLineValue_ConsumesATotpMarker` (same file) | `s` = `line-one\nline-two`; `Redact.ToCommentReport("token: line-one\nline-two  # tswap: old-name:totp\n", db)` | `Content` is `token: ""  # tswap: s\n`, `Skipped` empty |
| `BracedTokens_TakeATotpToken` (same file) | `RunCommand.BracedTokens(["x", "{a:totp}", "{a:other}"])` | `["{a:totp}"]` |
| `Apply_ATotpMarker_ResolvesOnce_WithoutThePreviousPreCheck` (same file) | a hand-written `ISecretLookup` fake: `Contains` true, `HasPreviousValue` false, `IsBurnedToken` false, `ThrowIfUnreadable` does nothing, `ResolveToken` records each token and returns `123456`; `Apply.ApplySecretsReporting("c: \"\"  # tswap: t:totp\n", fake, null)` | content `c: "123456"  # tswap: t:totp\n`; the recorded tokens are exactly `["t:totp"]` |

Break it once (each in the commit message):
- `ValueKinds.With` (`ValueKinds.cs:109`): return `result` always. `Reindex_Twice_…` must fail. This mutation works
  only because `vault reindex` decides "current" with `ReferenceEquals(ValueKindsFromValues(state), state.Extensions)`
  (`RecordVaultStore.cs:1445`, a T60 file). If T60 has landed first and changed that check, pick a mutation that
  makes the reindex rewrite an unchanged TOTP record under the new code, and name it in the commit message.
- `PrepareV3` (`RecordVaultStore.cs:2092`): `Extensions = record.Extensions` always. `Reindex_AFormatTwoTotpRecord_…`
  must fail. (A test-time edit of a T60 file; revert it.)
- drop `|:totp` from `ToCommentProcessor.cs:16`, then from `SecretMatcher.cs:327`, then from `RunCommand.cs:518` (at f2e3a5a): the
  matching test of the three must fail each time (the first two leave `:totp` behind the marker).
- `Apply.cs:98`: drop `previous &&`. `Apply_ATotpMarker_…` must fail (two recorded tokens).

If `Period1_PrintsEverySecond` prints another code, stop and report it (an off-by-one in the counter), don't change
the number.

**#435.7 moves after T60.** Not in this brief. In the report, propose a one-line issue for it ("compute
`ValueKinds.Classify` only for a new version, after T60"), so this commit says `Part of #435` and the controller
closes #435 when that issue exists.

Release note: none (docs, comments and tests).

## Task 3 (#436): an authenticator export link is refused without sudo

### The format (parser-first)

Google Authenticator's "Transfer accounts" export is a QR code holding
`otpauth-migration://offline?data=<payload>`. There is no published spec; the format is known from the apps that
import it, which agree:
- Aegis, `GoogleAuthInfo.parseExportUri`
  (github.com/beemdevelopment/Aegis, `app/src/main/java/com/beemdevelopment/aegis/otp/GoogleAuthInfo.java`): the scheme
  must equal `otpauth-migration`, the host `offline`, the query parameter `data` must be present; `data` (after the
  query's percent-decoding: `+`, `/` and `=` travel as `%2B`, `%2F`, `%3D`) is standard base64, decoded and parsed as a
  protobuf `MigrationPayload`.
- dim13/otpauth, `migration/migration.proto`: `Payload { repeated OtpParameters otp_parameters = 1; int32 version = 2;
  int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5; }`, each `OtpParameters` holding `bytes secret = 1`
  (the raw key), `name`, `issuer`, `algorithm`, `digits`, `type` (HOTP or TOTP) and `counter`. One link holds the seeds
  of several accounts, HOTP ones included; a large export is split over several links (`batch_size`,
  `batch_index`).

RFC 3986 3.1: a scheme is ASCII (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) and compared case-insensitively; a
reader takes the scheme from the text before the first `:`. So the marker is **`otpauth-migration:`**, ASCII letters in
either case.

### Design

- **Recognition** (generous, as T58's D1). A value is an otpauth record when it contains `otpauth:` **or
  `otpauth-migration:`** anywhere. Both markers compare ASCII letters case-insensitively and every other character
  exactly: a byte or char `c` matches marker character `m` when `c == m`, or `c` is an ASCII letter and its lower case
  is `m`.
  - `OtpAuthUri.IsOtpAuth(string)`: true when either marker occurs. Keep `otpauth:` with today's
    `OrdinalIgnoreCase` (no letter of `otpauth` has a non-ASCII case partner, so nothing changes for it); look for
    `otpauth-migration:` with the ASCII rule above, so that the string and byte forms agree on `otpauth-mıgration:`
    (U+0131, which `OrdinalIgnoreCase` would fold to `i`).
  - `OtpAuthUri.IsOtpAuth(ReadOnlySpan<byte>)`: one private marker loop for both markers with the ASCII rule. Today's
    loop folds every byte with `| 0x20` except at `:` (`OtpAuthUri.cs:20`), which would let a CR (`0x0D | 0x20` =
    `-`) match the `-` of the new marker; fold only bytes `A`-`Z`.
  - New `internal static bool IsExportLink(string value)`: `otpauth-migration:` occurs (the same ASCII rule).
  - **Recognition never decodes anything:** no percent-decoding, base64 or protobuf. The payload is never read.
- **Refusal** (fail closed). `TotpSeed` gets `internal const string RExport = "the value is an authenticator export
  link (otpauth-migration:), which holds the seeds of several accounts; store each account's otpauth://totp/ URI on
  its own";`. In `FromUri`, the first check after `var text = value.Trim();` is
  `if (OtpAuthUri.IsExportLink(text)) throw new TotpSeedException(RExport);`, before R0. The reason names no part of
  the value. Everything else follows from code that already exists:
  - `TotpCodes.Classify` gives `OtpAuthUnusable`, so `names` shows ` [OTPAUTH: unusable]` (`"otpauth-unusable"` in
    `--json`), from the next write or `vault reindex`;
  - `CommandValues.Resolve` takes the `FromUri` path for `{{t}}`, `{{t:previous}}`, `{{t:totp}}`, `--env`, a
    `{{@file}}` marker, `apply` and `totp`, and refuses with `RefusalText`/`PreviousRefusalText` and `RExport`;
  - `rotate` refuses (`RotateCommand.cs:67`), burned or not; `ingest --rotate t` with a usable URI is the way out;
  - the broker refuses it on routes, templates and the ssh-agent and zeroes the value (`BrokerSecrets.cs:99`, `:143`,
    `SshKeys.cs:102`), with today's text;
  - `sudo tswap get` and `export` still give the value.
- **The whole value.**

  | The value holds | Outcome |
  |---|---|
  | the link alone, any letter case, white space at either end | refused, `RExport` |
  | the link with other text before or after it (a label, notes), a line break, a second link, a usable `otpauth://totp/` URI before or after it | refused, `RExport` (the check comes first, so never R0 and never a code) |
  | any host or parameters (`online`, no `data`, `&batch_index=1`, percent-encoded `data`, an empty or non-base64 `data`) | refused, `RExport` (no part after the marker is read) |
  | `otpauth-migration:` inside an `otpauth://totp/` URI (an unencoded issuer) | refused, `RExport`: an over-refusal, accepted (percent-encode it) |
  | the marker spelled otherwise: `otpauth-migration` without `:`, `otpauth-migration%3A`, `otpauth_migration:`, a CR for the `-`, a non-ASCII letter (`otpauth-mıgration:`) | not recognised: no importer reads it as an export link |
  | the payload without the scheme (bare base64), or a QR image | not recognised (out of scope: any base64 can be anything) |
- Summaries: `OtpAuthUri`'s class and `IsOtpAuth` summaries and `ValueKind.OtpAuthUnusable` (`ValueKind.cs:15`) say
  "contains `otpauth:` or `otpauth-migration:` (brief T65, #436)".

### Tests

Values: `internal const string Link = "otpauth-migration://offline?data=bm90IGEgcmVhbCBwYXlsb2Fk"` (base64 of `not a
real payload`; no real seed is needed, since nothing decodes it) and `internal const string Data =
"bm90IGEgcmVhbCBwYXlsb2Fk"`, both in `ExportLinkTests` (below); `TotpParseTests` and `BrokerTotpTests` use them as
`ExportLinkTests.Link`.

`ExportLink_IsRefused_WithItsOwnReason(string value)` (`TotpParseTests`, new theory over a
`public static TheoryData<string> ExportLinks()`, as the file's other theories take `MemberData`, since row 2 is no
constant): `TotpSeed.FromUri(value)`
throws `TotpSeedException` with `Reason == RExport`, and `TotpCodes.Classify(value)` is `OtpAuthUnusable`:

| # | Value |
|---|---|
| 1 | `Link` |
| 2 | `Link.ToUpperInvariant()` |
| 3 | `"  " + Link + "\n"` |
| 4 | `"export: " + Link` |
| 5 | `Link + "\n" + Link` |
| 6 | `Sha1 + "\n" + Link` |
| 7 | `Link + "\n" + Sha1` |
| 8 | `Link + "&batch_index=1"` |
| 9 | `"otpauth-migration://offline?data=%2B%2F%3D"` |
| 10 | `"otpauth-migration://online"` |
| 11 | `"otpauth-migration:"` |
| 12 | `"otpauth://totp/X?secret=" + Sha1Seed + "&issuer=otpauth-migration:x"` |

New rows in `TotpParseTests.Classify`: `Link` → `OtpAuthUnusable`; `otpauth-migration//offline` (no colon),
`otpauth-migration%3A//offline?data=x`, `otpauth_migration:x`, `"otpauth\rmigration:x"`, `"otpauth-m\u0131gration:x"`
→ `None`. New rows in `BrokerTotpTests.IsOtpAuth_OnBytes_AgreesWithTheStringForm`: `Link`, `"xx OTPAUTH-MIGRATION:"`
→ true; `"otpauth-migration"`, `"otpauth\rmigration:x"`, `"otpauth-m\u0131gration:x"` → false. (The existing
`otpauth-backup-codes` → false rows stay as they are.)

New file `TswapTests/Totp/ExportLinkTests.cs`, class `ExportLinkTests`, with `RunTotpTests`' fixture copied
(`FleetMachine`, `RecordingPty`, `Store`, `Run`, `Refusal(shown, reason)`):
- `ExportLink_InEveryForm_IsRefused`: `Store("t", Link)`, `f.yaml` = `code: ""  # tswap: t\n`. For `["tool", "{{t}}"]`
  (`'{{t}}'`), `["tool", "{{t:totp}}"]` (`'{{t:totp}}'`), `["--env", "OTP={{t}}", "--", "tool"]` (`'{{t}}'`) and
  `["tool", "-f", "{{@f.yaml}}"]` (`'# tswap: t' (line 1)`): exit 1, `_pty.Starts` 0, `err` contains
  `Refusal(shown, RExport)`, and neither `Data` nor `offline?data` is in stdout or stderr. `tswap totp t` (no sudo):
  exit 1, empty stdout, the same refusal with `'t'`.
- `ExportLink_IsMarkedUnusable_AndRotateRefuses`: `Store("t", Link)`; the `names` line for `t` ends
  ` [OTPAUTH: unusable]` (as `ValueKindsTests.NamesTail` reads it); `rotate t` (sudo) exits 1 with
  `'t' holds a TOTP seed, which comes from the issuer`; after `burn t seen`, `rotate t` without sudo exits 1 the same
  way; `Sha1Uri | ingest --rotate t` exits 0, then `{{t}}` gives `050471` and `{{t:previous}}` is refused with
  `CommandValues.PreviousRefusalText("'{{t:previous}}'", "t", RExport)`.
- `BrokerTotpTests.Broker_RefusesAnExportLink` (a new `[UnixFact("the broker is Unix-only …")]` in that file): calls
  `Route_Template_AndSshKey_RefuseAnOtpauthRecord_AndStillServeAPlainOne(Link)`.

Break it once:
1. drop the `otpauth-migration:` marker from `IsOtpAuth(string)`: `Classify`'s `Link` row, `ExportLink_IsRefused_…`
   rows 1-5 and 8-11 (via `Classify`), both command tests and the string half of the `IsOtpAuth` rows must fail;
2. drop it from the byte overload only: the `IsOtpAuth` byte rows and `Broker_RefusesAnExportLink` must fail;
3. delete the `RExport` check in `FromUri`: every `ExportLink_IsRefused_…` row must fail (rows 1-11 get another reason,
   row 12 parses);
4. put back `| 0x20` for every byte but `:`: the `"otpauth\rmigration:x"` byte row must fail.

**Docs** (each a sentence or a few words; the files are T60/T61's, see the ownership table):
- `docs/commands.md:629`, after the first sentence: "So is a value that contains `otpauth-migration:` (an
  authenticator's export link, such as Google Authenticator's "Transfer accounts" QR code, which holds the seeds of
  several accounts): it is refused wherever tswap gives a value or a code (`run`, `apply`, `totp`, the broker),
  with or without sudo; only `sudo tswap get` and `sudo tswap export` show it, and its payload is never read. Store
  each account's `otpauth://totp/` URI on its own. An `otpauth://totp/` URI whose label or issuer holds
  `otpauth-migration:` is refused too (percent-encode it)."
- `docs/security-model.md:385`: "a value holding `otpauth:` or `otpauth-migration:` (an export link, refused
  wherever a value or a code is given; only `sudo tswap get` and `export` show it) is an otpauth record".
- `docs/BROKER.md:947`: "(a value holding `otpauth:` or `otpauth-migration:`, #374, #436)".

Release note: "A value holding an authenticator export link (`otpauth-migration:`, Google Authenticator's transfer
QR code) is now refused wherever tswap gives a value or a code (`run`, `apply`, `totp`, the broker); only `sudo tswap
get` and `export` show it. `run`, `totp` and `rotate` refuse it at once; `names` marks it ` [OTPAUTH: unusable]` from
the record's next write or `sudo tswap vault reindex`. An older tswap on another machine still hands it out, so update
every machine. Store each account's otpauth URI on its own. An `otpauth://totp/` URI whose label or issuer holds
`otpauth-migration:` is now refused too (percent-encode it)." Not in scope: a sudo-only import that splits a link into one record per
account (the issue's "optionally, later"; it would need a protobuf reader).

## Task 4 (#434): `redact` and `run` take a lone CR as a line break; the T63 review Minors

### The rule

As T63 decided for the broker and the field check: `\r\n`, `\n` and a lone `\r` (a `\r` not followed by `\n`) are
all line breaks, in any mix, and a stored value whose breaks are all one kind is found whatever mix the output has.
A value whose own breaks are mixed is found in its own spelling, or where the output's breaks happen to match it, as
before. A break doubled by a converting layer (`\r\r\n`) is two breaks (still out of scope), except that `run` keeps
today's folded view, which matches a CRLF value printed through a PTY as `\r\r\n`.

### Design

**`LineEndingViews`** gets:
- `public static bool HasLoneCr(ReadOnlySpan<char> text)`: some `\r` is the last character or is followed by a
  character other than `\n`.
- `public static int WriteBreaks(ReadOnlySpan<char> text, string lineBreak, Span<char> view, Span<int> rawStart,
  Span<int> rawEnd)`, `lineBreak` one of `"\n"`, `"\r\n"`, `"\r"` (else `ArgumentException`); `view` and the maps are
  at least `2 * text.Length` long; returns the view's length. The view text is exactly
  `WithLineBreaks(text, lineBreak)`. The maps, for a break at raw index `i`:

  | Raw break | to `\n` or `\r` | to `\r\n` |
  |---|---|---|
  | `\r\n` at `i` | one char, `[i, i + 2)` | `\r` `[i, i + 1)`, `\n` `[i + 1, i + 2)` |
  | lone `\r` at `i` | one char, `[i, i + 1)` | `\r` `[i, i + 1)`, inserted `\n` `[i + 1, i + 1)` |
  | `\n` at `i` | one char, `[i, i + 1)` | inserted `\r` `[i, i)`, `\n` `[i, i + 1)` |

  Every other character maps to itself. A hit over view indices `[s, s + L)` has the raw span
  `[rawStart[s], rawEnd[s + L − 1])`, as for the existing views. The class summary's last sentence becomes: "Brief T65
  (#434): `WriteBreaks` builds the views with every break written as `\n`, `\r\n` or `\r`, for the fingerprint
  matchers; `tocomment` keeps the two views above." `WithLineBreaks`' summary (`:81-85`) drops "not for the views
  above" and says: "`WriteBreaks` builds the same text with span maps, for the fingerprint matchers; this form is for
  checks that compare whole spellings (the field check)."

**The three new views** (a view's hits are added only under its condition, which is when it can differ from the
views already scanned):

| View | Scanned when the text |
|---|---|
| every break as `\n` | `HasLoneCr` (without one it is the folded view) |
| every break as `\r\n` | `HasLoneCr` (without one it is the unfolded view) |
| every break as `\r` | holds a `\n` (without one it is the raw text) |

**`redact`** (`SecretMatcher`):
- `ViewHits(string text, bool anyLineBreak)`: today's three scans, then, when `anyLineBreak`, the three new views
  through `AddViewHits` (capacity `2 * text.Length`, builder `WriteBreaks` with the break bound). `Select` (redact,
  `:499`) passes `true`; `SelectMultiLine` (tocomment, `:338`) passes `false`, so `tocomment` is unchanged (out of
  scope, below).
- `AddViewHits`' filter (`:84`) becomes: skip a hit when its raw span is empty or when the raw text over its span
  equals the view text of the hit (ordinal); that one is the raw view's hit again.
- **The view order is load-bearing**: raw, folded, unfolded, then `\n`, `\r\n`, `\r`. `Entries` keeps the first span
  per raw start (`SecretMatcher.cs:465-471`), so an earlier view's span wins. Put that in a comment above the view
  list in `ViewHits`, naming the case: for `abc def-gh\r` in `x: abc def-gh\n` the unfolded view gives `[3, 13)` and
  the `\r` view `[3, 14)`; the unfolded span wins and the line feed stays (`LineEndingRedactTests` row 8,
  `x: [REDACTED: s]\n`, unchanged). For the folded and unfolded views
  this keeps exactly today's hits: their hit text differs from the raw text exactly when it holds a folded `\n` or an
  inserted `\r`, which is exactly when the lengths differ. The new views need the text test, because a lone `\r`
  written as `\n` (or a `\n` as `\r`) keeps the length.
- `Redact`'s summary: "on the raw content and on its line-ending views (T50a), and with every line break written as
  `\n`, `\r\n` or `\r` (brief T65, #434)".

**`run`** (`FingerprintScanner`):
- In `Scan`, inside `if (_freeShapes.Length > 0)` after `ScanUnfolded`, the three new views under their conditions,
  each through a `ScanBreaks(text, lineBreak, b, found)` built as `ScanUnfolded` is (pooled arrays of `2n`,
  `WriteBreaks`, prefix hashes and whitespace counts over the view, `ScanFree(…, carried: 0, rawStart, rawEnd, …)`,
  the view array returned with `clearArray: true`).
- **One hit per raw start and candidate, the earliest view's** (as `Entries` does for `redact`). Each found hit
  carries its view's index internally: 0 raw, 1 folded, 2 unfolded, 3 `\n`, 4 `\r\n`, 5 `\r` (the order `Scan`
  scans them, the same as `ViewHits`); `ScanState.Hits` keeps the hits before this deduplication (as it keeps
  them before the whole-token filter today), each with its index and its entry length, so a carried hit keeps both. Before today's sort (`:310-320`; the whitespace-run hits of `TryFoldedWhitespaceRun` count as folded, 1), of hits with equal `Start`, `Name`, `IsPrevious`, `Kind` and entry length (the view window's length `L`, which
  `redact`'s `Entries` also keys on through the entry's text), keep only the
  one with the lowest view index (the first found on a tie); then sort and drop equal spans as today. Two such hits
  are the same entry found over the same value text, so either covers every character of the value; they differ only
  in which break characters the span takes. Without this, `Scan_LineEndings_ExactlyOneHit`'s row
  `{ "abc def-gh\r", "x: abc def-gh\n", 3, 10 }` (`FingerprintScannerTests.cs:221`) gets a second hit `(3, 11)` from
  the `\r` view and its `Assert.Single` fails; with it, the unfolded `(3, 10)` is the one hit, the assertion stays as
  it is, and `run` keeps the line feed exactly as `redact` does (`x: [REDACTED: s]\n`). A comment above the
  deduplication says the view order is load-bearing, naming that row.
- **A trailing `\r` is decided by the next window.** In the carry (`:246-268`), let `held` be
  `state.Text.Length − 1` when `state.Text` ends with `\r`, else `state.Text.Length`. Then `carried` is
  `held − state.Pending` (0 when that is negative; the continuation check compares those `carried` characters), and
  a hit is carried only when `hit.Start >= state.Pending && hit.Start + hit.Length <= held`. A raw window ending at
  that `\r` is then tried again, and a view hit ending there comes only from the new window's own views. Without this,
  a window ending in the `\r` of a `\r\n` carries a hit in which that `\r` stood for a whole break, which a fresh scan
  of the next window, seeing the `\r\n`, reports with the longer span. When the hit holds no other lone `\r`, the
  folded view (index 1) finds the longer span too and the deduplication drops the stale one, so nothing shows. When it
  does hold one (`line-one-secret\rline-two-secret\r` cut before the final `\n`), only the `\n` view (index 3) finds
  either span: the carried `(2, 32)` and the fresh `(2, 33)` tie on the view index, the carried one is found first, and
  it is kept. Then the carried state no longer gives a fresh scan's hits, and `run` lets the `\n` through. `ScanState`'s summary (`:195-202`) says the next window "continues
  it up to `held` (the last window without a trailing `\r`)" instead of "starts with the held end of the last one".
- **The window rule stays exact.** `MaxRawLength`, the caps, `PendingFromCore` and `FingerprintStreamMatcher`'s
  `MaxMatchLength` don't change, because every new hit obeys the bounds they already assume. Take a free entry of
  length `L` with `W` whitespace characters (CR, LF, space, tab), so `ScanFree`'s count filter admits only view windows
  holding exactly `W` of them.
  - In the `\n` and `\r` views, each view character stands for one raw character, except a `\r\n` written as one
    character, which is whitespace in the view. So a hit's raw length is at most `L + W` (`RawLength`, `:109`;
    `2L` for an unknown kind).
  - In the `\r\n` view, each view character stands for at most one raw character (inserted ones for none), so the raw
    length is at most `L`.
  - `PendingFromCore` counts raw whitespace with a `\r\n` as one (`:384`). Every raw break in a hit's span gives at
    least one whitespace character of the view window, and spaces and tabs one each. So the counted whitespace of
    any part of a hit's raw span is at most `W`, a trailing `\r` counted alone included, and the pending point holds
    every occurrence that can still end past the window.
- The class summary, after the T50a sentence: "Brief T65 (#434): free entries are also tried on the views with every
  line break written as `\n`, `\r\n` or `\r` (`LineEndingViews.WriteBreaks`); each such hit's raw span is at most
  `L + W` long and holds at most `W` counted whitespace, so the caps and `PendingFrom` need nothing more. A window's
  trailing `\r` is never carried: the next window decides it."

**`run`'s own values** (`Redaction.Variants`, plaintext): the multi-line branch (`:38-42`) applies to a spelling
holding a `\r` or a `\n`, and builds `[spelling, WithLineBreaks(spelling, "\r\n"), WithLineBreaks(spelling, "\n"),
spelling.Replace("\n", "\r\n"), WithLineBreaks(spelling, "\r")]`. For a spelling without a lone `\r` the first four
are today's four, in today's order (`WithLineBreaks(s, "\n")` is then `s.Replace("\r\n", "\n")`), so only the `\r`
form and its encodings are new. RedactingPty's hold is the longest `Find.Length − 1` (`StreamRedactor.cs:40`, RedactingPty
1.3.0), and `FingerprintStreamMatcher`'s short-form holds come from the list
(`FingerprintStreamMatcher.cs:49-56`): both follow the new forms with no change. The summary adds "and, brief T65, its
form with every line break as a lone `\r`; a spelling with only lone `\r` breaks gets the same list".

**The T63 review Minors** (comments and one test):
- `RedactEngineTests`' summary, after the T22 sentence: "Brief T63 adds a third: `tocomment` comments out a
  continuation line holding a value, where the oracle removes it. The fixed seed produces no such line; if a seed or
  corpus change does, apply the owner-sanctioned T63 rule written in brief T63 (Task 1, "Oracle") to
  `PlaintextRedactOracle`: a continuation candidate that holds a value is commented out (or kept in block content),
  never removed." `PlaintextRedactOracle.cs` doesn't change.
- `FingerprintScannerTests.Scan_RawHits_EqualFingerprintIndexScan`'s summary: "Its only other hits are folded,
  unfolded (brief T50a) or, brief T65, from the views with every break written as `\n`, `\r\n` or `\r`". Its
  assertions stay; if it fails on a hit from a new view, stop and report.
- `FieldSecretCheck.cs`: re-wrap the class summary (`:7-17`) at 120 columns; no word changes.
- `ToCommentContinuationCommandTests` (add `using System.Text.RegularExpressions;`): **add**
  `Assert.Single(Regex.Matches(dryErr, "Warning: line 2: "));` and the
  same for `stderr`, after the existing assertions (they stay).

### Tests

`V2(eol) = "line-one-secret" + eol + "line-two-secret"`, `V3(e1, e2) = "first-line-value" + e1 + "second-line-value"
+ e2 + "third-line-value"`. Printed text sits between `x ` and ` y` unless the row says otherwise.

`Redact_MasksAValue_PrintedWithALoneCr(int row)` (new file `TswapTests/LoneCrRedactionTests.cs`, class
`LoneCrRedactionTests`, a `SecretsDb` as `RedactEngineTests.Db` builds it, stored as `s`, through
`Redact.RedactContent`) and `Scanner_FindsAValue_PrintedWithALoneCr(int row)` (in `FingerprintScannerTests`, beside the
carried-state tests: a scanner built from `s`'s set with its helpers; one `Scan`, then `Assert.Single` on its hits,
or `Assert.Empty` for row 7):

| # | Stored | Printed | `redact` gives | Scanner hit |
|---|---|---|---|---|
| 1 | `V2("\n")` | `V2("\r")` | `x [REDACTED: s] y` | `("s", Plain, 2, 31)` |
| 2 | `V2("\r\n")` | `V2("\r")` | `x [REDACTED: s] y` | `(2, 31)` |
| 3 | `V2("\r")` | `V2("\n")` | `x [REDACTED: s] y` | `(2, 31)` |
| 4 | `V2("\r")` | `V2("\r\n")` | `x [REDACTED: s] y` | `(2, 32)` |
| 5 | `V3("\n", "\n")` | `V3("\r", "\r\n")` | `x [REDACTED: s] y` | `(2, 52)` |
| 6 | `V3("\r", "\r")` | `V3("\n", "\r")` | `x [REDACTED: s] y` | `(2, 51)` |
| 7 | `V2("\n")` | `V2("\r\r")` (two breaks) | unchanged (`x ` + printed + ` y`) | none |
| 8 | `V2("\n") + "\n"` | `"x " + V2("\r") + "\r"` (the text ends in the `\r`) | `x [REDACTED: s]` | `(2, 32)` |

(A scanner hit is `FingerprintHit("s", false, VariantKind.Plain, Start, Length)`; the length is the printed text's:
`V2` is 30 characters plus its break, `V3` 49 plus its two.)

Facts:
- `WriteBreaks_MapsEachBreak` (new file `TswapTests/LineEndingViewsTests.cs`): `("a\r\nb", "\n")` → view `a\nb`,
  starts `[0, 1, 3]`, ends `[1, 3, 4]`; `("a\rb", "\r\n")` → `a\r\nb`, `[0, 1, 2, 2]`, `[1, 2, 2, 3]`;
  `("a\nb", "\r")` → `a\rb`, `[0, 1, 2]`, `[1, 2, 3]`; `("a\nb", "\r\n")` → `a\r\nb`, `[0, 1, 1, 2]`, `[1, 1, 2, 3]`;
  `("\r", "\n")` → `\n`, `[0]`, `[1]`.
- `WriteBreaks_ViewIsWithLineBreaks`: for every string of length 0 to 6 over `a`, `\r`, `\n` and each of the three
  breaks, the view equals `WithLineBreaks`, and every map entry has `rawStart ≤ rawEnd`, non-decreasing in the view
  index.
- `HasLoneCr`: `"a\rb"`, `"a\r"`, `"\r\r\n"` → true; `"a\r\nb"`, `"a\nb"`, `""` → false.
- `Scan_CarriedState_WindowEndingInACr_SameHitsAsFreshScan` (`FingerprintScannerTests`): stored
  `"line-one-secret\nline-two-secret\n"`; text `"x line-one-secret\rline-two-secret\r\n y"` (the first break a lone `\r`, so only the `\n` view
  finds the value). For every cut `c` from 1 to `text.Length − 1`: a fresh state; scan `text[..c]` with it, take
  `PendingFrom(text[..c], state)`, then scan `text[..c][pending..] + text[c..]` with the state; the hits equal a fresh
  `Scan` of that window. The cut that pins the rule is `c = 34` (the window ends in the `\r` at index 33): the window's
  hit is `(2, 32)`, the next window's fresh hit `(2, 33)`.
- `Scan_CarriedState_MixedBreaks_SameHitsAsFreshScan`: `Scan_CarriedState_SameHitsAsFreshScan`'s loop (seed 5150,
  120 rounds, its `RandomVault`/`PlantedText`), with each line break of the planted text (`\r\n`, a lone `\r`, `\n`)
  rewritten as one of the three at random (`rng.Next(3)`) before chunking.
- `Variants_HoldTheLoneCrForm` (`LoneCrRedactionTests`): `Redaction.Variants(V2("\n"))` contains `V2("\r")` and its
  base64; `Redaction.Variants(V2("\r"))` contains `V2("\n")`, `V2("\r\n")` and their base64; both lists are distinct.
- `Variants_OfAValueWithoutALoneCr_KeepTodaysForms`: the distinct forms, in today's order, then the `\r` form. With
  `Enc(f) = [f, b64, b64.TrimEnd('='), b64url, b64url.TrimEnd('=')]` (`b64` the base64 of `f`'s UTF-8, `b64url` it
  with `+/` as `-_`, as `Redaction.cs:50-52` builds them), the expected list is the concatenation below with
  duplicates dropped (ordinal, first kept), as `Redaction.cs:54` does:
  - `V2("\n")`: `Enc(V2("\n"))`, `Enc(V2("\r\n"))`, `Enc(V2("\r"))` (its LF form is itself, and its PTY form is its
    CRLF form);
  - `V2("\r\n")`: `Enc(V2("\r\n"))`, `Enc(V2("\n"))`, `Enc("line-one-secret\r\r\nline-two-secret")` (the PTY form),
    `Enc(V2("\r"))` (its CRLF form is itself).
  The `\r` form carries its encodings too, as every form does. Duplicates come from the encodings: the 33-character
  PTY form's base64 has no padding, so its trimmed copy is dropped, and a base64 without `+` or `/` equals its
  base64url.

**Command tests** (new file `TswapTests/RunLoneCrRedactionTests.cs`, with `RunVaultRedactionTests`' fixture copied):
- `Run_AnotherVaultValue_PrintedWithLoneCrs_Masked`: `token` = `token-value-1`, `other` = `V2("\n")` (ingested);
  child prints `"log: " + V2("\r") + "\n"`; `run curl {{token}}` exits 0 and `Output` is `log: [REDACTED: other]\n`.
- `Run_ItsOwnValue_PrintedWithLoneCrs_Masked`: the same with `run curl {{other}}`.
- `Run_ChunkedThroughTheMatcher_SameOutputForEveryChunkSize` (`FingerprintScannerTests`, beside
  `Matcher_CarriedState_SameOutputForEveryChunkSize`, its record building copied): `s` = `V2("\n") + "\n"`, text
  `"a " + V2("\r") + "\r\n b " + V2("\r\n") + "\r c\n"`; for chunk sizes 1 to 64, the carrying matcher's output equals
  `a [REDACTED: s] b [REDACTED: s] c\n` (each occurrence's raw span takes its final break: the `\r\n` after the first,
  the lone `\r` after the second).
- `Matcher_AValueEndingInACr_PrintedWithLf_KeepsTheLineFeed` (`FingerprintStreamMatcherTests`, its `Record`, `Vault`
  and `Pieces` helpers): `s` = `abc def-gh\r`; text `x: abc def-gh\n`; for every cut from 0 to the text's length,
  `string.Concat(Pieces(matcher, [text[..cut], text[cut..]]))` is `x: [REDACTED: s]\n`. This pins `run`'s output for
  the `Scan_LineEndings_ExactlyOneHit` row.
- `PendingFrom_IsSound_MixedBreaks` (`FingerprintScannerTests`, beside `PendingFrom_IsSound`): its loop (seed 2026,
  150 rounds, `RandomVault`) over a `PlantedText` copy that rewrites each line break of every planted form and filler
  piece (`\r\n`, a lone `\r`, `\n`) as one of the three at random before appending it, so the planted spans stay
  right; for every planted `[start, end)` and every cut inside it, `scanner.PendingFrom(text.AsSpan(0, cut)) <= start`.
  Each round's vault also holds `long` = two lines of 127 characters of `Word` (as `RandomVault` draws them) joined by
  `\n` (`L` = 255, `W` = 1, so `L + W` = 256 and `_capFree` is 256: the cap is reached), planted once as its CRLF
  form (256 characters, every break `\r\n`, not rewritten) besides its rewritten forms.

Break it once:
1. drop the three new views from `ViewHits`: `Redact_…` rows 1-6 and 8 must fail;
2. put back the length-only filter in `AddViewHits`: `Redact_…` rows 1, 3, 6 and 8 must fail (their view keeps the
   length);
3. drop the three new views from `FingerprintScanner.Scan`: `Scanner_…` rows 1-6 and 8,
   `Run_AnotherVaultValue_…` and the chunked test must fail;
4. drop the trailing-`\r` rule from the carry: `Scan_CarriedState_WindowEndingInACr_…` must fail at `c = 34`, and
   `Run_ChunkedThroughTheMatcher_SameOutputForEveryChunkSize` at chunk sizes 1, 2, 17 and 34 (a chunk boundary between
   the first occurrence's final `\r` and `\n`, index 34); if `Scan_CarriedState_MixedBreaks_…` fails too, say so;
5. drop the `\r` form from `Redaction.Variants`: `Variants_HoldTheLoneCrForm` must fail
   (`Run_ItsOwnValue_…` still passes, since the vault's fingerprints mask it too; say so);
6. write the warnings twice in `ToCommentCommand` (call `WriteWarnings` a second time at `:94`): the
   `ToCommentContinuationCommandTests` additions must fail;
7. drop the scanner's per-start deduplication: `Scan_LineEndings_ExactlyOneHit`'s `abc def-gh\r` row and
   `Matcher_AValueEndingInACr_PrintedWithLf_KeepsTheLineFeed` must fail;
8. two mutations of `PendingFromCore`'s free clause, each on its own:
   - (a) a trailing `\r` is not held: `if (n > 0 && text[n - 1] == '\r') start = n;` before `pending = Math.Min(pending,
     start)`. `PendingFrom_IsSound_MixedBreaks` must fail at a cut just after a `\r` inside a planted multi-line form
     (the other classes' trailing runs end at that `\r`, so nothing else holds it); `PendingFrom_IsSound` fails too;
   - (b) one character less: `n - (_capFree - 1)` to `n - (_capFree - 2)`. `PendingFrom_IsSound_MixedBreaks` must fail
     on `long`'s CRLF form at the cut `start + 255`: the free clause then gives `start + 1`, and the whitespace-free and
     base64 clauses give at least the start of the trailing line (`start + 129`).

After the task, run
`TSWAP_PERF=1 dotnet test TswapTests -c Release --filter Category=Perf --logger "console;verbosity=detailed"` (the
test's own Release command) once on this commit and once on the commit before Task 4's (the tasks may land in any
order), and put both throughput lines in the report (measured, not asserted). The `\r` view adds one scan of every window that holds a `\n` whenever the vault has a
free entry (a value with any whitespace, a space is enough), and the `\n` and `\r\n` views one each when a window
holds a lone `\r`. `redact` gains up to three index scans per file; it has no perf test, so none is measured.

**Docs** (small; `commands.md` and `security-model.md` are T60/T61's):
- `docs/commands.md:84-85`: "`redact` masks a value with line breaks whatever the line breaks of the value and of the
  file (`\r\n`, `\n` or, since 0.3.3, a lone `\r`, in any mix); a value whose own breaks are mixed is
  found in its own spelling only."
- `AGENTS.md:256` ("and a multi-line value's `\r\n`, `\n` and PTY-printed forms") and `docs/security-model.md:412-413`
  ("its `\r\n` and `\n` forms and the form a terminal prints"): add the lone-`\r` form ("`\r\n`, `\n`, lone-`\r` and
  PTY-printed forms"; "its `\r\n`, `\n` and lone-`\r` forms and the form a terminal prints").
- `docs/security-model.md:298`: "the `\r\n`, `\n`, lone-`\r` and PTY-printed forms of a multi-line value";
  `:302`: "through a pipe (line breaks as stored, or all written as `\n`, `\r\n` or a lone `\r`; a value whose own
  breaks are all one kind is found whatever the output's mix)".

Release note: "`redact` and `run` now also mask a multi-line value printed with lone CR line breaks (old Mac tools,
`\r`-redrawn output), or stored with them and printed with LF or CRLF."

## Task 5 (#448): `wslg` is checked as `wsl` is, by wslg.exe's own parser; an option value WSL would split is refused

### The parser (parser-first)

Read at microsoft/WSL **f753835d5464** (master, 2026-11-26), `src/windows/common/WslClient.cpp` (`WslgMain`, the
dispatcher), `src/windows/inc/wsl.h` (the option names) and `src/windows/common/helpers.cpp` (`ParseArgument`). The
implementer checks these citations before writing code; if the file has moved, stop and report.

- **Dispatch** (`WslClient.cpp:1885-1922`; `CommandLineToArgvW` at `:1887`, the stem at `:1890-1891`): `CommandLineToArgvW` of the command line, then
  `std::filesystem::path(argv[0]).stem()`, lower-cased: `bash` → `BashMain`, `wslconfig` → management only, `wslg` →
  `WslgMain`, anything else → `WslMain`. So `wslg`, `WSLG.EXE` and `C:\Program Files\WSL\wslg.exe` all run `WslgMain`.
  The name is argv[0] as the caller writes it, not the file's: a copy or link under another name is the residual T51
  and T64 already declare. (`wslg.exe.` has the stem `wslg.exe` and runs `WslMain`: a shell launcher either way, and
  refused below as padded.)
- **`WslgMain`** (`:1376-1475`): `ParseLegacyArguments` first (`:1029-1064`: a GUID, then `~`, each consumed when it
  is the next word). Then the loop (`:1387-1441`), words split by `ParseArgument` and compared exactly and
  case-sensitively:
  - `-d`, `--distribution` (`:1395-1405`), `-u`, `--user` (`:1414-1421`), `--cd` (`:1422-1427`): take the next word as
    their value;
  - `--shell-type` (`:1406-1413`) with `login` or `standard` (shell mode) or `none` (**exec mode**), the last one
    winning; any other value, or none, is an error (`ParseShellOptionArg`, `:88-107`);
  - `--` (`:1428-1432`) ends the options;
  - **any other word starting with `-` is an error** (`WSL_E_INVALID_USAGE`, `:1435`): wslg has **no `-e`/`--exec`**
    and none of wsl's `--system`, `--distribution-id`, `--parent-console`, management options, `--debug-shell` or
    `--install`; such a word runs nothing;
  - any other word begins the command.
- **Modes** (`:1443-1474`): an empty command is an error (`:1444`, present since the first public commit, 697572d664c9;
  what older closed-source builds did can't be read). Exec mode (only `--shell-type none`) runs
  `CommandLineToArgvW(rest)` directly (`:1450-1459`); otherwise the whole rest goes to the user's shell, by default a
  login shell (`DefaultUseShell = true`, `DefaultLogin = IsUseShell()`, `:1466-1467`), which parses a substituted
  value again.
- **How the words are split** (`helpers.cpp:664-684`): `ParseArgument` cuts the remaining command line at its first
  space or tab and keeps quote characters, except for `--cd`'s value (`HandleQuotes = true`), which, when it starts
  with `"`, runs to the next `"`. `run` builds the command line with RedactingPty 1.3.0's `WindowsCommandLine.Build`
  (`WindowsCommandLine.cs`, `QuoteArgument`: a word that is empty or holds any `char.IsWhiteSpace` or `"` is quoted,
  `"` escaped as `\"`). So a value with a space or tab (`-d "My Distro"`) is read as `"My`, and `Distro"` begins the
  command **in shell mode**, while the guard's walk, which sees one word, carries on in exec mode; a `--cd` value
  with a `"` ends at the escaped quote the same way. `WslMain` (`:1533-1843`, what T51's `CheckWsl` models) splits its
  values with the same `ParseArgument`, so **this is a fail-open of `wsl` too**, T51's: `tswap run wsl -d "a b" -e
  ./deploy.sh {{secret}}` passes every guard today and the value reaches `$SHELL -c`. Task 5 closes both (fail
  closed; found while reading the parser for #448; the commit message says so).

**The whole word list.** A second `--shell-type` is honoured (last wins; rows 9 and A4); a repeated `-d` is an error in
wslg (nothing runs; allowed, no row); a legacy `~` or GUID is taken for the command, as T51 takes it for `wsl` (an
over-refusal, rows 11-12); a lone `-` is an unknown option (row 26); an empty word before the command is quoted as `""`
by RedactingPty and read as the two characters `""` (a value: consumed whole; an option position: the command begins
in both readings); text after the command is never an option.

### Design

All in `TswapCore/Validation.cs`; cited lines at f2e3a5a. The refusal's `Program` stays the word's `ProgramName`
(as typed, `.exe` dropped) on the `GetBlockedInvocation` path, as for `wsl` today, and the set's spelling (`"wsl"` or
`"wslg"`) on the `BashLauncherRefusal` path.

1. **`Wrappers`** (`:541-550`): add `"wslg"` after `"wsl"`, with the comment `// Brief T65 (#448): WSL's second entry
   point, checked by CheckWsl as wsl is.` This makes it a checked program everywhere `Wrappers` is read:
   `GetBlockedInvocation` (`:720`) reaches `CheckWrapper`; `IsCheckedProgram` (`:1694-1699`), so a wrapper's,
   `find -exec`'s or a runner's command `wslg` is checked; `ProgramPositions` (`:269-298`) walks into its command
   (for `GetFileTokenRefusal`); `NameBashWord`'s wrapper lookup.
2. **`WrapperValued`** (`:1057-1080`): `["wslg"] = ["-d", "--distribution", "-u", "--user", "--cd", "--shell-type"]`,
   with the comment `// Brief T65 (#448): wslg.exe's options that take the next word (WslgValued, and --shell-type).`
3. **`CheckWrapper`** (`:1113-1115`): `if (program.Equals("wsl", StringComparison.OrdinalIgnoreCase) ||
   program.Equals("wslg", StringComparison.OrdinalIgnoreCase)) return CheckWsl(program, args);`, the comment naming
   brief T65 (#448).
4. **The wslg grammar.** Below `WslValued` (`:1196-1199`), with a comment citing f753835d5464 `WslgMain` and the
   lines above: `private static readonly HashSet<string> WslgValued = new(StringComparer.Ordinal) { "-d",
   "--distribution", "-u", "--user", "--cd" };`. `WalkWsl(string program, List<string> args)` keeps its signature and
   sets `var wslg = program.Equals("wslg", StringComparison.OrdinalIgnoreCase);`. For wslg: the valued set is
   `WslgValued`; `--shell-type` and `--` as today, except that an invalid `--shell-type` value (rows 21-22) takes the `-` rule's verdict
   too; `--system`, `-e`/`--exec`, `WslManagement`, `--debug-shell` and
   `--install` are **not** recognised, so they fall to the `-` rule, whose verdict is `new(program, WslgUnknownReason)`.
   For wsl every branch stays as it is.
5. **The value rule, both grammars** (fail closed). After a valued option (the `WslValued`/`WslgValued` branch,
   `:1258-1262`), when `i + 1 < args.Count` and the value `args[i + 1]` is empty, or holds a `"` or any character for
   which `char.IsWhiteSpace` is true (the words RedactingPty quotes), the walk ends: `new(true, new(program,
   WslQuotedValueReason(wslg ? "wslg" : "wsl")), false, 0)`. `--cd` included, although wsl.exe reads a quoted `--cd`
   value without a `"` whole: one rule, an over-refusal, declared. `--shell-type`'s value is already matched exactly.
6. **`CheckWsl`** (`:1229-1241`): the shell-mode verdict is `new(program, wslg ? WslgShellModeReason :
   WslShellModeReason)` (`wslg` computed as in `WalkWsl`). The no-command line (`:1235`) stays: shell mode with no
   command gives `NoCommandShell(program)` (reused; over-refusal for today's wslg.exe, which refuses an empty command
   itself, kept because an older build can't be read), exec mode with none gives null (`wslg --shell-type none`: an
   error in wslg.exe, as `wsl -e` is in wsl.exe). The exec-mode inner check and its `'{program}' runs '…'` prefix are
   reused unchanged.
7. **The bash launcher walk.**
   - `NameBashWord.Names` (`:887-898`): `if (ProgramName(name) is var p && (p.Equals("wsl", StringComparison.OrdinalIgnoreCase)
     || p.Equals("wslg", StringComparison.OrdinalIgnoreCase))) return (BashWord.Wsl, p.Equals("wsl",
     StringComparison.OrdinalIgnoreCase) ? "wsl" : "wslg");`, still before the wrapper lookup (wslg is in `Wrappers`
     now). Rename the tuple element `Wrapper` to `Known` (the set's spelling of a wrapper, a runner, or `wsl`/`wslg`)
     and update its two readers. The padded, quote, trailing `.`/`\`/`/` and stream rules of `NameBashWord`
     (`:863-886`) then cover wslg with no further change.
   - `WslRule(IReadOnlyList<string> argv, int k, int end, string name)` (`:934-944`): `WalkWsl(name, args)` and the
     prefix `$"'{name}' runs '{refusal.Program}': …"`.
   - `BashScan` (`:957`) and `BashLauncherWalk` (`:982`): `padded ? PaddedWslRefusalFor(known!) : WslRule(argv, i, end,
     known!)`, with `private static BlockedInvocation PaddedWslRefusalFor(string name) => name == "wslg" ?
     PaddedWslgRefusal : PaddedWslRefusal;` and `private static readonly BlockedInvocation PaddedWslgRefusal =
     new("wslg", PaddedWslgReason);` beside `PaddedWslRefusal` (`:850`).
8. **Texts** (new; `WayOut` is the existing constant, which `run` swaps on Windows; `PaddedWslReason`,
   `WslShellModeReason`, `WslUnknownReason` and `NoCommandShell` are unchanged):
   - `WslgShellModeReason` = `"'wslg' without --shell-type none runs its command line through the Linux shell (the
     user's login shell by default), which parses a substituted value again and can transform and print secrets past
     redaction. Give the command after --shell-type none: 'wslg --shell-type none ./deploy.sh {{secret}}'. " + WayOut`
   - `WslgUnknownReason` = `"'wslg': an option or a value this check doesn't know (wslg.exe takes only -d, --distribution, -u,
     --user, --cd, --shell-type (login, standard or none) and --, matched exactly, and has no -e), so it can't tell what wslg runs. Give the
     command after --shell-type none: 'wslg --shell-type none ./deploy.sh {{secret}}'. " + WayOut`
   - `PaddedWslgReason` = `@"'wslg' written with quote characters, surrounding white space, or a trailing dot, '\' or
     '/' can't be checked: run reads it as another program, but Windows starts wslg.exe, which runs its command line
     through the Linux shell. Write it plainly: 'wslg --shell-type none ./deploy.sh {{secret}}'."`
   - `private static string WslQuotedValueReason(string name) => $"'{name}': an option's value is empty or holds white
     space or a double quote, which run's command line quotes, but {name}.exe reads an option's value up to the first
     space or tab and keeps the quotes, so it can't be told where {name}'s command begins (the rest would run through
     the Linux shell). Give the value without them (cd in a script instead of --cd). " + WayOut;`
   No text holds a word of the command.
9. **Comments.** `BashLauncherRefusal`'s summary (`:821-837`): "in wsl's exec mode, at wsl's command" → "in the exec
   mode of wsl or wslg (brief T65, #448), at its command"; "after a bash or wsl name" → "after a bash, wsl or wslg
   name". `CheckWsl`'s summary (`:1219-1228`) gains: "Brief T65 (#448): <c>wslg</c> by wslg.exe's walk
   (<c>WslgMain</c>, f753835d5464): <c>WslgValued</c>, <c>--shell-type</c> and <c>--</c>, any other <c>-</c> word
   unknown (it has no <c>-e</c>). For both, a valued option's value that is empty or holds white space or a
   <c>"</c> is refused: wsl.exe splits its options at a space or tab and keeps quotes (<c>ParseArgument</c>), so
   the rest of such a value would begin a shell-mode command."

`GetBlockedInvocation` runs before `BashLauncherRefusal` in `run` (`RunCommand.cs:89`, `:97`), so a padded `wslg` that
`ProgramName` still reads as `wslg` (`wslg.exe.`, `wslg.exe:x`, and a trailing space, which `WindowsFileName` trims, so P15-P16 only through `BashLauncherRefusal`) gets `CheckWsl`'s verdict first; `"wslg"`, ` wslg`,
`wslg/` and `wslg::$DATA` aren't `wslg` to `ProgramName` and get `PaddedWslgReason`. The broker's templates use
`GetBlockedInvocation` (`BrokerTemplatePolicy.cs:265`) and so refuse wslg's shell mode too; nothing there changes.
`env … wslg` is refused as `env` already (`BlockedCommands`, `:76`).

### Tests

Write each test, run it and quote the failure, then write the code.

New file `TswapTests/WslgWalkTests.cs`, class `WslgWalkTests`, with the texts written out as test constants:
`WslgShell`, `WslgUnknown`, `PaddedWslg` (each exactly as in Design 8, with `Validation.WayOutFor(false)` for
`WayOut`), `QuotedValue(name)` (the function's text), `NoCommand(p)` = `$"'{p}' with no command starts a shell reading
stdin, which can transform and print secrets past redaction. {Validation.WayOutFor(false)}"`, `WslShell` (written out as
`InlineCodeBlockTests.WslShellReason` writes it, `InlineCodeBlockTests.cs:982`: that constant is private, so the text is copied, not referenced, and stays private), and `Runs(p, inner)` = `$"'{p}' runs '{i.Program}': {i.Reason}"` with `i =
Validation.GetBlockedInvocation(inner)` (asserted not null), as `Wsl_ByItsOwnWalk_IsRefused` builds its inner case.

**`GetBlockedInvocation_IsRefused(string[] argv, string program, string reason)`** (`MemberData`): the refusal is
`new BlockedInvocation(program, reason)` exactly.

| # | argv | Program | Reason |
|---|---|---|---|
| 1 | `wslg ./deploy.sh {{x}}` | `wslg` | `WslgShell` |
| 2 | `wslg.exe ./deploy.sh {{x}}` | `wslg` | `WslgShell` |
| 3 | `C:\Program Files\WSL\wslg.exe ./deploy.sh {{x}}` | `wslg` | `WslgShell` |
| 4 | `WSLG.EXE ./deploy.sh {{x}}` | `WSLG` | `WslgShell` |
| 5 | `wslg.exe. ./deploy.sh {{x}}` | `wslg` | `WslgShell` |
| 6 | `wslg -d Ubuntu -u app --cd /srv ./deploy.sh {{x}}` | `wslg` | `WslgShell` |
| 7 | `wslg --shell-type login ./x.sh {{x}}` | `wslg` | `WslgShell` |
| 8 | `wslg --shell-type standard ./x.sh {{x}}` | `wslg` | `WslgShell` |
| 9 | `wslg --shell-type none --shell-type login ./x.sh {{x}}` | `wslg` | `WslgShell` |
| 10 | `wslg -- ./x.sh {{x}}` | `wslg` | `WslgShell` |
| 11 | `wslg ~ --shell-type none ./x.sh {{x}}` (over-refusal) | `wslg` | `WslgShell` |
| 12 | `wslg {00000000-0000-0000-0000-000000000000} --shell-type none ./x.sh {{x}}` (over-refusal) | `wslg` | `WslgShell` |
| 13 | `wslg -e ./deploy.sh {{x}}` | `wslg` | `WslgUnknown` |
| 14 | `wslg --exec ./deploy.sh {{x}}` | `wslg` | `WslgUnknown` |
| 15 | `wslg --system --shell-type none ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 16 | `wslg --distribution-id 1 --shell-type none ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 17 | `wslg --parent-console 1 --shell-type none ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 18 | `wslg --list` | `wslg` | `WslgUnknown` |
| 19 | `wslg --debug-shell` | `wslg` | `WslgUnknown` |
| 20 | `wslg --install` | `wslg` | `WslgUnknown` |
| 21 | `wslg --shell-type bogus ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 22 | `wslg --shell-type None ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 23 | `wslg --Shell-Type none ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 24 | `wslg --shell-type=none ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 25 | `wslg -D Ubuntu --shell-type none ./x.sh {{x}}` | `wslg` | `WslgUnknown` |
| 26 | `wslg -` | `wslg` | `WslgUnknown` |
| 27 | `wslg` | `wslg` | `NoCommand("wslg")` |
| 28 | `wslg -d Ubuntu` | `wslg` | `NoCommand("wslg")` |
| 29 | `wslg --` | `wslg` | `NoCommand("wslg")` |
| 30 | `wslg -d` | `wslg` | `NoCommand("wslg")` |
| 31 | `wslg -d "My Distro" --shell-type none ./deploy.sh {{x}}` (one word `My Distro`) | `wslg` | `QuotedValue("wslg")` |
| 32 | `wslg --cd "C:\My Dir" --shell-type none ./deploy.sh {{x}}` (over-refusal) | `wslg` | `QuotedValue("wslg")` |
| 33 | `wslg --shell-type none python3 /dev/stdin` | `python3` | `Runs("wslg", ["python3", "/dev/stdin"])` |
| 34 | `wslg --shell-type none bash -c "echo {{x}}"` | `bash` | `Runs("wslg", ["bash", "-c", "echo {{x}}"])` |
| 35 | `wslg -d Ubuntu --shell-type none -- sh -c x` | `sh` | `Runs("wslg", ["sh", "-c", "x"])` |
| 36 | `wslg --shell-type none wsl ./x.sh {{x}}` | `wsl` | `"'wslg' runs 'wsl': " + WslShell` |
| 37 | `wsl -e wslg ./x.sh {{x}}` | `wslg` | `"'wsl' runs 'wslg': " + WslgShell` |
| 38 | `timeout 5 wslg ./x.sh {{x}}` | `wslg` | `"'timeout' runs 'wslg': " + WslgShell` |
| 39 | `sudo -u app wslg ./x.sh {{x}}` | `wslg` | `"'sudo' runs 'wslg': " + WslgShell` |
| 40 | `taskset -c 0 wslg ./x.sh {{x}}` | `wslg` | `"'taskset' runs 'wslg': " + WslgShell` |
| 41 | `runuser -u app wslg ./x.sh {{x}}` | `wslg` | `"'runuser' runs 'wslg': " + WslgShell` |
| 42 | `nice -n 5 wslg.exe ./x.sh {{x}}` | `wslg` | `"'nice' runs 'wslg': " + WslgShell` |
| 43 | `find . -exec wslg ./x.sh {} ;` | `wslg` | `"'find -exec' runs 'wslg': " + WslgShell` |
| 44 | `npx wslg ./x.sh {{x}}` | `wslg` | `"'npx' runs 'wslg': " + WslgShell` |
| 45 | `uv run wslg ./x.sh {{x}}` | `wslg` | `"'uv' runs 'wslg': " + WslgShell` |
| 46 | `wsl -d "My Distro" -e ./deploy.sh {{x}}` | `wsl` | `QuotedValue("wsl")` |
| 47 | `wsl -u "a b" -e ./deploy.sh {{x}}` | `wsl` | `QuotedValue("wsl")` |
| 48 | `wsl --cd "C:\My Dir" -e ./deploy.sh {{x}}` (over-refusal) | `wsl` | `QuotedValue("wsl")` |
| 49 | `wsl -d "a\tb" -e ./x.sh {{x}}` (a tab) | `wsl` | `QuotedValue("wsl")` |
| 50 | `wsl -d "a\"b" -e ./x.sh {{x}}` (a `"`) | `wsl` | `QuotedValue("wsl")` |
| 51 | `wsl -d "" -e ./x.sh {{x}}` (empty) | `wsl` | `QuotedValue("wsl")` |
| 52 | `wsl --distribution-id "x y" -e ./x.sh {{x}}` | `wsl` | `QuotedValue("wsl")` |
| 53 | `sudo wsl -d "My Distro" -e ./x.sh {{x}}` | `wsl` | `"'sudo' runs 'wsl': " + QuotedValue("wsl")` |

**`GetBlockedInvocation_IsAllowed(string[] argv)`**: null for

| # | argv |
|---|---|
| A1 | `wslg --shell-type none ./deploy.sh {{x}}` |
| A2 | `wslg.exe -d Ubuntu -u app --cd /srv --shell-type none ./deploy.sh {{x}}` |
| A3 | `wslg --distribution Ubuntu --user app --shell-type none -- ./deploy.sh {{x}}` |
| A4 | `wslg --shell-type login --shell-type none ./deploy.sh {{x}}` |
| A5 | `wslg --shell-type none` (no command: wslg.exe refuses it, nothing runs) |
| A6 | `wslg --shell-type none bash ./x.sh {{x}}` |
| A7 | `wslg --shell-type none ./x.sh "a b" {{x}}` (the command's words may hold spaces) |
| A8 | `timeout 5 wslg --shell-type none ./deploy.sh {{x}}` |
| A9 | `wsl -d Ubuntu-22.04 -e ./deploy.sh {{x}}` |
| A10 | `wsl --cd C:\work -e ./deploy.sh {{x}}` |
| A11 | `wsl -e ./x.sh "a b" {{x}}` |
| A12 | `wslgx ./deploy.sh {{x}}`, `wslconfig /l`, `tool wslg ./x.sh {{x}}` (three rows) |

**`BashLauncherRefusal_KnowsWslg(string[] argv, bool windows, string? program, string reason)`** (`MemberData`; the
probe `MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"])` on Windows, null off it; with `program` null the
result is null, else exactly `new BlockedInvocation(program, reason)`; `Off` is
`BashLauncherRefusalTests.OffWindowsReason`):

| # | argv | windows | Program | Reason |
|---|---|---|---|---|
| P1 | `"wslg.exe" ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P2 | `"w"slg --shell-type none ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P3 | ` wslg ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P4 | `wslg.exe. ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P5 | `wslg/ ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P6 | `wslg::$DATA ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P7 | `wslg.exe:x --shell-type none ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P8 | `"C:\Program Files\WSL\wslg.exe" ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P9 | `wslg::$DATA ./deploy.sh {{x}}` | false | `wslg` | `PaddedWslg` |
| P10 | `sudo "wslg" ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P11 | `timeout 5 wslg. ./deploy.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P12 | `find . -exec "wslg" ./x.sh ;` | true | `wslg` | `PaddedWslg` |
| P13 | `uv run "wslg" ./x.sh {{x}}` | true | `wslg` | `PaddedWslg` |
| P14 | `wsl -e "wslg.exe" ./x.sh {{x}}` | true | `wslg` | `"'wsl' runs 'wslg': " + PaddedWslg` |
| P15 | `wslg  ./deploy.sh {{x}}` (the word is `wslg` and a space) | true | `wslg` | `PaddedWslg` |
| P16 | `wslg.exe  --shell-type none ./deploy.sh {{x}}` (the word is `wslg.exe` and a space) | true | `wslg` | `PaddedWslg` |
| E1 | `wslg --shell-type none bash.exe ./x.sh {{x}}` | true | `bash.exe` | `"'wslg' runs 'bash.exe': " + Off` |
| E2 | `wslg -d Ubuntu -u app --cd /srv --shell-type none /mnt/c/Windows/System32/bash.exe ./x.sh {{x}}` | true | `bash.exe` | `"'wslg' runs 'bash.exe': " + Off` |
| E3 | `wslg --shell-type none -- BASH.EXE ./x.sh {{x}}` | true | `bash.exe` | `"'wslg' runs 'bash.exe': " + Off` |
| E4 | `sudo wslg --shell-type none bash.exe ./x.sh {{x}}` | true | `bash.exe` | `"'wslg' runs 'bash.exe': " + Off` |
| E5 | `wslg.exe --shell-type none bash.exe ./x.sh {{x}}` | false | `bash.exe` | `"'wslg' runs 'bash.exe': " + Off` |
| E6 | `wsl -e wslg.exe --shell-type none bash.exe ./x.sh {{x}}` | true | `bash.exe` | `"'wsl' runs 'bash.exe': 'wslg' runs 'bash.exe': " + Off` |
| E7 | `wslg --shell-type none wsl.exe -e bash.exe ./x.sh {{x}}` | true | `bash.exe` | `"'wslg' runs 'bash.exe': 'wsl' runs 'bash.exe': " + Off` |
| N1 | `wslg --shell-type none bash ./x.sh {{x}}` | true | null | |
| N2 | `wslg --shell-type none ./deploy.sh {{x}}` | true | null | |
| N3 | `wslg bash.exe ./x.sh {{x}}` (shell mode: `GetBlockedInvocation`'s) | true | null | |
| N4 | `wslg -e bash.exe ./x.sh {{x}}` (unknown: `GetBlockedInvocation`'s) | true | null | |
| N5 | `wslgx ./x.sh {{x}}`, `tool wslg.exe ./x.sh` (two rows) | true | null | |

**Facts** (same file):
- `ProgramWords_WalkIntoWslgsCommand`: `Validation.ProgramWords(["wslg", "-u", "app", "--shell-type", "none", "timeout",
  "5", "x"])` is `["wslg", "timeout", "x"]`.
- `GetFileTokenRefusal_InstallBehindWslg_IsRefused`: `Validation.GetFileTokenRefusal(["wslg", "-u", "app",
  "--shell-type", "none", "install", "{{@f}}", "/tmp/x"])` has `Program` `install` and a reason starting `'install'
  copies files` (as `RunuserWalkTests.GetFileTokenRefusal_InstallBehindRunuser_IsRefused`).
- `TheNewReasons_HaveTheExactText`: rows 1, 13, 31 and P1 written out in full as literals (not through the
  constants), with the Unix way out.

**`run`** (new methods in `RunBashLauncherTests`, its fixture and `AssertRefusedBeforeUnlock`):
- `Wslg_IsRefusedBeforeUnlock`: Windows, `wslg ./capture.sh {{pw}}`; `AssertRefusedBeforeUnlock(…,
  WslgWalkTests.WslgShell.Replace(Validation.WayOutFor(false), Validation.WayOutFor(true)), windows: true)` (exit 1,
  no start, no key challenge, the exact stderr, the value nowhere).
- `QuotedWslg_IsRefusedBeforeUnlock`: Windows, `"wslg.exe" ./deploy.sh {{pw}}`; `AssertRefusedBeforeUnlock(…,
  WslgWalkTests.PaddedWslg, windows: true)`.
- `WslgExecMode_StartsWithTheArgvAsGiven`: Windows, `wslg --shell-type none ./capture.sh {{pw}}`: exit 0, one start,
  `_pty.Argv` is `["wslg", "--shell-type", "none", "./capture.sh", Value]`.
- `ADistroNameWithASpace_IsRefusedAfterSubstitution_NamingTheToken`: `Secrets(("d", "My Distro"), ("pw", Value))`;
  Windows, `wsl -d {{d}} -e ./capture.sh {{pw}}`: exit 1, no start, stderr contains `After substitution, the value of
  {{d}} makes this a command 'run' refuses`, and neither `My Distro` nor `Value` is in stdout or stderr.

**Break it once** (each in the commit message, with the failing rows quoted):
1. drop `"wslg"` from `Wrappers`: rows 1-45 (allowed), `ProgramWords_…`, `GetFileTokenRefusal_…` and
   `Wslg_IsRefusedBeforeUnlock` must fail;
2. drop the `wslg` half of `CheckWrapper`'s condition (Design 3): rows 1, 13 and 37-45 must fail (the generic wrapper walk
   lets them through; rows 37-45 no longer reach wslg's own walk);
3. give wslg wsl's grammar (make `wslg` false in `WalkWsl`): rows 13-26 must fail (13-18 allowed, 19-20
   `NoCommand`, 21-26 get wsl's own verdicts, not `WslgUnknown`);
4. drop the value rule (Design 5): rows 31-32 and 46-53 and `ADistroNameWithASpace_…` must fail;
5. drop the `wslg` test from `NameBashWord.Names`: P1-P16 must fail (P1-P13, P15 and P16 get `PaddedWrapperReason("wslg")`, the
   word now being a wrapper) and `QuotedWslg_IsRefusedBeforeUnlock`;
6. call `WalkWsl("wsl", args)` and write `'wsl' runs` in `WslRule`: E1-E7 must fail (on the prefix; E1 also when the
   walk is wsl's);
7. drop `WrapperValued["wslg"]`: `ProgramWords_…` and `GetFileTokenRefusal_…` must fail (`app` taken for the
   command).

If any existing test fails on an assertion (no existing row has a `wsl` option value with white space, a `"` or
nothing in it: checked with grep at f2e3a5a), stop and list it.

**Docs.**
- `docs/security-model.md:172`, after "and `wsl` with no command (a login shell reading stdin),": "`wslg`
  (`wslg.exe`, WSL's second launcher, which has no `-e`) without `--shell-type none` (write `wslg --shell-type none
  ./deploy.sh {{secret}}`) or with no command, `wsl` or `wslg` with an option value that is empty or holds white space
  or a double quote (`wsl -d "My Distro" -e …`: wsl.exe reads an option's value up to the first space or tab, so the
  rest would begin a command run through the Linux shell),".
- `docs/security-model.md:186`: "in the command of `wsl -e`" → "in the command of `wsl -e` or `wslg --shell-type
  none`"; "(or of `wsl.exe`)" → "(or of `wsl.exe` or `wslg.exe`)"; "`wsl`'s shell mode is not refused" → "`wsl`'s or
  `wslg`'s shell mode is not refused"; "names bash or wsl before it" → "names bash, wsl or wslg before it"; "`wsl`
  written with quote characters, surrounding white space or a trailing dot" → "`wsl` or `wslg` written with quote
  characters, surrounding white space or a trailing dot"; and after "`wsl -d` with a missing value;": "`wsl` or
  `wslg` with an option value that is empty or holds white space or a `"` (`wsl --cd "C:\My Dir" -e …`: cd in the
  script instead); `wslg ~ --shell-type none ./x.sh`, `wslg -d` with a missing value, `wslg` with no command (today's
  wslg.exe refuses it itself) and every option wslg.exe doesn't take (`-e`, `--exec`, `--system`, `--list`, …; it
  refuses them itself);".
- `docs/broker-threat-model.md:530-531`: "also refuses `wsl` without `-e` and `wslg` without `--shell-type none` (both
  run that command line through the Linux shell): write `wsl -e ./deploy.sh {arg}`."

Release note: "`run` and the broker's templates now check `wslg` (`wslg.exe`, WSL's second launcher) as they check
`wsl`: without `--shell-type none` it runs its command line through the Linux shell, so it is refused; write `wslg
--shell-type none ./deploy.sh {{secret}}` (wslg has no `-e`). `wsl` and `wslg` with an option value that holds white
space or a double quote (`wsl -d "My Distro" -e …`) are now refused too: wsl.exe cut such a value at the space, and
the rest ran through the Linux shell."

## Out of scope

- `tocomment` and a lone `\r`: it keeps T50a's two views (`SelectMultiLine` passes `anyLineBreak: false`). It rewrites
  files, and taking a lone `\r` as a line break there changes which lines a multi-line occurrence spans. Propose a
  follow-up issue in the report.
- `\r\r\n` as one break (beyond `run`'s existing folded view); a stored value with mixed breaks matched in other
  spellings; a value made only of whitespace (`TryFoldedWhitespaceRun`, `docs/security-model.md`'s limit, unchanged).
- #435.7 (after T60), #435.4 (record only), #434 comment 5 (no profile), the `*.rsp` scan (already refused).
- A sudo-only import of an export link; seeds in a bare base64 payload or a QR image.
- Any code change in a T60 or T61 file other than Task 5's in `Validation.cs`; the broker's refusal text (`OtpAuthUri.BrokerRefusal` says "(an
  otpauth:// URI)" for an export link too; it is pinned by `BrokerTotpTests`' `Refusal` constant, so it stays).
- #438's padded-program refusals (T64 review M-2) and its wrapper option walks; a copy or link of `wsl.exe` or
  `wslg.exe` under another name (declared). A broker template whose `{arg}` placeholder sits in `wsl`'s or `wslg`'s
  option region: the broker checks a template's argv at load (`BrokerTemplatePolicy.cs:265`), not after an argument
  is filled in, so a caller's value with a space there is not refused by Task 5. Propose a follow-up issue in the
  report.

In the report, also propose a follow-up issue for the broker's and `rotate`'s refusal texts, which call an export link
"a TOTP seed (an otpauth:// URI)" and "a TOTP seed, which comes from the issuer".

In your report, give the release-note lines above (one per issue; "none" for #440 and #435), the two perf lines, and
the proposed issues (#435.7, `tocomment` and a lone `\r`, the broker template placeholder in wsl's option region).

## Amendment history

- **Round 1 (MiMo r1 ready; GLM r1 not ready, 2 Important, 10 Minor; controller rulings).**
  - I-1: the scanner keeps one hit per raw start and candidate, the earliest view's, as `Entries` does for `redact`, so
    `Scan_LineEndings_ExactlyOneHit` keeps its assertion and `run` keeps the line feed like `redact`. The view order is
    documented as load-bearing in both, pinned by a new `FingerprintStreamMatcherTests` test, with break-it-once 7.
  - I-2: the `Variants` test expects the distinct forms in today's order, with GLM's lists (the `\r` form with its
    encodings; the unpadded base64 is the 33-character PTY form's).
  - Minors: M-1 (row 8 in break-it-once 2), M-2 (`security-model.md:302` wording), M-3 (`WithLineBreaks` and
    `ScanState` summaries), M-4 (release note: the mark after a write or reindex, update every machine), M-5 (the
    docs sentence only; `BrokerRefusal` stays, pinned), M-6 (`PendingFrom_IsSound_MixedBreaks`, break-it-once 8), M-7
    (the Release perf command, against the commit before Task 4), M-8 (the fake's `ThrowIfUnreadable`, the `using
    static`, `Assert.Single`, `MsysTargetTests`), M-9 (the `ReferenceEquals` dependency noted in Task 2), M-10
    ("case ignored").
- **Round 2 (MiMo r2 ready; GLM r2 not ready, 2 Important, 9 Minor; controller rulings).**
  - I-1: `Scan_CarriedState_WindowEndingInACr_…` uses `x line-one-secret\rline-two-secret\r\n y`, which fails without
    the carry rule at `c = 34`; the design text says why a hit without another lone `\r` hides it (the folded view
    and the deduplication); break-it-once 4 also names the chunked matcher test at chunk sizes 1, 2, 17 and 34.
  - I-2: break-it-once 8 uses "a trailing `\r` is not held"; `PendingFrom_IsSound_MixedBreaks` plants a 256-character
    CRLF value (`L + W` = 256) so the cap path is reached, and the one-less mutation fails at `start + 255`.
  - Minors: the lone-`\r` form in `AGENTS.md:256` and `security-model.md:412-413`; the percent-encode note in the
    docs and release note; a proposed issue for the broker and `rotate` texts; `Scan_RawHits_…`' summary; `Link` and
    `Data` in `ExportLinkTests`, `MemberData` for the theory, the missing usings; Task 2's gap tests take their
    break-it-once as evidence; the entry length in the dedup key; `ScanState.Hits` keeps the pre-dedup hits; the perf
    wording.
- **Round 5 (MiMo r4 ready, 6 Minor).** M-1 break-it-once lists 1-3 widened; M-2 an invalid `--shell-type` value takes
  the `-` rule's verdict and `WslgUnknownReason` covers "a value"; M-3 `WslShell` written out; M-5 `Find.Length − 1`;
  M-6 rows P15-P16 (trailing white space, `PaddedWslg`). M-4 no change.
- **Round 4 (controller: add #448).** New Task 5: `wslg` checked as `wsl` by wslg.exe's own parser (microsoft/WSL
  f753835d5464 `WslgMain`: no `-e`, exec mode only `--shell-type none`, every other `-` word an error), at every
  program position and in every padded spelling; and, found reading that parser, an option value that wsl.exe or
  wslg.exe would split at a space (or a `"`) is refused for both, closing a fail-open of T51's `wsl` walk. Base
  merged with f2e3a5a (T64); the Validation.cs and RunCommand.cs citations of Task 2 moved to f2e3a5a; the ownership
  table, Out of scope and the report list updated.
