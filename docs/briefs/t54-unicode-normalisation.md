# Brief T54: a secret is recognised in either Unicode spelling, and typed passphrases and PINs are NFC (#400)

Issue: #400 (read it with its comments). Milestone 0.3.3. Base: `origin/main` at 666336c. Design (decided, read it
first): `docs/superpowers/specs/2026-11-23-unicode-normalisation-design.md`. Read AGENTS.md and CLAUDE.md, then
`TswapCore/Fingerprints/SecretVariants.cs`, `Fingerprinter.cs`, `FingerprintSet.cs`, `FingerprintScanner.cs` (`Build`),
`TswapCore/Keyring/RecordMerge.cs` (`MergeAll` fingerprint grouping, `ValidateFingerprints`),
`TswapCore/RecordVaultStore.cs` (`SameValue`, the read-path check near line 1067, `IsCurrent`, `LoadMetadata`'s counts,
`PrepareV3`), `TswapCore/Keyring/SecretRecordCodec.cs` (the fingerprint block), `TswapCore/Redaction.cs`,
`TswapCore/Broker/BrokerRedactor.cs` (`ForSecret`), `TswapCore/SecretMatcher.cs`, `TswapCore/ExportCrypto.cs`,
`TswapCli/Commands/ExportCommand.cs`, `ImportCommand.cs`, `TswapCli/Fido2PinPrompt.cs`, `TswapCli/SystemConsole.cs`
(`ReadPassword`), `TswapCore/VaultPassword/VaultPasswordKdf.cs`, `TswapTests/EvilValuesTests.cs` (the two `Nfd_*`
facts) and `TswapTests/SecretVariantsTests.cs`.

**Dependency on T50b.** T50b (`docs/briefs/t50b-tocomment-whole-values-and-line-breaks.md`, branch `brief/t50b`, not yet
on main) reworks `SecretMatcher` and `ToCommentProcessor`. **Before Task 1, `git fetch origin` and merge `origin/main`
into this branch** (the one sanctioned merge). If T50b has landed by then, re-check every `SecretMatcher` anchor below
against the merged code: at `brief/t50b` 9305253 the `VariantKind.Plain` checks are at `SecretMatcher.cs:160, 203, 218,
321`; at 666336c they are at `:160, 175`. If T50b has not landed, build Tasks 1-3 and 5-8, skip Task 4 and say so in your
report. Task 4 is written against main as it is now, plus the T50b rules it names.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or security keys, or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Commit with explicit paths. No push, no rebase, and no merge
other than the one above. Stop and report when the brief can't be built as written. **No existing test's assertions
change except the ones under "Sanctioned test edits"**; if any other existing test fails because of a rule here, stop
and list it. Do not touch `TswapCore/Validation.cs` or `run`'s guards. No production message and no custom test failure
text contains a value, a passphrase or a PIN (expected values inside `Assert.Equal` of engine tests are fine). Line
numbers are at 666336c; find anchors by content if they drifted.

## Owner and controller decisions (2026-11-23)

1. **Unicode-version drift of the vault password is a documented limit** (owner). There is no second try with the raw
   bytes: one typed password stays one TPM authorisation.
2. **`tocomment` replaces a value found in its other spelling with a marker** (owner). `apply` fills in the stored
   form, as an encoded occurrence is filled with the plain value today.
3. **Reindex notice** (controller): the existing "older variant set" note plus a release-note line. No extra notice.
4. **FIDO2 PIN in NFC, no automatic second try, in this brief** (owner).

## What is wrong (evidence)

1. **Masking knows one spelling.** `SecretVariants.For` (`TswapCore/Fingerprints/SecretVariants.cs:40-58`) yields the
   value, its whitespace-stripped form, base64 and base64url, all of the stored spelling. `redact`, `tocomment`, `run`'s
   scanner and the field guard rail match only those fingerprints. `run`'s token path (`Redaction.Variants`,
   `TswapCore/Redaction.cs:19-40`) and the broker (`BrokerRedactor.ForSecret`, `TswapCore/Broker/BrokerRedactor.cs:61`)
   build forms of the stored bytes only. T46 records the gap: `EvilValuesTests.Nfd_InRunOutput_RecordedForTheOwner`
   (line 506) and `Nfd_InRedactInput_RecordedForTheOwner` (line 524) log "not masked". `docs/security-model.md:763-768`
   documents the field guard rail's half of it.
2. **Export passphrases are bytes as typed.** `ExportCrypto.DeriveArgon2id` encodes without normalising
   (`TswapCore/ExportCrypto.cs:53`), as does v1's `Crypto.DeriveKeyFromPassphrase` (`TswapCore/Crypto.cs:51`). `export`
   compares the confirmation ordinally (`TswapCli/Commands/ExportCommand.cs:39`). An export made with `\u00e9` typed as NFD
   doesn't import when `\u00e9` is typed as NFC.
3. **The FIDO2 PIN is bytes as typed.** `Fido2PinPrompt.Ask` returns the terminal's bytes (`TswapCli/Fido2PinPrompt.cs:58`).
   CTAP 2.1 §6.5.1 says platform PINs "are in Unicode normalization form C". The minimum-length check counts UTF-16 units
   (`:69`), the spec counts code points.
4. **Half a character in a vault password.** Backspace in `ReadPassword` removes one UTF-16 unit
   (`TswapCli/SystemConsole.cs:127-131`), so deleting a character outside the BMP leaves a lone surrogate.
   `VaultPasswordKdf.Stretch` then throws .NET's `ArgumentException` from `Normalize` (`VaultPasswordKdf.cs:67`), and
   `CliRunner.cs:28` prints .NET's text.
5. **Not wrong: the vault password itself.** `Stretch` has normalised to NFC since it was written (de9c60e, v0.2.0), and
   `StretchedPasswordTests.Stretch_NfdAndNfcPasswordsAgree` (line 99) pins it. No vault-password slot needs a fallback,
   and nothing here changes how a vault password unlocks.

## The Unicode rules (read before building; every task relies on them)

- **The normaliser.** `string.Normalize` in .NET 11 calls the platform's library: ICU on Linux and macOS (system ICU,
  `libicucore` on macOS), ICU on Windows 10 1903 and later (NLS before that)
  (https://learn.microsoft.com/dotnet/core/extensions/globalization-icu). tswap does not set `InvariantGlobalization`.
  On the controller's machine (Fedora 44) .NET 11 loads `libicuuc.so.77.1` (ICU 77, Unicode 16.0).
- **What this brief relies on, and nothing more:**
  1. For any string `s`, NFC(`s`) and NFD(`s`) are canonically equivalent to `s`, and each is idempotent (UAX #15,
     https://unicode.org/reports/tr15/).
  2. Normalisation stability: for strings of characters *assigned* in a library's Unicode version, every later version
     gives the same result (Unicode Character Encoding Stability Policy, "Normalization Stability",
     https://www.unicode.org/policies/stability_policy.html). An *unassigned* code point is left unchanged, so two
     machines can disagree about a character newer than one of them (decision 1; Task 2's tolerance).
  3. Every ASCII character is unchanged by NFC and by NFD.
  4. `Normalize` throws `ArgumentException` on a lone surrogate (checked with .NET 11).
- **Fail closed means "never less than today".** Where a string can't be normalised (a lone surrogate, bytes that are
  not valid UTF-8), the masking paths keep exactly today's forms. Creating a passphrase or PIN refuses. Reading one
  (import, PIN entry) uses the bytes as they are.
- **Test values use only characters from Unicode 3.2 or earlier** (`\u00e9` U+00E9, `e` + U+0301, `\u00e4`/`\u00f6`, U+0958, U+212B),
  so every supported ICU gives the same result. Build test strings from `\u` escapes, never pasted characters.

## Task 1: form variants and variant set version 2

In `TswapCore/Fingerprints/SecretVariants.cs`:

- `VariantKind` gains, appended (the byte values are format):

  | Value | Name | Value | Name |
  |---|---|---|---|
  | 4 | `NfcPlain` | 8 | `NfdPlain` |
  | 5 | `NfcWhitespaceStripped` | 9 | `NfdWhitespaceStripped` |
  | 6 | `NfcBase64` | 10 | `NfdBase64` |
  | 7 | `NfcBase64Url` | 11 | `NfdBase64Url` |

- `public static VariantKind BaseKind(this VariantKind kind)`: 4-7 → 0-3, 8-11 → 0-3, every other value unchanged
  (in a new `public static class VariantKinds` in the same file).
- `CurrentSetVersion = 2`. Its comment says what version 2 added.
- `For(value)`: today's list for `value`, then, when `value` holds no lone surrogate, today's list for NFC(`value`) with
  each kind moved to its `Nfc` kind, then the same for NFD(`value`) with the `Nfd` kinds. Each form's list is added only
  when that form differs from `value`. A text already in the result is not added again (the first kind keeps it). The
  summary states the order.
- `public static bool IsCurrent(FingerprintSet set)`: true when `set.VariantSetVersion == CurrentSetVersion`, or when it
  is 1 and the set proves the value ASCII. A set proves it when:
  - it has no entries (an empty value); or
  - it has a `Plain` entry of length `P` and either:
    - a `Base64Url` entry of length `U`, with `floor(3·U/4) == P`; or
    - no `Base64Url` entry and a `Base64` entry of length `B`, with `B % 4 == 0` and `3·B/4 == P`.

  The summary carries the reason: unpadded base64url gives the exact UTF-8 byte count; without a base64url entry the
  base64 has no padding; UTF-8 bytes equal UTF-16 units exactly when every character is ASCII.

Lone-surrogate detection goes into a new `internal static class UnicodeText` (`TswapCore/UnicodeText.cs`):
`int? FindLoneSurrogate(ReadOnlySpan<char>)`, with the body of `FieldRules.FindLoneSurrogate`
(`TswapCore/Fields/FieldRules.cs:148`), which then calls it.

Tests (`SecretVariantsTests`), `For` exactly:

| # | Value | `For` |
|---|---|---|
| 1 | `abc` | `[(Plain, "abc"), (Base64, "YWJj")]` (unchanged) |
| 2 | `caf\u00e9` | `[(Plain, "caf\u00e9"), (Base64, "Y2Fmw6k="), (Base64Url, "Y2Fmw6k"), (NfdPlain, "cafe\u0301"), (NfdBase64, "Y2FmZcyB")]` |
| 3 | `cafe\u0301` | `[(Plain, "cafe\u0301"), (Base64, "Y2FmZcyB"), (NfcPlain, "caf\u00e9"), (NfcBase64, "Y2Fmw6k="), (NfcBase64Url, "Y2Fmw6k")]` |
| 4 | `\u0958x` | `[(Plain, "\u0958x"), (Base64, "4KWYeA=="), (Base64Url, "4KWYeA"), (NfcPlain, "\u0915\u093cx"), (NfcBase64, "4KSV4KS8eA=="), (NfcBase64Url, "4KSV4KS8eA")]` (NFD gives the same texts) |
| 5 | `p\u00e4ss w\u00f6rd` | the 4 base entries, then `(NfdPlain, "pa\u0308ss wo\u0308rd")`, `(NfdWhitespaceStripped, "pa\u0308sswo\u0308rd")`, `(NfdBase64, "cGHMiHNzIHdvzIhyZA==")`, `(NfdBase64Url, "cGHMiHNzIHdvzIhyZA")` |
| 6 | `x\uD800y` | base kinds only |

`IsCurrent`, sets from `Fingerprinter.Compute` with the version set by hand:

| # | Set | `IsCurrent` |
|---|---|---|
| 1 | version 2 of `caf\u00e9` | true |
| 2 | version 1 of `abc`, of `ab`, of `??>` | true |
| 3 | version 1 of `caf\u00e9` | false |
| 4 | version 1 of `\U0001F600` | false |
| 5 | version 1 of the empty value | true |
| 6 | version 0 of `abc` | false |
| 7 | version 1 of `abc` with its `Base64` entry removed | false |

Also: `BaseKind` maps all twelve kinds and leaves 200 unchanged; `Fingerprinter.Compute` of row 2 has 5 entries and
version 2; a record ingested with value 2 round-trips its set through `SecretRecordCodec` unchanged.

Break-it-once: (a) drop the NFD half of `For`: row 2 must fail; (b) in `IsCurrent` compare `U·3/4` rounded up: row 2 of
the second table (`ab`) must fail.

## Task 2: validation and merge compare base entries; form entries are a union

Add to `FingerprintSet`:

- `public bool SameBaseEntries(FingerprintSet other)`: the entries whose `Kind.BaseKind() == Kind` (kinds 0-3), in
  order, are equal (`FingerprintEntry.Equals`, fixed-time HMAC).
- `public static FingerprintSet Union(FingerprintSet a, FingerprintSet b)` (same version, `SameBaseEntries` true, else
  `ArgumentException`): the base entries, then the distinct form entries of both sorted by kind, then length, then HMAC
  bytes ordinally. `Fingerprinter.Compute` writes its form entries in that order already (one per kind, ascending), so
  `Union(x, x)` equals `x`.

Use them at every place that compares sets today:

| Site (666336c) | Today | After |
|---|---|---|
| `RecordMerge.cs:156-162` and `:239-245` (copies of one version) | a group of one variant-set version must be equal, else "two copies hold different fingerprints" | must have `SameBaseEntries`, else the same exception. The group's set is the `Union` of all |
| `RecordMerge.cs:391-396` (`ValidateFingerprints`) | sets of `CurrentSetVersion` must equal the recomputation | sets that are `IsCurrent` must have `SameBaseEntries` with the recomputation |
| `RecordVaultStore.cs:1067-1074` (read path) | the same | the same as the row above |
| `RecordVaultStore.cs:935-936` (`SameValue`) | version `== CurrentSetVersion` and full equality | `IsCurrent` and `SameBaseEntries` |
| `RecordVaultStore.cs:1443` (`IsCurrent` of reindex) | `VariantSetVersion >= CurrentSetVersion` | `>= CurrentSetVersion` or `SecretVariants.IsCurrent` |
| `RecordVaultStore.cs:1783` (`LoadMetadata`'s older count) | `< CurrentSetVersion` | `< CurrentSetVersion` and not `SecretVariants.IsCurrent` |
| `RecordVaultStore.cs:2052-2055` (`PrepareV3`) | recompute when older | recompute when `< CurrentSetVersion` and not `SecretVariants.IsCurrent` |

So `vault reindex` rewrites only records that hold a non-ASCII value fingerprinted by version 1, and the note
(`FingerprintTexts.NoteOlderVariants`) counts exactly those. The metadata merge's "fingerprints prove them equal"
(`RecordMerge.cs:252-257`) is sound with base entries: the plain entry's HMAC decides.

Tests (`RecordMergeV3Tests`, `RecordStoreV3Tests`, `RecordStoreMetadataTests`):
- two copies of one version whose sets differ only in one `NfdPlain` entry (a hand-made "other library" set) merge,
  and the merged set holds both entries, sorted;
- copies whose `Plain` entries differ still conflict;
- a stored version 2 set whose `NfdPlain` entry differs from the recomputation reads, loads and merges; one whose
  `Base64` entry differs is refused as today;
- `LoadMetadata`'s `OlderVariantSet` is 0 for a vault with a version 1 ASCII record and 1 with a version 1 `caf\u00e9`
  record;
- `vault reindex` rewrites the second and not the first (`ReindexResult` counts);
- `add` of the same `caf\u00e9` value over a version 2 record decrypts nothing (the existing `ValueDecrypted` seam).

Break-it-once: (a) compare whole sets in `ValidateFingerprints` again: the "differs from the recomputation" test must
fail; (b) leave `LoadMetadata`'s count at `< CurrentSetVersion`: the ASCII count test must fail.

## Task 3: every matcher uses the new forms

- `FingerprintScanner.Build` (`:141-171`): classify an entry by `entry.Kind.BaseKind()`. A plain entry pairs with the
  whitespace-stripped entry **of its own form** (`Plain` with `WhitespaceStripped`, `NfcPlain` with
  `NfcWhitespaceStripped`, `NfdPlain` with `NfdWhitespaceStripped`), not the set's first one. Only kinds above 11 reach
  `default:`.
- `RedactProcessor.Label` (`TswapCore/RedactProcessor.cs:16-21`) and `SecretProcessor.TypeOf` (`SecretProcessor.cs:71-75`)
  switch on `kind.BaseKind()`: a label never says which spelling was found.
- `TokenBoundary.IsShort` (`TswapCore/Fingerprints/TokenBoundary.cs:83-90`) stays as it is: the stored form's `Plain`
  length decides for every form (T30).
- `Redaction.Variants(writtenForm)` (`Redaction.cs:19-40`): the forms are `writtenForm`, then NFC and NFD of it (each
  when it differs and `writtenForm` holds no lone surrogate). Each gets the line-ending forms and encodings of today.
  Duplicates go, as today. Line 35 keeps taking the `Base64` entry (the first kind), which is the form's own.
- `BrokerRedactor.ForSecret` (`BrokerRedactor.cs:61`): move today's body into a local function over one byte array, and
  call it for the secret's bytes. Then, when those bytes decode with `new UTF8Encoding(false, throwOnInvalidBytes:
  true)`, call it for the UTF-8 of NFC and of NFD of the decoded text, each when it differs from the bytes. `Add`'s
  duplicate check, the longest-first order and `Window` are unchanged.
- `FieldSecretCheck` needs no change (it uses the index).

Tests:

| # | Stored (`ingest`) | Input | Command | Outcome |
|---|---|---|---|---|
| 1 | `caf\u00e9-secret-value` (NFC) | `nfc caf\u00e9-secret-value end\nnfd cafe\u0301-secret-value end\n` | `redact` | both lines masked |
| 2 | `cafe\u0301-secret-value` (NFD) | the same | `redact` | both lines masked |
| 3 | `\u0958-secret-value` | `\u0915\u093c-secret-value` | `redact` | masked |
| 4 | row 1 | base64 of `cafe\u0301-secret-value`'s UTF-8 | `redact` | `[REDACTED: s (base64)]` |
| 5 | row 1 | the child prints row 1's input, `run tool {{s}}` | `run` (token path) | both lines masked |
| 6 | row 1, and `other` ASCII | the child prints row 1's input, `run tool {{other}}` | `run` (scanner path) | both lines masked |
| 7 | row 2 | field value `caf\u00e9-secret-value` | `field set` | refused (guard rail) |
| 8 | `x\uD800y-secret-value` (via `add`) | that text | `redact` | masked, no exception |
| 9 | `p\u00e4ss w\u00f6rd-secret`, and `other` ASCII | the child prints `pa\u0308ss wo\u0308rd-secret`, `run tool {{other}}` | `run` (scanner path) | masked |

Engine-level rows for the scanner (`FingerprintScannerTests`): the hit for row 1's NFD text has the NFD text's raw
span. `Scan_RawHits_EqualFingerprintIndexScan`'s generator plants NFD and NFC spellings of values containing `\u00e9`, and
the oracle comparison holds. `BrokerRedactorTests`: for the class's `Secret` (it contains `\u00e9`), `Forms` contains the
UTF-8, base64, upper hex and percent form of its NFD spelling. For the bytes `0xFF 0x41 0x42 0x43 0x44 0x45`, no form
contains `EF BF BD`.

`EvilValuesTests.Nfd_InRunOutput_RecordedForTheOwner` and `Nfd_InRedactInput_RecordedForTheOwner` become
`Nfd_InRunOutput_Masked` and `Nfd_InRedactInput_Masked`: the `_output.WriteLine` goes, and they assert
`NfdLine(output) == $"nfd {Label} end"` with a failure text that names the case only.

Also `Redaction.Variants("caf\u00e9")` contains `cafe\u0301` and `Y2FmZcyB`, and `Redaction.Variants("abc")` is
unchanged.

Break-it-once: (a) pair every plain entry with the set's first whitespace-stripped entry (today's code): row 9 must
fail; (b) drop NFD from `Redaction.Variants`: its unit test must fail; (c) drop the alternate loop in `ForSecret`:
the `Forms` test must fail.

## Task 4: `tocomment` replaces the other spelling (owner decision 2; after merging T50b)

Every `VariantKind.Plain` comparison in `SecretMatcher` compares `Kind.BaseKind()`: T22's `EncodedTokens` (`:160` at
666336c), T20's `WholeValueToken` (`:175`), and in T50b's code (at 9305253) `:160`, `:203`, `:218` and rule (a′)'s
`envForm` (`:321`). Then:
- `NfcPlain` and `NfdPlain` count as plain for T20, T22 and rule (a′);
- the `Nfc`/`Nfd` stripped and encoded kinds count as encoded, like their base kinds;
- `ToCommentProcessor` needs no kind change at 666336c, and T50b's `TypeOf` (`ToCommentProcessor.cs:98-103`) gets
  `BaseKind()` like `SecretProcessor.TypeOf`.

Tests (stored `caf\u00e9-db-pass-1`, name `s`; through `Redact.ToComment`, with T50b's `ToCommentRoundTrip.Check` on
every change):

| # | File | Result |
|---|---|---|
| 1 | `password: cafe\u0301-db-pass-1\n` | `password: ""  # tswap: s\n` (the round trip fills the stored NFC value) |
| 2 | `DB_PASS=cafe\u0301-db-pass-1\n` | `DB_PASS=""  # tswap: s\n` (`NfdPlain` passes (a′)) |
| 3 | `DB_PASS=Y2FmZcyBLWRiLXBhc3MtMQ==\n` (base64 of the NFD spelling) | unchanged, one `SkippedValue` (R1), as for a base64 occurrence on an `=` line |
| 4 | `key: \|\n  cafe\u0301-db-pass-1\n` (a literal block holding the NFD spelling) | adopted whole, as T20 adopts the stored spelling |

Break-it-once: compare raw `Kind` in (a′) again: row 2 must fail.

## Task 5: vault password: a whole character per backspace, a clear refusal, a pinned vector

- `SystemConsole.ReadPassword` (`SystemConsole.cs:127-131`): when the last two characters are a high and a low
  surrogate, backspace removes both and writes `"\b \b"` twice (one `*` was written per key char).
- `VaultPasswordKdf.Stretch` (`VaultPasswordKdf.cs:59-81`): before normalising, a lone surrogate
  (`UnicodeText.FindLoneSurrogate`) throws `TswapException(VaultPasswordKdf.LoneSurrogateText)`, with
  `public const string LoneSurrogateText = "The vault password holds half of a character (a lone UTF-16 surrogate), so it can't be used. Type it again.";`.
  No vault has such a password: setting one threw before.
- `StretchedPasswordTests.Stretch_KnownAnswer`: `Stretch("p\u00e4sswort-kat", salt = bytes 0x00..0x1F, PasswordVaultTestSupport.Cheap)`
  equals a fixed 32-byte hex constant. **Compute the constant with the code at 666336c, before any change in this
  brief**, and say so in the test's summary. The test also asserts that the NFD spelling gives the same bytes.

Tests:
- `SystemConsoleTests`: keys `a`, `\uD83D`, `\uDE00`, Backspace, `b`, Enter give `"ab"`, and the echo is `***` (one per key char) then
  `\b \b\b \b` then `*` and the newline;
- `Stretch("x\uD800")` throws `TswapException` with `LoneSurrogateText`;
- an in-process TPM password vault made by `PasswordVaultTestSupport.InitTpmPasswordVault` with
  `p\u00e4sswort-nfc` opens when the prompt is answered with `pa\u0308sswort-nfc`, and the reverse (a command that
  unlocks, scripted as `AgentCommandTests` does). These pin today's behaviour.

Break-it-once: drop `.Normalize(FormC)` from `Stretch`: the known-answer test's NFD assertion and
`Stretch_NfdAndNfcPasswordsAgree` must fail.

## Task 6: export in NFC, import any spelling

In `ExportCrypto`:
- `public static string NormalisePassphrase(string passphrase)`: refuses a lone surrogate with
  `TswapException("The passphrase holds half of a character (a lone UTF-16 surrogate); type it again.")`, else NFC.
- `public static IReadOnlyList<string> PassphraseCandidates(string typed)`: `[typed]` when `typed` holds a lone
  surrogate; otherwise NFC(`typed`), `typed`, NFD(`typed`), with ordinal duplicates removed, in that order.

`export` (`ExportCommand.cs:34-49`): both readings go through `NormalisePassphrase`, the confirmation compares the
results ordinally, and the key derives from the normalised one. The file format and version don't change.

`import` (`ImportCommand.cs:30-51`): for each candidate in order, `DeriveKey` and `Crypto.Decrypt`. The first that
authenticates wins. When none does, the existing "Decryption failed — wrong passphrase or file tampered" message.
A `FormatException` stops the loop at once, with today's message. Zero every derived key that fails.

Tests (`RecordStoreExportImportTests`; export files built in the test with a fixed salt where a "made by an older
tswap" file is needed, through `ExportCrypto.DeriveKey` over the raw passphrase and `Crypto.Encrypt`):

| # | Export made with | Import typed as | Result |
|---|---|---|---|
| 1 | `export`, `p\u00e4ss-export-1` (NFC) | `pa\u0308ss-export-1` (NFD) | imports |
| 2 | `export`, `pa\u0308ss-export-1` (NFD) | NFC | imports |
| 3 | older v3 file, raw NFD bytes | NFC | imports (third candidate) |
| 4 | older v3 file, raw NFC bytes | NFD | imports (first candidate) |
| 5 | older v1 (PBKDF2) file, raw NFD bytes | NFC | imports |
| 6 | older v3 file, raw `x\uD800y` (encoded as UTF-8 does) | `x\uD800y` | imports (`[typed]`) |
| 7 | `export`, confirmation typed in the other spelling | | accepted |
| 8 | `export`, passphrase `x\uD800y` | | refused with the lone-surrogate text, nothing written |
| 9 | any | a wrong passphrase | today's decryption-failed message |

Break-it-once: (a) drop NFD from the candidates: row 3 must fail; (b) compare the confirmation raw again: row 7 must
fail.

## Task 7: the FIDO2 PIN in NFC

In `Fido2PinPrompt`, `Ask` (`:55-59`) passes the terminal's bytes through
`internal static byte[] NormalisePin(byte[] pin)`:
- all bytes below 0x80: returned as they are (no string is made, so a numeric PIN never becomes one);
- valid UTF-8 (strict decode) with no lone surrogate: the UTF-8 of NFC of it, the input zeroed;
- anything else: the bytes as they are.

`AskNew` (`:61-95`) then checks the normalised bytes:
- bytes that are not valid UTF-8 are asked again with
  `public const string NotUtf8Text = "A FIDO2 PIN must be text (UTF-8); type it again.";`;
- the minimum counts runes of the decoded text (`TooShortText` unchanged);
- the 63-byte maximum applies to the normalised bytes;
- the two entries are compared after normalising, so a repeat typed in the other spelling matches.

No second try with the raw bytes after the key refuses a PIN (decision 4). The managed string made for a non-ASCII PIN
can't be zeroed. Say so in `NormalisePin`'s summary, as `VaultPasswordKdf`'s does for the password (`:36-40`).

Tests (`SlotAddFido2Tests` for the new-PIN rows, an unlock test with a FIDO2 slot for row 3; `FakeFido2Keys`, `FakeTerminal`):

| # | Typed | The fake receives / result |
|---|---|---|
| 1 | new PIN `1234`, repeat `1234` | `1234` |
| 2 | new PIN `cafe\u0301`, repeat `caf\u00e9` | the UTF-8 of `caf\u00e9` |
| 3 | unlock PIN `cafe\u0301` for a key whose PIN is `caf\u00e9` | the unlock succeeds, one PIN call |
| 4 | new PIN of 31 `\u00e9` typed as NFD (93 bytes) | accepted: 62 bytes once normalised |
| 5 | new PIN `\U0001F600\U0001F600` (2 runes, 4 UTF-16 units) | asked again with `TooShortText` |
| 6 | new PIN bytes `0xFF 0xFE 0x41 0x42` | asked again with `NotUtf8Text` |

The existing `SlotAddFido2_NewPinOver63Bytes_AskedAgain` cases stay as they are.

Break-it-once: return the input from `NormalisePin` unchanged: rows 2 and 3 must fail.

## Task 8: docs

- `docs/security-model.md:763-768`, "Unicode forms": a stored value is now recognised in its stored, NFC and NFD
  spellings, also base64 and base64url of each, by `redact`, `tocomment`, `run`, the broker and this check. Left out:
  a mixed spelling that is neither normal form, and compatibility forms (full-width letters, ligatures). Records
  fingerprinted by an older tswap get the other spellings with `sudo tswap vault reindex`.
- `docs/commands.md`, "Fingerprints, format 2 records and `vault reindex`" (lines 62-80): one sentence that the note
  appears for records holding non-ASCII values written before 0.3.3, and the reindex adds their other spellings.
- `docs/vault-password-and-agent.md`, in the password section: the password is compared in NFC, so `\u00e9` typed either
  way works on every OS. The limit (decision 1): a character newer than a machine's Unicode library may be normalised
  differently there, so keep vault passwords to characters a few years old.
- `docs/design/multi-machine-keying.md:582-583`: the same limit in one clause.
- `docs/commands.md`, `export`/`import`: the passphrase is compared in NFC, and an export made with an older tswap
  imports whichever way `\u00e9` is typed, unless the passphrase mixed both spellings.
- `docs/design/hardware-backends.md`, the FIDO2 section: the PIN is sent in NFC (CTAP 2.1 §6.5.1).
- In your report, the text of the 0.3.3 release-note entries (do not edit `docs/release-notes/`):
  - `redact`, `tocomment`, `run`, the broker and the field check recognise a secret in either Unicode spelling of
    accented letters (NFC/NFD), base64 included. Vaults with non-ASCII secrets: run `sudo tswap vault reindex` once; until
    then a note says how many records it would update. Older tswap versions read the new records.
  - Export passphrases are compared in NFC; older exports import whichever way an accented letter is typed.
  - The FIDO2 PIN is sent in NFC, as CTAP 2.1 requires. A PIN set through tswap 0.3.2 or earlier by typing a decomposed
    accent no longer matches: change it with another FIDO2 tool.
  - Known limit: a vault password holding a character newer than a machine's Unicode library may not open there.

## Sanctioned test edits

| Test | Change | Why |
|---|---|---|
| `SecretVariantsTests.CurrentSetVersion_IsOne` | becomes `CurrentSetVersion_IsTwo`, asserts 2 | the version bump |
| `FingerprintTests.Compute_EmptyValue_HasZeroEntries` (line 103) | asserts `SecretVariants.CurrentSetVersion` instead of `1` | the same |
| `SecretVariantsTests.BuildMatchList_ForOneSecret_EqualsTheMappedVariants` | `Assert.Equal(pinned, fromVariants)` compares with the base-kind entries of `For` only; `Map` maps through `BaseKind`; an added assertion pins the form entries against a pinned rule written out in the test (`PinnedFormVariants`) | its random values contain `\u00e9`, `\u20ac` and lone surrogates |
| `FingerprintScannerTests.MaxRawLength_UnknownKind_AllowsFoldSlack` | `(VariantKind)9` → `(VariantKind)200` (input) | 9 is now defined |
| `SecretRecordCodecV3Tests.UnknownVariantKind_IsRefusedInAKnownSetVersion_KeptInANewerOne` | `(VariantKind)7` → `(VariantKind)200` (input) | 7 is now defined |
| `EvilValuesTests.Nfd_InRunOutput_RecordedForTheOwner`, `Nfd_InRedactInput_RecordedForTheOwner` | renamed and asserted (Task 3) | the gap is closed |
| `RunVaultRedactionTests.RunCoverage_OlderVariantSet_Noted` | summary only ("unreachable at variant set 1" goes) | no longer true |

## Out of scope

- Compatibility normalisation (NFKC/NFKD), case folding, look-alikes; escapes a path doesn't match today.
- Normalising stored secret values, names or fields (fields already are).
- A raw-bytes fallback for the vault password (decision 1); anything else in the unlock paths.
- NFC views of scanned text (design approach B).
- Windows' own FIDO2 PIN dialog; the recovery key (base64); classic vaults.
- The release notes themselves (the controller writes them from your report).
