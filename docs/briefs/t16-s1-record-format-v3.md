# Brief T16-S1: record format v3 with keyed fingerprints, `vault reindex`, classic vaults migration-only (v0.2.0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** every record can be recognised in a file or stream without decrypting its value: record format v3 splits each
record into an encrypted metadata section (with keyed fingerprints of every retained value) and value sections encrypted
once, plus `sudo tswap vault reindex`, record vaults by default, and classic vaults refused except for migration.

**Architecture:** the codec gains a v3 layout next to v2 (v2 stays readable). The store keeps decoded `SecretRecord`s for
today's whole-database commands and adds a metadata-only load path that decrypts no value section, which Stages 2 and 3
build on. Fingerprints (`TswapCore/Fingerprints/`) are computed from exactly the variants `SecretProcessor` matches today.

**Tech stack:** C# 14 / .NET 10, NativeAOT, xUnit; `System.Security.Cryptography` (`HKDF`, `HMACSHA256`, `AesGcm`) only.
No new package.

**Spec:** `docs/superpowers/specs/2026-11-01-import-story-design.md`, sections "Constraints", "Stage 1", "Threat model
additions". The spec is the authority; this brief settles what it leaves to the builder and records the rulings below.

Read `AGENTS.md`, the spec, `MULTI_MACHINE_KEYING.md` (metadata section) and `docs/briefs/t6-record-store.md`
(decisions 3–6, 10) first. One commit per task, test first, a break-it-once check per task (name in the commit message
which line you reverted and which test failed). `./runtests.sh --unit` after each task, the full `./runtests.sh` at the
end. No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR`
and temp folders only.

## Rulings (the designer's calls in this brief; the owner may overrule)

1. **Every section uses a fresh random 96-bit nonce** (owner, 2026-11-02, as the spec says; the owner declined the
   synthetic-nonce alternative the first draft proposed). Each value section is still encrypted **once** by the
   machine that creates or converts its version and copied byte for byte afterwards. Consequence: two machines that both
   convert the same v2 version (a concurrent `vault reindex`, or two machines writing after the marker appears) produce
   two different, equally valid ciphertexts of one plaintext. That is legitimate, not damage, and converges by ruling
   11. Each such key meets at most a handful of encryptions, far inside GCM's random-nonce limits.
2. **No cleartext version stamps.** Value sections follow the metadata section in the order of the metadata's version
   list; their stamps are learned by decrypting metadata, and each value section's associated data still binds its
   stamp. A transport observer gains no value-change timestamps beyond what the spec's leak delta already names.
3. **When this build writes v3:** when the vault folder holds the marker file `record-format` whose content, after
   trimming a BOM and whitespace (CR/LF included), is `3`, **or** when this command has read any v3 record from the
   folder (a deleted marker can't silently downgrade a reindexed vault). Otherwise v2. A marker holding a number above 3
   refuses every write (`written by a newer tswap … upgrade`); an empty or unparsable marker is a warning with a repair
   hint and counts as absent (a sync artefact must not block all writes). Conflicted copies of the marker are ignored.
   The marker is written through the store's file layer (owner, mode, atomic). New vaults (`init`, `migrate
   --to-records`) are created with the marker and v3 records from the start (`migrate` writes the marker into its temp
   folder before the read-back comparison, so the rename carries it).
4. **Plain `init` makes a record vault**: what `init --keyring` does today (one YubiKey slot plus a recovery slot), in
   the record store at `<config dir>/vault`, marker included; `--tpm` / `--secure-enclave` likewise. `--keyring` stays
   accepted as a no-op so scripts keep working. New: `init ... --folder <dir>` creates the vault folder at `<dir>`
   (absent or empty; for a Syncthing or cloud-drive folder). The two-YubiKey XOR vault can no longer be created (a
   record store needs a keyring; XOR vaults exist only to be migrated); there is no flag for it, so nothing to refuse:
   the help text stops saying "Initialize with 2 YubiKeys". **`init` on a config dir that already holds a classic vault
   refuses** (exit 1): `This config folder holds a classic vault. Convert it with 'sudo tswap migrate --to-records', or
   move config.json and secrets.json.enc aside to start a new vault.` (`init` on an existing record vault keeps today's
   behaviour.)
5. **Classic vaults are refused at store open**, for every command except `init` (which then refuses as above),
   `migrate` (all forms: the plain form is the touch-upgrade guide) and `export` (commands that never open the store are
   unaffected). The README and release notes say "only `migrate --to-records` and `export` work on a classic vault",
   matching the spec.
6. **Unknown metadata extensions are preserved.** The metadata section ends with a list of (type, bytes) extension
   entries; this build defines none, and keeps entries it doesn't know byte for byte on every rewrite (merge, burn,
   reindex), so tags (#221) added by a later build survive an older v0.2 machine.
7. **The fingerprint scanner ships in this stage** (`FingerprintIndex.Scan`, returning every confirmed hit, unresolved).
   Stages 2 and 3 run in parallel and both consume it; overlap resolution and output formatting are theirs.
8. **Downgrade/replay bookkeeping:** no new mechanism here (#197 covers rollback detection). This stage only reports
   such records as "not fingerprinted".
9. **`vault reindex` skips records already v3 with the current variant set** (nothing to change), and writes the marker
   only after every record succeeded, so "marker present" means the reindex finished once.
10. **`K_plan` is not derived in this stage**; its label `tswap-extract-plan-v1` is reserved for Stage 4.
11. **Two sections or fingerprint sets for one version stamp** are resolved the same way on every path:
   - **Same plaintext, different ciphertext** (ruling 1's concurrent conversion): keep the section whose bytes sort
     first (ordinal), so every machine converges on the same file without another write war. A full merge knows the
     plaintexts; the metadata-only path, which has none, treats two sections as the same plaintext when their
     fingerprint sets are equal at the same variant-set version (the plain variant's 128-bit HMAC covers the whole
     value) and applies the same choice.
   - **Different plaintext** (only damage or a clock rollback re-minting a stamp): a full merge keeps today's content
     tie-break (`RecordMerge.CompareContent`), and the version's section and fingerprints come only from an input whose
     plaintext for that version equals the winner's. The metadata-only path can't tell, so a same-stamp difference in
     fingerprints (or sections without fingerprints to compare) makes that record unreadable there (fail closed).
   - **Same plaintext but different fingerprint sets at the same variant-set version** (impossible without a bug, since
     fingerprints are a function of the value and `K_v`): `RecordConflictException : TswapException`.
   The store catches `RecordConflictException` **per record** and treats that record as unreadable (warned, never merged,
   never overwritten), as it does an undecryptable file. It never aborts the load.
12. **A record whose main file or any conflicted copy is format 2 counts as "not fingerprinted"** in the metadata-only
   load, without decrypting the v2 file (its version stamp is inside its payload, so the metadata path can't tell whether
   it is the newer version).

## Global constraints

- Every key derives from `K_v` by HKDF-SHA256 with its own label: metadata `tswap-record-meta-v3` (salt
  `recordId ‖ writeStamp`), value `tswap-record-value-v3` (salt `recordId ‖ versionStamp`), `K_fp` `tswap-fingerprint-v1`, `K_roll` `tswap-rollhash-v1` (no salt).
  Stamps serialise as today (`RecordKeyDerivation.Derive(…, Stamp)`: HLC ms 8 LE, logical 4 LE, origin 16).
- Associated data per section is only: magic, format version, record id, section role (`0x01` metadata, `0x02` value),
  and that section's own stamp (write stamp / version stamp); the metadata section also binds `valueSectionCount`.
  Nothing a later write changes in a value section. Decoding consumes the file exactly (no trailing bytes, every length
  prefix checked against what remains).
- Every file a sudo command writes (records, marker, `config.json`) goes through `DirectoryOwnerMatcher` like today's
  writes, so it keeps the vault owner and the tightened modes.
- Each section is AES-256-GCM, padded with zeros to a multiple of 256 bytes (`KeyringFormat.PaddingBucketSize`).
- Fingerprints never leave an encrypted metadata section or process memory: no logging, no `ToString` that prints
  them, no files.
- HMAC comparisons use `CryptographicOperations.FixedTimeEquals`; every match decision confirms on the HMAC.
- Key material and decrypted values are zeroed after use, as the existing codec and store do.
- NativeAOT and trim clean; the build stays warning-free.
- Fixed-binary, explicitly ordered layouts (see `KeyringFormat`'s doc comment for why not JSON).

## Review focus

1. **An empty secret value** (`create`/`ingest` of ""): its version has a fingerprint set with zero entries, and counts
   as fingerprinted. Test in Task 6.
2. **Two machines reindex the same vault concurrently**: their value sections differ (random nonces), the sync
   conflict copy merges without error, and both machines end with the same section (ruling 11). Test in Task 5 (merge) and Task 7 (store-level, two `FleetMachine`s).
3. **A conflict copy that is v2 against a main file that is v3** (or the reverse): load merges them, the next write is
   v3 with fingerprints for every retained version. Test in Task 6.
4. **A value that is not valid UTF-8** (ingested binary): fingerprints are computed from the same decoded string
   `SecretProcessor` matches today, so redaction behaviour is unchanged. Test in Task 2.
5. **A metadata extension written by a newer build**: survives a burn and a merge written by this build. Test in Task 4
   (codec round trip) and Task 6 (store rewrite).
6. **The anti-goal itself**: no fingerprint material in the clear. Test in Task 6 (`RawFileBytes_HoldNoFingerprintMaterial`).

---

### Task 1: one variant list for matching and fingerprints

**Files:**
- Create: `TswapCore/Fingerprints/SecretVariants.cs`
- Modify: `TswapCore/SecretProcessor.cs:26-61` (`BuildMatchList` uses `SecretVariants`)
- Test: `TswapTests/SecretVariantsTests.cs`

**Interfaces:**
- Produces: `public enum VariantKind : byte { Plain = 0, WhitespaceStripped = 1, Base64 = 2, Base64Url = 3 }`;
  `public static class SecretVariants { public const byte CurrentSetVersion = 1; public static IReadOnlyList<(VariantKind Kind, string Text)> For(string value); }`
  (empty list for an empty value; same inclusion rules and order as `BuildMatchList` today).

- [ ] **Step 1: Write the failing tests** `SecretVariantsTests`:
  `For("abc")` → `[(Plain,"abc"), (Base64,"YWJj")]` (base64url equals base64, so absent);
  `For("a b\nc")` → contains `(WhitespaceStripped,"abc")`;
  `For("??>")` (base64 `Pz8+`) → contains `(Base64Url,"Pz8-")`;
  `For("")` → empty;
  `For(" \n\t")` (all whitespace) → `[(Plain," \n\t"), (Base64,…)]` with no whitespace-stripped entry (it would be empty);
  a property test: for 200 random strings (including `"\uD800"` and multi-line values), the `(MatchType, SearchText)`
  pairs `BuildMatchList` yields for one secret equal the mapping of `SecretVariants.For` (Plain and WhitespaceStripped →
  `MatchType.Plaintext`).
- [ ] **Step 2:** run `./runtests.sh --unit` filtered to `SecretVariantsTests`; expect a compile failure.
- [ ] **Step 3:** implement `SecretVariants.For`; make `BuildMatchList` build its entries from it (sorting unchanged).
- [ ] **Step 4:** run the filtered tests and `RedactTests`, `PreviousValueScanTests`: all pass.
- [ ] **Step 5:** commit (`T16-S1 task 1: one variant list for redaction and fingerprints`). Break-it-once: drop the
  whitespace-stripped variant from `SecretVariants`; the property test must fail.

### Task 2: fingerprint primitives and the scanner

**Files:**
- Create: `TswapCore/Fingerprints/FingerprintKeys.cs`, `RollingHash.cs`, `FingerprintSet.cs`, `Fingerprinter.cs`,
  `FingerprintIndex.cs`
- Modify: `TswapCore/Keyring/RecordKeyDerivation.cs` (the two labels)
- Test: `TswapTests/FingerprintTests.cs`, `TswapTests/FingerprintIndexTests.cs`

**Interfaces:**
- Consumes: `SecretVariants.For`, `VariantKind` (Task 1).
- Produces:
  - `public sealed class FingerprintKeys : IDisposable { public static FingerprintKeys Derive(byte[] vaultKey); }`
    (holds `K_fp` 32 bytes and the rolling-hash base; zeroes both on dispose).
  - `public sealed record FingerprintEntry(VariantKind Kind, int Length, ulong RollingHash, byte[] Hmac)` (Hmac 16 bytes;
    value equality over all four fields; `ToString` prints the kind only).
  - `public sealed record FingerprintSet(byte VariantSetVersion, IReadOnlyList<FingerprintEntry> Entries)` (value
    equality, entries in `SecretVariants.For` order).
  - `public static class Fingerprinter { public static FingerprintSet Compute(byte[] valueBytes, FingerprintKeys keys); }`
    — the value is decoded with `Encoding.UTF8.GetString` (as `RecordVaultStore.ToSecret` does) before `SecretVariants.For`.
  - `public sealed record FingerprintHit(string Name, bool IsPrevious, VariantKind Kind, int Start, int Length);`
  - `public sealed class FingerprintIndex { public static FingerprintIndex Build(IEnumerable<(string Name, bool IsPrevious, FingerprintSet Set)> sets, FingerprintKeys keys); public IReadOnlyList<FingerprintHit> Scan(ReadOnlySpan<char> text); public int MaxLength { get; } }`
    — `Scan` returns every confirmed hit, ordered by `Start`, then `Length` descending, then `Name` ordinal. This is a
    reporting order, not today's replacement order (longest first, then search text, then live before burned); Stage 2
    resolves overlaps and pins that behaviour.

Definitions (exact):
- `Length` = UTF-16 code units of the variant text.
- `Hmac` = first 16 bytes of `HMAC-SHA256(K_fp, Encoding.UTF8.GetBytes(variantText))`.
- `p = 2^61 − 1`; base `b = 2 + (u64_le(HKDF(K_v, 8, info = "tswap-rollhash-v1")) mod (p − 3))`, i.e. in [2, p−2].
  `RollingHash(s) = (Σ_{i=0}^{L−1} s[i]·b^{L−1−i}) mod p` over UTF-16 code units (`UInt128` products, then reduce).
- `Scan`: for each distinct stored length `L`, slide a window, update the hash in O(1) per character, look up
  `(L, hash)`; on a hit compute the window's HMAC and compare with every entry under that key (fixed time). A rolling-hash
  match without an HMAC match is never a hit.

- [ ] **Step 1: Write the failing tests:**
  - `Keys_AreDistinctFromEachOtherAndFromRecordKeys` (K_fp ≠ names key ≠ record key for one K_v).
  - `Compute_IsDeterministicPerVaultKey_AndDiffersAcrossVaultKeys`.
  - `Compute_EmptyValue_HasZeroEntries` (`VariantSetVersion == 1`, `Entries` empty).
  - `Compute_InvalidUtf8Value_UsesTheDecodedString`: bytes `{0x66, 0xFF, 0x6F}` give the same set as the string
    `"f�o"`.
  - `RollingHash_SlidingUpdate_EqualsDirectHash` (random text, every window of length 1..40).
  - `Scan_FindsEachVariantKind` (plain, whitespace-stripped, base64, base64url of one value inside surrounding text, with
    the right `Start`/`Length`/`Kind`).
  - `Scan_PreviousValue_IsFlagged` (`IsPrevious == true`).
  - `Scan_RollingCollisionWithoutHmacMatch_IsNoHit`: build an index whose entry has a correct `RollingHash` and `Length`
    but a wrong `Hmac`; scanning the value yields nothing.
  - `Scan_OverlappingSecrets_ReturnsAllHits` (`"abcdef"` and `"cde"` both found).
  - `Scan_PemSizedSecret` (a 4,200-character value is found; `MaxLength` ≥ 4200 after its base64 variant).
- [ ] **Step 2:** run them; expect compile failures.
- [ ] **Step 3:** implement the five types to the definitions above.
- [ ] **Step 4:** run them; all pass.
- [ ] **Step 5:** commit (`T16-S1 task 2: keyed fingerprints and the scanner`). Break-it-once: make `Scan` accept a
  rolling-hash match without checking the HMAC; `Scan_RollingCollisionWithoutHmacMatch_IsNoHit` must fail.

### Task 3: prove an older build never clobbers a newer-format record (before the codec changes)

The spec asks this "with tests against the v0.1.x code path". Today's code **is** that path (main = v0.1.0 + .NET 10
refactor; the format code is unchanged since v0.1.0), so write the test first, on the unchanged codec.

**Files:**
- Test: `TswapTests/NewerFormatRecordTests.cs`

- [ ] **Step 1: Write the test** with a planted record file: valid magic, format byte `KeyringFormat.RecordFormatVersion + 1`
  (written as that expression, so it stays "one newer" after Task 4), a plausible header and random payload, under a
  record file name. Then, through the CLI in test mode on that vault: `create other`, `burn other`, `delete other`
  (sudo bypass), `vault merge` from a second folder that holds a newer write of the same record id, `rotate`, `import`
  of an export, and a `migrate --to-records` refusal path. After each, assert the planted file's bytes are unchanged and
  it still exists, and that commands needing it (`get` of its name is impossible: assert instead that `LoadSecrets`
  reports it in `UnreadableFiles`) fail closed.
  Run the same test once more with the format byte as the literal `3` (a second `[InlineData]`, kept only in this
  commit's version of the test; after Task 4 the literal case is removed, since 3 becomes readable). The commit message
  records both outcomes: this commit is the evidence for the release-notes claim about v0.1.x machines.
- [ ] **Step 2:** run it on the unchanged code.
  - **Passes:** commit (`T16-S1 task 3: an older build never deletes or overwrites a newer-format record`). The release
    notes (Task 9) say "older machines refuse reindexed records until upgraded" (no hard requirement).
  - **Fails:** STOP and report to the controller with the failing path. Do not fix v0.1.x behaviour here; the release
    notes must then say "upgrade every machine before `vault reindex`" as a hard requirement, and the owner decides.
- [ ] **Step 3:** break-it-once: make `SaveSecrets` treat an unreadable record as absent; the test must fail. Revert.

### Task 4: the v3 codec

**Files:**
- Modify: `TswapCore/Keyring/KeyringFormat.cs` (`RecordFormatVersion = 3`, new `RecordFormatVersionV2 = 2`),
  `TswapCore/Keyring/SecretRecord.cs`, `TswapCore/Keyring/SecretRecordCodec.cs`,
  `TswapCore/Keyring/RecordKeyDerivation.cs`
- Create: `TswapCore/Keyring/RecordMetadata.cs`
- Test: `TswapTests/SecretRecordCodecV3Tests.cs` (existing `SecretRecordCodecTests` keep passing for v2)

**Interfaces:**
- Consumes: `FingerprintSet` (Task 2).
- Produces:
  - `SecretRecord` gains `FingerprintSet? Fingerprints = null` (of `Version`'s value),
    `IReadOnlyList<RecordExtension> Extensions` (default empty), and `IReadOnlyDictionary<Stamp, byte[]>? Sealed = null`
    (value-section bytes by version stamp, as read; not part of `SameState`). `PreviousValue` gains
    `FingerprintSet? Fingerprints = null`. `SameState` also compares `Fingerprints`, `Previous.Fingerprints` and
    `Extensions`.
  - `public sealed record RecordExtension(ushort Type, byte[] Data)` (value equality).
  - `public sealed record RecordMetadata(byte[] RecordId, Stamp Write, RecordType Type, Stamp Version, string Name, long CreatedMs, IReadOnlyList<BurnEntry> Burns, FingerprintSet? Fingerprints, Stamp? PreviousVersion, FingerprintSet? PreviousFingerprints, IReadOnlyList<RecordExtension> Extensions)`.
  - `SecretRecordCodec.Encode(SecretRecord record, byte[] vaultKey, byte formatVersion)` — `formatVersion` 2 writes
    today's layout (fingerprints, extensions and `Sealed` dropped); 3 writes v3: for each retained version, a value
    section from `record.Sealed[version]` copied byte for byte when present, otherwise encrypted from the plaintext with
    a fresh random nonce (ruling 1). The existing `Encode(record, key)` overload writes `RecordFormatVersion`.
  - `SecretRecordCodec.Decode(bytes, key)` reads v2 and v3 (v3 fills `Sealed` with the value-section bytes);
    `SecretRecordCodec.DecodeMetadata(byte[] bytes, byte[] vaultKey) → RecordMetadata?` decrypts **only** the metadata
    section of a v3 record and returns null for a v2 record **without decrypting anything**;
    `SecretRecordCodec.OpenValue(byte[] bytes, byte[] vaultKey, Stamp version) → byte[]` decrypts one value section.
    `Encode` throws `ArgumentException` when `Sealed` holds a stamp that isn't a retained version, or when a fingerprint
    set has more than 255 entries (`entryCount` is one byte).
  - `SecretRecordCodec.PeekHeader` and `FormatVersionOf(byte[] bytes) → byte?` work for both versions.
  - `RecordKeyDerivation.DeriveMetadataKey(vaultKey, recordId, Stamp write)`,
    `DeriveValueKey(vaultKey, recordId, Stamp version)`.

v3 layout (pinned so reviewers can check AAD and nonce use; field encodings follow v2's):
```
magic "TSR1" | formatVersion 3 | recordId 32 | writeStamp 28 | valueSectionCount 1
metadataLength 4 | metadata: nonce 12 | tag 16 | ciphertext (padded to 256)
per value section, in the metadata's version order: length 4 | nonce 12 | tag 16 | ciphertext (padded to 256)
metadata plaintext: recordType 1 | versionStamp 28 | createdMs 8 | nameLength 2 + name
  | versionCount 1 (0 tombstone, 1 current, 2 current + previous), per version: stamp 28 | role 1 (0 current, 1 previous)
    | hasFingerprints 1, then variantSetVersion 1 | entryCount 1 | per entry: kind 1 | length 4 | rollingHash 8 | hmac 16
  | burns (as v2) | extensionCount 2, per extension: type 2 | length 4 | data | zero padding
value plaintext: valueLength 4 | value | zero padding
AAD (metadata) = magic | 3 | recordId | 0x01 | writeStamp | valueSectionCount
AAD (value)    = magic | 3 | recordId | 0x02 | versionStamp
```
(The length prefixes need no AAD: a wrong slice fails its section's tag, and decoding must consume the file exactly.
Say so in the layout comment so nobody "optimises" the consistency checks away.)
Strict decoding as v2's (lengths, padding all zero, record id = `HMAC(K_names, name)`), plus: `valueSectionCount` must
equal the metadata's version count; a tombstone has none; a version listed without a section, or a section without a
version, is a `TswapException` (fail closed); duplicate stamps in the version list are refused.

- [ ] **Step 1: Write the failing tests** in `SecretRecordCodecV3Tests`:
  - `RoundTrip_ValueBurnedTombstone_WithAndWithoutPrevious` (all fields, fingerprints and extensions survive).
  - `DecodeMetadata_DecryptsNoValueSection`: corrupt one byte inside each value section's ciphertext; `DecodeMetadata`
    still succeeds, `Decode` throws `CryptographicException`.
  - `DecodeMetadata_V2Record_ReturnsNullWithoutDecrypting`: a v2 record whose payload is garbage (bad tag) gives null,
    not an exception.
  - `ValueSection_CopiedBytes_AuthenticateUnderANewWriteStamp`: encode, change `Write`, re-encode with `Sealed` from the
    decode; the value-section bytes are identical and the record decodes.
  - `ValueSection_FreshEncodes_UseDifferentNonces` (two encodes of one new version differ; both decrypt).
  - `ValueSection_SwappedBetweenVersions_FailsAuthentication` (current and previous sections exchanged).
  - `ValueSection_FromAnotherRecord_FailsAuthentication`.
  - `MetadataListsVersionWithoutSection_FailsClosed` and `SectionWithoutVersion_FailsClosed` (hand-built bytes with a
    valid metadata section).
  - `UnknownExtension_SurvivesDecodeEncode`.
  - `V2Records_StillDecode_AndEncodeAsV2WhenAsked` (existing fixtures).
  - `NewerFormatVersion_IsRefusedWithUpgradeMessage` (format byte 4).
  - `PadsEachSectionTo256` (ciphertext lengths for a 1-byte, a 300-byte and a 4,200-byte value).
  - Strictness: `TruncatedFile_FailsClosed`, `AppendedBytes_FailClosed`, `TamperedValueSectionCount_FailsClosed`,
    `MetadataSectionInAValueSlot_FailsAuthentication`, `NonZeroPaddingInASection_FailsClosed`,
    `DuplicateVersionStamps_AreRefused`, `Encode_SealedForAnUnretainedVersion_Throws`,
    `Encode_MoreThan255FingerprintEntries_Throws`.
  - `BinaryValue_RoundTripsByteForByte` (value bytes `{0x00, 0xFF, 0xFE, 0x80}`).
  - `DerivedKeys_AreDistinct` (metadata and value keys for one record and stamp differ).
- [ ] **Step 2:** run them; expect failures.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run `SecretRecordCodecV3Tests`, `SecretRecordCodecTests`, `RecordKeyDerivationTests`: all pass.
- [ ] **Step 5:** commit (`T16-S1 task 4: record format v3`). Break-it-once: include the write stamp in a value
  section's AAD; `ValueSection_CopiedBytes_AuthenticateUnderANewWriteStamp` must fail.

### Task 5: merge carries fingerprints and sealed sections

**Files:**
- Modify: `TswapCore/Keyring/RecordMerge.cs`
- Test: `TswapTests/RecordMergeV3Tests.cs`

**Interfaces:**
- Consumes: Task 4's `SecretRecord` fields.
- Produces: `public sealed class RecordConflictException : TswapException` and `RecordMerge.Merge` / `Normalize` with
  ruling 11's rules: the winner is chosen as today (version stamp, then `CompareContent`) and keeps its versions; for
  each retained version, only inputs whose plaintext for that version equals the winner's contribute; among them, the
  fingerprint set with the higher `VariantSetVersion` (a null set merges with anything; equal versions with different
  entries throw `RecordConflictException`, message naming the record file, never value bytes), and the section whose
  bytes sort first; sections are restricted to the winner's retained versions; `Extensions` are the winner's, plus
  entries of the other input whose `Type` the winner lacks (sorted by type). Merge stays commutative, associative and
  idempotent on every input that doesn't throw.

- [ ] **Step 1: Write the failing tests:** `Merge_KeepsFingerprintsOfTheRetainedVersions`,
  `Merge_PrefersTheNewerVariantSet`, `Merge_UnionsSealedSections_DropsUnretained`,
  `Merge_EqualPlaintextDifferentSections_KeepsTheOrdinallySmaller` (in both argument orders),
  `Merge_EqualVariantSetDifferentEntries_ThrowsRecordConflict`,
  `Merge_SameStampDifferentValues_KeepsTodaysTieBreak_AndTheWinnersSections` (the damage case: no throw, the content
  winner's section and fingerprints survive, the loser's are dropped),
  `Merge_ConcurrentConversion_ConvergesOnOneSection` (encode the same v2 record as v3 on two "machines" with different
  write stamps: different sections; decode both; merge either way keeps the same one), and a property test over random
  pairs/triples, including same-stamp inputs, for commutativity, associativity and idempotence (inputs that throw must
  throw in every order).
- [ ] **Step 2:** run them; expect failures.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run them plus `RecordMergeTests`, `RecordConflictTests`: all pass.
- [ ] **Step 5:** commit (`T16-S1 task 5: merge rules for fingerprints and value sections`). Break-it-once: keep the
  first input's section on a mismatch; `Merge_EqualPlaintextDifferentSections_KeepsTheOrdinallySmaller` must fail.

### Task 6: the store writes v3, preserves sections, and offers a metadata-only load

**Files:**
- Modify: `TswapCore/RecordVaultStore.cs`
- Create: `TswapCore/VaultMetadata.cs`
- Test: `TswapTests/RecordStoreV3Tests.cs`, `TswapTests/RecordStoreMetadataTests.cs`

**Interfaces:**
- Consumes: Tasks 2, 4, 5.
- Produces:
  - `public const string RecordFormatMarkerFileName = "record-format";` and `public bool WritesV3 { get; }` (ruling 3,
    evaluated after a load).
  - Every write (`SaveSecrets`, `MergeRecords`, `WriteSnapshot`) encodes with the chosen format. In v3: a new value
    version gets `Fingerprinter.Compute` of its plaintext and a freshly sealed section; a version that already has a
    sealed section and fingerprints is copied; a version from a v2 record (plaintext known from the load) is sealed and
    fingerprinted now.
  - `public VaultMetadata LoadMetadata(byte[] vaultKey, TextWriter? warnings = null)` with
    `public sealed record VaultMetadata(IReadOnlyList<RecordMetadata> Records, int NotFingerprinted, int OlderVariantSet, IReadOnlyList<string> Unreadable)`:
    decrypts metadata sections only; a v2 record is counted in `NotFingerprinted` without being decrypted; a v3 record
    with a retained version lacking fingerprints is counted there too; `OlderVariantSet` counts records whose sets are
    below `SecretVariants.CurrentSetVersion`; tombstones are listed but never counted as missing. Conflict copies fold in
    by the same merge rules on metadata (winner by version stamp, burns by `CanonicalBurns`, fingerprints and extensions
    as Task 5); same-stamp sections and fingerprints resolve by ruling 11 (equal fingerprints: the
    ordinally smaller section; different fingerprints, or none to compare: that record unreadable here), and a record whose main file **or any conflicted copy** is v2 is counted in `NotFingerprinted` without
    decrypting the v2 file (ruling 12). `VaultMetadata.IsFullyFingerprinted` (a property:
    `NotFingerprinted == 0 && Unreadable.Count == 0`) is the one definition Stages 2 and 3 use.
  - Full loads (`LoadSecrets`, `LoadRecordStates`, `ReadSecretValue`) catch `RecordConflictException` per record and
    treat that record as unreadable (ruling 11).
  - `internal Action<string, Stamp>? ValueDecrypted { get; set; }` — test seam, called for every value section
    decrypted (`RecordDecrypted` keeps its meaning: a record's metadata/payload decrypted).
  - `ReadSecretValue(string name, byte[] key, bool previous = false)` decrypts the metadata section and the one value
    section asked for (the current value, or the previous value for a `name:previous` token in Stages 3 and 4); null
    when that version doesn't exist.

- [ ] **Step 1: Write the failing tests:**
  - `NoMarker_WritesV2` and `Marker_WritesV3WithFingerprints` (inspect `FormatVersionOf` of the files written by
    `create`).
  - `AnyV3RecordRead_WritesV3EvenWithoutMarker` (ruling 3).
  - `MarkerNewerVersion_RefusesWrites` (`"4"` → `TswapException` naming "newer tswap"; nothing written),
    `MarkerWithCrlfOrBom_IsV3` (`"﻿3\r\n"`), `MarkerEmptyOrGarbage_WarnsAndCountsAsAbsent`.
  - `Burn_CopiesValueSectionsByteForByte` (the named invariant: value-section bytes identical before and after `burn`,
    and after a `vault merge` that changes only burns).
  - `Rotate_KeepsPreviousSectionBytes_AddsNewSection`.
  - `EmptyValue_IsFingerprintedWithZeroEntries` (review focus 1).
  - `V2CopyAgainstV3Main_MergesAndNextWriteIsV3` (review focus 3, both directions).
  - `NewerExtension_SurvivesBurnAndMerge` (review focus 5: plant a record with extension type 0x7777 via the codec).
  - `LoadMetadata_DecryptsNoValueSection`: a vault with 20 v3 secrets (with previous values); `ValueDecrypted` is never
    called; names, burns and fingerprints match a full load.
  - `LoadMetadata_CountsV2AndMissingFingerprints_WithoutDecryptingV2` (`RecordDecrypted` not called for the v2 file).
  - `LoadMetadata_FoldsConflictCopies_LikeTheFullLoad` (property test over random histories, whose generator also
    produces v2 conflicted copies and same-stamp damage: for records without either, names, types, burns and
    fingerprints equal those of the full load; a record with a v2 copy is in `NotFingerprinted`; a same-stamp
    difference is in `Unreadable`).
  - `LoadMetadata_V2ConflictCopyOfAV3Record_IsNotFingerprinted_WithoutDecryptingIt` (ruling 12).
  - `FullLoad_RecordConflict_MarksOnlyThatRecordUnreadable` (a damaged conflicted copy with equal plaintext and a
    different fingerprint set at the same variant-set version: the load succeeds, other secrets work, that record is
    unreadable and its files are untouched).
  - `LoadMetadata_ConcurrentConversionCopies_PickTheSameSectionAsTheFullLoad`.
  - `ReadSecretValue_DecryptsOnlyTheRequestedValueSection` (current, and `previous: true`).
  - `RawFileBytes_HoldNoFingerprintMaterial` (review focus 6): for a known value with all four variants, the record
    file's bytes contain none of the variant texts, none of the 16-byte HMACs and none of the 8-byte rolling hashes
    (little- and big-endian), and no 32-byte window equal to the metadata plaintext's fingerprint block.
- [ ] **Step 2:** run them; expect failures.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run them plus every `RecordStore*`, `RecordConflict*`, `StaleWriteGuard*`, `Broker*` and
  `MigrateToRecordsTests`: all pass.
- [ ] **Step 5:** commit (`T16-S1 task 6: the store writes v3 and loads metadata without decrypting values`).
  Break-it-once: re-encrypt copied sections on every write; `Burn_CopiesValueSectionsByteForByte` must fail.

### Task 7: `sudo tswap vault reindex`

**Files:**
- Modify: `TswapCli/Commands/VaultCommand.cs` (subcommand, help text), `TswapCore/RecordVaultStore.cs`
  (`public ReindexResult Reindex(byte[] vaultKey)`)
- Test: `TswapTests/VaultReindexTests.cs`

**Interfaces:**
- Produces: `public sealed record ReindexResult(int Rewritten, int AlreadyCurrent, int Tombstones);` and the command
  `vault reindex` (sudo; refuses without it with the platform-neutral "requires" message).

Behaviour: unlock; load every record (full decode); for each live record that is v2, lacks a fingerprint set, or has an
older variant set, write it as v3 with a new write stamp (stale-write guard applies; sealed sections copied where they
exist); tombstones are rewritten as v3 metadata-only records too; skip records already current (ruling 9); refuse
before writing anything if any record is unreadable (name the files; the user restores or deletes them first); write
the marker last. Prints counts only (no names, no values). Idempotent: a second run rewrites nothing.

- [ ] **Step 1: Write the failing tests:** `Reindex_RequiresSudo`, `Reindex_ConvertsEveryRecord_WritesMarkerLast`
  (crash seam after the third record: no marker, a re-run finishes, then the marker exists),
  `Reindex_SecondRun_RewritesNothing`, `Reindex_UnreadableRecord_RefusesBeforeWriting`,
  `Reindex_OutputHasNoNamesOrValues` (stdout and stderr contain none of the secret names or values),
  `Reindex_ConcurrentOnTwoMachines_ConvergesCleanly` (review focus 2: two `FleetMachine`s on copies of one vault both
  reindex; `vault merge` of one copy into the other succeeds, and after one more write on each machine both folders hold byte-identical value sections), and
  `Reindex_ThenOlderFormatWrite_IsReportedNotFingerprinted` (plant a v2 write of one record after the reindex;
  `LoadMetadata.NotFingerprinted == 1`), `Reindex_EmptyVault_WritesMarkerOnly`,
  `Reindex_UnderSudo_KeepsTheVaultOwnerAndModes` (with the fake `IUnixOwnership` seam `FileOwnershipTests` uses: every
  rewritten record, the marker and `config.json` are chowned to the vault folder's owner, records and marker 0600),
  `VaultMerge_CopiesTheMarker_InBothDirections` (a reindexed folder merged into an unreindexed one gives it the marker;
  the reverse leaves the marker in place).
- [ ] **Step 2:** run them; expect failures.
- [ ] **Step 3:** implement. `vault merge` also copies the other folder's marker when it has one (so merging a
  reindexed copy keeps v3).
- [ ] **Step 4:** run them plus `VaultMerge*` tests: all pass.
- [ ] **Step 5:** commit (`T16-S1 task 7: sudo tswap vault reindex`). Break-it-once: write the marker first; the crash
  test must fail.

### Task 8: record vaults by default; classic vaults migration-only

**Files:**
- Modify: `TswapCli/Commands/InitCommand.cs`, `TswapCli/CliHost.cs` (store opening), `TswapCli/ICliCommand.cs`
  (`bool WorksOnClassicVault => false;`), `TswapCli/Commands/MigrateCommand.cs`, `TswapCli/Commands/ExportCommand.cs`,
  `TswapCli/RecordMigration.cs` (marker + v3 for the new folder), test harnesses that inject `new Storage(dir)` (use
  `VaultStores.Open(dir)` per invocation, like the binary)
- Test: `TswapTests/ClassicVaultRefusalTests.cs`, `TswapTests/InitRecordVaultTests.cs`; existing tests converted

**Interfaces:**
- Produces: `ICliCommand.WorksOnClassicVault` (true only for `init`, `migrate`, `export`); the refusal message
  (exact text):
  `This is a classic single-file vault (secrets.json.enc), which tswap 0.2 only migrates. Run 'sudo tswap migrate --to-records' to convert it (or 'sudo tswap export <file>' to take your secrets out).`
  with `tswap` replaced by `ctx.Prefix`.

- [ ] **Step 1: Write the failing tests:**
  - `ClassicVault_EveryOtherCommandRefuses` (theory over every registered command with `NeedsVault` true except the
    three: exit 1, the exact message on stderr, the vault files unchanged).
  - `ClassicVault_MigrateAndExportStillWork` (`migrate --to-records` converts; `export` writes a file that `import` into
    a new record vault reads back).
  - `Init_Plain_MakesARecordVault_WithMarker` (`config.json` `Store == "records"`, `VaultDir == <config dir>/vault`,
    keyring has one YubiKey slot and a recovery slot, `record-format` contains `3`, a `create` writes a v3 record).
  - `Init_Folder_CreatesTheVaultThere` and `Init_Folder_RefusesANonEmptyFolder`.
  - `Init_KeyringFlag_IsAcceptedAsNoOp`.
  - `Init_OnAClassicVault_Refuses` (ruling 4's exact message; `config.json` and `secrets.json.enc` unchanged).
  - `Init_Folder_WindowsAndUnixPaths` (relative and absolute paths resolve to the same full path in `VaultDir`).
  - `MigrateToRecords_WritesMarkerAndV3`.
- [ ] **Step 2:** run them; expect failures.
- [ ] **Step 3:** implement, then convert existing tests: a test of a command's behaviour on a classic vault moves to a
  record vault when the behaviour still exists; a test that only asserted classic behaviour of a now-refused command is
  replaced by the refusal theory. List every converted or removed test in the commit message with the reason "brief T16-S1
  ruling 4/5 changed the rule" (AGENTS.md: inputs may change when the brief changes the rules; assertions about
  behaviour that still exists may not be weakened). Classic-store unit tests of `Storage` itself stay (migration and
  export still read it).
- [ ] **Step 4:** `./runtests.sh` (unit + E2E): all pass.
- [ ] **Step 5:** commit (`T16-S1 task 8: record vaults by default; classic vaults migration-only`). Break-it-once:
  set `WorksOnClassicVault` true for `names`; the refusal theory must fail.

### Task 9: docs, version and release notes

**Files:**
- Modify: `TswapCli/TswapCli.csproj` (`<Version>0.2.0</Version>`), `README.md` (init, vault folder, `vault reindex`,
  classic deprecation, the threat-model lines on fingerprints), `MULTI_MACHINE_KEYING.md` (metadata section: the v3 leak
  delta from the spec's threat model, the marker and what deleting or planting it can do (only degrade to a fail-closed
  refusal), ruling 1 (encrypted once, then copied; why two machines may each convert a version, and how ruling 11 converges them),
  ruling 11), `AGENTS.md` (sudo list: `vault reindex`; project
  overview no longer says "two YubiKeys enrolled once" as the default), `TswapCore/Prompt.cs` only if its text names
  `init` behaviour (then `prompt-hash` tests update)
- Create: `docs/release-notes/v0.2.0.md` (leads with `sudo tswap migrate --to-records`, then `vault reindex`, the
  mixed-fleet rule from Task 3's outcome, and what changed for `init`)

- [ ] **Step 1:** update the files; `HelpTests` and `PromptTests` adjust only where the text changed (say so in the
  commit message).
- [ ] **Step 2:** `./runtests.sh --unit`: all pass.
- [ ] **Step 3:** commit (`T16-S1 task 9: docs and v0.2.0`).

### Finish

- [ ] Full `./runtests.sh` from a clean build; record the summary lines in the report.
- [ ] Push `brief/t16-s1`, open a PR (CI on all three OS must be green), and request the external code review (GLM and
  MiMo) **plus the dedicated security review of the format and key derivations** the spec requires. Tag and release
  only on the owner's go.

## Out of scope

- Switching `redact`, `tocomment` or `run` to fingerprints (Stages 2 and 3), `extract` (Stage 4), tags (#221), key
  rotation (#126), rollback detection (#197), a longer value history than one previous version.
