# Brief T60: a merge keeps the value it discards, warns, and lets a person use, restore or drop it (#312)

Issue: https://github.com/stevedcc/TokenSwap/issues/312. Milestone 0.3.3. Design:
`docs/superpowers/specs/2026-11-27-merge-discards-and-rollback-design.md` on branch `design/records-033` at **6262c2f**
(rounds 1-10; Part 1, §1.4a, Tests "T60", "Briefs", owner Decisions). The design's body is authoritative; its amendment
history only records why. This brief is Part 1 of that design; Part 2 (#197, the floors) is brief T61, which runs after
this one. A later design amendment is diffed against 6262c2f.

**Design rounds 8-9 (2f1ed12), folded into the body below:** the silence rule (an OR of three) and R12 without its
"also the previous value" form; silent entries listed but never counted as open; R13 (position); R8 for any input,
with writes that would update a newer-format lineage refused; no kind byte (R3 moot); earlier-life entries (R14);
`field adopt` refuses a SECRET holding entries; every write carries `T` and `forgotten`; tied winners as a set (R15);
`burn` exempt from the entry cap.

**Design round 10 (6262c2f), folded below:** the upgrade step, numbered, in the docs and the release-note lines; the
caps' lifetime arithmetic in the docs; the `--clear` text and docs say a machine still holding the value as its current
value loses it too (confirmed by the owner on 2026-11-27, design Decisions 4); a bare Base32 seed handed out as text, the v0.3.0
earlier-life leak, the export warning naming the lineage, `S` alone and format 2, the `names` metadata cost; the v0.3.2
release check kept.

**Base.** This brief builds on T58 (TOTP, PR #433, branch `brief/t58` at a0836c2): its record extension `0x0101`
(`ValueKinds`), `CommandValues` and its token grammar. **The base is `origin/main` once T58 has merged** (today main is
dcc4c04, which `brief/t58` contains). Line numbers below are at `brief/t58` a0836c2; for files T58 doesn't touch they
are the same at dcc4c04 (`RecordMerge.cs`, `SecretRecordCodec.cs`, `SecretRecord.cs`, `SecretEntry.cs`,
`PendingWrite.cs`, `VaultView.cs`, `Hlc.cs`, `FingerprintIndex.cs`). If the merged T58 differs from a0836c2 in a place
this brief names, stop and report.

Read AGENTS.md and CLAUDE.md first ("The record store", "Privilege Boundary", "Token Substitution"). Then:
- the design's Part 1 (§1.1-§1.10) and §1.4a in full; its Tests section, "T60 (#312)";
- `TswapCore/Keyring/RecordMerge.cs` (all), `RecordWrites.cs` (all), `RecordMetadata.cs`, `SecretRecord.cs`;
  `SecretRecordCodec.cs:55-92` (the format 3 layout), `:593-651` (`SealValue`, `OpenSealed`), `:808-908` (`ParseMetadata`),
  `:1008-1021` (`WriteStamp`, `ReadStamp`);
- `TswapCore/RecordVaultStore.cs`: `OpenSecret` (`:586-654`), `OpenFromMetadata` (`:731-810`), `CommitWrites`
  (`:828-917`), `CarriesEdits` (`:923`), `WithMissingSets` (`:965-1003`), `OpenValueSection` (`:1053-1080`), `ToSecret`
  (`:1105-1125`), `CopyNote` (`:1198-1201`), `FoldConflictCopies` (`:1217-1269`), `Reindex`/`IsCurrent` (`:1401-1455`),
  `NextRecord` (`:1533-1584`), `Tombstone` (`:1606-1610`), `WriteSnapshot` (`:1618`), `LoadMetadata` (`:1675-1820`),
  `MergeRecords` (`:1903`), `WriteAll` (`:1989-2054`), `PrepareV3` (`:2064-2094`);
- `TswapCore/SecretEntry.cs`, `PendingWrite.cs`, `SecretInfo.cs`, `VaultView.cs`, `VaultWriter.cs`, `ISecretLookup.cs`,
  `Models.cs:236-336` (`SecretsDb`), `Validation.cs:1-60` and `:160-180`, `Apply.cs:1-110`, `Check.cs:150-175`,
  `SecretMatcher.cs:280-420`, `Fingerprints/FingerprintIndex.cs:40-75`, `Totp/CommandValues.cs`, `Totp/ValueKinds.cs`;
- `TswapCli/CommandContext.cs:50-70` and `:349-367`, `Commands/FieldCommand.cs:240-320` (`field adopt`), `TswapCli/FingerprintStreamMatcher.cs:55-71`,
  `TswapCli/FieldWhoSource.cs`, `Commands/RunCommand.cs:140-200`, `NamesCommand.cs`, `RestoreCommand.cs`,
  `DeleteCommand.cs`, `ExportCommand.cs`, `CliJson.cs`, `CommandRegistry.cs`;
- the tests `RecordMergeTests`, `RecordMergeV3Tests`, `RecordWritesTests` (both parity tests, `:367`, `:525`),
  `RecordConflictTests` (the conflict copy names, `:120-123`), `VaultMergeTests`, `MetadataCommandTests`,
  `WriteCommandDecryptionTests`, `RunEnvTests`, `TswapTests/Totp/RunTotpTests.cs`, `FleetMachine.cs`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written.

**Existing assertions that change, and only these.**
- Task 5: T58's suffix-pinning assertions, `FieldTokenRefusalTests.MalformedMessage` and `.MarkerMessage`
  (`FieldTokenRefusalTests.cs:24`, `:135`), and `RunEnvTests`' `Exactly` (`RunEnvTests.cs:227`) with its `{{x:bogus}}`
  row (`:241`). Sanctioned by the design ("Briefs"): each pins the list of token suffixes, which gains `:discarded`.
- Tasks 2 and 3: the tests that pin a record's whole extension list after a value write, a delete, or a merge that
  now sets a value aside, because each such record now carries a `0x0103` extension (a value write makes the lineage
  exact, §1.4 rule 4 and §1.5; a merge of a lineage-less tombstone or first value with an older value keeps that value,
  §1.1's D2 fallback with an empty `S`). **Sanctioned by the owner on 2026-11-27** (the design doesn't
  name them). Merges (Task 2): `RecordMergeV3Tests.MergeAll_Tombstone_DropsFields_KeepsOtherExtensions` (`:406`) and
  `.MergeAll_RecreatedWithoutFields_ThenTwoStaleCopies_NoOldFields` (`:449`);
  `RecordStoreV3Tests.VaultMerge_V3TombstoneWithAnExtension_IntoAnUnmarkedFolder_KeepsItAndWritesV3` (`:388`). Writes (Task 3):
  `RecordWritesTests.Create_WithoutFields_WritesEmptyExtension`, `.Create_AfterDelete_NewSinceNoOldFields`,
  `.Extensions_SurviveEveryWrite` (its `NewVersion` and `Tombstone` lines, `:189`, `:191`; the `Burn` line `:190` stays),
  `.Tombstone_DropsFields_KeepsOtherExtensions` (`:260-261`); `RecordStoreV3Tests.AnyV3RecordRead_CreateWithoutFields_WritesAnchor`
  (`:116`); `MigrateToRecordsTests.Migrate_WritesFieldsAnchor_SinceIsVersion` (`:154`); and the golden fixture of
  `SaveSecretsGoldenTests.SaveSecrets_MatchesItsGolden` (`TswapTests/Fixtures/save-secrets-golden.json`). Each changes
  in one way only: the list it asserted is compared with the `0x0103` entry left out
  (`.Where(e => e.Type != ValueLineageCodec.Type)`), and one added assertion pins that entry's `AsOf` (writes) or its one discarded version (merges). The golden is
  regenerated, and the commit message says the diff adds only `0x0103` entries.
- Test-input change, Task 4: `RecordStoreSelectiveReadTests.LoadMetadata_WarnsLikeTheFullLoad` (`:231-261`) plants
  `newer-value` as a first value of the same name as `main-value`, which this brief makes a discarded value, so its
  `Note:` line would become the conflict warning. Plant the copy as a rotation of the main record instead (previous =
  `main-value` at `S(now - 5000)`); the assertions stay.

Any other existing assertion that fails: stop and report it (name, line, why). That includes the seeded generators of
`RecordMergeV3Tests.MergeAll_RandomCopies_OrderIndependentAndIdempotent` and
`RecordWritesTests.MergeAllMetadata_MatchesMergeAll_OrRefuses_OnRandomCopySets`: they may now draw two copies holding
one losing stamp under different sections without sets, which Task 2 makes a conflict. Don't change their seeds.

These stay unchanged, and the brief is written so they do: `MetadataCommandTests.Names_DecryptsNoValue` and
`Burned_DecryptsNoValue`, `WriteCommandDecryptionTests.Rotate_DecryptsOnlyTheCurrentValue` (`:401`),
`PromptTests.Prompt_RunBullet_SaysScriptBlock`, `SecretValueOutputTests`, `RecordWritesTests.RecordWrites_MatchNextRecord_OnRandomStates`
(`:367`, no input change: Task 3 adds its own parity test).

Tests never read the real clock (`FleetMachine.Time`, fixed `TimeProvider`s), never sleep, and use inert marker values.
No test, message or log prints a value, seed or URI. `SpellingTests` scans `.cs` files too.

**File ownership** (design "Briefs"; T61 follows on the same files, so keep to this list). New:
`TswapCore/Keyring/ValueLineage.cs`, `TswapCore/Keyring/ConflictDisplay.cs`, `TswapCli/Commands/ConflictsCommand.cs`,
`TswapCli/ConflictWarnings.cs`, the new test classes. Edited: `RecordMerge.cs`, `RecordWrites.cs`, `SecretRecord.cs`
(one property), `SecretRecordCodec.cs` (two helpers extracted, Task 1), `RecordVaultStore.cs`, `SecretEntry.cs`,
`PendingWrite.cs`, `VaultWriter.cs`, `VaultView.cs`, `SecretInfo.cs`, `Models.cs` (`Secret`, `SecretsDb`), `ISecretLookup.cs`
(its contract comment, Task 5), `Validation.cs`, `Apply.cs`, `Check.cs`, `ToCommentProcessor.cs`, `SecretMatcher.cs`, `Totp/CommandValues.cs`,
`Fields/FieldSet.cs` (registry comment), `Prompt.cs`; in `TswapCli`: `CommandContext.cs`, `FieldWhoSource.cs` (make
`ValidateBy` internal), `FingerprintStreamMatcher.cs`, `CliJson.cs`, `CommandRegistry.cs`, `Commands/FieldCommand.cs`
(the adopt refusal, Task 5), and the commands that warn (Task 4) or change (Task 5); docs in Task 6. Don't touch `TswapCore/Vault/VaultUnlocker.cs`, `KeyringUnion.cs` or
`VaultCommand.cs` (T61's).

## What is wrong (evidence)

Two machines rotate one secret before they sync. The merge keeps the later value and nothing else:
`RecordMerge.MergeAll` retains only the winner's current and previous versions (`RecordMerge.cs:124-131`) and says so
("Versions the winner doesn't retain are ignored", `:91-93`); `MergeAllMetadata` likewise (`:220`). The next write of
that record writes the merged state and deletes the folded copy (`RecordVaultStore.cs:2044-2045`), so the losing value
is gone from every file. The only sign is a `Note:` per copy naming the hashed file, "Combined by the merge rules"
(`CopyNote`, `:1198-1201`, printed at `:801`, `:1244`, `:1772`). If machine A had already set its value at a service
(`rotate db-pw && run psql … ALTER ROLE`), the service now holds a value the vault doesn't, and `{{db-pw:previous}}`
gives the common base, not A's value (`VaultView.ResolveToken`, `VaultView.cs:183-222`).

## Rulings where the design was silent or the code disagreed

These are decided here; each is marked where it is used.
- **R1, unsealed entries.** A full load can set aside a format 2 copy's value, which has no value section yet
  (format 2 keeps no sections, `WriteAll` `:2030-2036`). In memory its entry has `sectionLength` 0 and its plaintext is
  held by reference in `SecretRecord.UnsealedDiscards` (no copy; the decoded inputs that own it are zeroed as today).
  A merge input's empty-section entry takes its plaintext from that input's `UnsealedDiscards`, so a merged result
  merged again with its inputs is unchanged (`RecordMergeTests.MergeBothWays`, `RecordMergeTests.cs:28-37`).
  `WriteAll` seals it before encoding. A file whose entry has `sectionLength` 0 can't be merged (no plaintext anywhere):
  the record is unreadable, the same fail-closed outcome as the design's "section of at least 28 bytes".
- **R2, comparing a format 2 holding.** On the full path a holding without a section (format 2) is compared by
  plaintext with holdings whose plaintext is in hand (any copy's current or previous value), as `MergeAll` compares
  retained versions today (`RecordMerge.cs:145-148`). Against an entry (section only, never decrypted to merge) it is a
  holding "without a set", so differing is a `RecordConflictException` (design §1.4 rule 2).
- **R3** is moot: the design dropped the entry's kind byte (round 8 model 7). Nothing stores or shows an entry's kind;
  `{{x:discarded}}` decides from the value (T58's `CommandValues`).
- **R4, `flags`**: bit value `0x01` is "burned"; every other bit zero.
- **R5, `byLength`** counts UTF-8 bytes (0-255; 0 is no label). `--by` keeps the fields rules (`FieldWhoSource.ValidateBy`,
  at most 64 characters, `FieldWhoSource.cs:15`, `:29-40`) and is also refused over 255 UTF-8 bytes:
  `--by: a label is at most 255 bytes in UTF-8.`
- **R6, `discardedCount`** decodes 0-255 (the byte); the 64 is a write cap (§1.4 "Bounds"), not a decode rule, so a
  record holding more in memory stays readable, as the design wants. `supersededCount`, `retiredCount` ≤ 64 and
  `ackCount` ≤ 8 are decode rules, since every writer and merge caps them.
- **R7, an all-zero lineage is not written.** A lineage with no superseded, retired or discarded stamps, `forgotten`,
  `asOf` and `exactFrom` all `Stamp.Zero` behaves exactly as no extension (inexact, so the bound is D2's, §1.1), so a
  write leaves it out. This is what `burn` and field writes create on a record that had none (§1.5) and what a merge
  of extension-less copies gives; leaving it out keeps those writes byte-identical to today.
- **R8, a newer-format lineage** (format byte > 1) on **any** input of a merge, whichever input has the larger write
  stamp: the whole merge uses no lineage rule for `0x0103` (the whole-list rule, as for an unknown type: the chosen
  list's `0x0103` bytes, whatever their format), sets nothing aside, and this build writes no `0x0103` of its own on
  it. A format 1 chosen list may then drop the newer copy's retirements; T61's R4 backstops floored entries (design
  §1.4 rule 7). Warned once per record per command (Task 4). A write that would have to update such a lineage (a value
  write, `delete`, `--ack`, `--clear`, `restore --discarded`) is refused (design §1.3, round 8 model 6):
  `Refused: record <file> of '<name>' carries value lineage written by a newer tswap, and this change would have to update it. Upgrade tswap on this machine. Nothing was written.`
  `burn` and field writes keep it byte for byte.
- **R9, JSON nulls.** `CliJsonContext` omits nulls (`CliJson.cs:33`); the design's `conflicts --json` shows `null`s. The
  conflicts records mark those properties `[property: JsonIgnore(Condition = JsonIgnoreCondition.Never)]` so the shape
  is stable.
- **R10, `conflicts` text.** The status goes at the end of each `discarded` line (one secret can hold entries in
  different states); the header line is the name, plus ` (deleted)` for a tombstone.
- **R11, the cap text** leaves out "(on a rolled-back record, accept it first)": that command is T61's, which adds it.
- **R12, which warning form.** "was replaced by" when no retained version lies between the entry and the current
  version (no previous, or the previous is older than the entry); "set aside by a merge; the current value is …"
  otherwise. An entry whose stamp is the previous version is silent (design round 8 model 2, which overrides this
  ruling's former "also the previous value" form). Decided from metadata.
- **R13, the merged `ValueLineage`'s position** (design §1.4 rule 6) follows `Fields`' rule in `MergeExtensions`
  (`RecordMerge.cs:315-346`): the place it has in the chosen list (the whole list of the input with the largest write
  stamp, `Fields` and `ValueLineage` left out for the tie order), at the end when that list has none; when both are
  appended, `Fields` first, then `ValueLineage`.
- **R14, earlier-life entries** (design §1.10, round 8 model 4): an entry of a live record whose version is below the
  current life's start, the `Fields` extension's `Since` (`FieldsCodec.TryGet(extensions)?.Since`; `RecordWrites.cs:99`
  sets it on a new life). A record with no `Fields` extension (re-created by v0.3.0) can't tell: every entry is
  current-life (documented). A tombstone has no current life: its entries are not earlier-life.
- **R15, tied winners** (design §1.4 rule 3, round 8, Claude 2): `MergeAll` takes `tied[0]` (`RecordMerge.cs:119-120`),
  which depends on input order. The lineage takes the tied copies as a set: exact when any tied copy's format 1
  lineage has `AsOf == W.Version`, `ExactFrom` then the smallest among those exact ones; with none exact, `AsOf` and
  `ExactFrom` are the smallest among the tied copies' lineages (both `Stamp.Zero` when none has one). `R` is the same
  for every tied copy (they must agree on the previous version, `:121-122`, `:208-215`).

## Task 1: `ValueLineage` and its codec (extension `0x0103`)

New `TswapCore/Keyring/ValueLineage.cs` (namespace `TswapCore.Keyring`, all public: the CLI reads it):

```csharp
public sealed record Acknowledgement(Stamp Stamp, string? By);
public sealed record DiscardedBurn(Stamp Stamp, string? Reason);
public sealed record DiscardedValue(Stamp Version, DiscardedBurn? Burn,
    IReadOnlyList<Acknowledgement> Acknowledgements, FingerprintSet? Fingerprints, byte[] Section);
public sealed record ValueLineage(Stamp AsOf, Stamp ExactFrom, IReadOnlyList<Stamp> Superseded,
    IReadOnlyList<Stamp> Retired, Stamp Forgotten, IReadOnlyList<DiscardedValue> Discarded)
{
    public static ValueLineage None { get; }   // all Stamp.Zero, empty lists
    public bool IsNone { get; }                 // R7
}
```
Equality of lineages is by `ValueLineageCodec.Encode` bytes (records holding lists compare by reference). An empty
`Section` (length 0) is an unsealed entry (R1).

`public static class ValueLineageCodec`:
- `public const ushort Type = 0x0103; MaxStamps = 64; MaxEntries = 64; MaxEntryBytes = 65_536; MaxAcknowledgements = 8;`
- `public static byte[] Encode(ValueLineage lineage)`; `public static ValueLineage Decode(byte[] data)` (throws
  `TswapException("Malformed value lineage: <what>")`); a candidate entry starts with no acknowledgements;
- `public static LineageRead Read(IReadOnlyList<RecordExtension> extensions)` →
  `public readonly record struct LineageRead(ValueLineage? Lineage, bool NewerFormat)`: none → `(null, false)`; one
  `0x0103` of format 1 → decoded; format byte > 1 → `(null, true)`; two or more `0x0103`, or a format 1 that doesn't
  decode → throws (fail closed: a reader that can't see the list can't tell whether a value is missing);
- `public static IReadOnlyList<RecordExtension> With(IReadOnlyList<RecordExtension> extensions, ValueLineage? lineage)`:
  the `0x0103` replaced in place (at the end when there was none), removed for null or `IsNone` (R7), every other
  extension kept in place and bytes; returns the same list when nothing changes (as `ValueKinds.With`, `ValueKinds.cs:91-110`);
- `public static bool ForcesFormatThree(IReadOnlyList<RecordExtension> extensions)`: a format 1 lineage with entries or
  retired stamps (§1.4 rule 4; superseded alone doesn't force it).

Layout, little-endian, stamps as `SecretRecordCodec.WriteStamp` (`:1008-1014`, 28 bytes):

```
format            1   = 1
asOf              28
exactFrom         28
supersededCount   1   0..64, then that many stamps, strictly ascending
retiredCount      1   0..64, then that many stamps, strictly ascending
forgotten         28
discardedCount    1   0..255 (R6), then per entry, strictly ascending by version:
  version         28
  flags           1   0x01 burned (R4); other bits zero
  ackCount        1   0..8, then per acknowledgement, strictly ascending by stamp:
    stamp         28
    byLength      1   0..255 UTF-8 bytes (R5), then the label (strict UTF-8; 0: no label)
  [burned]        28 the burn's stamp, then reasonLength 2 (0xFFFF: none) + UTF-8 reason; present iff flags 0x01
  hasFingerprints 1   0 or 1; then variantSetVersion 1, entryCount 1, entries as the metadata stores them
  sectionLength   4   then the section: nonce 12 | tag 16 | ciphertext (0: unsealed, R1)
```

Decode is strict for format 1: every length within the data, counts within bounds, strict ascending order (no
duplicates), zero reserved bits, `hasFingerprints` 0/1, a section of 0 or at least 28 bytes, no trailing bytes,
fingerprint kinds checked as `ParseMetadata` checks them (`SecretRecordCodec.cs:861-864`). Extract the fingerprint set
read and write of `ParseMetadata`/`EncodeV3` into `internal static int WriteFingerprintSet(Span<byte>, int, FingerprintSet)`
and `internal static (FingerprintSet Set, int Offset) ReadFingerprintSet(byte[], int)` in `SecretRecordCodec` and call
them from both places (no behaviour change; the existing codec tests cover it).

Add `0x0103` to the registry comment (`FieldSet.cs:8-11`): "values a merge set aside and the lineage that decides them (#312)".

Tests, `TswapTests/ValueLineageCodecTests.cs`:

| Case | Outcome |
|---|---|
| a lineage with each part filled (2 superseded, 1 retired, `forgotten`, two entries: one burned with a reason, one with 8 acknowledgements, one with and one without a set) | `Decode(Encode(x))` encodes to the same bytes; the bytes laid out as the table above, checked field by field |
| each malformed form: truncated in every field, superseded 65, retired 65, ack 9, a non-ascending or duplicate stamp in each list, flags `0x02`, `hasFingerprints` 2, a 27-byte section, a trailing byte, a bad UTF-8 label or reason | `TswapException` "Malformed value lineage: …" |
| format byte 2 with any bytes after it | `Read` gives `(null, true)`; nothing decoded |
| two `0x0103` extensions | `Read` throws |
| `With` on a list holding `0x0100`, `0x0101`, `0x7777`; with `IsNone` | the others in place and byte-identical; `IsNone` removes `0x0103` |
| `ForcesFormatThree`: superseded only; one retired; one entry | false; true; true |

Break-it-once: accept a non-ascending superseded list (the ordering row fails).

## Task 2: the merge rule, in both paths

New, in `ValueLineage.cs`, the rule as a pure function both merge paths call:

```csharp
internal sealed record ValueHolding(FingerprintSet? Fingerprints, byte[]? Section, byte[]? Plaintext);
internal sealed record LineageCopy(Stamp Version, bool IsTombstone, Stamp? PreviousVersion,
    IReadOnlyList<BurnEntry> Burns, IReadOnlyList<RecordExtension> Extensions,
    ValueHolding? Current, ValueHolding? Previous);
internal static class ValueLineageMerge
{
    /// Null: no copy has a lineage and nothing is set aside (the extension list is then merged as today).
    internal static (ValueLineage Lineage, IReadOnlyDictionary<Stamp, byte[]> Unsealed)? Merge(
        IReadOnlyList<LineageCopy> copies, Stamp winnerVersion);
}
```

The rule is the design's §1.1 and §1.4, exactly, with `W` the copy whose `Version` is `winnerVersion`:
- `R` = `W`'s current and previous versions (none for a tombstone).
- `S` = every copy's `Superseded` and every copy's previous version, minus `R`, the 64 largest kept.
- `T` = the union of every copy's `Retired`, the 64 largest kept; `forgotten` = the largest of every copy's `Forgotten`
  and every stamp the cap pushed out of `T`. A merge writes only explicit marks into `T`.
- `B` = `min(stated, known)`: `stated` = `W.ExactFrom` when `W` has a format 1 lineage **and** `W.AsOf == W.Version`
  (for tied winners, R15);
  otherwise `W`'s previous version, or `W`'s version for a tombstone or a first value. `known` = the largest stamp in
  `S ∪ {W's previous}`, or `Stamp.Zero`.
- Entries = (every copy's entries ∪ candidates) minus the stamps in `T`, where the candidates are every copy's current
  version `V` (not a tombstone) with `V > B` and `V ∉ R ∪ S ∪ T`. `S`, `R`, the bound and equality never remove an
  existing entry.
- Per entry stamp, over every copy holding it as current, previous or entry: the holdings must agree, by equal section
  bytes or equal base fingerprint entries (`FingerprintSet.SameBaseEntries`), plaintext only per R2; otherwise
  `RecordConflictException($"two copies hold different values of the discarded version {stamp}")`. A section-less
  holding with no plaintext (R1): `RecordConflictException($"a copy lists the discarded version {stamp} without its value section")`.
  Chosen: the section ordinally smallest among non-empty ones (empty only when none is sealed, its plaintext then in
  `Unsealed`); sets joined as `JoinGroup` does (`RecordMerge.cs:378-388`, make it `internal`); acknowledgements the
  union by stamp, the 8 largest (a new entry has none); burn the earliest found in any copy's `Burns` for that version
  or any copy's entry.
- `AsOf`, `ExactFrom`: `W`'s, unchanged, when `W` has a format 1 lineage (tied winners: R15); both `Stamp.Zero`
  otherwise. A merge never refreshes `AsOf`.
- A tombstone winner keeps its lineage and entries (owner decision 1).

Wiring:
- `RecordMerge.MergeAll` and `MergeAllMetadata` build one `LineageCopy` per input and call `Merge`. When any input's
  `ValueLineageCodec.Read` reports `NewerFormat`, or `Merge` returns null, the `0x0103` follows `MergeExtensions` as
  today (R8). Otherwise `MergeExtensions` leaves `0x0103` out of the chosen list (as it does `Fields`, `:322`) and the
  merged lineage goes back in its place (`ValueLineageCodec.With`). A `TswapException` from `Read` becomes
  `RecordConflictException($"a copy's value lineage can't be read ({ex.Message})")`, as for `Fields` (`:337-340`).
- Full path: a holding's section is `input.Sealed[stamp]` (format 3, `SecretRecordCodec.cs:700`) or none (format 2,
  `Sealed` null), its plaintext `input.Value` / `input.Previous.Value`. Metadata path: sections from the input's dictionary,
  no plaintext.
- `SecretRecord` gains `public IReadOnlyDictionary<Stamp, byte[]>? UnsealedDiscards { get; init; }` (not in `SameState`):
  `MergeAll` sets it from `Merge`'s `Unsealed`, references only, and keeps the inputs' own.
- Update the summaries of `MergeAll` (`:81-108`, the "Versions the winner doesn't retain are ignored" bullet) and
  `MergeExtensions` (`:304-314`).

Tests, `TswapTests/ValueLineageMergeTests.cs`. Every row through `MergeAll` **and** `MergeAllMetadata` (format 3 copies;
the format 2 rows full path only), in every input order, asserting equal encoded lineages between paths and orders:

| Inputs | Outcome |
|---|---|
| A rotates `v0`→`a` at 16:20:16, B `v0`→`b` at 16:20:20 | current `b`, previous `v0`, one entry `a` (origin A) |
| the same, stamps reversed | current `a`, entry `b` |
| A burns `v0`; B rotates `v0`→`b` | no entry; burn history kept |
| A and B burn `v0` | no entry; the earliest burn |
| A holds `v1`; B rotated `v1`→`v2`→`v3`, lineage exact | no entry |
| the same, B built with the extension at `asOf` = `v1`, then its version moved to `v3` with the extension bytes untouched (as 0.3.2 writes) | no entry (not exact, `B` = `v2`) |
| the same, B with no extension | no entry (D2) |
| a 0.3.2-shaped tombstone (no extension, or one with a stale `asOf`) after `v5`; B rotated `v5`→`b` concurrently; the delete wins | tombstone with entry `b` |
| two 0.3.2-shaped first values of one name | the loser is an entry |
| a 0.3.2-shaped tombstone after `v1`…`v5`; a copy holding `v2` (previous `v1`) | entry `v2` (the residual, pinned) |
| a 0.3.2-shaped re-creation of a deleted name, merged with a copy of the earlier life | the earlier life's value an entry (the second residual) |
| inexact `v3` (previous `v2`, no extension); a concurrent value older than `v2` | no entry (the D2 miss, pinned) |
| exact since a first write over an inexact lineage (`v5`, previous `v4`, `exactFrom` = `v4`); a concurrent value older than `v4` | no entry (the `exactFrom` miss, pinned) |
| A, B, C rotate from `v0` | two entries; all 6 orders all at once and every pairwise order give equal bytes |
| a result merged again with each input | byte-identical |
| an entry acknowledged in one copy, open in another | both acknowledgements kept |
| **§1.4a orders**: every row of the design's two §1.4a tables (`X`/`X'`/`Y`/`Z`, and GLM's A/B/C with clear and delete), all at once and the six pairwise orders | the tables' results, byte-identical per row |
| an entry in one copy, its stamp in another copy's `Retired` | no entry |
| an entry `a` in one copy, `a` another copy's previous version | entry `a` kept |
| an entry whose stamp is the winner's previous version | kept |
| A and B rotate to the same value (two stamps) | an entry (equality is display only, Task 4) |
| an entry, then the winner rotates to the entry's value again | the entry kept |
| an entry cleared in B's copy; A's copy still holds it as current; and the same after A burned `x` | no entry, both |
| an entry burned in a copy that holds the value as its current value | the entry burned, earliest burn |
| an entry and the winner's previous at one stamp, different sections and base fingerprints | `RecordConflictException` |
| two entries of one stamp: different sections and base fingerprints; different sections with one set missing (metadata path); different sections with equal base fingerprints | conflict; conflict; merged, the smaller section kept |
| a candidate without a set (metadata path) | an entry without a set |
| A deletes after seeing `v1`; B holds `v1` | tombstone, no entry |
| A deletes; B rotates concurrently; the delete later | tombstone with B's value as an entry |
| A and B create the same name | one entry |
| a format 2 loser (full path): its plaintext against a format 3 copy holding it as previous; against an entry with another section | in `UnsealedDiscards`, section empty; merged (plaintexts equal); conflict (R2) |
| an entry with `sectionLength` 0 read from a file | `RecordConflictException` (R1) |
| 65 rotations on one machine, then a merge with a copy 65 behind | that copy's value an entry |
| MiMo's r6 construction (A 65 rotations from `x`, B 64 more after syncing A, H frozen at `x`): all at once; ((A, H), B) | all at once entry `x`; ((A, H), B) no entry (pinned) |
| the same with 63 and 62 rotations | entry `x` in every order |
| 65 retirements on one record; a stale copy holding the first retired stamp as an acknowledged entry | the entry back; `Forgotten` ≥ its stamp |
| those 65 retirements merged pairwise in every order and all at once | equal `Forgotten` |
| 65 entries | merged without a cap (no trim, no exception) |
| a malformed format 1 lineage; a format 2 lineage byte | `RecordConflictException`; whole-list rule, nothing set aside (R8) |
| a newer-format `0x0103` on the copy with the **smaller** write stamp, format 1 on the other, both paths | whole-list rule for the whole merge; nothing set aside |
| two copies tied at the winning version (same value and previous), one with an exact lineage, one with a stale `AsOf`, against a stale third copy; every input order | the same `B` (exact, R15) and the same bytes in every order |
| claim 3's boundary: A (inexact, `v3`, previous `v2`), B, and H holding a value between `v1` and `v2`; ((A, H), B) and all at once | pins what each gives where the precondition (an exact winner at every step) fails |
| Claude r7 I-1's (A, B, C) shape, ((A, B), C) and all at once | ((A, B), C) holds `a` and `b`; all at once `b` only (`a` is `C`'s previous, so silent in Task 4) |
| a 0.3.2-shaped tombstone (no lineage) over `v5`; a copy (a backup from before the delete) holding `v5` | `v5` an entry on the tombstone (the `known` term kept, design round 8, Claude I-3) |
| a clear on B (`Retired` ∋ `a`); C, which never saw it, writes later; a 0.3.2-shaped merge keeps C's extension list (entry `a`), open and acknowledged | entry `a` back (T61's R4 reports it on B) |

Parity: `ValueLineageMergeTests.BothPaths_Agree_OnRandomCopySets`, seeded, 400 rounds of 2-4 format 3 copies of one
record (rotations from a shared history, deletes, burns, lineages exact, stale or absent, entries, retirements,
acknowledgements, sets present or stripped): `MergeAllMetadata` equals `MergeAll` (winner, extensions, sections) or
both refuse; every permutation gives the same bytes; re-merging the result with any input changes nothing. Count
rounds that set something aside (> 50) and that refused (> 5) and assert both.

Break-it-once, each named in the commit: drop the `S` exclusion (the "two rotations behind" row creates an entry);
treat "has the extension" as exact (the stale-`asOf` row reports `v1`); let `S` remove entries (the previous-version
row loses `a`); let `R` remove entries (the §1.4a demotion rows lose `a`); let a candidate with a retired stamp through
(the (`Z`,`X`),`Y` order keeps `a`); drop the `known` term (both 0.3.2 tombstone/first-value rows lose the value);
take the lineage from `tied[0]` alone (the tied-winners row differs between orders); decide R8 from the chosen list's
`0x0103` only (the smaller-write-stamp row sets a value aside).

## Task 3: writes

**Lineage on writes** (pure, in `ValueLineage.cs`, used by both write paths):
`internal static ValueLineage ForNewVersion(ValueLineage? old, Stamp? oldVersion, Stamp? oldPrevious, bool oldIsTombstone, Stamp newVersion, Stamp? restoredDiscarded)`,
`ForTombstone(ValueLineage? old, Stamp oldVersion, Stamp? oldPrevious, Stamp tombstone)`, `Acknowledge(ValueLineage, IReadOnlyList<Stamp> entries, Stamp ack, string? by)`,
`Clear(ValueLineage, IReadOnlyList<Stamp> entries)`. Exact is `old` present and `old.AsOf == oldVersion`.

| Write | Lineage | Entries |
|---|---|---|
| new version over a live record (`create`, `add`, `ingest`, `rotate`, `ingest --rotate`, `import`, `restore`) | the dropped old previous joins `Superseded`; `AsOf` = new; when not exact, `ExactFrom` = old previous, or old version when none; `Retired`, `Forgotten` unchanged | unchanged |
| new version with no record | `AsOf` = new, `ExactFrom` = `Stamp.Zero` | none |
| new life over a tombstone | the tombstone's `Superseded`, `Retired`, `Forgotten` and entries kept (a deleted value never comes back through a stale copy); `AsOf` = new; `ExactFrom` = the tombstone's version when not exact, else unchanged | kept, now earlier-life (R14) |
| `restore --discarded` of entry `e` | as a new version, and `e` joins `Retired` | `e` removed |
| `delete` | current and previous join `Superseded`, each entry's stamp joins `Retired`; `AsOf` = tombstone; `ExactFrom` as a value write | all removed |
| `burn`, `field set`/`unset` | unchanged (none stays none, R7) | unchanged, sections and sets byte for byte |
| `conflicts --ack` | unchanged | an `Acknowledgement(ackStamp, by)` on each named entry, the 8 largest kept |
| `conflicts --clear` | each named entry's stamp joins `Retired` | removed |

Every write carries `Retired` and `Forgotten` unchanged unless it is a person's action that adds to `Retired`
(`--clear`, `restore --discarded`, `delete`); only the cap removes from it. `Superseded` and `Retired` keep their 64
largest; a write that pushes a stamp out of `Retired` raises `Forgotten` exactly as a merge does.

**A newer-format lineage** (R8): `CommitWrites` refuses a `ValueWrite`, `DeleteWrite` or `LineageWrite` on a record whose
`ValueLineageCodec.Read` gives `NewerFormat`, with R8's text, before any write. `BurnWrite` and `FieldsWrite` go on and
keep the `0x0103` bytes as they are (`ValueLineageCodec.With` is not called for them).

**Both write paths, in step:**
- `RecordWrites.NewVersion`/`Next` and `RecordVaultStore.NextRecord` gain `Stamp? restoredDiscarded = null`. With it, the
  entry's own burn (if any) is issued again on the new version (`new BurnEntry(version, burn.Stamp, burn.Reason)`), not
  the previous value's (`RecordWrites.cs:92-93`, `RecordVaultStore.cs:1555-1557` stay for plain `restore`). Then the
  lineage per the table, written with `ValueLineageCodec.With` (after T58's `ValueKinds.ForNewVersion`).
  Don't route entries through T58's `ValueKinds` code, which drops entries of stamps no longer retained (design round 3
  amendment 13).
- `RecordWrites.Tombstone` and `RecordVaultStore.Tombstone`: `ForTombstone`. `FieldEdits.ForTombstone` keeps `0x0103`
  (it drops only `0x0100` and `0x0101`, `FieldEdits.cs:116-117`).
- `WriteSnapshot` (`migrate --to-records`): each record a new version with no record.
- New `RecordWrites.EditLineage(RecordMetadata state, Func<ValueLineage, ValueLineage> edit)` and
  `RecordVaultStore.EditLineageRecord(SecretRecord state, Func<ValueLineage, ValueLineage> edit)`: the extension
  replaced, everything else kept, live or tombstone; null when the bytes don't change.
- `PendingWrite.cs`: `ValueWrite` gains `Stamp? RestoredDiscarded = null`; new
  `internal sealed record LineageWrite(string Name, SecretEntry Entry, LineageEdit Edit) : PendingWrite(Name, Entry);`
  with `internal abstract record LineageEdit; sealed record AckEdit(IReadOnlyList<Stamp> Entries, string? By); sealed record ClearEdit(IReadOnlyList<Stamp> Entries);`.
  `CommitWrites` (`:828`) dispatches it on both branches (the ack stamp is `NextStamp()`).
- `CommitWrites`, the cap (§1.4 "Bounds"): before adding a `RecordWrite`, when the written lineage holds more than
  `MaxEntries` entries or more than `MaxEntryBytes` encoded entry bytes and the write is not a `ClearEdit` or a
  `restore --discarded`, throw (nothing written, once per command). A `BurnWrite` is exempt from the 64-entry cap (it
  never grows the list, so it stores what a fold grew) but not from the 64 KiB one, and the codec's 255 entries bind it:
  `Refused: 'x' holds more values a merge set aside than a record can store (64, or 64 KiB). Drop some first with 'sudo tswap conflicts --clear x'. Nothing was written.` (R11).
  The copies stay, and reads are unaffected.
- `WriteAll` (`:1989`): format 3 when `WritesV3 || reindex || write.ForceV3 || ValueLineageCodec.ForcesFormatThree(<the record's extensions>)`,
  on both the metadata and the plaintext branch. On the plaintext branch, before `PrepareV3`, a new
  `private static SecretRecord PrepareDiscarded(SecretRecord record, byte[] vaultKey, FingerprintKeys keys, bool reindex)`:
  seals every unsealed entry from `UnsealedDiscards` (`SecretRecordCodec.SealValue(recordId, entry.Version, plaintext, key)`)
  and fingerprints it from that plaintext; fills a missing set, or with `reindex` an older one (as `PrepareV3`'s `For`,
  `:2069-2075`), by opening the entry's section (`OpenSealed`) and zeroing the plaintext. The encoded record never holds an empty section: assert it
  (`InvalidOperationException`).
- Metadata path: `WithMissingSets` (`:965`) also fills missing entry sets, through `OpenValueSection` with that entry's
  section, but only for a `ValueWrite` (burn, field, ack and clear writes carry entries as they are; a tombstone's only
  through `vault reindex`, since `WithMissingSets` returns early for one, `:996-997`).
- `IsCurrent` (`:1434`) is false when an entry has no set, an older set, or an empty section.

**`VaultWriter`** (all public):
- `public RecordMetadata? Record(string name)`: the opened record's merged metadata, tombstone included; null for no
  record or an unreadable one.
- `public Stamp RestoreDiscarded(string name, string? stamp, DateTime created)`: the refusals below in order, then
  decrypts that one entry (`SecretEntry.DecryptDiscarded`) and stages
  `ValueWrite(name, entry, value, Always: true, Restored: false, created, RestoredDiscarded: e.Version)`; returns the stamp.
  Refusals: no record or a tombstone without entries `Secret 'x' not found` (unreadable named first, as `Restore`);
  no entry `'x' has no value a merge set aside.`; several and no `--stamp`
  `'x' has 2 values a merge set aside; name one with --stamp (see 'tswap conflicts x').`; the `--stamp` texts of Task 5;
  a section that can't be decrypted: `SecretsDb.UnreadableRecordText` (nothing written).
- `public int Acknowledge(string name, string? stamp, string? by, byte[] thisOrigin)` and
  `public int ClearDiscarded(string name, string? stamp)`: stage a `LineageWrite`; return how many entries they name
  (0: nothing staged). Without `--stamp`, `Acknowledge` names every entry `ConflictDisplay` shows as not acknowledged on
  this machine, `ClearDiscarded` every entry.

**`SecretEntry`**: `public byte[] DecryptDiscarded(Stamp version)`: format 3 through `RecordVaultStore.OpenValueSection`
with a one-entry dictionary of that entry's section and its set (so the `ValueDecrypted` seam fires once and a set is
checked against its value, `:1068-1078`); decoded whole: a copy of `Decoded.UnsealedDiscards[version]`, or the sealed
section opened the same way. The caller zeroes it.

Tests, `TswapTests/ValueLineageWriteTests.cs` (both write paths; a new parity test
`RecordWrites_MatchNextRecord_WithLineage_OnRandomStates`, seed `3_12`, 400 rounds, random lineages including stale,
absent, with entries and retirements, over every operation including `EditLineage` and `restoredDiscarded`, compared as
`RecordWrites_MatchNextRecord_OnRandomStates` compares, `RecordWritesTests.cs:485-505`):

| Write | Outcome |
|---|---|
| rotate a record holding an entry | entry kept byte for byte; the dropped old previous in `Superseded`; `AsOf` = new |
| rotate a 0.3.2-written record (no extension, previous `p`) | extension created, `ExactFrom` = `p` |
| `burn` and `field set` on a record with no extension | no `0x0103` written (R7); the next merge uses the D2 bound |
| `burn` over a stale `AsOf` | `AsOf` unchanged |
| `--clear` in a folder that writes format 2 | written in format 3, `Retired` kept |
| a rotation in a format 2 folder, the record with only `Superseded` | written in format 2, the extension dropped; the next merge uses D2 |
| any write of a record with entries in a format 2 folder | format 3 |
| delete | entries gone, their stamps in `Retired`, current and previous in `Superseded` |
| `burn`, `field set` on a record with entries | entries byte-identical, sets missing stay missing |
| a value write on a record with a set-less entry (metadata path) | the set filled from its section, one `ValueDecrypted` call for it |
| a 0.3.2-shaped round trip (unknown extension kept) | unchanged bytes |
| `restore --discarded` of a burned entry | the new version burned with the entry's burn stamp and reason, not the previous value's |
| a record at 65 entries in memory: `field set`, `rotate`, `--ack`; then `burn`; then `--clear`, `restore --discarded` | the first three refused with the cap text, nothing written; `burn` written (exempt from the entry cap); the last two written |
| `burn` on a record whose entries pass 64 KiB | refused with the cap text |
| a write command (`rotate`) on a record whose fold of conflicted copies would hold 65 entries | the cap text, once; the copies kept; `sudo conflicts --clear` then writes |
| a 0.3.2-shaped value write over a record with entries (the `0x0103` bytes untouched, version moved) | entries kept; a stale `AsOf`; the next merge uses the D2 bound |
| delete (`Retired` ∋ `a`), `create x` again, a stale copy holding entry `a` folds; `{{x:discarded}}` | no entry `a` (the new life carried `Retired`); the token gives the no-entry text |
| the 65th `--clear` on one record (a write capping `Retired`) | `Forgotten` raised by the write to the stamp pushed out |
| every write (value, burn, field, ack, delete, new life) on a record with `Retired` and `Forgotten` set | both carried unchanged unless the write adds to `Retired` |
| a newer-format lineage: `rotate`, `delete`, `--ack`, `--clear`, `restore --discarded`; `burn`, `field set` | the first five refused with R8's text, nothing written; `burn` and `field set` written, the `0x0103` bytes unchanged |
| entries whose encoding would pass 64 KiB | a write refused with the cap text |
| a format 2 loser folded by a write | the entry sealed under its own stamp; `OpenSealed` of it gives the plaintext |
| `vault reindex` | entries' missing and older sets recomputed; a second run rewrites nothing |

Break-it-once: drop the format 3 forcing (the `--clear` in format 2 row loses `Retired`); re-issue the previous value's
burn on `restore --discarded` (the burned-entry row fails); start the new life's lineage without the tombstone's
`Retired` (the delete-then-create row brings `a` back); let a value write update a newer-format lineage (the R8 rotate
row writes); apply the entry cap to `burn` (the burn-at-65 row is refused).

## Task 4: what a person sees: warnings, `names`, masking

**Display** (new `TswapCore/Keyring/ConflictDisplay.cs`, pure):

```csharp
public enum DiscardedState { Open, OpenHere, Acknowledged, Forgotten }
public sealed record DiscardedView(DiscardedValue Entry, DiscardedState State, string? SameAs, bool EarlierLife); // SameAs: "current" | "previous" | "superseded" | null
public static class ConflictDisplay
{
    public static IReadOnlyList<DiscardedView> Of(RecordMetadata record, byte[] thisOrigin); // [] for none or a newer format
    public static bool Warns(DiscardedView view);   // State != Acknowledged && SameAs is null
}
```
`EarlierLife` per R14 (display and `{{x:discarded}}` only; membership unchanged). `Forgotten` when
`Entry.Version <= lineage.Forgotten` (whatever its acknowledgements); else `Acknowledged` when there is
an acknowledgement and (the entry's origin isn't `thisOrigin`, or one acknowledgement's origin is); `OpenHere` when
acknowledged elsewhere but not here on the writer's machine; else `Open`. `SameAs` (the silence rule, design §1.1, an
OR of three): `"previous"` when the entry's stamp is the record's previous version, or its set and the previous
version's share base entries; `"current"` when its set and the current version's do; `"superseded"` when its stamp is
in the merged `S`. A silent entry (`SameAs` set) is listed by `conflicts` but never counted in `N open conflict(s)` or
`--json`'s `Open`, and never makes `names --json`'s `Conflict` true. `RecordVaultStore` gains `public byte[] OwnOriginId() => OriginId();` (`:2230`).

**Texts and where** (new `TswapCli/ConflictWarnings.cs`; times `yyyy-MM-dd'T'HH:mm:ss'Z'` of the stamp's physical part
via `Hlc.ToDisplayDate`, as `FieldCommand.cs:403`; machine = the first 8 hex of the origin, plus ` (this machine)`;
`tswap` is `ctx.Prefix`; one line each, stderr, no value or fingerprint):
- `internal static void ForSecret(CommandContext ctx, RecordMetadata? record)`: once per secret per command (a
  `HashSet<string> ConflictsWarned` on `CommandContext`), one line per entry for which `Warns`:
  - replaced (R12): `⚠ x: two machines changed its value at the same time. The value machine 5d918462 (this machine) wrote at 2026-11-14T16:20:16Z was replaced by the one machine c7cad1d5 wrote at 2026-11-14T16:20:20Z. tswap kept the replaced value. If a service was updated with it, see 'tswap conflicts x'.`
  - moved on: `… The value machine … wrote at … was set aside by a merge; the current value is the one machine … wrote at …. tswap kept the replaced value. If a service …`
  - tombstone: `⚠ x: it was deleted while machine 5d918462 changed its value (at 2026-11-14T16:20:16Z). tswap kept that value. See 'tswap conflicts x'.`
  - earlier life (R14), whatever R12 says: `⚠ x: tswap kept a value machine 5d918462 wrote at 2026-11-14T16:20:16Z from before 'x' was deleted and created again. See 'tswap conflicts x'.`
- `internal static void Summary(CommandContext ctx, IEnumerable<RecordMetadata> records)`:
  `⚠ 1 secret has a value a merge set aside: x. See 'tswap conflicts'.` / `⚠ 3 secrets have values a merge set aside: a, b (deleted), c. See 'tswap conflicts'.`;
  names ordinal, at most 5, then `and N more`; tombstones named `x (deleted)`; nothing when none warns.

| Command | Call |
|---|---|
| `run` (every secret a token, `--env` value or `{{@file}}` marker names), `totp`, `get`, `apply`, `field show` | `ForSecret(ctx, view.Record(name))` |
| `rotate`, `ingest` (incl. `--rotate`), `add`, `restore`, `burn`, `delete`, `field set`/`unset` | `ForSecret(ctx, writer.Record(name))` |
| `names`, `burned`, `list`, `check`, `redact`, `tocomment` | `Summary(ctx, view.LoadAll(…).Records)` once |

`VaultView` gains `public RecordMetadata? Record(string name)` (from `LoadAll`'s records when loaded, tombstones
included, else `Open(name)`; null for none or unreadable).

**Fold notes.** `RecordVaultStore` gains `public Action<RecordMetadata>? ConflictCreated { get; set; }`, raised once per
record whose merge created an entry (a stamp no input held as an entry), on every load path (`FoldConflictCopies`,
`OpenFromMetadata`, `LoadMetadata`, `MergeRecords`). `CommandContext.Storage` sets it once, on first use, when the store is
a `RecordVaultStore` (`CommandContext.cs:55-69`): `record => ConflictWarnings.ForSecret(this, record)`. `CopyNote` moves
after the merge on the two paths that print it before (`:1244`, `:1772`) and is not printed for a copy whose current
version became a new entry; it gains the name: `Note: record <file> ('<name>') has a …` (the rest unchanged). A fold of a
copy whose current value was retired raises nothing (design §1.8, M-4).

R8's warning, once per record per command: `Warning: record <file> carries value lineage written by a newer tswap; this one keeps it as it is but can't keep or show values a merge sets aside for that secret. Upgrade tswap.`

**`names`**: ` [CONFLICT]` after the date and T58's mark, before ` [BURNED]` (`NamesCommand.cs:113-121`), for a secret
with an entry that `Warns`; `NameEntry` gains `bool? Conflict = null` (`CliJson.cs:13`), set to `true` only then.
`names` still decrypts no value.

**Masking** (design §1.10 "Masking"): every entry's set joins the index under the name `<name>:discarded` with
`IsPrevious` false, tombstones included: `VaultView.BuildIndex` (`VaultView.cs:129-142`) and
`FingerprintStreamMatcher.For` (`FingerprintStreamMatcher.cs:64-71`). The label is then `[REDACTED: x:discarded]`, and
`tocomment` writes `# tswap: x:discarded` for such a hit, as it writes `x:previous`. `LoadMetadata` counts a record with a
set-less entry as not fingerprinted (`:1797-1798`), so `redact` and `tocomment` refuse and the other readers warn.

Tests, `TswapTests/ConflictWarningTests.cs` (`FleetMachine` A and B sharing a folder, a conflict as
`<hash>.sync-conflict-20261114-162020-ABCDEF`):

| Steps | Outcome |
|---|---|
| burned `sync-conflict-test`; A `ingest --rotate` `from-a` at 16:20:16; B `ingest --rotate` `from-b` at 16:20:20; conflict copy; `names` on A | stderr the summary line naming it; stdout `[CONFLICT]`; `names --json` `"conflict": true`, other entries without the key; no value on either stream |
| the same, `get sync-conflict-test` (sudo bypass) on A | the replaced form, A's origin with ` (this machine)`, both times |
| the same with the copy kept as main and the newer as copy; and the reverse | the same warning (the fold, not the main file, decides) |
| A and B rotate to the same value | no warning, no `[CONFLICT]`; `conflicts` shows ` (same value as the current value)` |
| a same-value entry whose stamp is copy C's current value; C rotates twice before merging; merge | silent: its stamp is in `S(M)` |
| the same, but the two rotations run on the merged record | it warns after the second rotation |
| an entry that is also the previous value | silent; `conflicts` lists it ` (same value as the previous value)`; not counted as open; no `Conflict` in `names --json` |
| B clears `a`; A's copy, still holding `a` current, folds on A | no conflict warning on A |
| A's current `a` against B's entry acknowledged on B | open on A (warning shown), acknowledged on B (none) |
| 9 acknowledgements of one entry, the 8 kept all from other machines | open on the writer's machine, acknowledged elsewhere |
| 65 retirements, a stale acknowledged entry comes back | warns (`Forgotten`) |
| `run` of another secret | no warning |
| a tombstone with an entry, `names` | the summary names `x (deleted)` |
| the fold of a conflict on a `run` | the full warning instead of the copy's `Note:`; a copy that lost nothing keeps its note, with the name |
| a newer-format lineage | the R8 warning once |
| a newer-format `0x0103` on the input with the **smaller** write stamp, format 1 on the other | the whole-list rule for the whole merge; nothing set aside; the R8 warning once |
| merged `ValueLineage` position: the chosen list has `Fields` then `ValueLineage`; has neither | kept in place; appended `Fields` then `ValueLineage` (R13) |
| an entry without a set, `redact` | refused as "not fully fingerprinted" |
| the current value rotated after the entry was set aside, `get` | the "moved on" form (R12) |
| a set-less entry whose value equals the current value, its stamp neither in `S` nor the previous | warns (equality needs base entries) |
| `names --json` of a secret with no entries, and of one with only silent entries | no `conflict` key in either |
| an entry whose stamp is the winner's previous version | silent |
| the child of `run` prints an entry's value (not used as a token) | `[REDACTED: x:discarded]` |

Break-it-once: drop the writer's-machine rule (the "open on A" row fails); compute discards from the main file only
(the reversed-copies row fails).

## Task 5: `tswap conflicts`, `restore --discarded`, `{{name:discarded}}`, export

**Grammar** (one more suffix, every place T58 lists, T58 brief Task 2): `TokenRegex` (`Validation.cs:10`),
`ThrowIfUnknownTokenSuffix` (`:19-29`), `AnyTokenRegex` (`:176`), the malformed-token text (`:54`); `Apply.MarkerRegex`,
`ValidMarkerTail` (`Apply.cs:9`, `:16`), the marker texts (`:74`, `:81`), the base-name split (`:86-89`, strip
`:discarded` too; the previous-value pre-check stays `:previous` only); `Check.MarkerRegex` (`Check.cs:8`) and its split
(`:156-160`: a `:discarded` marker is `Ok`/`Burned` by `IsBurnedToken` of the token, `Missing` when the secret is,
entries not checked); `ToCommentProcessor.ExistingMarker` (`:16`); `SecretMatcher.ConsumedMarker` (`:290`) and `BaseName`
(`:367-368`); `RunCommand.BracedNameRegex` (`:511`), the encoded-token decoding and the `--env` text (`:445`). Texts:
- `Unknown token '{{x:bogus}}': the suffixes are ':previous' (the value the last rotation replaced), ':totp' (the current code of a TOTP seed) and ':discarded' (a value a merge set aside).`
- `'…' is not a valid token: a token is {{NAME}}, {{NAME:previous}}, {{NAME:totp}} or {{NAME:discarded}}, and fields aren't substituted into commands.`
- `'…' is not a valid marker: a marker is # tswap: NAME, # tswap: NAME:previous, # tswap: NAME:totp or # tswap: NAME:discarded, and fields aren't substituted into commands.`
- `Unknown marker '# tswap: x:bogus' (line N): the suffixes are ':previous', ':totp' and ':discarded'.`
- `the value must be exactly one {{name}}, {{name:previous}}, {{name:totp}} or {{name:discarded}} token`

`{{x:discarded:totp}}` stays two suffixes: refused by T58's rule (my-call row in the design §1.10).

**Resolution.** `SecretsDb.DiscardedSuffix = ":discarded"` (`Models.cs:258-261`).
- `CommandValues` passes `x:discarded` to `inner` unchanged, exactly as `x:previous` (`CommandValues.cs:66-67`), and
  decides from the returned value as for `:previous`; its name derivation (`:72-74`) strips `:discarded` too. Its
  refusal for a `:discarded` token names the restore: Unix `… so nothing was substituted. The user can put that value back with 'sudo <prefix> restore x --discarded' and then see it with 'sudo <prefix> get x'.`;
  Windows `… with '<prefix> restore x --discarded' and then see it with '<prefix> get x', from an elevated command prompt.`
- `VaultView` (`Split`, `:280-284`, becomes a suffix kind): `ResolveToken` for `x:discarded`, with `shown` = `'{{x:discarded}}'`
  or `'# tswap: x:discarded' (line N)` as `CommandValues.cs:40`: no record → today's not-found path; a tombstone with no
  entry → `Secret 'x' not found{where}`; a tombstone with entries →
  `{shown}: 'x' was deleted; it has 1 kept value(s): see 'tswap conflicts x'.`; no entry →
  `{shown}: secret 'x' has no value a merge set aside.`; several →
  `{shown}: secret 'x' has 2 values a merge set aside, so the token can't tell which. The user can put one back with 'sudo tswap restore x --discarded --stamp <stamp>' (stamps: 'tswap conflicts x').`
  (earlier-life entries count towards "several"); exactly one and it is earlier-life (R14) →
  `{shown}: the value 'x' kept from before it was deleted and created again can only be put back by the user: 'sudo tswap restore x --discarded'.`;
  exactly one current-life entry (open or acknowledged): `SecretEntry.DecryptDiscarded`, cached and zeroed as `:212-221`; an
  undecryptable section → `SecretsDb.UnreadableRecordText`. `IsBurnedToken("x:discarded")`: true when there is exactly one
  entry and it is burned.
- `SecretsDb.ResolveToken` (`Models.cs:286`): `'{{x:discarded}}': values a merge set aside are read through 'tswap run' on a record vault only.`;
  `SecretsDb.IsBurnedToken` (`:273`) false for it. `ISecretLookup`'s summary ("Both give the same answers and the same
  exception texts", `ISecretLookup.cs:6-7`) gains: except `:discarded`, which `SecretsDb` refuses (design round 8, MiMo M-6).
- `run` needs nothing else: its burned warning and its masking label come from the token (`RunCommand.cs:150-155`,
  `:179-193`). The broker is unchanged (it serves names, not tokens).
- An entry without a set, used: `run` adds the set it computes from the decrypted value to that command's matcher
  before the child starts (`VaultView` returns it with the value through a new `internal FingerprintSet? ComputedSet(string token)`;
  `run` builds its matcher with it); nothing is written.

**`--stamp S`** (shared, `ValueLineage.cs`: `public static IReadOnlyList<DiscardedValue> Select(ValueLineage, string name, string? stamp)`):
`<ms>.<logical>@<8 hex>` or `@<32 hex>`, hex in either case, the HLC part by `Hlc.TryParse` (`Hlc.cs:61-70`). It must
match exactly one entry. Texts (the stamp shown through `Validation.Printable`):
- not a stamp: `'--stamp S' is not a stamp: give it as 'tswap conflicts x' prints it (<ms>.<logical>@<8 hex digits>) or in full (@<32 hex digits>).`
- two 8-hex matches: `Two values of 'x' match the stamp S; give it in full, as 'tswap conflicts x --json' shows it.`
- none: `No discarded value of 'x' has the stamp S; see 'tswap conflicts x'.`

**`TswapCli/Commands/ConflictsCommand.cs`**, registered after `burned` (`CommandRegistry.cs:32`): `Name` `conflicts`,
`HelpUsage` `conflicts [name] [--json] | --ack <name> [--stamp S] [--by LABEL] | --clear <name> [--stamp S]`, `RequiresSudo`
false, `Description` `List values a merge set aside, without the values; --ack quietens one, sudo --clear drops it`.
- Listing (no sudo, `ctx.OpenVault`, `LoadAll(FormatTwoRecords.Decode)`, decrypts no value): one block per secret with
  entries, ordinal, blank line between; R10's lines:
  ```
  sync-conflict-test
    current    2026-11-14T16:20:20Z  machine c7cad1d5
    discarded  2026-11-14T16:20:16Z  machine 5d918462 (this machine)  stamp 1794673216219.0@5d918462 (open)
  ```
  Status: `(open)`, `(open on this machine; acknowledged on machine c7cad1d5 at <time>)`,
  `(acknowledged <time>, machine c7cad1d5, by owner)` (`, by …` only with a label; the newest acknowledgement),
  `(open: its retirement may have been forgotten)`, then ` (from before 'x' was deleted)` for an earlier-life entry;
  before it, in order: ` [BURNED 2026-11-15T09:12:00Z: <reason>]` (`: <reason>` only with one), ` [not fingerprinted]`,
  ` (same value as the current value)` / `previous value` / ` (replaced knowingly by a later value)` for `"superseded"`. A tombstone: header `x (deleted)`, no `current` line. Then
  `N open conflict(s).` (`1 open conflict.`, `2 open conflicts.`; open = `Warns`), then the four hint lines of the
  design §1.9 naming the secret when one is listed, `NAME` otherwise. None: `No value conflicts.` / `No value conflicts for 'x'.`;
  a name with no record, or a tombstone without entries: `Secret 'x' not found` (exit 1).
- `--json`: `ConflictsReport(int Open, List<ConflictJson> Conflicts)`, `ConflictJson(string Name, bool Deleted,
  ConflictVersionJson? Current, List<DiscardedJson> Discarded)`, `ConflictVersionJson(string Stamp, string Machine,
  bool ThisMachine, string Time)`, `DiscardedJson(string Stamp, string Machine, bool ThisMachine, string Time, bool EarlierLife,
  bool Burned, BurnJson? Burn, bool Open, bool Fingerprinted, string? SameAs, List<AckJson> Acknowledged)`,
  `BurnJson(string Time, string? Reason)`, `AckJson(string Time, string Machine, string? By)`; `Stamp` in full
  (`<ms>.<logical>@<32 hex>`); `Open` false for a silent entry, and the report's `Open` counts `Warns` only; nullable
  properties written as null (R9).
  Registered in `CliJsonContext`.
- `--ack NAME` (no sudo, owner decision 2): `--by` through `FieldWhoSource.ValidateBy` plus R5; `ctx.OpenVaultForWrite`,
  `Acknowledge`, `Commit`. Output `✓ Acknowledged 1 value of 'x' that a merge set aside. It is kept until 'sudo tswap conflicts --clear x' or 'sudo tswap restore x --discarded'.`
  (`2 values`); none named: `No open value conflicts for 'x'.`, exit 0, nothing written.
- `--clear NAME`: `ctx.RequireSudo("conflicts --clear")` first (`CommandContext.cs:454-466`), then `ClearDiscarded`.
  Output `✓ Dropped 1 value of 'x' that a merge set aside, for good: a copy on another machine that still holds the same value doesn't bring it back. Only an older file put back from before this clear (a sync restore) can, as any rolled-back change can, or a stale copy after 64 later drops on this secret, or a merge done by an older tswap; in those cases tswap warns about it again. A machine that still holds this value as its current value (it hasn't merged yet) loses it too, with no warning there: check 'tswap conflicts x --json' on each machine before clearing.`
  (`2 values`); none: `No value conflicts for 'x'.`, exit 0, nothing written.
- Both work on a tombstone. Usage errors and refusals exit 1. No mode decrypts a value.

**`field adopt`** (design §1.7, round 8, Claude I-6): it deletes SECRET (`FieldCommand.cs:309`), so after the "fields of
its own" check (`:280-283`) and before it resolves the value (`:286`), it refuses a SECRET whose `writer.Record(secret)`
holds entries: `'<secret>' has <n> value(s) a merge set aside; see 'tswap conflicts <secret>', then clear or restore them before adopting it.`

**`restore --discarded`** (`RestoreCommand.cs`): `restore <name> [--discarded [--stamp S]]`; `HelpUsage` the same.
`VaultWriter.RestoreDiscarded(name, stamp, ctx.Time.GetUtcNow().UtcDateTime)`, `Commit`. Output
`✓ Secret 'x' restored to the value machine 5d918462 wrote at 2026-11-14T16:20:16Z, which a merge had set aside (a new version; the value it replaced is now the previous one).`
(on a tombstone: `… set aside (the secret is back).`), then today's burn and "external system" lines (`:36-38`). Plain
`restore` unchanged.

**`delete`** (`DeleteCommand.cs:32-35`; the count from `writer.Record(name)` before staging): after `✓ Secret 'x' deleted`, when it had entries: `It also dropped 1 value set aside by a merge; it can no longer be restored.`
(`2 values set aside by a merge; they can no longer be restored.`).

**`export`** (owner decision 3): `Secret` gains `[JsonIgnore] public int DiscardedCount { get; init; }` (from
`SecretInfo`, which gains `int DiscardedCount = 0` set in `From`; `ToSecret`, `:1105-1125`, carries it; no entry decrypted).
`ExportCommand` after the file is written, on stderr: `Warning: 1 secret has a value a merge set aside (x); this export doesn't include it, nor the record's lineage of dropped values, so after an import a value dropped earlier can come back from a stale copy. Restore or clear it first if it matters.`
(`2 secrets have values … (a, b); this export doesn't include them, nor …`).

Regenerate the generated block of `docs/commands.md` in this commit (`TSWAP_REGENERATE_DOCS=1` on
`CommandReferenceIsCurrent`).

Tests, `TswapTests/ConflictsCommandTests.cs` and `TswapTests/DiscardedTokenTests.cs` (the `RunEnvTests` `RecordingPty`
harness and value recorder; `FleetMachine.Time` fixed; T58's SHA1 URI at 1111111111.5 s):

| Steps | Outcome |
|---|---|
| the issue case, then `conflicts --json` on B | `open` 1; the entry's machine A's; full stamps |
| `run test '{{sync-conflict-test:discarded}}' = from-a` | exit 0; exactly one value section decrypted, the entry's |
| `{{sync-conflict-test:previous}}` | the original value |
| the child prints `from-a` | `[REDACTED: sync-conflict-test:discarded]` |
| `conflicts --ack sync-conflict-test --by owner`, sync | no warning on A or B; `conflicts` shows acknowledged, `by owner` |
| `conflicts --clear` without sudo | refused ("requires sudo"), the record file unchanged |
| `sudo restore sync-conflict-test --discarded` | current `from-a`, previous `from-b`, no entry; no warning on B after a sync |
| three machines, two entries: `{{x:discarded}}`; `restore --discarded` without `--stamp`; with each `--stamp` | the two refusals; `--stamp` picks one |
| `--stamp` with two entries sharing the 8-hex prefix at one HLC, for `restore --discarded`, `--ack`, `--clear`; a malformed stamp; an unknown one | the ambiguity text for 8 hex, the full form picks one; the not-a-stamp and none texts |
| a discarded otpauth value: `{{t:discarded}}` | child `050471`; URI and seed in neither argv nor output |
| `{{t:discarded:totp}}` | T58's unknown-suffix text |
| the child prints the discarded seed in each spelling T58's `StoredForms` lists | each `[REDACTED: t:discarded]`; a hex key line unmasked |
| a discarded bare Base32 value, `{{t:discarded}}` | the stored text, as `{{t}}` gives for one |
| an unusable discarded otpauth value | the refusal naming `restore t --discarded` |
| `{{x:discarded}}` through `SecretsDb.ResolveToken` | its refusal |
| A and B rotate from `v0`; B folds; A rotates again before its folder merges; B rotates; full sync | both of A's values entries on both machines; `conflicts` two entries |
| `{{x:discarded}}` on a tombstone with an entry; `restore --discarded` there | the tombstone text; the secret back |
| B clears `a`; A, never merged, holds `a` current; full sync (and the same after A burned `x`) | `a` gone everywhere, no warning |
| A, B, C: `a` set aside; C acknowledges; B clears; A unchanged; full sync, in each machine order | `a` gone, the same files everywhere |
| a clear on a first-value record, then a stale copy holding the entry; `restore --discarded` likewise | the entry doesn't come back |
| `restore --discarded`, `burn`, `restore` | the discarded value burned and kept as the previous value |
| `--clear` and `--ack` on a tombstone | both work |
| `--ack` twice; `--clear` twice | the second writes nothing, exit 0, the texts above |
| an entry without a set; one whose section can't be decrypted | ` [not fingerprinted]` in `conflicts`; the unreadable text from `{{x:discarded}}` and `restore --discarded`, nothing written; `--clear` works |
| `run` with `{{x:discarded}}` of a set-less entry, the child prints it | masked; the set stored at the next value write |
| a burned entry in `conflicts` and `--json`; `{{x:discarded}}` of it | ` [BURNED <time>: <reason>]`, `"burn"`; `run`'s burned warning naming `x:discarded` |
| a discarded burn pushed out of the record's burn list by 16 later burns | the entry keeps its burn; the warning still given |
| `export` with an open entry; that export imported | the warning names the secret; no entry decrypted (`ValueDecrypted`); imports without it |
| `delete` of a record with an entry | the delete line |
| `sudo get x` | the current value, unchanged |
| T58's `Rotate_DecryptsOnlyTheCurrentValue` scenario on a record with entries | still one value decrypted |
| `vault merge` and a full load of a record with entries | no entry decrypted |
| **absence sweep**: every new command and mode, every new warning and refusal, on inert markers | no marker value, seed or URI on stdout or stderr, whole or in any `Redaction.Variants` form (`Redaction.cs:22`) |
| `--by` of 65 characters; of 64 four-byte characters | the fields text; R5's text |
| an entry from before a delete and re-creation (earlier life): `{{x:discarded}}`; `sudo restore x --discarded`; `get x`; `conflicts` and `--json` | the earlier-life refusal; restored; the earlier-life warning; ` (from before 'x' was deleted)`, `"earlierLife": true` |
| the same with one earlier-life and one current-life entry, `{{x:discarded}}` | the "2 values" text |
| a record re-created by v0.3.0 (no `Fields` extension) holding an entry from before the delete | treated as current-life (documented) |
| `sudo field adopt n f --from s` where `s` holds an entry | refused with the adopt text, nothing written, `s` still there |
| `conflicts` text of a secret with one open and one acknowledged entry | each status at the end of its line; the header the name only |
| `conflicts` of a secret with only silent entries; `--json` | listed with their reasons; `0 open conflicts.`; `"open": 0`, each entry `"open": false` |

Break-it-once: strip `:discarded` before the inner lookup (the `= from-a` row gets `from-b`); let `{{x:discarded}}`
bypass `CommandValues` (the TOTP row gets the URI); drop `RequireSudo` from `--clear` (its refusal row fails); drop the
`Since` comparison (the earlier-life row gives the value); drop the adopt check (the adopt row deletes `s` and its
entry).

## Task 6: docs (last)

- **`docs/commands.md`** (prose; the block was regenerated in Task 5): a section "Values a merge set aside": when a
  value is kept (§1.1, with the three documented misses: the D2 and `exactFrom` misses, and past 64 rotations or
  retirements), the warning, `[CONFLICT]`, `conflicts` and its modes, `restore --discarded`, `{{name:discarded}}` and
  `# tswap: name:discarded` (one entry; TOTP gives its code; no `:discarded:totp`; `check` doesn't test that an entry
  exists), the `--stamp` forms, the masking label, the cap, and burning a discarded value (`sudo tswap restore x
  --discarded`, `tswap burn x "<reason>"`, `sudo tswap restore x`); the `--clear` text's sentence; silent entries
  (the three reasons, listed but not counted); earlier-life entries (only `restore --discarded` brings one back; a record
  re-created by v0.3.0, which has no `Fields` extension, can't tell them apart); `field adopt` refusing a secret that
  holds entries; the newer-format refusal; that a machine still holding a cleared value as its current value loses it
  too, with no warning there, so check `tswap conflicts --json` on each machine before clearing; that a discarded bare
  Base32 seed is handed out as its text (store TOTP seeds as otpauth URIs); that on a record re-created by v0.3.0
  `{{x:discarded}}` can hand out a value from the deleted life without sudo.
- **`docs/multi-machine.md`**: "The merge rules" (`:456`) gains a bullet that a merge keeps a concurrent value it
  discards (a pointer to commands.md) and a "Mixed versions" paragraph like the fields one (`:482-489`): a 0.3.x merge
  can still drop a value and a discarded version's burn; a merge here can miss a value on a record whose lineage an
  older build wrote; a value rotated away on 0.3.x can be reported once (both residuals named); a tombstone without an
  exact lineage reports any copy that still holds the deleted value, a `vault merge` of a backup from before the delete
  included; a folder with 0.1 machines writes records with entries or retirements in format 3, while a record with only
  `S` is written in format 2 and drops its lineage (exactness traded for 0.1 readability). Then, **numbered**:
  "Upgrading a shared folder: 1. Upgrade every machine that shares the folder. 2. Then run `tswap conflicts` and deal
  with what it lists. Until a machine running this release writes a record, an older tswap's fold of its conflicted
  copies can drop a set-aside value with no warning anywhere." And the caps' arithmetic: `S` and `T` keep 64 stamps
  over a record's whole life, so a secret rotated daily passes 64 rotations after about two months, after which a copy
  more than 64 rotations stale may be kept or dropped depending on merge order. The provider row (`:592-596`) gains: a
  metadata-only write that grew by at least one 256-byte bucket can mean a conflict was kept.
- **`docs/security-model.md`**, "What each command decrypts" (`:209`): `export`, `vault merge`, `migrate`: no entry;
  `run` with `{{x:discarded}}`: that entry only; `restore --discarded`: that entry only; `vault reindex`: entries without
  a current set; value writes: that record's entries without a set; `conflicts` (every mode), `burn`, field writes: none.
  One paragraph: an entry is sealed under its own version's key and never decrypted by a merge; `names` decrypts it
  with the metadata, not its value, so its metadata decrypt cost scales with the discarded values' sizes (up to the
  64 KiB cap per record).
- **`TswapCore/Prompt.cs`** (ASCII, `Prompt_IsAsciiOnly`): in "Commands you SHOULD use", after `burned`:
  `` `%CMD% conflicts [name]` - Lists values a merge set aside (no values shown). On a merge warning, tell the user what it says and that `%CMD% conflicts` has the details; never acknowledge, clear or restore one unless the user asks. ``
  The `names` bullet: `[CONFLICT]` marks them.
- **AGENTS.md**: `conflicts [name] [--json]` and `conflicts --ack <name>` in the No-sudo list (`AGENTS.md:115`);
  `conflicts --clear <name>` and `restore <name> --discarded` in Requires sudo (`:123`); one sentence in "Token
  Substitution" for `{{name:discarded}}`.
- **Release notes** are the controller's. Lines for the controller: a merge now keeps a concurrent value it would have
  dropped, warns, and `tswap conflicts` lists it; `{{name:discarded}}`; 0.3.x machines still drop such values in their
  own merges; export leaves them out; **upgrade every machine, then run `tswap conflicts`** (the two numbered steps).
  And the release check (design "Briefs"): the v0.3.2 binary on a copy of a vault
  this build wrote (`names`, `run`, a rotate, a merge of a conflict copy), recorded in the PR.

## Out of scope

Part 2 (#197: floors, rollback warnings and refusals, `accept-rollback`, `restore-slots`, R4's gone-entry check, and
the cap text's "accept it first"); changing who wins a merge; a history of values beyond one previous; version
vectors; a combined `:discarded:totp` suffix; the broker serving discarded values; masking discarded values on 0.3.x;
a `burn` of a discarded version in place (the restore, burn, restore sequence covers it).
