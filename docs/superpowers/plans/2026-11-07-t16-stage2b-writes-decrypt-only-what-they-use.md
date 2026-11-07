# T16 Stage 2b: the write commands decrypt only what they use (issue #220)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or
> superpowers:executing-plans). Every task is TDD: the named tests first, watched failing for the
> stated reason, then the production change.

**Plan review round 1** (MiMo, DeepSeek: request changes, no Blocking). Every finding is fixed in
place, none declined:
- *MiMo I-1 / DeepSeek I1:* the zero-decryption claim is qualified in the Goal, the decryption
  section, the per-command table and the AGENTS.md sentence (revised; owner re-confirmed,
  decision 7). Three exceptions, each confined to the written record:
  - `add`'s comparison fallback, which is real in mixed fleets: the "unreachable" claim is dropped;
  - a copied version without a fingerprint set;
  - copies that only plaintext can merge, which makes `restore` 2 values there, not 1.
  `add` joins difference 2, as does the `create`/`ingest` refusal reason on a damaged record. The
  `add` fallback was put to the owner and accepted (decision 6).
- *DeepSeek I2 / MiMo M-6:* one stated rule for unreadable targets (`Find`, the staging methods,
  `Commit`), with command-level tests for `burn` and `add`.
- *DeepSeek I3:* task 10's scan now covers only the write commands' own files. Checked: `VaultCommand.cs:118`
  does call `LoadSecrets`, so the old allow-list would have failed on correct code.
- *MiMo M-1:* task 2's property test also runs on random raw copy sets: the metadata merge equals
  `MergeAll` or refuses, which takes the fallback.
- *MiMo M-2:* difference 1's other warnings and the target's own warnings, and difference 5's `burn`
  half, now have named tests.
- *MiMo M-3:* every command-level decryption test also reads the write back.
- *MiMo M-4:* task 2 starts with a golden test of today's `SaveSecrets`, recorded before the
  extraction.
- *MiMo M-5 / DeepSeek M2:* task 10 has a Break.
- *DeepSeek M1:* `FormatTwoDecoded` counts format 2 records only.
- *DeepSeek M3:* the probe's no-value claim is backed by code evidence and a test.
- *MiMo checklist 1 and 2:* file ownership and modes are named; "all-or-nothing" is scoped to
  refusals.
- *MiMo nit:* signing is named by its issue, #240, throughout.

**Goal.** No write command decrypts a value it doesn't use (owner, 2026-11-07, binding: "unlocking
all secrets is bad practice"). On format 3 records `create`, `ingest`, `ingest --rotate`, `rotate`,
`burn`, `delete`, `add` and `import` decrypt **no** vault value, and `restore` decrypts exactly one
(the previous value it puts back), except where the written record itself can only be decided or
merged by its value. Those exceptions decrypt that one record's values only:
- `add` over a secret whose stored fingerprint set is of another variant-set version, or missing,
  compares that current value (1);
- a retained version without a fingerprint set is fingerprinted from its own section (1);
- a record whose conflicted copies only plaintext can merge is decoded whole (its versions; for
  `restore` that is 2, not 1).
Each command reads only the record(s) it writes (metadata sections; a
folder probe of one metadata section on a vault without the format marker). A format 2 record is
decoded whole, only when it is the one being written, with Stage 2's warning discipline. Merge
semantics, the stale-write guard, the HLC rules and the on-disk formats are unchanged. Target
v0.3.0, after Stage 2 (PR #268).

**Why.** Every write command loads the whole vault and saves it whole: `ctx.LoadSecrets`
(`TswapCli/CommandContext.cs:309-310` → `RecordVaultStore.LoadSecrets`, `TswapCore/RecordVaultStore.cs:486`,
which decodes every record with `DecodeFull`, `:929`) and `ctx.Storage.SaveSecrets`
(`RecordVaultStore.cs:1090`): `CreateCommand.cs:50,59`, `IngestCommand.cs:31,47`,
`BurnCommand.cs:21,37`, `RotateCommand.cs:32` + `SecretRotation.cs:46`, `RestoreCommand.cs:27,40,42`
(a second full load just to print the burn line), `AddCommand.cs:30,33`, `DeleteCommand.cs:22,31`,
`ImportCommand.cs:63,93`. `SaveSecrets` needs the whole database because it diffs it against every
loaded record (`:1113-1172`), turns any missing name into a tombstone and refuses more than one
(`:1096-1100`), compares values to decide on a new version (`:1122`), and takes its HLC from every
record seen (`_highestSeen`, `:69`, raised by `ObserveAll`, `:1082`). Yet it only ever writes the
record(s) the command changed.

**Source of truth.** Spec `docs/superpowers/specs/2026-11-01-import-story-design.md` (Stage 1 record
format v3, nonce ruling, merge rules, mixed fleets; the 2026-11-07 Delivery amendment). Stage 2's plan
`docs/superpowers/plans/2026-11-07-t16-stage2-redact-without-decrypting.md` ("The store API",
"Behaviour differences", "Stage 2b"). Stage 1/2 commits: `git log --oneline --grep 'T16-S[12]'`.

## Scope: every command that still loads or saves the whole vault

| Caller | In 2b? | Why |
|---|---|---|
| `create`, `ingest`, `ingest --rotate`, `rotate`, `burn`, `restore`, `add`, `delete`, `import` | **Yes** | Each writes one record (import: each record it adds), so it needs only that record. |
| `export` (`ExportCommand.cs:43`) | No, kept | It writes every value into the backup: it must read every value by its nature. |
| `run` (`RunCommand.cs:72`) | No | Stage 3 (`feat/t16-stage3` already moves it to `ctx.OpenVault`). |
| `migrate --to-records` (`RecordMigration.cs:125`, `:163`, `:398`) | No | Reads a **classic** vault (`Storage.LoadSecrets`, one encrypted file, all or nothing, `Storage.cs:124`), writes a snapshot into an empty folder and reads the whole copy back to verify it. Conversion of every value by nature. |
| `vault merge` (`VaultCommand.cs:118-125`) | No (owner) | Not "by definition" (Stage 2's plan says so, see Corrections): two format 3 folders could merge on metadata. But `MergeRecords` merges plaintext states (`RecordMerge.MergeAll`, `:1480`), the metadata merge can refuse where the full one merges (Stage 2 difference 10), and a merge into an unmarked folder writes format 2, which needs plaintext. Sudo, administrative, touches every record. Follow-up issue #271 (owner decision 2). |
| `vault reindex` (`VaultCommand.cs:179` → `Reindex`, `:1027`) | No (owner) | Converts format 2 records, which needs their values. It also decodes already-current format 3 records whole (`LoadRecords` → `DecodeFull`) though it rewrites none of them (`IsCurrent`, `:1060`): avoidable, follow-up issue #271 (owner decision 2). |
| `slot …`, `recover`, `init`, `yubikey`, `agent`, broker | No | They write no record (`SlotCommand.cs:198`: no `SaveSecrets`; keyring and `vault-password` only). The broker reads one record (`ReadSecretValue`, `:533`). |
| `SaveSecrets` itself (`IVaultStore.cs:34`) | Kept, unused by commands | The interface requires it, the classic store still has it, and it is the **oracle** for task 3's equivalence test (my call). `StaleWriteGuardTests` and `EmptySaveGuardTests` keep testing it unchanged. |

**Classic vaults:** unchanged. Every write command refuses when the store opens
(`CommandContext.Storage`, `CommandContext.cs:54-69`; `ICliCommand.WorksOnClassicVault`, `ICliCommand.cs:37`),
so the new code only meets a `RecordVaultStore`; `ctx.OpenVaultForWrite` throws a `TswapException`
on anything else (a guard, as `OpenVault` does, `CommandContext.cs:317`).

## What each write must decrypt (format 3), and why nothing else

Format 3 keys a value section by **its own version stamp** (`value key = HKDF(K_v, recordId ‖
versionStamp)`, `SecretRecordCodec.cs:76`; the AAD binds only magic, format, record id, role and that
stamp, `:889`), and the codec copies a held section byte for byte (`EncodeV3`, `:521-526`). So:

- **burn**: a burn entry and a new write stamp; every section and fingerprint set copied. 0 values.
- **delete**: a tombstone (no sections, no fingerprints, burns kept as history). 0 values.
- **rotate, ingest --rotate, add (changed value), import, create, ingest**: the new value is in the
  command's hands; it is sealed under the new version's key (encryption, not decryption). The old
  current version moves into the previous slot with its section and fingerprint set copied (already
  pinned: `RecordStoreV3Tests.Rotate_KeepsPreviousSectionBytes_AddsNewSection`, `:199`); an older
  previous is dropped with its section. **0 values.**
- **restore**: the previous value becomes the current one as a **new** version (it must out-stamp
  the current version on every replica: existence is the largest version stamp, `RecordMerge.MergeAll`,
  `RecordMerge.cs:104`), so its section, bound to the old stamp, can't be reused: the plaintext must
  be sealed again (`RecordStoreV3Tests.Restore_KeepsTheRestoredSectionBytes`'s summary, `:219-224`).
  **Exactly 1 value**, through `SecretEntry.DecryptValue(previous: true)` (fingerprint-checked,
  `RecordVaultStore.cs:710-718`). The replaced current value's section moves to the previous slot.
- **add over an existing secret** must know whether the value changed (`SaveSecrets`, `:1122`: same
  value, no write). Answered from the stored fingerprints (my call): equal when the stored current set
  is of `SecretVariants.CurrentSetVersion` and equals `Fingerprinter.Compute(newValue)`. Sound because
  every stored value is the UTF-8 encoding of a .NET string (`:1120`, `:1204`), on which UTF-8
  decoding (what `Fingerprinter.Compute` hashes, `Fingerprinter.cs:19`) is injective, and the plain
  variant's 128-bit HMAC decides. A set of another variant-set version (older: written by an older
  build in a mixed fleet, which Stage 2's `OlderVariantSet` note exists for; or newer: a later build),
  or none: that one current value section is decrypted and compared (1 value, only that record). A
  reindex removes the older case. Owner decision 6: accepted.
- **A copied version without a fingerprint set** (only planted records; v0.2+ always writes one):
  that section is decrypted to compute the set, as today's `PrepareV3` does from the full load
  (`:1586-1589`). Same behaviour, one value of the written record.
- **`create` and `ingest` on an existing name** decrypt nothing: existence comes from metadata.
- **Copies that only plaintext can merge** (`MergeAllMetadata` refuses, `RecordMerge.cs:246-248`,
  where `MergeAll` merges): the write falls back to decoding **that record** whole, as today, and so
  still converges the copies, as `LoadMetadata`'s own warning promises ("a full load (any command
  that writes this record) may still be able to merge them", `RecordVaultStore.cs:1349`) and
  `docs/security-model.md` says ("A write of that record … converges the copies"). Both its versions
  are reported to `ValueDecrypted`; no other record's. For `restore` the previous value then comes
  from that decode, so the count is 2, not 1. No format 2 warning: the record is format 3.

"Decrypts" is a call of the `ValueDecrypted` seam (`RecordVaultStore.cs:138`), which fires at the
store's two value-decryption sites only: `OpenValueSection` (`:700`) and `DecodeFull` (`:937-943`).
Task 3 adds no third site. `RecordDecrypted` (`:132`, every metadata section too) proves the
metadata of the target **was** read, so a zero count can't pass on a command that read nothing.

## The store write API

All new code is in `TswapCore`; names below are binding where Stage 3 or tests depend on them,
otherwise the implementer's.

```csharp
// TswapCore/VaultWriter.cs (new): what the write commands use
public sealed class VaultWriter : IDisposable
{
    public SecretInfo? Find(string name);         // that record's metadata; null: none, tombstone, or unreadable (rule below)
    public void ThrowIfUnreadable(string name);   // SecretsDb.UnreadableRecordText(name, file) (Models.cs, Stage 2)
    public void SetValue(string name, string value, DateTime created, bool always = false,
                         DateTime? importedBurnAt = null, string? importedBurnReason = null);
        // SaveSecrets' new-version branch for one name (:1122-1154): writes when there is no live
        // record, when `always` (rotate, ingest --rotate), or when the value differs (add)
    public void Burn(string name, string? reason); // SaveSecrets' burn branch (:1155-1158); live, unburned only
    public void Delete(string name);               // the tombstone (:1167-1171)
    public void Restore(string name);              // ResolveToken(name:previous)'s errors, then one decrypt
    public IReadOnlyDictionary<string, SecretInfo?> Commit(); // guard every staged record, then write; the written states
    public int FormatTwoDecoded { get; }           // records with a format 2 file decoded whole (the warning's n);
                                                   // the copy-conflict fallback on format 3 records is not counted
    public void Dispose();                         // zeroes held sections, decoded format 2 values, plaintexts
}
// CommandContext.cs
public VaultWriter OpenVaultForWrite(byte[] key); // new VaultWriter((RecordVaultStore)Storage, key, Console.Error)
```

**Unreadable targets: one rule (DeepSeek I2, MiMo M-6).** `OpenForWrite` is called once per name and
its result cached: an entry, "no file", or "unreadable" with the hashed file name. For an unreadable
name:
- `Find` returns null, as `SecretsDb` does (`LoadSecrets` leaves unreadable records out,
  `RecordVaultStore.cs:494-496`), and `ThrowIfUnreadable` throws `SecretsDb.UnreadableRecordText`
  naming the file.
- `SetValue`, `Burn`, `Delete` and `Restore` stage **nothing** for that name and record the error.
- `Commit` throws the first recorded error in ordinal name order **before** any guard check or write,
  exactly as `SaveSecrets` throws `Unreadable` while building its writes (`:1117-1118`).
So an unreadable record is never skipped as absent and never overwritten. Commands keep today's
calls: `create`, `ingest`, `delete`, `burn` and `rotate` call `ThrowIfUnreadable` where they do
today, so they name the file before "not found" or "already exists"; `add` and `import`, which
today learn it only at the save, learn it at `Commit`.

**Staging, then one commit (my call).** Operations stage; `Commit` assigns stamps and writes. This
keeps today's guarantees exactly: (a) `import`'s all-or-nothing **refusal** (a crash in the middle of
`Commit` leaves the records written so far, exactly as today's `WriteRecords` loop does): every staged record is
re-read and compared before the first write (`WriteRecords` → `CheckUnchanged`, `:1534`, `:1647`), so a
changed record refuses the whole import with nothing written, as today; (b) stamp order: version and
burn stamps are issued per record in **ordinal** name order, then the write stamps in the same order,
exactly as `SaveSecrets` (`:1113`, then `WriteRecords`, `:1541-1545`), even though `import` iterates
in culture order (`ImportCommand.cs:66`, `OrderBy(kv => kv.Key)`); (c) an unreadable target is
recorded when opened and thrown at `Commit` (the rule above), so `import` prints its
"Skipped" lines in today's order before failing, as `SaveSecrets` throws only after the loop
(`:1117-1118`).

```csharp
// RecordVaultStore.cs (internal)
internal WriteSession BeginWrite(byte[] vaultKey);            // ReadMarker (warnings as today); _highestSeen = LastHlc; one ScanRecords()
internal SecretEntry? OpenForWrite(WriteSession s, string name); // below
internal IReadOnlyList<RecordMetadata> CommitWrites(WriteSession s, IReadOnlyList<PendingWrite> writes);
```

`OpenForWrite` is `OpenSecret(name, key, scan)` (`:563`) with four write-only additions:
1. every **authenticated** input's stamps are observed (`ObserveAll` on the full path as today,
   `:867`, `:916`; on the metadata path the same for each decoded metadata: write, version, burns),
   never a header that failed authentication (`UnauthenticatedHlcTests`);
2. an authenticated format 3 metadata section sets `_sawV3` (ruling 3; the read path doesn't need it);
3. a `RecordConflictException` from `MergeAllMetadata` (`:678-686`) falls back to `OpenFull`
   (`:633`) for that record instead of throwing;
4. the entry keeps the main file's bytes as read (the guard's reference, `LoadedRecord.MainBytes`,
   `:475`) and the copies folded into it with their bytes (removed after the write, `:1564-1565`).
   For parity with the full load it also writes, for **that record only**, the copy notes
   (`CopyNote`, `:824`) and the year-ahead warning (`YearAheadText`, `:816`) (my call).

`SecretEntry` gains internal accessors for those (the Stage 2 plan anticipated this:
"`SecretEntry` will need to expose its held sealed sections to the store internally").

**Two paths, one rule set.**
- *Whole-record path* (a format 2 file in the set, the copy-conflict fallback, or an unmarked folder
  writing format 2): the entry holds a merged `SecretRecord` with plaintext. `SaveSecrets`' per-secret
  body (`:1115-1160`) and tombstone body (`:1165-1171`) are extracted, behaviour unchanged, into
  `private static SecretRecord? NextRecord(SecretRecord? state, …)` / `Tombstone(…)`, used by both
  `SaveSecrets` and this path (a `csharp-refactoring` step, task 2). Encoding is today's
  `WriteRecords` (format 3 via `PrepareV3`, which seals what has no section, or format 2, `:1547-1561`).
- *Metadata path* (every file format 3): new `TswapCore/Keyring/RecordWrites.cs` applies the same rules
  to `RecordMetadata` + held sections (new version, burn, tombstone, restore), normalised by a new
  `RecordMerge.Normalize(RecordMetadata)` (`CanonicalBurns` + `TypeOf`, as `Normalize(SecretRecord)`,
  `RecordMerge.cs:59-64`). Encoded by a new codec entry (task 1):

```csharp
// SecretRecordCodec.cs
internal static byte[] EncodeV3(RecordMetadata metadata, IReadOnlyDictionary<Stamp, byte[]> sections, byte[] vaultKey);
// every retained version must have a section (new values are sealed by the caller with SealValue, :551);
// no plaintext parameter exists, so this path can't decrypt or re-encrypt a held section
```
`EncodeV3(SecretRecord, …)` (`:395`) becomes "seal the versions without a section, build the
metadata, call the overload", so there is **one** metadata encoder and the bytes v0.2 readers decode
can't drift. Task 3's oracle test holds the two rule sets equal.

`CommitWrites` is today's `WriteRecords` (`:1526`) generalised to take either form per record:
newer-marker refusal (`:1531`), `CheckUnchanged` over all (`:1534`), `TightenModes`, one write stamp
each (`:1543-1545`), copy removal (`:1564`), `AfterRecordWritten`, `LastHlc` saved (`:1570-1572`):
shared code, not copied.

**Which format a write produces (ruling 3, kept).** `WritesV3` (`:152`) is the marker or "this
command read a format 3 record". Today the full load reads every record, so any format 3 record in
the folder selects format 3 (`RecordStoreV3Tests.AnyV3RecordRead_WritesV3EvenWithoutMarker`, `:70`).
Per record, that is decided as (my call): the marker; else the target's own authenticated format 3
file; else, at `Commit`, a **probe**: the scan's files whose cleartext format byte is 3
(`SecretRecordCodec.FormatVersionOf`, `:232`), main files then copies in ordinal order, each until one
metadata section authenticates (`SecretRecordCodec.DecodeMetadataAndSections`, `:619`; each attempt
reported to `RecordDecrypted`). No value section is opened. In the code, `DecodeMetadataAndSections`
→ `ReadV3Metadata` (`:737-764`) decrypts only the metadata section. `FrameV3` (`:677-711`) slices the
value sections and returns them still encrypted. The store's `ValueDecrypted` seam is not reached on
this path. The implementer confirms this with `Unmarked_AuthenticatedFormatThreeRecord_SelectsFormatThree_DecryptingNoValue`
(task 3: `ValueDecrypted` empty, `RecordDecrypted` only the probed file). A file that fails authentication selects nothing
(`ADamagedFormat3File_DoesNotSelectFormat3`, `:111`) and is not warned about (it is not this
command's record). Invariant this relies on: when the folder writes format 2, no readable file of the
target is format 3, so the target is absent or format 2 and its plaintext is in hand.

## Per-command changes

| Command | Today | After (format 3) |
|---|---|---|
| `create`, `ingest` | full load; `ThrowIfUnreadable`, exists? (`CreateCommand.cs:52-55`, `IngestCommand.cs:41-44`) | `OpenVaultForWrite` → `ThrowIfUnreadable` → `Find` → `SetValue` → `Commit`. 0 values; existence from metadata (format 2: that record whole, warned). An existing name with a damaged value section now refuses as "already exists" (difference 2) |
| `ingest --rotate`, `rotate` | full load; `SecretRotation.Check` on `SecretsDb` (`SecretRotation.cs:20-40`) | `Check` on the writer's `Find`/`ThrowIfUnreadable` (same texts and order: not found, classic branch, sudo unless burned) → `SetValue(always: true)`. 0 values |
| `burn` | full load; already-burned check (`BurnCommand.cs:23-34`) | `Find`; null → `ThrowIfUnreadable` → "not found" (as today) → already burned? → `Burn`. 0 values |
| `delete` | full load; tombstone pass over every record | `Find` → `ThrowIfUnreadable` → `Delete`. 0 values; one tombstone by construction |
| `restore` | full load, `ResolveToken(name:previous)`, save, **second full load** for the burn line | `Restore` (same errors) → `Commit`; the burn line from the written state. 1 value (2 under the copy-conflict fallback) |
| `add` | full load; save writes only if the value changed; an unreadable target refused at the save with the file named (`:1117-1118`) | `SetValue` (fingerprint comparison) → `Commit` (an unreadable target refused there, same text). 0 values; 1 (that current value) when the stored set is of another variant-set version or missing (owner decision 6) |
| `import` | full load; skip existing live names; save | per name in today's order: `Find` (skip as today when non-null) → `SetValue(importedBurnAt…)` (stages nothing for an unreadable name) → one `Commit` (throws the first unreadable name). 0 vault values (the export file's values are read, by nature) |

The other rows (`rotate`, `delete`) decrypt nothing beyond the record-level exceptions in the Goal,
which apply to every row. Every one prints `FingerprintTexts.WarnFormatTwo(…, writer.FormatTwoDecoded, FormatTwoUse.Write)` in a
`finally` after its output, as `get` does (`GetCommand.cs:29-32`). New text (my call, count and fix
only, Stage 2's discipline): `Warning: {n} of the records written here were stored in the old record
format 2, which tswap can only decrypt whole; the value versions not needed were wiped. Ask the user
to run {fix} once to convert the vault.` The agent prompt needs no change: rule 11 already covers any
command that "prints a warning about the old record format 2" (`TswapCore/Prompt.cs:86-87`).

## Format 2 records and mixed fleets

- **A write of a format 2 record** decodes that one record whole (the only way to read it; existence
  and type are inside its single payload), reports both its versions, wipes what isn't written on
  dispose, and warns. The folder decides the output: unmarked (format 2 everywhere) → format 2, so
  v0.1.x machines keep reading it; marked (or any authenticated format 3 record) → format 3, the
  record converted (both values sealed once, as `PrepareV3` does today, `:1591-1604`).
- **No format change.** 2b writes byte layouts v0.2.0 already writes (one encoder, task 1), so
  v0.2.x machines read everything 2b writes, and v0.1.x machines read the format 2 it writes and fail
  closed on format 3 without deleting or overwriting it (Stage 1, commit ab1f2ad,
  `NewerFormatRecordTests.OlderBuild_NeverDeletesOrOverwritesANewerFormatRecord`). No dual-write, no
  overlap rule: no field changes meaning.
- **Edits through older machines.** Today's `SaveSecrets` also writes only changed records; 2b writes
  the same records with the same per-record guard, so an edit an older machine makes to **another**
  record is never touched, and one it makes to the **same** record between this command's read and
  write is refused (`changed on disk`), as today. Nothing older machines write can be lost that isn't
  lost today.

## Preserved guarantees, and how

| Guarantee | Today | Kept by |
|---|---|---|
| Stale-write guard per record | `CheckUnchanged` against the bytes loaded (`:1647-1656`, `GenerationGuard.CheckUnchanged`, `GenerationGuard.cs:52`) | the entry's main bytes; the same `CheckUnchanged` over every staged record before any write |
| Unreadable records never overwritten | `Unreadable(name, file)` (`:1513`) / `ThrowIfUnreadable` | `UnreadableRecordException` from `OpenForWrite` → `SecretsDb.UnreadableRecordText` (identical text to `:1513-1515`) |
| Newer-format records untouched | they are unreadable | same path (`CheckFormat` throws on a newer byte) |
| Conflicted copies folded, removed on that record's write | `FoldConflictCopies` + `RemoveRedundantCopies` (`:843`, `:311`) | the entry's folded copies (bytes compared before removal, as today) |
| Merge rules | `RecordMerge.MergeAll` | `MergeAllMetadata` (same rules on metadata, `RecordMerge.cs:188`), and `MergeAll` whenever only plaintext can decide |
| Marker rules | `ReadMarker`, `WritesV3`, newer-marker refusal | `BeginWrite` reads the marker (same warnings); probe above; refusal in `CommitWrites` |
| HLC per record, machine clock monotonic | `Hlc.Next(_highestSeen, now)` (`:1108`, `:1543`), `LastHlc` saved (`:1570`), `SaveConfig` keeps the max on disk (`:193-196`) | `_highestSeen` = `LastHlc` max the written record's authenticated stamps; same `Next`, same save. No rule compares stamps across records: `MergeAll` and `MergeAllMetadata` take one record's copies only (`RecordMerge.cs:100-102`, `:193-195`), and burns compare within one version |
| At most one delete per command | the empty-save guard (`:1096-1100`) | `Delete` stages one tombstone for one name; nothing else tombstones |
| Extensions survive | `Extensions = state?.Extensions` (`:1151`) | carried in `RecordMetadata.Extensions` |
| File ownership and modes under sudo | `TightenModes` before the first write (`:1613`), every file through `DirectoryOwnerMatcher` (`_owner.WriteDurable`, `:1562`; `WriteMachineConfig`, `:230-240`) | the same `CommitWrites` code; no new file or temp path. `RecordStoreFileLayerTests` (`UnderSudo_EveryRecordKeyringBackupAndTempFolderWrite_IsDoneAsTheFoldersOwner`, `NewFoldersAre0700_AndFiles0600_UnderUmask0`, `AVaultWithWiderModes_IsTightenedOnTheNextWrite_…`) stay green; task 6 adds `burn` and `delete` to the first one's commands if it doesn't run them |

## Behaviour differences from today

1. **Warnings about records a write doesn't touch** (unreadable records and their count, copy notes,
   unusable copies, year-ahead stamps) are no longer printed by write commands; those about the
   written record are, with the same texts. Marker warnings and the permissions notice unchanged.
   (Stage 2 difference 6, for writes.)
2. **A format 3 record with a damaged value section or fingerprints that don't match its value**:
   `burn`, `rotate`, `ingest --rotate`, `add` (a changed value, or a same value its fingerprints
   confirm) and `delete` now succeed on it (sections and sets copied forward byte for byte; a delete
   drops them). Today the full load marks it unreadable (`RecordMerge.ValidateFingerprints`,
   `:880-881`; a failed section, `DecodeV3`) and they refuse. `create` and `ingest` on its name now
   refuse with "already exists" instead of the unreadable-record text.
   Whoever uses that value still fails closed, naming the file (`get`, `apply`, `run`, `restore` of
   that version, through `OpenValueSection`'s authentication and fingerprint check). Detecting it
   needs the value, which these commands must not decrypt. (Owner decision 1: accepted; `add` and the
   `create`/`ingest` refusal reason, added after review round 1, re-confirmed in decision 7.)
3. **HLC reach.** A write's stamps exceed `LastHlc` and the written record's stamps, no longer every
   stamp in the folder. A machine whose clock lags another's now stamps its writes with its own time
   (shown as `Modified`/burn time) unless the record itself carries a later stamp, and `LastHlc` no
   longer absorbs unrelated records' (absurd) stamps. Ordering within a record, the only ordering the
   merge uses, is unchanged. (Owner decision 4: accepted; pinned by
   `Hlc_UnrelatedFutureRecord_DoesNotRaiseTheStamp`, task 3.)
4. **Unmarked folders: what selects format 3.** An authenticated format 3 metadata section, where
   today a whole decode was needed; so a format 3 record with an intact metadata section and a damaged
   value section now selects format 3. Such a file was written by tswap ≥ 0.2 under this vault's key.
5. **A record whose stored bytes aren't the UTF-8 encoding of a string** (only planted; every write
   path stores `Encoding.UTF8.GetBytes(string)`) is no longer rewritten by unrelated writes: today
   `SaveSecrets` round-trips every value through a string and compares (`:1120-1122`), so each write
   command re-versions such a record with U+FFFD-mangled bytes, and `burn` of it writes a new version
   instead of a burn. Fixed as a side effect.
6. `restore` no longer reloads the vault to print its burn line (output unchanged).
7. Write commands print the format 2 warning when they decoded a format 2 record (new stderr line;
   exit codes unchanged).
8. **`sudo tswap add` warns about a value ending in whitespace** (owner decision 5, task 11): a new
   stderr line, no refusal, exit code unchanged.

No other observable change: texts, exit codes, sudo rules, file contents (up to random nonces) and
stamps (for a single-origin history) are pinned by the oracle and the existing tests.

## Tasks

Tests named per task; "Break:" is the production change that must make the task's key test fail (done
once, reverted, reported in the commit message). Fixtures: `InitRecordVault` (format 3, marked) and
`InitFormatTwoVault` (`RecordVaultTestSupport.cs:38`, `:46`); spawned `tswap init` passes
`--no-recovery` or `--recovery-key-out` (#253, as Stage 2's plan says). Decryption is watched through
`FleetMachine.StoreOpened` (`FleetMachine.cs:84`).

1. **Codec: format 3 from metadata and held sections** (`SecretRecordCodec.cs`). New tests in
   `SecretRecordCodecV3Tests`: `EncodeFromMetadata_DecodesToTheSameState` (a record encoded both ways:
   `Decode` gives `SameState`, the held sections byte-identical in the output);
   `EncodeFromMetadata_CopiesSectionsByteForByte`; `EncodeFromMetadata_MissingOrUnlistedSection_Throws`;
   `EncodeFromMetadata_OpaqueSections_NeverOpened` (sections of random bytes of a valid length: encoding
   succeeds, `DecodeMetadata` reads the metadata, opening a value fails: proof the encoder never touched
   them). Every existing `SecretRecordCodecV3Tests`/`SecretRecordCodecTests` test unchanged and green.
   Break: the overload seals a fresh section instead of copying (the byte-identical test fails).
2. **Rules on metadata, and `SaveSecrets`' body extracted** (`RecordMerge.cs`, new `RecordWrites.cs`,
   `RecordVaultStore.cs` refactor only).
   - **First, before any production edit (MiMo M-4):** `SaveSecrets_MatchesItsGolden`, committed
     green on today's code. A scripted history (fixed clock and origin; create, add of a same and of
     a new value, burn, rotate, restore of a burned previous, delete, re-create, import with a burn)
     driven through `LoadSecrets` + `SaveSecrets`. Every record's decoded state, minus the
     random-nonce section bytes, is compared with a checked-in golden file
     (a new `TswapTests/Fixtures/save-secrets-golden.json`, copied to the output as the signing branch does with its fixtures: stamps, types, burns, created, names, values,
     previous, fingerprints). The extraction must keep it byte-equal, so the oracle's reference
     can't move with the production code.
   - New `RecordWritesTests`: new version over a live record
   (previous section and set kept, older previous dropped, outstanding burn becomes history), over a
   tombstone (created time from the input, burns kept, no previous), burn (a burn of the current
   version, sections untouched), tombstone (no sections or sets, burns as history), restore (the
   restored version's burns re-issued on the new version with their original stamp and reason,
   `:1139-1141`; `FixRoundShouldFixTests`' equal-stamp case), imported burn (`:1143-1144`), extensions
   kept; `RecordWrites_MatchNextRecord_OnRandomStates` (seeded: for random merged states and operations,
   the metadata result equals `NextRecord`'s, converted with fingerprints);
   `MergeAllMetadata_MatchesMergeAll_OrRefuses_OnRandomCopySets` (MiMo M-1). Seeded: random raw
   copy sets of one record (diverging versions, burns, previous values, re-encrypted sections, with
   and without fingerprint sets). Either `MergeAllMetadata` equals `MergeAll`'s result converted to
   metadata (winner, burns, write stamp, extensions, chosen sections), or it throws
   `RecordConflictException`, which is exactly the case that takes the whole-record fallback; it
   never gives a different winner. `StaleWriteGuardTests`,
   `EmptySaveGuardTests`, `RotateTests`, `PreviousValueTests` unchanged and green (the refactor).
   Breaks: drop the restore burn re-issue in `RecordWrites`; change `NextRecord`'s created-time rule
   over a tombstone (the golden fails).
3. **Store write session** (`RecordVaultStore.cs`, `SecretEntry.cs`). New `RecordStorePerRecordWriteTests`:
   `Burn_FormatThree_ReadsOnlyItsRecord_DecryptsNoValue` (`ValueDecrypted` empty, `RecordDecrypted` is
   exactly the target file, every other file byte-identical, the target's sections byte-identical);
   `Guard_TargetChangedSinceOpen_RefusesWritingNothing` (another store writes it between open and
   commit: "changed on disk", records and `config.json` unchanged);
   `Guard_RecordCreatedElsewhereSinceOpen_IsNotOverwritten`; `Guard_Batch_OneChanged_NoneWritten`;
   `Copies_FoldedAndRemoved_OnlyForTheWrittenRecord`;
   `CopiesOnlyPlaintextCanMerge_FallBackToThatRecord_AndConverge` (Stage 2's difference 10 setup: the
   write succeeds, the copies are gone, `ValueDecrypted` names only that record's file, and
   `FormatTwoDecoded` stays 0);
   `UnreadableTarget_StagesNothing_CommitThrowsFirstInOrdinalOrder_BeforeAnyWrite` (two unreadable names
   and one writable one in one session: nothing written, the error names the ordinally first file); `Hlc_ObservesTheTargetsAuthenticatedStampsOnly` (a valid copy
   from a clock three days ahead: the new stamps order after it; a junk copy with a future header: no
   effect); `Hlc_UnrelatedFutureRecord_DoesNotRaiseTheStamp` (difference 3);
   `Unmarked_AuthenticatedFormatThreeRecord_SelectsFormatThree_DecryptingNoValue`,
   `Unmarked_DamagedFormatThreeFile_SelectsNothing`,
   `Unmarked_FormatThreeWithDamagedValueSection_SelectsFormatThree` (difference 4);
   `NewerMarker_RefusesBeforeWriting`. **The oracle:** `PerRecordWrites_MatchSaveSecrets_OnRandomHistories`
   (seeded, one machine, fixed `TimeProvider`: random sequences of create/ingest/add with same and new
   values/burn/rotate/restore/delete/import over two copies of one folder, one driven through
   `LoadSecrets` + `SaveSecrets` exactly as today's commands mutate the database, one through
   `VaultWriter`; after each step every record equal: `SameState` including stamps, retained values,
   held sections byte-identical where copied; run on a marked folder and on an unmarked format 2 one,
   and every written file decodes with `SecretRecordCodec.Decode`, v0.2's reader). Existing
   `RecordStoreV3Tests`, `RecordConflictTests`, `UnauthenticatedHlcTests`, `NewerFormatRecordTests`,
   `TimeProviderTests` green. Breaks: `CommitWrites` without `CheckUnchanged` (the guard tests); `OpenForWrite`
   through `LoadRecords` (the first test); the probe skipped (`AnyV3RecordRead_WritesV3EvenWithoutMarker`).
4. **`VaultWriter`, `OpenVaultForWrite`, the write warning** (`VaultWriter.cs`, `CommandContext.cs`,
   `FingerprintTexts.cs`). New `VaultWriterTests`: `Lookups_MatchSecretsDb` (random vaults: `Find`,
   `ThrowIfUnreadable` and `Restore`'s error texts equal `SecretsDb`'s from `LoadSecrets`);
   `Add_SameValue_ByFingerprints_DecryptsNothing_WritesNothing`;
   `Add_SetOfAnotherVariantVersion_DecryptsOnlyThatCurrentValue`;
   `Restore_DecryptsOnlyThePreviousSection` (exactly `(file, previousVersion)`);
   `CopiedVersionWithoutASet_IsFingerprintedFromItsSection` (planted; one decrypt, set present after);
   `Import_StampsInOrdinalOrder_SkippedLinesInCultureOrder` (names `B-x` and `a-x`);
   `FormatTwoWriteWarning_CountOnly` (a format 2 record and tombstone with distinctive names and values:
   the line equals the text with `n`, carries no name, value or hashed file name). Break: `SetValue`
   compares through `DecryptValue` (the first `Add_` test fails).
5. **`create`, `ingest`, `add`** (their commands). New `WriteCommandDecryptionTests` (format 3,
   `StoreOpened`): `Create_DecryptsNoValue`, `Ingest_DecryptsNoValue`, `Add_NewName_DecryptsNoValue`,
   `Add_ChangedValue_DecryptsNoValue`. Each asserts `ValueDecrypted` empty, `RecordDecrypted` only
   the target and every other record file byte-identical, **and reads the write back** (MiMo M-3):
   the value through `get`, `Modified` through `names`, and for `add` the old value now under
   `name:previous`. Further tests:
   - `Add_UnreadableTarget_RefusesNamingTheFile_WritesNothing`.
   - `Create_ExistingNameWithDamagedValueSection_RefusesAsExisting` (difference 2).
   - `Write_UntouchedRecordsWarnings_NotReported` (difference 1, MiMo M-2): an unrelated unreadable
     record, an unrelated conflicted copy (note), an unusable copy and a year-ahead record. Exit 0,
     and stderr carries none of their file names.
   - `Write_TargetsOwnWarnings_SameTexts`: the same four situations on the written record give the
     full load's exact texts. `RecordConflictTests.AnUndecryptableConflictCopy_IsWarnedAbout_AndKept_EvenAfterAWrite`
     also stays green.
   - `Write_UnrelatedNonUtf8Record_NotRewritten` and `Burn_NonUtf8Record_WritesABurn_NotANewVersion`
     (difference 5, both halves, planted with `SecretRecordCodec.Encode`). `RotateTests.CreateAndIngest_OnAnExistingName_RefuseAndPointToRotate`,
   `RecordConflictTests.ATruncatedMainRecord_FailsClosed`, `RecordStoreTests`, `TimeProviderTests`,
   `RecordStoreV3Tests` marker tests unchanged. Break: `create` calls `ctx.LoadSecrets`.
6. **`burn`, `delete`, `rotate`, `ingest --rotate`** (`BurnCommand.cs`, `DeleteCommand.cs`,
   `RotateCommand.cs`, `IngestCommand.cs`, `SecretRotation.cs`). Tests: `Burn_DecryptsNoValue`,
   `Delete_DecryptsNoValue`, `Rotate_DecryptsNoValue`, `IngestRotate_DecryptsNoValue`, each with a
   read-back (the burn in `burned --json`, the tombstone's record type, the previous value under
   `name:previous`); `Burn_UnreadableTarget_NamesTheFile` (command-level text); difference 2:
   `Burn_DamagedValueSection_Succeeds_GetStillFailsNamingTheFile`,
   `Rotate_FingerprintMismatch_KeepsItAsPrevious_RestoreFailsClosed`,
   `Delete_DamagedValueSection_WritesATombstone`, `Add_DamagedValueSection_NewVersion_KeepsItAsPrevious`. Existing `RotateTests` (sudo unless burned, nothing
   written on refusal, `LastHlc` unchanged), `EmptySaveGuardTests.Deleting*`, `RecordConflictTests`,
   `RecordStoreV3Tests.Burn_CopiesValueSectionsByteForByte` green. Measure `burn` on a 1,000-record
   vault before/after and record both times in the commit (no test). Break: `burn` opens its record
   through `OpenFull`.
7. **`restore`** (`RestoreCommand.cs`). `Restore_DecryptsOnlyThePreviousValue` (one `ValueDecrypted`,
   `RecordDecrypted` only the target, `get` returns the restored value);
   `Restore_CopiesOnlyPlaintextCanMerge_DecryptsThatRecordsTwoVersions` (exactly two, both of that file); `Restore_BurnLine_FromTheWrittenState` (output equal to today's
   for a burned and an unburned previous). `PreviousValueTests`, `RecordStoreV3Tests.Restore_KeepsTheRestoredSectionBytes`,
   `TimeProviderTests.Restore_WritesTheNewVersionsTime_FromTheTimeProvider` green. Break: the burn line
   from `ctx.LoadSecrets` again (the first test fails).
8. **`import`** (`ImportCommand.cs`). `Import_DecryptsNoVaultValue` (export of three, vault holding one
   of them live, one deleted, one absent: `ValueDecrypted` empty, `RecordDecrypted` only those three
   files; the absent and the deleted names read back with `get`, the live one unchanged);
   `Import_UnreadableTarget_RefusesWritingNothing` (today's text, file named, every record and
   `config.json` byte-identical, the earlier "Skipped" lines printed). `RecordStoreExportImportTests`,
   `FixRoundShouldFixTests` (import with `--include-burned` keeps the burn time) green. Break: import
   writes each record as it goes (the refusal test finds a written record).
9. **Every write on format 2 vaults** (no production code unless a test finds a gap). New
   `FormatTwoWriteTests` (`InitFormatTwoVault`): `burn`, `rotate`, `delete`, `restore`, `add` of a
   format 2 record report `ValueDecrypted` only for that record's files, write format 2 in the unmarked
   folder, and warn with `n = 1`; `Create_ExistingFormatTwoName_DecodesItToRefuse_AndWarns`; the same
   writes after `WriteMarker` convert that record to format 3 and leave every other format 2 record
   byte-identical. `RecordStoreV3Tests.NoMarker_WritesV2`, `V2CopyAgainstV3Main_MergesAndNextWriteIsV3`,
   `MarkerEmptyGarbageOrBelow3_WarnsAndCountsAsAbsent`, `MarkerConflictCopy_IsIgnored` green. Break: the
   warning printed with the record's name (`FormatTwoWriteWarning_CountOnly` and this class fail).
10. **Guard and docs.** `WriteCommands_DontUseTheWholeVaultApi` (my call; DeepSeek I3). A source
    scan of exactly the write commands' own files (`Create`, `Ingest`, `Burn`, `Rotate`, `Restore`,
    `Add`, `Delete`, `Import` in `TswapCli/Commands/`, plus `TswapCli/SecretRotation.cs`). None of
    them may contain `LoadSecrets(`, `SaveSecrets(`, `LoadRecordStates(` or `MergeRecords(`. The
    Scope table's whole-vault callers are out of the scan on purpose: `ExportCommand.cs:43`,
    `VaultCommand.cs:118` (`vault merge`, #271), `RecordMigration.cs:125,398` (outside `Commands/`)
    and `RunCommand.cs:72` (Stage 3). The behavioural counters are the proof; this keeps a later edit
    honest. Break: add `ctx.LoadSecrets(key);` to `AddCommand.Execute` (the scan fails). Docs: `docs/security-model.md` (the write-commands row of
    "What each command decrypts", `:121`, and the threat row's last sentence, `:87`), `docs/commands.md`
    (format 2 section, `:46-77`: writes too), `docs/release-notes/v0.3.0.md` (replace `:56-57` with a
    2b section listing the differences and the record-level exceptions), the spec's Delivery section
    (an "Owner amendment, 2026-11-07 (brief T16-S2b)" stating the write commands' minimum decryption,
    its exceptions and restore's one value), AGENTS.md
    `:203-207` (owner decision 3: the sentence given there). `TswapTests/Docs` green. No `Prompt.cs`
    change (rule 11 covers the warning).

11. **`add` warns about a value ending in whitespace** (owner decision 5; `AddCommand.cs`,
    `Validation.cs`). Today `add` stores the value exactly as typed or piped (`SystemConsole.ReadPassword`,
    `TswapCli/SystemConsole.cs:17-59`, trims nothing; `AddCommand.cs:22-32`). New
    `Validation.EndsInWhitespace(string)` (last character `char.IsWhiteSpace`; false for an empty value).
    After its success line, `add` writes to stderr (my call on the wording):
    `Warning: the value of '{name}' ends in whitespace (or is only whitespace). That is usually a paste
    mistake, and 'run' can't always mask such a value in a command's output. If it wasn't meant, run
    {fix} again.` (`{fix}` = `ElevatedCommand.For(prefix, $"add {name}")`, `ElevatedCommand.cs:13-16`.)
    It names the secret and the reason only: never the value, its length or which whitespace. Printed
    whenever the value given ends in whitespace, also when `add` writes nothing (same value). Tests
    (`AddWhitespaceWarningTests`, red first: today no such line): `Add_TrailingSpace_Warns_StoresAsTyped`
    (stderr equals the text, the value read back with `get` keeps its space, exit 0),
    `Add_WhitespaceOnly_Warns`, `Add_TrailingNewlineOrTab_Warns` (`"v\t"`), `Add_NoTrailingWhitespace_NoWarning`
    (also leading and inner spaces), `Add_Warning_LeaksNoValueOrLength` (a distinctive value: stderr
    contains neither it nor its length). Break: test only `' '` instead of `char.IsWhiteSpace` (the tab
    test fails). **`ingest` needs nothing:** `Validation.ReadBoundedStdin` already trims all trailing
    whitespace (`TrimEnd()`, `TswapCore/Validation.cs:78`), and a whitespace-only input becomes empty and
    is refused ("Empty input received", `IngestCommand.cs:26-27`); both already documented in AGENTS.md
    ("Stdin Ingestion"). `import` stores exported values as they are (a restore, not an entry; my call:
    no warning). Docs: `docs/commands.md` (`add`'s entry), one release-notes line in 2b's section
    ("`sudo tswap add` warns when a value ends in whitespace: usually a paste mistake, and `run` can't
    always mask it"), and the `run` limit cross-referenced from security-model.md if Stage 3's text is on
    main by then.

Each task: one commit with explicit paths; full suite once at the end through
`~/RiderProjects/tswap-wt/tools/with-suite-lock.sh ./runtests.sh`; British English.

## File ownership and merge order (v0.3.0)

| 2b touches | Overlaps |
|---|---|
| `TswapCore/RecordVaultStore.cs`, `SecretEntry.cs`, `Keyring/SecretRecordCodec.cs`, `Keyring/RecordMerge.cs`, new `Keyring/RecordWrites.cs`, new `VaultWriter.cs` | Stage 2's files (merged first); no other open brief |
| `TswapCli/CommandContext.cs`, `FingerprintTexts.cs`, `SecretRotation.cs`, `TswapCore/Validation.cs` (`EndsInWhitespace`), Commands `Create`, `Ingest`, `Burn`, `Rotate`, `Restore`, `Add`, `Delete`, `Import` | `ImportCommand.cs` with polish (PR #269 adds three lines at `:42`; 2b edits `:61-93`: separate hunks) |
| New test files above; no edit to `FleetMachine.cs` | polish adds a helper to `FleetMachine.cs`; Stage 3 edits `RunFileTokenTests.cs`, not 2b's |
| `docs/security-model.md`, `docs/commands.md`, `docs/release-notes/v0.3.0.md`, the spec's Delivery section, AGENTS.md (approved) | Stage 3 edits the same table and threat row (adds a `run` row, rewrites `:87`), polish and signing (issue #240) add release-notes sections: text conflicts only |
| Not touched: `RunCommand.cs`, `Redaction.cs`, `FingerprintScanner.cs` (Stage 3); `InitCommand.cs`, `RecoverCommand.cs`, `SlotCommand.cs`, `Prompt.cs` (polish); `release.yml`, `contrib/packaging/*`, `InstallScript.cs` (signing) | |

Order: Stage 2 (#268) merges first; 2b branches from it (this worktree, `design/t16-stage2b` at
4b492e2) and merges `origin/main` (`git merge --no-edit`, never rebase) before its PR. Stage 3,
polish and signing are independent of 2b's code and may merge in any order before or after it;
whichever merges second resolves the docs conflicts (security-model table: keep both the `run` row
and the new write row; release notes: one section per brief). Task 10's source scan names
`RunCommand.cs` only while it still calls `LoadSecrets`; if Stage 3 is on main first, drop it there.

## Review focus

1. No write command reaches `LoadSecrets`, `LoadRecords`, `DecodeFull` or `SaveSecrets` except the
   whole-record fallback for **its own** record; no new `ValueDecrypted` site.
2. The guard: every staged record compared before the first write; nothing written on any refusal;
   `LastHlc` saved only after writes.
3. The two rule sets agree (task 2's property test, task 3's oracle); `SaveSecrets` untouched apart from
   the extraction.
4. Ruling 3 per record: the probe never opens a value section; an unauthenticated file selects nothing.
5. Only authenticated stamps move the clock; version, burn and write stamps in `SaveSecrets`' order.
6. Zeroing: held sections, decoded format 2 values, the new value's bytes after sealing, the restore
   plaintext; the format 2 warning carries only a count and the fix.
7. Differences 2, 3 and 8 are deliberate, pinned, and owner-confirmed; the whitespace warning leaks no value or length.

## Owner decisions (2026-11-07, all recommendations taken)

1. **Damaged value section or mismatched fingerprints:** `burn`, `rotate`, `ingest --rotate`, `add`
   and `delete` on such a record **succeed** and carry the damage forward byte for byte; no value is
   decrypted to check it; `create`/`ingest` on its name refuse as "already exists". Later users of
   that value (`get`, `apply`, `run`, `restore`) still fail closed, naming the file. Difference 2,
   pinned by task 6's four tests and task 5's `Create_ExistingNameWithDamagedValueSection_RefusesAsExisting`.
2. **`vault merge` and `vault reindex` are out of 2b:** follow-up issue #271 (metadata-only merge of
   format 3 folders; reindex without decoding records already current).
3. **AGENTS.md `:203-207`** is updated in task 10. The last sentence ("`LoadSecrets`, which decrypts
   every record, is left only to the write commands until Stage 2b; new code never calls it to read.")
   is replaced, exactly, by the text below (revised after review round 1, because the first approved
   text claimed no exceptions, which the plan's own tests contradict; owner re-confirmed verbatim,
   decision 7):
   > Write commands decrypt only what they use too (T16 Stage 2b): on format 3 records `create`,
   > `ingest`, `rotate`, `burn`, `delete`, `add` and `import` decrypt no value and `restore` only the
   > previous value it puts back (`VaultWriter`, `RecordVaultStore.OpenForWrite`), except where the
   > written record itself can only be decided or merged by its value: `add` compares that record's
   > current value when its stored fingerprints are of another variant-set version or missing, a
   > retained version without fingerprints is fingerprinted from its own value, and a record whose
   > conflicted copies only plaintext can merge, like a format 2 record, is decrypted whole. Only
   > `export` and `migrate` (by their nature) and `vault merge` and `vault reindex` (follow-up #271)
   > read every value; new code never calls `LoadSecrets` or `SaveSecrets` to read or write anything
   > else.
4. **HLC reach accepted:** a write's stamps beat only the written record's and `LastHlc`; a slow
   machine's stamps no longer jump past unrelated records. Difference 3, pinned by task 3's
   `Hlc_UnrelatedFutureRecord_DoesNotRaiseTheStamp`.
5. **New: `sudo tswap add` warns on a value ending in whitespace** (whitespace-only included): `run`
   can't always mask such a value (Stage 3 documents a whitespace-only value split across two reads
   as a limit), and trailing whitespace is usually a paste mistake. The warning names the secret and
   the reason, never the value or its length, and doesn't refuse (owner prefers warnings). Task 11;
   difference 8.
6. **`add`'s comparison fallback accepted (option a):** when the stored current fingerprint set is
   of another variant-set version, or missing, `add` decrypts that one record's current value to tell
   "same value" from a new one. It is one value of the record being written, by a sudo user typing a
   value, and a reindex removes the case. Rejected: always writing a new version, which would push the
   real previous value out of the one-level history, and refusing, which would block `add` in mixed
   fleets for no gain. Pinned by task 4's `Add_SetOfAnotherVariantVersion_DecryptsOnlyThatCurrentValue`.
7. **Decisions 1 and 3 re-confirmed as revised:** difference 2 includes `add` and the
   `create`/`ingest` refusal reason, and the AGENTS.md sentence in decision 3 is approved verbatim.

No owner decision is open.

## Corrections to the spec and to Stage 2's "Stage 2b" section

1. "A burn, a delete **and a restore** need no value at all": wrong for `restore`. Its value becomes a
   new version, and value keys are per version stamp (`SecretRecordCodec.cs:76`), so it decrypts
   exactly one value (the previous one) and seals it again.
2. "Proof: … none but the new one for create/ingest/add/rotate": the new value is never decrypted
   (it is in hand and sealed); the expected count is **0** for those, 1 only for `restore`.
3. "`import`: … only the records it overwrites" (and the brief's "existing ones merged per record"):
   `import` overwrites and merges nothing. It skips every existing live secret, burned included
   (`ImportCommand.cs:74-79`), and writes only absent or deleted names.
4. "Existence checks for `create`/`ingest` from metadata": only for format 3; a format 2 record's
   existence and type are inside its one payload, so checking it decodes that record whole (warned).
5. "Stamps: the next HLC from `LastHlc` and the written record's own stamps": right, but only its
   **authenticated** stamps (`ReadRecord`'s fix round 1 A1, `:909-916`), and it changes what a lagging
   clock shows (difference 3).
6. Ruling 3's "has read any v3 record" can't be answered from the written record alone
   (`AnyV3RecordRead_WritesV3EvenWithoutMarker`): a folder probe is needed on unmarked folders.
7. Stage 2's plan: "`export`, `vault merge`, `vault reindex`, `migrate`: they need every value by
   definition" holds for `export` and `migrate` only (see Scope).
8. Spec Stage 1, Reindex: "Every write path (`add`, `create`, `ingest`, rotate, burn, **`slot`
   operations**, migration) writes v3 … for the record it touches": `slot` operations write no record.
9. Line drift only: Stage 2's section cites `SaveSecrets` at `:1014`, its guard at `:1019-1023`, the
   value comparison at `:1046` and `_highestSeen` at `:696`, `:1004`; after Stage 2 they are `:1090`,
   `:1096-1100`, `:1122`, `:69`, `:1080`.

## Risks

- **Two rule implementations** (whole-record and metadata) could drift. Mitigation: one extracted
  `NextRecord`, one metadata encoder, task 2's property test and task 3's oracle run on every build;
  later, `SaveSecrets` can be rebuilt on `RecordWrites` once nothing else needs it (follow-up).
- **The probe on large unmarked vaults** reads every file's header until one format 3 metadata section
  authenticates; on an all-format-2 vault that is every file per write (reads, no decryption). Such
  vaults are pre-reindex, and the release notes already lead with `sudo tswap vault reindex`.
- **Agents meet the write warning** on pre-reindex vaults on every write of a format 2 record; the
  prompt's rule 11 sends them to the user, as for the reading commands.
- **Parallel docs edits** with Stage 3, polish and signing: text conflicts only (see ownership).
