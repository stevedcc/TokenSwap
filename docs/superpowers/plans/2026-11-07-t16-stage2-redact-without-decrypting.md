# T16 Stage 2: `redact` and `tocomment` decrypt nothing; every other reader decrypts only what it uses (issue #220)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or
> superpowers:executing-plans). Every task is TDD: the named tests first, watched failing for the
> stated reason, then the production change.

**Goal.** No command decrypts a secret value it doesn't use (owner, 2026-11-07, binding: "unlocking
all secrets is bad practice"). `redact` and `tocomment` decrypt **no** value: they read metadata
sections only and recognise secrets by their keyed fingerprints (spec Stage 2). `check`, `names`,
`list` and `burned` decrypt no value either; `get` and `apply` decrypt exactly the value versions
they print or substitute. Target v0.3.0.

**Why.** Every one of these commands calls `ctx.LoadSecrets(key)` today
(`TswapCli/CommandContext.cs:309-310` → `RecordVaultStore.LoadSecrets`,
`TswapCore/RecordVaultStore.cs:486`), which decodes every record whole (`DecodeFull`, `:853`) and
turns every value into a managed string (`ToSecret`, `:673`): `RedactCommand.cs:22`,
`ToCommentCommand.cs:23`, `ApplyCommand.cs:25`, `GetCommand.cs:21`, `CheckCommand.cs:36`,
`NamesCommand.cs:18`, `ListCommand.cs:15`, `BurnedCommand.cs:18`. Stage 1 (v0.2.0) shipped what is
needed to stop that and nothing uses it yet: `LoadMetadata` (`RecordVaultStore.cs:1148`, no caller
outside the store), `FingerprintIndex` (no caller), and the one-record read `ReadSecretValue`
(`:531`), used only by the broker (`TswapCore/Broker/BrokerSecrets.cs:80,121`,
`Broker/SshAgent/SshKeys.cs:84`).

**Source of truth.** `docs/superpowers/specs/2026-11-01-import-story-design.md` (Goals, Anti-goals,
Trust model, Stage 1, Fingerprints, Stage 2, Threat model, Delivery). Stage 1's commits:
`git log --oneline --grep T16-S1`.

## Out of scope

- `run` (Stage 3, planned in parallel in
  `docs/superpowers/plans/2026-11-07-t16-stage3-run-fingerprints.md`). This plan defines the API
  Stage 3 consumes (below) and does not touch `RunCommand.cs`.
- Write commands (`create`, `ingest`, `burn`, `rotate`, `restore`, `add`, `delete`, `import`) still
  decrypt the whole vault through `LoadSecrets` + `SaveSecrets` (`RecordVaultStore.cs:1014`, which
  needs every record's state to build tombstones and the stale-write guard). They are Stage 2b, a
  separate brief in v0.3.0 after this one (owner, 2026-11-07); see "Stage 2b" below.
- `export`, `vault merge`, `vault reindex`, `migrate`: they need every value by definition.
- Any record format change. Stage 2 reads formats 2 and 3 exactly as v0.2.0 writes them, so a fleet
  mixing v0.2.x and v0.3.0 machines needs nothing new.
- `extract`, `check --verify` (Stage 4).

## What happens on a classic vault

Unchanged: all eight commands refuse when the store opens (`CommandContext.Storage`,
`TswapCli/CommandContext.cs:54-69`, `ICliCommand.WorksOnClassicVault` false by default,
`ICliCommand.cs:37`), with `ClassicVaultRefusal` (`:109`), pinned by `ClassicVaultRefusalTests`.
The new code therefore only ever meets a `RecordVaultStore`; `CommandContext.OpenVault` (below)
throws a `TswapException` if it is handed anything else (a guard, not a path).

## The store API (shared with Stage 3)

All in `TswapCore`. "Decrypts" below means a call of the `ValueDecrypted` seam
(`RecordVaultStore.cs:138`), which today fires at both of the store's value-decryption sites and
only there: `ReadValueFromMetadata` (`:648`, before `OpenSealed` at `:652`) and `DecodeFull`
(`:861`, after `SecretRecordCodec.Decode` at `:856`). `RecordDecrypted` (`:132`) also fires for
every **metadata** section, so it is not the zero-decryption counter (the spec names the wrong
hook, see "Spec amendments").

```csharp
// RecordVaultStore.cs
public SecretEntry? OpenSecret(string name, byte[] vaultKey);
```
One secret's record (main file plus its conflicted copies), nothing else read. Format 3 throughout:
metadata sections decrypted and folded (`RecordMerge.MergeAllMetadata`, as `ReadValueFromMetadata`
does today, `:601-640`), **no value decrypted**. Any format 2 file in the set: that record decoded
whole as today (`ReadValueFull`, `:574`; both its versions reported to `ValueDecrypted`), the only
way to read format 2. Null when there is no file. An unreadable record throws the text of
`SecretsDb.ThrowIfUnreadable` (`TswapCore/Models.cs:302`), which names the hashed file
(`RecordConflictTests.ATruncatedMainRecord_FailsClosed` asserts the file name for `get` and `apply`;
today it comes from `LoadSecrets`' warnings, and `ReadSecretValue`'s messages, `:580`, `:619`, lack it).

```csharp
public sealed class SecretEntry : IDisposable        // new file SecretEntry.cs
{
    public string FileName { get; }
    public RecordMetadata Metadata { get; }           // may be a tombstone
    public SecretInfo? Info { get; }                  // null for a tombstone
    public byte[]? DecryptValue(bool previous);       // format 3: one value section (fingerprint-checked as today, :661-667);
                                                      // format 2: a copy of the decoded value; null when there is none. Caller zeroes.
    public void Dispose();                            // zeroes a format 2 record's decoded values and held sections
}
```
`ReadSecretValue` becomes `using var e = OpenSecret(…); return e?.DecryptValue(previous)` with its
contract and messages unchanged (broker tests pin it).

```csharp
public VaultMetadata LoadMetadata(byte[] vaultKey, TextWriter? warnings = null,
                                  FormatTwoRecords formatTwo = FormatTwoRecords.Skip);
public enum FormatTwoRecords { Skip, Decode }
```
`Skip` is today's behaviour (a format 2 record is counted in `NotFingerprinted`, never decrypted,
`:1172`, `:1201`). `Decode` (for `names`, `list`, `burned`; owner decision 1) decodes exactly the
records that have a format 2 file, through the existing `ReadRecord` + `FoldConflictCopies` path,
converts each to `RecordMetadata` (fingerprints null, so it still counts as not fingerprinted) and
zeroes its values at once. `VaultMetadata` gains `IReadOnlyList<SecretInfo> Secrets` (live records,
by name) and `int FormatTwoDecoded`.

**The format 2 warning (owner decision 1: "keep working with warning").** Whenever a command decoded
at least one format 2 record (`names`, `list`, `burned` through `Decode`; `check`, `get`, `apply`
through `OpenSecret` on a record they name), it writes one line to stderr after its output,
`VaultView.FormatTwoWarning` (text my call):
`Warning: {n} record(s) are in record format 2, which can only be read by decrypting the whole
record, value included; tswap decrypted them and wiped the values at once. Ask the user to run
'sudo {prefix} vault reindex' once to convert the vault.` What it may contain (thought through):
only the count `n` and the fix. `n` is the number of record files tswap decoded because their
format byte (cleartext, `SecretRecordCodec.FormatVersionOf`, `SecretRecordCodec.cs:232`) is 2, so
anyone who can list the vault folder can count them without the key: the warning adds nothing a
decryption revealed. It never carries a name (a format 2 **tombstone**'s name, which `names` and
`list` don't print, would otherwise leak a deleted secret's name), a hashed file name, a value, a
length or a type. For `get`/`apply`/`check` the count covers only the records they named, so it
says nothing beyond "a name you gave is stored in format 2". Exit codes are unchanged. **Diagnostics parity (my call, forced by existing tests):** the
metadata path writes the same warning texts as the full load for unreadable records, conflicted
copies (with the sync tool's name, `:792`) and stamps more than a year ahead (`:737`); today it
writes shorter texts without the tool name and no stamp warning (`:1186-1250`), which would break
`RecordConflictTests.ARealConflictCopyName_IsResolvedByTheRules`,
`AnUndecryptableConflictCopy_IsWarnedAbout_AndKept_EvenAfterAWrite` and
`AnAbsurdFutureStamp_IsWarnedAbout_AndNamesShowsFarFuture` once those run on format 3.

```csharp
public sealed record SecretInfo(string Name, DateTime Created, DateTime Modified, DateTime? BurnedAt,
    string? BurnReason, IReadOnlyList<PastBurn> History, bool HasPrevious, bool PreviousBurned)
{ public static SecretInfo From(RecordMetadata metadata); }   // new file SecretInfo.cs
```
`ToSecret` (`:673`) is rewritten on top of `SecretInfo.From`, so the two can't disagree.

```csharp
public interface ISecretLookup                        // new file ISecretLookup.cs
{
    bool Contains(string name);
    bool HasPreviousValue(string name);
    bool IsBurnedToken(string token);
    string ResolveToken(string token, string? where = null);
    void ThrowIfUnreadable(string name);
}
```
`SecretsDb` implements it with its existing members (`Models.cs:254-311`), behaviour unchanged.

```csharp
public sealed class VaultView : ISecretLookup, IDisposable   // new file VaultView.cs
{
    public VaultView(RecordVaultStore store, byte[] vaultKey, TextWriter? warnings);
    public VaultMetadata LoadAll(FormatTwoRecords formatTwo);  // cached; decrypts no value with Skip
    public SecretInfo? Find(string name);                      // LoadAll's entry if loaded, else OpenSecret(name)
    public void ThrowIfAnyUnreadable(string command);          // SecretsDb.ThrowIfAnyUnreadable's text (Models.cs:290)
    public void RequireFingerprints(string command);           // Stage 2's refusal (below)
    public FingerprintIndex BuildIndex(FingerprintKeys keys);  // every retained version of every live record, as (name, isPrevious)
    public bool IsBurned(string name);                         // the outstanding burn, from metadata
    // ISecretLookup: ResolveToken decrypts that one version via SecretEntry.DecryptValue, keeps the string,
    // zeroes the bytes; a second ResolveToken of the same token decrypts nothing.
}
// CommandContext.cs
public VaultView OpenVault(byte[] key);   // new VaultView((RecordVaultStore)Storage, key, Console.Error)
```
(my call) One `RecordDirectoryScanner.Scan` per `VaultView`, handed to `OpenSecret` through an
internal overload, so `apply` with many markers doesn't rescan the folder per marker.

**Stage 3 uses:** `ctx.OpenVault(key)`, `ResolveToken`/`IsBurnedToken` for `{{name}}` tokens,
`Apply.ApplySecretsReporting(content, ISecretLookup, warnings)` for `{{@file}}`,
`LoadAll(Skip)` + `NotFingerprinted` for its warning, `BuildIndex` for its streaming matcher.

## File ownership (Stage 2 vs Stage 3)

| Stage 2 owns | Stage 3 owns |
|---|---|
| `RecordVaultStore.cs`, `VaultMetadata.cs`, new `SecretEntry.cs`, `SecretInfo.cs`, `ISecretLookup.cs`, `VaultView.cs`, `SecretMatcher.cs` | `TswapCli/Commands/RunCommand.cs`, `TswapCore/Redaction.cs`, `TswapCli/FilledFiles*.cs` |
| `Models.cs` (`SecretsDb` implements `ISecretLookup`), `Apply.cs`, `Check.cs` | RedactingPty package version (`TswapCli.csproj`) and any new streaming-matcher file |
| `Redact.cs`, `SecretProcessor.cs`, `RedactProcessor.cs`, `ToCommentProcessor.cs` | |
| `Fingerprints/FingerprintIndex.cs` (task 1's rule only; Stage 3 builds on it, rebases after task 1) | |
| Commands `redact`, `tocomment`, `apply`, `check`, `get`, `names`, `list`, `burned`; `CommandContext.cs` (`OpenVault`) | |
| `TswapTests/FleetMachine.cs` (`StoreOpened` seam), `RecordVaultTestSupport.cs` (fixtures, task 2), new test files listed below | its own test files |
| Docs/prompt: the sections on those commands; `docs/release-notes/v0.3.0.md` gets one Stage 2 section; the spec's Stage 1, Stage 2 and Delivery sections (task 10) | the `run` sections; its own release-notes section; the spec's Stage 3 section |

Order: tasks 1-4 are the contract; Stage 3 starts coding against them once they are pushed. If
Stage 3's plan defines a different API, the owner reconciles the two plans before either brief starts.

## Per-command changes

| Command | Today | After |
|---|---|---|
| `redact` | all values decrypted, plaintext regex per line | `OpenVault` → `LoadAll(Skip)` → `ThrowIfAnyUnreadable` → `RequireFingerprints` → `SecretMatcher` over the file. 0 values |
| `tocomment` | same, plus `RedactContent` for the dry-run lines | same matcher for the rewrite and the dry-run lines. 0 values |
| `check` | all values; `ThrowIfAnyUnreadable` | `LoadAll(Skip)` + `ThrowIfAnyUnreadable`; a marker name not among the format 3 records is looked up with `Find` (a format 2 record is decoded only when a marker names it, then the format 2 warning). 0 values on format 3 |
| `names`, `burned` | all values | `LoadAll(Decode)`; warnings as today plus the format 2 warning; no refusal. 0 values on format 3 |
| `list` | all values; `ThrowIfAnyUnreadable` | `LoadAll(Decode)` + `ThrowIfAnyUnreadable`, plus the format 2 warning. 0 values on format 3 |
| `get` | all values | `Find(name)` then `ResolveToken(name)`: one value section (format 2: that record, plus the warning) |
| `apply` | all values; each marker resolved before its line shape is checked (`Apply.cs:184`) | per marker: existence, `:previous` and burned from metadata (errors in today's order); the value decrypted only when the line is substituted; once per distinct token; the format 2 warning if a named record was format 2 |

**Stage 2's refusal (owner), text (my call):** `'{command}' recognises secrets by their
fingerprints, and {n} record(s) in this vault have none yet (written by an older tswap, or the vault
was never reindexed). Ask the user to run 'sudo {prefix} vault reindex'. Nothing was read or
changed.` On stderr, exit 1, stdout empty, the input file not read (`tocomment`: not written).
`OlderVariantSet > 0` is a one-line note on stderr, and matching goes on (spec).

## The matcher (`SecretMatcher`, my calls within the spec)

- **Index:** `VaultView.BuildIndex`: for each live record its current version as `name` and its
  previous version as `name:previous`, each with every stored variant. Variant kind → label as
  today: `Plain`/`WhitespaceStripped` → `[REDACTED: name]`, `Base64` → `(base64)`, `Base64Url` →
  `(base64url)` (`RedactProcessor.cs`, `SecretProcessor.cs:166-171`).
- **Priority, exactly today's sort** (`SecretProcessor.cs:179-193`): matched length descending, then
  the matched text ordinally, then live before burned, then name, then match type. The matched text
  is the window of the input (no plaintext from the vault needed), so this is reproducible. Today's
  quirk is kept: a `name:previous` entry always counts as not burned (`TryGetValue` on
  `"x:previous"` fails, `:186-187`).
- **Selection, single pass over spans:** entries in priority order; each entry's occurrences left to
  right; an occurrence is taken when it overlaps neither a taken span nor that entry's previous
  taken occurrence (what sequential `Regex.Replace` does, `:222-227`, minus matches that exist only
  in inserted text). Then all taken spans are replaced in one pass.
- **`tocomment`'s context** (`ToCommentProcessor.cs:354-364`: quotes consumed, `(?<![-\w])` /
  `(?![-\w])` boundaries, an existing marker consumed): evaluated by running that same regex,
  built from the window's text, anchored at the occurrence on the **original** line. Continuation
  line removal (`SecretProcessor.cs:235-262`) unchanged.
- **Scope:** `tocomment` scans line by line, as today. `redact` scans the whole CRLF-normalised text
  (owner-approved 2026-11-07, "redact behaviour is great": a multi-line value such as a PEM key can
  only match across lines; today `redact` prints it unmasked because no line holds the whole value).
- **The SecretsDb adapters** `Redact.RedactContent(string, SecretsDb)` and
  `Redact.ToComment(string, SecretsDb)` stay, made `internal`: they fingerprint the database under a
  random key and run the new engine, so the 57 existing `RedactTests` keep pinning the new engine
  unchanged. No command calls them (asserted by the zero-decryption tests).

## Behaviour differences from today (spec requires the list)

1. `redact`/`tocomment` refuse on a vault with records lacking fingerprints: format 2 records
   (also format 2 tombstones, whose type can't be known undecrypted, `VaultMetadata.cs:10-15`) and
   format 3 records with a retained version without a set. Owner decision (spec Stage 2).
2. No match inside text tswap inserted: a secret equal to, say, `RED` or `tswap` is no longer
   replaced inside an earlier `[REDACTED: …]` label or `# tswap:` marker. Spec-listed; a value can
   never corrupt another's marker.
3. `tocomment`'s boundary and quote checks see the original neighbours, not an inserted marker
   (differs only for two secrets with no separator between them). Same reason as 2.
4. `redact` masks multi-line values across lines (more masking; owner-approved).
5. A window that cuts a surrogate pair is never confirmed (task 1). Today's plaintext matcher never
   matched there; the fingerprint engine without the fix could only through a keyed rolling-hash
   collision (task 1's evidence), so this is hardening, not an observable change in practice.
6. `get`, `apply`: warnings about records they don't read (unreadable, conflicted copies, absurd
   stamps) are no longer printed; errors about the records they use are unchanged, file name
   included. They read only those records.
7. `apply`: a line whose value is already filled no longer decrypts its secret (warning unchanged).
8. `check`: an unreadable **format 2** record that no marker names no longer stops `check` (format 2
   can't be read without decrypting it). Unreadable format 3 records still stop it, as today.
9. `check`, `names`, `list`, `burned` on format 3 no longer notice a damaged **value** section or a
   fingerprint/value mismatch (`RecordMerge.ValidateFingerprints`, run by the full load, `:805`):
   they don't open values. The command that uses the value still fails closed (`DecryptValue`).
10. `LoadMetadata`'s copy merge can refuse where the full load merges (its own warning says so,
    `:1238`): `list` and `check` then refuse that record, `names` and `burned` warn. Rare (a
    divergence only plaintext could settle); listed, not changed.
11. `names`, `list`, `burned`, and `check`/`get`/`apply` on a record they name, print the format 2
    warning when they decoded a format 2 record (owner decision 1). Nothing else changes for them
    on such a vault.

## Tasks

Tests named per task; "Break:" is the production change that must make the task's key test fail
(done once, reverted, reported in the commit message).

1. **Fingerprint confirmation made injective** (`FingerprintIndex.cs`; owner-approved). What is true,
   checked on 2026-11-07 against this worktree's `TswapCore` (a scratch console project, not
   committed): `Fingerprinter.Hmac` encodes the window with `Encoding.UTF8` (`Fingerprinter.cs:31-46`),
   and `UTF8("ab\uD83D")` (a window ending on the high half of `😀`) and `UTF8("ab�")` are both
   `6162EFBFBD`, so the **HMAC step alone** confirms a window whose text differs from the stored
   variant (a value with invalid UTF-8 bytes `61 62 FF` decodes to `ab�`, `Fingerprinter.cs:19`).
   But the scan reaches the HMAC only after the keyed rolling hash, which runs over UTF-16 code
   units and differs (`RollingHash.Of("ab\uD83D", b) == RollingHash.Of("ab�", b)`: `False`),
   and `FingerprintIndex.Build([("binary-secret", false, Compute([61 62 FF]))]).Scan("ab😀")` gave
   **0 hits** (`Scan("ab�")`: 1, control `Scan("abc")`: 0). So a false hit needs a collision of
   the 61-bit keyed rolling hash as well: not reachable in practice, and my first report overstated
   it. The fix stays (cheap, and it makes "never a false match", `FingerprintIndex.cs:13-14`, hold
   without the probabilistic caveat): `Confirm` skips a window that starts on a low surrogate or ends
   on a high one. Tests (`FingerprintIndexTests`): `Scan_ForgedRollingHashCollisionAcrossASurrogatePair_NoHit`
   (an index built from a hand-made `FingerprintEntry` with the rolling hash of `ab\uD83D` and the
   HMAC of `ab�`, i.e. the collision forced; text `ab😀`: one hit today, none after),
   `Scan_ValueWithAnEmoji_StillMatched`. Break: remove the check.
2. **Test fixtures make format 3 vaults** (tests only; owner decision 1: fixtures over special-casing
   the warning). `RecordVaultTestSupport.InitRecordVault` keeps the `record-format` marker that `init`
   writes (today it deletes it, `RecordVaultTestSupport.cs:39-44`, so 32 call sites in 24 classes get
   format 2 vaults); the old behaviour moves to a new `InitFormatTwoVault`. Evidence (2026-11-07,
   a scratch copy of the worktree with only the marker deletion removed, the 24 classes plus
   `TouchNoticeTests` run through the suite lock): 235 tests, 214 passed, 21 failed, all in four
   classes that test format 2 on purpose: `RecordStoreV3Tests` (4: `NoMarker_WritesV2`,
   `MarkerConflictCopy_IsIgnored`, `ADamagedFormat3File_DoesNotSelectFormat3`,
   `VaultMerge_V3TombstoneWithAnExtension_IntoAnUnmarkedFolder_KeepsItAndWritesV3`),
   `RecordStoreMetadataTests` (2: `LoadMetadata_CountsV2AndMissingFingerprints_WithoutDecryptingV2`,
   `LoadMetadata_ConcurrentConversionCopies_PickTheSameSectionAsTheFullLoad`), `VaultReindexTests`
   (13, every test that starts from a format 2 vault) and `RecordStoreTests` (2: format 2 file sizes,
   `ValuesInOneSizeBucket_…` expects 898 and got 642, `Delete_WritesATombstone_NotAnAbsentFile`
   expects 642 and got 354). Those four classes call `InitFormatTwoVault` instead (a rename at the
   call site, assertions untouched). The other 20 classes now run on format 3 with no edit:
   `ApplyTests`, `BrokerVaultConflictTests`, `EmptySaveGuardTests`, `ClassicVaultRefusalTests`,
   `FixRoundShouldFixTests`, `KeyringFileTests`, `PreviousValueWarningTests`, `PreviousValueScanTests`,
   `NewerFormatRecordTests`, `RecordConflictTests`, `RecordStoreExportImportTests`,
   `RecordStoreFileLayerTests`, `PreviousValueTests`, `RotateTests`, `StaleWriteGuardTests`,
   `VaultMergeTests`, `UnreadableRecordCommandTests`, `UnauthenticatedHlcTests`, `TimeProviderTests`,
   `VaultPasswordStoreTests`. Why: format 2 vaults now make `redact`/`tocomment` refuse and the
   reading commands warn, by the owner's rules; the fixtures follow what `init` makes. Named in the
   commit message as a test-input change. `TouchNoticeTests`' empty-stderr assertions for `names`
   (`:83`, `:100`, `:209`) are not affected either way: its vaults come from a plain `init`
   (`:38`, `:166`), already format 3. Lost format 2 coverage of command behaviour is restored by
   task 9's `FormatTwoVaultCommandTests`. The implementer re-runs the 24 classes after the change and
   records the summary line; any failure outside the four classes is a stop-and-report, not an edit.
3. **Store: one record, and metadata with format 2 policy** (`RecordVaultStore.cs`,
   `VaultMetadata.cs`, `SecretEntry.cs`, `SecretInfo.cs`). New `RecordStoreSelectiveReadTests`:
   `OpenSecret_FormatThree_DecryptsNoValue` (`ValueDecrypted` empty, metadata right);
   `DecryptValue_DecryptsOnlyThatVersion` (current: exactly `(file, current)`; previous: exactly
   `(file, previous)`); `OpenSecret_FormatTwo_DecodesOnlyThatRecord` (only its file reported);
   `OpenSecret_Unreadable_NamesTheFile`; `OpenSecret_FoldsConflictCopiesLikeReadSecretValue`;
   `LoadMetadata_Decode_ListsFormatTwoRecords_DecodingOnlyThem` (`FormatTwoDecoded` counts a format 2
   tombstone too); `LoadMetadata_WarnsLikeTheFullLoad` (same folder, `LoadSecrets` vs
   `LoadMetadata(Decode)`: equal warning lines for an unreadable main file, a newer and an
   undecryptable conflicted copy per sync tool, a year-ahead stamp, on format 2 and on format 3).
   Extend the random-history property test in `RecordStoreMetadataTests` (`:254`):
   `SecretInfo.From(metadata)` equals the fields of `ToSecret(state)`. Existing broker tests
   (`BrokerVaultReadTests`, `BrokerVaultConflictTests`, `SshAgentKeyTests`) pass unchanged. Break:
   `OpenSecret` calls `DecodeFull` for format 3.
4. **`VaultView`, `ISecretLookup`, `Apply`/`Check` overloads, seams** (`VaultView.cs`,
   `ISecretLookup.cs`, `Models.cs`, `Apply.cs`, `Check.cs`, `CommandContext.cs`; tests:
   `FleetMachine.StoreOpened` (an `Action<RecordVaultStore>` run on each command's store)). New
   `VaultViewTests`: `ResolveToken_DecryptsOnce` (twice → one `ValueDecrypted`);
   `Lookup_MatchesSecretsDb` (random vaults: `Contains`, `HasPreviousValue`, `IsBurnedToken` and
   every exception text of `ResolveToken`/`ThrowIfUnreadable`/`ThrowIfAnyUnreadable` equal to
   `SecretsDb`'s from `LoadSecrets`); `Apply_ViaVaultView_MatchesSecretsDb` (the inputs of
   `ApplyTests` against a real vault: byte-identical output and warnings);
   `Apply_FilledLine_DecryptsNothing`; `CheckMarkers_ViaVaultView_MatchesSecretsDb`;
   `FormatTwoWarning_CountOnly` (a format 2 vault holding a live record and a tombstone with
   distinctive names and values: the warning line equals the expected text with `n = 2` and contains
   neither name, neither value nor any hashed file name). Break: `ResolveToken` without its cache.
5. **Pin today's redaction (tests only; they pass on today's engine).** New
   `RedactBehaviourPinTests`, each for `redact` and `tocomment`: overlapping secrets; equal-length
   ties decided by text, not position (`xab`/`abz` in `xabz` gives `x[REDACTED: abz-secret]`);
   containment; a self-overlapping value (`aa` in `aaa`); burned vs live with one value; a burned
   `name:previous` tie; `name:previous`; the whitespace-stripped variant; base64 and base64url
   labels; CRLF input; regex metacharacters; quotes, boundaries and an existing marker in
   `tocomment`; continuation-line removal; the dry-run's redacted lines. Copy today's
   `SecretProcessor`/`RedactProcessor`/`ToCommentProcessor` into `TswapTests/PlaintextRedactOracle.cs`
   (the reference for task 6). No production change, so no Break.
6. **The engine switch** (`SecretMatcher.cs`, `SecretProcessor.cs`, `Redact.cs`,
   `RedactProcessor.cs`, `ToCommentProcessor.cs`). Red first: `Redact_SecretInsideAnInsertedLabel_NotReplaced`,
   `ToComment_SecretInsideAnInsertedMarker_NotReplaced`, `ToComment_AdjacentSecrets_UseOriginalNeighbours`,
   `Redact_MultiLineValue_MaskedAcrossLines` (differences 2-4). Then: `RedactTests`, task 5's pins
   and `CommandTests`' redact/tocomment tests unchanged and green;
   `Engine_MatchesOracle_OnRandomCorpus` (seeded loop: secrets and texts over an alphabet sharing no
   character with the inserted texts and with separators between secrets, so differences 2-3 can't
   arise: output equal to the oracle's). Measure a 1 MB file against 200 secrets × 4 variants, old vs
   new, and record both times in the commit (no test). Break: drop the text-ordinal tie-break (the
   `xab`/`abz` pin fails).
7. **`redact`, `tocomment` read metadata only** (`RedactCommand.cs`, `ToCommentCommand.cs`). New
   `RedactWithoutDecryptingTests` (format 3 vault through `StoreOpened`):
   `Redact_DecryptsNoValue` and `ToComment_DecryptsNoValue` (also `--dry-run`: `ValueDecrypted`
   empty, output with `name`, `name:previous` and base64 labels correct);
   `Redact_FormatTwoRecord_Refuses` (`InitFormatTwoVault`; exit 1, stdout empty, stderr names
   `1 record(s)` and `sudo tswap vault reindex`, nothing decrypted);
   `ToComment_FormatTwoRecord_RefusesFileUnchanged`; `Redact_RecordWithoutFingerprints_Refuses` (a
   planted format 3 record without a set); `Redact_OlderVariantSet_NotesAndMasks` (a planted set
   version 0); `Redact_AfterReindex_Masks` (format 2 vault → refuse → `vault reindex` → masked).
   `PreviousValueScanTests` (format 3 since task 2) green unchanged, incl.
   `RedactAndCheck_FailClosedOnUnreadableRecords` (a truncated format 3 record is unreadable, so its
   file is named). Break: `redact` calls `ctx.LoadSecrets` (`Redact_DecryptsNoValue` fails).
8. **`check`, `names`, `list`, `burned`** (their commands). New `MetadataCommandTests`: each
   `_DecryptsNoValue` on format 3 with output equal to today's (names table and `--json`, burned
   outstanding and rotated, list columns, check statuses and exit codes 0/1/2) and no format 2
   warning. `RecordConflictTests`' three names tests above now run on format 3 (task 2) and pin the
   diagnostics parity unchanged. Existing `UnreadableRecordCommandTests.List_Refuses_NamingTheFile`,
   `RecordConflictTests`, `PreviousValueScanTests.Check_*`, `CheckTests`, `TouchNoticeTests`
   unchanged and green. Break: `names` loads with `LoadSecrets`.
9. **`get`, `apply`, and every reader on a format 2 vault** (their commands). New tests:
   `Get_DecryptsOnlyItsCurrentValue` (exactly one `(file, current)`); `Apply_DecryptsOnlyItsMarkers`
   (two markers, one filled line, one unrelated secret: exactly the two values, each once);
   `Apply_UnrelatedUnreadableRecord_NotReported` (difference 6). New `FormatTwoVaultCommandTests`
   (`InitFormatTwoVault`): `names`, `list`, `burned` list every live secret as today, print the
   format 2 warning with the right count once, and report `ValueDecrypted` only for format 2 files;
   `check` with a marker on a format 2 record resolves it and warns with `n = 1`, and
   `Check_UnnamedUnreadableFormatTwoRecord_NoLongerStops` (difference 8); `get` and `apply` on a
   format 2 record return the right value and warn; a truncated format 2 main record makes `get`
   and `apply` fail naming the file (the format 2 counterpart of
   `RecordConflictTests.ATruncatedMainRecord_FailsClosed`, which now runs on format 3). Existing
   `ApplyTests`, the apply-needs-sudo tests and `PreviousValueWarningTests` unchanged and green.
   Break: `get` decrypts via `LoadAll(Decode)` + full load; and, separately, the warning printed
   with the record's name (`FormatTwoWarning_CountOnly` and this class fail).
10. **Docs, prompt and spec.** `docs/commands.md` (`redact`/`tocomment` refusal and reindex; what
    each command decrypts; the format 2 warning), `docs/security-model.md` (a "what each command
    decrypts" table; the minimum-decryption row), `docs/upgrading-from-0.1.md` and
    `docs/release-notes/v0.3.0.md` (lead, owner-approved: run `sudo tswap vault reindex` once on every
    vault that holds format 2 records, i.e. any record vault made before v0.2 and not reindexed, or
    `redact`/`tocomment` refuse and the reading commands warn; upgrade every machine on a shared
    folder to ≥ 0.2 first, see Risks), `TswapCore/Prompt.cs` (if `redact` or `tocomment` refuses, or a
    command prints the format 2 warning, ask the user to run the reindex; never run sudo) and its
    prompt-hash test, `docs/design/multi-machine-keying.md` if it states which commands decrypt.
    **Spec:** edit `docs/superpowers/specs/2026-11-01-import-story-design.md` with the four
    amendments below (Stage 1's Fingerprints and Reindex paragraphs, Stage 2, Delivery; Stage 3's
    section is Stage 3's to edit), each marked "Owner amendment, 2026-11-07" like the existing one.
    AGENTS.md's Storage paragraph only with the owner's approval. Doc tests in `TswapTests/Docs`
    green.

Each task: one commit with explicit paths; full suite once at the end through
`~/RiderProjects/tswap-wt/tools/with-suite-lock.sh ./runtests.sh`; British English.

## Review focus

1. No path of the eight commands reaches `LoadSecrets`, `DecodeFull` or `OpenSealed` except where
   the table says; every new decryption path fires `ValueDecrypted` (the store's two sites stay the
   only ones, `:652`, `:856`).
2. The refusal is fail-closed: no fallback to plaintext matching, the input file not read.
3. Engine equivalence: the oracle test's corpus really excludes only differences 2-3, and every
   other listed difference has its own test.
4. Error texts for unreadable records still name the hashed file; `list`/`check` still refuse on an
   unreadable format 3 record.
5. Zeroing: format 2 decodes and `DecryptValue` byte arrays zeroed; no value string kept past the
   command beyond today's (strings can't be zeroed; same as today, fewer of them).
6. Stage 3's needs are met by the API without editing Stage 2's files.
7. The format 2 warning carries only a count and the fix: no name (tombstones!), hashed file name,
   value, length or type, on any command; the fixture change (task 2) touched only the four
   format 2 classes' setup, no assertion.

## Owner decisions (2026-11-07)

1. **Format 2 records in the reading commands:** "keep working with warning". Decode that record,
   wipe its values at once, print the format 2 warning (count and fix only). Test fixtures make
   format 3 vaults (task 2); a dedicated format 2 fixture covers the warning (tasks 4, 9).
2. **Write commands:** a separate brief, Stage 2b, in v0.3.0, after Stage 2 (section below).
3. **`redact` masks multi-line values across lines:** approved ("redact behaviour is great").
4. **Spec amendments:** approved as listed below; task 10 writes them into the spec.

Still open: none. (Task 1 was approved on my first, overstated description; its own text now says
what was measured. It stays as cheap hardening unless the owner drops it.)

## Spec amendments (owner-approved 2026-11-07; task 10 edits the spec)

1. **Zero-decryption counter.** Stage 2's "counting decrypted value sections (… `RecordDecrypted`
   hook)" becomes the `ValueDecrypted` hook (`RecordVaultStore.cs:138`): `RecordDecrypted` fires for
   every metadata section too (`:608`, `:1210`, `:1278`).
2. **Overlap order.** Fingerprints' "longest first, then leftmost" becomes today's order, which
   Stage 2 pins: matched length descending, then the matched text ordinally, then live before burned,
   then name, then match type (`SecretProcessor.cs:179-193`); each entry's occurrences left to right.
3. **The confirmation step.** "A rolling-hash collision only costs an extra HMAC" and
   `FingerprintIndex`'s "never a false match" hold only with task 1's rule: the HMAC is taken over
   UTF-8, which is not injective on UTF-16 windows that split a surrogate pair (measured in task 1),
   so such windows are never confirmed. Without the rule a false hit needs a keyed 61-bit
   rolling-hash collision on top.
4. **Reindex is a mandatory upgrade step.** Stage 1's reindex is required, not optional, for every
   vault holding format 2 records (record vaults made before v0.2 and never reindexed, or written
   since by a v0.1.x machine on a shared folder): until then `redact`/`tocomment` refuse and the
   reading commands warn. The v0.3.0 release notes lead with `sudo tswap vault reindex`.

## Stage 2b (separate brief, v0.3.0, after Stage 2)

Owner, 2026-11-07. The write commands `create`, `ingest` (incl. `--rotate`), `burn`, `rotate`,
`restore`, `add`, `delete` and `import` decrypt only the records they write. What it must cover:

- **Today's shape:** every one calls `ctx.LoadSecrets` (e.g. `BurnCommand.cs:21`, `CreateCommand.cs:50`,
  `IngestCommand.cs:31`, `RestoreCommand.cs:27,42`, `ImportCommand.cs:63`) and `SaveSecrets`
  (`RecordVaultStore.cs:1014`), which takes a whole `SecretsDb`, turns any missing secret into a
  tombstone and refuses more than one (`:1019-1023`), compares each value with the stored one to
  decide on a new version (`:1046`), and needs every record loaded for the stale-write guard and
  the highest stamp seen (`_highestSeen`, `:696`, `:1004`).
- **A per-record write API** replacing whole-database saves for these commands: new value version,
  burn, tombstone, restore, each from one `SecretEntry`. A burn, a delete and a restore need no
  value at all (copy the held value sections byte for byte, change metadata); a new version seals
  one new value section and copies the previous one. "Same value as stored?" (`:1046`) answered by
  the stored fingerprints (HMAC of the plain variant) or dropped (`rotate` sets `Rotated` anyway).
- **Stamps:** the next HLC from `LastHlc` and the written record's own stamps, not from every
  record; check that this keeps per-record ordering and the machine's monotonic clock.
- **Format 2:** a write of a format 2 record decodes that one record (warning as in Stage 2) and
  writes format 3 when the vault does; existence checks for `create`/`ingest` from metadata.
- **Unchanged guarantees:** stale-write guard per record, unreadable records never overwritten,
  conflicted copies folded and removed on that record's write, the marker rules (`WritesV3`).
- **`import`:** reads the export file's values (needed) and only the records it overwrites.
- **Proof:** the `ValueDecrypted` counter through `FleetMachine.StoreOpened`: 0 values for burn,
  delete and restore; none but the new one for create/ingest/add/rotate.

What Stage 2 already gives it: `OpenSecret`/`SecretEntry` (one record's merged metadata, its held
sections and file name; `DecryptValue` for one version), `VaultView` and `LoadAll`, `SecretInfo`,
the format 2 warning, `ISecretLookup`, `ctx.OpenVault`, the `StoreOpened` seam and the format 3 test
fixtures. `SecretEntry` will need to expose its held sealed sections to the store internally (not
publicly), which is Stage 2b's change to make.

## Risks

- **Shared folders with older machines.** v0.2.x machines write format 3 once the marker exists:
  fine. A v0.1.x machine still writes **new** records in format 2 (it ignores the marker), and a
  sync tool can replay an old format 2 copy: either makes `redact`/`tocomment` refuse on every
  v0.3 machine until someone reindexes again (fail closed, never a leak). A v0.1.x binary never
  overwrites a format 3 record it can't read (Stage 1, commit ab1f2ad). Release notes: upgrade every
  machine to ≥ 0.2 before relying on `redact`.
- **Agents blocked.** A refusal sends the agent to the user for a sudo command; the prompt text
  (task 10) must say so, or agents may try workarounds.
- **Performance.** The scan is O(text × distinct stored lengths); a large file against a large
  vault may be slower than today's per-line regexes. Task 6 measures; a large regression goes to
  the owner before task 7.
- **Parallel Stage 3** edits overlap at `Apply.cs`'s overload and `FingerprintIndex.cs`: both are
  Stage 2's (tasks 1 and 4, pushed first).
