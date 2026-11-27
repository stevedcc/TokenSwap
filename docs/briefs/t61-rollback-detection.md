# Brief T61: notice records and keyring slots rolled back to an older copy (#197)

Issue: https://github.com/stevedcc/TokenSwap/issues/197. Milestone 0.3.3. Design: Part 2 of
`docs/superpowers/specs/2026-11-27-merge-discards-and-rollback-design.md` at **2f1ed12** (branch `design/records-033`;
still under review, GLM round 3 pending: if the design moves after 2f1ed12, stop and ask which wins). Its body is
authoritative where this brief is silent; this brief wins where it rules on something the design leaves open (the
rulings are marked **R-n**).

**Base: `origin/main` after T60 (#312) is merged** (T58 → T60 → T61, serialised: the design's "Briefs" section). This
brief's file and line citations are at `origin/main` dcc4c04, before T58 and T60; both move lines in
`RecordVaultStore.cs`, `VaultWriter.cs` and `VaultView.cs`, so find each place by the member named. No other brief that
edits `RecordVaultStore.cs`, `RecordMerge.cs`, `RecordWrites.cs` or the token grammar runs beside this one.

Read AGENTS.md and CLAUDE.md first (AGENTS.md "The record store", "Privilege Boundary"). Then: the design's Part 2,
§1.3 (`ValueLineage`), §1.5 (writes), the T61 test table and "Briefs"; `TswapCore/RecordVaultStore.cs` (`ForFolder`
`:98-103`, `LoadConfig` `:181`, `SaveConfig` `:189-205`, `WriteMachineConfig` `:234-244`, `ReadKeyringWithCopies`
`:254-286`, `WriteKeyring` `:294-306`, `LoadSecrets` `:490`, `OpenSecret` `:570-655`, `BeginWrite` `:672`,
`OpenFromMetadata` `:731`, `CommitWrites` `:828`, `LoadRecords` `:1127-1167`, `FoldConflictCopies` `:1217`, `Reindex`
`:1401`, `LoadMetadata` `:1667`, `MergeRecords` `:1895`, `WriteAll` `:1981-2047`); `TswapCore/VaultWriter.cs` (all);
`TswapCore/Vault/VaultUnlocker.cs` (`FindOwnMachineSlot` `:1139`, `HardwareSlotOpens` `:1194`, `UnlockKeyring`
`:1302-1348`); `TswapCore/Keyring/KeyringUnion.cs`; `TswapCore/FileOwnership.cs` (`WriteAtomic` `:159`);
`TswapCli/Commands/VaultCommand.cs`; `TswapCore/Broker/BrokerSecrets.cs:66-128`; `TswapTests/FleetMachine.cs`,
`TswapTests/RecordConflictTests.cs` (its fixed clock `:16`, `:25-31`), `TswapTests/SlotAcceptRecordVaultTests.cs` (a TPM
machine and a key-A machine sharing a vault, `:20-43`), `TswapTests/FileOwnershipTests.cs` (`FakeOwnership` `:43`,
`Privileged_IntoAnotherUsersFolder_ConfigSecretsAndBackupAreWrittenAsTheFoldersOwner_Mode0600` `:139`).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with `Co-Authored-By: Claude Opus 5.5
<noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and report when the brief can't be built
as written. Every clock is fixed (`FleetMachine.Clock`/`Time`, set per step as `RecordConflictTests` does); no sleeps.
Values are inert markers (`marker-v1`, …); no value, seed or URI appears in any message or test failure text.

**No existing test's assertions change.** Two test-input changes are sanctioned here, and nothing else:
- `FleetMachine.CopyVaultTo` (`TswapTests/FleetMachine.cs:244-257`) and `RecordVaultTestSupport.CopyVault`
  (`TswapTests/RecordVaultTestSupport.cs:102-109`) also copy the source's `seen-records-*.json` and `seen-keyring-*`
  files into the other config folder (a copied config folder, as moving a machine does).
- A new helper `RecordVaultTestSupport.ForgetSeenState(FleetMachine)` deletes that machine's `seen-*` files. An existing
  test that hand-writes a record with **older** stamps over one this machine already saw, to set up a scenario that is
  not about rollbacks (for example `RecordStoreMetadataTests.cs:114` and `:256`, `FieldCommandTests.cs:546`,
  `RecordStorePerRecordWriteTests.cs:152`), calls it right after writing the file. List every test you change this
  way in the Task 2 commit message.

If any other existing test fails because of the new warnings, the notice, the refusal or a new file in the config
folder (`MigrateToRecordsTests.cs:108` and `SecureEnclaveTouchChoiceTests.cs:322` snapshot the config folder), stop
and list it.

## What is wrong (evidence)

- A record file replaced by an older copy is read as the current state, silently: `LoadRecords`
  (`RecordVaultStore.cs:1127-1167`) and `LoadMetadata` (`:1667`) fold the main file and its copies and report only
  unreadable records, copies and far-future stamps. A deleted secret is listed again, a burn disappears from `burned`.
- A record file deleted outright is a secret that never existed: `OpenSecret` returns null when there is no main file
  and no copy (`:608-609`).
- The only per-machine memory is `LastHlc`, one high-water mark (`Models.cs` `Config.LastHlc`, saved at
  `RecordVaultStore.cs:2043-2045`): it can't say which record went back.
- A keyring that lost slots is read as it is (`ReadKeyringWithCopies`, `:254-286`). When this machine's own slot is the
  one lost, the unlock says `Config is corrupted: keyring has no machine slot matching this machine. Restore config.json
  from backup or re-run 'tswap init'.` (`VaultUnlocker.cs:1342-1343`, also `:1197-1198`): wrong advice, since
  config.json is fine and `init` would make a new vault.
- `docs/security-model.md:836-841` says so: "tswap does not yet notice a record or keyring going back in time."

## What T61 uses from T60 (names as the design defines them)

- The `ValueLineage` extension, type `0x0103`, in `TswapCore/Keyring/ValueLineage.cs` (design §1.3): its **retired
  list `T`** (version stamps a person dropped) and its **entries** (each: `version` stamp; `flags` bit 1, burned).
  `forgotten`, `S`, `asOf` and `exactFrom` are not used here. Where this brief says "the record's entries" and "the
  record's retired list" it means T60's decoded members for those (a record without the extension has neither). A
  malformed lineage makes the record unreadable (T60), so T61 never sees one.
- T60's write staging in `VaultWriter` for `conflicts --ack`, `conflicts --clear` and `restore --discarded`, and its
  `{{x:discarded}}` resolution with `ISecretLookup.IsBurnedToken` in `VaultView.cs`.
- T60's entry-cap refusal and its cap predicate. Per the design's round 8 ruling on T60's R11, T60 writes it without
  the rollback parenthetical: `Refused: 'x' holds more values a merge set aside than a record can store (64, or 64
  KiB). Drop some first with 'sudo tswap conflicts --clear x'. Nothing was written.` T61 adds the parenthetical: on a
  record whose check is `Older`, it inserts ` (on a rolled-back record, accept it first)` after the `--clear` command
  and appends the order sentence (Task 2).
- T60's test helpers for a "0.3.2-shaped" write (the extension dropped, or kept byte for byte with a stale `asOf`).

If T60 as merged names any of these differently, use T60's names; if one is missing, stop and report.

## Amendments (design rounds 8-9)

The design at 2f1ed12 folds R-1 to R-15 below in as its own rulings and changes the model. All of it is in the body
below; this list says where.

- The `restore-slots` vault-id step is dropped (round 8 model 8): Task 3's steps are renumbered, its row now expects
  the "no record of slots" text, and a malformed `VaultId` is treated as absent everywhere. Every text here matches
  the design's Appendix A: R4 loses the "import of an export" cause (round 8, Claude 4) and gains the "retired value
  back" text; `restore-slots` handles a `keyring` the codec refuses (round 9, M-9).
- **The floor takes only persisted entries** (round 8 model 1): `Discarded` and `Retired` rise only from entries and
  retirements held in an authenticated file (a main file or a conflicted copy as loaded, or what this machine
  commits), never from a fold's in-memory result (Task 1 `PersistedLineage`, Task 2).
- **A floor `Retired` list, never pruned** (round 8 model 5): the stamps this machine saw in a record's `T` in an
  authenticated file. An entry the record retires and no longer holds moves from `Discarded` to `Retired`; R4 warns
  when a `Retired` stamp is an entry again, whoever merged it (Task 1).
- **The floor pair is `(Version, Deleted, Burn)`** (R-1, now the design's §2.3).
- **R1 is checked again at save** for the records a write commits, against the floor re-read then (round 8, Claude 8),
  and **an R3 record raises nothing**, not even from its copies (round 8, Claude 5) (Task 2).
- **Elevation words** (round 8, MiMo M-5): R-16 below.
- **`KeyringSlotId` null** (round 8, Claude 13): the "differs" texts gain one sentence, and a lost own slot then shows
  today's unwrap failure (Task 3).
- **Documented limits** (Task 5): the mixed-version entry loss (round 9 amendment 1: anti-goals, §1.6, §2.8), the
  plain-value rollback-then-stale-write case and the deleted copy whose fold failed (round 9, M-8), the burn
  exception's lost incident record (round 8, Claude 7), R4 past the `T` cap (round 8, Claude 10).

## Rulings (where the design is open or contradicts the code)

- **R-1, the floor records a delete.** The design's floor (§2.3) has no record type, but its texts and tests need "it
  was deleted" (`delete x`, then the pre-delete file put back). The floor gains `"Deleted": true` (omitted when false),
  part of the `(Version, Burn)` pair: replaced whole with it, never on its own. Still `Format` 1.
- **R-2, the date in "saw on …"** is the physical time of the floor's `Write` stamp (the newest copy seen was written
  then; the design's example shows that time).
- **R-3, no `--verbose` form.** The store has no verbose flag (`VaultStores.Open`, `TswapCore/VaultStores.cs:16-22`,
  takes none). R1 shows the short file form (`3f2a…c9`: first 4, `…`, last 2) because `accept-rollback NAME` takes
  the name; **R2 always shows the full 64-hex name**, since `--file` needs it and the unreadable-record warning
  already prints full names (`RecordVaultStore.cs:1185-1188`).
- **R-4, one record or a summary.** A command that reads all metadata (`LoadMetadata`, and the full load
  `LoadRecords`) prints the full R1/R2 text when exactly one record is flagged, and one summary line for two or more
  (design §2.5; the design's first test row expects the full text from `names`). A later open of a named secret in the
  same command still prints that record's full text once.
- **R-5, R2 needs no file at all.** "No usable copy" (§2.4) with a file present stays today's unreadable record (R3):
  `OpenFromMetadata` throws `UnreadableRecordException(…, "no readable copy")` (`:783`), which already refuses
  writes. R2 is a floor whose file name has no main file and no conflicted copy in the scan.
- **R-6, format 2 records under `FormatTwoRecords.Skip`** (`:1704-1731`) are neither checked nor floored, and their
  file names, being present in the scan, are never R2.
- **R-7, the notice** (§2.3, missing `seen-records.json` on a machine that used the vault) fires only when `config.json`
  has a `LastHlc` **and no `VaultId`**, that is, a config last written before this release. Otherwise a fresh
  `migrate --to-records` (which writes `LastHlc`, `TswapCli/RecordMigration.cs:234-235`) would print it on every new
  vault. A config written by this release always gets `VaultId` (R-8), so the notice shows at most once per machine.
- **R-8, where `VaultId` is written.** `SaveConfig` of a non-detached store fills a missing `VaultId` from the keyring
  being saved, else from the vault folder's `keyring` when it exists: that covers `init` (`InitCommand.cs:303`) and
  `slot accept` (`SlotCommand.cs:946`) without editing them. `migrate --to-records` writes `config.json` itself
  (`RecordMigration.cs:235`); T61 adds `VaultId` to that one `newConfig` (the design names migrate; the Briefs list
  omits the file). A config without one gets it at the first save of `seen-records` after an authenticated load, and
  at any record write (`WriteAll`'s config save).
- **R-9, the `{{x:discarded}}` floor-burn warning** (§1.10 assigns it to T61) needs one edit in `VaultView.cs`, outside
  the Briefs file list: `IsBurnedToken` for `x:discarded` is also true when this machine's floor holds that entry's
  stamp with `Burned`. Nothing else in `VaultView.cs` changes.
- **R-10, the slot kind word** in the lost-slot warning is a short word computed in Core (the `slots` descriptions live
  in `TswapCli/Commands/SlotsCommand.cs:309-363`, which Core can't call): Recovery `recovery`; a one-key YubiKey blob or
  none (a legacy pair) `YubiKey`; FIDO2 `FIDO2`; `HardwareSlotKinds.Classify` (`TswapCore/Keyring/HardwareSlotKind.cs:62`)
  TPM kinds `TPM`, `SecureEnclave` `Secure Enclave`, `NotRecorded` `hardware`; a blob that needs a newer tswap or is
  corrupt `unknown kind`. This machine's slot adds `, this machine's`: `3f2a9c1b (TPM, this machine's)`.
- **R-11, the own-slot unlock texts** come from `VaultUnlocker` via a non-serialised `Config.KeyringFolder` that
  `LoadConfig` fills (Task 3), so every unlock path (CLI, agent, broker) gets them without new plumbing.
- **R-12, files are always 0600.** The seen files are written with `WriteAtomic(path, bytes, keepMode: false)`, as the
  YubiKey slot hint is (`WriteAtomic`'s `keepMode`, `FileOwnership.cs:159`), so a file chmodded wider is narrowed at the next write.
- **R-13, texts the design leaves out** are given verbatim below (R2 variants, the summary, damaged-file reasons, the
  write-failure warning, the R2 refusal, `reindex`'s refusal, the `accept-rollback` and `restore-slots` lines). The R4
  texts gain one closing sentence naming the repair, which the design's texts lack.
- **R-14, five tasks, not four.** The Briefs section's fourth task ("`accept-rollback` and docs") is split so the docs
  task is last and alone.
- **R-15, R4 ignores `forgotten`.** A floor entry whose retirement was later pushed out of `T` by 64 more retirements,
  on a machine that never saw the record in between, warns as gone (the safe side; design §2.4). Not tested beyond the
  R4 rows.
- **R-16, elevation words.** Every `'sudo tswap …'` in the texts below follows T58 amendment 8 (design §2.5): on
  Windows it reads `'tswap …' (from an elevated command prompt)`. Texts built in Core decide that with
  `OperatingSystem.IsWindows()` through one helper, `SeenFloor.Sudo(string command, bool windows)`, and tests pass both
  values. The command word stays the literal `tswap` in Core-built texts: the store is created in
  `VaultStores.Open` (`TswapCore/VaultStores.cs:16-22`) with no prefix, and the store's existing texts already name
  `tswap` (`RecordVaultStore.cs:1479`). Texts built in `VaultCommand.cs` use `ctx.Prefix` (the design wants `ctx.Prefix`
  everywhere; plumbing it into the store would touch `CliHost`/`VaultStores`, outside the file list).
- **R-17, `accept-rollback` and a retired value back.** Accepting sets `Discarded` to the current persisted entries
  and removes from `Retired` the stamps that are current entries again (the person keeps them); `Retired` is
  otherwise never pruned. The design is silent on how the "retired value back" R4 is accepted.
- **R-18, the clear-then-restore rows.** The design's rows "(b) clear; the pre-clear file put back … R4 silent,
  because the floor entry was pruned" and "`conflicts --clear` on M; the record file put back from before the clear; a
  stale machine writes over it" predate round 8 model 5. On the machine that saw the clear, the stamp is now in the
  floor's `Retired`, so both rows also give R4's "retired value back" text. Machines that never saw the clear stay
  silent (the documented limit).

## Task 1: the floor model and the two files

### `TswapCore/Keyring/SeenFloor.cs` (new): the rules of §2.4 as pure functions

```csharp
public sealed record FloorEntry(Stamp Stamp, bool Burned);
/// What this machine saw of one record: the floor (§2.3). Discarded and Retired never share a stamp.
public sealed record RecordFloor(Stamp Write, Stamp Version, bool Deleted, Stamp? Burn,
    IReadOnlyList<FloorEntry> Discarded, IReadOnlyList<Stamp> Retired);
/// One record's merged state (main file and usable copies) as one operation authenticated it: what R1 and R4 check.
public sealed record SeenRecord(string Name, Stamp Write, Stamp Version, bool Deleted, Stamp? Burn,
    IReadOnlyList<FloorEntry> Entries, IReadOnlySet<Stamp> Retired);
/// The entries and retirements held in the record's authenticated files: what the floor may rise from (round 8 model 1).
public sealed record PersistedLineage(IReadOnlyList<FloorEntry> Entries, IReadOnlySet<Stamp> Retired)
{
    public static PersistedLineage Of(IEnumerable<RecordMetadata> files);   // union by stamp, Burned OR-ed; T a union
    public static PersistedLineage Of(IEnumerable<SecretRecord> files);
}
public enum Rollback { None, Older /* R1 */, Missing /* R2 */ }
public sealed record FloorCheck(Rollback Rollback, IReadOnlyList<FloorEntry> EntriesGone, IReadOnlyList<FloorEntry> BurnsGone,
    IReadOnlyList<FloorEntry> RetiredBack)
{
    public bool Flagged => Rollback != Rollback.None || EntriesGone.Count > 0 || BurnsGone.Count > 0 || RetiredBack.Count > 0;
}
public static class SeenFloor
{
    public static SeenRecord Observe(RecordMetadata merged);
    public static SeenRecord Observe(SecretRecord merged);
    public static FloorCheck Check(RecordFloor? floor, SeenRecord? merged);   // merged null: no file at all
    public static RecordFloor Raise(RecordFloor? floor, SeenRecord merged, PersistedLineage persisted);
    public static RecordFloor Accept(RecordFloor? floor, SeenRecord current, PersistedLineage persisted);
    public static string Sudo(string command, bool windows);                  // R-16
}
```

- `Observe`: `Deleted` = tombstone; `Burn` = the burn stamp of the `Burns` entry whose `Version` equals the record's
  version (`CanonicalBurns` keeps one, the earliest, `RecordMerge.cs:32-48`), null for a tombstone or none; `Entries`
  and `Retired` from T60's lineage of the merged state (empty without it), `Burned` = entry flag bit 1.
- `PersistedLineage.Of` takes the record's **authenticated input files** only: `LoadedRecord.Inputs`
  (`RecordVaultStore.cs:484-488`) on the full path, the per-file decoded metadata `OpenFromMetadata` and `LoadMetadata`
  collect (`inputs`, `:734`, `:1733`), or the states `WriteAll` wrote. Never the merged result: a fold's new candidate exists
  only in memory until a write persists it.
- `Check` (F = floor, M = merged): F null → `None`, nothing else. M null → `Missing`. **R1** `Older` when `M.Write <
  F.Write`, or `M.Version < F.Version`, or `M.Version == F.Version` and `F.Burn` set and `M.Burn` null. **R4**, also on
  an R1 record: `EntriesGone` = `F.Discarded` stamps neither in `M.Entries` nor in `M.Retired`; `BurnsGone` =
  `F.Discarded` entries with `Burned` whose stamp is in `M.Entries` without `Burned`; `RetiredBack` = `M.Entries`
  whose stamp is in `F.Retired` (whoever merged it).
- `Raise`: `Write` the larger of F's and `merged.Write`. The pair from `merged`: F null or `merged.Version > F.Version`
  → `(merged.Version, merged.Deleted, merged.Burn)` whole; equal versions → F's version and `Deleted`, `Burn` the
  earlier of the two non-null burns; `merged.Version < F.Version` → F's pair unchanged. `Retired` = F's ∪
  `persisted.Retired`, never shrunk. `Discarded` = the union by stamp of F's and `persisted.Entries`, `Burned` OR-ed,
  minus every stamp now in `Retired` (an entry the record retires moves to `Retired`; that is also how a
  `conflicts --clear` or `restore --discarded` on this machine drops it, §1.5). Lists ascending by stamp.
- `Accept` = `(current.Write, current.Version, current.Deleted, current.Burn, persisted.Entries, F.Retired ∪
  persisted.Retired minus the stamps in persisted.Entries)` (R-17).

Tests (`SeenFloorTests`, stamps built from fixed HLCs and two origins A and B; `v10` etc. are version stamps, `t1 < t2`
burn stamps):

Rows give one state for both `merged` and `persisted` unless they name them apart.

| Floor | Merged | `Check` | `Raise(floor, merged, persisted)` |
|---|---|---|---|
| null | `(w5, v5)` | None | `(w5, v5)` |
| `(w5, v5)` | null | Missing | n/a |
| `(w8, v8)` | `(w9, v5)` (older value, newer write) | Older | n/a |
| `(w8, v8)` | `(w7, v8)` (a field change lost) | Older | n/a |
| `(w8, v8, burn t1)` | `(w9, v8, no burn)` | Older | n/a |
| `(w8, v10, burn t1)` | `(w9, v12, no burn)` | None | `(w9, v12, no burn)`: the pair whole |
| `(w8, v10, burn t2)` | `(w9, v10, burn t1)` | None | burn `t1` |
| `(w8, v10, burn t1)` | `(w9, v10, burn t2)` | None | burn `t1` |
| `(w8, v8, Deleted)` | `(w9, v5)` live | Older | n/a |
| entries `{a, b burned}` | entries `{a}`, retired `{b}` | None | `Discarded {a}`, `Retired {b}` (b moved) |
| entries `{a}` | no entries, no retired | EntriesGone `{a}` | entries `{a}` kept |
| entries `{a burned}` | entries `{a}` not burned | BurnsGone `{a}` | `{a burned}` (OR) |
| entries `{a}` | entries `{a, c}` | None | `{a, c}` |
| `Retired {a}` | entries `{a}` (an older merge or a put-back file) | RetiredBack `{a}` | `Retired {a}`, `Discarded` without `a` |
| `Retired {a}` | no entries, retired `{}` (a 0.3.2-shaped merge dropped `T`) | None | `Retired {a}` kept (never pruned) |
| null | merged entries `{a}`; persisted entries `{}` (a fold's in-memory candidate) | None | `Discarded {}` |
| entries `{}` | merged entries `{a}`; persisted `{a}` (the fold written) | None | `Discarded {a}` |
| `(w8, v8)`, entries `{a}` | `(w7, v8)`, no entries | Older and EntriesGone | n/a |
| `Retired {a}`, entries `{b}` | `Accept`: current entries `{a, b}` | n/a | `Accept` gives `Discarded {a, b}`, `Retired {}` |

`Sudo("vault merge <a newer copy>", false)` is `'sudo tswap vault merge <a newer copy>'`; with `true`, `'tswap vault
merge <a newer copy>' (from an elevated command prompt)`.

Break-it-once: raise `Burn` independently of `Version` (take the earliest burn whatever the version); the
`(v10, burn t1)` → `(v12, no burn)` row must fail. Drop the version clause of R1; the `(w9, v5)` row must fail. Raise
`Discarded` from `merged.Entries` instead of `persisted.Entries`; the in-memory-candidate row must fail. Prune
`Retired` when the record's `T` no longer holds a stamp; the "dropped `T`" row must fail.

### `TswapCore/SeenState.cs` (new): the two files

```csharp
internal enum SeenFileState { Present, Missing, Damaged }
internal sealed record SeenRecordsFile(SeenFileState State, IReadOnlyDictionary<string, RecordFloor> Floors);
internal sealed class SeenState(string configDir, DirectoryOwnerMatcher owner, TextWriter? warnings)
{
    public static string Prefix(byte[] vaultId) => Convert.ToHexStringLower(vaultId)[..16];
    public string RecordsPath(byte[] vaultId);   // <configDir>/seen-records-<Prefix>.json
    public string KeyringPath(byte[] vaultId);   // <configDir>/seen-keyring-<Prefix>
    public SeenRecordsFile ReadRecords(byte[] vaultId);
    /// Re-reads the file, applies <paramref name="apply"/> to what is on disk now, writes only when the bytes change.
    public void SaveRecords(byte[] vaultId, Func<IReadOnlyDictionary<string, RecordFloor>, IReadOnlyDictionary<string, RecordFloor>> apply);
    public Keyring.Keyring? ReadKeyring(byte[] vaultId);                    // null: missing or damaged
    public void SaveKeyring(Keyring.Keyring folder, IReadOnlyList<Slot> add); // union with the file on disk, by slot id
    public IReadOnlyList<string> KeyringFiles();                            // every seen-keyring-* in configDir, ordinal
    internal Action<string, byte[]>? Write { get; set; }                   // test seam; default owner.WriteAtomic(path, bytes, keepMode: false)
}
```

The JSON (`System.Text.Json` through a source-generated context declared in this file, `SeenStateJsonContext`):
`{"Format":1,"Records":{"<file>":{"Write":"…","Version":"…","Burn":"…","Deleted":true,"Discarded":[{"Stamp":"…","Burned":true}],"Retired":["…"]}}}`
(design §2.3); `Deleted`, `Burn`, `Discarded`, `Burned` and `Retired` omitted when false, null or empty. Written
compact, keys in ordinal order, `Discarded` and `Retired` ascending by stamp, so equal floors give equal bytes. A stamp is `<ms>.<logical>@<32 hex>`: write it with
`Hlc.ToString()` (`Hlc.cs:56-57`), `@`, `Convert.ToHexStringLower(origin)` (or T60's full-form formatter if it added
one: the same text).

**Reading is strict, and anything else is "damaged"** (parser-first: this is our own format, read only by this code):
options `AllowDuplicateProperties = false`, `UnmappedMemberHandling = Disallow`, case-sensitive names, no comments or
trailing commas (the defaults). `Format` must be the number 1. A `Records` key must be exactly 64 characters of
`[0-9a-f]`. A stamp must match `^[0-9]{1,19}\.[0-9]{1,10}@[0-9a-f]{32}$` with the milliseconds fitting a `long` and the
logical part a `uint`. Two `Discarded` entries of one stamp, a stamp twice in `Retired`, a stamp in both lists, or
`Write`/`Version` missing, are damaged. If
`AllowDuplicateProperties` isn't available in this SDK, stop and report. `seen-keyring` is damaged when
`KeyringCodec.Decode` (`TswapCore/Keyring/Keyring.cs:217`) throws, or when its vault id, format version or `K`
differs from the folder keyring's or from its own file name's prefix.

Texts (stderr, each at most once per command and file):
- damaged: `Warning: <path> can't be read (<reason>); this machine starts tracking record versions again from now.`
  (for `seen-keyring`: `…; this machine starts tracking the keyring's slots again from now.`), reasons: `it is not
  valid JSON`, `its Format is <n>, not 1`, `record <file>'s <field> is not a stamp`, `a key is not a record file
  name`, `it isn't a keyring this tswap reads (<codec message>)`, `it holds another vault's keyring`. Then a fresh
  baseline: the damaged file is overwritten at the next save.
- notice (R-7): `Notice: this machine starts tracking record versions for this vault now; a record that was rolled
  back before now can't be detected.`
- a failed write: `Warning: <path> can't be written (<message>); rollback detection goes on from what was saved
  before.` The command goes on.

`Config` (`TswapCore/Models.cs:60-176`) gains, last, `[property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
string? VaultId = null`: base64 of the keyring's 16-byte vault id, a machine field (R-8 says where it is written). A
`VaultId` that isn't base64 of 16 bytes is treated as absent everywhere.

Tests (`SeenStateTests`, files in a temp config folder; `MachineConfigVaultIdTests` for `VaultId`):

| Input | Outcome |
|---|---|
| floors saved, read back | equal floors; file name `seen-records-<16 lower hex>.json`, keyring `seen-keyring-<16 lower hex>` (no upper-case letter) |
| saved twice with equal floors | second save writes nothing (bytes and mtime unchanged) |
| file not JSON / `Format` 2 / a stamp with upper-case hex / a stamp `-5.0@…` / a duplicate key / an unknown property / a key of 63 hex / a stamp in both `Discarded` and `Retired` | Damaged, the matching reason, empty floors |
| a floor with `Retired` only (no `Discarded`), saved and read back | equal; `Discarded` omitted from the bytes |
| no file | Missing, no text |
| `SaveRecords` whose `apply` is given what another writer put on disk between read and save | `apply` sees the disk's floors (the re-read) |
| `seen-keyring` with another vault id; with bytes the codec refuses | Damaged with its reason |
| `SaveKeyring` with slots X; then another writer adds Y on disk; save Z | file holds X, Y, Z |
| the `Write` seam throws, for `seen-records` and for `seen-keyring` | each old file intact; the write-failure warning; the next read gets the old contents |
| a file chmodded 0644, then a save (`UnixFact`) | 0600 |
| `init` of a record vault; `slot accept` (as `SlotAcceptRecordVaultTests`) ; `migrate --to-records` | `config.json` has the keyring's `VaultId` |

Break-it-once: drop `keepMode: false`; the 0644 row must fail. Write the stamp's origin with `Convert.ToHexString`; the
lower-case row must fail.

## Task 2: the record checks, the warnings and the refusal

### Where the store checks and raises (`RecordVaultStore.cs`)

A **detached** store (`_detached`, `ForFolder` at `:98-103`) never reads or writes either file: guard every step below
on `!_detached`. That covers `init --vault-dir`, `slot accept --vault-dir`, `migrate --to-records`'s temp folder,
`vault merge`'s other copy and `vault move`'s target (`InitCommand.cs:296`, `:483`, `SlotCommand.cs:457`, `:940`,
`RecordMigration.cs:158`, `:393`, `VaultCommand.cs:67`, `VaultCommand.Move.cs:143`).

The vault id comes from the folder's keyring: every `ReadKeyringWithCopies` keeps it in a field; an operation that
needs it before any keyring read calls `ReadKeyring()` first.

Each **store operation** creates one private `SeenSession`: it reads `seen-records` once at its start (no copy is kept
between operations, so the broker's long-lived store, `BrokerSecrets.cs:66-128`, reads it per operation), collects what
the operation authenticated, and saves **once** at its end through `SeenState.SaveRecords`, applying `SeenFloor.Raise`
per authenticated record **against the floors on disk at save time**, never writing back anything read earlier. Each
raise gets the merged state (for `Write` and the pair) and the record's `PersistedLineage` (for `Discarded` and
`Retired`): the authenticated input files, never the fold's in-memory result. A record whose `Check` gave `Older` or
`Missing` gets no raise; an R4 finding doesn't stop it. **An R3 record raises nothing**, not even from the copies that
authenticated before its merge failed (`FoldConflictCopies`' `RecordConflictException` branch, `:1257-1266`; the
metadata path's `:786-797`; an `UnreadableRecordException` from an open). Nothing rose: nothing is written. The
operations:

| Operation | Checks and raises from |
|---|---|
| `LoadRecords` (`LoadSecrets`, `Reindex`, `MergeRecords`' own load) | every merged `LoadedRecord.State`, its `Inputs` as persisted; R2 for floor names absent from the scan |
| `LoadMetadata` | every merged record it lists (R-6), its per-file `inputs` as persisted; R2 as above |
| `OpenSecret` for a read (`:586`, also `ReadSecretValue`, `VaultView`'s opens) | that record and its files; R2 when the floor has its file name and there is no file |
| a write session: `BeginWrite` … `CommitWrites` | each `OpenForWrite`, then every record `WriteAll` wrote; saved at the end of `CommitWrites` (in a `finally`), or by a new `internal void EndWrite(WriteSession)` that `VaultWriter.Dispose` calls when nothing was committed |
| `MergeRecords`, `Reindex` after `LoadRecords` | the records `WriteAll` wrote, one more save |

`WriteAll` (`:1981-2047`) adds what it wrote to the operation's `SeenSession` (from its returned metadata: the written
state is both the merged state and its persisted lineage) and, when the config has no `VaultId`, writes it with
`LastHlc` (`:2043-2045`).

**R1 is checked again at save** (design §2.3, round 8 Claude 8): `CommitWrites`, after its records are built and
before `WriteAll` writes the first one (beside `WriteAll`'s guard, `CheckUnchanged`, `:1989`), re-reads `seen-records` and runs
`SeenFloor.Check` on each record it is about to write, against the state that record was opened as (null for a name
with no file). An `Older` or `Missing` result throws the refusal below for the ordinally first such name, nothing
written. `BurnWrite` is exempt as at staging; `MergeRecords` is never checked (it is the repair). `Reindex` checks
the same way before its writes. A `vault merge` refused by the stale-write guard
(`CheckUnchanged`, `:2183-2194`) writes nothing, so only this folder's load raised anything. The raise of a written
record is checked like any other: a merge that wrote a state still older than the floor leaves it flagged; one that
only moved the write stamp past it clears the flag (§2.5).

On a **missing** `seen-records` file the operation checks nothing (a baseline) and prints the notice only per R-7; on a
**damaged** one, the damaged warning and a baseline.

Three test seams on the store: `internal Action? BeforeSeenSave { get; set; }` (runs before the save's re-read),
`internal Action? BeforeSaveCheck { get; set; }` (runs before the save-time R1 check of a commit) and `SeenState.Write`
(through `internal SeenState? Seen`).

### The warnings (stderr; each record at most once per store instance, which is per command in the CLI)

R1 (`SeenFloor.OlderWarning(string fileName, RecordFloor floor, SeenRecord merged)`):

```
⚠ Record <4 hex>…<2 hex> (secret '<name>') is older than the copy this machine saw on <F.Write time>: <state>. A sync
restore, a backup you restored, a stale copy or someone with access to the vault folder replaced it. If a sync is in
progress, wait for it to finish and run again. Changes to it are refused until it is repaired: 'sudo tswap vault
merge <a newer copy>', or keep this version with 'sudo tswap vault accept-rollback <name>'.
```

(One line; wrapped here.) `<state>`, the first that applies (machine = first 8 hex of the origin, as `Stamp.ToString`
gives it, `Hlc.cs:136`; times `yyyy-MM-ddTHH:mm:ssZ` of `Hlc.ToDisplayDate(physical)`, `Hlc.cs:81-89`):

| Condition | `<state>` |
|---|---|
| F `Deleted`, M live, `M.Version < F.Version` | `then its version was from machine <F.V> at <t> and it was deleted; now it holds a value from machine <M.V> at <t>` |
| both live, `M.Version < F.Version` | `then its value was from machine <F.V> at <t>; now it holds an older value from machine <M.V> at <t>` |
| M deleted, `M.Version < F.Version` | `then its version was from machine <F.V> at <t>; now it holds an older delete from machine <M.V> at <t>` |
| equal versions, the burn gone | `it was burned on <F.Burn t>; now the burn is gone` |
| the write stamp only | `a change made at <F.Write t> by machine <F.W> is missing` |

R2 (`MissingWarning`): `⚠ Record <64 hex>, which this machine saw on <F.Write time>, is missing from the vault folder
(its secret is gone).` — with `Deleted`: `(it recorded a delete; without it a stale copy can bring the secret back)` —
then ` A sync restore, a backup you restored, a stale copy or someone with access to the vault folder removed it. If a
sync is in progress, wait for it to finish and run again. Changes to it are refused until it is repaired: 'sudo tswap
vault merge <a newer copy>', or accept that it is gone with 'sudo tswap vault accept-rollback --file <64 hex>' (or
--all).`

Summary (R-4, two or more R1/R2 records in one all-metadata load): `⚠ <n> records are older than this machine saw:
<items>. Changes to them are refused until they are repaired: 'sudo tswap vault merge <a newer copy>', or keep them
as they are with 'sudo tswap vault accept-rollback NAME…' (--file <hash> for a missing record, --all for every one).`
Items in ordinal file order: `'<name>'` for R1, `<64 hex> (missing)` for R2; up to 5, then `and <k> more`.

R4, one line per finding (design §2.4/§2.5 texts, plus R-13's sentence):
- `⚠ <name>: a value a merge had set aside (machine <o>, <t>) is gone from its record; an older tswap's merge or a
  rolled-back file dropped it. To stop this warning: 'sudo tswap vault accept-rollback <name>'.`
- `⚠ <name>: the value machine <o> wrote at <t> (set aside by a merge) was burned when this machine last saw it; its
  burn is gone. It is still compromised. To stop this warning: 'sudo tswap vault accept-rollback <name>'.`
- `⚠ <name>: the value machine <o> wrote at <t> was dropped on purpose (here or on another machine), but an older
  tswap's merge, a rolled-back file, or 64 later drops on this secret brought it back. Drop it again with 'sudo tswap
  conflicts --clear <name>'.`

`run` with `{{x:discarded}}` on an entry the floor saw burned gives T60's burned-value warning (R-9).

### The refusal (`VaultWriter.cs`)

`VaultWriter` asks the store after each open: `internal Rollback RollbackOf(WriteSession session, string name)` (`Older`
or `Missing` from that session's checks, else `None`). `Stageable` (`:222-234`) records a flagged name in a new
`SortedDictionary<string, Rollback> _rolledBackStaged` and stages nothing, **except** for `Burn` (`:129-133`), which
stages as today. `Commit` (`:181-195`) throws, after the unreadable refusal and before `CommitWrites`, for the ordinally
first name, exit 1, nothing written:

- `Older`: `Refused: the record of '<name>' is older than the copy this machine saw (see the warning above), so
  changing it could undo a change made elsewhere, such as a delete or a burn. Repair it first: 'sudo tswap vault merge
  <a newer copy>', or 'sudo tswap vault accept-rollback <name>' to keep this version. Nothing was written.`
- `Missing`: `Refused: the record of '<name>' is missing from the vault folder, though this machine saw it (see the
  warning above), so writing it could undo a change made elsewhere, such as a delete or a burn. Repair it first: 'sudo
  tswap vault merge <a newer copy>', or 'sudo tswap vault accept-rollback <name>' to accept that it is gone. Nothing was
  written.`
- for `delete`, before `Nothing was written.`: `To delete it anyway, accept its current state first: 'sudo tswap vault
  accept-rollback <name> && sudo tswap delete <name>'.`
- when the record is also at T60's entry cap, before `Nothing was written.`: `Because it also holds as many set-aside
  values as a record can store, repair it in this order: 'sudo tswap vault accept-rollback <name>', then 'sudo tswap
  conflicts --clear <name>', then 'sudo tswap vault merge <a newer copy>' if one exists.` The same sentence is
  appended to T60's cap refusal when `vault merge` hits the cap on an `Older` record.

`Restore` (`:148-173`), and T60's `restore --discarded`, throw the refusal at once, before decrypting anything. This
covers `create`, `ingest`, `add`, `rotate`, `ingest --rotate`, `restore`, `delete`, `field set`/`unset`/`adopt`,
`import`, `conflicts --ack`/`--clear` and `restore --discarded`. `vault merge` is never refused (it is the repair).
`Reindex` (`:1401-1430`) refuses, after its unreadable check and before writing, on `Older` records only (it writes no
file for an R2 one): `Refusing to reindex: <n> record(s) are older than this machine saw (<files>). Repair each first:
'sudo tswap vault merge <a newer copy>', or keep its current state with 'sudo tswap vault accept-rollback --file
<file>'. Nothing was written.`

Tests (`RollbackDetectionTests`: `FleetMachine` A, B, C sharing or copying one vault folder; a "sync" copies files; a
"conflict" is `<hash>.sync-conflict-20261114-162020-ABCDEF`; `T0` = 2026-11-14T16:20:16Z, one minute per step):

| Steps | Outcome |
|---|---|
| A writes `x`; save `records/<x>`; A rotates `x`; put the saved copy back; `names` on A | the R1 text naming `x`, `<4>…<2>`, "now it holds an older value"; the floor not lowered |
| then `rotate x` | the `Older` refusal, exit 1, the file's bytes unchanged |
| then `burn x` | written; the R1 text again at the next `names` |
| then `sudo vault merge <folder with keyring and the newer file>` | no warning afterwards; `rotate x` works |
| instead `sudo vault accept-rollback x` | no warning; `rotate` works; the floor equals the current state |
| `delete x`, then the pre-delete file put back; `names` | "it was deleted; now it holds a value"; `names` lists `x` |
| `burn x`, then the pre-burn file put back | "it was burned on …; now the burn is gone" |
| `field set x k v` rolled back | "a change made at … is missing" |
| a record file deleted; `names`; `create x` | the R2 text with the full name; `create` gets the `Missing` refusal; `accept-rollback --all` clears it |
| two records rolled back; `names` | one summary line naming both |
| normal sync: B rotates, the file copied to A | no warning; A's floor raised |
| a conflict: the older file kept as main, the newer as the copy | no warning |
| the #312 case (A and B rotate, conflict) on both machines | no rollback warning on either |
| `conflicts --clear` on B, synced to A | no R4 |
| an entry dropped by a 0.3.2-shaped merge (main rewritten without the extension, newer write stamp) | R4 "is gone" only; writes work |
| `conflicts --clear` on A, then a 0.3.2-shaped merge drops the lineage | no R4 |
| machine C first sees an entry already acknowledged; then the record 0.3.2-shaped merged without it | R4 on C |
| an entry's burned flag rolled back (pre-burn file back, entry present) | the R4 burn text; `{{x:discarded}}` still warns burned |
| A burns `v10`; B rotates to `v12`; sync; `names`, `rotate` on A | no warning; `rotate` works |
| A and B burn `v10` concurrently; sync | no warning |
| `conflicts --ack`, `--clear`, `restore --discarded` on an R1 record | each the `Older` refusal |
| `{{x:discarded}}` on an R1 record | the value given to the child; the R1 text on stderr |
| `delete x` on a flagged record; then `accept-rollback x`, `delete x` | the refusal with the delete line; then deleted |
| a rolled-back record at 64 entries: `vault merge` (adds one), `conflicts --clear`; then `accept-rollback`, `--clear`, `vault merge` | the first two refused (cap, rollback), both with the order sentence; the sequence works |
| `vault reindex` with an R1 record | the reindex refusal naming its file; nothing written |
| a command on an unchanged vault | `seen-records` bytes and mtime unchanged |
| `seen-records` missing; another vault id's file only; not JSON | baseline, no text / baseline, no text / the damaged warning; nothing refused |
| missing `seen-records`, `config.json` with `LastHlc` and no `VaultId` | the notice once; `VaultId` written; the next command prints nothing |
| P1 (a store with `BeforeSeenSave`) loads metadata; the seam writes a floor with a larger `Write` and a smaller pair, then P1 saves | `Write` the larger; the pair whole from the larger version |
| floor `(v10, burn t2)`; on disk `(v10, burn t1)` written in the seam | burn `t1` |
| two operations' entry lists interleaved through the seam | the union by stamp, burned bits OR-ed |
| P1 loads a flagged `x`; the seam runs `accept-rollback x`; P1 saves | still accepted (no warning next) |
| the same with an R2 record | the R2 entry stays removed |
| the same through `VaultBrokerSecretSource.Read` | still accepted |
| P1 authenticates the pre-rollback state; `accept-rollback x` in the seam; P1 saves | `x` flagged again (the safe direction) |
| a conflicted copy's removal arrives before the new main file, then the main file | R1 with "wait for it to finish", then no warning |
| a rollback seen only in the write stamp, then `vault merge`; a version rollback, then `vault merge` of an older copy | the first no longer reported; the second still is |
| `init --vault-dir`, `slot accept --vault-dir`, `migrate --to-records`, `vault merge <other>`, `vault move <target>` | no `seen-*` file in the other, target or temp folder; this machine's files raised only from its own folder |
| a `vault merge` refused by the stale-write guard | floors equal what this folder's files hold |
| a read-only config folder (`UnixFact`), `names` | one write-failure warning; floors unchanged; exit 0 |
| a machine whose clock is behind writes after seeing the record | no R1 anywhere |
| a machine a year ahead writes; its copy is then lost | R1 with the future time, and the year-ahead warning |
| an R4 warning, then a newer write of the record | `Write` and the pair still rise |
| `accept-rollback x` on a record with an R4 warning | R4 silent |
| a floor entry whose stamp is in the record's retired list | moved from `Discarded` to `Retired` at the next save |
| each write command, `delete` included, on a fixture vault | no main record file disappears (R2's premise) |
| clear; A's later copy (written after a burn) merges | no entry re-forms; R4 silent (`a` is retired, which a person did) |
| clear on A; the pre-clear file put back, its copies gone; `names` on A | the entry back as that file held it; R1 (write stamp); R4's "retired value back" text (R-18) |
| the same on B, which never saw the clear | R1 only if B's floor saw the clear's write; no R4 (the limit, §2.4) |
| clear; the pre-clear file put back while a copy carrying `T` survives | no entry |
| `--clear` on A; the pre-clear file put back; a stale machine writes over it | no R1 (the limit); the entry back open (warning) or acknowledged (silent) as the file held it; on A also R4's "retired value back" (R-18) |
| a retired stamp brought back by a 0.3.2-shaped merge that keeps an older copy's extension (`T` without the stamp, the entry present) | R4 "retired value back" on every machine that saw the retirement in a file; writes work |
| Claude r7 C-1's three machines: B folds (A, B) in memory (entry `a`, nothing written); C writes its own fold without `a`; B reads C's main file | no R4 on B: `a` was never floored (round 8 model 1) |
| the same with B **writing** its fold before C's main arrives | `a` floored; R4 only if a later merge drops it without a retirement |
| a fold on A sets `a` aside in memory (never written); a 0.3.2-shaped fold of the same copies writes the merged state | on A: no entry, no R4, no `[CONFLICT]` (the documented loss, round 9 amendment 1) |
| the same, but A burns the record first (entry `a` persisted), then the 0.3.2-shaped fold | R4 "is gone" on A |
| an R3 record (copies that can't be merged) whose copy authenticated | nothing raised; after the user removes the damaged copy, no R1 |
| someone deletes the newer conflicted copy of a record whose fold had failed (R3) | no R1: undetected (round 9, M-8; documented) |
| P1 opens `x` for a write; `BeforeSaveCheck` raises `x`'s floor through P2 (another machine's newer file folded on this machine) and then puts the older file back; P1 commits | the `Older` refusal at save; nothing written |
| R2 with a conflicted copy present and no main file | R3 (the unreadable text), not R2 |
| R1's "older delete": the floor saw a value, the put-back file holds an older delete | "now it holds an older delete" |
| the upgrade notice with `config.json` holding `LastHlc` and a `VaultId` | no notice |
| a plain value put back older, then rotated on by a machine above the floor | R1 until that rotation, then silent: the newer value is gone (the documented limit, §2.4) |
| every Core-built text with `windows: true` | `'tswap …' (from an elevated command prompt)` in place of each `'sudo tswap …'` |
| the same for a delete, then a stale machine writes a newer value | no R1 (the limit) |
| `run` of another secret | no warning about `x` |
| a `run` with `{{x}}` on an R1 record after `names` printed the summary | the full R1 text once |
| every new text on a vault of inert markers | no marker, seed or URI on either stream, in any form `Redaction.Variants` lists |

Break-it-once: compare the main file instead of the merged state (the conflict row warns); treat a missing file with
no copies as unchanged (the R2 rows are silent); let R4 accept a stamp through `S` instead of the retired list (the
clear-then-0.3.2-merge row warns, the dropped-entry row is silent); let a write go on over R1 (the `rotate`-refused row
fails); keep the floors read at the start and write them back at save (the P1/P2 rows lose the accept); raise floors
in a detached store (the `vault merge <other>` row finds a file); raise `Discarded` from the merged state instead of
the files (Claude's three-machine row warns); drop the save-time R1 check (the P1-commits row writes); raise from an
R3 record's authenticated copy (the R3 row gives R1 after the copy is removed); drop the `RetiredBack` check (the
0.3.2-shaped `T`-dropping row is silent).

## Task 3: the keyring check, the unlock texts and `restore-slots`

### The check (`ReadKeyringWithCopies`, `:254-286`)

After the union with the conflicted copies (non-detached only), compare with `SeenState.ReadKeyring(vaultId)` slot by
slot by id, with `KeyringUnion.SameSlot` (`KeyringUnion.cs:48-52`), never `Union` (it throws on a differing same-id
slot, `:25-29`):

- missing file: baseline, no text; damaged: its warning, then baseline;
- a seen slot the folder lacks: one line per command, `⚠ The vault folder's keyring has lost <n> slot(s) this machine
  saw before: <id8> (<kind>)[, …]. The keyring file was replaced by an older copy (a sync restore, a stale copy, or
  someone with access to the folder); machines whose slot is missing can't open the vault. Put it back with 'sudo
  tswap vault restore-slots'.` (`1 slot` / `2 slots`; `<kind>` per R-10);
- a same-id slot with other bytes: `Warning: slot <id8> in the vault folder's keyring differs from the one this machine
  saw. Slots never change once written, so the keyring was damaged or tampered with; this machine keeps the copy it
  saw. Compare <vault folder>/keyring with <seen-keyring path>.` That slot is not added;
- folder slots the copy lacks (by id, not differing) are added with `SaveKeyring` (a union with the file on disk).

The folder's own conflicted keyring copies keep today's rule (a differing same-id slot refuses, `:282`). Keyring writes
are not refused while slots are missing (`WriteKeyring` never drops a slot, `:294-306`). Add the comment the design's
non-goals ask for above `KeyringUnion.Union` (`KeyringUnion.cs:16`): slots are never removed, and #197's `seen-keyring`
and `restore-slots` rely on that; a revocation brief must revisit both.

### The own-slot texts (`VaultUnlocker.cs`, R-11)

`Models.cs` gains `public sealed record KeyringFolderFacts(string VaultDir, string SeenKeyringFile, Keyring.Keyring? Seen);`
and on `Config` `[JsonIgnore] public KeyringFolderFacts? KeyringFolder { get; init; }`. `LoadConfig` (`:181-187`) of a
non-detached store sets it (the seen copy it just compared; null when missing or damaged). With `KeyringFolder` set:

- the two "no machine slot matching this machine" throws (`:1197-1198`, `:1342-1343`), and the end of `Unlock` when no
  slot opened and `Config.KeyringSlotId` names a slot the keyring lacks, throw instead:
  - not in `Seen`: `This machine's slot <id8> is missing from the keyring in <vault folder>. The keyring file may have
    been replaced by an older copy; config.json is fine. Copy the current keyring from another machine or a backup into
    the vault folder.`
  - in `Seen`: `This machine's slot <id8> is missing from the keyring in <vault folder>, though this machine saw it there
    before: the keyring file was replaced by an older copy. config.json is fine. Put the slot back with 'sudo tswap
    vault restore-slots'.`
- when the own slot is present, no slot opened, and `Seen` holds that id with other bytes: `This machine's slot <id8> in
  the keyring in <vault folder> differs from the one this machine saw: the keyring was damaged or tampered with.
  config.json is fine. Move <vault folder>/keyring aside, copy <seen-keyring path> in its place, and compare the two.
  Then run 'sudo tswap vault restore-slots' on each other machine, so slots added since this machine last read the
  keyring come back too.` (the last sentence: design §2.7, round 8 Claude 13; `restore-slots` prints the same
  instruction when the slot it skips is this machine's own).

Without `KeyringFolder` (a classic vault, whose keyring is in `config.json`) the texts stay as they are.
`OwnerSwitchException` is never replaced. With `Config.KeyringSlotId` null (`FindOwnMachineSlot` takes the first
machine slot, `VaultUnlocker.cs:1141-1142`; `migrate` from a plain XOR vault writes it null, `TswapCli/RecordMigration.cs:140`)
a lost own slot shows as today's unwrap failure against another machine's slot, not these texts; `restore-slots`
still puts it back.

### `sudo tswap vault restore-slots [--yes]` (`VaultCommand.cs`)

`ctx.RequireSudo("vault restore-slots")`; record stores only (as `merge`, `:51-53`). **No unlock and no `LoadConfig`**
(it throws without a keyring): it reads `config.json` through a new `public Config LoadMachineConfig()` and the folder
through new store methods `public Keyring.Keyring? ReadFolderKeyring()` (null: no `keyring` file),
`public Keyring.Keyring? ReadSeenKeyring(byte[] vaultId)`, `public IReadOnlyList<string> SeenKeyringFiles()` and
`public void RestoreSlots(IReadOnlyList<Slot> slots)` (through `WriteKeyring`'s union, as the vault folder's owner).

1. No `keyring` file: today's text (`:259-260`) plus, per file in `SeenKeyringFiles()`, `This machine kept a copy of
   every slot it saw: <path>. It is a complete keyring; to put it back, copy it to <vault folder>/keyring.` Exit 1,
   nothing written. A `keyring` the codec refuses takes the same shape, with `The keyring file <vault folder>/keyring
   can't be read: <codec message>.` in place of today's text.
2. No seen file for the keyring's vault id (missing or damaged): `This machine has no record of slots for vault <16
   hex>; nothing to put back.` Exit 1.
3. Missing = seen slots whose id the folder lacks; a same-id slot with other bytes is skipped with the "differs"
   warning, and when it is this machine's own slot the own-slot "differs" text follows. None missing: `Nothing to put
   back.` Exit 0.
4. Each slot to add: `Putting back: <SlotCommand.DescribeSlot(slot)>` (`SlotCommand.cs:1970-1982`: id, kind,
   fingerprint). Input redirected and no `--yes`: `The keyring this machine saw has <n> slot(s) the vault folder's
   keyring lacks:` + one `  <DescribeSlot>` line each + `Putting a slot back gives whoever holds its device a way to
   open this vault again. Compare each fingerprint with the one shown when that slot was created, then run this again
   on a terminal to confirm each one, or pass --yes. Nothing was put back.` Exit 1 (as `merge`, `:95-101`). On a
   terminal, `YesNo.Ask(…, "Put it back? Compare the fingerprint first.", defaultAnswer: null)` per slot; a no:
   `Slot not confirmed. Nothing was put back.` Exit 1.
5. `RestoreSlots`, then `✓ Put back <n> slot(s) in <vault folder>/keyring.` Exit 0.

`HelpUsage` (`:33`) and `Description` (`:34`) name both new subcommands.

Tests (`KeyringRollbackTests`; router = TPM machine, desktop = key A, joined as `SlotAcceptRecordVaultTests.JoinWithKeyA`
does):

| Steps | Outcome |
|---|---|
| `keyring` replaced by a copy without the desktop's slot; `names` on the router | the lost-slot line naming the desktop's `<id8> (YubiKey)` |
| `keyring` replaced by a copy without the router's own slot; `names` on the router | the "though this machine saw it" text; no "Config is corrupted" |
| then `sudo vault restore-slots --yes` on the router, `_keys.PluggedIn = []` | exit 0; the router unlocks again; the desktop's slot back too; `_keys.Challenges` empty (no unlock) |
| own slot lost and no `seen-keyring` | the "may have been replaced" text naming the keyring |
| own slot present with other bytes than `seen-keyring`'s | the "differs" unlock text with the `restore-slots`-on-each-other-machine sentence; `restore-slots` skips it and prints the same instruction |
| `KeyringSlotId` null (a vault migrated from a plain XOR vault), its slot lost | the unwrap failure as today; `restore-slots --yes` puts it back |
| a slot with the same id and other bytes (not own) | the "differs" warning; not added to `seen-keyring`; the other new slots added |
| `restore-slots` with nothing missing | `Nothing to put back.`; the keyring's bytes unchanged |
| `restore-slots` with no file for the keyring's vault id | the "no record of slots" text; nothing written |
| `restore-slots` where the folder keyring's same-id slot differs | that slot skipped with the warning; the others put back |
| `restore-slots` with no `keyring` file | the refusal naming each `seen-keyring-*`; nothing written |
| `restore-slots` against a folder whose keyring belongs to another vault | `This machine has no record of slots for vault <16 hex>; nothing to put back.`; nothing written |
| `restore-slots` on a `keyring` the codec refuses | step 1's shape with the decode message; nothing written |
| `restore-slots`, input redirected, no `--yes` | refused; nothing written |
| `restore-slots` without sudo (`Sudo = false`) | refused ("requires"); nothing written |
| `seen-keyring` damaged | the warning; a fresh baseline; nothing refused |
| the config pointed at another vault | its own baseline files; the first vault's untouched |
| two commands' `seen-keyring` writes interleaved (`BeforeSeenSave`) | a union of both slot sets |
| `Ownership` = `FakeOwnership(privileged: true, euid: 0)` with the vault folder owned by uid 2000, `SudoEscalated = true`: `names`, then `sudo vault restore-slots --yes` | each `seen-*` write switched to the config folder's owner (uid 1000), both files 0600; the `keyring` write to uid 2000, its mode 0600 |
| `CliEnvironment`'s config-folder resolution (`RefuseAmbiguousMacVault` `:235`, the legacy move `:317-322`) and `VaultStores.IsRecordStore` with both files present | the same results as without them (the 0.3.2-shaped reader) |

Break-it-once: make `restore-slots` unlock first (the `Challenges` row fails); skip the `seen-keyring` comparison (the
lost-slot rows are silent); compare with `KeyringUnion.Union` (the differing-slot row throws).

## Task 4: `sudo tswap vault accept-rollback NAME… | --file <64 hex>… | --all`

`ctx.RequireSudo("vault accept-rollback")`; record stores only. Names and `--file` may be mixed; `--all` takes nothing
else. `--file` takes exactly 64 characters of `[0-9a-f]` (parser-first: what the file names are,
`FilenameHasher.ToFilename`, `TswapCore/Keyring/FilenameHasher.cs:54`); anything else is a usage error: `--file takes a
record's file name: 64 lower-case hex digits, as the warning prints it.` It unlocks (`ctx.Unlock`) and calls a new
`public IReadOnlyList<AcceptedRollback> AcceptRollback(byte[] vaultKey, IReadOnlyCollection<string> names,
IReadOnlyCollection<string> files, bool all)` that loads metadata (`FormatTwoRecords.Decode`) without printing the
rollback warnings, hashes each name (`FilenameHasher.ComputeFilename`), and in **one** save (re-read at save, as Task
2) sets each targeted flagged record's floor to `SeenFloor.Accept(floor, current, persisted)` (R-17) and removes each
targeted R2 floor;
unflagged records it authenticated are raised as by any load. `AcceptedRollback(string FileName, string? Name,
FloorCheck Check, RecordFloor Floor, SeenRecord? Current)`.

Output (stdout), per target, exit 0:
- R1: `✓ Accepted the current version of '<name>' (<why>).`, `<why>` by the Task 2 `<state>` row: `it was deleted when
  this machine last saw it` / `this machine last saw a newer version, from machine <o> at <t>` / `it was burned when
  this machine last saw it` / `this machine last saw a later change, made at <t> by machine <o>`.
- R2: `✓ Accepted that '<name>' is gone (record <64 hex>; this machine saw it on <t>).`, without a name `✓ Accepted
  that record <64 hex> is gone (this machine saw it on <t>).`
- R4: `✓ Accepted that '<name>' no longer holds <n> value(s) a merge had set aside.` and `✓ Accepted that <n> value(s)
  of '<name>' a merge had set aside are no longer marked burned.`; a retired value back (R-17): `✓ Accepted that
  '<name>' holds <n> value(s) again that were dropped on purpose; drop them with 'sudo tswap conflicts --clear <name>'
  if that is still wanted.`
- nothing flagged: `Nothing to accept for '<name>': it isn't older than this machine saw.` (`--file`: `for record <64
  hex>`; `--all`: `Nothing to accept: no record is older than this machine saw.`); an unreadable record: `Nothing to
  accept for '<name>': its record can't be read (see the warning above).`

Tests (`AcceptRollbackTests`):

| Steps | Outcome |
|---|---|
| `accept-rollback --all` with R1, R2 and R4 records | all three lines; all silent afterwards |
| `accept-rollback <name>` of an R2 record; `--file <hash>` of another | both accepted |
| `accept-rollback x` with nothing flagged | `Nothing to accept …`, exit 0, `seen-records` unchanged |
| `accept-rollback` without sudo | refused ("requires"); `seen-records` unchanged |
| `--file 3F2A…` (upper case), `--file` of 63 hex, `--all x` | usage errors, exit 1 |
| `accept-rollback x` after a delete was rolled back | the "it was deleted" line; then `delete x` works |
| `accept-rollback x` on a "retired value back" record | the R-17 line; R4 silent afterwards; `conflicts --clear x` then retires it again and R4 stays silent |
| every `accept-rollback` and `restore-slots` text on Windows (`ctx.Os`) | `'<prefix> …' (from an elevated command prompt)`, the prefix from `ctx.Prefix` |

Break-it-once: let `accept-rollback` run without sudo (its refusal row fails); accept only R1 under `--all` (the R2
and R4 parts of the first row stay flagged); keep `Retired` unchanged in `Accept` (the "retired value back" row still
warns).

## Task 5: docs and the agent prompt (last)

- `docs/commands.md`: regenerate the `vault` block (`TSWAP_REGENERATE_DOCS=1 ./runtests.sh --unit`,
  `TswapTests/Docs/CommandReferenceTests.cs:47`); sudo-table rows (`:45-47`) for `vault accept-rollback` ("Can bring
  back a deleted secret or drop a burn on this machine's view") and `vault restore-slots` ("Adds slots back to the
  keyring: each one a way to open the vault"); a "Rolled-back records and slots" paragraph under `vault`: the two
  warnings, the refusal, the three repairs and the order for a record at the entry cap.
- `docs/multi-machine.md`: a "When a file goes back" section after the merge rules: what is detected (§2.4's table, in
  prose), the "wait for the sync" case, `burn` and `vault merge` as the only writes on a flagged record, why `delete`
  refuses, the repairs, and that each machine accepts for itself. Its documented limits, each in a sentence:
  - a stale machine's newer re-creation of a deleted name, and a cleared value brought back by a put-back file that a
    stale machine then writes over (no R1; a machine that saw the clear gets R4's "retired value back");
  - **the plain-value case** (round 9, M-8): a file put back with an older value and then rotated on by a machine whose
    stamps are above the floor ends R1's flag, and the newer value rolled away is gone with no entry and no warning;
  - a deleted newer conflicted copy of a record whose fold had failed (R3) goes undetected, since R3 raises nothing;
  - `burn` on a record whose current burn was rolled away satisfies R1, so the original burn's time and reason (the
    incident record) are gone without a report (round 8, Claude 7);
  - R4 warns as gone for an entry whose retirement left `T` by the 64-stamp cap before this machine saw it (round 8,
    Claude 10).
  
  The "Mixed versions" paragraph (T60 writes it) gains the round 9 sentences (§1.6, §2.8, the anti-goals): R4 warns on
  every machine that had the entry **in a file**; an entry no machine had written yet (set aside only in a fold's
  memory) is lost without a later warning when an older tswap folds the copies, and a 0.3.x format 2 write drops the
  extension, entries and `T` together; a set-aside value is kept once a machine running this release writes the
  record, so in a folder with older machines run `tswap conflicts` after every machine is upgraded; an older tswap's
  merge or format 2 write can bring back a value a person dropped, which this release then reports ("retired value
  back").
- `docs/security-model.md`: replace the "What is not detected yet" bullet (`:836-841`) and add a "Rolled-back files"
  section (§2.9): detected on machines that saw the newer state; not detected: a vault rolled back before a machine
  first saw it, a stale machine's newer re-creation of a deleted name or a cleared value, the plain-value
  rollback-then-stale-write case, a process running as the vault's user that edits the config folder too, and a
  `seen-*` file lost, damaged or restored from a backup; detection rests only on files this machine authenticated,
  never on a merge's in-memory result;
  `seen-records-*` reveals hashed record names with burn and conflict times to whoever reads the config folder;
  `seen-keyring-*` is a complete copy of the vault's keyring (0600, owner only), so a backup of the config folder holds
  the vault's wrapped key material. A resurrected deleted secret is still handed out by `run`, `get` and the broker,
  with the warning. (The design also names `docs/setup.md`'s backup guidance; setup.md has none, so the sentence goes
  here only.)
- `AGENTS.md`: both commands in the "Requires sudo" list (`:123`).
- `TswapCore/Prompt.cs`: under "Commands you must NEVER use" (`:79-97`): `- \`sudo %CMD% vault accept-rollback <name>\`
  - Keeps a rolled-back record as it is (human use only; ask the user)` and `- \`sudo %CMD% vault restore-slots\` -
  Puts lost slots back into the keyring (human use only)`; key rule 13: `If a command warns that a record or the
  keyring is older than this machine saw, or refuses a change for that reason, stop and tell the user what it says.
  Never run the repairs yourself.` ASCII only. A `PromptTests` test pins both bullets under "NEVER" and rule 13.
- `docs/release-notes/v0.3.3.md` (create it if T58/T60 haven't): the two warnings, the refusal, the three commands,
  `VaultId`, the two config-folder files, and that 0.3.0-0.3.2 ignore them.

## Out of scope

- Part 1 (#312, T60): entries, `T`, the merge rule, `tswap conflicts`, `restore --discarded`, `{{x:discarded}}` beyond
  R-9.
- A MAC over the seen files (design L4), auto-repair of slots, slot revocation, a purge command (R2 assumes none).
- The `vault-password` file going back (the design's non-goals).
- The pre-release check with the v0.3.2 binary (design "Briefs", recorded in the PR, not a test).
- A `--verbose` flag for the store (R-3).
