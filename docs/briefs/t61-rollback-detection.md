# Brief T61: notice records and keyring slots rolled back to an older copy (#197)

This body is authoritative: every rule is stated once, as it now stands; the amendment notes record only what changed.

Issue: https://github.com/stevedcc/TokenSwap/issues/197. Milestone 0.3.3. Design: Part 2 of
`docs/superpowers/specs/2026-11-27-merge-discards-and-rollback-design.md` at **e874448** (branch `design/records-033`,
round 12; rounds 11 and 12 change only T60's parts and Appendix A's R2 `delete` line, taken below; GLM round 3 may
still change it: if the design moves after e874448, stop and ask which wins). Its body is
authoritative where this brief is silent; this brief wins where it rules on something the design leaves open (the
rulings are marked **R-n**).

**Base: `origin/main` after T60 (#312) merges** (T58 → T60 → T61, serialised: the design's "Briefs" section). This
branch was last synced with main at 686f1fe (T58 and T62 merged); main has since moved to 66c3620 (T63), and
citations marked "at 66c3620" are taken there; main is now at f2e3a5a (T64: only `TswapCore/Validation.cs`,
`RunCommand.cs`, `MsysTarget.cs` and tests), and citations marked "at f2e3a5a" are taken there. **Before starting, run `git fetch origin && git merge
origin/main`** (a merge, as AGENTS.md asks; stop and report on a conflict outside this brief's file), so the branch
holds T60. The file and line citations are at dcc4c04; T58 moved `RecordVaultStore.cs`, `VaultWriter.cs`, `Models.cs`
and `Prompt.cs` by a few lines (686f1fe), and T60 will move more, so find each place by the member named. No other brief that
edits `RecordVaultStore.cs`, `RecordMerge.cs`, `RecordWrites.cs` or the token grammar runs beside this one.

Read AGENTS.md and CLAUDE.md first (AGENTS.md "The record store", "Privilege Boundary"). Then: the design's Part 2,
§1.3 (`ValueLineage`), §1.5 (writes), the T61 test table and "Briefs"; `TswapCore/RecordVaultStore.cs` (`ForFolder`
`:98-103`, `LoadConfig` `:181`, `SaveConfig` `:189-205`, `WriteMachineConfig` `:234-244`, `ReadKeyringWithCopies`
`:254-286`, `WriteKeyring` `:294-306`, `LoadSecrets` `:490`, `OpenSecret` `:570-655`, `BeginWrite` `:672`,
`OpenFromMetadata` `:731`, `CommitWrites` `:828`, `LoadRecords` `:1127-1167`, `FoldConflictCopies` `:1217`, `Reindex`
`:1401`, `LoadMetadata` `:1675`, `MergeRecords` `:1903`, `WriteAll` `:1989-2055`, these three at f2e3a5a); `TswapCore/VaultWriter.cs` (all);
`TswapCore/Vault/VaultUnlocker.cs` (`FindOwnMachineSlot` `:1139`, `HardwareSlotOpens` `:1194`, `UnlockKeyring`
`:1302-1348`); `TswapCore/Keyring/KeyringUnion.cs`; `TswapCore/FileOwnership.cs` (`WriteAtomic` `:159`);
`TswapCli/Commands/VaultCommand.cs`; `TswapCore/Broker/BrokerSecrets.cs:66-128`; `TswapTests/FleetMachine.cs`,
`TswapTests/RecordConflictTests.cs` (its fixed clock `:16`, `:25-31`), `TswapTests/SlotAcceptRecordVaultTests.cs` (a TPM
machine and a key-A machine sharing a vault, `:20-43`), `TswapTests/FileOwnershipTests.cs` (`FakeOwnership` `:43`,
`Privileged_IntoAnotherUsersFolder_ConfigSecretsAndBackupAreWrittenAsTheFoldersOwner_Mode0600` `:139`).

One commit per task, test first (for each task: write the test, run it and quote the failure, then write the code), a break-it-once check per key test (name in the commit message which line you changed
and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with `Co-Authored-By: Claude Opus 5.5
<noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and report when the brief can't be built
as written. Every clock is fixed (`FleetMachine.Clock`/`Time`, set per step as `RecordConflictTests` does); no sleeps.
Values are inert markers (`marker-v1`, …); no value, seed or URI appears in any message or test failure text.

**No existing test's assertions change.** One test-input change is sanctioned (by the controller, round 4), and
nothing else: Task 5 adds two drivers to `SudoTableDrive` (`TswapTests/Docs/CommandReferenceTests.cs:339`), beside
`vault merge` and `vault reindex` (`:393-395`): `results["vault accept-rollback"] = R(a.Run("", "vault",
"accept-rollback", "x"));` and `results["vault restore-slots"] = R(a.Run("", "vault", "restore-slots"));`, each run
without sudo as those are, so each records its "requires sudo" refusal. `SudoTableMatchesBehaviour` (`:218-226`) needs a
driver per sudo-table row; adding them changes no assertion. (Rounds 1-3 also sanctioned `CopyVaultTo`/`CopyVault`
copying the `seen-*` files. Nothing needs it since R-7: a copy made by this build carries `VaultId`, so its first
command starts a silent baseline. It is withdrawn; MiMo r3 M-8.)

Round 1 also sanctioned a `ForgetSeenState` helper for four existing tests said to hand-write an older record over one
the machine had seen. The code at 686f1fe shows none of them does, so under this brief's `Check` none can be flagged,
and the sanction is withdrawn:
- `RecordStoreMetadataTests.cs:112-114` (`LoadMetadata_CountsOlderVariantSets`) writes a **new** record
  (`var older = NewRecord("o", S(1000), "o-value"); … WriteAllBytes(FileOf("o"), …)`) before any command has seen `o`:
  no floor exists.
- `RecordStoreMetadataTests.cs:254-256` (`LoadMetadata_DifferentSectionsWithoutFingerprints_FailClosed`) writes a new
  `s` and its copy (`NewRecord("s", v, "same")`), never seen before; the record is also R3 on the metadata path.
- `FieldCommandTests.cs:545-547` (`FieldUnset_OnVaultWithUnfingerprintedRecords_Allowed`) re-encodes `old` with **the
  same stamps** as format 2 (`Encode(SecretRecordCodec.Decode(File.ReadAllBytes(old), _key), _key,
  KeyringFormat.RecordFormatVersionV2)`): equal `Write`, `Version` and burn, no entries.
- `RecordStorePerRecordWriteTests.cs:150-152` (`Copies_FoldedAndRemoved_OnlyForTheWrittenRecord`) writes the older
  bytes as a **conflicted copy** (`File.WriteAllBytes(Copy(RecordFile(_m, _key, name)), older)`); the merged state is
  the newer main file.

If any existing test fails because of the new warnings, the notice, the refusal or a new file in the config folder,
stop and report the test, the failing assertion and why; don't change it. That includes the two that snapshot the
config folder, `MigrateToRecordsTests.cs:107-116` and `SecureEnclaveTouchChoiceTests.cs:321-330`.

## What is wrong (evidence)

- A record file replaced by an older copy is read as the current state, silently: `LoadRecords`
  (`RecordVaultStore.cs:1127-1167`) and `LoadMetadata` (`:1675` at f2e3a5a) fold the main file and its copies and report only
  unreadable records, copies and far-future stamps. A deleted secret is listed again, a burn disappears from `burned`.
- A record file deleted outright is a secret that never existed: `OpenSecret` returns null when there is no main file
  and no copy (`:608-609`).
- The only per-machine memory is `LastHlc`, one high-water mark (`Models.cs` `Config.LastHlc`, saved at
  `WriteAll`'s config save, `RecordVaultStore.cs:2051-2053` at f2e3a5a): it can't say which record went back.
- A keyring that lost slots is read as it is (`ReadKeyringWithCopies`, `:254-286`). When this machine's own slot is the
  one lost, the unlock says `Config is corrupted: keyring has no machine slot matching this machine. Restore config.json
  from backup or re-run 'tswap init'.` (`VaultUnlocker.cs:1342-1343`, also `:1197-1198`): wrong advice, since
  config.json is fine and `init` would make a new vault.
- `docs/security-model.md:836-841` (`:869-873` at 686f1fe) says so: "tswap does not yet notice a record or keyring going back in time."

## What T61 uses from T60 (names as the design defines them)

- The `ValueLineage` extension, type `0x0103`, in `TswapCore/Keyring/ValueLineage.cs` (design §1.3): its **retired
  list `T`** (`ValueLineage.Retired`, version stamps a person dropped) and its **entries** (`ValueLineage.Discarded`,
  each a `DiscardedValue`: its `Version`, and burned iff `DiscardedValue.Burn != null`, T60's decoded form of the codec's
  `flags` bit `0x01`), read with `ValueLineageCodec.Read(extensions)`; names as T60's brief gives them.
  `forgotten`, `S` (T60's `Superseded`), `asOf` and `exactFrom` are not used here. Where this brief says "the record's entries" and "the
  record's retired list" it means T60's decoded members for those (a record without the extension has neither). A
  malformed lineage makes the record unreadable (T60), so T61 never sees one.
- T60's write staging in `VaultWriter` for `conflicts --ack`, `conflicts --clear` and `restore --discarded`
  (`Acknowledge` and `ClearDiscarded` stage a `LineageWrite`, `RestoreDiscarded` a `ValueWrite`), and its
  `{{x:discarded}}` resolution with `ISecretLookup.IsBurnedToken` in `VaultView.cs`.
- T60's entry-cap refusal and its cap, `ValueLineageCodec.MaxEntries` (64) entries or `MaxEntryBytes` (65 536) encoded
  entry bytes, checked in `WriteAll` before the first write (T60 brief at e4f415b, Task 3), so `CommitWrites`,
  `MergeRecords` (`vault merge`) and `Reindex` are all capped; each `RecordWrite` carries `CapExemption Cap`
  (`internal enum CapExemption { None, EntryCount, All }`: `All` for a `ClearEdit` and `restore --discarded`,
  `EntryCount` for a `BurnWrite`, `None` for `MergeRecords` and `Reindex`). There is no predicate method: compare
  with the two constants. Per the design's round 8 ruling on T60's R11, T60 writes it without
  the rollback parenthetical: `Refused: 'x' holds more values a merge set aside than a record can store (64, or 64
  KiB). Drop some first with 'sudo tswap conflicts --clear x'. Nothing was written.` On a record whose check is
  `Older`, T61 makes it exactly (one line; GLM r3 M-6): `Refused: 'x' holds more values a merge set aside than a
  record can store (64, or 64 KiB). Drop some first with 'sudo tswap conflicts --clear x' (on a rolled-back record,
  accept it first). Because it also holds as many set-aside values as a record can store, repair it in this order:
  'sudo tswap vault accept-rollback x', then 'sudo tswap conflicts --clear x', then 'sudo tswap vault merge <a newer
  copy>' if one exists. Nothing was written.` The order sentence is the one constant Task 2's refusal also uses,
  kept word for word as Appendix A gives it.
- **T60's 0.3.2-shaped test helpers** (T60 brief at 0a4d63a, "Interfaces T61 relies on"): `internal static class
  Older032` in `TswapTests/Older032.cs`, which keeps `0x0101` and `0x0103` byte for byte and merges them by the
  whole-list rule, as v0.3.2 does:
  - `ValueWrite(SecretRecord? state, byte[] recordId, string name, byte[] value, Stamp version, DateTime created)`
    (Write = version);
  - `Burn(SecretRecord state, Stamp burn, string? reason)` (Write = burn);
  - `Delete(SecretRecord state, Stamp version)` (drops only `Fields`);
  - `MergeAll(IReadOnlyList<SecretRecord> inputs)` and `MergeAllMetadata(…)`, through T60's production option
    `RecordMerge.MergeAll(inputs, LineageRule.WholeList)` (`public enum LineageRule { Apply, WholeList }` in
    `RecordMerge.cs`, T60 brief at d9d621b);
  - `Plant(FleetMachine machine, byte[] vaultKey, SecretRecord record, string? conflictSuffix = null)` (format 3, as the
    main file or as `<hash><conflictSuffix>`).

  The state to start from is `RecordVaultTestSupport.ReadRecord(machine, vaultKey, name)`
  (`TswapTests/RecordVaultTestSupport.cs:71`). The helpers have no "write" step of their own, so a test that plays a
  0.3.2 machine's **fold** does what v0.3.2's `WriteAll` does by hand: `merged with { Write = <a new stamp above every
  input> }`, `Plant` it as the main file, and `File.Delete` the conflicted copies it folded. Every "0.3.2-shaped" row
  below is built this way (the "How" column of Task 2's table says which calls). **If T60 as merged lacks any of
  these members, stop and report**; don't write one here.

If T60 as merged names any of these differently, use T60's names; if one is missing, stop and report.

## Amendments (brief round 7: MiMo r6, at 2b8dc07)

- **I-1:** the `Format` pre-pass classifies each value on its own (`ValueKind == Number && TryGetInt64`, else "not a
  whole number"; nothing throws), in document order, and decides after the loop; rows. **I-2:** copies decoded at
  save join the record's raise (`PersistedLineage` and the merged state); a row and a break-it-once.
- M-1: an explicit null-member check; the repeated-`Records` row asserts the generic reason ("listed twice" dropped).
  M-2: the fill wording. M-3: both `restore-slots` step 1 cases. M-4: three departures added. M-5: citations fixed
  by member at f2e3a5a.

## Amendments (brief round 6: GLM r3, at 25eca57)

- **I-1:** the save-time check decodes only files new or changed since the session read them; otherwise it reuses the
  session's state (no second `RecordDecrypted`/`ValueDecrypted`); rows. **I-2:** no vault id (no `keyring` read by
  this store) skips the seen files, the notice and the `VaultId` fill silently; a row. **I-3:** the own-slot pre-check
  is `OwnBackend`'s for every backend, the end-of-`Unlock` site is dropped (never reached); rows and a break-it-once.
- Minors 1-4, 6, 8-11 taken. M-5: a new or changed copy that can't be decoded or merged at save is left out of the
  check, no new refusal; a row. M-7: each point pinned (Task 1 reasons, Task 2 refusal order and the save-time kinds,
  Task 3 unreadable `seen-keyring`, Task 4 order and output, the Windows delete line). M-12: R2 on the all-records
  paths for a floored record with only unusable copies (the safer side); `Observe` takes the earliest burn.
  Departures from the design listed under "Rulings".

## Amendments (brief round 5: MiMo r4)

- **Important:** the SeenStateTests row that listed `Format` 2 as Damaged is split: not JSON is Damaged, the format 1
  failures are Damaged, `Format` 2 is Newer (the whole table checked: no other row contradicts the pre-pass).
- M-3: the `KeyringSlotId`-null text and a row. M-4: rows 2 and 3 share the R1 accept line. M-5: a clamped stamp prints
  `far future`; a row. M-6: an R2 record's dedup key, and `apply` on a damaged file. M-2 and M-7: no change (M-2 was
  done in 2342555; M-7 goes to the design).

## Amendments (brief round 4: MiMo r3; controller rulings)

- **I-1:** `Format` is read in a tolerant pre-pass before the strict parse: above 1 (as `long`) is **Newer** (never
  written), only a format 1 file that fails is **Damaged**; rows for an unknown member at `Format` 2, `5000000000`, a
  repeated `Records` key, `null` members and a bad `Vault`; reasons named (M-2).
- **I-2:** T60's names at 0e2cdc2: the cap in `WriteAll` with `CapExemption` (`vault merge` and `vault reindex`
  capped), and `ValueLineageCodec.Read`, `SecretEntry.NewerLineages`, `LoadedRecord.NewerLineages` (T60 at e4f415b;
  non-empty means a newer-format lineage), `VaultMetadata.NewerLineageFiles`; the stops kept.
- **I-3:** the two `SudoTableDrive` drivers sanctioned and named; no assertion changes. The `CopyVaultTo` sanction is
  withdrawn (M-8: nothing needs it since R-7).
- **M-3:** the cap parenthetical goes after the quoted command. **M-7:** the own-slot rows name the desktop and pin the
  end-of-`Unlock` site. Also taken: M-4 (only `Records` keys sorted), M-5, M-6, M-9, M-10, M-1 (below).
- **M-1:** `OwnBackend`'s pre-check also fires when `FindOwnMachineSlot` returns null with `KeyringSlotId` null and no
  machine slot at all. **M-5:** file-level warnings follow the record rule: once per command in the CLI, again in the
  broker when the file's state changes. **M-6:** `SaveKeyring` itself refuses to write when the file's format version
  or `K` differs from the folder keyring's (a second guard). **M-10:** `EndWrite` is a no-op once `CommitWrites` ran:
  one save per session.

## Amendments (brief round 3: MiMo r2, Claude r2; controller rulings)

- **Design** at e874448 (rounds 11-12 touch only T60's parts and the R2 `delete` line).
- **I-1:** round 11's R2 `delete` line; `DeleteCommand.cs` asks `VaultWriter.RolledBack` before its "not found", with
  rows. **I-2:** `OwnBackend` checks the own slot before `UnlockHardware`, so TPM-only and Secure-Enclave-only machines
  get the new texts without `HardwareBlobLocator`'s "Config is corrupted" or the foreign-slot hint; rows with no
  YubiKey slot. **I-3:** the `vault merge` cap refusal cited by role as T60's merge-path cap refusal, with a stop.
  **I-4:** the save-time check runs `CheckUnchanged` first, then compares the floor with the record as on disk now;
  rows for a newer copy and a replaced main file. **I-5:** a missing `records/` folder is an empty scan (every floored
  record R2); a row. **I-6:** a read I/O error is "Unreadable", not damage: skip, warn, never write; rows. **I-7:** a
  `seen-keyring` whose version or `K` differs from the folder keyring is evidence: never overwritten, a warning,
  `restore-slots` offers the copy; a row. **I-8:** a newer-format lineage: no R4, the floor's entries kept, one warning;
  a row.
- **Claude minors, all taken:** M-1 (no main and only unusable copies: skipped on the all-records paths; the R3 row
  goes through an open, plus a `names` row), M-2 (the docs say a lost update can undo an accept), M-3 (warnings once
  per record state, so the broker warns again), M-4 (`Stageable(name, refused)`; `Burn` passes null), M-5 (`EndWrite`
  when `CommitWrites` never ran), M-6 (a higher `Format` is "Newer": never written), M-7 (file names matched exactly),
  M-8 (the `Tpm = null` unlock check, the stamp break names the read-back row, the 0644 row changes bytes), M-9
  (`SaveSecrets` raises nothing), M-10 (a slot `DescribeSlot` can't describe), M-11 (the `VaultId` fill re-reads
  `config.json`), M-12 (the two rows: the body supports `restore-slots` adding every missing slot, so the crafted
  keyring lacks both slots and the second row stands).
- **MiMo r2 minors, taken:** M1 (the three stale citations given at 686f1fe too), M2 (the refused write's kind is
  recorded, also with no entry), M3 (`Restore` routed through `Stageable`), M4 (one save for `Reindex`;
  `SaveSecrets`), M5 (`SaveKeyring` writes only on a change; a row), M6 (`TpmPlatformNotRecorded` → `TPM`), M7 (step 1
  lists only `VaultId`'s file when known), M8 (the prompt rule pinned by its text), M9 (the PR says the in-process row
  is a proxy), M10 (the docs say the notice can repeat after an older tswap writes `config.json`), M11 (bytes are the
  assertion, mtime where the file system resolves it).

## Amendments (brief round 2: MiMo r1, DeepSeek r1)

- **Base** (controller): main after T60; merge origin/main before starting; synced at 686f1fe.
- **I-1** (MiMo): the 0.3.2-shaped helpers are now cited by name, from T60 at 0a4d63a (`Older032`, with T60's
  `LineageRule`), with a stop-and-report if T60 as merged lacks them; each 0.3.2-shaped row says how it is built.
- **I-2** (MiMo, verified at 686f1fe): the `ForgetSeenState` sanction is withdrawn; none of its four tests hand-writes an
  older record over a seen one (the evidence is quoted where the sanction was).
- Taken: MiMo M-1 (`DiscardedValue.Burn != null`), M-2 (`MaxEntries`/`MaxEntryBytes`), M-3 (the rollback variant of
  C's row), M-4 (R-10 in rule order, `YubiKeySlotKinds` first), M-5 (absent `Format`/`Vault`/`Records` are damaged),
  M-6 (one write-failure warning per command), M-7 (`burn` outside the rule), M-8 (every staging path through
  `Stageable`), M-9 (a row for `delete` on an R2 name; the design's text stays), M-10 (the v0.3.2 check carried in
  Task 5), M-12 (an operation defined), and its safety notes (reads write only the config folder; the lost-update
  sentence; a `vault move` row). DeepSeek 1 (format/`K` checked by the caller), 2 (`FloorSawBurned`), 3 (the
  `RecordVaultStore.cs:257-260` citation), 4 (report, don't change, the snapshot tests), 6 (the canonical-form rule
  for stamps; "fits a `long`" kept, since 19 digits can exceed it).
- Not taken: MiMo M-11 (no action asked: the brief already follows Appendix A, R-14 and uses `names`). DeepSeek 5:
  `VaultId` is a positional member and `KeyringFolder` a body `init` property, and C# records include both in
  equality and `with` copies, so the "excluded from equality" premise doesn't hold; the brief now says `VaultId`
  takes part in both. MiMo's nit on multi-step rows: left to the implementer (one test per step is allowed).
- To the design owner: M-9's `delete` line leads to "not found" for an R2 name (the design's Appendix A text).

## Amendments (design round 10, 6262c2f)

- A `seen-records` file whose content names another vault id than its file name is damaged (the damaged-file warning,
  no floor): the JSON gains `"Vault"`, the 16 hex of the file name, and a mismatch gives the reason `it names another
  vault (<16 hex>)` (Task 1, its rows).
- A sync tool deleting a conflicted copy that had raised the floor, with no newer main file, is R1 until repaired by
  `vault merge` or `accept-rollback`, not by waiting (design §2.4, DeepSeek M-6): a row in Task 2.
- R-16 to R-18 are now the design's own (§2.5, §2.6, Tests); the design's Appendix A holds every text of this brief,
  including the cap repair-order sentence, the reindex refusal, the `--file` usage error, R-17's accept line and the
  "each other machine" sentence. The design no longer names `docs/setup.md`.

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
  writes. R2 is a floor whose file name has no main file and no conflicted copy in the scan. One exception, on the
  all-records paths only (`LoadRecords`, `LoadMetadata`; GLM r3 M-12): a **floored** record with no main file and only
  copies that can't be used, which those paths neither list nor report as unreadable today, is R2 there (the secret
  is gone from what this machine can read), with the copy warning as today; an open of it stays R3.
- **R-6, format 2 records under `FormatTwoRecords.Skip`** (`:1704-1731`) are neither checked nor floored, and their
  file names, being present in the scan, are never R2.
- **R-7, the notice** (§2.3, missing `seen-records.json` on a machine that used the vault) fires only when `config.json`
  has a `LastHlc` **and no `VaultId`**, that is, a config last written before this release. Otherwise a fresh
  `migrate --to-records` (which writes `LastHlc`, `TswapCli/RecordMigration.cs:234-235`) would print it on every new
  vault. Every config this release writes for a record vault with a keyring gets `VaultId` (R-8 lists the writers),
  so the notice shows at most once per machine.
- **R-8, where `VaultId` is written.** `SaveConfig` of a non-detached store fills a missing `VaultId` from the keyring
  being saved, else from the vault folder's `keyring` when it exists: that covers `init` (`InitCommand.cs:303`) and
  `slot accept` (`SlotCommand.cs:946`) without editing them. `migrate --to-records` writes `config.json` itself
  (`RecordMigration.cs:235`); T61 adds `VaultId` to that one `newConfig` (the design names migrate; the Briefs list
  omits the file). Two writers bypass `SaveConfig` (GLM r3 M-4, checked at f2e3a5a): `init --vault-dir` writes
  `config.json` by hand (`InitCommand.cs:496-510`; T61 sets `VaultId` from the `keyring` it read at `:488` in that
  `config`), and `slot request` on a record-store machine rebuilds the config in `KeepRecordStoreFields`
  (`SlotCommand.cs:1052-1058`; T61 adds `VaultId = current.VaultId` to its `with`; both one-line edits outside the design's file list). A config without one gets it at
  the first save of `seen-records` after an authenticated load, and at any record write (`WriteAll`'s config save).
  **The fills after an authenticated load or write also correct** (the `seen-records` save, `WriteAll`, and
  `SaveConfig` from the keyring being saved, never from the folder's `keyring` alone): a `VaultId` that is invalid or
  differs from the vault id of the keyring whose records were just authenticated is replaced by it (the seen files are
  always keyed by the folder keyring's id, so this only keeps `restore-slots` step 1 from offering another vault's
  `seen-keyring`). With no vault id known (I-2 under Task 2), nothing is filled.
- **R-9, the `{{x:discarded}}` floor-burn warning** (§1.10 assigns it to T61) needs a store accessor and one edit in
  `VaultView.cs`, outside the Briefs file list: `RecordVaultStore` gains `internal bool FloorSawBurned(string fileName,
  Stamp version)` (reads `seen-records` fresh; false for a detached store, a missing or damaged file, or no such entry),
  and `IsBurnedToken` for `x:discarded` is also true when it returns true for that entry's stamp. Nothing else in
  `VaultView.cs` changes.
- **R-10, the slot kind word** in the lost-slot warning is a short word computed in Core (the `slots` descriptions live
  in `TswapCli/Commands/SlotsCommand.cs:309-363`, which Core can't call), by these rules in order: Recovery
  `recovery`; then `YubiKeySlotKinds.Classify(slot.HwBlob)` (`TswapCore/Keyring/YubiKeySlotKinds.cs:42`): `Otp`
  `YubiKey`, `Fido2` `FIDO2`, `NeedsNewerTswap` or `Corrupt` `unknown kind`; then no blob at all (a legacy pair)
  `YubiKey`; then `HardwareSlotKinds.Classify` (`TswapCore/Keyring/HardwareSlotKind.cs:62`, which returns `NotRecorded`
  for a YubiKey blob too, hence this order): the TPM kinds (`LinuxTpmEcc`, `LinuxTpmRsa`, `WindowsTpm`,
  `TpmPlatformNotRecorded`) `TPM`, `SecureEnclave` `Secure Enclave`, `NotRecorded` `hardware`. This machine's slot adds `, this machine's`: `3f2a9c1b (TPM, this machine's)`.
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
  `tswap` (`RecordVaultStore.cs:1479`, `:1481-1482` at 686f1fe). Texts built in `VaultCommand.cs` use `ctx.Prefix` (the design wants `ctx.Prefix`
  everywhere; plumbing it into the store would touch `CliHost`/`VaultStores`, outside the file list).
- **R-17, `accept-rollback` and a retired value back.** Accepting sets `Discarded` to the current persisted entries
  and removes from `Retired` the stamps that are current entries again (the person keeps them); `Retired` is
  otherwise never pruned. The design is silent on how the "retired value back" R4 is accepted.
- **R-18, the clear-then-restore rows.** The design's rows "(b) clear; the pre-clear file put back … R4 silent,
  because the floor entry was pruned" and "`conflicts --clear` on M; the record file put back from before the clear; a
  stale machine writes over it" predate round 8 model 5. On the machine that saw the clear, the stamp is now in the
  floor's `Retired`, so both rows also give R4's "retired value back" text. Machines that never saw the clear stay
  silent (the documented limit).

**Where this brief departs from the design at e874448** (GLM r3; the design should record each):
- `Format` above 1 is **Newer** (never written), not Damaged as §2.3 (`:1304`) and its test row (`:1771`) say: the
  safer way round, since a damaged file is overwritten.
- Texts Appendix A lacks, given here verbatim: the Unreadable and Newer warnings, the newer-lineage warning, the
  keyring-differs (I-7) warning, the `KeyringSlotId`-null own-slot text, the damaged-file reasons of Task 1, the
  Windows form of the `delete` line, `restore-slots`' unreadable-copy text.
- `restore-slots` step 1 offers only the `VaultId` file (MiMo M7) and gains the keyring-differs exit (I-7).
- At save, a new or changed copy that can't be decoded or merged is left out of the check (Task 2), not refused.
- R2 on the all-records paths for a floored record with only unusable copies (R-5).
- The own-slot "missing" texts come from `OwnBackend`'s pre-check, `HardwareSlotOpens` and `:1342`; Appendix A's third
  site, the end of `Unlock`, is dropped, as no lost own slot reaches it without passing `OwnBackend` (Task 3).
- The cap refusal's parenthetical ` (on a rolled-back record, accept it first)` is a text Appendix A lacks (it says
  only that the order sentence is appended).
- The `restore-slots` "needs no unlock" row is built with `router.Tpm = null` and no key plugged in (exit 0 proves no
  unlock ran), not the design's "the unlocker seam counts none": equivalent evidence, another construction.

## Task 1: the floor model and the two files

### `TswapCore/Keyring/SeenFloor.cs` (new): the rules of §2.4 as pure functions

```csharp
public sealed record FloorEntry(Stamp Stamp, bool Burned);
/// What this machine saw of one record: the floor (§2.3). Discarded and Retired never share a stamp.
public sealed record RecordFloor(Stamp Write, Stamp Version, bool Deleted, Stamp? Burn,
    IReadOnlyList<FloorEntry> Discarded, IReadOnlyList<Stamp> Retired);
/// One record's merged state (main file and usable copies) as one operation authenticated it: what R1 and R4 check.
/// LineageUnknown: the record has a newer-format lineage (Task 2): R4 is skipped, Discarded and Retired are left as they are.
public sealed record SeenRecord(string Name, Stamp Write, Stamp Version, bool Deleted, Stamp? Burn,
    IReadOnlyList<FloorEntry> Entries, IReadOnlySet<Stamp> Retired, bool LineageUnknown = false);
/// The entries and retirements held in the record's authenticated files: what the floor may rise from (round 8 model 1).
public sealed record PersistedLineage(IReadOnlyList<FloorEntry> Entries, IReadOnlySet<Stamp> Retired,
    bool LineageUnknown = false)
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

- `Observe`: `Deleted` = tombstone; `Burn` = the earliest burn stamp among the `Burns` entries whose `Version` equals
  the record's version (`CanonicalBurns` normally leaves one, `RecordMerge.cs:32-48`; `Observe` does not rely on it),
  null for a tombstone or none; `Entries`
  and `Retired` from T60's lineage of the merged state (empty without it), `Burned` = `DiscardedValue.Burn != null`.
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
| `(w8, v10)` | `Observe` of a state whose `Burns` hold two entries for `v10`, `t2` and `t1` | n/a | `Observe` gives burn `t1` |
| entries `{a}`, `Retired {b}` | no entries; `LineageUnknown` | None (no R4) | `Discarded {a}`, `Retired {b}` unchanged |

`Sudo("vault merge <a newer copy>", false)` is `'sudo tswap vault merge <a newer copy>'`; with `true`, `'tswap vault
merge <a newer copy>' (from an elevated command prompt)`.

Break-it-once: raise `Burn` independently of `Version` (take the earliest burn whatever the version); the
`(v10, burn t1)` → `(v12, no burn)` row must fail. Drop the version clause of R1; the `(w9, v5)` row must fail. Raise
`Discarded` from `merged.Entries` instead of `persisted.Entries`; the in-memory-candidate row must fail. Prune
`Retired` when the record's `T` no longer holds a stamp; the "dropped `T`" row must fail.

### `TswapCore/SeenState.cs` (new): the two files

```csharp
internal enum SeenFileState { Present, Missing, Damaged, Unreadable, Newer }
internal sealed record SeenRecordsFile(SeenFileState State, IReadOnlyDictionary<string, RecordFloor> Floors);
internal sealed class SeenState(string configDir, DirectoryOwnerMatcher owner, TextWriter? warnings)
{
    public static string Prefix(byte[] vaultId) => Convert.ToHexStringLower(vaultId)[..16];
    public string RecordsPath(byte[] vaultId);   // <configDir>/seen-records-<Prefix>.json
    public string KeyringPath(byte[] vaultId);   // <configDir>/seen-keyring-<Prefix>
    public SeenRecordsFile ReadRecords(byte[] vaultId);
    /// Re-reads the file, applies <paramref name="apply"/> to what is on disk now, writes only when the bytes change.
    public void SaveRecords(byte[] vaultId, Func<IReadOnlyDictionary<string, RecordFloor>, IReadOnlyDictionary<string, RecordFloor>> apply);
    public (SeenFileState State, Keyring.Keyring? Keyring) ReadKeyring(byte[] vaultId);
    public void SaveKeyring(Keyring.Keyring folder, IReadOnlyList<Slot> add); // union with the file on disk, by slot id;
                                                                            // refuses (writes nothing) when the file's
                                                                            // format version or K differs from folder's
                                                                            // writes only when the bytes change
    public IReadOnlyList<string> KeyringFiles();  // names matching ^seen-keyring-[0-9a-f]{16}$ in configDir, ordinal
    internal Func<string, byte[]>? Read { get; set; }                       // test seam; default owner.ReadAllBytes
    internal Action<string, byte[]>? Write { get; set; }                   // test seam; default owner.WriteAtomic(path, bytes, keepMode: false)
}
```

The JSON (`System.Text.Json` through a source-generated context declared in this file, `SeenStateJsonContext`):
`{"Format":1,"Vault":"<16 hex>","Records":{"<file>":{"Write":"…","Version":"…","Burn":"…","Deleted":true,"Discarded":[{"Stamp":"…","Burned":true}],"Retired":["…"]}}}`
(design §2.3); `Deleted`, `Burn`, `Discarded`, `Burned` and `Retired` omitted when false, null or empty. Written
compact, the `Records` keys in ordinal order (members in the order shown), `Discarded` and `Retired` ascending by stamp, so equal floors give equal bytes. A stamp is `<ms>.<logical>@<32 hex>`: write it with
`Hlc.ToString()` (`TswapCore/Keyring/Hlc.cs:57-58`), `@`, `Convert.ToHexStringLower(origin)` (or T60's full-form formatter if it added
one: the same text).

**Three ways a file can fail, kept apart** (round 3, I-6 and M-6):
- **Unreadable**: the read itself throws (`IOException`, `UnauthorizedAccessException`; a Windows sharing or replace
  race with the broker, EIO, a NAS-backed home). Not damage: the operation checks nothing and raises nothing for that
  file, prints `Warning: <path> can't be read now (<message>); rollback detection skips this command.` once per
  command, and `SaveRecords`/`SaveKeyring` **never write** when their re-read fails this way.
- **Newer**: `Format` above 1 (`seen-records`), from a later tswap on this machine. Check nothing, never write, and warn
  once per command: `Warning: <path> was written by a newer tswap; this one doesn't use or change it.`
- **Damaged**: a file whose own `Format` is 1 and which fails the rules below. Only a damaged file gets the baseline
  and is overwritten at the next save.

**`Format` is read first, in a tolerant pre-pass** (round 4, MiMo r3 I-1), before any strict rule:
`JsonDocument.Parse` of the bytes (which keeps repeated properties), then every root property named exactly `Format`
(`EnumerateObject`, not `GetProperty`, so a repeated `Format` is seen whole), walked in document order. **Each value
is classified on its own** (MiMo r6 I-1): only when `ValueKind == JsonValueKind.Number && TryGetInt64(out n)` is it
an integer `n` (`TryGetInt64` **throws** `InvalidOperationException` on a value that isn't a number, so it is never
called on one; it returns false for `1.0`, `1e3` and a number beyond `long`). Every other value (`"1"`, `true`,
`null`, an object, `1.0`, `1e3`, beyond `long`) is "not a whole number". `JsonDocument.Parse` failing (a
`JsonException`) is "not JSON". Nothing in the pre-pass throws. **After the loop**, the first of these that applies
decides (GLM r3 M-7; the safer state wins, since only a Damaged file is overwritten, so the order of repeated
members never matters):
- not JSON: **Damaged**, reason `it is not valid JSON`; the root not an object: **Damaged**, `it is not a JSON object`;
  no `Format`: **Damaged**, `it has no Format`;
- any value an integer above 1 (so `5000000000` too): **Newer**, whatever else the file holds (unknown members,
  other stamp spellings, another `Format` beside it, before or after);
- any value not a whole number: **Damaged**, `its Format is not a whole number`;
- any integer below 1: **Damaged**, reason `its Format is <n>, not 1` (`<n>` the first such value in document order);
- otherwise (every value is the integer 1, concluded only here): the strict parse below, which rejects a repeated
  `Format`.

Only files whose names match `^seen-records-[0-9a-f]{16}\.json$` and `^seen-keyring-[0-9a-f]{16}$` are ever read
(`WriteAtomic`'s temp files, `<name>.<12 hex>.tmp`, `FileOwnership.cs:163`, never match).

**Format 1 reading is strict, and anything else is "damaged"** (parser-first: this is our own format, read only by
this code):
options `AllowDuplicateProperties = false`, `UnmappedMemberHandling = Disallow`, case-sensitive names, no comments or
trailing commas (the defaults). A `JsonException` the strict parse throws for anything not covered by a named reason
below (an unknown member, a repeated member, a member of the wrong JSON type) gives the reason `it doesn't follow
format 1 at <path>`, `<path>` being `JsonException.Path` (`$` when null); the file holds only hashed names and
stamps, so the path reveals nothing. `Format`, `Vault` and `Records` are required (absent: damaged, reason `it has no
<member>`; an empty `Records` object is fine). `Vault` must be 16 characters of `[0-9a-f]` (otherwise reason `its
Vault is not a vault id`) and equal the file name's 16 hex (a mismatch: `it names another vault (<16 hex>)`).
**Explicit `null` members** (MiMo r6 M-1): the options above deserialise `"Burn": null` into a nullable member
silently, which would read as "no burn" (fail-open: R1's "the burn is gone" lost). So the reader checks the
`JsonDocument` of the pre-pass before the strict parse: any member whose `ValueKind` is `Null`, at the root, in a
`Records` entry, in a `Discarded` item, or as a `Records`, `Discarded` or `Retired` element, makes the file damaged,
reason `record <file>'s <field> is null` (`<field>` the member's name; at the root, `it has a null <member>`); the
writer never writes `null`. **Duplicate keys inside `Records`**: `AllowDuplicateProperties = false` (already used on
a source-generated context here, `TswapCore/Broker/BrokerConfig.cs:222-229`) is applied by `System.Text.Json` to the
whole document, nested objects included, so a repeated `Records` key is a `JsonException` and gets the generic
reason `it doesn't follow format 1 at <path>`; there is no separate "listed twice" reason and no reader fallback. If
the row shows the option doesn't reject it, stop and report. A `Records` key must be exactly 64 characters of
`[0-9a-f]`. A stamp must match `^[0-9]{1,19}\.[0-9]{1,10}@[0-9a-f]{32}$`, its milliseconds must fit a `long` (19
digits can exceed `long.MaxValue`) and its logical part a `uint`, and it must be the canonical form (formatting it back
gives the same text, so `007.0@…` is damaged). Two `Discarded` entries of one stamp, a stamp twice in `Retired`, a stamp in both lists, or
`Write`/`Version` missing, are damaged (reasons `record <file> lists a stamp twice`, and `it has no <member>` with
`<member>` `Write` or `Version`). `seen-keyring` is damaged only when
`KeyringCodec.Decode` (`TswapCore/Keyring/Keyring.cs:217`) throws or its vault id doesn't match its file name's prefix
(both checked in `SeenState.ReadKeyring`). **A `seen-keyring` whose format version or `K` differs from the folder
keyring's is evidence, not damage** (round 3, I-7): the file name pins the vault id, and no tswap changes a keyring's
format version or `K` (`KeyringFormat.cs:111-116`: a vault keeps its keyring version for life; `K` and the vault id: `Keyring.cs:109-111` and `KeyringUnion.RequireSameVault`, `KeyringUnion.cs:41-44`), so one of the two
was damaged or replaced; which one can't be told from here (GLM r3 M-9: the seen copy's header may be the damaged
one). `ReadKeyringWithCopies` then leaves `seen-keyring` untouched (no slot added, never overwritten), checks no
slot against it, and warns, once per command: `Warning: the vault folder's keyring (<vault folder>/keyring) and the
copy this machine saw (<seen-keyring path>) have a different keyring version or k, which tswap never changes, so one
of them was damaged or replaced; the keyring's slots aren't checked until they agree. Compare both with the keyring
on another machine: if the vault folder's is the odd one, copy <seen-keyring path> to <vault folder>/keyring; if
this machine's copy is, delete <seen-keyring path> and this machine starts tracking the keyring's slots again.`
No lost-slot or "differs" slot lines are printed against such a keyring. (The warning repeats on every command
until one of the two files is replaced; that is the intended cost of never overwriting evidence.)

Texts (stderr, each at most once per command and file):
- damaged: `Warning: <path> can't be read (<reason>); this machine starts tracking record versions again from now.`
  (for `seen-keyring`: `…; this machine starts tracking the keyring's slots again from now.`), reasons: `it is not
  valid JSON`, `it is not a JSON object`, `it has no Format`, `its Format is not a whole number`, `its Format is <n>,
  not 1`, `it doesn't follow format 1 at <path>`, `it has no <member>`, `record <file> lists a stamp twice`, `its Vault is not a vault id`, `record
  <file>'s <field> is null`, `it has a null <member>`, `record <file>'s <field> is not a stamp`, `a key is not a record file
  name`, `it isn't a keyring this tswap reads (<codec message>)`, `it holds another vault's keyring`, `it names another
  vault (<16 hex>)`. Then a fresh
  baseline: the damaged file is overwritten at the next save; `SaveRecords` gives `apply` empty floors for a damaged
  file, so what it writes holds only this operation's raises (MiMo r4 M-6).
- notice (R-7): `Notice: this machine starts tracking record versions for this vault now; a record that was rolled
  back before now can't be detected.`
- a failed write: `Warning: <path> can't be written (<message>); rollback detection goes on from what was saved
  before.` The command goes on. **One such warning per command**, for the first failure, whichever file (a
  `seen-*` file or `config.json`'s `VaultId` fill) failed; later failures in the same command print nothing. Only an
  `IOException` or `UnauthorizedAccessException` from the write becomes this warning (GLM r3 M-3); every other
  exception propagates unchanged, so a failed switch to the config folder's owner (`OwnerSwitchException`, a
  `TswapException`, `FileOwnership.cs:103`) stays T12's hard stop.
- **Nothing to save, nothing written**: a save whose result has no floors, with no file on disk, writes no file (no
  empty baseline); likewise `SaveKeyring` with no file and no slot.

`Config` (`TswapCore/Models.cs:60-176`) gains, last, `[property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
string? VaultId = null`: base64 of the keyring's 16-byte vault id, a machine field (R-8 says where it is written). A
`VaultId` that isn't base64 of 16 bytes is treated as absent everywhere. As a positional member it takes part in
`Config`'s record equality and in every `with` copy (so `vault move`'s config switch, `VaultCommand.Move.cs:153-154`,
which writes `config.json` itself, keeps it).

Tests (`SeenStateTests`, files in a temp config folder; `MachineConfigVaultIdTests` for `VaultId`):

| Input | Outcome |
|---|---|
| floors saved, read back | equal floors; file name `seen-records-<16 lower hex>.json`, keyring `seen-keyring-<16 lower hex>` (no upper-case letter) |
| saved twice with equal floors | second save writes nothing (bytes unchanged; mtime too, where the file system's resolution allows) |
| file not JSON | Damaged, `it is not valid JSON`, empty floors |
| at `Format` 1: a stamp with upper-case hex / a stamp `-5.0@…` / a duplicate key / an unknown property / a key of 63 hex / a stamp in both `Discarded` and `Retired` | Damaged, the matching reason, empty floors |
| `Format` 2 | Newer: the "newer tswap" warning once; nothing checked; never written |
| a floor with `Retired` only (no `Discarded`), saved and read back | equal; `Discarded` omitted from the bytes |
| no file | Missing, no text |
| `SaveRecords` whose `apply` is given what another writer put on disk between read and save | `apply` sees the disk's floors (the re-read) |
| `seen-keyring` with another vault id; with bytes the codec refuses | Damaged with its reason |
| the `Read` seam throws `IOException`, at an operation's start and at save, for each file | Unreadable: the "can't be read now" warning once; nothing checked; the file's bytes unchanged (no save) |
| `seen-records` with `Format` 3 | Newer: the "newer tswap" warning; nothing checked; the file's bytes unchanged after a write command |
| `Format` 2 with an unknown property and a stamp in another spelling | Newer (the pre-pass decides before the strict parse); bytes unchanged after a write command |
| `Format` 5000000000 | Newer |
| `Format` 0; `Format` `1.0`; `Format` `"1"`; no `Format` | Damaged, reasons `its Format is 0, not 1`, `its Format is not a whole number` (twice), `it has no Format` |
| a `Records` key repeated | Damaged, reason starting `it doesn't follow format 1 at $.Records` (the generic reason; MiMo r6 M-1) |
| `{"Format":"x","Format":2}`; `{"Format":null}`; `{"Format":"1"}`; `{"Format":1e3}` | Newer (the other order is in the row below); Damaged `its Format is not a whole number` (each; no exception escapes) |
| `"Discarded":[{"Stamp":"…","Burned":null}]` at `Format` 1; `"Vault": null` | Damaged `record <file>'s Burned is null`; Damaged `it has a null Vault` |
| root `[]`; `{"Format":1,"Format":2,…}`; `{"Format":2,"Format":"x"}`; `{"Format":1,"Format":1,…}`; `{"Format":1,"Format":0,…}` | Damaged `it is not a JSON object`; Newer; Newer; Damaged `it doesn't follow format 1 at $…`; Damaged `its Format is 0, not 1` |
| at `Format` 1, an unknown member `X` | Damaged, `it doesn't follow format 1 at <path>` naming `X`'s path |
| an operation that raises nothing, with no `seen-records` file | no file written |
| `"Burn": null`; `Vault` `"XYZ"` | Damaged, the null reason; the vault-id reason |
| a `seen-keyring-<16 hex>.<12 hex>.tmp` and a `seen-keyring-<16 HEX>` in the config folder | `KeyringFiles()` lists neither |
| `SaveKeyring` with nothing new | the file's bytes unchanged |
| `SaveKeyring` with slots X; then another writer adds Y on disk; save Z | file holds X, Y, Z |
| the `Write` seam throws, for `seen-records` and for `seen-keyring` | each old file intact; the write-failure warning; the next read gets the old contents |
| the `Write` seam throws `OwnerSwitchException` | the command fails with its text and exit code; no write-failure warning |
| a file chmodded 0644, then a save that changes its bytes (`UnixFact`) | 0600 |
| `init` of a record vault; `slot accept` (as `SlotAcceptRecordVaultTests`) ; `migrate --to-records`; `init --vault-dir`; `slot request` on a record-store machine whose config had it | `config.json` has the keyring's `VaultId` (`slot request`: kept) |
| `config.json` with another vault's `VaultId`; `names` | `VaultId` now the folder keyring's; nothing else in `config.json` changed |

Break-it-once: drop `keepMode: false`; the 0644 row must fail. Write the stamp's origin with `Convert.ToHexString`; the
"floors saved, read back" row must fail (the strict reader rejects upper-case hex). Treat a read `IOException` as
damaged; the Unreadable row's "bytes unchanged" must fail.

## Task 2: the record checks, the warnings and the refusal

### Where the store checks and raises (`RecordVaultStore.cs`)

A **detached** store (`_detached`, `ForFolder` at `:98-103`) never reads or writes either file: guard every step below
on `!_detached`. That covers `init --vault-dir`, `slot accept --vault-dir`, `migrate --to-records`'s temp folder,
`vault merge`'s other copy and `vault move`'s target (`InitCommand.cs:296`, `:483`, `SlotCommand.cs:457`, `:940`,
`RecordMigration.cs:158`, `:393`, `VaultCommand.cs:67`, `VaultCommand.Move.cs:143`).

The vault id comes from the folder's keyring: every `ReadKeyringWithCopies` keeps it in a field, which later keyring
reads overwrite and nothing clears. An operation that needs it while the field is empty reads the keyring first
**only when the `keyring` file exists** (`_owner.FileExists(KeyringFile)`): `ReadKeyring()` throws "has no keyring
file" otherwise (`RecordVaultStore.cs:257-260` at f2e3a5a). **With no vault id** (the field empty and no `keyring`
file; GLM r3 I-2), a non-detached operation skips everything of this brief silently: no seen file is read or
written, no check, no notice, no `VaultId` fill, no text, and nothing of the seen logic throws. That is the store's
documented keyring-less use (`TswapTests/BareRecordVault.cs:11-13`: "the record store's load and save don't read
it"; `VaultWriterTests.cs:318` opens a writer on it, the oracle at `:405` and `:493` loads from it, `FieldWhoTests`
uses it), and `BeginWrite`, `LoadSecrets`, `CommitWrites` and `SaveSecrets` work there exactly as today. A real
command can't get here without a keyring (its unlock reads one), and a long-lived store (the broker) that read the
keyring once keeps the id, so a keyring deleted under it doesn't switch detection off.

An **operation** is one call to a public or internal store member that authenticates records: `LoadSecrets`,
`LoadRecordStates` (for this folder), `LoadMetadata`, one `OpenSecret`/`ReadSecretValue`, one write session
(`BeginWrite` to `CommitWrites` or `EndWrite`), `MergeRecords`, `Reindex`, `AcceptRollback`. `SaveSecrets`
(`:1472`, a test oracle; `StaleWriteGuardTests.cs:70` and others call it) is not an operation: its `WriteAll` has no
`SeenSession` and raises nothing (`WriteAll` treats a null session as "raise nothing"). Each creates one private
`SeenSession`: it reads `seen-records` once at its start (no copy is kept
between operations, so the broker's long-lived store, `BrokerSecrets.cs:66-128`, reads it per operation), collects what
the operation authenticated, and saves **once** at its end through `SeenState.SaveRecords`, applying `SeenFloor.Raise`
per authenticated record **against the floors on disk at save time**, never writing back anything read earlier. Each
raise gets the merged state (for `Write` and the pair) and the record's `PersistedLineage` (for `Discarded` and
`Retired`): the authenticated input files, never the fold's in-memory result. A record whose `Check` gave `Older` or
`Missing` gets no raise; an R4 finding doesn't stop it. **An R3 record raises nothing**, not even from the copies that
authenticated before its merge failed (`FoldConflictCopies`' `RecordConflictException` branch, `:1257-1266`; the
metadata path's `:786-797`; an `UnreadableRecordException` from an open). **A record with a newer-format lineage**
(round 3, I-8), told by T60's names (brief at e4f415b, "Interfaces T61 relies on"):
`ValueLineageCodec.Read(extensions).NewerFormat` for one record's extension list; `SecretEntry.NewerLineages`
(`IReadOnlyList<byte[]>`, the `0x0103` data of each newer-format input of an opened entry's merge) on the open and write
paths; `LoadedRecord.NewerLineages` (the same, set by `FoldConflictCopies`) on the full load;
`VaultMetadata.NewerLineageFiles` (hashed file names) on `LoadMetadata`. "The record has a newer-format lineage" means
`NewerLineages` is non-empty (or the file is in `NewerLineageFiles`).
`SeenRecord` and `PersistedLineage` carry `bool LineageUnknown`; `Check` then skips R4 (no `EntriesGone`, `BurnsGone`
or `RetiredBack`), and `Raise` and `Accept` leave `Discarded` and `Retired` as they are (R1, R2 and the pair work as
usual). The store warns once per command per record: `Warning: record <file> ('<name>') carries value lineage written
by a newer tswap; this one can't tell whether a value a merge set aside is missing from it.` A record whose main file
is missing and whose copies are all unusable is neither listed nor unreadable on the all-records paths
(`FoldConflictCopies` returns no state and no reason, `:1248-1249`; `LoadMetadata` skips it, `:1779-1780`): those
paths raise nothing from it, and, when the floor has its file name, report it as R2 (`Check(floor, null)`, R-5's
exception; GLM r3 M-12); with no floor, nothing, as today. An open reports it as R3 ("no readable copy", `:783`).
Nothing rose: nothing is written. The operations:

| Operation | Checks and raises from |
|---|---|
| `LoadRecords` (`LoadSecrets`, `Reindex`, `MergeRecords`' own load) | every merged `LoadedRecord.State`, its `Inputs` as persisted; R2 for floor names with no file in the scan |
| `LoadMetadata` | every merged record it lists (R-6), its per-file `inputs` as persisted; R2 as above |
| `OpenSecret` for a read (`:586`, also `ReadSecretValue`, `VaultView`'s opens) | that record and its files; R2 when the floor has its file name and there is no file |
| a write session: `BeginWrite` … `CommitWrites` | each `OpenForWrite`, then every record `WriteAll` wrote; saved at the end of `CommitWrites` (in a `finally`), or, when `CommitWrites` never ran (a refusal in `VaultWriter.Commit` included: `Commit` sets `_committed` before its refusals), by a new `internal void EndWrite(WriteSession)` that `VaultWriter.Dispose` calls; `EndWrite` is a no-op once `CommitWrites` ran, so a session saves exactly once |
| `Reindex`, `MergeRecords` | `Reindex`'s own `LoadRecords` and the records `WriteAll` wrote, in **one** save at its end (a `finally`); `MergeRecords` (after the `LoadSecrets` operation `vault merge` runs first, `VaultCommand.cs:123`) saves the records it wrote |

**A missing `records/` folder is an empty scan** (round 3, I-5). `LoadRecords` (`:1134-1138`), `LoadMetadata`
(`:1683-1686`) and `OpenSecret` (`scan is null`, `:599-600`) return before any file logic today; T61 runs the R2
check first on each: every floored record is `Missing`. The all-records paths print the summary (or the full R2 text
for one), and the write session's `RollbackOf` gives `Missing` for a floored name, so `create x` refuses until the
repair.

`WriteAll` (`:1989-2055` at f2e3a5a) adds what it wrote to the operation's `SeenSession` (from its returned metadata: the written
state is the merged state, and its lineage is persisted). **The copies decoded at save join the raise** (MiMo r6
I-2; design §2.3: `Discarded` takes every entry seen in an authenticated file): a new or changed conflicted copy that
step 2 decoded and merged, which the write didn't fold and so leaves on disk, is one of the record's authenticated
input files, so its entries and retirements join that record's `PersistedLineage` (union by stamp, `Burned` OR-ed,
`T` a union), exactly as a load's inputs do, and its state joins the merged state the raise takes `Write` and the
pair from; a copy left out of the check (undecodable or unmergeable) raises nothing. When the config lacks a valid
`VaultId` for that keyring, `WriteAll` writes it with
`LastHlc` (`:2051-2053` at f2e3a5a). Every `VaultId` fill (here, `SaveConfig`, and the seen-records save of R-8) re-reads
`config.json` just before writing and writes only if the file still lacks a valid `VaultId` for the keyring whose
records were just authenticated (absent, invalid, or another vault's: R-8's correction; MiMo r6 M-2), changing
nothing else, so a
concurrent `slot approve` or `vault move` isn't reverted (round 3, Claude M-11).

**R1 is checked again at save** (design §2.3, round 8 Claude 8), in `WriteAll` for writes from `CommitWrites` and
`Reindex`, in this order (round 3, I-4):
1. `CheckUnchanged` (`:2202-2210` at 66c3620) first, as today: a main file that changed since it was opened gives the
   existing stale-write refusal, never a rollback text.
2. Re-read `seen-records`, then for each record about to be written build its state **as it is on disk now**, decoding
   only what changed (GLM r3 I-1: a second decode would fire `RecordDecrypted`/`ValueDecrypted` again, and
   `WriteCommandDecryptionTests.cs` asserts exact lists, `:166`, `:372`, `:392`, `:409-410`, `:426`, `:564-565`, `:662`;
   AGENTS.md: write commands decrypt only what they use). The `SeenSession` keeps, for each record the operation
   opened or loaded, the file names and bytes it already read (main file, folded copies, and the copies it skipped as
   unusable; `RecordWrite.MainBytes`/`Copies` hold the first two) and each file's decoded metadata; no extra read at
   open. At save it re-scans the record's file names and reads their bytes (no decode):
   - names and every file's bytes equal what the session read: the session's merged `SeenRecord` is the state on disk
     now; nothing is decoded and no seam fires;
   - otherwise only the files that are new or whose bytes changed are decoded (authenticated, as `OpenFromMetadata`
     does; the full decode for a format 2 file), firing `RecordDecrypted` (and `ValueDecrypted` for a format 2 file)
     for those files only, and merged with the session's decoded metadata of the unchanged files (null when no file
     exists). The main file can't be among them (step 1 refused that).
   A new or changed copy that can't be decoded, or whose merge with the rest throws (`RecordConflictException`), is
   left out of this state and the check runs on the rest (GLM r3 M-5): no new refusal, and the write goes on as
   today, the copy staying for the next load to report (R3) as it does today. Leaving it out can only make the state
   older, so it never hides a rollback the rest shows.
3. `SeenFloor.Check(floor, onDiskNow)`: `Older` or `Missing` throws for the ordinally first such name, nothing
   written, exit 1. In `CommitWrites` the text is `Commit`'s refusal below for that kind, with the lines `Commit`
   would add: `RecordWrite` gains `RefusedWrite? Refused` (set by `CommitWrites` from the staged write's kind; null
   for a `BurnWrite`, which is exempt), so a `DeleteWrite` gets the delete line and a record at T60's entry cap (its
   written metadata at `MaxEntries` or `MaxEntryBytes`) the order sentence. In `Reindex` the text is the reindex
   refusal below for that one file.

A record that only moved forward (a newer conflicted copy arrived, another process raised the floor from it) passes
step 3, and the write goes on: the new copy is not one the write folded, so it stays and folds later, as today.
`BurnWrite` is exempt as at staging (`Refused` null); `MergeRecords` is never checked (it is the repair). A `vault merge` refused by the stale-write guard
(`CheckUnchanged`, `:2198-2210` at f2e3a5a, called from `MergeRecords` at `:1942`) writes nothing, so only this folder's load raised anything. The raise of a written
record is checked like any other: a merge that wrote a state still older than the floor leaves it flagged; one that
only moved the write stamp past it clears the flag (§2.5).

On a **missing** `seen-records` file the operation checks nothing (a baseline) and prints the notice only per R-7; on a
**damaged** one, the damaged warning and a baseline.

Four test seams on the store: `internal Action? BeforeSeenSave { get; set; }` (runs before the save's re-read),
`internal Action? BeforeSaveCheck { get; set; }` (runs before step 1 of the save-time check), and `SeenState.Write`
and `SeenState.Read` (through `internal SeenState? Seen`).

### The warnings (stderr; each record at most once per state seen)

The store keeps the (file name, merged write stamp, finding) of each record it warned about (for an R2 record, which
has no merged state, the key is (file name, finding); MiMo r4 M-6); it warns again only when
that changes. File-level warnings (damaged, unreadable, newer, write failure, the notice) follow the same rule, keyed by
(path, the warning): once per command in the CLI, again in the broker when that file's state changes (MiMo r3 M-5). In the CLI (one store per command) that is once per command; the broker's long-lived store
(`BrokerSecrets.cs:66-128`) warns again when a record rolls back again, not only once per process (round 3, Claude
M-3). The keyring lines follow the same rule, keyed by the set of slots lost or differing.

R1 (`SeenFloor.OlderWarning(string fileName, RecordFloor floor, SeenRecord merged)`):

```
⚠ Record <4 hex>…<2 hex> (secret '<name>') is older than the copy this machine saw on <F.Write time>: <state>. A sync
restore, a backup you restored, a stale copy or someone with access to the vault folder replaced it. If a sync is in
progress, wait for it to finish and run again. Changes to it are refused until it is repaired: 'sudo tswap vault
merge <a newer copy>', or keep this version with 'sudo tswap vault accept-rollback <name>'.
```

(One line; wrapped here.) `<state>`, the first that applies (machine = first 8 hex of the origin, as `Stamp.ToString`
gives it, `TswapCore/Keyring/Hlc.cs:136`; times `yyyy-MM-ddTHH:mm:ssZ` of `Hlc.ToDisplayDate(physical)`, `Hlc.cs:81-89`; a stamp that
`ToDisplayDate` clamps prints `far future`, as `names` does through `Hlc.Display` (`:94-95`), never a made-up date; a
time at or below the epoch prints as the epoch, as there. This holds for every time in every text of this brief; MiMo
r4 M-5):

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
or `Missing` from that session's checks, else `None`). `Stageable` (`:242-254` at f2e3a5a) gains a parameter:
`Stageable(string name, RefusedWrite? refused)`. With `refused` non-null and the name flagged, it records
`(Rollback, RefusedWrite)` in a new `SortedDictionary<string, (Rollback Rollback, RefusedWrite Write)>
_rolledBackStaged` and stages nothing; it records **before** looking at the entry, so a name with no file (R2) is
recorded too. `internal enum RefusedWrite { Value, Fields, Delete, Lineage, Restore }` tells `Commit` which lines to
add; the entry's metadata, when there is one, says whether the cap sentence applies. `Burn` (`:149-153` at f2e3a5a; at 66c3620
it calls `Stageable` at `VaultWriter.cs:151`) passes `refused: null`: it stages as today and records nothing, so a
flagged `burn` writes (the design's one carve-out). **Every other staging path passes its kind**: `SetValue`,
`SetFields`, `Delete`, `Restore` (which today stages through `Stage` directly, `VaultWriter.cs:192` at 66c3620: route
it through `Stageable`), and T60's `Acknowledge`, `ClearDiscarded` and `RestoreDiscarded` (if T60 stages one through
`Stage` directly, route it through `Stageable` rather than leaving it unchecked). `Commit` (`:201-215` at f2e3a5a) throws, after
the unreadable refusal and before `CommitWrites`, for the ordinally first name, exit 1, nothing written:

- `Older`: `Refused: the record of '<name>' is older than the copy this machine saw (see the warning above), so
  changing it could undo a change made elsewhere, such as a delete or a burn. Repair it first: 'sudo tswap vault merge
  <a newer copy>', or 'sudo tswap vault accept-rollback <name>' to keep this version. Nothing was written.`
- `Missing`: `Refused: the record of '<name>' is missing from the vault folder, though this machine saw it (see the
  warning above), so writing it could undo a change made elsewhere, such as a delete or a burn. Repair it first: 'sudo
  tswap vault merge <a newer copy>', or 'sudo tswap vault accept-rollback <name>' to accept that it is gone. Nothing was
  written.`
- for `delete` on an `Older` record, before `Nothing was written.`: `To delete it anyway, accept its current state
  first: 'sudo tswap vault accept-rollback <name> && sudo tswap delete <name>'.` On Windows, where `&&` is not valid in
  Windows PowerShell 5.1 (and `&` is its call operator), the two commands are quoted apart (GLM r3 M-7): `To delete it
  anyway, accept its current state first: 'tswap vault accept-rollback <name>', then 'tswap delete <name>' (from an
  elevated command prompt).` (built by `SeenFloor.Sudo` with `windows: true` for the pair). On a `Missing` record (R2), instead:
  `It is already gone from the vault folder: accept that with 'sudo tswap vault accept-rollback <name>'; there is
  nothing to delete.` (design round 11, Appendix A).

  `DeleteCommand` (`TswapCli/Commands/DeleteCommand.cs:26-30`, added to this brief's files, round 3 I-1) returns
  `Secret 'x' not found` when `writer.Find(name)` is null, before `Delete` and `Commit` run, which an R2 name always
  is. It asks first: when `writer.RolledBack(name)` (a new public `VaultWriter` member over `RollbackOf`) is `Missing`,
  it calls `writer.Delete(name)` and `writer.Commit()`, which throw the `Missing` refusal with the line above.
- when the record is also at T60's entry cap, before `Nothing was written.`: `Because it also holds as many set-aside
  values as a record can store, repair it in this order: 'sudo tswap vault accept-rollback <name>', then 'sudo tswap
  conflicts --clear <name>', then 'sudo tswap vault merge <a newer copy>' if one exists.` The same sentence is in
  T60's cap refusal in `WriteAll` when it fires on an `Older` record, whose full text is pinned under "What T61 uses
  from T60" (T60 brief at e4f415b, Task 3: `MergeRecords` passes `CapExemption.None`, so `vault merge` is capped).
- order of the lines: the refusal sentence, then the delete line, then the order sentence, then `Nothing was
  written.` If T60 as merged doesn't cap `MergeRecords`' writes,
  stop and report: the 64-entry row below can't be built without it.

`Restore` (`:168-193` at f2e3a5a), and T60's `RestoreDiscarded`, throw the refusal at once, before decrypting
anything, exit 1, in this order (GLM r3 M-7; fail-closed: a rolled-back record is never answered from its rolled-back
contents): first the unreadable-record refusal (`ThrowIfUnreadable`, as today), then the `Older` or `Missing`
refusal, and only then today's `Secret '<name>' not found` and `no previous value` (`Restore`) or T60's refusals in
T60's order (`RestoreDiscarded`). So `restore x` on an R2 name gives the `Missing` refusal, not "not found", and on an
R1 record with no previous value the `Older` refusal. This
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
| the same, but the record file put back from before the entry existed | R1 and R4 "is gone" on C |
| `delete x` where `x`'s record file is gone (R2) | the `Missing` refusal ending `It is already gone from the vault folder: accept that with 'sudo tswap vault accept-rollback x'; there is nothing to delete.`, exit 1; after `accept-rollback x`, `delete x` gives `Secret 'x' not found`, exit 1 |
| `delete y` of a name never seen (no floor, no file) | `Secret 'y' not found`, as today |
| `vault move <new folder>` on a config with `VaultId` | `config.json` still has it; the seen files stay in the config folder |
| an entry's burned flag rolled back (pre-burn file back, entry present) | the R4 burn text; `{{x:discarded}}` still warns burned |
| A burns `v10`; B rotates to `v12`; sync; `names`, `rotate` on A | no warning; `rotate` works |
| A and B burn `v10` concurrently; sync | no warning |
| `conflicts --ack`, `--clear`, `restore --discarded` on an R1 record | each the `Older` refusal |
| `restore x` on an R2 name; `restore y` on an R1 record never rotated (no previous value); `restore --discarded y` on an R1 record with no entry | the `Missing` refusal; the `Older` refusal; the `Older` refusal; each exit 1, nothing decrypted (`ValueDecrypted` empty) |
| `{{x:discarded}}` on an R1 record | the value given to the child; the R1 text on stderr |
| `delete x` on a flagged record; then `accept-rollback x`, `delete x` | the refusal with the delete line; then deleted |
| a rolled-back record at 64 entries: `vault merge` (adds one), `conflicts --clear`; then `accept-rollback`, `--clear`, `vault merge` | the first two refused (cap, rollback), both with the order sentence; the sequence works |
| `vault reindex` with an R1 record | the reindex refusal naming its file; nothing written |
| a command on an unchanged vault | `seen-records` bytes and mtime unchanged |
| `seen-records` missing; another vault id's file only; content naming another vault id; not JSON | baseline, no text / baseline, no text / the damaged warning, no floor / the damaged warning; nothing refused |
| a sync tool deletes a conflicted copy that had raised the floor; no newer main arrives | R1 stays after waiting; `vault merge` of the writer's folder or `accept-rollback` clears it |
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
| a floor whose `Write` has a physical part at or beyond `Hlc.MaxDisplayableMs`; the record put back older | the R1 text says `saw on far future`, no made-up date |
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
| P1 opens `x` for a write; `BeforeSaveCheck` raises `x`'s floor through P2 (another machine's newer file folded on this machine) and then puts back the older file P1 opened (main bytes equal again) | the `Older` refusal at save (step 3); nothing written |
| R2 with a conflicted copy present and no main file, through `run '{{x}}'` (an open) | R3 (the unreadable text), not R2 |
| the same through `names`, `x` floored | the copy warning and the R2 text for `x`'s file (GLM r3 M-12); `x` not listed |
| the same through `names`, `x` never seen (no floor) | only the copy warning, as today |
| on a vault where every record is floored: `add a` of a new value (format 3), and `rotate b` of a format 2 record, with the `RecordDecrypted` and `ValueDecrypted` seams watched as `WriteCommandDecryptionTests` does | the same lists as without T61 (`add a`: `[a's file]` once; format 2 `rotate b`: `b`'s file once in each); the existing `WriteCommandDecryptionTests` pass unchanged (GLM r3 I-1) |
| P1 opens `x` for `rotate`; `BeforeSaveCheck` plants a new conflicted copy of `x`; P1 commits | `RecordDecrypted` lists `x`'s main file once (at open) and the new copy once (at save), nothing else |
| P1 opens `x` for `rotate`; `BeforeSaveCheck` plants a new conflicted copy of `x` holding entry `c` (a value a merge set aside, persisted in that copy); P1 commits (the write doesn't fold it); the copy is then deleted before any other load; `names` | R4 "is gone" for `c` (the save floored it; MiMo r6 I-2), with R1 as well when the copy's write stamp was above P1's |
| P1 opens `x` for `rotate`; `BeforeSaveCheck` plants a copy of `x` that can't be decoded, or one whose merge throws | written, no refusal; the copy kept; the next `names` reports it as today (GLM r3 M-5) |
| a `BareRecordVault` (no `keyring` file, `config.json` with `LastHlc`): `LoadSecrets`, a `VaultWriter` create and commit, `SaveSecrets` | no exception; no `seen-*` file in the config folder; no notice or other text on the warnings writer; `config.json` gets no `VaultId` (GLM r3 I-2) |
| the "`Older` refusal at save (step 3)" row above, for `delete x` instead of a write | the `Older` refusal with the delete line (the save-time text matches staging's) |
| `records/` removed; `names`; `create x` | the R2 summary naming every floored record (or the full R2 text for one); `create` gets the `Missing` refusal |
| P1 opens `x` for `rotate`; `BeforeSaveCheck` delivers B's newer write of `x` **as a conflicted copy** and P2 (`names`) raises the floor from it; P1 commits | written; no refusal; the copy kept and folded at the next load |
| the same, but B's newer write **replaces the main file** | the existing stale-write refusal, not the rollback text |
| a record whose conflicted copy carries a newer-format lineage (`0x0103` format byte 2) and whose floor holds entries | no R4; the "written by a newer tswap" warning once; the floor's `Discarded` and `Retired` unchanged |
| `seen-records` unreadable at save (the `Read` seam throws `IOException`) in a write command | the write goes on; the "can't be read now" warning; the file's bytes unchanged |
| a broker store reads `x` (R1 warning); `x` is repaired, then rolled back again; the broker reads `x` | the R1 warning both times |
| R1's "older delete": the floor saw a value, the put-back file holds an older delete | "now it holds an older delete" |
| the upgrade notice with `config.json` holding `LastHlc` and a `VaultId` | no notice |
| a plain value put back older, then rotated on by a machine above the floor | R1 until that rotation, then silent: the newer value is gone (the documented limit, §2.4) |
| every Core-built text with `windows: true` | `'tswap …' (from an elevated command prompt)` in place of each `'sudo tswap …'`; the R1 delete line exactly its Windows form (two quoted commands joined by `, then `, no `&&` anywhere) |
| the same for a delete, then a stale machine writes a newer value | no R1 (the limit) |
| `run` of another secret | no warning about `x` |
| a `run` with `{{x}}` on an R1 record after `names` printed the summary | the full R1 text once |
| every new text on a vault of inert markers | no marker, seed or URI on either stream, in any form `Redaction.Variants` (`TswapCore/Redaction.cs:22`, production code) lists |

How the 0.3.2-shaped rows are built (`Older032`, T60 at 0a4d63a; `R(m, x)` = `RecordVaultTestSupport.ReadRecord(m,
vaultKey, "x")`; "fold and write" = `Older032.MergeAll([...]) with { Write = <a new stamp of machine O, above every
input> }`, `Older032.Plant(m, vaultKey, merged)`, then `File.Delete` each conflicted copy it folded; machine O is a
0.3.2 machine with an origin of its own):

| Row | Built with |
|---|---|
| an entry dropped by a 0.3.2-shaped merge | A's main holds entry `a` (written by this release); O's stale copy `s` (a state from before the conflict, no `0x0103`) is written again as `Older032.Burn(s, <stamp above A's write>)`; fold and write `[R(A, x), that copy]`: the whole-list rule takes O's list, so `a` is gone |
| `conflicts --clear` on A, then a 0.3.2-shaped merge drops the lineage | the same fold and write after the clear; O's list has neither `a` nor `T` |
| C acknowledged an entry; the record 0.3.2-shaped merged without it | the same, with C's floor holding the acknowledged entry |
| a retired stamp brought back by a 0.3.2-shaped merge | B cleared `a` (B's main: `T` ∋ `a`); C's copy, which never saw the clear, still holds entry `a`; C plays O: `Older032.Burn(R(C, x), <stamp above B's write>)`; fold and write `[R(B, x), that copy]`: the result holds entry `a` and no `T` (T60's row "a clear on B … a 0.3.2-shaped merge keeps C's extension list" is the same build) |
| a fold on A sets `a` aside in memory; a 0.3.2-shaped fold writes the merged state | the main file and its conflicted copy (A's `a`, B's `b`, neither with an entry) on disk; `names` on A (the in-memory fold); then fold and write `[main, copy]` as O |
| the same, but A burns the record first | A's `burn x` persists entry `a`; then O's stale copy written again with `Older032.Burn` above A's write; fold and write `[R(A, x), that copy]` |

Every row above can be built with `Older032` as T60 names it. Two things the helpers don't do, which the tests do by
hand as stated: the new write stamp of a fold (v0.3.2's `WriteAll` restamps; `MergeAll` returns the inputs' largest)
and the removal of the folded copies. No T61 row needs a 0.3.2 **format 2** write (the round 9 "drops the extension,
entries and `T` together" case is documented in Task 5, not tested); if one is wanted, it needs a helper T60 doesn't
list.

Break-it-once: compare the main file instead of the merged state (the conflict row warns); treat a missing file with
no copies as unchanged (the R2 rows are silent); let R4 accept a stamp through `S` (`Superseded`) instead of the retired list (the
clear-then-0.3.2-merge row warns, the dropped-entry row is silent); let a write go on over R1 (the `rotate`-refused row
fails); keep the floors read at the start and write them back at save (the P1/P2 rows lose the accept); raise floors
in a detached store (the `vault merge <other>` row finds a file); raise `Discarded` from the merged state instead of
the files (Claude's three-machine row warns); drop the save-time R1 check (the P1-commits row writes); raise from an
R3 record's authenticated copy (the R3 row gives R1 after the copy is removed); drop the `RetiredBack` check (the
0.3.2-shaped `T`-dropping row is silent); compare the floor with the record as opened instead of as on disk now (the conflicted-copy
P1 row is refused); skip the R2 check when `records/` is missing (the `records/` removed row creates `x`); check R4 on
a newer-format lineage (that row warns); let `DeleteCommand` return "not found" before asking (the R2 `delete` row
prints "not found"); decode every file at save instead of only the changed ones (the `add a` decryption row lists
`a`'s file twice); call `ReadKeyring()` without the `FileExists` guard (the `BareRecordVault` row throws "has no
keyring file"); raise a written record from its written state only (the planted-copy R4 row is silent).

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

**After a keyring write** (GLM r3 M-8): `WriteKeyring` (`:294-306`) reads the old on-disk keyring through
`ReadKeyringWithCopies` (`:299`), so the check above sees the keyring as it was, and writes the new one after. A
non-detached `WriteKeyring` therefore also calls `SaveKeyring(written, written.Slots)` with the keyring it just wrote
(after `WriteDurable`), so a slot this machine added is in `seen-keyring` at once and a rollback that drops it before
the next keyring read is still reported. The same guards apply (a header that differs: nothing written; a failed
write: the warning).

The folder's own conflicted keyring copies keep today's rule (a differing same-id slot refuses, `:282`). Keyring writes
are not refused while slots are missing (`WriteKeyring` never drops a slot, `:294-306`). Add the comment the design's
non-goals ask for above `KeyringUnion.Union` (`KeyringUnion.cs:16`): slots are never removed, and #197's `seen-keyring`
and `restore-slots` rely on that; a revocation brief must revisit both.

### The own-slot texts (`VaultUnlocker.cs`, R-11)

`Models.cs` gains `public sealed record KeyringFolderFacts(string VaultDir, string SeenKeyringFile, Keyring.Keyring? Seen);`
and on `Config` `[JsonIgnore] public KeyringFolderFacts? KeyringFolder { get; init; }`. `LoadConfig` (`:181-187`) of a
non-detached store sets it (the seen copy it just compared; null when missing or damaged). It takes part in
`Config`'s record equality, and `Keyring` (a `byte[]` and a list) compares by reference, so two loads of one config
are unequal; that is accepted (GLM r3 M-10): `Config` already holds lists compared by reference (`YubiKeySerials`),
and no code at f2e3a5a compares whole `Config`s (searched: no `==`, `Equals` or `Assert.Equal` over two `Config`
values). New code must not either. With `KeyringFolder` set:

- **a lost own slot**, at the sites given under "Where the own-slot texts come from" below, throws:
  - not in `Seen`: `This machine's slot <id8> is missing from the keyring in <vault folder>. The keyring file may have
    been replaced by an older copy; config.json is fine. Copy the current keyring from another machine or a backup into
    the vault folder.`
  - with `Config.KeyringSlotId` null and no machine slot at all (MiMo r3 M-1), the "not in `Seen`" text with the
    slot id left out (there is none to name): `This machine's machine slot is missing from the keyring in <vault
    folder>. The keyring file may have been replaced by an
    older copy; config.json is fine. Copy the current keyring from another machine or a backup into the vault folder.`
    (MiMo r4 M-3);
  - in `Seen`: `This machine's slot <id8> is missing from the keyring in <vault folder>, though this machine saw it there
    before: the keyring file was replaced by an older copy. config.json is fine. Put the slot back with 'sudo tswap
    vault restore-slots'.`
- when the own slot is present, no slot opened, and `Seen` holds that id with other bytes: `This machine's slot <id8> in
  the keyring in <vault folder> differs from the one this machine saw: the keyring was damaged or tampered with.
  config.json is fine. Move <vault folder>/keyring aside, copy <seen-keyring path> in its place, and compare the two.
  Then run 'sudo tswap vault restore-slots' on each other machine, so slots added since this machine last read the
  keyring come back too.` (the last sentence: design §2.7, round 8 Claude 13; `restore-slots` prints the same
  instruction when the slot it skips is this machine's own).

**Where the own-slot texts come from** (round 3 I-2; GLM r3 I-3, traced at f2e3a5a). A lost own slot always reaches
`OwnBackend`, whatever the backend: with the own slot gone, `OwnSlotIsAYubiKeySlot` is false (`VaultUnlocker.cs:938-944`),
so `Classify` sets `OwnPath` (`:793`) with `OwnKind` `None` (`:806` needs a slot), and pass 1 calls `OwnBackend`
(`:183-198`): directly when the keyring has no one-key YubiKey or FIDO2 slot (`:188-189`), else inside the
`try` whose failure becomes `ownError` before the one-key slots are tried. Inside `OwnBackend`, `UnlockHardware` runs
first and throws its own text before `UnlockKeyring` (`:1342`) is reached: for the `SlotAcceptRecordVaultTests`
desktop, `YubiKeyHardwareService.Unlock`'s `Config is corrupted: expected exactly 2 YubiKey serials, found 0 …`
(`TswapCore/Vault/YubiKeyHardwareService.cs:48-51`); for a TPM or Secure Enclave slot,
`HardwareBlobLocator.ReadFromOwnMachineSlot`'s "Config is corrupted: keyring has no machine slot matching this
machine…" (`TswapCore/Vault/HardwareBlobLocator.cs:96-98` at 66c3620) plus `ForeignHardwareSlotHint` from
`OwnBackend`'s catch (`:903-918`). So:
- **`OwnBackend` checks first, for every backend, before `UnlockHardware`**: with `KeyringFolder` set and
  `Config.KeyringSlotId` naming a slot the keyring lacks (or, with `KeyringSlotId` null, `FindOwnMachineSlot`
  finding no machine slot at all; MiMo r3 M-1), it throws the matching "missing" text above, with no hint and
  before any hardware is touched (no YubiKey challenge, no TPM dictionary-attack exposure, no Touch ID prompt). When
  the vault has one-key or FIDO2 slots, that throw is `ownError` as any `OwnBackend` failure is today, those slots are
  tried, and if none opens the unlock ends with that text as it ends with `ownError` today.
- `HardwareSlotOpens` (`:1197-1198`), which doesn't go through `OwnBackend`, throws the same "missing" texts in place
  of its "no machine slot matching this machine" throw; the throw at `:1342-1343` gets them too, as a second guard.
- **The "differs" text** comes from `OwnBackend`'s catch, for every backend (keeping today's filter's exclusions:
  `OwnerSwitchException` and the two vault-password exceptions), when `UnlockKeyring` failed on a present own slot
  that `Seen` holds with other bytes (in place of the hint for TPM and Secure Enclave), and from the end of `Unlock`
  when no slot opened and the own slot is a one-key slot present with bytes other than `Seen`'s (the desktop's case,
  which never enters `OwnBackend`).
- The end of `Unlock` gives no "missing" text: a lost own slot never gets there without passing `OwnBackend` first.
`HardwareBlobLocator.cs` and `YubiKeyHardwareService.cs` are not edited: the pre-check means their throws are never
reached for this case. `OwnBackend`'s other failures keep today's text and hint.

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

1. No `keyring` file: today's text (`RecordVaultStore.cs:257-260`) plus one line per offered file (MiMo r6 M-3): when `config.json` has a
   valid `VaultId`, only that vault's file, if it exists (another vault's copy is never offered; MiMo M7); when it has
   none or an invalid one, every file in `SeenKeyringFiles()`, in ordinal order. Each line: `This machine kept a copy of
   every slot it saw: <path>. It is a complete keyring; to put it back, copy it to <vault folder>/keyring.` Exit 1,
   nothing written. A `keyring` the codec refuses takes the same shape, with `The keyring file <vault folder>/keyring
   can't be read: <codec message>.` in place of today's text.
2. No seen file for the keyring's vault id (missing or damaged): `This machine has no record of slots for vault <16
   hex>; nothing to put back.` Exit 1. A seen file whose format version or `K` differs from the folder keyring's
   (round 3, I-7): the keyring-differs warning of Task 1 (which says how to settle it either way), then `Nothing was
   put back.` Exit 1, nothing written (a union across keyring versions is impossible). A seen file that can't be read
   now (Unreadable; GLM r3 M-7): its "can't be read now" warning, then `This machine's copy of the slots
   (<seen-keyring path>) can't be read now; nothing was put back. Run this again when it can be read.` Exit 1,
   nothing written (never treated as "no record").
3. Missing = seen slots whose id the folder lacks; a same-id slot with other bytes is skipped with the "differs"
   warning, and when it is this machine's own slot the own-slot "differs" text follows. None missing: `Nothing to put
   back.` Exit 0.
4. Each slot to add: `Putting back: <SlotCommand.DescribeSlot(slot)>` (`SlotCommand.cs:1970-1982`: id, kind,
   fingerprint). `DescribeSlot` throws for a `NeedsNewerTswap` or `Corrupt` blob (`:1978-1979`); such a slot is shown
   as `Putting back: slot <id8> (a slot this tswap can't describe: <the classifier's message>), fingerprint
   <SlotFingerprint.Compute(slot.PublicKey)>` instead (Claude M-10), and the command goes on. Input redirected and no `--yes`: `The keyring this machine saw has <n> slot(s) the vault folder's
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
| `keyring` replaced by a crafted copy that holds only the recovery slot (neither the router's nor the desktop's); `names` on the router | the "though this machine saw it" text; the lost-slot line naming the desktop's slot; no "Config is corrupted" |
| then `sudo vault restore-slots --yes` on the router with `router.Tpm = null` and `_keys.PluggedIn = []` (`SimulatedYubiKeyService.PluggedIn`, `:43`) (so any unlock would throw) | exit 0; both slots back; with `Tpm` set again the router unlocks and the desktop (key A) does too |
| a **TPM-only** machine (`init --tpm`: its TPM slot and the recovery slot, no YubiKey or FIDO2 slot) whose own slot is lost | the "though this machine saw it" text; no "Config is corrupted" and no `ForeignHardwareSlotHint` sentence; the simulated TPM is not asked (the pre-check runs first) |
| the same, no `seen-keyring` | the "may have been replaced" text, no hint |
| a TPM-only machine whose own slot is present with other bytes than `seen-keyring`'s | the "differs" unlock text, no hint |
| a **Secure-Enclave-only** machine (`FleetMachine.SecureEnclave` set, `init --secure-enclave`, as the existing Secure Enclave fleet tests set it up; stop and report if no such fixture can be made) whose own slot is lost | the "though this machine saw it" text, no hint |
| the folder's `keyring` replaced by one of another `K` (same vault id) | the keyring-differs warning; `seen-keyring`'s bytes unchanged; no slot lines; `restore-slots` prints that warning and `Nothing was put back.`, exit 1, and writes nothing; after `seen-keyring` is deleted, the next `names` prints no warning and starts a baseline |
| `seen-keyring` unreadable (the `Read` seam throws `IOException`) | the "can't be read now" warning; no keyring lines; the file's bytes unchanged; `restore-slots` prints the warning and the "can't be read now; nothing was put back" text, exit 1, nothing written |
| the desktop (key A, a one-key YubiKey slot) loses its own slot, no `seen-keyring` (deleted first) | the "may have been replaced" text naming the keyring, from `OwnBackend`'s pre-check (no one-key slot left, so `Unlock` returns `OwnBackend` at `:188-189`); no "Config is corrupted"; key A is not challenged |
| the desktop loses its own slot, with `seen-keyring` | the "though this machine saw it" text, from `OwnBackend`'s pre-check |
| the desktop loses its own slot while the keyring keeps a one-key slot of key B (not plugged in), with `seen-keyring` | the "though this machine saw it" text (the pre-check's `ownError`, after the one-key pass finds no key) |
| a TPM-only machine whose config has `KeyringSlotId` null and whose keyring holds no machine slot | `This machine's machine slot is missing from the keyring in <vault folder>. …`; no "Config is corrupted", no hint |
| the desktop's own slot present with other bytes than `seen-keyring`'s | the "differs" unlock text with the `restore-slots`-on-each-other-machine sentence; `restore-slots` skips it and prints the same instruction |
| `KeyringSlotId` null (a vault migrated from a plain XOR vault), its slot lost | the unwrap failure as today; `restore-slots --yes` puts it back |
| a slot with the same id and other bytes (not own) | the "differs" warning; not added to `seen-keyring`; the other new slots added |
| the router adds a slot S (`slot accept`, which writes the keyring); before any other command the `keyring` is replaced by the copy from before S; `names` on the router | `seen-keyring` held S straight after the accept; the lost-slot line names S (GLM r3 M-8) |
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

Break-it-once: make `restore-slots` unlock first (the `Tpm = null` row fails: the unlock throws); skip the
`seen-keyring` comparison (the lost-slot rows are silent); compare with `KeyringUnion.Union` (the differing-slot row
throws); drop `OwnBackend`'s pre-check (the TPM-only row prints "Config is corrupted" and the hint); restrict the
pre-check to the TPM and Secure Enclave backends (the first desktop row prints `expected exactly 2 YubiKey serials`;
GLM r3 I-3); treat a header
mismatch as damage (the other-`K` row rewrites `seen-keyring`).

## Task 4: `sudo tswap vault accept-rollback NAME… | --file <64 hex>… | --all`

**Order** (GLM r3 M-7; as `vault merge`, `VaultCommand.cs:46-54`): the arguments are parsed and checked first, then
the record-store check (`'vault accept-rollback' works on record-store vaults only. Convert this vault first: sudo
<prefix> migrate --to-records`, as merge's), then `ctx.RequireSudo("vault accept-rollback")`, then the unlock; each
refusal exits 1 with nothing read or written. Names and `--file` may be mixed; `--all` takes nothing else. Usage errors
(`UsageException` with the command's usage line, exit 1): no target, `--all` with anything else, `--all` twice, a
`--file` with no value, any other argument starting with `-`. `--file` takes exactly 64 characters of `[0-9a-f]`
(parser-first: what the file names are, `FilenameHasher.ToFilename`, `TswapCore/Keyring/FilenameHasher.cs:54`);
anything else (upper case, 63 or 65 characters, a space or line break inside) is the error `--file takes a record's
file name: 64 lower-case hex digits, as the warning prints it.`, exit 1. Each name goes through
`Validation.ValidateName` (`TswapCore/Validation.cs:82` at f2e3a5a, as `delete` and `burn` do), its message and exit
code unchanged. Targets are deduplicated by file name (a name and its own `--file` are one target, shown by name).
It unlocks (`ctx.Unlock`) and calls a new
`public IReadOnlyList<AcceptedRollback> AcceptRollback(byte[] vaultKey, IReadOnlyCollection<string> names,
IReadOnlyCollection<string> files, bool all)` that loads metadata (`FormatTwoRecords.Decode`) without printing the
rollback warnings, hashes each name (`FilenameHasher.ComputeFilename`), and in **one** save (re-read at save, as Task
2) sets each targeted flagged record's floor to `SeenFloor.Accept(floor, current, persisted)` (R-17) and removes each
targeted R2 floor;
unflagged records it authenticated are raised as by any load. `AcceptedRollback(string FileName, string? Name,
FloorCheck Check, RecordFloor Floor, SeenRecord? Current)`.

Output (stdout), per target in ordinal file-name order, exit 0 (also when some targets had nothing to accept). A
record with several findings prints one line for each, the R1 or R2 line first, then the R4 lines in the order below:
- R1: `✓ Accepted the current version of '<name>' (<why>).`, `<why>` by the Task 2 `<state>` row: row 1 (deleted)
  `it was deleted when this machine last saw it`; rows 2 and 3 (an older value, an older delete) both `this machine last
  saw a newer version, from machine <o> at <t>`; row 4 `it was burned when this machine last saw it`; row 5 `this
  machine last saw a later change, made at <t> by machine <o>` (MiMo r4 M-4).
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
| `--file 3F2A…` without sudo; `accept-rollback 'bad name'` without sudo | the usage error; `ValidateName`'s error; neither the "requires" text (arguments first) |
| `accept-rollback`, no target; `--all --all`; `--file` with no value; `--force x` | usage errors, exit 1 |
| an R1 record that also has an R4 finding | the R1 line, then the R4 line; both silent afterwards |
| `accept-rollback x --file <x's hash>` | one line for `x` |
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
  keyring: each one a way to open the vault"), with their two `SudoTableDrive` drivers (the sanction above); a
  "Rolled-back records and slots" paragraph under `vault`: the two
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
- `docs/security-model.md`: replace the "What is not detected yet" bullet (`:836-841` at dcc4c04, `:869-873` at 686f1fe) and add a "Rolled-back files"
  section (§2.9): detected on machines that saw the newer state; not detected: a vault rolled back before a machine
  first saw it, a stale machine's newer re-creation of a deleted name or a cleared value, the plain-value
  rollback-then-stale-write case, a process running as the vault's user that edits the config folder too, and a
  `seen-*` file lost, damaged or restored from a backup; detection rests only on files this machine authenticated,
  never on a merge's in-memory result;
  `seen-records-*` reveals hashed record names with burn and conflict times to whoever reads the config folder;
  `seen-keyring-*` is a complete copy of the vault's keyring (0600, owner only), so a backup of the config folder holds
  the vault's wrapped key material. A resurrected deleted secret is still handed out by `run`, `get` and the broker,
  with the warning. (Only here: `docs/setup.md` has no backup section, and the design no longer names it.)
  Also the "What each command decrypts" table (`docs/security-model.md:209` at f2e3a5a; GLM r3 M-11): a row for
  `vault accept-rollback` (format 3: no value, every record's metadata; format 2: each record decrypted whole, a
  warning, as `names`), a row for `vault restore-slots` (nothing: no unlock), and one sentence under the table: the
  write commands' save-time rollback check decodes only record files that are new or changed since the command read
  them (metadata only, a format 2 file whole), so it decrypts nothing more in the usual case.
- `AGENTS.md`: both commands in the "Requires sudo" list (`:123`); under "Storage" (`:258-262` at f2e3a5a) the two
  config-folder files, `seen-records-<16 hex>.json` and `seen-keyring-<16 hex>` (one line each: what they hold, 0600);
  in "The record store" (`:275-277`) `VaultId` added to the machine-field list (`VaultDir`, `OriginId`, `LastHlc`,
  `VaultId` and the backend's own).
- `TswapCore/Prompt.cs`: under "Commands you must NEVER use" (`:83-101` at 686f1fe): `- \`sudo %CMD% vault accept-rollback <name>\`
  - Keeps a rolled-back record as it is (human use only; ask the user)` and `- \`sudo %CMD% vault restore-slots\` -
  Puts lost slots back into the keyring (human use only)`; the next key rule (13 at 686f1fe, unless T60 took it): `If a command warns that a record or the
  keyring is older than this machine saw, or refuses a change for that reason, stop and tell the user what it says.
  Never run the repairs yourself.` ASCII only. A `PromptTests` test pins both bullets under "NEVER" and the rule by its text (`If a command warns that a record or
  the keyring is older…`), not by its number (T60 also edits `Prompt.cs`).
- `docs/release-notes/v0.3.3.md` (create it if T58/T60 haven't): the two warnings, the refusal, the three commands,
  `VaultId`, the two config-folder files, and that 0.3.0-0.3.2 ignore them; and the behaviour change that a
  read-only config folder now gets the write-failure warning on every command (GLM r3).
- `docs/multi-machine.md` also says, in the new section: read commands may write this machine's **config** folder
  (the `seen-*` files, and `VaultId` once), never the vault folder; the upgrade notice can show again after an older tswap
  rewrites `config.json` (it drops `VaultId`); and two commands saving at once can leave a floor
  lower than it could be (less detection), never higher than a state that existed; such a lost update can also undo an
  `accept-rollback` made at the same moment, which then shows the warning again: run the accept again (Claude M-2;
  no lock, by the design's §2.3 rule).
- **The v0.3.2 one-off check is carried** (design "Briefs", round 10): before the release, run the v0.3.2 binary on a
  copy of a vault this build wrote (`names`, `run`, a rotate, a merge of a conflict copy), with `seen-records-*` and
  `seen-keyring-*` in its config folder, and record the result in the PR, as T54 did. Task 3's in-process
  "0.3.2-shaped reader" row is a proxy for this check, not a replacement (MiMo M9). Not a test; the implementer
  writes the steps in the PR description for the controller to run.

## Out of scope

- Part 1 (#312, T60): entries, `T`, the merge rule, `tswap conflicts`, `restore --discarded`, `{{x:discarded}}` beyond
  R-9.
- A MAC over the seen files (design L4), auto-repair of slots, slot revocation, a purge command (R2 assumes none).
- The `vault-password` file going back (the design's non-goals).
- A `--verbose` flag for the store (R-3).
