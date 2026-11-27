# Design: keep merge-discarded values and detect rolled-back records (#312, #197)

Issues: https://github.com/stevedcc/TokenSwap/issues/312 and https://github.com/stevedcc/TokenSwap/issues/197.
Date: 2026-11-27. Base: origin/main e86f028. Branch: `design/records-033`.
Status: **decided 2026-11-27** (owner decisions at the end). Nothing is built. Marked **(my call)** where the designer
decided and **(owner)** where an owner rule or decision settles it. Every claim about the code cites `file:line` at e86f028. Brief T58 (TOTP, #374, branch `brief/t58` at
7cae0bd, `docs/briefs/t58-totp-codes.md`) is not merged yet; where this design depends on it, it says so.

## Amendments (round 1)

Round 1 review by MiMo (`~/RiderProjects/tswap-wt/tools/design-records-r1-mimo.md`, "not ready to plan"), with the
controller's rulings. They are folded into the text below; each is tagged where it lands.

1. **I-1, the fallback bound (ruling: MiMo's bound).** `B = min(stated bound, max(S ∪ {W's previous}))`, the second
   term `Stamp.Zero` when that set is empty (§1.1). It catches a concurrent rotation against a tombstone a 0.3.x
   machine wrote, and two first values written by 0.3.x, which the old D2 bound dropped silently. Owner decision 1
   stands. Residuals documented in §1.1 and §1.6; two test rows added (and one pinning a residual).
2. **I-2, the floor's discarded entries (ruling: every entry, plus a burned bit).** §2.3's floor lists every entry
   seen, open and acknowledged, each with a burned bit; R4 also warns when an entry is still there but no longer
   burned, and `{{x:discarded}}` gives the burned warning from the floor's bit (§2.4, §1.10). Test rows added.
3. **I-3, exactness (ruling: state it, settle refresh, test the real shape).** Exact means the winner has the
   extension **and** `asOf == W.Version`; a merge never refreshes `asOf` (§1.4 rule 3). The stale-`asOf` test row now
   builds the shape 0.3.2 writes (extension kept, version moved twice), with a break-it-once.
4. **M-1** taken: `:discarded` behaves exactly as `:previous` in `CommandValues`, `StoredForms` and `IsBurnedToken`;
   `SecretsDb.ResolveToken` refuses it with its own text; a redaction row for a discarded seed's spellings (§1.10).
5. **M-2** taken: the anti-goals follow T58's classification (otpauth seeds and URIs never reach a non-sudo output; a
   bare Base32 value behaves exactly as `{{name}}` does).
6. **M-3** taken: `--stamp` takes the full 32-hex form as well; the 8-hex form must be unique, with its own text when
   it isn't (§1.9).
7. **M-4** taken: 0.3.2 reads the config folder's files by name and ignores the two new ones; pinned by a test and by
   the pre-release v0.3.2 check (§1.6, Briefs).
8. **M-5** taken: `conflicts --clear` and `restore --discarded` remove that stamp from this machine's floor (§2.3).
9. **M-6** taken: documented under §1.6; amendment 2's burned bit covers it on machines that saw the burn.
10. **M-7** taken: the `seen-keyring` comparison is `KeyringUnion.SameSlot`, slot by slot (§2.7).
11. **M-8** taken: why `delete` refuses on a flagged record, the accept-then-delete path, and a reworded delete line
    (§1.5, §2.5).
12. **M-9** taken: `Stamp` is `TswapCore/Keyring/Hlc.cs:98-137` (`ToString` `:136`); the scanner's full path.
13. **M-10** taken: R2 rests on no command removing a record's main file; stated and tested (§2.4).
14. **M-11** taken: entry bytes are zeroed as `VaultView.ResolveToken` does; `conflicts` decrypts nothing (§1.9, §1.10).
15. From MiMo's §B (ambiguities and missing rows): `delete`'s `exactFrom`, the 32-stamp cap on writes, the T58 tests
    T60 must re-sanction, the 32-cap false warning named in the anti-goals, and the rows listed in its §B.7 (§1.4,
    §1.5, Tests, Briefs).

## Amendments (round 2)

Round 2 review by MiMo (`~/RiderProjects/tswap-wt/tools/design-records-r2-mimo.md`, "not ready to plan", one
Critical), with the controller's rulings. Folded into the text below and tagged where they land; they win over
round 1 where the two differ.

1. **C1, a merge dropped a kept entry (ruling: MiMo's fix).** In round 1 an entry whose stamp was in `S` was removed,
   and `S` includes every copy's previous version, so a losing writer that rotated again before its folder merged
   (its previous is then the discarded value) made the next merge drop the entry silently, and R4 accepted it. Now
   an entry is removed **only** when its stamp is the merged record's current version, or when a person's action
   retired it: `conflicts --clear`, `restore --discarded`, or a `delete` that dropped it. Those marks travel in a
   separate **retired** list in `ValueLineage` (§1.3), apart from the rotation-derived superseded set `S`; a merge
   writes only those explicit marks as retirements (§1.4 rule 1). `S` stays for the bound `B` and for excluding
   candidates. An entry whose stamp becomes the winner's **previous** version is **kept**, still counts as
   discarded, and keeps its warning until a person drops it (§1.1). Every earlier table row re-checked (§1.1); the
   step-6 row and the "A rotates again before its folder merges" end-to-end row added; R4 now accepts a gone entry
   only through the retired list (§2.4).
2. **I1, entries without a fingerprint set (ruling: both).** A stored entry without a current set makes the record
   "not fully fingerprinted" (`redact`/`tocomment` refuse, readers warn), and no entry is written without a set except
   when its section can't be decrypted, in which case the record is marked as above. The guarantee for
   metadata-only readers is stated in §1.10.
3. **I2, seven points settled (controller defaults).** (1) T60 gives `{{x:discarded}}` the burned warning from the
   entry's own burn; T61 adds the floor-bit check. (2) Only an R1 or R2 failure stops a floor's raise. (3)
   `accept-rollback` drops the floor's discarded stamps of the records it accepts. (4) `seen-keyring` is written like
   `seen-records.json`; the floor's entry list merges as a union by stamp with the burned bits OR-ed. (5) At 255
   entries the record stays readable; only a write that would hold a 256th is refused, naming `conflicts --clear`,
   and `--clear` and `restore --discarded` always work. (6) `{{x:discarded}}` on a tombstone has its own text. (7) A
   new entry's kind comes from T58's `0x0101` entry for its stamp, else none; the full path classifies the plaintext.
   (§1.4, §1.10, §2.3, §2.6.)
4. **M1** taken: the `burn` sentence corrected, and the anti-goal carves `burn` out by name (§2.5, Anti-goals).
5. **M2** taken: a candidate whose value equals a retained value (plaintext on the full path, base fingerprint
   entries on the metadata path) is not set aside; test row added (§1.1).
6. **M3** taken: the warning names a backup you restored; the `maxConflicts` row names the repair source and what
   accepting gives up; a far-ahead clock note (§2.4, §2.5).
7. **M4** taken: the missing test rows added (Tests).
8. **M5** taken: the value-write citation is `RecordWrites.cs:93` (v0.3.0 `:76-77`); the revocation note cites the doc
   and T61 adds the code comment; the section constraint says "under its own stamp".
9. **M6** taken: floor entries retired in the record are pruned at save; a lost or restored floor file is listed as
   undetected (§2.3, §2.9).

## Intent and why

Both issues are about the per-record store losing data **without saying so clearly**.

1. **#312, a merge drops a value.** Two machines rotate one secret before they sync. The merge keeps the later
   value, and the other one is gone: `RecordMerge.MergeAll` keeps only the winner's current and previous values
   (`TswapCore/Keyring/RecordMerge.cs:124-131`) and the comment says so ("Versions the winner doesn't retain are
   ignored", `:91-93`). If machine A had already set its value at a service (`rotate db-pw && run psql … ALTER ROLE`),
   the service now uses a value the vault no longer holds. The only sign is the copy note, which says the copies were
   "Combined by the merge rules" and names only the hashed file (`TswapCore/RecordVaultStore.cs:1198-1201`).
2. **#197, a file is replaced by an older one.** The merge rules protect deletes and burns when two copies **meet**.
   They can't help when a record file is simply **replaced** by an older copy (a sync tool's "restore previous
   version", a stale replica winning, anyone with write access to the folder): a deleted secret comes back, a burn
   disappears from `burned`. The same goes for the `keyring` file losing slots, which strands those machines.
   `LastHlc` is one high-water mark per machine (`TswapCore/Models.cs` `Config.LastHlc`, saved at
   `RecordVaultStore.cs:2043-2045`) and can't say which record went back.

The two share a store, a write path and a merge, and #197's check must not mistake #312's discarded values for a
rollback. So one design, two briefs.

## Goals

1. A value that loses a merge is **kept**, encrypted, with its stamp and origin, out of `{{name}}` and
   `{{name:previous}}`, until a person drops it or puts it back. Nothing that merges copies loses a value silently.
2. A **warning that names the secret**, on every machine that uses it, until someone acknowledges it. No warning
   when nothing was lost (two burns, a burn against a rotation, a normal sync).
3. `tswap conflicts` lists conflicts without sudo and without values; `sudo tswap restore NAME --discarded` puts one
   back; `{{name:discarded}}` lets `run` use one without anybody seeing it.
4. Each machine remembers, per record, the newest state it has seen, and **warns** when a record goes back; a
   **write** to such a record refuses until it is repaired.
5. The same for the keyring's slots, with a repair that works even when this machine's own slot is the one lost.
6. Older tswap (0.3.0 to 0.3.2) keeps reading and writing the vault; what it can't do is written down.
7. Every behaviour is tested with fixed clocks and simulated machines, no hardware.

## Non-goals

- Changing who wins a merge. "The last change wins" (`docs/multi-machine.md:458-459`) stays.
- Version vectors or a full history of values. tswap keeps one previous value by owner decision (fix round 1, B,
  `TswapCore/Keyring/SecretRecord.cs:19-25`); this design adds values a **merge** set aside, not a history.
- Protecting against a process running as the vault's own user that edits both the vault folder and the config
  folder. It can delete records outright today. #197 is about sync tools, other machines and other people with
  access to the **shared** folder (security model, below).
- The `vault-password` file: differing copies already refuse (`RecordVaultStore.cs:348-353`, ruling 2); an older
  copy that replaces it is a lockout, not a silent data change, and stays as it is.
- Revoking slots. There is no slot removal today (`docs/multi-machine.md:601-605`); #197 relies on that, and a
  future revocation brief must revisit the slot rule (`docs/multi-machine.md:601-605` says there is none; T61 adds a
  comment saying so at `KeyringUnion.Union`).

## Anti-goals (a failure even if it works)

- A secret value, or an otpauth seed or URI, printed by anything an agent can run without sudo. (A TOTP code is
  what T58's `totp` and `run` hand out by design; a bare Base32 value is an ordinary value, as T58 classifies it.)
- A record a 0.3.2 machine can no longer read.
- A warning on a normal sync, or for a merge that lost nothing. False alarms train people to ignore the real ones.
  Accepted exceptions, each on the safe side (the value kept): a copy more than 32 value changes stale (§1.4), and
  the mixed-version residuals of §1.1 and §1.6.
- A discarded otpauth value handed out as its URI or seed without sudo. (A discarded bare Base32 value behaves
  exactly as `{{name}}` does for one: its text.)
- Writing on top of a rolled-back record, which would make the rollback permanent in every copy. One write is
  carved out by name: `burn`, which only adds a fact (§2.5, round 2 amendment 4).
- A repair path that needs the thing that was lost (for example `vault merge`, which needs an unlock, as the only
  repair for this machine's own lost slot).

## Constraints

- **Record format 3 allows at most two value versions.** The metadata's version count must be 0, 1 or 2, and the
  roles must be current then previous (`TswapCore/Keyring/SecretRecordCodec.cs:828-843`); the same check is in
  v0.3.2 (`git show v0.3.2:TswapCore/Keyring/SecretRecordCodec.cs`, line 828). The file's `valueSectionCount` must
  equal that count (`:796-798`), and it is in the metadata's associated data (`:919-928`). A third value section
  makes the record "Malformed" on every release so far.
- **Extensions survive older builds.** The metadata section carries an extension list kept byte for byte
  (`SecretRecord.cs:34-48`, codec `:883-898`). v0.3.0 keeps every extension on a value write and on a tombstone
  (`git show v0.3.0:TswapCore/Keyring/RecordWrites.cs`, lines 76-77 and 92-96); v0.3.1 and later drop only
  `Fields` on a tombstone (`TswapCore/Keyring/RecordWrites.cs:114-118`, `TswapCore/Fields/FieldEdits.cs:113-114`).
  Every release merges an unknown extension by "the whole list of the input with the largest write stamp"
  (`RecordMerge.cs:315-346`, the same code in v0.3.2).
- **Taken extension types** (`TswapCore/Fields/FieldSet.cs:5-12`): `0x0100` Fields; `0x0101` T58's `ValueKinds`;
  tests use `0x0001`, `0x0002`, `0x0005`, `0x0102`, `0x7000`, `0x7777`, `0xFFFF` as types no build defines.
- **A value section binds only its own stamp.** Its associated data is `magic | 3 | recordId | 0x02 | versionStamp`
  and its key is `HKDF(K_v, recordId || versionStamp)` (codec `:75-86`, `:931-939`), so a section copied byte for
  byte to another place in the same record still opens **under its own stamp**, and only there: under another
  version's stamp, another record or the metadata slot it fails its tag (`OpenSealed`, `:615-644`).
- **Two merge paths held equal.** `MergeAll` (plaintext) and `MergeAllMetadata` (no plaintext, sections compared by
  bytes or fingerprints, `RecordMerge.cs:185-280`); `RecordWrites` and `NextRecord` likewise
  (`RecordWritesTests.RecordWrites_MatchNextRecord_OnRandomStates`, `TswapTests/RecordWritesTests.cs:327`).
- **Readers decrypt only what they use** (T16 Stage 2, AGENTS.md "The record store"): `names`, `redact`,
  `tocomment`, `check`, `list` and `burned` read metadata only (`LoadMetadata`, `RecordVaultStore.cs:1667-1840`);
  writes copy sections (`RecordWrites`, `:16`).
- **Stamps.** `Stamp` is (HLC, 16-byte origin), a total order; `ToString` is `<ms>.<logical>@<8 hex>`
  (`TswapCore/Keyring/Hlc.cs:98-137`). Every write takes an HLC above everything this machine has seen, including
  the record it is writing (`Observe`, `RecordVaultStore.cs:752-758`, `:1459-1467`). Only authenticated stamps move
  the clock (`:1283-1284`).
- **The stale-write guard** re-reads each record before writing and refuses on any change
  (`RecordVaultStore.cs:2183-2194`, `GenerationGuard`).
- **Copy removal.** A write removes the conflicted copies it folded (`:2034-2037`, `:315-337`).
- **Keyring.** Slots are added, never changed or removed (`TswapCore/Keyring/KeyringUnion.cs:3-31`); every keyring
  write is a union with what is on disk (`RecordVaultStore.cs:288-306`). A missing own slot today says
  `Config is corrupted: keyring has no machine slot matching this machine. Restore config.json from backup or re-run
  'tswap init'.` (`TswapCore/Vault/VaultUnlocker.cs:1341-1343`, also `:1198`), which is wrong advice when the
  keyring file is what changed.
- **T58** (not merged): token grammar gains `:totp`, one suffix at most; `CommandValues` is "the one place a stored
  value becomes what a command is given" and decides from the **value** whether it is an otpauth seed, so
  `{{name:previous}}` of a seed gives its code (T58 D2, D3, Task 2); extension `0x0101` marks the kind of each
  retained version by its stamp, display only (T58 Task 4, amendment 7).
- **Owner rules** (brief): reliability and data safety before features; fail closed; warnings over refusals except
  where data could be lost; agents never see values and nothing they can run prints one; sudo for anything that
  exposes or restores values; fixed clocks in tests; established libraries; British English.

## What happens today

| Situation | Code | Result |
|---|---|---|
| Two rotations of one secret meet (sync conflict copy, or `vault merge`) | `RecordMerge.MergeAll`, `:118-131`; fold `RecordVaultStore.cs:1217-1269` | the larger version wins; the other value is not retained; a `Note:` per copy naming the hashed file (`:1198-1201`, `:1244`, `:1764`, `:801`) |
| The next write of that record | `WriteAll`, `:1981-2047` | the merged state is written and the copy deleted: the losing value is gone from every file |
| `{{x:previous}}` after that | `VaultView.ResolveToken`, `TswapCore/VaultView.cs:184-215` | the winner's previous value (the common base), never the lost one |
| A record file replaced by an older copy | load paths | read as it is; no warning; `burned` loses the burn, a deleted secret is listed again |
| A record file deleted | `OpenSecret`, `RecordVaultStore.cs:607-609` | the secret no longer exists, silently |
| `keyring` replaced by one with fewer slots | `ReadKeyringWithCopies`, `:254-286` | those machines can't unlock; this machine's own slot gone gives "Config is corrupted …" |

## Part 1 (#312): keep what a merge discards

### 1.1 What counts as discarded

A value version is **discarded** when some copy holds it as its **current** value and the merged record neither
retains it nor descends from it. The hard part is "descends from": format 3 keeps one previous value, so after two
rotations the record no longer shows which values its writers had seen.

Approaches:

| | Rule | Trade-off |
|---|---|---|
| D1 | discarded = an input's current value that the winner doesn't retain | wrong after two rotations: a copy that was simply two rotations behind (a laptop off for a week, a stale USB copy in `vault merge`, a burn made while the other machine rotated twice) is reported as a conflict. False alarms on normal syncs. |
| D2 | D1, but only versions newer than the winner's previous version | catches the issue's case (both rotations replace the same base, so the loser is newer than the winner's previous) and never alarms on a stale copy; misses a concurrent value written before the other machine's second offline rotation |
| D3 | a bounded **lineage**: each record lists the version stamps it knowingly dropped; discarded = not retained, not in any copy's lineage | exact while every writer keeps the lineage; needs a little metadata per record and a fallback for records written by older builds |
| D4 | version vectors per origin | exact in theory, but needs every machine to record what it saw of every other machine; a large format change for one warning |

**Pick: D3, falling back to D2 where the lineage can't be trusted (my call).** D3 is the only rule that is right
for both the issue's case and the "two rotations behind" case, and it costs at most 32 stamps (896 bytes) of
encrypted metadata per record. D2 is today's information plus one comparison, so records written before this
release, or since by an older build, still get the issue's main case.

The rule, for one merge of copies `I₁ … Iₙ` with winner `W` (the copy with the largest version, as today):

- `R` (retained) = `W`'s current and previous versions; none for a tombstone.
- `S` (known superseded) = the union of every copy's lineage set, **plus every copy's previous version** (a copy's
  own current value knowingly replaced it).
- The bound `B` (amendment 1) = `min(stated, known)`, where:
  - `stated`: `W`'s `exactFrom` when `W`'s lineage is **exact**, that is `W` has the extension and its `asOf` equals
    `W.Version` (amendment 3); otherwise `W`'s previous version, or `W`'s version for a tombstone or a first value
    (rule D2);
  - `known` = the largest stamp in `S ∪ {W's previous}`, or `Stamp.Zero` when that set is empty.

  For an exact lineage created by this release `exactFrom` is `Stamp.Zero`, so `B` is zero. For an inexact value
  record `known` ≥ `W`'s previous, so `B` is D2's bound. The `known` term matters for a tombstone written by 0.3.x
  (a concurrent rotation is newer than the pre-delete value that the loser's previous puts in `S`) and for first
  values (both sets empty: `B` is zero).
- `T` (retired) = the union of every copy's retired list: stamps a person dropped (§1.5).
- **Discarded** (round 2 amendment 1) = every existing discarded entry of any copy, **minus** those whose stamp is
  in `T` or is `W.Version`; **plus** every copy's current value version `V` with `V > B` and `V ∉ R ∪ S ∪ T`, unless
  `V`'s value equals a value `W` retains (amendment 5: the same value written twice under two stamps loses nothing;
  compared by plaintext on the full path and by base fingerprint entries on the metadata path, and a candidate
  without a set counts as different).
- `S` never removes an existing entry: it only bounds and excludes **new** candidates. An entry whose stamp is `W`'s
  **previous** version stays an entry (it still counts as discarded, with its warning) until a person drops it; the
  value is then held twice, as the previous value and as the entry, until the next rotation drops the previous.

| Case | Result |
|---|---|
| A and B both rotate from `v0` | `W` = the later; the earlier is discarded (`v0` is in `S` and `R`) |
| A burns `v0`, B rotates `v0` → `v1` | A's current `v0` is B's previous: retained, nothing discarded, no warning |
| two burns of `v0` | same version: nothing discarded |
| A holds `v1`; B rotated `v1` → `v2` → `v3` | B's lineage holds `v1` (dropped at the second rotation): nothing discarded |
| the same, B on 0.3.2 (no lineage) | D2: `v1` < `v2` = `W`'s previous: nothing discarded |
| A and B create the same name independently | both first values; the loser is discarded (a real value conflict) |
| A deletes after seeing `v1`; B still holds `v1` | the delete put `v1` in the lineage: nothing discarded |
| A deletes; B rotates concurrently; the delete wins | B's value is discarded (owner decision 1: kept on the tombstone) |
| A, B, C rotate from `v0` | two discarded entries |
| a discarded entry cleared, restored or acknowledged on another machine, then a stale copy arrives | clear and restore put its stamp in the retired list, so the entry goes and is not discarded again; an acknowledgement travels with the entry |
| A and B rotate from `v0` (`a`, `b`); B folds (entry `a`); A rotates `a`→`c` before its folder merges; B rotates `b`→`d`; the copies meet | `W` = `d`, `R` = {`d`, `b`}, `S` ∋ `a` (A's previous): entry `a` **kept** (not retired), and `c` > `B`, ∉ `R ∪ S ∪ T`: entry `c` too (round 2 amendment 1) |
| the same, but A's `c` is later than `d` | `W` = `c`, previous `a`: entry `a` kept although it is the previous value (demotion keeps it); B's current `d` is a new entry; `b`, B's own previous (B replaced it knowingly), is not |
| A and B both rotate to the same value from `v0` | no entry: the loser's value equals the winner's (amendment 5) |
| A on 0.3.2 deletes after `v5`; B rotated `v5`→`b` concurrently; the delete wins; a merge here | `S` holds B's previous `v5`, so `B` = `v5`; `b` > `v5`: discarded, kept on the tombstone (owner decision 1) |
| A and B on 0.3.2 create the same name; a merge here | both sets empty, `B` = zero: the loser is discarded |

Residuals of the inexact case (documented in `docs/multi-machine.md` "Mixed versions"): a tombstone 0.3.x wrote
after several 0.3.x rotations, merged with a copy that is stale but newer than that copy's own previous value, reports
the stale value once (a warning, the value kept); and a 0.3.x re-creation of a deleted name can bring an earlier
life's value up as an entry once. Both are false warnings on the safe side; a person clears them with sudo.

### 1.2 Where a discarded value lives

| | Representation | 0.3.2 reading it | Trade-off |
|---|---|---|---|
| S1 | a third value section, role 2 | **refuses the record** ("at most 2", codec `:828-829`) | the natural layout, but every machine on 0.3.2 loses access to that secret until it upgrades: fails the anti-goal |
| S2 | a sibling file per discarded value (`records/<hash>.d<n>`) | ignores it (scanner: unknown names are ignored) | the sync provider sees conflicts happen; a OneDrive-shaped name would be taken for a conflicted copy (`TswapCore/Keyring/RecordDirectoryScanner.cs`, the OneDrive rule); separate life cycle, separate guard, separate rollback check |
| S3 | **an extension in the metadata section** that carries the discarded version's value section byte for byte, still encrypted under its own value key | reads the record; keeps the bytes on value writes; merges it by its whole-list rule | needs only metadata decryption to list conflicts; no format change; grows the metadata section by one value section per discarded value |

**Pick: S3 (my call).** It is the only one that keeps every 0.3.x machine working. The value stays sealed under
`HKDF(K_v, recordId || itsVersionStamp)` with its own associated data (codec `:75-86`), so decrypting the metadata
(which `names` does) never decrypts it, and a section moved into the extension from another record fails its tag.
What a sync provider learns: a metadata-only write that grew by at least one 256-byte bucket, which it could read as
"a conflict was kept". That is added to the provider row in `docs/multi-machine.md:592-596`.

### 1.3 The `ValueLineage` extension (type `0x0103`)

Added to the registry comment in `TswapCore/Fields/FieldSet.cs:5-12`. Deterministic binary, little-endian, using the
codec's stamp encoding (`SecretRecordCodec.WriteStamp`, `:1008-1014`) and fingerprint set encoding (`:851-871`):

```
format            1   = 1
asOf              28  the record version this lineage describes (exact when it equals the record's version)
exactFrom         28  versions older than this are assumed superseded (Stamp.Zero: none are)
supersededCount   1   0..32, then that many stamps, ascending (S: rotation-derived, for the bound only)
retiredCount      1   0..32, then that many stamps, ascending (T: dropped by a person; removes entries)
discardedCount    1   0..255, then per entry, ascending by stamp:
  version         28  the discarded value's version stamp (its origin is the machine that wrote it)
  kind            1   T58's value kind of that value: 0 none, 1 Totp, 2 OtpAuthUnusable (display only)
  flags           1   bit 0 acknowledged, bit 1 burned; other bits zero
  [acknowledged]  28 stamp of the acknowledgement, then byLength 1 (0..64) + UTF-8 --by label
  [burned]        28 stamp of that version's earliest burn, then reasonLength 2 (0xFFFF none) + UTF-8 reason
  hasFingerprints 1   then variantSetVersion 1, entryCount 1, entries as the codec stores them (0 only when the
                      section can't be decrypted: the record is then "not fully fingerprinted", round 2 amendment 2)
  sectionLength   4   then the value section: nonce 12 | tag 16 | ciphertext, exactly as format 3 stores it
```

- **Decode** is strict for format 1 (lengths, ascending order, no duplicate stamps, zero reserved bits, a section of
  at least 28 bytes). A malformed format 1 extension makes **that record** unreadable, like a damaged `Fields`
  extension (`RecordMerge.cs:332-340`): fail closed, because a reader that can't see the discarded list can't tell
  whether a value is missing. A **newer** format byte is kept byte for byte, ignored, and warned about once per
  command ("record … carries value lineage written by a newer tswap"), so a later format doesn't make records
  unreadable here **(my call)**.
- **Burns of a discarded version** are copied into its entry because the record's burn list is bounded to 16 and
  keeps the outstanding burn plus the most recent others (`RecordMerge.cs:32-48`): a discarded version's burn could
  otherwise fall out of the list, and 0.3.2 trims by the same rule.
- The **kind** byte is display only, as T58's mark is (T58 Task 4: "display only: never an unreadable record"). What
  `{{name:discarded}}` gives is decided from the value (§1.10).

### 1.4 The merge rule, in both paths

`RecordMerge` gets one more special case beside `Fields` in `MergeExtensions` (`RecordMerge.cs:315-346`), used by
`MergeAll` and `MergeAllMetadata` alike, with a parity test like the existing one:

1. `S` = every copy's superseded set and previous version, minus `R`; kept to the 32 newest by stamp. `T` = the
   union of every copy's retired list, the 32 newest. A merge **writes only explicit marks into `T`**: it never moves
   a stamp from `S`, a previous version or anywhere else into `T` (round 2 amendment 1). A retired stamp that falls
   out of the cap lets a stale copy's entry come back (a warning, the value kept: the safe side).
2. Discarded per §1.1. Per discarded stamp, over every copy that holds it (as its current value or as an entry):
   - the plaintext must agree, as for retained versions today (`RecordMerge.cs:141-155` full path; on the
     metadata path equal sections or equal base fingerprint entries, `:243-258`). A disagreement is a
     `RecordConflictException`: the record is unreadable until the damaged copy is removed (today's rule for retained
     versions, applied to the values this design now keeps);
   - section: the ordinally smallest (`:151-153`); fingerprints: joined as `JoinGroup` does (`:378-388`);
   - acknowledged if any copy acknowledged it, with the **earliest** acknowledgement (as two burns keep the earliest);
   - burned with the earliest burn found in any copy's burn list or entry; kind: the largest byte. A **new** entry's
     kind is T58's `0x0101` entry for its stamp in the copy it came from, else none, on the metadata path; the full
     path classifies the plaintext as T58's write path does (round 2 amendment 3, point 7).
3. `asOf` and `exactFrom`: the winner's, unchanged, when the winner has the extension; `Stamp.Zero` for both when
   it has none. **A merge never refreshes `asOf`** (amendment 3): only a value write or delete by this release does
   (§1.5). So exactness is decided at each merge from the winner alone: exact iff the winner has the extension
   **and** `asOf == W.Version`. "Has the extension" is not enough: 0.3.x keeps the extension byte for byte on its own
   value writes (`RecordWrites.NewVersion`, `TswapCore/Keyring/RecordWrites.cs:93` through `FieldEdits.ForWrite`; v0.3.0
   `RecordWrites.cs:76-77`), which leaves it present
   with a stale `asOf`; treating that as exact would set `B` to zero and report every stale copy as a conflict.
4. The extension is written whenever there is anything to say (a superseded stamp or an entry); otherwise left out.
   `S` is capped at the 32 newest stamps on writes as on merges.
5. A tombstone winner keeps the extension (unlike `Fields`): its lineage stops a stale copy's value from being
   reported as discarded, and (owner decision 1) its discarded entries.

Properties (tested): the same copies in any order give the same bytes; merging a result again with any of its
inputs changes nothing; an entry leaves only through `T` or by becoming the current version, so no order of merges
loses one. Pairwise merges can **keep more** entries than one merge of all the copies (a first step can set a value
aside that a third copy's `S` would have excluded, and `S` never removes it afterwards): the difference is always a
warning about a kept value, never a lost one. With every copy's lineage exact and `exactFrom` zero, and no copy
having superseded another's current value, the pairwise and all-at-once results are equal. With a lineage stale
from a 0.3.x write the result may miss what D2 misses (pinned in Tests).

**Bounds.** A merge never trims discarded entries (as a merge never trims fields, fields spec Merge rule 7). More
than 255 can't be encoded, but the record stays **readable** (the merged state holds them in memory); only a write
that would store a 256th entry is refused: `Refused: 'x' holds 255 values a merge set aside, the most a record can
store. Drop some first with 'sudo tswap conflicts --clear x'. Nothing was written.` `conflicts --clear` and
`restore --discarded` always work, since they shrink the list (round 2 amendment 3, point 5). It takes 255
concurrent rotations of one secret. The 32-stamp lineage cap
only drops the oldest stamps; the effect is that a copy more than 32 rotations stale can be reported as a conflict
(a warning, the value kept: the safe side).

### 1.5 Writes

`RecordWrites` and `NextRecord`/`PrepareV3` in step (parity test):

| Write | Lineage | Discarded entries |
|---|---|---|
| a new value version (`create`, `ingest`, `add`, `rotate`, `ingest --rotate`, `import`, `restore`) | the dropped old previous version joins `S`; `asOf` = the new version. If the lineage was not exact (`asOf` ≠ the old version), `exactFrom` = the old previous version, or the old version when there was none | unchanged |
| a new life over a tombstone | the tombstone's `S` and entries are kept; `asOf` = the new version; `exactFrom` = the tombstone's version when its lineage wasn't exact | kept (owner decision 1) |
| `burn`, `field set`/`unset` | unchanged | unchanged |
| `delete` (sudo) | current and previous join `S`, every dropped entry's stamp joins `T`; `asOf` = the tombstone version; `exactFrom` as for a value write (unchanged when the lineage was exact, else the old previous version, or the old version) | **dropped**: `delete` prints `It also dropped 1 value set aside by a merge; it can no longer be restored.` |
| `conflicts --ack` (§1.8) | unchanged | the flag and acknowledgement set |
| `conflicts --clear` (sudo) | the stamps join `T` | removed |
| `restore --discarded` (sudo) | a new value version as above, and the restored entry's stamp joins `T` | that entry removed; its burn is outstanding again on the new version, as `restore` re-issues the previous value's burns today (`RecordWrites.cs:87-88`) |

- **No entry is written without a set** (round 2 amendment 2): on the metadata path a write fills a missing set from
  the entry's own section, as `WithMissingSets` does for retained versions (`RecordVaultStore.cs:965-1003`, one
  section decrypted and zeroed); only a section that can't be decrypted is written without one, with that function's
  warning, and the record then counts as "not fully fingerprinted".
- Any write of a record carrying entries is written in **format 3** even in a folder that still writes format 2,
  as a write with fields is (`RecordVaultStore.cs:919-923`, `CarriesEdits`); format 2 stores no extensions
  (`:2022-2029`).
- On the metadata path a write copies every entry's section and set byte for byte (no value decrypted). The full
  path seals an entry that has no section (a format 2 loser) and fingerprints one without a set, as `PrepareV3`
  does for retained versions (`:2056-2085`).
- `vault reindex` recomputes entries' older variant sets as it does for retained values, and `IsCurrent`
  (`:1434-1451`) also requires current sets on entries.
- Full loads validate entries' fingerprints against their plaintext (`RecordMerge.ValidateFingerprints`,
  `:403-417`), so a stored set can't hide a discarded value from redaction.

### 1.6 Compatibility

| Who | What happens to a record with `ValueLineage` |
|---|---|
| 0.3.0-0.3.2 reading (`names`, `run`, `get`) | reads it as before; doesn't list, mask or substitute the discarded values |
| 0.3.x writing a value, burn or field | keeps the extension byte for byte (stale `asOf`: §1.1 falls back to D2 for that record) |
| 0.3.x deleting | keeps the extension in its tombstone, entries included; this release then treats them as kept on a tombstone (`tswap conflicts` shows "deleted") |
| 0.3.x merging (a conflict copy it folds) | keeps the whole extension list of the copy with the largest write stamp: it **can drop** entries this release would keep, and it drops losers as today |
| 0.2.x | as 0.3.0 for the extension |
| 0.1 (format 2 only) | can't read format 3 at all, as today; a vault with 0.1 machines writes format 2, except records with entries (written in format 3, as records with fields are) |

`docs/multi-machine.md` "The merge rules" gains a "Mixed versions" paragraph like the fields one (`:482-489`): in a
folder shared with 0.3.x machines, a merge done there can still lose a value, and a value another machine rotated
away on 0.3.x can be reported once as a conflict (with §1.1's two residuals named). #197's R4 (§2.4) warns when a
discarded value disappears that way. A discarded version's burn can also vanish there: 0.3.x trims the record's burn
list to 16 (`RecordMerge.cs:32-48`) and can't copy burns into entries it doesn't know; R4's burned bit (amendment 2)
reports it on machines that had seen the entry burned (amendment 9).

The two new config-folder files (§2.3) don't affect 0.3.x: it reads `config.json` and the vault folder's files by
name, and its config-folder code (the legacy-folder move and `RefuseAmbiguousMacVault`, `TswapCli/CliEnvironment.cs`)
moves or checks whole folders or `config.json` only. A test pins that a 0.3.2-shaped reader (today's code with the
two files present) behaves the same, and the pre-release v0.3.2 check runs with both files present (amendment 7).

### 1.7 When a discarded value is dropped

Approaches:

| | Dropped | Trade-off |
|---|---|---|
| X1 | at the next value change after it was reported | "reported" is per machine and per command; a rotation on a machine that never showed the warning would drop it; a burned secret can be rotated without sudo, so an agent could drop a value without anyone deciding to |
| X2 | after it is acknowledged and then the next value change | the acknowledgement is not a decision to delete; still reachable without sudo |
| X3 | **only by a person's explicit action with sudo**: `conflicts --clear`, `restore --discarded` (it becomes the current value), or `delete` of the secret | entries can pile up if nobody looks, but each one is a real concurrent write, which is rare |

**Pick: X3 (owner rule: no data loss without a person deciding; sudo for anything that restores values; my call
that clearing counts too).** Acknowledging (§1.8) only quietens the warning. A merge never drops an entry, except
one a person retired on another machine (its stamp in that copy's retired list, §1.4) (round 2 amendment 1).

### 1.8 The warning

Shown **only** for entries not yet acknowledged, on stderr, at most once per secret per command:

```
⚠ sync-conflict-test: two machines changed its value at the same time. The value machine 5d918462 (this machine)
wrote at 2026-11-14T16:20:16Z was replaced by the one machine c7cad1d5 wrote at 2026-11-14T16:20:20Z. tswap kept
the replaced value. If a service was updated with it, see 'tswap conflicts sync-conflict-test'.
```

(One line in the output; wrapped here.) `<machine>` is the first 8 hex digits of the origin id, as `Stamp.ToString`
shows it (`Hlc.cs:136`), with ` (this machine)` when it is this machine's origin. Times are the stamps' physical
parts in UTC with `Z` (the fields rule, fields spec Constraints). The second half names the **current** value. When
the current value has moved on since the conflict, it reads `… was set aside by a merge; the current value is the
one machine c7cad1d5 wrote at …`. With several entries, one line each. On a tombstone: `⚠ x: it was deleted while
machine 5d918462 changed its value (at …). tswap kept that value. See 'tswap conflicts x'.` `tswap` is `ctx.Prefix`.

Where:

| Command | What |
|---|---|
| a command that opens a named secret: `run` (each token's secret), `totp` (T58), `get`, `apply`, `rotate`, `ingest --rotate`, `restore`, `burn`, `delete`, `field set`/`unset`/`show` | the full warning for that secret |
| a command that reads all metadata: `names`, `burned`, `list`, `check`, `redact`, `tocomment` | one line: `⚠ 1 secret has a value a merge set aside: sync-conflict-test. See 'tswap conflicts'.` (names listed, up to 5, then `and N more`) |
| a merge that creates an entry (a fold on load, `vault merge`) | the full warning instead of the copy note for that record; the existing `Note:` (`RecordVaultStore.cs:1198-1201`) stays for copies that lost nothing, and gains the secret's name when the record was decrypted |
| `names` | ` [CONFLICT]` after the date and T58's mark, before ` [BURNED]`; `names --json` gains `"conflict": true` (omitted when false, so today's JSON is unchanged) |

Acknowledged entries print nothing except in `tswap conflicts`. The warnings carry no value and no fingerprint.
`tswap prompt` (`TswapCore/Prompt.cs`, ASCII) tells agents: on this warning, tell the user what it says and that
`tswap conflicts` has the details; don't acknowledge, clear or restore it unless the user asks.

### 1.9 `tswap conflicts`

```
tswap conflicts [NAME] [--json]                         no sudo; metadata only, decrypts no value
tswap conflicts --ack NAME [--stamp S] [--by LABEL]     no sudo (owner decision 2); a metadata-only write
sudo tswap conflicts --clear NAME [--stamp S]           sudo; drops the value(s)
```

Text output (no values; names are not secret and `names` prints them already):

```
sync-conflict-test (open)
  current    2026-11-14T16:20:20Z  machine c7cad1d5
  discarded  2026-11-14T16:20:16Z  machine 5d918462 (this machine)  stamp 1794673216219.0@5d918462

1 open conflict.
  Use it once:  tswap run … '{{sync-conflict-test:discarded}}'
  Put it back:  sudo tswap restore sync-conflict-test --discarded
  Keep it, stop the warning:  tswap conflicts --ack sync-conflict-test
  Drop it:      sudo tswap conflicts --clear sync-conflict-test
```

- `(open)` or `(acknowledged 2026-11-15T09:12:00Z, machine c7cad1d5, by owner)`; `(deleted)` for a tombstone; a
  discarded TOTP value shows ` [TOTP]` from its kind byte; a burned one ` [BURNED]`.
- No conflicts: `No value conflicts.` (`No value conflicts for 'x'.` with a name; a missing name is `Secret 'x' not
  found`). Exit 0 in both cases; usage errors and refusals exit 1.
- `--json` (source-generated, `TswapCli/CliJson.cs`): `{"open": 1, "conflicts": [{"name": "…", "deleted": false,
  "current": {"stamp": "…", "machine": "c7cad1d5", "thisMachine": false, "time": "…Z"}, "discarded": [{"stamp": "…",
  "machine": "5d918462", "thisMachine": true, "time": "…Z", "kind": "totp" | null, "burned": false,
  "acknowledged": null | {"time": "…Z", "machine": "…", "by": "…" | null}}]}]}`. `current` is null on a tombstone.
- `--stamp S` takes the stamp as printed (`<ms>.<logical>@<8 hex>`) or in full (`<ms>.<logical>@<32 hex>`, the
  form `seen-records.json` uses; in `--json`, `"stamp"` is the full form and `"short"` the printed one). The full form
  matches at most one entry. The 8-hex form must match exactly one; two matches (two origins sharing 8 hex digits at
  one HLC) give `Two values of 'x' match the stamp S; give it in full (see 'tswap conflicts x --json').`, and none
  gives `No discarded value of 'x' has the stamp S; see 'tswap conflicts x'.` Without `--stamp`, `--ack` takes every
  open entry of NAME, and `--clear` every entry (amendment 6).
- `conflicts` in every mode decrypts no value: listing reads metadata only, and `--ack` and `--clear` copy sections
  byte for byte (amendment 14).
- `--ack` stamps the acknowledgement like any write and records `--by` (at most 64 characters, the field rules for
  characters, fields spec "Fields"). It works on a tombstone too, so a deleted secret's warning can be quietened.
  Output: `✓ Acknowledged 1 value of 'x' that a merge set aside. It is kept until 'sudo tswap
  conflicts --clear x' or 'sudo tswap restore x --discarded'.`
- `--clear`: `✓ Dropped 1 value of 'x' that a merge set aside.`

### 1.10 `restore --discarded` and `{{name:discarded}}`

`sudo tswap restore NAME --discarded [--stamp S]`: decrypts that one entry's section (metadata path: one section,
`OpenSealed`) and writes it as a new version through the restore path (`VaultWriter.Restore`,
`TswapCore/VaultWriter.cs:148-171`): the current value becomes the previous one, the entry goes (§1.5). With more than
one entry and no `--stamp`, it refuses: `'x' has 2 values a merge set aside; name one with --stamp (see 'tswap
conflicts x').` On a tombstone it brings the secret back. Output: `✓ Secret 'x' restored to the value machine
5d918462 wrote at 2026-11-14T16:20:16Z, which a merge had set aside (a new version; the value it replaced is now the
previous one).` plus today's burn and "update the external system" lines (`TswapCli/Commands/RestoreCommand.cs:35-38`).
Plain `restore NAME` is unchanged. A restored otpauth value is marked by T58's write path (it classifies the value
being written).

`{{name:discarded}}` (and `# tswap: name:discarded`, everywhere T58 changes the grammar together: `Validation`,
`Apply`, `Check`, `ToCommentProcessor`, `SecretMatcher`, `RunCommand`; T58 Task 2 lists the places):

- resolves through T58's `CommandValues`, which decides from the value: a discarded otpauth value gives its
  **current code**, never the URI or seed (as `{{name:previous}}` does, T58 D3). A discarded bare Base32 value gives
  the stored text, as `{{name}}` does for one; `{{name:discarded:totp}}` is two suffixes and refused by T58's rule
  **(my call: no combined suffix; restore it with sudo if a bare seed's code is needed)**;
- exactly one entry (open or acknowledged): its value. None: `'{{x:discarded}}': secret 'x' has no value a merge set
  aside.` More than one: `'{{x:discarded}}': secret 'x' has 2 values a merge set aside, so the token can't tell which.
  The user can put one back with 'sudo tswap restore x --discarded --stamp <stamp>' (stamps: 'tswap conflicts x').`
  A tombstone holding entries: `'{{x:discarded}}': 'x' was deleted; it has 1 kept value(s): see 'tswap conflicts
  x'.` (a tombstone without entries: `Secret 'x' not found`) (round 2 amendment 3, point 6);
- a burned entry gives `run`'s burned-value warning from the entry's own burn (T60, through `IsBurnedToken`); T61 adds
  the same warning for an entry this machine's floor (§2.3) saw burned (round 2 amendment 3, point 1). The value is
  masked as `[REDACTED: x:discarded]` like any token. `SecretsDb.IsBurnedToken` answers false for `:discarded`, and
  its `ResolveToken` refuses as below;
- **`:discarded` behaves exactly as `:previous`** in T58's `CommandValues` (the suffix stripped before asking the inner
  lookup), in `StoredForms` (a code-giving discarded otpauth token masks the stored value and T58 amendment 5's seed
  spellings), and in `ISecretLookup.IsBurnedToken` (`TswapCore/ISecretLookup.cs`; `VaultView.cs:171-175`)
  (amendment 4). `SecretsDb.ResolveToken` (`TswapCore/Models.cs:283`, the whole-vault view of full loads) doesn't
  resolve it: `'{{x:discarded}}': values a merge set aside are read through 'tswap run' on a record vault only.`;
- the entry's bytes are decrypted once and zeroed as `VaultView.ResolveToken` does for other tokens
  (`VaultView.cs:218-221`); `restore --discarded` zeroes them after sealing them under the new version, as `restore`
  does today (amendment 14);
- the broker never serves discarded values (it serves names, not tokens: T58 D8's table is unchanged).

Masking: every entry's fingerprint set joins the index that `run`, `redact`, `tocomment` and the field guard rail use
(`TswapCore/VaultView.cs:136-140`, `TswapCli/FingerprintStreamMatcher.cs:64-71`), so a discarded value that a
service prints is masked, labelled `[REDACTED: x:discarded]`. A 0.3.x machine doesn't mask it (§1.6).

**The guarantee for metadata-only readers** (round 2 amendment 2): every value a record holds, current, previous or
an entry, either has a fingerprint set in the index, or the vault is "not fully fingerprinted": `redact` and
`tocomment` then refuse and the other reading commands warn, as for a retained version without a set today
(`LoadMetadata`'s count, `RecordVaultStore.cs:1788-1791`; `docs/multi-machine.md:589-590`). A merge on a read path that
sets aside a value without a set counts the same way for that command.

Export: the export format carries current values, burns and fields (`TswapCore/Models.cs`, `Secret` docs). Owner
decision 3: an export leaves entries out and `export` warns, naming the secrets, `Warning: 1 secret has a value a merge set aside
(sync-conflict-test); this export doesn't include it. Restore or clear it first if it matters.`

## Part 2 (#197): notice records and slots that go back

### 2.1 What a normal sync can and can't do

For one record file, every legitimate change has a **larger write stamp** than the content it replaced: a write
observes the record first and takes an HLC above it (constraints), a merge's write stamp is the largest of its inputs
(`RecordMerge.cs:170`, `:268`) and is then restamped (`WriteAll`, `:1997-2000`). Its **version** never decreases
either: a merge takes the largest (`:118`), and value writes, restores and deletes all take new stamps. A merge never
removes a burn of the current version (burns are a union, `:172`). So "the record's state now is older than a state
this machine saw" can't come from tswap; it comes from outside.

One subtlety: a sync tool may keep the **older** file as the main one and rename the newer to a conflicted copy (it
decides by its own rules, not by tswap's stamps). Every check below therefore uses the record's **merged** state,
main file and authenticated copies together, never the main file alone.

### 2.2 Approaches

| | Where the "seen" state lives | Trade-off |
|---|---|---|
| L1 | a map in `config.json` | one file, already written on every record write; but it grows with the vault (about 150 bytes per record), is rewritten by read commands, and a damaged map would sit in the file whose damage makes every command refuse ("Config is corrupted") |
| L2 | **a sibling file in the config folder** (`seen-records.json`), plus a copy of the last keyring seen (`seen-keyring`) | per machine like `config.json`, never synced; damage is contained; the keyring copy makes the slot repair possible without an unlock |
| L3 | something inside the vault folder (a signed counter, a log) | a rollback of the folder rolls it back too; it can only detect a partial rollback |
| L4 | a MAC over L2's file under a key from `K_v` | stops a forged lower floor, but not deleting the file; the threat it adds coverage for (a process running as the user) is out of scope |

**Pick: L2 (my call).** It answers the issue's "config.json (or a sibling file)" with the sibling, so the seen state
can never break `config.json`.

### 2.3 Format and when it is written

`<config dir>/seen-records.json`, written 0600 as the folder's owner through `DirectoryOwnerMatcher.WriteAtomic`
(the way `config.json` is, `RecordVaultStore.cs:234-245`), JSON through the source-generated context:

```json
{
  "Format": 1,
  "VaultId": "<base64 of the keyring's vault id>",
  "Records": {
    "<64 hex file name>": {
      "Write": "1794673220031.0@c7cad1d5…(32 hex)",
      "Version": "1794673220031.0@c7cad1d5…",
      "Burn": "…",
      "Discarded": [{ "Stamp": "…", "Burned": true }]
    }
  }
}
```

The **floor** of a record is `Write` (the largest write stamp seen), `Version` (the largest version seen), `Burn`
(the outstanding burn of that version, when it had one; omitted otherwise) and `Discarded`: **every** entry seen,
open or acknowledged, each with a burned bit set once it was seen burned (amendment 2; omitted when none). A machine
whose first sight of an entry is already acknowledged still floors it. The acknowledgement itself is not floored: an
acknowledgement lost to a rollback only brings the warning back, the safe direction, so there is nothing for R4 to
check (round 2 amendment 3, point 4: "keep the ack if either side has it" has no field to apply to). At save time an
entry whose stamp is in the record's retired list is pruned from the floor (round 2 amendment 9). Stamps are written in full (`<ms>.<logical>@<32 hex>`), not the 8-hex display form.
`<config dir>/seen-keyring` is the keyring codec's bytes (`KeyringCodec.Encode`) of every slot this machine has seen,
written exactly as `seen-records.json` is: 0600, as the config folder's owner, through `WriteAtomic`, merged with
the file on disk (a union of slots) before writing (round 2 amendment 3, point 4). Its format is the codec's own,
versioned by the keyring's format byte.
Neither file holds a name, a value or a fingerprint. What `seen-records.json` adds to what a reader of the config
folder learns: which hashed records were burned or had conflicts, and when; an agent learns as much from `burned`
and `tswap conflicts`.

- **Updated** after any load that authenticated records (the full load, `LoadMetadata`, a single record's open for
  a read or a write) and after a commit, raising each floor component to what was seen; **never lowered**, except by
  `vault accept-rollback` (§2.6), and by `conflicts --clear` and `restore --discarded` run **on this machine**, which
  remove that entry's stamp from this machine's floor: a person decided, and without this a later 0.3.x merge that
  loses the lineage would make R4 report a deliberate drop (amendment 8). A record whose R1 or R2 check failed (§2.4) gets no raise; an R4 warning doesn't stop
  the raise (round 2 amendment 3, point 2). At most one file write per store
  operation, and only when something rose, so a command on an unchanged vault writes nothing.
- **Merged with the file on disk** before writing (per component, the larger; the entry lists as a union by stamp,
  burned bits OR-ed), as `SaveConfig` merges `LastHlc`
  (`RecordVaultStore.cs:195-201`). A lost update between two processes can only leave a floor lower than it could be
  (less detection), never higher than a real state.
- **Missing** file: the first load records a baseline and warns about nothing (the upgrade path, and a new machine
  joining a folder). **A different `VaultId`** (the config was pointed at another vault): start again, with a
  `Notice:`. **Damaged** file: `Warning: … can't be read (…); this machine starts tracking record versions again from
  now.`, then a fresh baseline **(my call: a damaged local file is not a reason to block the vault; the threat model
  of #197 is the shared folder)**.
- Write failures (a read-only config folder) are one warning per command; detection keeps using what was last saved.
- Only authenticated stamps count, as for `LastHlc` (`RecordVaultStore.cs:1283-1284`).

### 2.4 What counts as a rollback

For a record whose merged state is `M` (main file plus usable copies, as §2.1 says) and whose floor is `F`:

| Rule | Condition | Meaning |
|---|---|---|
| R1 | `M.Write < F.Write`, or `M.Version < F.Version`, or `M.Version = F.Version` and `F.Burn` is set and `M` has no burn of that version | the record went back: a delete undone, a burn gone, a value or field change lost |
| R2 | `F` exists and the record has no main file and no usable copy | the record is gone: the secret vanished. Sound only because no tswap command removes a record's main file: `delete` writes a tombstone, and copy removal touches conflicted copies only (`RecordVaultStore.cs:315-337`). A future purge command must update `F` itself (amendment 13) |
| R3 | a file this machine can't read | **not** a rollback: today's unreadable-record rule applies (`RecordVaultStore.cs:1185-1188`) |
| R4 | a stamp in `F.Discarded` is neither an entry of `M`, nor in `M`'s **retired** list, nor `M`'s current version (round 2 amendment 1: `S` no longer explains a gone entry); or it is still an entry of `M` but not burned while `F` saw it burned | a value a merge had set aside is gone, or its burn is (a 0.3.x merge dropped it, or the file went back). **Warning only**, no refusal: refusing can't bring it back. The burn text: `⚠ x: the value machine 5d918462 wrote at … (set aside by a merge) was burned when this machine last saw it; its burn is gone. It is still compromised.` |

A component check uses the version **and** the write stamp because each catches what the other can't: a rolled-back
field change keeps its version; a rolled-back delete that another (stale) machine then writes over has a newer write
stamp but an older version. The `Burn` component catches a burn removed while a stale machine's metadata write raised
the write stamp. A stale machine re-creating a deleted name with a **newer** version than the delete is
indistinguishable from a legitimate value after the delete: the merge rules accept it too (limit, documented).

What a normal sync and the #312 rules produce, checked against the table:

| Situation | Result |
|---|---|
| another machine's write replaces the file | write stamp and version rise: no warning, floor raised |
| a sync conflict, the older file kept as main and the newer as a copy | the merged state carries the newer stamps: no warning |
| tswap removes a folded copy after writing it | the written main file carries everything: no warning |
| a merge sets this machine's own value aside (#312) | the merged version is the largest of the inputs, so it never goes down; the value is an entry: no warning |
| `conflicts --clear` or `restore --discarded` on another machine | the stamp moves into the retired list, which R4 accepts: no warning |
| `vault move`, a second config folder, a machine joining | same vault id, or a new baseline: no warning |
| Syncthing's "Revert Local Changes", OneDrive's or Dropbox's "restore previous version", a backup copied over the folder | R1 for each record that went back, R2 for records created since |
| someone deletes the newer conflicted copy before tswap folds it | R1 (or R2): correct, that change is lost |
| Syncthing deletes an old conflicted copy over its `maxConflicts` limit before tswap folds it | R1 when that copy held the newest state: correct, though Syncthing did it on its own. The newer state still exists on the machine that wrote it: merge from that machine's folder; `accept-rollback` instead gives that state up (round 2 amendment 6) |
| a machine with a clock far ahead writes, then its copy is lost | R1 shows a time in the future; the year-ahead warning (`RecordVaultStore.cs:1190-1192`) names the clock as well |
| a network share's client cache returns an old file | R1: a real problem on that machine (`docs/multi-machine.md:512-515`) |

### 2.5 The warning, and the refusal on write

Reads go on, with a warning on stderr once per record per command **(owner rule: warnings, since a read loses
nothing)**:

```
⚠ Record 3f2a…c9 (secret 'db-pw') is older than the copy this machine saw on 2026-11-20T10:02:11Z: then its
version was from machine c7cad1d5 at 2026-11-20T10:02:11Z and it was deleted; now it holds a value from machine
5d918462 at 2026-11-14T16:20:16Z. A sync restore, a backup you restored, a stale copy or someone with access to the
vault folder replaced it. Changes to it are refused until it is repaired: 'sudo tswap vault merge <a newer copy>', or keep this version
with 'sudo tswap vault accept-rollback db-pw'.
```

The first 4 and last 2 hex digits of the file name, as the warning shows it (full name in `--verbose`). The state
part names what changed, from the floor and the merged state: `it was deleted; now it holds a value`, `it was burned
on …; now the burn is gone`, `a change made at … is missing` (write stamp only). R2: `⚠ Record 3f2a…c9, which this
machine saw on …, is missing from the vault folder (its secret is gone).` with the same repair line and `--all`
(the name is unknown without the file). R4: `⚠ sync-conflict-test: a value a merge had set aside (machine 5d918462,
2026-11-14T16:20:16Z) is gone from its record; an older tswap's merge or a rolled-back file dropped it.` Commands that
read all metadata print one summary line for R1 and R2 (`⚠ 2 records are older than this machine saw: …`).

**Writes refuse** (fail closed: a write on top makes the rollback permanent in every copy and can undo a delete or a
burn elsewhere), naming the record, before anything is written, exit 1:

```
Refused: the record of 'db-pw' is older than the copy this machine saw (see the warning above), so changing it
could undo a change made elsewhere, such as a delete or a burn. Repair it first: 'sudo tswap vault merge <a newer
copy>', or 'sudo tswap vault accept-rollback db-pw' to keep this version. Nothing was written.
```

It applies to `create`, `ingest`, `add`, `rotate`, `ingest --rotate`, `restore`, `delete`, `field set`/`unset`/
`adopt`, `import`, `conflicts --ack`/`--clear` and `vault reindex` (which refuses listing the records, as it does for
unreadable ones, `RecordVaultStore.cs:1405-1410`). Two exceptions **(my call)**:

- **`burn`** still writes: a burn adds a fact and is the agent's first duty after seeing a value (AGENTS.md "Working
  with tswap"). The warning stays after the burn only when the floor's version (or its burn) is above the record's:
  a rollback that lost only a field change or an acknowledgement keeps the version, so the burn's newer write stamp
  satisfies R1 and that loss is no longer reported. A documented limit, and the one write the anti-goals carve out.
- **`vault merge`** still writes: it is the repair. After it, a record that is still below its floor stays flagged.

`delete` refuses too, although deleting a resurrected secret looks like the safe direction: a delete drops every
discarded entry (§1.5), and on a rolled-back record the entries it would drop may be what the rollback brought back
or hid. To delete a secret a rollback brought back, accept the current state first, then delete: `sudo tswap vault
accept-rollback x && sudo tswap delete x`. The refusal adds that line for `delete` (amendment 11).

### 2.6 Repair

1. **A newer copy exists** (another machine's folder, a backup, the sync tool's version folder such as
   Syncthing's `.stversions`): `sudo tswap vault merge <folder>`. The merge brings the newer state back by the
   merge rules, and the next load raises nothing and clears the warning. A folder needs its `keyring` and
   `records/`; with only single record files, put them in `records/` beside a copy of the current keyring.
2. **The current state is the wanted one** (a deliberate restore from backup): `sudo tswap vault accept-rollback
   NAME…` or `--all` (R1 and R2 records). Sudo, because accepting can bring back a deleted secret or drop a burn. It
   unlocks, reads metadata only, sets those floors to the current state and prints each change it accepts:
   `✓ Accepted the current version of 'db-pw' (it was deleted when this machine last saw it).` R2 entries are
   removed, and the accepted records' floor entry lists are set to their current entries, which silences R4 for them
   (round 2 amendment 3, point 3). On other machines that saw the newer state, the warning stays until they accept too: each machine
   decides for itself.

### 2.7 Keyring slots

The floor for the keyring is `seen-keyring`: every slot this machine has seen, as bytes. After each keyring read
(`ReadKeyringWithCopies`, `RecordVaultStore.cs:254-286`) the copy gains each slot of the folder's keyring whose id it
lacks; it is never shrunk. The comparison is slot by slot with `KeyringUnion.SameSlot` (`KeyringUnion.cs:48-52`), not
`KeyringUnion.Union`, which throws on a same-id slot with other bytes (`:25-29`): such a slot is left out of the
update and warned about (below), and the other new slots are still added. The vault folder's own conflicted keyring
copies keep today's rule unchanged: a differing same-id slot there still refuses loudly (amendment 10).

- A slot in `seen-keyring` that the vault folder's keyring (with its conflicted copies) lacks gives:
  `⚠ The vault folder's keyring has lost 1 slot this machine saw before: 3f2a9c1b (TPM). The keyring file was replaced
  by an older copy (a sync restore, a stale copy, or someone with access to the folder); machines whose slot is
  missing can't open the vault. Put it back with 'sudo tswap vault restore-slots'.` The slot id short form and kind,
  as `tswap slots` shows them; `(this machine's)` for `KeyringSlotId`.
- A slot with the same id and different bytes is not unioned: `Warning: slot 3f2a9c1b in the vault folder's keyring
  differs from the one this machine saw. …` (slots never change once written, `KeyringUnion.cs:25-29`), and the copy
  is not updated.
- **This machine's own slot lost**: the unlock fails, so `vault merge` (which unlocks) can't be the repair. The
  unlocker's message (`VaultUnlocker.cs:1341-1343`, `:1198`) becomes, when `seen-keyring` holds that slot: `This
  machine's slot 3f2a9c1b is missing from the keyring in <vault folder>, though this machine saw it there before:
  the keyring file was replaced by an older copy. config.json is fine. Put the slot back with 'sudo tswap vault
  restore-slots'.`
- **`sudo tswap vault restore-slots [--yes]`** (new): adds back every slot of `seen-keyring` that the folder's keyring
  lacks, by a keyring write (a union, as always). It needs **no unlock** (a union needs no `K_v`) and so works for
  the own-slot case. It shows each slot's fingerprint (as `vault merge` does for new slots) and asks on a terminal,
  or takes `--yes`. Sudo because it adds ways into the vault. Refuses when the folder's keyring belongs to another
  vault (`KeyringUnion.RequireSameVault`).
- Keyring **writes** are not refused while slots are missing: a keyring write never drops a slot
  (`RecordVaultStore.cs:288-306`), and the local copy keeps the repair possible. Auto-repair is rejected **(my
  call)**: a future revocation must not be undone by a machine that saw the old keyring, so putting slots back stays
  a person's decision.

### 2.8 Interplay with Part 1

- A discarded value never lowers a floor (§2.4 table). The floor's `Version` is the merged version, which is the
  largest of the inputs whichever value is set aside.
- Clearing, restoring and deleting move stamps into the retired list (§1.5), which R4 accepts.
- R4 is how #197 covers #312's mixed-version limit: a 0.3.x merge that drops an entry is reported on every machine
  that had seen it.
- `conflicts --ack`/`--clear` and `restore --discarded` refuse on a rolled-back record like every other write.

### 2.9 Security model

`docs/security-model.md` gains a "Rolled-back files" section: what is detected (§2.4), on which machines (those that
saw the newer state), what isn't (a vault that was already rolled back before a machine first saw it; a stale
machine's newer re-creation of a deleted name; a process running as the vault's user that edits the config folder
too; a `seen-records.json` lost, damaged or restored from a backup, which starts a fresh or older baseline without a
warning that can tell it from a new machine), and that `seen-records.json` reveals hashed record names with burn and conflict times to whoever can read the
config folder.

## Tests

All in process with `TSWAP_TEST_KEY`, two or three `FleetMachine`s (`TswapTests/FleetMachine.cs`) with their own
origins, sharing a vault folder; a "sync" copies files, and a "conflict" renames one side to
`<hash>.sync-conflict-20261114-162020-ABCDEF` as `RecordConflictTests` does (`TswapTests/RecordConflictTests.cs:123`).
Every clock is a fixed `TimeProvider` set per step (`FleetMachine.Time`); no sleeps. Values are inert markers.
Each key row has a break-it-once check, named in the brief.

### T60 (#312)

**Merge rule** (`RecordMergeTests`, `RecordMergeV3Tests`; every row through `MergeAll` **and** `MergeAllMetadata`,
with a parity test over random states like `RecordWrites_MatchNextRecord_OnRandomStates`):

| Inputs | Outcome |
|---|---|
| A rotates `v0`→`a` at 16:20:16, B `v0`→`b` at 16:20:20 | current `b`, previous `v0`, one entry `a` (origin A), open |
| the same, the stamps the other way round | current `a`, entry `b` |
| A burns `v0`; B rotates `v0`→`b` | no entry; burn history kept; no warning |
| A and B burn `v0` | no entry; earliest burn |
| A holds `v1`; B rotated `v1`→`v2`→`v3` (lineage exact) | no entry |
| the same, B's record built with the extension (`asOf` = `v1`), then its version moved `v1`→`v2`→`v3` with the extension bytes untouched, as 0.3.2 writes it | no entry: not exact (`asOf` ≠ `v3`), `B` = `v2` |
| the same, B's record with no extension at all (written before this release) | no entry (D2 bound) |
| a 0.3.2-shaped tombstone (extension absent, or present with a stale `asOf`) after `v5`; B rotated `v5`→`b` concurrently; the delete wins | tombstone with `b` as an entry (amendment 1) |
| two 0.3.2-shaped first values of one name | the loser is an entry (amendment 1) |
| a 0.3.2-shaped tombstone after `v1`…`v5` written there; a copy holding `v2` (previous `v1`) | `v2` is an entry: the documented residual, pinned |
| a 0.3.2-shaped re-creation of a deleted name, merged with a copy of the earlier life | the earlier life's value is an entry: the second residual, pinned |
| an inexact record (`v3`, previous `v2`, no extension); a concurrent value older than `v2` | no entry: the D2 miss, pinned |
| A, B, C rotate from `v0` | two entries; all 6 input orders and every pairwise order give equal bytes |
| a result merged again with each input | byte-identical |
| an entry acknowledged in one copy, open in another | acknowledged, earliest acknowledgement |
| an entry in one copy, its stamp in another copy's retired list (cleared there) | no entry |
| an entry `a` in one copy, `a` another copy's **previous** version (step 6 of MiMo's C1 sequence) | entry `a` kept |
| an entry whose stamp is the winner's previous version | kept, warning kept |
| A and B rotate to the same value | no entry (amendment 5) |
| a candidate without a set on the metadata path | an entry; the vault "not fully fingerprinted" for that command; the next write fills the set from the section |
| two copies' entries of one stamp with different plaintext (full) / different sections and base fingerprints (metadata) | `RecordConflictException` |
| A deletes after seeing `v1`; B holds `v1` | tombstone, no entry |
| A deletes; B rotates concurrently; delete later | tombstone with B's value as an entry (owner decision 1) |
| A and B create the same name | one entry |
| 33 rotations on one machine, then a merge with a copy 33 behind | that copy's value is an entry (the cap's documented effect, an accepted exception in the anti-goals) |
| 256 entries | the record readable; a write refused with the cap text; `conflicts --clear` and `restore --discarded` work |
| a malformed format 1 extension; a format 2 extension byte | record unreadable; kept as it is with one warning |

**Writes** (`RecordWritesTests`, both write paths):

| Write | Outcome |
|---|---|
| rotate a record with an entry | entry kept; dropped old previous in the lineage; `asOf` = new version |
| rotate a 0.3.2-written record | extension created, `exactFrom` = old previous |
| delete | entries dropped, all stamps in the lineage, the delete line printed |
| `burn`, `field set` on a record with entries | entries byte-identical |
| any write in a format 2 folder of a record with entries | written in format 3 |
| a 0.3.2-shaped round trip (unknown extension kept) | unchanged bytes |

**Commands and the end-to-end case from the issue** (`FleetMachine` A and B):

| Steps | Outcome |
|---|---|
| burned `sync-conflict-test`; A `ingest --rotate` `from-a`; B `ingest --rotate` `from-b` (later); conflict; `names` on A | stderr has the §1.8 warning naming `sync-conflict-test`, A's origin with "(this machine)", both times; stdout `[CONFLICT]`; no value on either stream |
| then `tswap conflicts --json` on B | one conflict, `open` 1, the entry's machine is A's |
| `run test '{{sync-conflict-test:discarded}}' = from-a` | exit 0; one value section decrypted (the entry's) |
| `{{x:previous}}` | the original value, as today |
| child prints `from-a` | `[REDACTED: sync-conflict-test:discarded]` |
| `conflicts --ack sync-conflict-test --by owner` (no sudo) | warning gone on A and B after sync; `conflicts` shows acknowledged |
| `conflicts --clear` without sudo | refused ("requires"), nothing written |
| `sudo restore sync-conflict-test --discarded` | current is `from-a`, previous `from-b`, no entry, no warning on B after sync |
| three machines, two entries: `{{x:discarded}}`; `restore --discarded` without `--stamp` | both refused with the §1.10 texts; `--stamp` picks one |
| a discarded otpauth value (T58's SHA1 URI, fixed time 1111111111.5 s): `{{t:discarded}}` | child gets `050471`; the URI and seed are in neither argv nor output; `conflicts` shows `[TOTP]` |
| `{{t:discarded:totp}}` | T58's unknown-suffix text |
| the child prints the discarded seed in each spelling T58 amendment 5 lists | each masked as `[REDACTED: t:discarded]`; a hex key line stays unmasked, as T58 pins |
| a discarded bare Base32 value, `{{t:discarded}}` | the stored text, as `{{t}}` gives for a bare value (pinned parity) |
| `{{x:discarded}}` reaching `SecretsDb.ResolveToken` | its refusal text |
| A and B rotate from `v0`; B folds and shows the warning; **A rotates again before its folder merges**; B rotates; full sync | both A's values kept as entries on both machines; R4 silent; `tswap conflicts` lists two entries |
| `{{x:discarded}}` on a tombstone holding an entry | the tombstone text |
| `conflicts --ack` twice; `--clear` twice | the second of each writes nothing (exit 0, `No value conflicts for 'x'.` for the second clear) |
| an entry without a set read by `redact` | refused as "not fully fingerprinted" |
| `--stamp` with two entries sharing the 8-hex origin prefix at one HLC | the ambiguity text; the full form picks one |
| `sudo get` | unchanged (the current value) |
| `export` with an open entry | the §1.10 warning; the export imports without it |
| `vault reindex` | entries' sets recomputed; a second run rewrites nothing |
| the warning on `run` of another secret | no warning (only the secret used) |
| every new command's output | `CommandReferenceTests`, `docs/commands.md` regenerated |

Break-it-once: drop the lineage check (the "two rotations behind" row warns); treat "has the extension" as exact
(the 0.3.2-shaped stale-`asOf` row reports `v1`); let `S` remove entries (the step-6 and "A rotates again" rows lose
`a`); drop the `known` term from `B` (both amendment 1 rows lose the value); compute discards from the main file
only (the reversed-order row fails); let `{{x:discarded}}` bypass `CommandValues` (the TOTP row gets the URI); make
`--clear` not need sudo (its refusal row fails).

### T61 (#197)

| Steps | Outcome |
|---|---|
| A writes `x`; a copy of `records/<x>` is saved; A rotates `x`; the saved copy put back; `names` on A | R1 warning naming `x`, its file, "now holds an older value"; floor not lowered |
| then `rotate x` (sudo bypass) | refused with the §2.5 text, exit 1, the file unchanged |
| then `burn x` | written; the warning stays at the next `names` |
| then `sudo vault merge <folder with the newer file>` | no warning afterwards; `rotate` works |
| instead `sudo vault accept-rollback x` | no warning; `rotate` works; the floor equals the current state |
| `delete x`, then the pre-delete file put back | R1 "it was deleted; now it holds a value"; `names` still lists `x` (read goes on) |
| `burn x`, then the pre-burn file put back | R1 "the burn is gone" |
| a field set rolled back | R1 "a change … is missing" |
| a record file deleted | R2 naming the file; `create x` refused; `accept-rollback --all` clears it |
| normal sync: B rotates, the file copied to A | no warning, floor raised |
| conflict with the older file kept as main, the newer as copy | no warning |
| the #312 issue case on both machines | no rollback warning on either |
| `conflicts --clear` on B, synced to A | no R4 warning |
| an entry dropped by a 0.3.2-shaped merge (main rewritten without the extension, newer write stamp) | R4 warning only; writes work |
| a command on an unchanged vault | `seen-records.json` not rewritten (its bytes and mtime unchanged) |
| `seen-records.json` missing / of another vault id / not JSON | baseline, no warning / notice / warning; nothing refused |
| two commands' floors interleaved (write the file between load and save) | per-component maximum |
| `keyring` replaced by a copy without B's slot; `names` on A | warning naming B's slot id and kind |
| `keyring` replaced by a copy without A's own slot; any command on A | the new unlock text (not "Config is corrupted") |
| then `sudo vault restore-slots --yes` | A unlocks again; B's slot back too; no unlock was needed (the unlocker seam counts none) |
| `restore-slots` with nothing missing | `Nothing to put back.`, nothing written |
| a slot with the same id and other bytes | the "differs" warning; that slot not added to `seen-keyring`, the other new slots added |
| machine C first sees an entry already acknowledged; then the record rolled back (or 0.3.2-shaped merged) without it | R4 on C (amendment 2) |
| an entry's burned flag rolled back (the pre-burn file put back, the entry still present) | R4 burn text; `{{x:discarded}}` still gives the burned warning |
| `conflicts --clear` on this machine, then a 0.3.2-shaped merge drops the lineage | no R4 warning (amendment 8) |
| a machine whose clock is behind writes after seeing the record | no R1 anywhere |
| `delete x` on a flagged record; then `accept-rollback x` and `delete x` | refused with the delete line; then deleted |
| `restore-slots` against a folder whose keyring is another vault's | refused, nothing written |
| a read-only config folder | one warning; floors unchanged; commands go on |
| run under a sudo escalation (`FleetMachine.SudoEscalated`) | both new files owned by the config folder's owner, 0600 |
| each write command, `delete` included, run on a fixture vault | no main record file ever disappears (R2's premise) |
| a 0.3.2-shaped reader with `seen-records.json` and `seen-keyring` present | the same output as without them |
| two commands' `seen-keyring` writes interleaved | a union of both slot sets |
| two commands' floor entry lists interleaved | a union by stamp, burned bits OR-ed |
| a machine with a clock a year ahead writes; its copy is then lost | R1 with the future time and the year-ahead warning |
| a write of either new file killed before its rename (a write seam that throws) | the old file intact; the next command reads it |
| an R4 warning on a record, then a newer write of it | the floor's other components still raise |
| `accept-rollback x` on a record with an R4 warning | R4 silent afterwards |
| a floor entry whose stamp is in the record's retired list | pruned at the next save |

Break-it-once: compare the main file instead of the merged state (the conflict row warns); drop the version component
(the delete-then-stale-write row passes silently); let `accept-rollback` run without sudo (its refusal row fails);
make `restore-slots` unlock first (the own-slot row fails).

## Briefs

Serialised: **T58 → T60 → T61**. T60 needs T58's grammar and `CommandValues` and touches the same token files; T61
needs T60's extension for R4 and shares `RecordVaultStore.cs`. Neither T60 nor T61 runs in parallel with another
brief that edits `RecordVaultStore.cs`, `RecordMerge.cs`, `RecordWrites.cs` or the token grammar files.

**T60, keep merge-discarded values (#312).** Owns: new `TswapCore/Keyring/ValueLineage.cs` (model, codec, the
discard rule as pure functions), `TswapCli/Commands/ConflictsCommand.cs`; edits `TswapCore/Keyring/RecordMerge.cs`,
`RecordWrites.cs`, `RecordMetadata.cs`, `TswapCore/RecordVaultStore.cs` (fold notes, `NextRecord`, `Tombstone`,
`PrepareV3`, `IsCurrent`, entry sections, format 3 forcing), `TswapCore/VaultWriter.cs` (ack, clear, restore by
stamp), `TswapCore/VaultView.cs` (`:discarded`, the index), `TswapCore/SecretInfo.cs`, `TswapCli/FingerprintStreamMatcher.cs`,
T58's `TswapCore/Totp/CommandValues.cs` and the grammar files T58 lists, `TswapCli/Commands/RestoreCommand.cs`,
`NamesCommand.cs`, `DeleteCommand.cs`, `ExportCommand.cs`, the command registry, `TswapCli/CliJson.cs`,
`TswapCore/Fields/FieldSet.cs` (registry comment), `TswapCore/Prompt.cs`, `docs/commands.md`, `docs/multi-machine.md`,
`docs/security-model.md`, AGENTS.md (the privilege lists), the release notes; tests as above. T60 changes the token suffix list again, so it re-sanctions exactly T58's
suffix-pinning assertions (`FieldTokenRefusalTests.MalformedMessage` and `.MarkerMessage`, `RunEnvTests.Exactly` and
its `{{x:bogus}}` row) and no others. Six tasks: extension
and codec; merge rule and parity; writes; warnings and `names`; `conflicts`, `restore --discarded`, `:discarded`;
docs.

**T61, detect rolled-back records and slots (#197).** Owns: new `TswapCore/Keyring/SeenFloor.cs` (the rules of §2.4
as pure functions over merged metadata), `TswapCore/SeenState.cs` (the two files); edits `TswapCore/RecordVaultStore.cs`
(the load, open and commit hooks, `ReadKeyringWithCopies`, `Reindex`), `TswapCore/VaultWriter.cs` (the refusal),
`TswapCore/Vault/VaultUnlocker.cs` (the own-slot text), `TswapCli/Commands/VaultCommand.cs` (`accept-rollback`,
`restore-slots`), `TswapCore/Prompt.cs`, `docs/commands.md`, `docs/multi-machine.md`, `docs/security-model.md`,
AGENTS.md, release notes; tests as above. Four tasks: the floor model and file; the record checks and refusal; the
keyring check, unlock text and `restore-slots`; `accept-rollback` and docs.

Before each release, a one-off check with the v0.3.2 binary on a copy of a vault the new build wrote (`names`, `run`,
a rotate, a merge of a conflict copy), with `seen-records.json` and `seen-keyring` in its config folder, recorded in
the PR, as T54 did.

## Decisions (owner, 2026-11-27, were the open questions)

1. **A value that loses to a concurrent delete is kept on the tombstone as a discarded value (owner).** It is warned
   about and listed by `tswap conflicts`; `sudo tswap restore NAME --discarded` brings the secret back and
   `sudo tswap conflicts --clear NAME` drops it.
2. **`tswap conflicts --ack` takes no sudo (owner).** It destroys and reveals nothing, only quietens the warning on
   every machine, and records the machine, time and `--by` label. Dropping a value (`--clear`) and restoring one
   (`restore --discarded`) need sudo.
3. **Export leaves discarded values out and warns, naming the secrets (owner).** Exports stay importable by 0.3.2;
   the warning is the one in §1.10.
