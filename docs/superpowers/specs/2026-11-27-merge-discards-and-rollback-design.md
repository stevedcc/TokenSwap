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
   `seen-records.json`; the floor's entry list merges as a union by stamp with the burned bits OR-ed. (5) At the
   entry cap the record stays readable; only a write that would exceed it is refused, naming `conflicts --clear`,
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

## Amendments (round 3)

Round 3 review by MiMo (`~/RiderProjects/tswap-wt/tools/design-records-r3-mimo.md`, "not ready to plan": one Critical,
three Importants), with the controller's rulings. Folded into the text below and tagged where they land; they win
over rounds 1 and 2 where they differ. Tie-breakers used: no value lost without a person deciding; a normal sync or
rotation never warns or refuses; fail closed on values.

1. **C-1, the floor's `(Version, Burn)` pairing (taken).** `Version` and `Burn` are one component: `Burn` is always the
   outstanding burn of the floor's `Version`. When the seen version rises, the pair is replaced whole by the seen
   state's; in an interleaved save the pair comes whole from the side with the larger version (§2.3). Round 2's
   "per component, the larger" let a burn of `v10` survive a normal rotation to `v12` and fire a false R1 and a write
   refusal. R1's third clause keeps "no burn **of that version**": MiMo's alternative "no burn with stamp `F.Burn`"
   is refuted from the code, because two machines burning one version concurrently keep only the earliest burn
   (`RecordMerge.cs:34-37`), so the later burner's own stamp disappears in a normal merge. Every earlier T61 row and
   every C1 and I-2 sequence re-run against the corrected floor (§2.4); the burn-then-rotate row and its
   break-it-once added; the interleaved row now states the pairing.
2. **I-1, a `T` mark against a live current value (ruling: never removed).** `T` removes existing entries only; it
   never excludes a copy's **current** value. A value that is still some copy's current value becomes an entry again
   even after a clear on another machine, its stamp leaves the merged `T`, and the usual warning shows (§1.1, §1.4).
   This replaces MiMo's proposed extra warning: with no loss there is nothing extra to warn about. `--clear`'s output
   says a copy that still holds the value as its current one brings it back (§1.9). Rows added.
3. **I-2, the `:discarded` lookup (taken).** `:discarded` is passed to the inner lookup as `x:discarded`, as `:previous`
   is; nothing strips it (§1.10). Break-it-once added.
4. **I-3, `seen-keyring` rules (taken, simplified).** Both files are now **per vault**: `seen-records-<16 hex of the
   vault id>.json` and `seen-keyring-<16 hex>`. That removes the `VaultId` field and the "another vault" reset rule
   altogether (a config pointed at another vault simply has no file yet), and `restore-slots` reads the file of the
   folder keyring's own vault id, so it can't union another vault's slots. Missing and damaged get the same rules for
   both files; §2.9 names both (§2.3, §2.7, §2.9). Rows added.
5. **M-1** taken: the agreement check covers a stamp held as current, previous or an entry (§1.4).
6. **M-2** taken: byte-equal sections merge; differing sections where one side has no set fail closed (§1.4).
7. **M-3** taken: a write command whose fold would exceed the entry cap is refused once per command, the copies kept;
   "always work" is against the cap only; the cap text adds the rollback case (§1.4).
8. **M-4** taken: a warning variant for an entry that is also the previous value; a row (§1.8).
9. **M-5** taken: `restore-slots` adds slots the folder's keyring lacks by id and skips a differing same-id slot (§2.7).
10. **M-6** taken: `accept-rollback NAME` also takes an R4-flagged name; `--all` sweeps R1, R2 and R4 (§2.6).
11. **M-7** taken: the five missing rows added (Tests).
12. **Simplified (MiMo §8.1):** "or its stamp is `W.Version`" is gone from the entry rule and from R4. It can't happen:
    every copy that carries an entry has a version above the entry's stamp, and versions never decrease. An entry
    leaves only through `T`.
13. **Brief note (MiMo §5):** T58's `ValueKinds` drops entries of stamps no longer retained on a value write;
    `ValueLineage`'s entries must not share that code (Briefs).

## Amendments (round 4)

Round 4 review by MiMo (`~/RiderProjects/tswap-wt/tools/design-records-r4-mimo.md`: no Critical; F-1 and F-2
Important, wording and test rows; F-3 to F-9 Minor). All nine taken and settled here, not in the briefs.

1. **F-1, the bound's silent miss (taken).** Goal 1 is qualified: where a record's lineage can't be trusted (no
   extension, or bounded by `exactFrom`), a concurrent value at or below the bound `B` is dropped without a warning,
   as before this release. §1.1's residuals, the anti-goals' accepted exceptions and `docs/multi-machine.md` "Mixed
   versions" now name that miss, not only the false warnings; a row pins the `exactFrom`-bounded shape.
2. **F-2, a returning entry inherits a stale acknowledgement (taken).** An entry that re-forms over a `T` mark is
   **open**, whatever acknowledgements the copies carry: an acknowledgement belongs to one life of an entry, not to
   its stamp (§1.1, §1.4). `--clear`'s output names both ways a value can come back and promises a new warning
   (§1.9). The rollback-then-stale-write path, which no merge can see, is a documented limit for clears as for
   deletes (§2.4). Rows added for both.
3. **F-3** taken: `restore-slots` with no `keyring` file refuses with today's "no keyring file" text and names this
   machine's `seen-keyring-*` files, each a complete keyring that can be copied back as `keyring` (§2.7).
4. **F-4** taken: the floor's burn is the **earliest** burn seen of the floor's version (as `CanonicalBurns` keeps,
   `RecordMerge.cs:34-37`), in the raise and in the interleaved save alike; taking an earlier burn of the same version
   is not a lowering (§2.3).
5. **F-5** partly refuted, partly taken: a name **can** address an R2 record, because `accept-rollback` unlocks and
   hashes the name to its file (`FilenameHasher.ComputeFilename`, as `OpenSecret` does, `RecordVaultStore.cs:586-600`);
   what is unknown is the name in the warning, which shows only the hash. So `--file <64 hex>` is added for an R2
   record whose name the user doesn't know (§2.6).
6. **F-6** taken: an entry without a set shows ` [not fingerprinted]` in `conflicts`; one whose section can't be
   decrypted gives the record's unreadable text from `{{x:discarded}}` and `restore --discarded`; `--clear` works
   on it (§1.9, §1.10).
7. **F-7** taken: on a rolled-back record at the entry cap, the order is `accept-rollback`, then `conflicts --clear`,
   then `vault merge`; stated in §2.5, row added.
8. **F-8** taken: `T` subtracts the current-value stamps first, then keeps the 32 newest. The entry cap is lowered
   from 255 to **64** (MiMo's metadata-size note; round 6: §1.4 gives the figure), the same safety, since
   reaching the cap refuses a write and never drops a value; 64 concurrent rotations of one secret don't happen (§1.3,
   §1.4).
9. **F-9** taken: rows for the `exactFrom` miss, both returning-entry paths, the cap-plus-rollback order, an entry's
   burn surviving the 16-burn trim, and the equal-version burn tie (Tests).

## Amendments (round 5)

GLM's round 2 review (`~/RiderProjects/tswap-wt/tools/design-records-r2-glm.md` at 6485ae0: not ready; one Critical,
four Important, thirteen Minor), with the controller's rulings. Folded into the text below and tagged; they win over
earlier rounds where they differ. Owner decisions stay as recorded.

1. **C-1, merge order with `T` across three copies (ruling: the reviewer's direction, made order-independent).** Round 3
   and 4's rules ("a copy's current value is never removed by a `T` mark", "an entry that re-forms over `T` is open")
   were right for two copies and order-dependent for three. They are replaced by stamps that only ever take a maximum
   or a union, so every merge order computes the same thing (§1.4a):
   - each entry carries **`returnedBy`**: the largest write stamp of any copy that held its value as the current value,
     in any merge it went through. That is the reviewer's "from current" flag, as a stamp instead of a bit, so a
     stale copy can't set it again after a person acted;
   - each retirement in `T` carries **`covers`**: the entry's `returnedBy` when the person acted (`--clear`,
     `restore --discarded`, `delete`). An entry is removed only when some retirement of its stamp covers its
     `returnedBy`. A retirement that covers less is the reviewer's "plain mark" and never removes it; a person's action
     always writes a covering one, the reviewer's "after-return mark";
   - each acknowledgement carries `covers` too: an entry is acknowledged only when an acknowledgement covers its
     `returnedBy`. On the machine that wrote the value it stays open until an acknowledgement **from that machine**
     covers it, which settles "A's current against B's acknowledged entry: open on A".

   §1.4a works through the three pairwise orders of A, B and C, with and without C's acknowledgement, for `--clear`
   and for `delete`, plus the two acknowledgement cases, and shows each gives the all-at-once bytes. One plain
   difference from the review's expectation: `(A, B)` re-merged with C's stale acknowledged copy comes out
   **acknowledged** everywhere except on A's machine, not "still open", because C's acknowledgement covered the same
   copy of A's value; it stays order-independent. Round 3's "never removed while a copy holds it as current" is
   narrowed: a person's clear that covered that copy does remove it.
2. **I-1** taken: a detached store (`RecordVaultStore.ForFolder`, `RecordVaultStore.cs:98-103`) never reads or writes
   the seen files (§2.3). Rows added, including a refused `vault merge` that raises nothing.
3. **I-2** taken: a process keeps no copy of the floor file between operations; at save it re-reads the file and
   applies only what this operation authenticated, so a lowering on disk wins (§2.3). P1/P2 and broker rows added.
4. **I-3** taken: the extension is written whenever this release writes the record (§1.4 rule 4). Row added.
5. **I-4** taken, option (a): entries are decrypted lazily, only when resolved, restored, or written by a value write
   or `vault reindex` that must fill or recompute their set; a full load decrypts none (§1.5). Security-model rows,
   `PendingWrite.cs` and `SecretEntry.cs` in T60's files, and decrypt-count rows added.
6. **M-1** taken: R1's texts add "If a sync is in progress, wait for it to finish and run again."; a row (§2.5).
7. **M-2** taken, corrected: after a `vault merge` (or any write by this machine) a rollback seen only in the write
   stamp is no longer reported; the version and burn clauses still flag. GLM's "Burn-only" is refuted: R1's burn
   clause doesn't depend on the write stamp (§2.5).
8. **M-3** taken: the figure was the minimum. Entries also get a **64 KiB** cap on their total encoded size, the same
   as the `Fields` extension's; a write that would exceed it is refused (§1.4).
9. **M-4** taken: `restore --discarded`, `burn`, `restore` documented as the way to burn a discarded value (§1.10).
10. **M-5** taken: `conflicts` decrypts nothing in any mode; missing sets are filled by the next value write or by
    `vault reindex` (§1.5, §1.9).
11. **M-6 to M-13** taken as the reviewer suggests, with `--stamp` reduced to the 8-hex form (§1.5, §1.9, §1.10, §2.3,
    §2.5, §2.6, §2.7, §1.2, §1.6, §1.8).
12. **Q7** taken: every missing row the review lists, including the absence sweep and break-it-once rows for R2, R4,
    the slot check and the refusal (Tests).

## Amendments (round 6)

MiMo's round 5 review (`~/RiderProjects/tswap-wt/tools/design-records-r5-mimo.md` at 98447d2: two Critical, six
Important, nine Minor), with the controller's ruling: **simplify**. These win over every earlier round.

1. **C-1 and C-2: retirements name the value version (ruling: MiMo's alternative).** A retirement in `T` is the
   version stamp alone; `T` is a union; an entry is removed exactly when its stamp is in `T`, and a copy's current
   value whose stamp is in `T` is never a candidate (§1.1, §1.4, §1.4a). `returnedBy`, `covers` and every rule built
   on them are **gone**, and with them round 3's and round 5's "a copy written after a person's clear brings the value
   back, open". A person's sudo `--clear`, `restore --discarded` or `delete` retires that value for good: the same
   value arriving later from a stale copy is the value the person already decided about, so it is not a loss. Owner
   decision 1 stands: `delete` retires only the entries it saw, so a concurrent value it never saw stays on the
   tombstone. §1.4a now states the invariant and proves it, and works MiMo's C-1 shapes (demotion with `a ∈ R`, and
   `S ∋ a`) through all six pairwise orders and all at once. C-2 closes: with stamp retirements, R4's "in `M`'s
   retired list" is exactly "a person dropped it", and pruning a retired stamp from the floor is sound because no
   merge can bring an entry with a retired stamp back (§2.3, §2.4).
   **Behaviour dropped:** a value that a person cleared, restored or deleted never comes back as an entry, even from a
   copy that machine wrote after the decision (a burn or field change made on a copy that hadn't merged yet). The
   value is still that copy's current value until it merges, and the decision covers it.
2. **Acknowledgements are per stamp, a union (my call: the writer's-machine rule kept).** An entry is acknowledged when
   any acknowledgement of its stamp exists. "Open on the machine that wrote the value until that machine
   acknowledges it" stays: it is a pure display rule over the merged acknowledgement set (does an acknowledgement
   from this machine's origin exist?), so it can't affect merge results (§1.4a, §1.9).
3. **The equality rule becomes display only (my call, for the invariant).** Amendment 5 of round 2 excluded a
   candidate whose value equals a retained value, and MiMo's M-1 asked for the same on existing entries. Removing or
   excluding by equality depends on the winner **of each pairwise step**, so membership would no longer be decided
   from merged sets alone. Instead an entry whose base fingerprint entries equal a value the merged record retains
   stays an entry but gives no warning and no `[CONFLICT]`; `conflicts` lists it as `(same value as the current
   value)` (or previous). Nothing is lost and nothing warns (§1.1, §1.8).
4. **I-1** taken: `--stamp` accepts the printed `<ms>.<logical>@<8 hex>` form and the full `<ms>.<logical>@<32 hex>`
   form; §1.9, §1.10 and the row agree.
5. **I-2** taken: entries are compared by section bytes and base fingerprint entries on **both** paths (§1.4 rule 2);
   the plaintext row is rewritten.
6. **I-3** taken: a write that first creates the extension on a record without one sets `asOf = Stamp.Zero`
   (inexact), except value writes and `delete`, which follow §1.5's table. Both rows added.
7. **I-4** taken: when `{{x:discarded}}` or `restore --discarded` decrypts an entry without a set, it computes the set
   there and adds it to that command's matcher index; `restore --discarded` stores it with the new version (the value
   becomes current, with its set); `run` writes nothing, so the set is stored at the record's next value write or
   `vault reindex` (§1.10). Row added.
8. **I-5** taken: `--clear`'s text says the value is gone for good and a later copy of it doesn't bring it back; the
   same in `docs/multi-machine.md` (§1.9).
9. **I-6** taken: §2.9 and the backup guidance say `seen-keyring-*` is a copy of the vault's keyring.
10. **M-1** taken as display (amendment 3 above). **M-2** taken: format 3 whenever `S`, `T` or the entries are
    non-empty. **M-3** taken: `config.json` gains the vault id (`VaultId`), and `restore-slots` refuses a folder whose
    keyring belongs to another vault (§2.7). **M-4** taken: reworded, re-flag row added (§2.3). **M-5**: the
    break-it-once it names is gone with `returnedBy`; the new ones are listed. **M-6**: one figure, §1.4's. **M-7**:
    §2.5 says a resurrected deleted secret is still handed out, with the warning. **M-8**: `[burned]` is present iff
    the burned flag is set; the floor example shows both kinds of entry. **M-9**: file names use lower-case hex.

## Amendments (round 7)

MiMo's round 6 review (`~/RiderProjects/tswap-wt/tools/design-records-r6-mimo.md` at 4bb8d74: no Critical, five
Important, six Minor; "sound once those are folded in"), with the controller's rulings.

1. **I-1, the `S` cap and claim 3 (taken).** `S` is raised to **64** stamps. Claims 1, 3 and 4 and §1.4's Properties
   now state their precondition, "no cap reached at any step"; past it, a copy more than 64 rotations stale may be
   kept or dropped depending on merge order (§1.1, §1.6, Anti-goals). The proof line now reads `S_step ⊆ S(I) ∪
   R(W)`. MiMo's three-copy rows are added in both orders.
2. **I-2, the `T` cap and "for good" (taken: (i), (ii) and (iii)).** `T` is raised to 64 too. (i) Claim 1, "Part 2
   follows" and the `--clear` text state the exception: 64 later retirements on the same record can push a stamp out.
   (ii) A candidate-created entry is always open, and an acknowledgement travels only with an entry that existed
   before its stamp was retired: the record keeps `forgotten`, the largest stamp ever pushed out of `T` (a maximum,
   so order-independent), and an entry at or below it is shown open whatever its acknowledgements (§1.3, §1.4a).
   (iii) A `T`-cap row.
3. **I-3, format 2 (taken).** `T` or entries force format 3; `S` alone doesn't. Rule 4, §1.5 and §1.6 agree; an
   `S`-only row in a format 2 folder.
4. **I-4, own slot with other bytes (taken).** A third unlock text for a slot that is there but differs, and
   `restore-slots` prints the same instruction when the slot it skips is this machine's own (§2.7). A row.
5. **I-5, the C-2 row (taken).** Split into (a), (b) and (c); (a) is MiMo's round 5 C-2 (Tests).
6. **M-1** intended: once no retained version holds the entry's value, its warning is factually right; stated
   (§1.1) and a row. **M-2**: R4 names an import of an export as a cause; a row. **M-3**: `conflicts` shows an entry's
   burn date and reason, `--json` carries them. **M-4**: a fold that consumes a copy whose current value was retired
   shows nothing on A's machine (§1.8). **M-5**: acknowledgements past 8 drop the oldest, which can reopen an entry,
   the safe direction (§1.4). **M-6**: Goal 2 reads "until someone acknowledges or drops it on any machine".

## Amendments (round 8)

Inputs: MiMo's round 7 (`~/RiderProjects/tswap-wt/tools/design-records-r7-mimo.md` at 39fd371: no Critical, three
Important), an adversarial Claude review (`design-records-r7-claude.md`: one Critical, seven Important; not an external
review, its findings verified), and the gap rulings of the two brief drafts, T60 (`t60/docs/briefs/t60-merge-discards.md`
at 08a060f, R1-R12) and T61 (`t61/docs/briefs/t61-rollback-detection.md` at c1a79e0, R-1 to R-15), folded in so this
design stays authoritative. Controller rulings in brackets.

**The model, in what changed:**
1. **The floor takes only persisted entries** (Claude C-1). A fold's in-memory candidates never raise the floor's
   `Discarded` list; only entries held in an authenticated file (a main file or a conflicted copy, as loaded, or as
   this machine commits) do. Claim 2 then covers every floored entry, so a pairwise superset seen once in memory can't
   give a lasting false R4 (§2.3). Row: Claude's three-machine table.
2. **The properties are restated** (Claude I-1): the all-at-once merge is permutation-invariant and idempotent;
   pairwise results hold a superset of its entries; copies converge by union once every result has met (§1.4,
   §1.4a). The text no longer says "the same bytes in any order". **One silence rule** (Claude I-1, I-2): an entry is
   silent (no warning, no `[CONFLICT]`) when its stamp is in `S(M)`, is `W`'s previous version, or its base
   fingerprint entries equal a retained value: in each case a writer that held the value replaced it knowingly, or
   the record still holds it. Display only; membership is unchanged. It removes §1.8's "also the previous value"
   variant (which overrides T60's R12 for that form) and round 7 M-1's "starts warning two rotations later" (a dropped
   previous joins `S` and stays silent).
3. **Every write carries `T` and `forgotten`** (Claude I-4), the new-life write included; only a person's action adds
   to `T`, and only the cap removes from it (§1.5).
4. **Earlier-life entries** (Claude I-5): an entry whose stamp is below the current life's start (the `Fields`
   extension's `Since`, `RecordWrites.cs:93`) is refused by `{{x:discarded}}` and its warning names the earlier life
   (§1.8, §1.10).
5. **A floor `Retired` list** (Claude I-7, MiMo I-1): the stamps this machine saw retired in authenticated files,
   never pruned; R4 warns when one reappears as an entry, whoever merged it. Retirements are "for good" on machines
   running this release; an older tswap's merge or format 2 write can bring one back, and this release then warns
   (§1.6, §1.9, §2.3, §2.4).
6. **A newer-format lineage** (MiMo I-2, T60 R8): its record's merge uses the whole-list rule, sets nothing aside and
   warns once per record per command. Writes that would have to update the lineage are **refused** (the fail-closed
   choice); `burn` and field writes, which leave the lineage alone, keep it byte for byte (§1.3, §1.4).
7. **The `kind` byte is dropped** (over-design O-2): display only, and the source of the path-parity problem T60's R3
   worked around. Nothing reads it for safety: `{{x:discarded}}` decides from the value (T58). `conflicts` no longer
   shows `[TOTP]` on an entry.
8. **The `restore-slots` vault-id refusal is dropped** (over-design O-5): the per-vault file name already keeps
   another vault's slots out (`restore-slots` reads the file of the folder keyring's own vault id), so it only changed
   a message. `Config.VaultId` stays: T61's R-7 notice needs it.
9. Kept, each with why: **`forgotten`** (the floor `Retired` list warns only on machines that saw the retirement;
   `forgotten` makes the returning entry open on every machine, a new one included); **the floor's burned bit** (it is
   what reports an entry's burn lost to a 0.3.x merge that keeps an older list; dropping it loses that detection);
   **`accept-rollback --file`** (without it a person who can't name a missing record must use `--all`, which also
   accepts every other flagged record); **"open on the writer's machine"** (pure display; dropping it simplifies
   nothing).

**Rulings, finding by finding** (where each lands):
- Claude C-1 → model 1. Claude I-1, I-2 → model 2. Claude I-3 [keep the value]: the `known` term stays; §1.1, the
  anti-goals and `docs/multi-machine.md` say plainly that a tombstone without an exact lineage reports **any** copy
  that still holds the deleted value, including a `vault merge` of a backup from before the delete. Claude I-4 → model
  3. I-5 → model 4. I-6: `field adopt` refuses a SECRET that holds entries (§1.7; T60's files gain `FieldCommand.cs`).
  I-7 and MiMo I-1 → model 5. MiMo I-2 → model 6. MiMo I-3 (a)-(d): rows.
- **T60 R1-R12**, as written: R1 unsealed entries and R2 format 2 holdings (§1.4 rule 2); R3 moot (the kind byte is
  dropped); R4 `flags` bit value `0x01` is "burned"; R5 `byLength` counts UTF-8 bytes 0-255 and `--by` is also refused
  over 255 bytes; R6 `discardedCount` decodes 0-255 (64 is a write cap); R7 an all-zero lineage is not written (this
  replaces round 6 amendment 6's "a burn creates the extension with `asOf` zero": an extension whose every stamp is
  zero and whose lists are empty is exactly "no extension", inexact with D2's bound, so leaving it out is equivalent);
  R8 → model 6; R9 JSON properties shown as `null` are marked `JsonIgnoreCondition.Never`; R10 the status goes at the
  end of each `discarded` line; R11 T60's cap text has no rollback parenthetical (T61 adds it); R12 the warning forms,
  minus "also the previous value" (model 2).
- **T61 R-1 to R-15**, as written: R-1 the floor's `Deleted` flag, part of the pair; R-2 "saw on" is the floor's
  `Write` time; R-3 no `--verbose`: R1 shows the short file form, R2 the full 64 hex; R-4 one full text for one
  flagged record, a summary for two or more; R-5 R2 only when no file at all exists; R-6 `Skip`'s format 2 records
  are neither checked nor floored and never R2; R-7 the upgrade notice needs a `LastHlc` **and no `VaultId`**; R-8
  where `VaultId` is written; R-9 the `VaultView` edit for the floor's burned bit; R-10 the slot-kind words, computed
  in Core; R-11 `Config.KeyringFolder` carries the own-slot facts to `VaultUnlocker`; R-12 the seen files are always
  0600 (`WriteAtomic(…, keepMode: false)`); R-13 every text in full, now Appendix A; R-14 five tasks; R-15 R4 ignores
  `forgotten`.
- **Minors.** MiMo M-1 (both preconditions in the Properties), M-2 (`forgotten`'s write rule), M-3 (a candidate
  entry starts with no acknowledgements), M-4 (the network-share row re-cited), M-5 (elevation words per platform, as
  T58 amendment 8), M-6 (`ISecretLookup`'s contract comment amended), M-7 (R5), M-8 (`burn` exempt from the entry
  cap). Claude 1 (proof wording), 2 (tied winners), 3 (moot with the kind byte), 5 (an R3 record raises nothing), 6
  (R-7), 7 (the burn exception's lost incident named), 8 (R1 re-checked at save), 10 (R4 past the `T` cap named),
  11 (`exactFrom` zero with no old version), 12 (Goal 1 names format 2 folders), 13 (`KeyringSlotId` null; the
  "differs" instruction says to run `restore-slots` on the other machines). **Claude 4 conflicts with round 7 M-2's
  ruling and the code settles it:** `import` skips a name that exists (`ImportCommand.cs:103`) and otherwise writes
  through `SetValue` (`:128`, `RecordWrites.NewVersion`), which keeps entries, so an import can't drop one; the cause
  and its row are removed. **Claude 9 can't be adopted as written:** acknowledgement stamps and retired version stamps
  aren't ordered against each other, so "acknowledged after the retirement was forgotten" can't be decided from the
  merged record without a further stamp; the over-warning stays, on the safe side, with the hedged text.

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
   `{{name:previous}}`, until a person drops it or puts it back. Nothing that merges copies loses a value silently,
   except where a record's lineage can't be trusted (written before this release or since by 0.3.x, or by this
   release in a folder that writes format 2 with only `S` to keep; round 8, Claude 12): there a
   concurrent value at or below §1.1's bound is still dropped as today (round 4 amendment 1).
2. A **warning that names the secret**, on every machine that uses it, until someone acknowledges or drops it on any
   machine (round 7, M-6). No warning
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
  Accepted exceptions, each on the safe side (the value kept): the mixed-version false warnings of §1.1 and §1.6,
  including every copy that still holds a value deleted under an inexact lineage (round 8, Claude I-3).
  Accepted exceptions that can keep nothing: the bound's miss on a record whose lineage can't be trusted (§1.1, round
  4 amendment 1), and a copy more than 64 value changes stale, which may be kept or dropped depending on merge order
  (§1.4a, round 7 amendment 1).
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
for both the issue's case and the "two rotations behind" case, and it costs at most 64 stamps (1792 bytes; round 7) of
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
- `T` (retired) = the union of every copy's retired list: the version stamps a person dropped (round 6 amendment 1).
- **Discarded** (round 2 amendment 1, round 6 amendment 1) = every existing discarded entry of any copy, **plus**
  every copy's current value version `V` with `V > B` and `V ∉ R ∪ S ∪ T`; **minus** every one whose stamp is in `T`.
  A person's `--clear`, `restore --discarded` or `delete` retires the value for good; the same value from any copy,
  written before or after the decision, is the value that person decided about.
- An entry whose value equals a value the merged record retains, whose stamp is in `S(M)` or is `W`'s previous, is
  kept but silent (round 8 model 2; dropping it would make membership depend on each pairwise step's winner).
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
| a discarded entry cleared, restored or acknowledged on another machine, then a stale copy holding it **as an entry** arrives | clear and restore retire the stamp, so the entry goes; an acknowledgement travels with the entry |
| B folds A's copy (entry `a`) and clears it; A's copy, still holding `a` as its current value, then meets B's | no entry: `a` is retired (round 6 amendment 1; §1.4a works every order) |
| the same, but A burned `x` (or set a field) before its copy merged | no entry either: the clear retired the value, whichever copy carries it (the behaviour round 6 dropped) |
| `restore --discarded` of `a` on B; A still holds `a` as its current value | no entry: `a` is retired |
| A and B rotate from `v0` (`a`, `b`); B folds (entry `a`); A rotates `a`→`c` before its folder merges; B rotates `b`→`d`; the copies meet | `W` = `d`, `R` = {`d`, `b`}, `S` ∋ `a` (A's previous): entry `a` **kept** (not retired), and `c` > `B`, ∉ `R ∪ S ∪ T`: entry `c` too (round 2 amendment 1) |
| the same, but A's `c` is later than `d` | `W` = `c`, previous `a`: entry `a` kept although it is the previous value (demotion keeps it); B's current `d` is a new entry; `b`, B's own previous (B replaced it knowingly), is not |
| A and B both rotate to the same value from `v0` | an entry, silent: its value equals the current one (round 6 amendment 3) |
| A on 0.3.2 deletes after `v5`; B rotated `v5`→`b` concurrently; the delete wins; a merge here | `S` holds B's previous `v5`, so `B` = `v5`; `b` > `v5`: discarded, kept on the tombstone (owner decision 1) |
| A and B on 0.3.2 create the same name; a merge here | both sets empty, `B` = zero: the loser is discarded |

Residuals of the inexact case (documented in `docs/multi-machine.md` "Mixed versions"): a tombstone 0.3.x wrote
after several 0.3.x rotations, merged with a copy that is stale but newer than that copy's own previous value, reports
the stale value once (a warning, the value kept); and a 0.3.x re-creation of a deleted name can bring an earlier
life's value up as an entry once. Both are false warnings on the safe side; a person clears them with sudo. And one
miss, not on the safe side (round 4 amendment 1): on a record with no extension, or one whose `exactFrom` was set when
this release first wrote over an inexact lineage, a copy's current value at or below `B` is dropped with no entry and
no warning, exactly as before this release. It needs a value written concurrently with, but stamped before, a value
the winner's lineage only assumes superseded. And past the caps (round 7 amendment 1): a copy more than 64 rotations
stale may be kept as an entry or dropped silently depending on the order its copies merge in (§1.4a's precondition).

**Tombstones without an exact lineage** (round 8, Claude I-3, the value kept by ruling): a tombstone stores no
previous version (`RecordWrites.cs:114-118`), so for one written by 0.3.x, before this release, or by this release in a
folder that writes format 2 with nothing but `S`, the bound is `min(t, max(S))` and **any** copy that still holds the
deleted value itself (above its own previous) sets that value aside on the tombstone. That includes a copy written
concurrently with the delete and every `vault merge` of a backup taken before it, the repair §2.6 recommends: after
the upgrade, the first such merge reports every secret deleted since the backup was taken. The values are kept
(owner decision 1's side), warned about, and cleared with sudo. `docs/multi-machine.md` says so.

**Silence** (round 8 model 2): an entry gives no warning and no `[CONFLICT]` when its stamp is in `S(M)`, is `W`'s
previous version, or its base fingerprint entries equal a retained value. A writer that held the value as its
current value replaced it knowingly, or the record still holds it, so nothing of it is lost. A set-less entry can't
show equality (it has no base entries) and so warns unless its stamp is in `S(M)` or is the previous version
(MiMo r7 I-3 (d), pinned).

### 1.2 Where a discarded value lives

| | Representation | 0.3.2 reading it | Trade-off |
|---|---|---|---|
| S1 | a third value section, role 2 | **refuses the record** ("at most 2", codec `:828-829`) | the natural layout, but every machine on 0.3.2 loses access to that secret until it upgrades: fails the anti-goal |
| S2 | a sibling file per discarded value (`records/<hash>.d<n>`) | ignores it (scanner: unknown names are ignored) | the sync provider sees conflicts happen; the scanner ignores unknown names (its OneDrive rule needs a hyphen, `TswapCore/Keyring/RecordDirectoryScanner.cs:81-82`), so every reader, 0.3.x included, would need new code to find, move or delete them with their record; separate life cycle, separate guard, separate rollback check (round 5 amendment 11) |
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
supersededCount   1   0..64, then that many stamps, ascending (S: rotation-derived, for the bound only; round 7)
retiredCount      1   0..64, then that many version stamps, ascending (T: dropped by a person; round 6, 7)
forgotten         28  the largest stamp ever pushed out of T by its cap (Stamp.Zero: none; round 7 amendment 2)
discardedCount    1   0..255 decoded; 64 is a write cap (T60 R6), then per entry, ascending by stamp:
  version         28  the discarded value's version stamp (its origin is the machine that wrote it)
  flags           1   bit value 0x01 burned; every other bit zero (T60 R4; the kind byte is gone, round 8)
  ackCount        1   0..8, then per acknowledgement, ascending by stamp:
    stamp         28  the acknowledgement's own stamp (its origin is the machine that acknowledged)
    byLength      1   0..255 UTF-8 bytes, then the --by label (T60 R5)
  [burned]        28 stamp of that version's earliest burn, then reasonLength 2 (0xFFFF none) + UTF-8 reason;
                      present if and only if the burned flag is set (round 6, M-8)
  hasFingerprints 1   then variantSetVersion 1, entryCount 1, entries as the codec stores them (0 until a value
                      write or reindex fills it, or when the section can't be decrypted: the record is then "not fully
                      fingerprinted", round 2 amendment 2, round 5 amendment 10)
  sectionLength   4   then the value section: nonce 12 | tag 16 | ciphertext, exactly as format 3 stores it; 0 only
                      in memory for a format 2 copy's value not sealed yet (T60 R1: a file with 0 is unreadable)
```

- **Decode** is strict for format 1 (lengths, ascending order, no duplicate stamps, zero reserved bits, a section of
  at least 28 bytes). A malformed format 1 extension makes **that record** unreadable, like a damaged `Fields`
  extension (`RecordMerge.cs:332-340`): fail closed, because a reader that can't see the discarded list can't tell
  whether a value is missing. A **newer** format byte (T60 R8, round 8 model 6): the record stays readable; its
  merge uses the whole-list rule for `0x0103` (as for an unknown type), sets nothing aside, and warns once per record
  per command: `Warning: record <file> carries value lineage written by a newer tswap; this one keeps it as it is but
  can't keep or show values a merge sets aside for that secret. Upgrade tswap.` A write that would have to update the
  lineage (a value write, `delete`, `--ack`, `--clear`, `restore --discarded`) is refused, the fail-closed choice:
  `Refused: record <file> of '<name>' carries value lineage written by a newer tswap, and this change would have to
  update it. Upgrade tswap on this machine. Nothing was written.` `burn` and field writes, which don't touch it, keep
  it byte for byte. An all-zero lineage is not written (T60 R7).
- **Burns of a discarded version** are copied into its entry because the record's burn list is bounded to 16 and
  keeps the outstanding burn plus the most recent others (`RecordMerge.cs:32-48`): a discarded version's burn could
  otherwise fall out of the list, and 0.3.2 trims by the same rule.
- There is **no kind byte** (round 8 model 7). What `{{name:discarded}}` gives is decided from the value (§1.10).

### 1.4 The merge rule, in both paths

`RecordMerge` gets one more special case beside `Fields` in `MergeExtensions` (`RecordMerge.cs:315-346`), used by
`MergeAll` and `MergeAllMetadata` alike, with a parity test like the existing one:

1. `S` = every copy's superseded set and previous version, minus `R`; kept to the 64 newest by stamp. `T` = the
   union of every copy's retired list, then the 64 newest (round 6 amendment 1, round 7). A merge
   **writes only explicit marks into `T`**: it never moves
   a stamp from `S`, a previous version or anywhere else into `T` (round 2 amendment 1). `forgotten` = the largest of
   every copy's `forgotten` and every stamp the cap pushes out of `T` here. A retired stamp that falls out of the cap
   lets a stale copy's entry come back, **open** (§1.4a's display rule for stamps at or below `forgotten`): a warning,
   the value kept, the safe side (round 7 amendment 2).
2. Discarded per §1.1. Per discarded stamp, over every copy that holds it (as its current value, its previous value
   or an entry; round 3 amendment 5):
   - the copies must agree, shown **on both paths** by equal section bytes or equal base fingerprint entries, as the
     metadata path does for retained versions (`:243-258`; round 6 amendment 5: entries are never decrypted to merge,
     §1.5). Sealed metadata can't be forged without `K_v`, and a set is checked against its value whenever an entry is
     decrypted (§1.5). A disagreement, or differing sections where either side has no set, is a
     `RecordConflictException`: the record is unreadable until the damaged copy is removed (today's rule for retained
     versions, applied to the values this design now keeps; round 3 amendment 6);
   - section: the ordinally smallest (`:151-153`); fingerprints: joined as `JoinGroup` does (`:378-388`);
   - acknowledgements: the union by stamp, the 8 newest (round 6 amendment 2); past 8 the oldest drop, which can
     leave an entry open again: the safe direction (round 7, M-5). An entry created from a candidate starts with
     none (only entries carry acknowledgements; round 8, MiMo M-3);
   - burned with the earliest burn found in any copy's burn list or entry;
   - a format 2 copy's value set aside on the full path has no section yet: in memory its entry holds the plaintext by
     reference (`SecretRecord.UnsealedDiscards`), and `WriteAll` seals it (T60 R1). A format 2 holding is compared by
     plaintext with holdings whose plaintext is in hand; against an entry it is a holding without a set (T60 R2).
3. `asOf` and `exactFrom`: the winner's, unchanged, when the winner has the extension; `Stamp.Zero` for both when
   it has none. Copies tied at the winning version (`RecordMerge.cs:119-120` takes `tied[0]`) are taken as a set: the
   lineage is exact if any tied copy's is exact at `W.Version`, and `exactFrom` is the smallest (round 8, Claude 2). **A merge never refreshes `asOf`** (amendment 3): only a value write or delete by this release does
   (§1.5). So exactness is decided at each merge from the winner alone: exact iff the winner has the extension
   **and** `asOf == W.Version`. "Has the extension" is not enough: 0.3.x keeps the extension byte for byte on its own
   value writes (`RecordWrites.NewVersion`, `TswapCore/Keyring/RecordWrites.cs:93` through `FieldEdits.ForWrite`; v0.3.0
   `RecordWrites.cs:76-77`), which leaves it present
   with a stale `asOf`; treating that as exact would set `B` to zero and report every stale copy as a conflict.
4. The extension is written whenever this release writes the record (round 5 amendment 4: a clear on a first-value
   record leaves only `T`, and leaving the extension out would lose it), except an all-zero lineage, which is not
   written (T60 R7, which replaces round 6 amendment 6: such an extension is exactly "none"). A newer-format lineage
   is kept or refused per §1.3. Whenever `T` or the
   entries are non-empty the record is written in format 3, whatever the folder writes; `S` alone doesn't force it
   (round 7 amendment 3), so a record with only a lineage in a folder that writes format 2 (one with 0.1 machines) is
   written in format 2, drops the extension and falls back to D2 until a format 3 write. `S` and `T` are capped at
   the 64 newest stamps on writes as on merges.
5. A tombstone winner keeps the extension (unlike `Fields`): its lineage stops a stale copy's value from being
   reported as discarded, and (owner decision 1) its discarded entries.

Properties (tested; round 8, Claude I-1): **the all-at-once merge is permutation-invariant** (the same copies in any
order give the same bytes); **it is idempotent** (merging a result again with any of its inputs changes nothing);
**a pairwise order's entries are a superset of the all-at-once entries**; and **copies converge by union** once every
result has met. An entry leaves only through a retirement, a person's action. The superset, and with it "no order loses
an entry", hold **while no cap (`S`, `T`) is reached at any step and every winner along the way has an exact lineage
with `exactFrom` zero** (MiMo r7 M-1); §1.4a proves them. The extra pairwise entries are silent when their stamp is in
`S(M)` or is the previous value (§1.1's silence rule).

**Bounds.** A merge never trims discarded entries (as a merge never trims fields, fields spec Merge rule 7). More
than 64 entries, or more than **64 KiB** of encoded entries (the `Fields` extension's cap, fields spec "Storage";
round 5 amendment 8), are not stored, but the record stays **readable** (the merged state holds them in memory); only
a write that would store more is refused: `Refused: 'x' holds more values a merge set aside than a record can store
(64, or 64 KiB).`. `burn` is exempt (round 8, MiMo M-8): it never grows the list, so it stores what a fold grew,
up to the codec's 255 entries and the 64 KiB; past those it is refused too, an accepted consequence. An entry takes at least about 400 bytes (stamps, flags, a fingerprint set of four entries and a
section of one 256-byte bucket) and grows with its value's padded size, so 64 small entries are about 26 KB (round 6, M-6: the one figure) and a
handful of 4 KB values reach the byte cap first; every `names` decrypts them with the metadata. The cap text goes on: `Drop some first with 'sudo tswap conflicts --clear x' (on a rolled-back record, accept it first). Nothing was
written.` A write command whose fold of conflicted copies would exceed either cap is refused the same way, once per
command; the copies are kept and the record stays readable. `conflicts --clear` and `restore --discarded` are never
refused by the cap, since they shrink the list (round 2 amendment 3, point 5); like every write they are still
refused on a rolled-back record (§2.5) (round 3 amendment 7). It takes 64
concurrent rotations of one secret; reaching the cap refuses a write and never drops a value. The 64-stamp lineage cap
only drops the oldest stamps; the effect is that a copy more than 64 rotations stale can be reported as a conflict,
or, depending on the order its copies merge in, dropped (§1.4a, round 7 amendment 1).

### 1.4a The invariant (round 6 amendment 1)

**The merge.** For inputs `I` with winner `W` (the largest version over all of them), the merged record `M` has:

- `T(M)` = the union of every input's `T` (the 64 newest); `forgotten(M)` = the largest of every input's `forgotten`
  and every stamp the cap pushes out (round 7 amendment 2);
- `Entries(M)` = (every input's entries ∪ `C(I)`) minus the stamps in `T(M)`, where `C(I)` = every input's current
  value version `V` with `V > B(W)` and `V ∉ R(W) ∪ S(I) ∪ T(M)`;
- per entry: acknowledgements a union by stamp, the burn the earliest, the section the ordinally smallest, the set
  joined (§1.4 rule 2);
- `S(M)` = the union of every input's `S` and previous version, minus `R(M)`; `asOf` and `exactFrom` from `W`.

**Invariant** (reworded, round 8, Claude 1 and I-1). `T`, `forgotten` and every per-entry quantity are a union, a
maximum or a minimum over the inputs; `S(M)` is a union minus `R(M)`; an entry survives a merge exactly when no input
retires its stamp, and a new entry is created from the step's own `R`, `S` and `B`, which is why pairwise orders can
hold more (claim 3). Display (open or acknowledged, open on the
writer's machine, open at or below `forgotten`, same value as a retained one) is computed from the merged record and
never changes it. `forgotten` is order-independent: a stamp pushed out of the 64 newest of a union at any step has
64 larger stamps there, so it is outside the final 64 newest too, and the maximum of everything outside is the same
in every order.

**Precondition** of claims 1, 3 and 4 (round 7 amendment 1): **no cap is reached at any step**: at most 64 stamps in
`S` and in `T` in every intermediate merge. Past it, claim 1 fails for a stamp pushed out of `T` (an entry can come
back, shown open), and claim 3 fails for a stamp pushed out of `S` (MiMo's counterexample: a value more than 64
rotations stale is kept at once but can be dropped in a pairwise order, because an early step's `S` still holds it).

**Claims, with proofs.**

1. *Removal is order-independent* (no cap reached). An entry is removed by exactly one rule, its stamp in `T`, and
   `T` only grows by union. If any input retires stamp `e`, every merge order ends with `e ∈ T`, so no order ends with
   entry `e`; if none does, no step removes `e`. The exception past the cap: 64 later retirements on the same record
   can push `e` out of `T`, and a stale copy's entry `e` then comes back, shown open.
2. *Existing entries survive.* No rule other than claim 1's removes an entry: not `R` (an entry whose stamp is the
   winner's previous version stays, "demotion"), not `S`, not the bound, not equality. So an entry any input holds,
   with a stamp no input retires, is in the result of every order.
3. *Creation: pairwise keeps at least the all-at-once entries* (no cap reached) when every winner along the way has an exact lineage
   with `exactFrom` zero (so `B` = 0 at every step). Suppose the all-at-once merge creates `V`: `V` is input `Iₖ`'s
   current value and `V ∉ R(W) ∪ S(I) ∪ T`. In a pairwise order, take the step that first merges `Iₖ` (or a record
   carrying `Iₖ`'s current value). At that step `T_step ⊆ T` and `S_step ⊆ S(I) ∪ R(W)` (both are unions over a subset
   of the inputs; `S(I)` holds every input's previous version except those in `R(W)`, and `V ∉ R(W)`), so `V` is
   excluded only if it is that step's winner or its previous. Its previous is an input's previous, so in `S(I) ∪ R(W)`:
   excluded at once too, a contradiction. If `V`
   wins the step, it is carried as the current value and the argument repeats at the step where it loses; it loses
   somewhere, since `W` ≠ `V` (else the all-at-once merge wouldn't set it aside). So `V` is created in the pairwise
   order too, and claim 2 keeps it to the end. A pairwise order can create **more**: a step can set a value aside
   before a third copy that knowingly superseded it (its `S` or previous) is merged; that is a kept value and a
   warning, never a loss. With an inexact winner at some step, that step's `B` can be above the final one, and a
   pairwise order can then miss what D2 misses (§1.1's documented miss, the same domain).
4. *All at once, and convergence* (no cap reached). The all-at-once merge is a function of the multiset of inputs, so
   permuting them gives the same bytes; merging its result with any input again adds nothing (the same `R`, `S`, `B`
   exclude the same candidates). Pairwise results differ from it only by claim 3's extra entries, and merging all the
   results converges by union. Every per-entry quantity is a union, maximum or minimum, so the bytes agree, except which of two ciphertexts of one plaintext an entry keeps
   when format 2 copies were converted on different machines (a value section is otherwise sealed once and copied,
   ruling 1).

**Worked through: MiMo's round 5 C-1 shapes.** `X` = current `c`, previous `a`, `S` = {`v0`, `b`}, entry `a` (the
demotion shape, `a ∈ R`); `X'` = current `d`, previous `b`, `S` ∋ `a`, entry `a` (the `S ∋ a` shape); `Y` = A's copy,
current `a`, written after a burn; `Z` = a copy where a person ran `--clear`: `T` = {`a`}, no entry.

| Inputs | Order | Result |
|---|---|---|
| `X`, `Y`, `Z` | all at once | `a ∈ T`: no entry `a`, and `Y`'s `a` is no candidate |
| `X`, `Y`, `Z` | (`X`,`Y`),`Z` · (`Y`,`X`),`Z` · (`X`,`Z`),`Y` · (`Z`,`X`),`Y` · (`Y`,`Z`),`X` · (`Z`,`Y`),`X` | the same: whichever step meets `Z` removes the entry, and every later step has `a ∈ T`, so `Y` is never a candidate; identical bytes |
| `X'`, `Y`, `Z` | all at once and the six orders | the same: no entry `a`; identical bytes |
| `X`, `Y` (no clear) | all at once and both orders | entry `a` kept (claim 2: demotion doesn't remove it; `Y`'s `a` is in `R` and isn't created twice) |
| `X'`, `Y` (no clear) | all at once and both orders | entry `a` kept (`S` never removes an entry) |
| past the `S` cap (MiMo r6): A rotated 65 times from `x` (its `S` still holds `x`), B rotated 64 more after syncing A (its `S` doesn't), H frozen at `x` | all at once; ((A, H), B) | all at once: entry `x` (as the "copy 65 behind" row); ((A, H), B): no entry, the first step's `S` excluded `x`. The precondition is not met: the documented order-dependent miss |

**Worked through: GLM's round 2 C-1 shapes.** A rotates to `a` offline; B rotates to `c`, folds A's copy (entry `a`);
C syncs with B (C may acknowledge `a`); then B runs `--clear` (`T` ∋ `a`) or `delete` (a tombstone that retires `a`
and puts `c` and `v0` in `S`).

| Inputs | Order | Result |
|---|---|---|
| A, B, C, clear | all at once and all six pairwise orders, with or without C's acknowledgement | no entry `a` (it is retired); current `c`; identical bytes |
| A, B, C, delete | the same | a tombstone with no entry; `c` excluded by `S`, `a` retired; identical bytes |
| A's current `a` against B's entry acknowledged on B | either order | entry kept, acknowledged; on A's machine shown open until A acknowledges (display) |
| (A, B) with the entry open, then C's stale copy acknowledged on C | all orders | acknowledged (the union holds C's acknowledgement); on A's machine shown open (display) |
| A burned `x` before its copy merged, with the clear | all orders | no entry: the dropped behaviour (round 6 amendment 1) |
| A deletes; B rotates concurrently and the delete never saw B's value | all orders | B's value an entry on the tombstone (owner decision 1): the delete retired only what it saw |

**Part 2 follows.** The floor holds only persisted entries (round 8 model 1), and every persisted entry is in some
input of every later merge, so claim 2 covers it. R4 accepts a gone entry when its stamp is in `M`'s `T`: by claim 1 that means a person dropped
that value, and by claim 1 again no merge can bring an entry with that stamp back while no cap is reached, so pruning
it from the floor (§2.3) can't hide a later loss. Past the `T` cap an entry can come back; it is then shown open at or
below `forgotten`, so the §1.8 warning shows, though R4 (which looks for gone entries) has nothing to say (round 7
amendment 2). MiMo's C-2 sequence no longer arises: after the clear, A's later copy is not a
candidate, so there is no re-formed entry to lose.

Every row is a test row (Tests, T60 "§1.4a orders").

### 1.5 Writes

`RecordWrites` and `NextRecord`/`PrepareV3` in step (parity test):

| Write | Lineage | Discarded entries |
|---|---|---|
| a new value version (`create`, `ingest`, `add`, `rotate`, `ingest --rotate`, `import`, `restore`) | the dropped old previous version joins `S`; `asOf` = the new version. If the lineage was not exact (`asOf` ≠ the old version), `exactFrom` = the old previous version, or the old version when there was none, or `Stamp.Zero` with no old version at all (round 8, Claude 11); `T` and `forgotten` unchanged | unchanged |
| a new life over a tombstone | the tombstone's `S`, `T`, `forgotten` and entries are kept (round 8 model 3: a deleted value never comes back through a stale copy); its entries are now **earlier-life** entries (§1.10); `asOf` = the new version; `exactFrom` = the tombstone's version when its lineage wasn't exact | kept (owner decision 1) |
| `burn`, `field set`/`unset` | unchanged (`T` and `forgotten` with them) | unchanged |
| every write | carries `T` and `forgotten` unchanged unless it is a person's action that adds to `T`; a write that caps `T` raises `forgotten` exactly as a merge does (MiMo r7 M-2) | |
| `delete` (sudo) | current and previous join `S`, each dropped entry's stamp joins `T` (only the entries it saw); `asOf` = the tombstone version; `exactFrom` as for a value write (unchanged when the lineage was exact, else the old previous version, or the old version) | **dropped**: `delete` prints `It also dropped 1 value set aside by a merge; it can no longer be restored.` |
| `conflicts --ack` (§1.8) | unchanged | an acknowledgement of the entry's stamp added |
| `conflicts --clear` (sudo) | each entry's stamp joins `T` | removed |
| `restore --discarded` (sudo) | a new value version as above, and the entry's stamp joins `T` | that entry removed; **its own** burn (the entry's burn copy) is issued again on the new version, not the previous value's: `RecordWrites.NewVersion`'s `Restored` path re-issues the burns of `state.PreviousVersion` (`RecordWrites.cs:87-88`) and gets a parameter naming the restored stamp (round 5 amendment 11, M-7) |

- **Entries are decrypted lazily** (round 5 amendment 5, I-4 option a): an entry's section is decrypted only when
  `{{x:discarded}}` resolves it, `restore --discarded` restores it, or a **value write** or `vault reindex` must fill
  its missing set or recompute an older one (as `WithMissingSets` does for retained versions,
  `RecordVaultStore.cs:965-1003`, and with `OpenValueSection`'s check of a set against the value it opens,
  `:1068-1078`). A full load (`export`, `vault merge`, `migrate`, a record with a format 2 file) decrypts **no** entry:
  it compares entries across copies by section bytes and base fingerprint entries, as the metadata path does, and a
  difference it can't settle fails closed (§1.4 rule 2). The only plaintext involved is a format 2 copy's current
  value, which today's whole decode already decrypts (`OpenFull`, `:640-641`) and which `ZeroValues` (`:1082-1090`)
  already zeroes; sealing it into an entry adds no new copy. `SecretEntry` (`TswapCore/SecretEntry.cs:135-148`) holds
  entries as sections only, and `PendingWrite` (`TswapCore/PendingWrite.cs`) carries the restored entry's stamp, so
  every decrypted entry value lives in exactly one place that `Dispose` zeroes. `Secret`/`ToSecret`
  (`:1105-1125`) gain only the entry count `export` needs for its warning.
- `burn`, field writes, `--ack` and `--clear` carry entries as they are, sets included or not; a set-less entry keeps
  the record "not fully fingerprinted" until a value write or `vault reindex` fills it (round 5 amendment 10, M-5). On
  a tombstone only `vault reindex` fills them (`WithMissingSets` returns early for tombstones, `:996-997`; round 5
  amendment 11, M-6).
- Any write of a record carrying entries or retirements (`T`) is written in **format 3** even in a folder that still
  writes format 2 (round 7 amendment 3: `S` alone doesn't force it), as a write with fields is (`RecordVaultStore.cs:919-923`, `CarriesEdits`); format 2 stores no extensions
  (`:2022-2029`).
- A write copies every entry's section byte for byte. The full path seals an entry that has no section (a format 2
  loser, whose plaintext the decode already holds) and fingerprints it from that plaintext, as `PrepareV3` does for
  retained versions (`:2056-2085`).
- `vault reindex` recomputes entries' missing and older variant sets as it does for retained values (decrypting
  those entries), and `IsCurrent` (`:1434-1451`) also requires current sets on entries. An entry whose set is current
  isn't decrypted. (Round 5's note on the kind byte after `reindex` is moot: the byte is gone, round 8 model 7.)
- A stored set is checked against its value whenever an entry is decrypted (`OpenValueSection`'s check), so a set
  can't hide a discarded value from redaction once it is used; one never decrypted is still in the index as stored.
- `docs/security-model.md`'s "What each command decrypts" rows gain: `export`, `vault merge`, `migrate`: no entry;
  `run` with `{{x:discarded}}`: that entry only; `restore --discarded`: that entry only; `vault reindex`: entries
  without a current set; value writes: entries of that record without a set; `conflicts` (every mode), `burn`, field
  writes: none (round 5 amendment 5).

### 1.6 Compatibility

| Who | What happens to a record with `ValueLineage` |
|---|---|
| 0.3.0-0.3.2 reading (`names`, `run`, `get`) | reads it as before; doesn't list, mask or substitute the discarded values |
| 0.3.x writing a value, burn or field | keeps the extension byte for byte (stale `asOf`: §1.1 falls back to D2 for that record) |
| 0.3.x deleting | keeps the extension in its tombstone, entries included; this release then treats them as kept on a tombstone (`tswap conflicts` shows "deleted") |
| 0.3.x merging (a conflict copy it folds) | keeps the whole extension list of the copy with the largest write stamp: it **can drop** entries this release would keep, drops losers as today, and **can drop `T`**, bringing back a value a person cleared or deleted (round 8 model 5: this release then warns, R4's "retired value back") |
| 0.3.x writing format 2 (a folder with 0.1 machines) | drops the whole extension, entries and `T` included; R4 warns for the entries |
| 0.2.x | as 0.3.0 for the extension |
| 0.1 (format 2 only) | can't read format 3 at all, as today; a vault with 0.1 machines writes format 2, except records with entries or retirements (written in format 3, as records with fields are); a record with neither written in format 2 loses its lineage and falls back to D2 until a format 3 write |
| 0.3.2 writing a value over a record with entries | keeps the extension byte for byte; the entries stay; this release then sees a stale `asOf` (pinned in Tests) |

`docs/multi-machine.md` "The merge rules" gains a "Mixed versions" paragraph like the fields one (`:482-489`): in a
folder shared with 0.3.x machines, a merge done there can still lose a value, a merge here can lose a value written
before the winner's previous version on a record whose lineage an older build wrote (§1.1), and a value another machine rotated
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
that clearing counts too).** `field adopt NAME FIELD --from SECRET` deletes SECRET (`FieldCommand.cs:309`), so it
refuses a SECRET that holds entries, as it refuses one with fields of its own (`:280-283`): `'<secret>' has <n>
value(s) a merge set aside; see 'tswap conflicts <secret>', then clear or restore them before adopting it.` (round 8,
Claude I-6). Acknowledging (§1.8) only quietens the warning. A merge never drops an entry, except
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
one machine c7cad1d5 wrote at …` (T60 R12 decides between the two from metadata). An entry whose stamp is the
previous version is silent (round 8 model 2; round 3 amendment 8's variant is gone). An earlier-life entry (§1.10)
reads `⚠ x: tswap kept a value machine 5d918462 wrote at … from before 'x' was deleted and created again. See 'tswap
conflicts x'.` (round 8, Claude I-5). With several entries, one line each. On a tombstone: `⚠ x: it was deleted while
machine 5d918462 changed its value (at …). tswap kept that value. See 'tswap conflicts x'.` `tswap` is `ctx.Prefix`.

Where:

| Command | What |
|---|---|
| a command that opens a named secret: `run` (each token's secret), `totp` (T58), `get`, `apply`, `rotate`, `ingest --rotate`, `restore`, `burn`, `delete`, `field set`/`unset`/`show` | the full warning for that secret |
| a command that reads all metadata: `names`, `burned`, `list`, `check`, `redact`, `tocomment` | one line: `⚠ 1 secret has a value a merge set aside: sync-conflict-test. See 'tswap conflicts'.` (names listed, up to 5, then `and N more`). Deleted secrets' open entries count too, named `x (deleted)` (round 5 amendment 11, M-12) |
| a merge that creates an entry (a fold on load, `vault merge`) | the full warning instead of the copy note for that record; the existing `Note:` (`RecordVaultStore.cs:1198-1201`) stays for copies that lost nothing, and gains the secret's name when the record was decrypted |
| `names` | ` [CONFLICT]` for a secret with an **open** entry (not an acknowledged one), after the date and T58's mark, before ` [BURNED]`; `names --json` gains `"conflict": true` (omitted when false, so today's JSON is unchanged) |

Acknowledged entries, and silent ones (§1.1), print nothing except in `tswap conflicts`. A fold that consumes a copy whose current value a person on another machine had
retired (B cleared `a`; A's copy still held `a`) shows **nothing** on A's machine, by the round 6 ruling: the value is
the one that person decided about (round 7, M-4). The warnings carry no value and no fingerprint.
`tswap prompt` (`TswapCore/Prompt.cs`, ASCII) tells agents: on this warning, tell the user what it says and that
`tswap conflicts` has the details; don't acknowledge, clear or restore it unless the user asks.

### 1.9 `tswap conflicts`

```
tswap conflicts [NAME] [--json]                         no sudo; metadata only, decrypts no value (every mode)
tswap conflicts --ack NAME [--stamp S] [--by LABEL]     no sudo (owner decision 2); a metadata-only write
sudo tswap conflicts --clear NAME [--stamp S]           sudo; drops the value(s)
```

Text output (no values; names are not secret and `names` prints them already):

```
sync-conflict-test
  current    2026-11-14T16:20:20Z  machine c7cad1d5
  discarded  2026-11-14T16:20:16Z  machine 5d918462 (this machine)  stamp 1794673216219.0@5d918462  (open)

1 open conflict.
  Use it once:  tswap run … '{{sync-conflict-test:discarded}}'
  Put it back:  sudo tswap restore sync-conflict-test --discarded
  Keep it, stop the warning:  tswap conflicts --ack sync-conflict-test
  Drop it:      sudo tswap conflicts --clear sync-conflict-test
```

- An entry without a fingerprint set shows ` [not fingerprinted]` (`conflicts` decrypts nothing, so it can't tell an
  unreadable section from one not fingerprinted yet; `--json` `"fingerprinted": false`); `--clear` works on it
  (round 4 amendment 6).
- `--ack` and `--clear` work on a tombstone too (round 5 amendment 11, M-12).
- `(same value as the current value)` (or `previous`) for an entry whose value the record retains (round 6
  amendment 3).
- The status goes at the end of each `discarded` line (T60 R10): `(open)`, `(open on this machine; acknowledged on
  machine c7cad1d5 at …)` (§1.4a, display), `(acknowledged 2026-11-15T09:12:00Z, machine c7cad1d5, by owner)`, `(from
  before 'x' was deleted)` for an earlier-life entry; the header line is the name, plus ` (deleted)` for a tombstone. A
  burned entry shows ` [BURNED 2026-11-15T09:12:00Z: <reason>]`
  with its burn's date and reason, as `burned` shows them (round 7, M-3); an entry at or below `forgotten` shows
  `(open: its retirement may have been forgotten)`.
- No conflicts: `No value conflicts.` (`No value conflicts for 'x'.` with a name; a missing name is `Secret 'x' not
  found`). Exit 0 in both cases; usage errors and refusals exit 1.
- `--json` (source-generated, `TswapCli/CliJson.cs`): `{"open": 1, "conflicts": [{"name": "…", "deleted": false,
  "current": {"stamp": "…", "machine": "c7cad1d5", "thisMachine": false, "time": "…Z"}, "discarded": [{"stamp": "…",
  "machine": "5d918462", "thisMachine": true, "time": "…Z", "earlierLife": false, "burned": false,
  "burn": null | {"time": "…Z", "reason": "…" | null},
  "open": true, "acknowledged": [{"time": "…Z", "machine": "…", "by": "…" | null}]}]}]}`, `"open"` as this machine
  shows it (§1.4a). `current` is null on a tombstone. Properties shown as `null` are marked
  `JsonIgnoreCondition.Never`, since `CliJsonContext` omits nulls (`CliJson.cs:33`; T60 R9).
- `--stamp S` takes the stamp as printed (`<ms>.<logical>@<8 hex>`) or in full (`<ms>.<logical>@<32 hex>`, as
  `--json` shows it) (round 6 amendment 4). It must match exactly one entry: two matches of the 8-hex form (two
  origins sharing 8 hex digits at one HLC) give `Two values of 'x' match the stamp S; give it in full, as 'tswap
  conflicts x --json' shows it.`, and none gives `No discarded value of 'x' has the stamp S; see 'tswap conflicts
  x'.` Without `--stamp`, `--ack` takes every
  open entry of NAME, and `--clear` every entry (amendment 6).
- `conflicts` in every mode decrypts no value: listing reads metadata only, and `--ack` and `--clear` copy sections
  and sets byte for byte, filling none (amendment 14, round 5 amendment 10).
- `--ack` stamps the acknowledgement like any write and records `--by` (at most 64 characters, the field rules for
  characters, fields spec "Fields", and at most 255 UTF-8 bytes: `--by: a label is at most 255 bytes in UTF-8.`, T60 R5). It works on a tombstone too, so a deleted secret's warning can be quietened.
  Output: `✓ Acknowledged 1 value of 'x' that a merge set aside. It is kept until 'sudo tswap
  conflicts --clear x' or 'sudo tswap restore x --discarded'.`
- `--clear`: `✓ Dropped 1 value of 'x' that a merge set aside, for good: a copy on another machine that still holds
  the same value doesn't bring it back. Only an older file put back from before this clear (a sync restore) can, as
  any rolled-back change can, or a stale copy after 64 later drops on this secret, or a merge done by an older tswap;
  in those cases tswap warns about it again.` (round 7 amendment 2, round 8 model 5) (round 6 amendment 8; the same sentence goes in `docs/multi-machine.md`.)

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

**Burning a discarded value** whose leak is found after the merge (round 5 amendment 9, M-4): `burn` marks the current
version only (`RecordWrites.cs:103-108`), as for `:previous` today, so the way is `sudo tswap restore x --discarded`,
`tswap burn x "<reason>"`, then `sudo tswap restore x` (the burned value becomes the previous one, its burn kept as
history). No new command; `docs/commands.md` gives the three lines.

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
- an **earlier-life** entry (round 8, Claude I-5): one whose stamp is below the current life's start, the `Fields`
  extension's `Since` (`RecordWrites.cs:93`; a record with no `Fields` extension, re-created by v0.3.0, can't tell and
  counts as current-life, documented). `{{x:discarded}}` refuses it, as on the tombstone it came from: `'{{x:discarded}}':
  the value 'x' kept from before it was deleted and created again can only be put back by the user: 'sudo tswap restore x
  --discarded'.` It counts towards "more than one" too;
- a burned entry gives `run`'s burned-value warning from the entry's own burn (T60, through `IsBurnedToken`); T61 adds
  the same warning for an entry this machine's floor (§2.3) saw burned (round 2 amendment 3, point 1). The value is
  masked as `[REDACTED: x:discarded]` like any token. `SecretsDb.IsBurnedToken` answers false for `:discarded`, and
  its `ResolveToken` refuses as below;
- **`:discarded` behaves exactly as `:previous`** in T58's `CommandValues`: it is passed to the inner lookup as `x:discarded`, exactly as `:previous` is
  passed as `x:previous`, and `CommandValues` then decides from the returned value as it does for `:previous`;
  nothing strips the suffix first (round 3 amendment 3); in `StoredForms` (a code-giving discarded otpauth token masks the stored value and T58 amendment 5's seed
  spellings), and in `ISecretLookup.IsBurnedToken` (`TswapCore/ISecretLookup.cs`; `VaultView.cs:171-175`)
  (amendment 4). `ISecretLookup`'s comment ("Both give the same answers", `ISecretLookup.cs:5-7`) is amended to say
  `SecretsDb` refuses `:discarded` (round 8, MiMo M-6). `SecretsDb.ResolveToken` (`TswapCore/Models.cs:283`, the whole-vault view of full loads) doesn't
  resolve it: `'{{x:discarded}}': values a merge set aside are read through 'tswap run' on a record vault only.`;
- T58's refusal for an unusable otpauth value names `sudo tswap get x`, which shows the current value; for
  `:discarded` it names `sudo tswap restore x --discarded` instead (round 5 amendment 11, M-13);
- an entry whose section can't be decrypted gives the record's unreadable text (`SecretsDb.UnreadableRecordText`,
  naming the hashed file) from `{{x:discarded}}` and from `restore --discarded`, and nothing is written (round 4
  amendment 6);
- the entry's bytes are decrypted once and zeroed as `VaultView.ResolveToken` does for other tokens
  (`VaultView.cs:218-221`); `restore --discarded` zeroes them after sealing them under the new version, as `restore`
  does today (amendment 14);
- the broker never serves discarded values: it reads secrets by name (`BrokerSecrets.Read`), never tokens (round 8,
  MiMo citation fix).

**An entry without a set, when used** (round 6 amendment 7): `{{x:discarded}}` and `restore --discarded` decrypt
the entry, so they compute its set there and add it to that command's matcher index before the child starts; a
child that prints the value is masked. `restore --discarded` writes the value as the new current version with that
set; `run` writes nothing, so the set is stored at the record's next value write or `vault reindex`.

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

`<config dir>/seen-records-<first 16 hex digits of the vault id, lower case>.json` (round 6, M-9:
`Convert.ToHexStringLower`, so a case-insensitive file system can't hold two), called `seen-records.json` below, written 0600
as the folder's owner through `DirectoryOwnerMatcher.WriteAtomic` (the way `config.json` is,
`RecordVaultStore.cs:234-245`), JSON through the source-generated context. The vault id is the keyring's (cleartext
in the folder's `keyring`). One file per vault (round 3 amendment 4): a config pointed at another vault finds no file
and starts a baseline, so no file ever holds another vault's state.

**Only this machine's own store** reads or writes the two files (round 5 amendment 2, I-1). A detached store
(`RecordVaultStore.ForFolder`, `RecordVaultStore.cs:98-103`, whose config folder is the vault folder it was given)
never reads or writes them: not for `init --vault-dir`, `slot accept --vault-dir`, `migrate --to-records`, `vault
merge`'s other copy, or `vault move`'s target. Floors and `seen-keyring` rise only from this store's own folder, as
loaded or as committed, so a `vault merge` that the stale-write guard refuses raises nothing beyond what this folder's
files already hold.

```json
{
  "Format": 1,
  "Records": {
    "<64 hex file name>": {
      "Write": "1794673220031.0@c7cad1d5…(32 hex)",
      "Version": "1794673220031.0@c7cad1d5…",
      "Burn": "…",
      "Deleted": true,
      "Discarded": [{ "Stamp": "…", "Burned": true }, { "Stamp": "…" }],
      "Retired": ["…"]
    }
  }
}
```

The **floor** of a record is `Write` (the largest write stamp seen), the **pair** `(Version, Deleted, Burn)` (the
largest version seen, whether it was a delete, T61 R-1, and the outstanding burn **of that version**, omitted when it
has none; one component, never split, round 3 amendment 1), `Discarded`: **every** entry seen **in an authenticated
file** (a main file or a conflicted copy as loaded, or as this machine commits it; never a fold's in-memory candidate,
round 8 model 1), open or acknowledged, each with a burned bit set once it was seen burned (amendment 2; omitted when
none), and `Retired`: every stamp this machine saw in a record's `T` in an authenticated file, never pruned (one stamp
per person's clear, restore or delete; round 8 model 5). A machine
whose first sight of an entry is already acknowledged still floors it. The acknowledgement itself is not floored: an
acknowledgement lost to a rollback only brings the warning back, the safe direction, so there is nothing for R4 to
check (round 2 amendment 3, point 4: "keep the ack if either side has it" has no field to apply to). At save time an
entry whose stamp the record retires and no longer holds moves from `Discarded` to `Retired` (round 2 amendment 9,
round 8 model 5). A record whose check is R3 (unreadable, its copies can't be merged) raises nothing, not even from
its copies (round 8, Claude 5). Stamps are written in full (`<ms>.<logical>@<32 hex>`), not the 8-hex display form.
`<config dir>/seen-keyring-<16 hex of the vault id>`, called `seen-keyring` below, is the keyring codec's bytes (`KeyringCodec.Encode`) of every slot this machine has seen,
written exactly as `seen-records.json` is: 0600, as the config folder's owner, through `WriteAtomic`, merged with
the file on disk (a union of slots) before writing (round 2 amendment 3, point 4). Its format is the codec's own,
versioned by the keyring's format byte.
Neither file holds a name, a value or a fingerprint. What `seen-records.json` adds to what a reader of the config
folder learns: which hashed records were burned or had conflicts, and when; an agent learns as much from `burned`
and `tswap conflicts`.

- **Updated** after any load that authenticated records (the full load, `LoadMetadata`, a single record's open for
  a read or a write) and after a commit, raising each floor component to what was seen. The pair: a seen version
  above the floor's replaces `(Version, Burn)` whole with the seen state's (which may have no burn: that is a new
  version, not a lowering); a seen version equal to the floor's keeps the **earliest** burn of that version
  seen, the floor's or the seen state's (round 4 amendment 4: it is the same fact `CanonicalBurns` keeps,
  `RecordMerge.cs:34-37`, so taking an earlier one is not a lowering); **never lowered**, except by
  `vault accept-rollback` (§2.6), and by `conflicts --clear` and `restore --discarded` run **on this machine**, which
  remove that entry's stamp from this machine's floor: a person decided, and without this a later 0.3.x merge that
  loses the lineage would make R4 report a deliberate drop (amendment 8). A record whose R1 or R2 check failed (§2.4) gets no raise; an R4 warning doesn't stop
  the raise (round 2 amendment 3, point 2). At most one file write per store
  operation, and only when something rose, so a command on an unchanged vault writes nothing.
- **R1 is checked again at save** for the records this operation writes, against the floor re-read then, before the
  record write: a rollback between another process's raise and this write is refused too (round 8, Claude 8).
- **No copy kept between operations** (round 5 amendment 3, I-2). A process (the broker included, which keeps one
  store for its whole life, `BrokerSecrets.cs:66-86`, `:112-128`) reads the file at the start of each store operation
  and, at save, **re-reads it** and applies only what this operation authenticated: per record, the raise rules above
  against the floor now on disk (`Write` the larger; the pair whole from the larger version, equal versions the
  earliest burn; the entry lists as a union by stamp, burned bits OR-ed). Nothing from an earlier read is written
  back, so a lowering on disk (`accept-rollback`, a clear's pruning in another process) wins over anything this
  operation does not itself raise. A process that authenticated the state from **before** an `accept-rollback` and
  saves after it raises the floor again, and the record is flagged again until it is accepted again: the safe
  direction (round 6, M-4). This is not
  `SaveConfig`'s rule (`RecordVaultStore.cs:195-201`), which takes the larger of memory and disk. A lost update
  between two processes can only leave a floor lower than it could be (less detection), never higher than a real state.
- These rules hold for **both** files (round 3 amendment 4). **Missing** file: the first load records a baseline and
  warns about nothing (the upgrade path, a new machine joining a folder, a config pointed at another vault).
  **Damaged** file (not JSON, `Format` other than 1, a stamp that doesn't parse, or a keyring blob the codec refuses;
  round 5 amendment 11, M-11): `Warning: … can't be read (…); this machine starts tracking record versions again from
  now.`, then a fresh baseline **(my call: a damaged local file is not a reason to block the vault; the threat model
  of #197 is the shared folder)**.
- A **missing** `seen-records.json` on a machine whose `config.json` has a `LastHlc` **and no `VaultId`** (a config last
  written before this release; T61 R-7) gives one `Notice: this machine starts tracking record versions for this vault now; a record that
  was rolled back before now can't be detected.` (round 5 amendment 11, M-10).
- Write failures (a read-only config folder) are one warning per command; detection keeps using what was last saved.
- The file is parsed by every command that opens a record and is pruned only of entries `accept-rollback` removes; at
  about 150 bytes per record that is fine for the hundreds of records a vault holds (round 5 amendment 11, M-13).
- **Format 2 records under `FormatTwoRecords.Skip`** (`RecordVaultStore.cs:1704-1710`, `:1725-1731`) are neither
  checked nor floored by the commands that read with `Skip` (`redact`, `tocomment`, `check`, which refuse on such a
  vault anyway); `names`, `list` and `burned` (`Decode`), `run` (a single record's open) and every write decode them
  and check them (round 5 amendment 11, M-8).
- Only authenticated stamps count, as for `LastHlc` (`RecordVaultStore.cs:1283-1284`).

### 2.4 What counts as a rollback

For a record whose merged state is `M` (main file plus usable copies, as §2.1 says) and whose floor is `F`:

| Rule | Condition | Meaning |
|---|---|---|
| R1 | `M.Write < F.Write`, or `M.Version < F.Version`, or `M.Version = F.Version` and `F.Burn` is set and `M` has no burn of that version (the pair makes `F.Burn` always a burn of `F.Version`) | the record went back: a delete undone, a burn gone, a value or field change lost |
| R2 | `F` exists and **no file** of the record exists at all, main or conflicted copy (T61 R-5: a file that can't be used is R3) | the record is gone: the secret vanished. Sound only because no tswap command removes a record's main file: `delete` writes a tombstone, and copy removal touches conflicted copies only (`RecordVaultStore.cs:315-337`). A future purge command must update `F` itself (amendment 13) |
| R3 | a file this machine can't read | **not** a rollback: today's unreadable-record rule applies (`RecordVaultStore.cs:1185-1188`) |
| R4 | a stamp in `F.Discarded` is neither an entry of `M`, nor in `M`'s **retired** list (round 2 amendment 1: `S` no longer explains a gone entry); or it is still an entry of `M` but not burned while `F` saw it burned; or **a stamp in `F.Retired` is an entry of `M`** again, whoever merged it (round 8 model 5). R4 ignores `forgotten` (T61 R-15), and a floor entry whose stamp left `T` by the cap before this machine saw it retired warns as gone (round 8, Claude 10) | a value a merge had set aside is gone, or its burn is (a 0.3.x merge dropped it, or the file went back). **Warning only**, no refusal: refusing can't bring it back. The burn text: `⚠ x: the value machine 5d918462 wrote at … (set aside by a merge) was burned when this machine last saw it; its burn is gone. It is still compromised.` |

A component check uses the version **and** the write stamp because each catches what the other can't: a rolled-back
field change keeps its version; a rolled-back delete that another (stale) machine then writes over has a newer write
stamp but an older version. The `Burn` component catches a burn removed while a stale machine's metadata write raised
the write stamp. A stale machine re-creating a deleted name with a **newer** version than the delete is
indistinguishable from a legitimate value after the delete: the merge rules accept it too (limit, documented). The
same holds for a clear (round 4 amendment 2): a file put back from before a `conflicts --clear`, then written over by
a stale machine, raises every stamp past the floor (whose entry was pruned at the clear), so the cleared value is back
as an entry with no rollback warning: the old file carries neither the retirement nor the clear's write. It comes back
as that file held it, open (the §1.8 warning shows) or acknowledged (silent). A documented limit of the same class as
the delete case: it needs the file itself rolled back, not merely a stale copy.

What a normal sync and the #312 rules produce, checked against the table (re-run with the round 3 pair):

| Situation | Result |
|---|---|
| another machine's write replaces the file | write stamp and version rise: no warning, floor raised |
| A burns `v10`; B rotates to `v12`; synced to A | the seen version is above the floor's: the pair becomes (`v12`, none); no warning, writes work (round 3 amendment 1) |
| A and B burn `v10` concurrently; the merge keeps B's earlier burn | equal versions, a burn of `v10` present: no warning |
| a sync conflict, the older file kept as main and the newer as a copy | the merged state carries the newer stamps: no warning |
| tswap removes a folded copy after writing it | the written main file carries everything: no warning |
| a merge sets this machine's own value aside (#312) | the merged version is the largest of the inputs, so it never goes down; the value is an entry: no warning |
| `conflicts --clear` or `restore --discarded` on another machine | the stamp is retired, which R4 accepts: no warning |
| `vault move`, a second config folder, a machine joining | same vault id, or a new baseline: no warning |
| Syncthing's "Revert Local Changes", OneDrive's or Dropbox's "restore previous version", a backup copied over the folder | R1 for each record that went back, R2 for records created since |
| someone deletes the newer conflicted copy before tswap folds it | R1 (or R2): correct, that change is lost |
| Syncthing deletes an old conflicted copy over its `maxConflicts` limit before tswap folds it | R1 when that copy held the newest state: correct, though Syncthing did it on its own. The newer state still exists on the machine that wrote it: merge from that machine's folder; `accept-rollback` instead gives that state up (round 2 amendment 6) |
| a machine with a clock far ahead writes, then its copy is lost | R1 shows a time in the future; the year-ahead warning (`RecordVaultStore.cs:1190-1192`) names the clock as well |
| a network share's client cache returns an old file | R1: a real problem on that machine (stale reads over SMB or NFS; `docs/multi-machine.md:512-515` describes the write side of the same caching) |

### 2.5 The warning, and the refusal on write

Reads go on, with a warning on stderr once per record per command **(owner rule: warnings, since a read loses
nothing)**:

```
⚠ Record 3f2a…c9 (secret 'db-pw') is older than the copy this machine saw on 2026-11-20T10:02:11Z: then its
version was from machine c7cad1d5 at 2026-11-20T10:02:11Z and it was deleted; now it holds a value from machine
5d918462 at 2026-11-14T16:20:16Z. A sync restore, a backup you restored, a stale copy or someone with access to the
vault folder replaced it. If a sync is in progress, wait for it to finish and run again (round 5 amendment 6). Changes
to it are refused until it is repaired: 'sudo tswap vault merge <a newer copy>', or keep this version
with 'sudo tswap vault accept-rollback db-pw'.
```

The first 4 and last 2 hex digits of the file name, as the warning shows it (full name in `--verbose`). The state
part names what changed, from the floor and the merged state: `it was deleted; now it holds a value`, `it was burned
on …; now the burn is gone`, `a change made at … is missing` (write stamp only). R2: `⚠ Record 3f2a…c9, which this
machine saw on …, is missing from the vault folder (its secret is gone).` with the same repair line and `--all`
(the name is unknown without the file). R4: `⚠ sync-conflict-test: a value a merge had set aside (machine 5d918462,
2026-11-14T16:20:16Z) is gone from its record; an older tswap's merge or a rolled-back file dropped it.` (round 8:
the import cause is removed, Claude 4). A retired value back: `⚠ x: the value machine 5d918462 wrote at … was dropped on
purpose (here or on another machine), but an older tswap's merge or a rolled-back file brought it back. Drop it again
with 'sudo tswap conflicts --clear x'.` Every R1, R2 and R4 text in full is in Appendix A (T61 R-13). Commands that
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
  satisfies R1 and that loss is no longer reported. The same goes for a rollback that removed the current version's
  burn: the agent's new burn of that version satisfies R1, and the original burn's time and reason (the incident
  record, #35) are gone without a report (round 8, Claude 7). A documented limit, and the one write the anti-goals
  carve out.
- **`vault merge`** still writes: it is the repair. After it, a record whose version or burn is still below its floor
  stays flagged; a rollback seen only in the write stamp is no longer reported once the merge (or any write of this
  machine) has written the record, as for `burn` (round 5 amendment 7, M-2).

**Elevation words** (round 8, MiMo M-5): every text here and in Appendix A that says `sudo tswap …` follows T58
amendment 8: on Windows `tswap …, from an elevated command prompt`; `tswap` is `ctx.Prefix`.

**Reads of a rolled-back record go on** (round 6, M-7): when the rollback brought back a **deleted** secret, `run`,
`get` and the broker still hand out its value, with the R1 warning on stderr. That follows the owner rule (warnings,
where nothing is lost); a reader expecting the value to be withheld should know it isn't.

**A transient R1 on a normal sync** (round 5 amendment 6, M-1): on a third machine whose floor a conflicted copy
raised, a transport that doesn't order files can deliver the copy's removal (`RecordVaultStore.cs:2034-2037`,
`:315-337`) before the new main file. R1 fires until the main file arrives; hence the "wait and run again" sentence,
as the unreadable-record text has (`:1185-1188`).

`delete` refuses too, although deleting a resurrected secret looks like the safe direction: a delete drops every
discarded entry (§1.5), and on a rolled-back record the entries it would drop may be what the rollback brought back
or hid. To delete a secret a rollback brought back, accept the current state first, then delete: `sudo tswap vault
accept-rollback x && sudo tswap delete x`. The refusal adds that line for `delete` (amendment 11).

A rolled-back record at the entry cap (§1.4) needs its repairs in one order (round 4 amendment 7): `vault merge` is
refused by the cap and `conflicts --clear` by the rollback, so first `sudo tswap vault accept-rollback x`, then
`sudo tswap conflicts --clear x`, then `sudo tswap vault merge <a newer copy>` if one exists. The cap refusal on a
rolled-back record prints that order.

### 2.6 Repair

1. **A newer copy exists** (another machine's folder, a backup, the sync tool's version folder such as
   Syncthing's `.stversions`): `sudo tswap vault merge <folder>`. The merge brings the newer state back by the
   merge rules, and the next load raises nothing and clears the warning. A folder needs its `keyring` and
   `records/`; with only single record files, put them in `records/` beside a copy of the current keyring.
2. **The current state is the wanted one** (a deliberate restore from backup): `sudo tswap vault accept-rollback
   NAME…`, `--file <64 hex>` or `--all`. A name addresses R1, R2 and R4 records (it is hashed to its file); an R2
   warning can't show the name, so `--file` takes the hash it prints (in full under `--verbose`); `--all` sweeps R1,
   R2 and R4 (round 3 amendment 10, round 4 amendment 5). Sudo, because accepting can bring back a deleted secret or drop a burn. It
   unlocks, reads metadata only, sets those floors to the current state and prints each change it accepts:
   `✓ Accepted the current version of 'db-pw' (it was deleted when this machine last saw it).` A name with nothing
   flagged prints `Nothing to accept for 'x': it isn't older than this machine saw.` and exits 0 (round 5 amendment
   11, M-11). R2 entries are
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
  unlocker's message (`VaultUnlocker.cs:1341-1343`, `:1198`) changes in **every** case, since "Config is corrupted …
  Restore config.json … re-run 'tswap init'" is wrong advice whenever the keyring file is what changed (round 5
  amendment 11, M-9). Without a `seen-keyring` holding the slot: `This machine's slot 3f2a9c1b is missing from the
  keyring in <vault folder>. The keyring file may have been replaced by an older copy; config.json is fine. Copy the
  current keyring from another machine or a backup into the vault folder.` When `seen-keyring` holds it: `This
  machine's slot 3f2a9c1b is missing from the keyring in <vault folder>, though this machine saw it there before:
  the keyring file was replaced by an older copy. config.json is fine. Put the slot back with 'sudo tswap vault
  restore-slots'.` When the slot is there but its unwrap fails and `seen-keyring` holds a slot of that id with other
  bytes (round 7 amendment 4; `VaultUnlocker` finds its own slot by id, `VaultUnlocker.cs:1139-1155`): `This
  machine's slot 3f2a9c1b in the keyring in <vault folder> differs from the one this machine saw: the keyring was
  damaged or tampered with. config.json is fine. Move <vault folder>/keyring aside, copy <config dir>/seen-keyring-<id>
  in its place, and compare the two.` (`restore-slots` can't repair it: slots never change, so it skips a differing
  same-id slot.)
- **`config.json` gains `VaultId`** (round 6, M-3), a machine field, written where T61 R-8 says (`SaveConfig` of a
  non-detached store, and `migrate --to-records`). It serves the upgrade notice (T61 R-7). The `restore-slots` refusal
  it once fed is dropped (round 8 model 8).
- **`Config.KeyringFolder`** (T61 R-11), not serialised, carries the vault folder, the `seen-keyring` path and the
  seen copy from `LoadConfig` to `VaultUnlocker`, so every unlock path (CLI, agent, broker) gets the own-slot texts.
  The slot-kind words are computed in Core (T61 R-10).
- **`KeyringSlotId` null** (round 8, Claude 13): `FindOwnMachineSlot` then takes the first machine slot
  (`VaultUnlocker.cs:1141-1142`; `migrate` from a plain XOR vault writes it null, `RecordMigration.cs:140`). A lost own
  slot then shows as an unwrap failure against another machine's slot, not the own-slot texts; `restore-slots` still
  works, since it adds every missing slot. The "differs" instruction adds: `Then run 'sudo tswap vault restore-slots' on
  each other machine, so slots added since this machine last read the keyring come back too.`
- **`sudo tswap vault restore-slots [--yes]`** (new): reads `seen-keyring` of the vault id in the folder's keyring
  (so another vault's file is never read, round 3 amendment 4), and adds every slot it holds that the folder's keyring
  lacks **by id**; a same-id slot with other bytes is skipped with the "differs" warning below (round 3 amendment 9),
  and when the skipped slot is this machine's own it prints the "differs" unlock text's instruction (round 7
  amendment 4).
  It writes through `WriteKeyring`'s union, which then meets no differing same-id slot. With no file for that vault
  id: `This machine has no record of slots for vault <id>; nothing to put back.` With **no** `keyring` file in the
  folder there is no vault id to read: it refuses with today's text (`The vault folder … has no keyring file …`,
  `RecordVaultStore.cs:257-260`), adding `This machine kept a copy of every slot it saw: <config dir>/seen-keyring-<id>.
  It is a complete keyring; to put it back, copy it to <vault folder>/keyring.` for each such file (round 4
  amendment 3). Nothing is written. It needs **no unlock** (a union needs no `K_v`) and so works for
  the own-slot case. It shows each slot's fingerprint (as `vault merge` does for new slots) and asks on a terminal,
  or takes `--yes`; with input redirected and no `--yes` it refuses as `vault merge` does
  (`TswapCli/Commands/VaultCommand.cs:95-101`; round 5 amendment 11, M-11). Sudo because it adds ways into the vault.
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
- M-12: `burned` lists the record's burn list only, so it stops listing a discarded version's burn once that burn has
  left the list; the entry keeps its own copy, which `tswap conflicts` shows as ` [BURNED]` (round 5 amendment 11).

### 2.9 Security model

`docs/security-model.md` gains a "Rolled-back files" section: what is detected (§2.4), on which machines (those that
saw the newer state), what isn't (a vault that was already rolled back before a machine first saw it; a stale
machine's newer re-creation of a deleted name; a process running as the vault's user that edits the config folder
too; a `seen-records.json` or `seen-keyring` lost, damaged or restored from a backup, which starts a fresh or older baseline without a
warning that can tell it from a new machine), and that `seen-records.json` reveals hashed record names with burn and conflict times to whoever can read the
config folder. It also says (round 6 amendment 9): `seen-keyring-*` is a complete copy of this vault's keyring in the
config folder (0600, owner only), so a backup of the config folder now contains the vault's wrapped key material;
`docs/setup.md`'s backup guidance gains the same sentence.

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
| a record exact since this release's first write over an inexact lineage (`v5`, previous `v4`, `exactFrom` = `v4`); a concurrent value older than `v4` | no entry: the `exactFrom` miss, pinned (round 4 amendment 1) |
| a discarded version burned, then 16 more burns of later versions push its burn out of the record's burn list | the entry keeps its burn; `{{x:discarded}}` gives the burned warning |
| A, B, C rotate from `v0` | two entries; all 6 input orders and every pairwise order give equal bytes |
| a result merged again with each input | byte-identical |
| an entry acknowledged in one copy, open in another | acknowledged; both acknowledgements kept |
| **§1.4a orders**: every row of §1.4a's two tables (MiMo's `X`/`X'`/`Y`/`Z` shapes and GLM's A/B/C shapes), each of the six pairwise orders and all at once, through both merge paths | byte-identical results per row as the tables say |
| an entry in one copy, its stamp in another copy's retired list (cleared there) | no entry |
| an entry `a` in one copy, `a` another copy's **previous** version (step 6 of MiMo's C1 sequence) | entry `a` kept |
| an entry whose stamp is the winner's previous version | kept, silent (round 8 model 2) |
| A and B rotate to the same value | an entry; no warning, no `[CONFLICT]`; `conflicts` shows "same value as the current value" |
| an entry, then the winner rotates to the entry's value again (M-1) | the entry kept, silent |
| an entry cleared on B; A's copy still holds it as its current value | no entry (retired) |
| the same, A's copy written again (a burn) before it merged | no entry (the dropped behaviour) |
| an entry burned on a copy that still holds the value as its current value, merged later | the entry burned (earliest burn) |
| an entry and the winner's previous at one stamp with different sections and base fingerprints | `RecordConflictException` (round 3 amendment 5) |
| two copies' entries of one stamp, differing sections, one without a set (metadata path) | `RecordConflictException` (round 3 amendment 6) |
| a candidate without a set on the metadata path | an entry; the vault "not fully fingerprinted" for that command; the next write fills the set from the section |
| two copies' entries of one stamp with different sections and base fingerprints (both paths, no entry decrypted) | `RecordConflictException` |
| two copies' entries of one stamp, different sections, equal base fingerprints | merged; the smaller section kept |
| A deletes after seeing `v1`; B holds `v1` | tombstone, no entry |
| A deletes; B rotates concurrently; delete later | tombstone with B's value as an entry (owner decision 1) |
| A and B create the same name | one entry |
| 65 rotations on one machine, then a merge with a copy 65 behind | that copy's value is an entry (the cap's documented effect, an accepted exception in the anti-goals) |
| MiMo's r6 three-copy construction past the `S` cap (A 65 rotations from `x`, B 64 more, H frozen at `x`): all at once, and ((A, H), B) | all at once: entry `x`; ((A, H), B): no entry. Pins the documented order-dependent miss (round 7 amendment 1) |
| the same with 63 and 62 rotations (under the cap): all at once and both orders | entry `x` in every order |
| 65 retirements on one record, then a stale copy whose entry of the first retired stamp is acknowledged | the entry back, shown open at or below `forgotten`, the §1.8 warning shown (round 7 amendment 2) |
| `forgotten` after the same 65 retirements merged pairwise in every order and all at once | equal |
| a silent same-value entry, then two rotations of the current value | still silent: its stamp is in `S(M)` (round 8 model 2) |
| a set-less entry whose value equals the current value, its stamp neither in `S` nor the previous | warns: equality needs base entries (MiMo r7 I-3 (d)) |
| Claude r7 I-1's (A, B, C) shape merged ((A, B), C) and all at once | ((A, B), C) holds `a` and `b`; all at once `b` only; `a` silent (its stamp is `C`'s previous) |
| a 0.3.2-shaped tombstone (no lineage) over `v5`; `vault merge` of a backup holding `v5` | `v5` an entry on the tombstone, warned (round 8, Claude I-3) |
| delete (`T` ∋ `a`), `create x` again, a stale copy holding entry `a`, then `{{x:discarded}}` | no entry `a`: `T` carried by the new life (round 8, Claude I-4) |
| an entry from before a delete and re-creation (earlier life) | `{{x:discarded}}` refused with the earlier-life text; `sudo restore --discarded` works; the warning names the earlier life (Claude I-5) |
| `sudo field adopt n f --from s` where `s` holds an entry | refused with the adopt text, nothing written (Claude I-6) |
| clear on B; C (never saw the clear) writes later; a 0.3.2-shaped fold keeps C's extension list; open and acknowledged variants (MiMo r7 I-3 (a)) | entry `a` back; on B R4's "retired value back" in both variants |
| a newer-format lineage on one copy, through both merge paths and through a rotate, a burn and a field set (MiMo r7 I-3 (b)) | merge: whole-list, nothing set aside, the warning once; rotate refused with the newer-lineage text; burn and field set keep it byte for byte |
| the 65th `--clear` on one record (a write capping `T`) | `forgotten` raised by the write (MiMo r7 I-3 (c)) |
| `burn` on a record holding 65 entries in memory | written (exempt from the entry cap, MiMo M-8) |
| an all-zero lineage after `burn` on a record with none | no extension written (T60 R7) |
| `--by` of 64 characters and more than 255 UTF-8 bytes | refused with the byte text (T60 R5) |
| 65 entries | the record readable; a write refused with the cap text; `conflicts --clear` and `restore --discarded` work |
| a malformed format 1 extension; a format 2 extension byte | record unreadable; kept as it is with one warning |

**Writes** (`RecordWritesTests`, both write paths):

| Write | Outcome |
|---|---|
| rotate a record with an entry | entry kept; dropped old previous in the lineage; `asOf` = new version |
| rotate a 0.3.2-written record | extension created, `exactFrom` = old previous |
| `burn` (and `field set`) over a record with no extension | extension created, `asOf` zero; a merge with a stale copy uses the D2 bound as before (round 6 amendment 6) |
| `burn` over an inexact record (stale `asOf`) | `asOf` unchanged |
| `--clear` in a folder that writes format 2 | written in format 3: `T` kept (M-2) |
| a rotation in a folder that writes format 2, the record with only `S` (no entries, no `T`) | written in format 2, extension dropped; the next merge uses the D2 bound (round 7 amendment 3) |
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
| a discarded otpauth value (T58's SHA1 URI, fixed time 1111111111.5 s): `{{t:discarded}}` | child gets `050471`; the URI and seed are in neither argv nor output |
| `{{t:discarded:totp}}` | T58's unknown-suffix text |
| the child prints the discarded seed in each spelling T58 amendment 5 lists | each masked as `[REDACTED: t:discarded]`; a hex key line stays unmasked, as T58 pins |
| a discarded bare Base32 value, `{{t:discarded}}` | the stored text, as `{{t}}` gives for a bare value (pinned parity) |
| `{{x:discarded}}` reaching `SecretsDb.ResolveToken` | its refusal text |
| A and B rotate from `v0`; B folds and shows the warning; **A rotates again before its folder merges**; B rotates; full sync | both A's values kept as entries on both machines; R4 silent; `tswap conflicts` lists two entries |
| `{{x:discarded}}` on a tombstone holding an entry | the tombstone text |
| B clears `a`; A, never merged, still has `a` current; full sync | `a` gone on every machine, no warning; `T` keeps `a` |
| the same, but A burned `x` before syncing | `a` gone too (the dropped behaviour) |
| A, B, C: `a` set aside; C acknowledges it; B clears it; A unchanged; full sync, in each machine order | `a` gone everywhere, the same files on every machine |
| A's current `a` against B's entry acknowledged on B | `conflicts` on A: `(open on this machine; acknowledged on machine <B> …)`, the warning shown on A; on B acknowledged |
| a clear on a first-value record (entries only, `S` empty), then a merge with a stale copy holding the entry | the entry stays cleared (round 5 amendment 4) |
| `restore --discarded` on a first-value record, then the same merge | no entry comes back |
| `restore --discarded` of a burned entry | the new version burned with the entry's own burn, not the previous value's (M-7) |
| `restore --discarded`, `burn`, `restore` | the discarded value burned and kept as the previous value (M-4) |
| `--clear` and `--ack` on a tombstone | both work |
| a record at 65 entries in memory: `burn`, `field set`, `rotate`, `--ack`, `--clear`, `restore --discarded` | `burn`, `field set`, `rotate`, `--ack` refused with the cap text; `--clear` and `restore --discarded` work |
| a record whose entries would pass 64 KiB | a write refused with the cap text |
| a 0.3.2 value write over a record with entries (the extension bytes untouched) | entries kept; a stale `asOf`; the next merge uses the D2 bound |
| `export` of a vault with entries | no entry decrypted (the `ValueDecrypted` seam); the warning names the secrets |
| a burned entry in `conflicts` and `--json` | ` [BURNED <date>: <reason>]`; `"burn"` with time and reason (round 7, M-3) |
| `conflicts` text of a secret with one open and one acknowledged entry | the status at the end of each line; the header the name only (T60 R10) |
| B clears `a`; A's copy, still holding `a` current, folds on A | nothing shown on A (round 7, M-4) |
| 9 acknowledgements of one entry | the oldest dropped; still acknowledged; with the 8 kept all from other machines, open on the writer's machine (round 7, M-5) |
| T58's `Rotate_DecryptsOnlyTheCurrentValue` on a record with entries | still exactly one value decrypted |
| `vault merge` and a full load of a record with entries | no entry decrypted |
| **absence sweep**: every new command (`conflicts` in each mode, `restore --discarded`, `accept-rollback`, `restore-slots`) and every new warning and refusal, run on a vault whose values are inert markers | no marker value, seed or URI on stdout or stderr, as a whole or in any form `Redaction.Variants` lists |
| an entry without a set; an entry whose section can't be decrypted | ` [not fingerprinted]` in `conflicts`; the unreadable text from `{{x:discarded}}` and `restore --discarded`; `--clear` works |
| an entry that is also the previous value | silent; `conflicts` lists it (round 8 model 2) |
| a write command on a record whose fold would hold 65 entries | the cap text, once; copies kept; `conflicts --clear` then writes |
| `conflicts --ack` twice; `--clear` twice | the second of each writes nothing (exit 0, `No value conflicts for 'x'.` for the second clear) |
| an entry without a set read by `redact` | refused as "not fully fingerprinted" |
| `--stamp` with two entries sharing the 8-hex origin prefix at one HLC, for `restore --discarded`, `--ack` and `--clear` | the ambiguity text for the 8-hex form; the full 32-hex form picks one |
| `run` with `{{x:discarded}}` of an entry without a set; the child prints the value | masked `[REDACTED: x:discarded]`; the set stored at the next value write |
| `sudo get` | unchanged (the current value) |
| `export` with an open entry | the §1.10 warning; the export imports without it |
| `vault reindex` | entries' sets recomputed; a second run rewrites nothing |
| the warning on `run` of another secret | no warning (only the secret used) |
| every new command's output | `CommandReferenceTests`, `docs/commands.md` regenerated |

Break-it-once: drop the lineage check (the "two rotations behind" row warns); treat "has the extension" as exact
(the 0.3.2-shaped stale-`asOf` row reports `v1`); let `S` remove entries (the step-6 and "A rotates again" rows lose
`a`); let `R` remove entries (the demotion rows of §1.4a lose `a` without a clear); strip `:discarded` before the inner
lookup (the `{{sync-conflict-test:discarded}} = from-a` row gets `from-b`); let a current value with a retired stamp
be a candidate (the (`Z`,`X`),`Y` order keeps `a` while all at once doesn't); drop the per-machine open rule (the
"open on this machine" row fails); remove an entry whose value equals a retained one (the "winner rotates to the
entry's value" order rows differ); drop the `known` term from `B` (both amendment 1 rows lose the value); compute discards from the main file
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
| two commands' floors interleaved (write the file between load and save) | `Write` the larger; the (`Version`, `Burn`) pair whole from the side with the larger version |
| A burns `v10`; B rotates to `v12`; sync; `names` and `rotate` on A | no warning; `rotate` works (round 3 amendment 1) |
| A and B burn `v10` concurrently; sync | no warning |
| `conflicts --ack`, `--clear` and `restore --discarded` on an R1-flagged record | each refused with the §2.5 text |
| `{{x:discarded}}` on an R1-flagged record | the value given; the R1 warning shown |
| `seen-keyring` damaged | the warning; a fresh baseline; nothing refused |
| the config pointed at another vault | its own baseline files; the first vault's files untouched |
| `restore-slots` with no file for the folder keyring's vault id | the "no record of slots" text, nothing written |
| `restore-slots` where the folder's keyring has a same-id slot with other bytes | that slot skipped with the warning; the others put back |
| `accept-rollback --all` with R1, R2 and R4 records | all three silent afterwards |
| `accept-rollback <name>` of an R2 record, and `accept-rollback --file <hash>` of another | both accepted |
| `conflicts --clear` on M; the record file put back from before the clear; a stale machine writes over it | no R1 (the documented limit); the entry back as that file held it (open: the warning shown; acknowledged: silent) |
| the same for a delete: put back from before it, then a stale machine writes a newer value | no R1 (the documented limit) |
| a rolled-back record at 64 entries: `vault merge`, `conflicts --clear`, then `accept-rollback`, `--clear`, `vault merge` | the first two refused (cap, rollback) with the order printed; the sequence then works |
| floor `(v10, burn at t2)`; the file on disk `(v10, burn at t1 < t2)`; interleaved save | the floor's burn is `t1` |
| `restore-slots` with no `keyring` file | the refusal naming the `seen-keyring-*` files; nothing written |
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
| run under a sudo escalation (`FleetMachine.SudoEscalated`), and `sudo vault restore-slots` | both new files owned by the config folder's owner, 0600; the folder's `keyring` keeps its owner and mode |
| each write command, `delete` included, run on a fixture vault | no main record file ever disappears (R2's premise) |
| a 0.3.2-shaped reader with `seen-records.json` and `seen-keyring` present | the same output as without them |
| two commands' `seen-keyring` writes interleaved | a union of both slot sets |
| two commands' floor entry lists interleaved | a union by stamp, burned bits OR-ed |
| a machine with a clock a year ahead writes; its copy is then lost | R1 with the future time and the year-ahead warning |
| a write of either new file killed before its rename (a write seam that throws) | the old file intact; the next command reads it |
| an R4 warning on a record, then a newer write of it | the floor's other components still raise |
| `accept-rollback x` on a record with an R4 warning | R4 silent afterwards |
| a floor entry whose stamp is in the record's retired list | pruned at the next save |
| `init --vault-dir`, `slot accept --vault-dir`, `migrate --to-records`, `vault merge <other>`, `vault move <target>` | no `seen-*` file in the other, target or temporary folder; this machine's files raised only from its own folder |
| a `vault merge` refused by the stale-write guard | floors equal to what this folder's files hold; nothing raised from the other copy |
| P1 loads a flagged record; `accept-rollback x` runs in P2; P1 saves | still accepted |
| the same with an R2 record | the R2 entry stays removed |
| the same through a broker read (`VaultBrokerSecretSource`) | still accepted |
| a conflicted copy's removal arrives before the new main file (transport out of order), then the main file | R1 with "wait and run again", then no warning |
| a rollback seen only in the write stamp, then `vault merge` | no longer reported; a version rollback, then `vault merge` of an older copy: still reported |
| a missing `seen-records.json` with a `config.json` that has `LastHlc` | the one notice |
| `Format` 2, or an unparsable stamp, in `seen-records.json` | the damaged-file warning; a fresh baseline |
| `accept-rollback x` with nothing flagged | `Nothing to accept …`, exit 0 |
| `restore-slots` with input redirected and no `--yes` | refused, nothing written |
| own slot lost, no `seen-keyring` | the unlock text without "Config is corrupted", naming the keyring and a copy from another machine |
| P1 authenticates the pre-rollback state; `accept-rollback x` in P2; P1 saves | the record flagged again (M-4, the safe direction) |
| `restore-slots` against a folder whose keyring belongs to another vault | `This machine has no record of slots for vault <id>; nothing to put back.` (the refusal is dropped, round 8 model 8) |
| Claude r7 C-1's three-machine table (A, B, C; B folds (A, B) in memory; C writes its fold; B reads C's main) | no R4: the in-memory entry `a` was never floored (round 8 model 1) |
| the same with B **writing** its fold before C's main arrives | entry `a` floored (persisted); R4 then only if a later merge drops it without a retirement |
| an R3 record (copies that can't be merged) whose copy was authenticated | nothing raised; after the user removes the copy, no R1 (Claude 5) |
| a record written in P1 after P2 raised its floor and a rollback came in between | refused at save (Claude 8) |
| the upgrade notice: `config.json` with `LastHlc` and no `VaultId`; with `VaultId` | the notice once; none (T61 R-7) |
| R2 with a conflicted copy present but no main file | R3, not R2 (T61 R-5) |
| a `seen-records-*` and `seen-keyring-*` file name | lower-case hex (M-9) |
| (a) MiMo's round 5 C-2: clear; A's later copy (written after a burn) arrives and merges | no entry re-forms (round 6's fix); R4 silent because `a` is retired, which a person did |
| (b) clear; the pre-clear file put back by a restore, its copies gone | the entry back as that file held it; R1 fires (write stamp); R4 silent, because the floor entry was pruned at the clear: the documented limit (§2.4) |
| (c) clear; the pre-clear file put back while a copy carrying `T` survives | no entry: the union with that copy's `T` removes it |
| own slot present with other bytes than `seen-keyring`'s | the "differs" unlock text, with the `restore-slots`-on-each-other-machine line; `restore-slots` skips it and prints the same instruction (round 7 amendment 4, round 8) |
| `KeyringSlotId` null (migrated from a plain XOR vault), its slot lost | the unwrap failure as today; `restore-slots` puts it back (Claude 13) |
| an entry gone without any retirement (a 0.3.2-shaped merge) | R4 warns |

Break-it-once: merge `Burn` independently of `Version` (the burn-then-rotate row warns); compare the main file
instead of the merged state (the conflict row warns); drop the version component
(the delete-then-stale-write row passes silently); let `accept-rollback` run without sudo (its refusal row fails);
make `restore-slots` unlock first (the own-slot row fails); treat a missing file with no copies as unchanged (the R2
rows pass silently); let R4 accept a stamp only through `S` (the cleared-then-0.3.2-merge row warns, and the
dropped-entry row is silent); skip the `seen-keyring` comparison (the lost-slot rows are silent); let a write go on
over R1 (the `rotate`-refused row fails); keep the floor in memory between operations (the P1/P2 rows lose the
accept).

## Briefs

Serialised: **T58 → T60 → T61**. T60 needs T58's grammar and `CommandValues` and touches the same token files; T61
needs T60's extension for R4 and shares `RecordVaultStore.cs`. Neither T60 nor T61 runs in parallel with another
brief that edits `RecordVaultStore.cs`, `RecordMerge.cs`, `RecordWrites.cs` or the token grammar files.

**T60, keep merge-discarded values (#312).** Owns: new `TswapCore/Keyring/ValueLineage.cs` (model, codec, the
discard rule as pure functions), `TswapCli/Commands/ConflictsCommand.cs`; edits `TswapCore/Keyring/RecordMerge.cs`,
`RecordWrites.cs`, `RecordMetadata.cs`, `TswapCore/RecordVaultStore.cs` (fold notes, `NextRecord`, `Tombstone`,
`PrepareV3`, `IsCurrent`, entry sections, format 3 forcing, lazy entry decryption), `TswapCore/SecretEntry.cs` and
`TswapCore/PendingWrite.cs` (round 5 amendment 5), `TswapCli/Commands/FieldCommand.cs` (round 8, the adopt refusal),
`TswapCore/ISecretLookup.cs` (its contract comment), `TswapCore/VaultWriter.cs` (ack, clear, restore by
stamp), `TswapCore/VaultView.cs` (`:discarded`, the index), `TswapCore/SecretInfo.cs`, `TswapCli/FingerprintStreamMatcher.cs`,
T58's `TswapCore/Totp/CommandValues.cs` and the grammar files T58 lists, `TswapCli/Commands/RestoreCommand.cs`,
`NamesCommand.cs`, `DeleteCommand.cs`, `ExportCommand.cs`, the command registry, `TswapCli/CliJson.cs`,
`TswapCore/Fields/FieldSet.cs` (registry comment), `TswapCore/Prompt.cs`, `docs/commands.md`, `docs/multi-machine.md`,
`docs/security-model.md`, AGENTS.md (the privilege lists), the release notes; tests as above. T60 changes the token suffix list again, so it re-sanctions exactly T58's
suffix-pinning assertions (`FieldTokenRefusalTests.MalformedMessage` and `.MarkerMessage`, `RunEnvTests.Exactly` and
its `{{x:bogus}}` row) and no others. `ValueLineage`'s entries must not share T58's `ValueKinds` code that drops entries of stamps no longer retained on a
value write (round 3 amendment 13). Six tasks: extension
and codec; merge rule and parity; writes; warnings and `names`; `conflicts`, `restore --discarded`, `:discarded`;
docs.

**T61, detect rolled-back records and slots (#197).** Owns: new `TswapCore/Keyring/SeenFloor.cs` (the rules of §2.4
as pure functions over merged metadata), `TswapCore/SeenState.cs` (the two files); edits `TswapCore/RecordVaultStore.cs`
(the load, open and commit hooks, `ReadKeyringWithCopies`, `Reindex`), `TswapCore/VaultWriter.cs` (the refusal), `TswapCore/Models.cs` (`Config.VaultId`, round 6 M-3),
`TswapCore/Vault/VaultUnlocker.cs` (the own-slot text), `TswapCli/Commands/VaultCommand.cs` (`accept-rollback`,
`restore-slots`), `TswapCore/Prompt.cs`, `docs/commands.md`, `docs/multi-machine.md`, `docs/security-model.md`,
AGENTS.md, release notes; tests as above. Four tasks: the floor model and file; the record checks and refusal; the
keyring check, unlock text and `restore-slots`; `accept-rollback` and docs.

Before each release, a one-off check with the v0.3.2 binary on a copy of a vault the new build wrote (`names`, `run`,
a rotate, a merge of a conflict copy), with `seen-records.json` and `seen-keyring` in its config folder, recorded in
the PR, as T54 did.

## Appendix A: Part 2's texts in full (T61 R-13, round 8)

Copied verbatim from T61's brief at c1a79e0 so the design holds every text; the brief is its source. Round 8 changes
to them: every `sudo tswap …` follows §2.5's elevation words; `restore-slots`' step 2 (the vault-id check) is dropped
(model 8), steps 1 and 3-6 stand; the R4 "import of an export" cause is removed (Claude 4), and R4 gains the "retired
value back" text of §2.5.

### The two files

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


### R1, R2, the summary and R4

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
- `⚠ <name>: a value a merge had set aside (machine <o>, <t>) is gone from its record; an older tswap's merge, a
  rolled-back file, or an import of an export (which carries no set-aside values) dropped it. To stop this warning:
  'sudo tswap vault accept-rollback <name>'.`
- `⚠ <name>: the value machine <o> wrote at <t> (set aside by a merge) was burned when this machine last saw it; its
  burn is gone. It is still compromised. To stop this warning: 'sudo tswap vault accept-rollback <name>'.`

`run` with `{{x:discarded}}` on an entry the floor saw burned gives T60's burned-value warning (R-9).

### The refusal

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

### The keyring check

- missing file: baseline, no text; damaged: its warning, then baseline;
- a seen slot the folder lacks: one line per command, `⚠ The vault folder's keyring has lost <n> slot(s) this machine
  saw before: <id8> (<kind>)[, …]. The keyring file was replaced by an older copy (a sync restore, a stale copy, or
  someone with access to the folder); machines whose slot is missing can't open the vault. Put it back with 'sudo
  tswap vault restore-slots'.` (`1 slot` / `2 slots`; `<kind>` per R-10);
- a same-id slot with other bytes: `Warning: slot <id8> in the vault folder's keyring differs from the one this machine
  saw. Slots never change once written, so the keyring was damaged or tampered with; this machine keeps the copy it
  saw. Compare <vault folder>/keyring with <seen-keyring path>.` That slot is not added;
- folder slots the copy lacks (by id, not differing) are added with `SaveKeyring` (a union with the file on disk).


### The own-slot unlock texts

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
  config.json is fine. Move <vault folder>/keyring aside, copy <seen-keyring path> in its place, and compare the two.`

Without `KeyringFolder` (a classic vault, whose keyring is in `config.json`) the texts stay as they are.

### `restore-slots`

1. No `keyring` file: today's text (`:259-260`) plus, per file in `SeenKeyringFiles()`, `This machine kept a copy of
   every slot it saw: <path>. It is a complete keyring; to put it back, copy it to <vault folder>/keyring.` Exit 1,
   nothing written.
2. `config.json`'s `VaultId` not valid base64 of 16 bytes: `Config is corrupted: VaultId is not the base64 of a 16-byte
   vault id. Restore config.json from backup.` Set and different from the keyring's: `The keyring in <vault folder>
   belongs to vault <16 hex>, but this machine's config.json is for vault <16 hex>. Nothing was written.` Exit 1.
   Absent: go on.
3. No seen file for the keyring's vault id (missing or damaged): `This machine has no record of slots for vault <16
   hex>; nothing to put back.` Exit 1.
4. Missing = seen slots whose id the folder lacks; a same-id slot with other bytes is skipped with the "differs"
   warning, and when it is this machine's own slot the own-slot "differs" text follows. None missing: `Nothing to put
   back.` Exit 0.
5. Each slot to add: `Putting back: <SlotCommand.DescribeSlot(slot)>` (`SlotCommand.cs:1970-1982`: id, kind,
   fingerprint). Input redirected and no `--yes`: `The keyring this machine saw has <n> slot(s) the vault folder's
   keyring lacks:` + one `  <DescribeSlot>` line each + `Putting a slot back gives whoever holds its device a way to
   open this vault again. Compare each fingerprint with the one shown when that slot was created, then run this again
   on a terminal to confirm each one, or pass --yes. Nothing was put back.` Exit 1 (as `merge`, `:95-101`). On a
   terminal, `YesNo.Ask(…, "Put it back? Compare the fingerprint first.", defaultAnswer: null)` per slot; a no:
   `Slot not confirmed. Nothing was put back.` Exit 1.
6. `RestoreSlots`, then `✓ Put back <n> slot(s) in <vault folder>/keyring.` Exit 0.

### `accept-rollback`

Output (stdout), per target, exit 0:
- R1: `✓ Accepted the current version of '<name>' (<why>).`, `<why>` by the Task 2 `<state>` row: `it was deleted when
  this machine last saw it` / `this machine last saw a newer version, from machine <o> at <t>` / `it was burned when
  this machine last saw it` / `this machine last saw a later change, made at <t> by machine <o>`.
- R2: `✓ Accepted that '<name>' is gone (record <64 hex>; this machine saw it on <t>).`, without a name `✓ Accepted
  that record <64 hex> is gone (this machine saw it on <t>).`
- R4: `✓ Accepted that '<name>' no longer holds <n> value(s) a merge had set aside.` and `✓ Accepted that <n> value(s)
  of '<name>' a merge had set aside are no longer marked burned.`
- nothing flagged: `Nothing to accept for '<name>': it isn't older than this machine saw.` (`--file`: `for record <64
  hex>`; `--all`: `Nothing to accept: no record is older than this machine saw.`); an unreadable record: `Nothing to
  accept for '<name>': its record can't be read (see the warning above).`


## Decisions (owner, 2026-11-27, were the open questions)

1. **A value that loses to a concurrent delete is kept on the tombstone as a discarded value (owner).** It is warned
   about and listed by `tswap conflicts`; `sudo tswap restore NAME --discarded` brings the secret back and
   `sudo tswap conflicts --clear NAME` drops it.
2. **`tswap conflicts --ack` takes no sudo (owner).** It destroys and reveals nothing, only quietens the warning on
   every machine, and records the machine, time and `--by` label. Dropping a value (`--clear`) and restoring one
   (`restore --discarded`) need sudo.
3. **Export leaves discarded values out and warns, naming the secrets (owner).** Exports stay importable by 0.3.2;
   the warning is the one in §1.10.
