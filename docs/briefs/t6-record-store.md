# Brief T6: a vault folder that sync tools and copies can share: one record per secret, HLC, burn and rotate (#111–#114, #137, #132, #8)

Read AGENTS.md and issues #132 and #8 **with their 2026-10-30 owner comments**; they override the
plan where they differ. Then read `REFACTORING_PLAN.md` §Phase 6 ("Mergeable on-disk format",
"Per-file security considerations", "Implementation ordering", "Open questions"),
`MULTI_MACHINE_KEYING.md`, and issues #111, #112, #113, #114 and #137 in full. They are the
specification; this brief settles what they leave open.

The building blocks already exist and are tested but unused: `SecretRecordCodec`, `SecretRecord`,
`RecordType`, `RecordKeyDerivation`, `FilenameHasher`, `DurableFileWriter`, `GenerationGuard` and
`RecordDirectoryScanner` in `TswapCore/Keyring/`. **Build on them; don't rewrite them**, except where
this brief changes the record layout (decision 3) or their own tests show a fix is needed.

One commit per item, test first, a break-it-once check per item. `./runtests.sh --unit` after each
item, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys, or
`~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only.

**This brief starts after brief T5 is merged** (fleet enrolment: receipt, `slot merge`,
TPM/SE `slot request`, recovery key). Merge `main` into this branch first.

## Why

The owner's vaults are moving to several machines: a TPM vault on the router, YubiKeys at the
desktop and in the wallet, later more TPM and Secure Enclave machines. T5 makes every copy's
**keyring** open with every enrolled device. But a vault is still one `secrets.json.enc` blob, so
two copies can't be combined: the newer file overwrites the other, and edits made on two machines
are lost. One file per secret makes a vault folder shareable by OneDrive, Dropbox, Syncthing or a
network share, and makes two copies mergeable. And rotating a burned secret should not need
"delete, then add again" (#8).

## Decisions (made here; record them in `REFACTORING_PLAN.md` §Phase 6, and move the settled items out of "Open questions")

1. **Layout.**
   - **A vault folder** (shareable, possibly synced) holds `keyring` (the `KeyringCodec` bytes)
     and `records/<HMAC(K_names, name) hex>`.
   - **The machine's `config.json`** stays in the config dir, with only machine fields:
     `Backend`, the backend's own fields, `KeyringSlotId`, pending-slot fields, `ApprovedSlots`
     (T5), touch posture, a new random `OriginId` (16 bytes, created once per machine), and
     `VaultDir`.
   - A new `Store` field: absent means the classic single file, as today; `"records"` means
     this store.
   - **`LoadConfig` composes `Config.Keyring` from the vault folder's `keyring` file, so every
     command (T5's `slot merge` included) keeps working unchanged.**
2. **The keyring file.**
   - **Save** reads what's on disk, takes the union with the new keyring (by slot id; the vault id
     and format version must match), and writes atomically with `DurableFileWriter`. A save never
     drops a slot it didn't know about.
   - **Load** finds the sync tools' conflicted copies of `keyring` (`RecordDirectoryScanner`'s
     conventions) and folds them in as a union.
3. **Records.**
   - One per secret (#111–#113): types `value`, `tombstone`, `burned`; padding to 256-byte
     buckets; per-record key `HKDF(K_v, recordId || ordering stamp)`.
   - **`K_names` is derived from `K_v`** (settled for v0: there is no rotation yet; #126 revisits
     it).
   - **Ordering authority: a hybrid logical clock (HLC)** per write, with `OriginId` as the
     tiebreak (owner decision on #132: HLC now, not in v2).
     - The HLC is (physical milliseconds, logical counter).
     - A write takes `max(now, the highest HLC this machine has seen in the vault)`, plus the
       logical step when the physical part doesn't advance. So it never runs backwards and always
       orders after everything it has seen.
     - It replaces the plan's plain write counter in the record layout. Record format version 1
       has never shipped, so change `SecretRecordCodec` and its golden tests accordingly.
   - **The displayed time** (`names`) is the HLC's physical part.
4. **Merge rules** (owner decisions on #132 and #8), applied when one secret has several versions:
   the record, its sync-conflict copies, or another vault folder (decision 5):
   - **The last action wins, by (HLC, origin id), for values and tombstones alike.** A deleted
     secret only comes back if someone really wrote a value after the delete.
   - **A burn marks the value version it was issued against** (that value's HLC), with its own
     burn time and reason.
     - If the current winning value is that version, the secret is burned.
     - If a **newer** value exists, it wins: the burn becomes history, and the incident is kept in
       the record (a bounded list of past burns: when, reason, which version).
     - Two burns of the same version keep the earliest (the existing #35 rule: an incident record is
       never overwritten).
   - **A conflicted copy that can't be decrypted or authenticated** is reported as a warning
     (hashed filename, the sync tool's name) and **never deleted or chosen**.
   - **Copies made redundant by a decided conflict** are removed on the **next write** of that
     record, not on load. A read-only command never deletes anything.
5. **New `tswap vault merge <other-vault-dir>`** (sudo, because it decrypts every record): folds
   another copy's keyring (union) and records (decision 4's rules) into this vault. This is for
   copies moved by scp/rsync/USB rather than a sync tool. The other copy must have the same vault
   id; it's only read, never written.
6. **Stale-write guard:** before writing a record, re-read its on-disk version. If another machine
   or process wrote a newer one since this command loaded it, refuse with an actionable message
   (`GenerationGuard`), not silently overwrite.
7. **Rotation (#8).**
   - **`tswap rotate <name> [length]`** writes a new random value as a newer version (like `create`:
     the value is never displayed, and `RngMode` is respected).
   - **`ingest --rotate <name>`** does the same from stdin.
   - **The secret exists throughout:** no delete. Both work on burned and unburned secrets.
   - **`burned`** reports a burn superseded by a newer value as rotated, not outstanding.
   - **`create` and `ingest` without `--rotate`** keep refusing an existing name, but the message
     now points to `rotate` / `ingest --rotate`, not "delete first".
   - **The classic single-file store gets `rotate` too:** replace the value and keep the burn as
     history if its format allows; if it doesn't, say so and refuse on that store.
8. **Conversion: `tswap migrate --to-records [--vault-dir <dir>]`** (sudo).
   - Unlock; write every secret as a record (this `OriginId`) and the keyring file.
   - **Re-read everything and compare** (names, values by hash, burned state) before switching
     `config.json` to `Store: "records"`.
   - Keep `secrets.json.enc` as a `.bak` with a timestamp.
   - On any mismatch, change nothing and say what differed.
   - It works for plain XOR vaults (the owner's main vault; `K_v` is the derived master key) and
     for keyring vaults.
   - `--vault-dir` puts the vault folder elsewhere, e.g. in a OneDrive folder; the default is
     `<configDir>/vault`.
   - **Joining an existing shared folder:** `init`/`slot accept` with `--vault-dir <existing
     folder>` points another machine's config at the same folder.
9. **Export and import** keep their single-file encrypted format and serialize whatever store is
   active.

## Items

1. **The store, single machine** (decisions 1, 3, 6).
   - `RecordVaultStore : IFileVaultStore`, selected by `Store: "records"` at the composition root.
   - **Tests:**
     - create, get, apply, names, burn and delete round trips through the CLI;
     - one file per secret, with no plaintext name on disk;
     - two values of very different length give the same file size within a bucket;
     - burn and delete write records, not absent files;
     - golden-byte tests for one record of each type (lock the layout).
   - **Break-it-once:** skip padding; the size-bucket test fails.
2. **The keyring file and its union save** (decision 2).
   - **Tests:**
     - two copies of a vault folder each add a slot (T5's `slot add` or merge); the union file has
       both;
     - a conflicted-copy `keyring` is folded in on load;
     - a different vault id is refused.
   - **Break-it-once:** plain overwrite instead of union; the two-copies test fails.
3. **HLC, merge rules and conflicted copies** (decisions 3 and 4).
   - **Tests:**
     - **HLC:** never decreases, even with a clock set back between writes (a time seam); a write
       after observing a record from "the future" orders after it;
     - a table of pairs gives the expected winner, in both orders (commutativity) and when
       repeated (idempotence): value/value (different HLC; equal HLC with different origins),
       tombstone/value (the newer wins either way), a burn of the current version vs a value, a
       burn of an older version vs a newer value (the newer value wins and the burn is in
       history), burn/burn of the same version (the earliest is kept);
     - real conflict-copy filenames of Dropbox, OneDrive and Syncthing are resolved;
     - an undecryptable conflict copy is warned about and kept;
     - redundant copies are removed only on the next write.
   - **Break-it-once:** let a burn beat any value; the "newer value supersedes an old burn" test
     fails.
4. **Rotation** (decision 7).
   - **Tests:**
     - `rotate` on a burned secret: a new value, `burned` lists it as rotated, history kept;
     - `ingest --rotate` from stdin;
     - `create` on an existing name refuses and points to `rotate`;
     - `rotate` on a missing name refuses;
     - the same on the classic store, or its documented refusal.
   - **Break-it-once:** rotate without a newer HLC; the rotated-burn test fails.
5. **Stale-write guard** (decision 6).
   - **Test:** load, then another "process" writes a newer version, then save: refused, and nothing
     is written.
   - **Break-it-once:** skip the re-read; the test fails.
6. **`migrate --to-records`** (decision 8).
   - **Tests:**
     - a plain XOR vault and a TPM keyring vault (simulated) with 50 secrets, including burned ones,
       convert; everything reads back; `.bak` exists;
     - a forced mismatch (a test seam) changes nothing;
     - running it twice refuses ("already a record store").
   - **Break-it-once:** switch config before verifying; the mismatch test fails.
7. **`vault merge`** (decision 5).
   - **Tests:**
     - two copies edited separately (different secrets; the same secret on both; a delete on one;
       a burn on one and a rotate on the other) merge to the rules' result, in both directions to
       the same state;
     - a different vault id is refused;
     - the source copy is unchanged.
   - **Break-it-once:** merge writes into the source; the unchanged-source test fails.
8. **Docs.**
   - README: "Sharing a vault between machines" (sync folder, network share, scp + `vault merge`)
     and "Rotating a secret".
   - `REFACTORING_PLAN.md` / `MULTI_MACHINE_KEYING.md`: the settled decisions, and the
     edit-timing metadata leak stated plainly (`REFACTORING_PLAN.md` item 2).
   - AGENTS.md command lists: `rotate`, `ingest --rotate` (no sudo); `migrate --to-records`,
     `vault merge` (sudo).
   - The agent prompt (`tswap prompt`): `rotate` as the way to replace a burned secret.

## Out of scope
- #191 (SSH enrolment; a later `--via` sync can build on `vault merge`).
- v1 rotation of `K_v` and revocation (#126, #128).
- #185.
- The owner's real main-vault conversion: the orchestrator does that with the owner, on a backup
  first.
