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
     command (T5's `slot merge` included) keeps working unchanged.** A record store's
     `config.json` holds no `Keyring` of its own (one source of truth); `SaveConfig` writes the
     keyring part to the vault folder (decision 2) and the rest to `config.json`.
   - **Only the vault folder is shared.** `config.json` is per machine and must never be synced;
     the README says so (the default vault folder sits inside the config dir, so a user who syncs
     the config dir syncs machine config too: tell them to sync `--vault-dir` instead).
2. **The keyring file.**
   - **Save** reads what's on disk, takes the union with the new keyring (by slot id; the vault id
     and format version must match), and writes atomically with `DurableFileWriter`. A save never
     drops a slot it didn't know about.
   - **Load** finds the sync tools' conflicted copies of `keyring` (`RecordDirectoryScanner`'s
     conventions) and folds them in as a union.
   - **The same slot id with different bytes** (wrapped key, public key, kind or hwBlob), from
     disk, a conflicted copy or `vault merge`, is **refused loudly** (T5's rule in `slot merge`),
     never resolved by picking one: that difference is what T5's approval pinning exists to catch.
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
   - **Where the clock lives.** `config.json` keeps `LastHlc`, the highest HLC this machine has
     written or seen. A write takes the maximum of `now`, `LastHlc` and every HLC read in this
     command (records and their conflicted copies), steps the logical counter when the physical
     part doesn't advance, and saves `LastHlc` with the write. A clock set back between two
     commands therefore still orders after the first.
   - **Ties.** (HLC, OriginId) is a total order: the larger HLC wins; at equal HLC the larger
     `OriginId` (bytewise) wins. Two writes with the same HLC *and* origin can only come from two
     processes of one machine racing on one record, which the stale-write guard refuses (decision 6).
   - **Absurd stamps.** A physical part more than one year ahead of `now` is accepted (merge
     needs a total order) but warned about on load (hashed filename). Display clamps: a value
     beyond `DateTime.MaxValue` shows as "far future" instead of throwing, so one bad clock can't
     break `names` everywhere.
   - **Header.** The HLC and `OriginId` sit in the record's plaintext header, authenticated as
     AAD (the per-record key needs them before decryption). `OriginId` is created per machine
     config, i.e. per vault, so it does not link one machine across vaults; the edit-timing leak
     is documented (item 8).
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
   - **Existence is decided by values and tombstones only.** A burn annotates one value version:
     a burn of a version that is not the winner (deleted, or superseded) is history only. A burn
     never resurrects a deleted secret, and a delete after a burn deletes it.
   - **Burn history** is bounded to the 16 most recent entries by (burn HLC, origin); merging two
     histories takes their union by (version HLC, burn HLC, origin) and then truncates in that
     order, so the result doesn't depend on merge order. The #35 rule (earliest wins, never
     overwritten) applies to the outstanding burn of a version.
   - **A conflicted copy that can't be decrypted or authenticated** is reported as a warning
     (hashed filename, the sync tool's name) and **never deleted or chosen**.
   - **A main record that can't be read** (truncated mid-sync, fails authentication) **fails
     closed**: a command that needs that secret stops with an error naming the hashed file;
     `names` warns and counts unreadable records; the secret counts as present-but-unknown, so it
     is never treated as absent, overwritten, or deleted by a merge, and writes to it refuse until
     the file is restored or the sync finishes.
   - **Copies made redundant by a decided conflict** are removed on the **next write** of that
     record, not on load. A read-only command never deletes anything. A removal that fails (a
     sync tool or Windows holding the file) is a warning, not a failed write.
5. **New `tswap vault merge <other-vault-dir>`** (sudo, because it decrypts every record): folds
   another copy's keyring (union) and records (decision 4's rules) into this vault. This is for
   copies moved by scp/rsync/USB rather than a sync tool. The other copy must have the same vault
   id; it's only read, never written.
6. **Stale-write guard:** before writing a record, re-read its on-disk version. If it **changed
   since this command loaded it** (any difference, not only a newer HLC), refuse with an actionable message
   (`GenerationGuard`), not silently overwrite.
7. **Rotation (#8).**
   - **`tswap rotate <name> [length]`** writes a new random value as a newer version (like `create`:
     the value is never displayed, and `RngMode` is respected).
   - **`ingest --rotate <name>`** does the same from stdin.
   - **The secret exists throughout:** no delete. Both work on burned and unburned secrets.
   - **`burned`** reports a burn superseded by a newer value as rotated, not outstanding.
   - **`create` and `ingest` without `--rotate`** keep refusing an existing name, but the message
     now points to `rotate` / `ingest --rotate`, not "delete first".
   - **The classic single-file store gets `rotate` too, for unburned secrets only.** Its format
     has one burn field and no history, and #35 forbids overwriting an incident record, so on the
     classic store `rotate` of a burned secret refuses and points to `migrate --to-records`.
   - **Sudo (owner decision 2026-10-30): sudo unless the secret is burned.** Rotating a burned
     secret needs no sudo: it is already compromised, nothing usable is lost, and replacing it is
     the agent's job (`tswap prompt`). Rotating an unburned secret needs sudo, because an agent
     doing it alone could break every service that uses it. The check is on the winning version
     at the time of the write (a burn that a newer value already superseded doesn't count).
8. **Conversion: `tswap migrate --to-records [--vault-dir <dir>]`** (sudo).
   - **Order, so a crash at any point leaves the classic vault working:**
     1. Unlock; write the keyring file and every secret as a record (this `OriginId`) into a new
        folder `<vault-dir>.tmp-<random>` next to the target.
     2. **Re-read everything from it and compare** (names, values by hash, burned state). On any
        mismatch, delete the temp folder, change nothing, and say what differed.
     3. Rename the temp folder to the vault folder.
     4. Switch `config.json` to `Store: "records"` with `VaultDir` (its embedded keyring moves to
        the vault folder, decision 1).
     5. Only then rename `secrets.json.enc` to a timestamped `.bak`.
   - **"Already a record store"** is decided by `config.json`'s `Store` field only, never by files
     present. A re-run after a crash removes stale `<vault-dir>.tmp-*` folders (with a notice).
   - **The target folder** must be absent or empty; otherwise refuse (joining an existing shared
     folder is `init`/`slot accept --vault-dir`'s job, below).
   - Keyring vaults convert as above.
   - **Plain XOR vaults (the owner's main vault) become keyring vaults in the same run (owner
     decision 2026-10-30).** `K_v` stays the derived master key, so no secret is re-encrypted for
     it. A new vault id is minted. **Every enrolled YubiKey must be plugged in:** each gets its own
     slot (T4's one-key-per-slot construction, touch as configured). A missing serial refuses
     the run, naming it, before anything is written. A recovery slot is added and its key shown
     once, exactly as `init` does. Step 2's verification also unwraps `K_v` from every new slot.
     After step 4 the XOR fields (`RedundancyXor`, `UnlockChallenge`, `MasterKeySalt`) are gone from
     `config.json`. The vault is then shareable and takes T5's remote enrolment (the router's TPM).
   - `--vault-dir` puts the vault folder elsewhere, e.g. in a OneDrive folder; the default is
     `<configDir>/vault`.
   - **Joining an existing shared folder:** `init`/`slot accept` with `--vault-dir <existing
     folder>` points another machine's config at the same folder.
9. **Export and import** keep their single-file encrypted format and serialize whatever store is
   active. **An export is a snapshot of the current values and burn state; it does not take part
   in merge semantics** (no tombstones, no history). Importing into a record store writes each
   secret as a new version (newer HLC), so importing an old export can bring back a deleted
   secret: that is the user's explicit act, and the README says so.
10. **The file layer and permissions (T5, #194).**
   - **Every file in the vault folder and the config dir** (keyring, records, conflict-copy
     cleanup, backups, the migration's temp folder) is read and written through T5's
     `DirectoryOwnerMatcher`: under sudo, as the folder's owner (never as root in another user's
     folder); files created 0600 under a random temp name with `O_EXCL`, then renamed. Build
     `DurableFileWriter` on it (or merge the two), keeping `DurableFileWriter`'s fsync guarantees.
     No `File.*` call on a vault path outside it.
   - **Folders** (config dir, vault folder, `records/`) are created 0700.
   - **Existing vaults with wider modes** (#194): a folder wider than 0700 or a file wider than
     0600 is tightened on the next write, with one notice per command naming what changed. Reads
     never change modes.
   - Windows: no change (profile ACLs); say so in the docs.

## Items

1. **The store, single machine** (decisions 1, 3, 6).
   - `RecordVaultStore : IFileVaultStore`, selected by `Store: "records"` at the composition root.
   - **Tests:**
     - create, get, apply, names, burn and delete round trips through the CLI;
     - one file per secret, with no plaintext name on disk;
     - two values whose lengths fall in one 256-byte bucket give the same file size, and a value
       one byte past the bucket's end gives the next bucket's size;
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
     - burn/tombstone pairs in both orders (delete-then-burn, burn-then-delete): the secret stays
       deleted, the burn is history; burn histories merge to the same truncated list in both orders;
     - HLC: same millisecond on one machine gives distinct, increasing stamps; equal HLC is decided
       by origin; an absurd future stamp is warned about and `names` shows "far future";
     - a truncated main record: the command that needs it fails naming the file, `names` warns,
       a merge neither deletes nor overwrites it;
     - a redundant copy whose removal fails is a warning, the write succeeds.
   - **Break-it-once:** let a burn beat any value; the "newer value supersedes an old burn" test
     fails.
4. **Rotation** (decision 7).
   - **Tests:**
     - `rotate` on a burned secret: a new value, `burned` lists it as rotated, history kept;
     - `ingest --rotate` from stdin;
     - `create` on an existing name refuses and points to `rotate`;
     - without sudo: `rotate` of a burned secret works, of an unburned one refuses (nothing
       written); with sudo both work;
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
     - the XOR vault afterwards opens with each YubiKey alone and with the recovery key, has no
       XOR fields left, and a missing YubiKey refuses the run before anything is written;
     - a forced mismatch (a test seam) changes nothing (no vault folder, `config.json` and
       `secrets.json.enc` byte-identical);
     - a crash seam after each of steps 1, 3 and 4: the vault still opens (classic before step 4,
       records after), and a re-run finishes or refuses correctly;
     - a non-empty target folder is refused;
     - running it twice refuses ("already a record store").
   - **Break-it-once:** switch config before verifying; the mismatch test fails.
7. **`vault merge`** (decision 5).
   - **Tests:**
     - two copies edited separately (different secrets; the same secret on both; a delete on one;
       a burn on one and a rotate on the other) merge to the rules' result, in both directions to
       the same state;
     - a different vault id is refused; the same slot id with different bytes is refused;
     - merging the same copy twice changes nothing the second time;
     - the source copy is unchanged.
   - **Break-it-once:** merge writes into the source; the unchanged-source test fails.
8. **The file layer and permissions** (decision 10).
   - **Tests** (T5's fake identity switch and its "root-only" file):
     - under a fake sudo, every record, keyring, backup and temp-folder write asks for the
       folder owner's identity; a `records/<file>` planted as a link to a root-only file is
       neither read nor written through;
     - new folders 0700 and files 0600 under umask 0;
     - an existing vault folder 0755 with files 0644: the next write tightens them and prints one
       notice; a read changes nothing.
   - **Break-it-once:** write records with `File.WriteAllBytes`; the planted-link test fails.
9. **Docs.**
   - README: "Sharing a vault between machines" (sync folder, network share, scp + `vault merge`)
     and "Rotating a secret".
   - `REFACTORING_PLAN.md` / `MULTI_MACHINE_KEYING.md`: the settled decisions, and the
     edit-timing metadata leak stated plainly (`REFACTORING_PLAN.md` item 2).
   - AGENTS.md command lists: `rotate`, `ingest --rotate` (no sudo for a burned secret, sudo
     otherwise); `migrate --to-records`, `vault merge` (sudo).
   - The agent prompt (`tswap prompt`): `rotate` as the way to replace a burned secret.

## Out of scope
- #191 (SSH enrolment; a later `--via` sync can build on `vault merge`).
- v1 rotation of `K_v` and revocation (#126, #128).
- #185.
- The owner's real main-vault conversion: the orchestrator does that with the owner, on a backup
  first.
