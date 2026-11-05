# Using a vault on several machines

This page is for anyone who wants one vault on more than one machine, or more than one kind of
hardware. It covers joining another machine with hand-carried files, enrolling a YubiKey into a
TPM vault from another desk, sharing a vault folder through a sync tool, a network share or a plain
copy, the merge rules, which sync transports are safe, and record format 3 with `vault reindex`.

Set up the first machine before you start: [setup.md](setup.md). What a sync provider can see, and
what tswap doesn't detect yet in a shared folder, is in
[security-model.md](security-model.md#a-shared-vault-folder-what-a-sync-provider-sees-and-what-isnt-detected).
If the vault has a vault password, joining needs its `vault-password` file: see
[Joining with a password](vault-password-and-agent.md#joining-with-a-password).

## Two ways to share a vault

- **Each machine keeps its own copy**, and you carry small files between them: a new machine
  joins with four `slot` commands, and `vault merge` folds one copy's secrets into another.
- **The machines share one vault folder**, which a sync tool, a network share or a plain copy
  carries. A new slot or a new secret reaches every machine with the next sync.

Either way, each machine keeps its own `config.json` (its own slot, its origin id, its clock),
and it is never shared.

## Joining another machine

Another machine joins the vault in four steps. "There" is the new machine; "here" is a machine
that already opens the vault.

| Step | Where | Command | What it does |
|---|---|---|---|
| 1 | there | `tswap slot request request.json` | Enrols one plugged-in YubiKey; `--tpm` or `--secure-enclave --with-touch\|--no-touch` enrols that machine's own TPM or Secure Enclave instead. It prints the new slot's fingerprint |
| 2 | here | `sudo tswap slot approve request.json approve.json` | Unlocks the vault and writes the approve file. Compare the fingerprint it prints with step 1's |
| 3 | there | `tswap slot accept approve.json` | Finishes the slot and writes a receipt, `approve.json.receipt.json` (or the path given with `--receipt <file>`) |
| 4 | here | `sudo tswap slot merge approve.json.receipt.json` | Adds the new slot to this machine's keyring, so this copy opens with the new device too |

- **Move the files yourself** (scp, USB, a paste). Don't drop them in a sync folder.
- `tswap slots` lists the slots.
- **A machine without a vault:** `slot accept` creates a record vault at `~/.config/tswap/vault`
  (as `init` does). It holds the keyring and no secrets yet. Bring the secrets in with
  `sudo tswap vault merge <copy of the other vault folder>` (see
  [Copying the folder](#copying-the-folder-scp-rsync-or-a-usb-stick)), or join a shared folder
  instead with `tswap slot accept approve.json --vault-dir <shared folder>`.
- **Each machine keeps its own `config.json`.** A copy of a TPM machine's config does not open with
  another machine's TPM: merge receipts instead.
- **A YubiKey for this machine** needs no exchange: plug it in and run `sudo tswap slot add --yubikey`
  ([setup.md](setup.md#setting-up-with-a-yubikey-one-key-per-slot)).

### What `slot merge` adds

- It adds a slot silently only because this machine approved it in step 2.
- Any other new slot is shown by fingerprint and must be confirmed on a terminal, or passed with
  `--yes`.
- To bring in the slots of another copy of a record vault, use `vault merge <its vault folder>`
  ([below](#copying-the-folder-scp-rsync-or-a-usb-stick)): a record vault keeps its keyring in the
  vault folder, and `slot merge` refuses its `config.json` ("neither a slot receipt ... nor a
  keyring vault's config.json").
- It never removes or replaces a slot, and it refuses another vault's files.
- It backs up `config.json` first. Merging the same file twice changes nothing.

### What the guided `init` prints

At the end, the guided `tswap init` asks `Will other machines use this vault?`. Answer yes and it
prints the steps for your vault, as commands for "there" and "here":

- **A machine with a TPM** or **a Mac with a Secure Enclave:** the four steps above, with
  `slot request --tpm request.json` (or `--secure-enclave --with-touch`) and
  `slot accept approve.json --receipt receipt.json`, then `sudo tswap slot merge receipt.json`.
- **A YubiKey for another machine:** `tswap slot request request.json` there, then the same
  approve, accept and merge steps. Or plug the YubiKey into this machine and run
  `sudo tswap slot add --yubikey`.
- **A vault in a folder of its own** (made with `init --folder`): sync the folder to the other
  machine, run `tswap init --vault-dir <its copy of the folder>` there, and optionally give that
  machine's chip a slot with `slot request`, `slot approve` and `slot accept`. The slot goes
  straight into the shared keyring, so there is no merge step.
- On Windows, run the `sudo` steps from an administrator prompt, without `sudo`.

## Remote enrolment of a YubiKey into a TPM vault, step by step

The vault lives on a machine with a TPM (say a router VM), and the YubiKey stays at your desk: no
USB passthrough. Nothing secret crosses between the machines; you carry three small files.

```bash
# 1. Desk machine, YubiKey plugged in (use a separate config folder if this machine has a vault):
TSWAP_CONFIG_DIR=~/.config/tswap-router tswap slot request request.json
#    It prints the new slot's fingerprint. Copy request.json to the router.

# 2. Router: unlock with its TPM and approve (compare the fingerprint it prints):
sudo tswap slot approve request.json approve.json
#    Copy approve.json back to the desk machine.

# 3. Desk machine, same YubiKey plugged in:
TSWAP_CONFIG_DIR=~/.config/tswap-router tswap slot accept approve.json
#    It writes approve.json.receipt.json (or the path given with --receipt <file>).
#    Copy the receipt to the router.

# 4. Router: add the finished slot to the router's own keyring:
sudo tswap slot merge approve.json.receipt.json
```

After step 4 the router's vault opens with its TPM **or** that YubiKey, and a copy of the router's
files on another machine opens with the YubiKey too.

Repeat for each key (the one at the desk, the one in the wallet): each becomes its own slot.

### Without the exchange: the recovery key

The recovery key does it on the desk machine alone, with a copy of the router's vault folder:

1. Copy the router's vault folder to the desk machine, and point a separate config folder at the
   copy:

   ```bash
   TSWAP_CONFIG_DIR=~/.config/tswap-router tswap init --vault-dir <copy of the router's vault folder>
   ```

2. Add the YubiKey there, unlocking with the recovery key:

   ```bash
   sudo tswap get recovery-key | sudo TSWAP_CONFIG_DIR=~/.config/tswap-router tswap slot add --yubikey --recovery-key-stdin
   ```

3. Carry the copy back and merge it into the router, on a terminal:

   ```bash
   sudo tswap vault merge <the copy>
   ```

   The router never approved the new slot, so it shows the slot's fingerprint and asks
   `Add it to this vault? Compare the fingerprint first. (yes/no)`. Compare it with the
   `New slot fingerprint` that step 2 printed. Answering no merges nothing. Without a terminal,
   pass `--yes` instead (`sudo tswap vault merge <the copy> --yes`), after comparing the
   fingerprints yourself.

Afterwards the copy and `~/.config/tswap-router` on the desk machine are a second copy of the vault,
which opens with that YubiKey. tswap leaves them as they are: delete both if you don't need that
copy.

How tswap reads the recovery key: [setup.md](setup.md#the-recovery-key).

## Sharing a vault folder

A record vault keeps one encrypted file per secret in a **vault folder**. A sync tool, a network
share or a plain copy can carry that folder, and two copies of it can be merged.

```bash
# A new vault straight into a synced folder (an absent or empty one):
tswap init --folder ~/OneDrive/tswap-vault

# Another machine joins the same folder:
tswap init --vault-dir ~/OneDrive/tswap-vault        # opens with a YubiKey slot or the recovery key
# ...then, for that machine's own TPM / Secure Enclave slot:
tswap slot request --tpm request.json                # then 'sudo tswap slot approve' on an enrolled machine
tswap slot accept approve.json                       # the new slot goes straight into the shared keyring
# (a machine that hasn't run 'init --vault-dir' can instead finish with
#  'tswap slot accept approve.json --vault-dir ~/OneDrive/tswap-vault')
```

On a machine that has run `init --vault-dir`, `slot request` asks
`This machine already has a config. Overwrite and start a new slot request?`: answer `yes` (the
config keeps its shared folder).

A classic vault from 0.1 is converted first, and can be converted straight into a synced folder:
see [upgrading-from-0.1.md](upgrading-from-0.1.md#what-the-conversion-does).

### What is in the vault folder

- `keyring`: the wrapped vault key, one slot per device.
- `records/<hash>`: one file per secret. The file name is a keyed hash of the secret's name, so
  names never appear on disk.
- Every record is padded to 256-byte size buckets.
- Deletes and burns are records too, so a deleted secret can't come back from an old copy.
- `vault-password`, only when the vault has a vault password. If a sync tool leaves two different
  copies of it, see [Files](commands.md#files).

**Only the vault folder is shared.** Each machine's `config.json` stays in its config folder and
must never be synced. The default vault folder sits inside the config folder, so if you sync the
config folder you sync `config.json` too: give `--vault-dir` a folder of its own and sync that.

### Three ways to share

#### A sync folder

OneDrive, Dropbox, Google Drive, Syncthing, Nextcloud: point `--vault-dir` at a folder the tool
syncs.

- Two machines editing different secrets never conflict.
- When both edit the **same** secret before a sync, the tool keeps a "conflicted copy". tswap
  reads it, and the later change wins. It uses a hybrid logical clock, so a machine with a wrong
  clock can't make an older change win. The copy is removed the next time that secret is written.
- A copy tswap can't decrypt is reported and left alone.
- Mark the folder "available offline". OneDrive Files On-Demand and Google Drive stream files by
  default, and a placeholder can't be read offline.

#### A network share

SMB, NFS: works one machine at a time.

- Writes are flushed and renamed into place, but client caching means an interrupted write can
  still cost the record it was writing.
- A record that can't be read is reported, kept, and never overwritten or treated as deleted until
  you restore it.
- tswap uses no lock files. A command re-reads each record just before writing it; if another
  machine changed it in the meantime, the write is refused and nothing is written.
- Running Samba or NFS in a container changes nothing about this. A sync tool in a container
  (Syncthing, Nextcloud) gives each machine its own local copy and is the better choice.

Why: [Sync transports](#sync-transports).

#### Copying the folder: scp, rsync or a USB stick

Copy the other machine's vault folder anywhere and fold it in:

```bash
sudo tswap vault merge /mnt/usb/tswap-vault
```

- The other copy must be the same vault; it is only read.
- Keyrings are combined slot by slot. A new slot from the other copy is shown by fingerprint and
  must be confirmed, or passed with `--yes`, as with `slot merge`.
- Records are combined by the same rules as conflicted copies (below).
- Merging the same copy twice changes nothing. Run it on the other machine too to bring that copy
  up to date.
- `vault merge` takes `--recovery-key-stdin` too ([commands.md](commands.md#vault)).

### The merge rules

- **The last change wins**, for values and deletes alike. A deleted secret only comes back if
  someone really wrote a value after the delete.
- **A burn marks the value it was issued against.** While that value is current the secret is
  burned. A newer value (a rotation) supersedes it, and the burn becomes history.
- Two burns of the same value keep the earliest.

## Sync transports

tswap never syncs anything itself: it only writes files that a separate sync tool can copy to
other machines. Only a record vault's **vault folder** (`--vault-dir`) may be synced; each machine's
`config.json` stays local.

**The rule: keep the vault folder on local disk, and let a sync tool replicate it** (Dropbox,
OneDrive, Google Drive, Syncthing, Nextcloud, Seafile, ...). Pointing tswap directly at a network
mount (an SMB share, an NFS export, an rclone mount or a WebDAV mount) works one machine at a time
only.

**It is the protocol that matters, not where the server runs.**

- A container on your own NAS running Syncthing, Nextcloud or Seafile is fine: each machine still
  keeps and writes its own local copy, and the sync tool reconciles the copies afterwards.
- A container on that same NAS running Samba or an NFS server gives you what a raw NAS export
  gives you: every read and write goes over the wire, with no local copy in between.
- The same goes for a cloud drive's WebDAV endpoint or an rclone mount instead of its sync client.
  If the vault folder is a mount, not a plain local folder with a sync daemon watching it, treat it
  as a network mount.

**Why network mounts:** with client-side caching over SMB or NFS, a write can complete from the
writing process's point of view, and even rename successfully on the server, while the data never
reached the server. That gives a truncated or zero-length record with a single writer and no
concurrency: a weaker durability guarantee than local disk.

- tswap writes each record file to a temporary file in the same folder, with write-through and a
  flush to disk, then renames it (`TswapCore/Keyring/DurableFileWriter.cs`).
- **That mitigation is unit-tested only for its happy path** (write bytes, read them back,
  byte-exact). Durability under a killed process, or a real SMB or NFS server's flush behaviour,
  has not been tested and isn't claimed.

**A NAS.** If you want a NAS as the sync destination rather than a cloud provider, run a real sync
daemon against it (see above) and treat it as one machine at a time: no offline access on the
other machines, and an interrupted write costs at most one record, not the whole vault. Before
writing a record, tswap re-reads it and refuses the write if another machine changed it in the
meantime (the stale-write guard); that doesn't make two simultaneous writers safe. **NAS setups
have not been tested by this project.** These caveats are what the protocol-level reasoning
predicts, not a verified result: treat a NAS as unsupported until someone tests it.

**No lock files.** tswap doesn't write or honour any lock file. Advisory locking over NFS is
unreliable enough that a lock file would give a false sense of safety. The stale-write guard
catches a conflicting write after the fact instead of preventing it.

**Cloud placeholder files.** Google Drive for Desktop and OneDrive Files On-Demand stream files by
default, leaving a placeholder on disk until something reads the real file. Reads usually fetch it
transparently, but not when the machine is offline: an offline read of a record not fetched yet
fails or returns the wrong thing. **Mark the tswap vault folder "always available offline"** in
your sync client's settings. Google Drive is the worst of the four major providers for this;
OneDrive, Dropbox, and Syncthing or Nextcloud either don't stream on demand by default or make the
setting easy to find.

## Record format 3 and `vault reindex`

Since 0.2 a record has an encrypted **metadata section** (the name, burns, the version list and
keyed fingerprints of every retained value) and one encrypted **value section** per retained value.
The fingerprints cover each form tswap matches (plain, whitespace-stripped, base64 and base64url):
for each, its length, a keyed rolling hash and a truncated keyed HMAC.
Commands that only need names, burns or fingerprints then never decrypt a value.

```bash
sudo tswap vault reindex     # rewrites every record in format 3 with fingerprints; prints counts only
```

- **When:** once, after every machine sharing the folder runs 0.2. Until then a vault keeps writing
  format 2, so machines still on 0.1 can read it. The step is in
  [upgrading-from-0.1.md](upgrading-from-0.1.md#what-to-do).
- `vault reindex` decrypts every value once, inside tswap, rewrites each record that isn't current
  yet (with a new write stamp, so it merges like any other write), and then writes a
  `record-format` marker into the vault folder. From then on every machine sharing the folder
  writes format 3.
- It refuses, writing nothing, when a record can't be read. Running it again rewrites nothing; an
  interrupted run is finished by running it again.
- `vault merge` copies the marker from a reindexed copy. A new vault (`init`, `migrate
  --to-records`) starts in format 3.
- **"Not fully fingerprinted":** a record written in format 2 after the reindex (by a machine still
  on 0.1), a replayed older copy, a format 2 tombstone (its type can't be known without decrypting
  it) or a lingering format 2 sync-conflict copy
  leaves the vault reported this way until a write of that record, a `vault merge` or another
  `vault reindex`. In a folder that writes format 3, `vault merge` rewrites every record it can read
  that isn't format 3 yet, so merging a reindexed copy leaves the folder fully fingerprinted.
- **What a sync provider sees in format 3:** the number of sections per record (retained values
  + 1) and a size bucket per section, where format 2 showed one bucket per record. Since a value
  section stays identical across writes, it can tell a metadata-only write (a burn, a merge) from a
  value change. The fingerprints themselves exist only inside the encrypted metadata sections and
  in tswap's memory ([security-model.md](security-model.md#what-tswap-does-not-protect-against)).

The format itself, its keys and the merge of sections are in the design record:
[Record format 3](design/multi-machine-keying.md#record-format-3-metadata-and-value-sections-brief-t16-s1-v020).

## Limits

Files are carried by hand, there is no revocation and no rotation of the vault key yet: see
[setup.md, Limits of this version](setup.md#limits-of-this-version). The design behind the keyring,
receipts and merge is in [multi-machine-keying.md](design/multi-machine-keying.md).
