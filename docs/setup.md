# Setting up a vault

This page is for anyone setting up tswap on a machine for the first time. It covers preparing a
YubiKey, the guided `tswap init`, setting up with a YubiKey, a TPM or a Mac's Secure Enclave, the
recovery key, and the limits of this version. It ends with the test procedure for a no-touch
Secure Enclave slot on a Mac, with its recorded results.

Install tswap first: [install.md](install.md). What each kind of slot protects against, and how
they compare, is in [security-model.md](security-model.md#posture-per-backend).

## Preparing a YubiKey

Skip this if you won't use a YubiKey. tswap uses a YubiKey's slot 2, set up for HMAC-SHA1
challenge-response. Set it up once on each key, with `ykman` (installing it:
[YubiKey prerequisites](install.md#yubikey-prerequisites)).

With a touch requirement (recommended; it requires a button press):

```bash
ykman otp chalresp --generate --touch 2
```

Without a touch requirement (less secure: no button press):

```bash
ykman otp chalresp --generate 2
```

What the touch requirement protects against, and what a key without it allows:
[security-model.md](security-model.md#yubikey-touch-or-no-touch).

## The guided `tswap init`

Run `tswap init` in a terminal and it asks, in order:

1. **Plug in your keys.** It asks you to plug in the security keys you want to use, then press
   Enter. Don't touch a key yet; tswap says when it needs one.
2. **Pick what to use.** It lists the YubiKeys it finds (by serial number) and this machine's
   chip (the Secure Enclave on a Mac, the TPM on Windows and Linux). You type the numbers you
   want, for example `1 3`.
   - Any mix works: two YubiKeys and the chip, only keys, only the chip. tswap never picks
     hardware for you.
   - A chip it can't use is listed with the reason.
   - A YubiKey is listed by serial. If it turns out to be blocked (a Mac that blocks its OTP
     interface, say), tswap explains why when its challenge fails at step 5, and tells you what to
     allow in System Settings.
   - For the Secure Enclave you also choose whether every unlock asks for Touch ID or your login
     password, or none.
3. **Vault password (optional).** One password for the vault. If you add it and picked more than
   one slot (without `--password`), you choose which of them need it. A slot left out opens the
   vault without the password, for example a backup key you keep somewhere safe, so a forgotten
   password doesn't lock you out.
4. **Recovery slot.** Added by default. Its private key is shown once, so store it offline (see
   [The recovery key](#the-recovery-key)).
5. **Create.** tswap builds every slot, then writes the vault in one step.
   - If a key can't be used, it says why and asks whether to carry on without it. Nothing is
     written before you answer, and answering no writes nothing.
   - If the chip fails, nothing is written.
   - A YubiKey flashes when it wants a touch, and the prompt names the key (with several plugged
     in, touch the flashing one).
6. **Other machines?** Answer yes and tswap prints a step-by-step guide, with this vault's real
   folder and commands, for adding your other machines.

`init` never overwrites a vault. Before it asks anything, it refuses:

- a config folder that holds a classic vault (from tswap 0.1: see
  [upgrading-from-0.1.md](upgrading-from-0.1.md));
- a `config.json` that belongs to a record vault (wherever its folder is);
- a vault folder that isn't empty.

It checks all three again just before the write.

`--folder <dir>` sets where the vault goes (there is no question for it). Other flags answer a
question up front; they are listed in [commands.md](commands.md#init).

### Without a terminal

Scripts and agents have no terminal to answer questions, so they name the slot instead:

```bash
tswap init --yubikey                                   # one plugged-in YubiKey
tswap init --tpm                                       # this machine's TPM
tswap init --secure-enclave --with-touch               # or --no-touch
```

A plain `tswap init` without a terminal is refused and names these flags.

## Setting up with a YubiKey (one key per slot)

Prepare each key's slot 2 first ([Preparing a YubiKey](#preparing-a-yubikey)). Then:

```bash
# Script or agent, no terminal: a vault with ONE key plugged in (several plugged in: tswap asks which;
# TSWAP_YUBIKEY_SERIAL picks one)
tswap init --yubikey          # or: tswap init --yubikey --folder ~/Sync/tswap-vault   (an absent or empty folder)

# Add each spare key as its own slot: plug it in (the first key may stay plugged in) and run
sudo tswap slot add --yubikey
tswap slots                   # lists the slots, with each key's serial
```

What `init` makes:

- Every vault `init` makes (since 0.2) is a **keyring vault** in the **record store**: a random
  vault key wrapped once per slot, and one encrypted file per secret in a vault folder
  (`~/.config/tswap/vault`, or `--folder <dir>`, which must be absent or empty).
- Each YubiKey is **its own slot**, and any one enrolled key opens the vault alone. There is no XOR
  share to back up.
- `init` also makes a break-glass **recovery slot** and prints its private key once (store it
  offline; `--no-recovery` leaves it out).
- A key's serial, challenge and salt live in its slot, so the vault files plus any one enrolled key
  open the vault on any machine.
- `slot add --yubikey` refuses a key that already has a slot, and backs up `config.json` before it
  writes.

### Several YubiKeys plugged in

When several plugged-in YubiKeys can open the vault, an unlock never waits on a prompt in a script
or an agent's `tswap run`:

- **No terminal** (stdin redirected): tswap tries the keys that have a slot in this vault, the ones
  that need **no touch first, then unknown, then touch-required**, and the first that opens the
  vault wins (a classic vault takes the first enrolled key that answers). A touch-required key
  tried first would stall every unattended unlock until its touch timed out; with a no-touch key
  plugged in, an unattended unlock is possible anyway. Only when none opens it does tswap fail,
  saying why for each key.
- **On a terminal**, tswap asks which key to use, on stderr (stdout stays the command's output),
  and offers the **touch-required key as the default**: plugging in the touch key means "I am here
  and permit this".
- **`TSWAP_YUBIKEY_SERIAL=<serial>`** picks one key explicitly. A serial that isn't plugged in, or
  has no slot in the vault, is an error. `sudo` drops the variable unless you keep it
  (`sudo --preserve-env=TSWAP_YUBIKEY_SERIAL tswap ...`); that is intended.

Enrolling a key (`init`, `slot add`, `slot request`) still asks which key to enroll when several
qualify (on stderr).

`create` (and `rotate`) on a vault with **YubiKey entropy** (`init`'s entropy choice 2) asks a key
for randomness too. Unattended it takes the first plugged-in key, without looking at the touch
setting: if that is a touch-required key, the command waits for its touch (unplug it, or set
`TSWAP_YUBIKEY_SERIAL`, for a scripted `create`).

Keyring vaults made by an older tswap with a **YubiKey pair** (two keys, an XOR share) keep working
as they are. A pair vault whose keyring is format version 2 cannot take new slots. To give each key
its own slot, create a new vault with `tswap init --yubikey` (or the guided `tswap init`) and move
the secrets across.

## Setting up with a TPM or the Secure Enclave

```bash
# Linux/Windows with a TPM 2.0 (Linux needs tpm2-tools), or a Mac's Secure Enclave
tswap init --tpm              # or: tswap init --secure-enclave --with-touch   (or --no-touch, below)
```

What `init` makes:

- A **keyring vault**: a random vault key wrapped by this machine's TPM or Secure Enclave (the
  machine slot), plus a break-glass **recovery slot**.
- `init` prints the recovery private key once; store it offline (tswap never saves it).
  `--no-recovery` leaves the recovery slot out.
- `--tpm`, `--secure-enclave` and `--yubikey` cannot be combined. To set up several unlock methods
  in one run, use the guided `tswap init`.

What a TPM slot and a Secure Enclave slot protect against, and their review status:
[security-model.md](security-model.md#posture-per-backend).

### Secure Enclave: `--with-touch` or `--no-touch`

`--secure-enclave` needs exactly one of these, on `init`, `slot request` and `recover` alike; there
is no default:

- `--with-touch`: every unlock asks for Touch ID or the login password.
- `--no-touch`: no prompt.

Read what `--no-touch` trades away before you choose it:
[security-model.md](security-model.md#secure-enclave-touch-or-no-touch). Under sudo, Touch ID asks
the vault folder's owner, not root; the cases where that matters are in
[security-model.md](security-model.md#under-sudo-the-secure-enclave-asks-you-not-root).

### Letting your YubiKeys open this vault too

Plug each YubiKey into **this** machine and run:

```bash
sudo tswap slot add --yubikey
```

Each key becomes its own slot, which opens the vault on its own (for example on a laptop with a
copy of the vault files, or if the TPM is replaced).

## Adding another machine

Another machine can join the same vault in four steps:

1. `tswap slot request` on the new machine: with one YubiKey plugged in, or `--tpm` /
   `--secure-enclave --with-touch|--no-touch` for its own TPM or Secure Enclave.
2. `sudo tswap slot approve` on this one.
3. `tswap slot accept` back on the new one. It writes a receipt.
4. `sudo tswap slot merge <receipt>` on this one again, so this machine's copy opens with the new
   device too.

Move the files yourself (scp, USB). `tswap slots` lists the slots.

On a machine without a vault, `slot accept` creates a record vault at `~/.config/tswap/vault` (as
`init` does) holding the keyring and no secrets yet. Bring the secrets in with
`sudo tswap vault merge <copy of the other vault folder>`, or use
`tswap slot accept <file> --vault-dir <shared folder>` to join a shared folder instead.

## The recovery key

The guided `init`, `init --yubikey`, `--tpm` and `--secure-enclave` print a **recovery private
key** once. It opens the vault without any enrolled hardware.

tswap reads it **only from stdin**: never from an argument, the environment or a file path. Pipe it
from wherever you keep it, for example a secret in your main vault. Stdin must be the base64 key
alone; surrounding whitespace is fine.

```bash
# Total hardware loss (TPM cleared, keys lost): enroll new hardware as a new slot
sudo tswap get recovery-key | sudo tswap recover --yubikey     # or --tpm / --secure-enclave --with-touch|--no-touch

# Or unlock with it for a keyring change
sudo tswap get recovery-key | sudo tswap slot add --yubikey --recovery-key-stdin
```

`slot approve` and `slot merge` take `--recovery-key-stdin` too. A wrong or malformed key is
refused with one message and nothing is written; the recovery slot always stays.

## Limits of this version

- The keyring and record-store formats are new and may still change before they are declared
  stable (a change comes with a new format version that older builds refuse with a clear error).
- Move `slot request` / `slot approve` / receipt files yourself (scp, USB, paste); don't drop them
  in a sync folder. Automating that exchange is later work.
- There is no revocation and no rotation of the vault key yet: removing a lost or compromised
  machine or key means re-initialising the vault and moving the secrets across.

**Vaults made by `tswap init --tpm` or `--secure-enclave` before keyring vaults** (one sealed key,
no keyring) keep working unchanged, but are not migrated automatically. To move one to a keyring
vault, re-create it with `tswap init --tpm` (or `--secure-enclave`) and re-add your secrets.

## Checking a no-touch Secure Enclave slot on a Mac

This is a test procedure, not a setup step: the checks behind the `--no-touch` warning, and their
recorded results. Its design context is in
[hardware-backends.md](design/hardware-backends.md#touch-or-no-touch-an-explicit-choice-brief-t11).
Claims (a)-(c) below are the three points of the `--no-touch` warning, listed as 1-3 in
[security-model.md](security-model.md#secure-enclave-touch-or-no-touch).

Run by the owner on a real Mac before release; **every result is recorded, none is predicted**.
**Release gate:** v0.1.0 waits until steps 1-3, 5 (both halves: claim (b)) and 8 are recorded (**met** on 2026-10-31, #157; no result contradicted a claim; the root half of step 5 ran on the vault itself, not on a root-owned copy). If a
recorded step contradicts a warning claim (a)-(c), the warning text and its test assertions are
corrected before release, not only the docs.

Setup (an unsigned local build and a throwaway config folder; never your real vault):

```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-arm64
BIN="$PWD/TswapCli/bin/Release/net10.0/osx-arm64/publish"   # tswap + libtswapse.dylib
T="$BIN/tswap"
export TSWAP_CONFIG_DIR="$(mktemp -d)"                      # the no-touch vault (steps 1-7)
sw_vers -productVersion                                     # record: macOS version
sysctl -n machdep.cpu.brand_string                          # record: the chip
sysadminctl -screenLock status 2>&1                         # record: "require password after screen saver/sleep"
                                                            # (or read it in System Settings > Lock Screen)
```

1. `"$T" init --secure-enclave --no-touch --no-recovery` — does the warning show (all three
   claims)? Is there any prompt?
2. `"$T" create t11-check`, then `"$T" names` — any prompt? Is `t11-check` listed?
3. A fresh folder with the touch posture:
   `TOUCH_DIR="$(mktemp -d)"; TSWAP_CONFIG_DIR="$TOUCH_DIR" "$T" init --secure-enclave --with-touch --no-recovery`,
   then `TSWAP_CONFIG_DIR="$TOUCH_DIR" "$T" names` — does it prompt? (The only real-hardware run of
   `tswap_se_wrap_v2` with `1`.)
4. Screen unlocked, same user over ssh:
   `ssh localhost "TSWAP_CONFIG_DIR='$TSWAP_CONFIG_DIR' '$T' names"` — does step 2's vault unlock?
5. Claim (b). Another local account (`other` below), with a copy of the config folder and binary it
   can read: `sudo mkdir -p /Users/Shared/t11 && sudo cp -R "$TSWAP_CONFIG_DIR" /Users/Shared/t11/vault && sudo cp "$BIN/tswap" "$BIN/libtswapse.dylib" /Users/Shared/t11/ && sudo chown -R other /Users/Shared/t11`,
   then `sudo -u other env TSWAP_CONFIG_DIR=/Users/Shared/t11/vault /Users/Shared/t11/tswap names`
   — does it unlock? Then as root, with a root-owned copy:
   `sudo cp -R "$TSWAP_CONFIG_DIR" /var/root/t11-vault && sudo env TSWAP_CONFIG_DIR=/var/root/t11-vault "$T" names`
   — does it unlock? (If tswap refuses because of file ownership rather than the Secure Enclave,
   record the message: that is the ownership check, not an answer to (b).)
6. Screen locked, from another machine: `ssh <this-mac> "TSWAP_CONFIG_DIR='$TSWAP_CONFIG_DIR' '$T' names"`
   — does it unlock?
7. After a reboot, before anyone logs in, from another machine over ssh (if Remote Login is on):
   the same command — does it unlock?
8. Skew: a copy of the publish folder with a dylib built from the pre-T11 Swift source:
   `OLD="$(mktemp -d)"; cp "$BIN/tswap" "$OLD/"; git show 4f321a0:TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift > "$OLD/old.swift"; swiftc -emit-library -O -o "$OLD/libtswapse.dylib" "$OLD/old.swift"`
   (`4f321a0` is the last commit on `main` that changed the Swift source before T11; `main` is
   never rewritten, so it stays valid after this brief is merged. The release tags `v0.0.1` and
   `v0.0.2` predate the shim and can't be used),
   then `TSWAP_CONFIG_DIR="$(mktemp -d)" "$OLD/tswap" init --secure-enclave --with-touch --no-recovery`
   — does it fail with "update libtswapse.dylib together with tswap", and is no config written?
9. Steps 4, 6 and 7 again against step 3's touch vault (`TSWAP_CONFIG_DIR="$TOUCH_DIR"`).

Clean up afterwards: `rm -rf "$TSWAP_CONFIG_DIR" "$TOUCH_DIR" "$OLD"; sudo rm -rf /Users/Shared/t11 /var/root/t11-vault`.

| Step | What | Recorded |
|---|---|---|
| — | macOS version, chip, "require password after screen saver/sleep" setting | macOS 27.2 (26B123), Apple M4 Pro, Swift 6.4, .NET SDK 10.0.403; lock setting not recorded (2026-10-31, #157) |
| 1 | `init --no-touch`: warning shown? any prompt? | warning shown, no prompt |
| 2 | `create` + `names`: any prompt? name listed? | no prompt; listed (also `add`/`get`/`list` with zero Touch ID prompts) |
| 3 | `init --with-touch` + `names`: prompt? | Touch ID on every unlock |
| 4 | no-touch vault, ssh, screen unlocked: unlocks? | not run |
| 5 | no-touch vault, another account with a copy: unlocks? | yes, with no prompt: a copy in `/Users/Shared/t11`, `chown -R nobody`, then `sudo -u nobody … tswap names` listed the secret, exit 0 (claim (b) confirmed) |
| 5 | no-touch vault, root with a copy: unlocks? | under `sudo` (root) the user's no-touch vault unlocked with no dialog (the vault itself, not a root-owned copy) |
| 6 | no-touch vault, ssh, screen locked: unlocks? | not run |
| 7 | no-touch vault, ssh, after reboot before login: unlocks? | not run |
| 8 | new binary + pre-T11 dylib: "update together" error, nothing written? | yes: with `libtswapse.dylib` built from the pre-T11 Swift source (`4f321a0`), `init --secure-enclave --with-touch` failed with "libtswapse.dylib beside tswap is older than tswap (it has no tswap_se_wrap_v2). No key was created: update libtswapse.dylib together with tswap…", exit 1, no files written |
| 9 | touch vault: step 4 / step 6 / step 7 | not run |

**Brief T12 (under sudo the Secure Enclave runs as the folder's owner), recorded on the same Mac with a Release (NativeAOT) build of `24f584b`:** `sudo tswap names` on a `--with-touch` vault asks for the user's Touch ID (before T12 it showed the "System Administrator" password dialog and failed); `sudo tswap recover --secure-enclave --with-touch` enrols without a root dialog and the new slot unlocks for the user; `--no-touch` under sudo shows no prompt; without sudo nothing changed. A slot made as root by the older build (`recover` under sudo with `eb02143`) still opens under the T12 build, asking for the user's Touch ID with no root dialog, so decision 6's remedy (run `recover` again) isn't needed for that case. Not run: a second admin account (none on that Mac). So `seteuid` to the owner is enough for LocalAuthentication on the tested paths; the forked-`setuid` fallback is not needed for them (a second admin account was not available to test).
