# Setting up a vault

This page is for anyone setting up tswap on a machine for the first time. It covers preparing a
YubiKey, the guided `tswap init`, setting up with a YubiKey (its OTP slot or a FIDO2 slot), a TPM
or a Mac's Secure Enclave, the recovery key, and the limits of this version. It ends with the test
procedure for a no-touch Secure Enclave slot on a Mac, with its recorded results.

Install tswap first: [install.md](install.md). What each kind of slot protects against, and how
they compare, is in [security-model.md](security-model.md#posture-per-backend).

## Preparing a YubiKey

Skip this if you won't use a YubiKey, or will use only its FIDO2 slot ([FIDO2 slots](#fido2-slots):
nothing to prepare). A YubiKey's OTP slot is its slot 2, set up for HMAC-SHA1 challenge-response,
and tswap sets it up itself: run `tswap yubikey setup` once on each key. It needs no sudo and no
other tool (what a key needs on each OS: [YubiKey prerequisites](install.md#yubikey-prerequisites)).

With a touch requirement (recommended; every unlock needs a press of the key):

```bash
tswap yubikey setup --touch
```

Without a touch requirement (less secure: no button press):

```bash
tswap yubikey setup --no-touch
```

One of the two flags is required; there is no default. With several keys plugged in, tswap asks
which one at a terminal; a script names it with `--serial N`. tswap programs the slot with a new
random secret, then challenges it once to check that it answers as set up (with `--touch`, touch the
key when it flashes), and prints `YubiKey N slot 2: HMAC-SHA1 challenge-response, touch required`
(or `no touch required`).

**Warning:** programming slot 2 replaces what was there with a new secret. On a key that already
has a slot in a vault, that slot no longer opens the vault (`tswap slots` still lists it); enrol the
key again afterwards, as in [YubiKey: touch or no touch](security-model.md#yubikey-touch-or-no-touch).
So `tswap yubikey setup` guards an occupied slot:

- It refuses a slot 2 that is already set up, and changes nothing, unless you pass `--replace`.
- With `--replace` you type the key's serial to confirm, and it refuses if the vault tswap is
  pointed at would be left without a way in that doesn't need this key. A TPM, Secure Enclave or
  recovery slot counts, or another YubiKey's slot, if that key is plugged in and its slot opens the
  vault when tswap checks it. A legacy pair slot never counts (it doesn't open the vault with one
  key), a classic two-key vault that uses this key is always refused, and a slot this tswap can't
  read (for example one written by a newer tswap) doesn't count. If tswap can't read a vault there,
  it warns and goes on. An empty slot 2 is programmed without these checks: there is nothing on it
  to lose.

The check keeps the vault from being lost outright, not you from being stuck on this machine:
setup can't tell whether you still hold the recovery key, or whether a TPM or Secure Enclave slot
belongs to this machine or another one. Before `--replace`, make sure you have a way in that you
can use here (another enrolled key you can plug in, this machine's TPM or Secure Enclave, or the
recovery key at hand). It checks only the vault tswap is pointed at: a slot this key has in another
vault (another `TSWAP_CONFIG_DIR`) isn't looked at, and stops opening that vault too.

If setup is interrupted, slot 2 may be left programmed but unchecked: `slot add --yubikey` checks
a key before it enrols it, or run setup again with `--replace`.

What the touch requirement protects against, and what a key without it allows:
[security-model.md](security-model.md#yubikey-touch-or-no-touch).

## The guided `tswap init`

Run `tswap init` in a terminal and it asks, in order:

1. **Plug in your keys.** It asks you to plug in the security keys you want to use, then press
   Enter. Don't touch a key yet; tswap says when it needs one.
2. **Pick what to use.** It lists the YubiKeys it finds (by serial number) and this machine's
   chip (the Secure Enclave on a Mac, the TPM on Windows and Linux). Each YubiKey is offered twice,
   as an OTP slot and as a FIDO2 slot, in an order that depends on the OS
   ([Guided `init` on each OS](#guided-init-on-each-os)). You type the numbers you want, for
   example `1 3`.
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
   password doesn't lock you out. More on the password and the agent that holds it:
   [vault-password-and-agent.md](vault-password-and-agent.md).
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

Scripts have no terminal to answer questions, so they name the slot instead. (AI agents shouldn't
run `init`: creating a vault is the user's work, and `init` prints the recovery key, see
[agent-integration.md](agent-integration.md#agent-role-no-sudo).)

```bash
tswap init --yubikey                                   # one plugged-in YubiKey
tswap init --tpm                                       # this machine's TPM
tswap init --secure-enclave --with-touch               # or --no-touch
```

A plain `tswap init` without a terminal is refused and names these flags. `tswap init --fido2`
skips the questions too, but it still needs a person at a terminal to type the key's PIN, so a
script without one is refused ([FIDO2 slots](#fido2-slots)).

## Setting up with a YubiKey (one key per slot)

Prepare each key's slot 2 first ([Preparing a YubiKey](#preparing-a-yubikey)). Then:

```bash
# Script, no terminal: a vault with ONE key plugged in (several plugged in: tswap asks
# which on stderr, and takes the first listed when nothing answers)
tswap init --yubikey          # or: tswap init --yubikey --folder ~/Sync/tswap-vault   (an absent or empty folder)

# Add each spare key as its own slot: plug it in (the first key may stay plugged in) and run
sudo tswap slot add --yubikey
tswap slots                   # lists the slots, with each key's serial
```

What `init` makes:

- Every vault `init` makes (since 0.2) is a **keyring vault** in the **record store**: a random
  vault key wrapped once per slot, and one encrypted file per secret in a vault folder
  (`<config directory>/vault`, or `--folder <dir>`, which must be absent or empty; the config
  directory on each OS: [commands.md](commands.md#files)).
- Each YubiKey is **its own slot**, and any one enrolled key opens the vault alone. There is no XOR
  share to back up.
- `init` also makes a break-glass **recovery slot** and prints its private key once (store it
  offline; `--no-recovery` leaves it out).
- A key's serial, challenge and salt live in its slot, so the vault files plus any one enrolled key
  open the vault on any machine.
- `slot add --yubikey` enrols a plugged-in key that has no slot yet, and backs up `config.json`
  before it writes. Only when every plugged-in key already has a slot does it pick one of them and
  check it: a key with a working slot is refused, and one whose slots no longer open the vault (its
  slot 2 was reprogrammed) is enrolled again: see
  [YubiKey: touch or no touch](security-model.md#yubikey-touch-or-no-touch).

### Several YubiKeys plugged in

When several plugged-in YubiKeys can open the vault, an unlock never waits on a prompt in a script
or an agent's `tswap run`:

- **No terminal** (stdin redirected): tswap tries the keys that have a slot in this vault in this
  order: **no touch first, then unknown, then touch-required**. The first that opens the vault
  wins. (A classic vault takes the first enrolled key that answers.)
  - Why this order: a touch-required key tried first would stall every unattended unlock until its
    touch timed out. With a no-touch key plugged in, an unattended unlock is possible anyway.
  - Only when no key opens the vault does tswap fail, saying why for each key.
- **On a terminal**, tswap asks which key to use, on stderr (stdout stays the command's output),
  and offers the **touch-required key as the default**: plugging in the touch key means "I am here
  and permit this".
- **`TSWAP_YUBIKEY_SERIAL=<serial>`** picks one key explicitly. A serial that isn't plugged in, or
  has no slot in the vault, is an error. `sudo` drops the variable unless you keep it
  (`sudo --preserve-env=TSWAP_YUBIKEY_SERIAL tswap ...`); that is intended.

Enrolling a key (`init`, `slot add`, `slot request`) still asks which key to enroll when several
qualify (on stderr). With nothing to answer (stdin at its end), it takes the first key listed.
`TSWAP_YUBIKEY_SERIAL` picks the key for an unlock (and for the entropy below), not for an
enrolment.

`tswap init --yubikey` asks for the entropy source: `[1] System RNG` (the default) or
`[2] YubiKey`; the guided `tswap init` always uses the system's. On a vault with **YubiKey
entropy**, `create` (and `rotate`) ask a key for randomness too. Unattended they take the first
plugged-in key, without looking at the touch setting: if that is a touch-required key, the command
waits for its touch (unplug it, or set `TSWAP_YUBIKEY_SERIAL`, for a scripted `create`).

Keyring vaults made by an older tswap with a **YubiKey pair** (two keys, an XOR share) keep working
as they are. A pair vault whose keyring is format version 2 cannot take new slots. To give each key
its own slot, create a new vault with `tswap init --yubikey` (or the guided `tswap init`) and move
the secrets across.

## FIDO2 slots

A YubiKey can open a vault in two ways, and each is a slot of its own:

- **The OTP slot** (`--yubikey`): the key's slot 2, HMAC-SHA1 challenge-response
  ([Preparing a YubiKey](#preparing-a-yubikey)). No PIN; a touch if slot 2 was set up with one.
- **The FIDO2 slot** (`--fido2`): a FIDO2 credential on the key, with the hmac-secret extension.
  The key's FIDO2 PIN and a touch on every unlock.

### Why a FIDO2 slot

- **On a Mac it needs no Input Monitoring.** The OTP slot reaches the key through its keyboard
  interface, so macOS asks for Input Monitoring for the terminal app, and that lets every program
  the terminal runs read your keystrokes. The FIDO interface isn't a keyboard, so macOS asks for
  nothing.
- **It is meant to behave the same on Linux, macOS and Windows**, so that a FIDO2 slot made on one
  OS opens the vault on the others, wherever the vault folder goes. That is the design; what is
  verified so far is a spike on one key, in which one credential gave the same output on Linux and
  on Windows. Nothing of this build has run on macOS yet, and the cross-OS directions with this
  build are still to be checked on real keys.
- **There is nothing to prepare** on the key besides its FIDO2 PIN, which tswap offers to set when
  the key has none (Linux and macOS).

### PIN and touch on every unlock

Every FIDO2 enrolment and every FIDO2 unlock asks for the key's PIN and a touch. There is no
PIN-free mode: the key gives a different secret with and without PIN verification, and Windows'
dialog always verifies the PIN, so PIN and touch is the only way one slot opens on every OS. The
PIN is the key's own FIDO2 PIN (the one websites ask for), not a tswap password.

- **Linux and macOS:** tswap asks at the terminal, `FIDO2 PIN for YubiKey N: `, without echo. It
  reads the PIN from the terminal itself (`/dev/tty`), not from stdin, so `--recovery-key-stdin`
  works alongside. Once the PIN is typed it says `Touch your YubiKey when it blinks.`
- **Windows:** Windows' security key dialog asks for the PIN and the touch; tswap says
  `Follow Windows' security key dialog: the key's PIN, then a touch.` The dialog owns PIN entry:
  tswap can't count the tries there, and the dialog may ask for the PIN again after a wrong one
  within the same unlock. The dialog also picks the key, so `--serial` is refused on Windows.
- **Enrolment** is two key operations, each a PIN and a touch: making the credential, then opening
  it once to wrap the vault key.
- **A wrong PIN is never retried by tswap.** It stops and shows the key's remaining tries, for
  example: `YubiKey N: wrong FIDO2 PIN; 7 tries left before this key's FIDO2 is blocked (a key
  allows 8 wrong PINs in all). After three wrong PINs in a row, unplug the key and plug it in again
  before the next try.` Eight wrong PINs in all block the key's FIDO2 until a FIDO2 reset, which
  deletes every FIDO2 credential on it (below).
- **tswap never changes a PIN and never resets a key.** The one PIN it writes is a first one: on
  Linux and macOS a key without a FIDO2 PIN gets `YubiKey N has no FIDO2 PIN; a FIDO2 slot needs
  one. Set a FIDO2 PIN on it now? (yes/no): ` at enrolment, then the new PIN twice (at least 4
  characters). On Windows the dialog asks you to create one.
- **FIDO2 slots are tried last**, because PIN tries are limited: after every slot that needs no
  PIN, the vault-password agent and the vault-password prompt. On Linux and macOS tswap first
  checks silently (no PIN, no touch) which plugged-in key holds a slot's credential, and asks for a
  PIN only then; a slot whose key isn't plugged in gets `The FIDO2 slot of YubiKey N: plug it in.`
  On Windows the dialog opens only after the other slots fail, and offers every FIDO2 slot of the
  vault at once: the key you pick decides which slot opens.
- **One FIDO2 PIN per run.** If the first FIDO2 slot tried fails, the others are not tried in that
  run (`Another FIDO2 slot of this vault wasn't tried: tswap asks for one FIDO2 PIN per run. Run
  the command again with that key.`).

### No terminal, no FIDO2

A FIDO2 slot needs a person at a terminal. Without one (a script, CI, an AI agent's `tswap run`),
FIDO2 slots are skipped at unlock with no key call and no dialog, on Windows too, and an enrolment
is refused before any key call:
`A FIDO2 slot needs a person at a terminal to type the key's PIN and touch the key; there is no
terminal here, so the key was not used.` On Linux and macOS "a terminal" means `/dev/tty` opens;
on Windows, that stdin, stdout or stderr is a console. A vault whose only way in is a FIDO2 slot
therefore can't be used unattended: give the machine another slot (a TPM, the Secure Enclave, or
a YubiKey OTP slot) for that.

### Adding a FIDO2 slot

```bash
tswap init --fido2                     # a new vault: one YubiKey's FIDO2 slot, plus the recovery slot
tswap init --fido2 --serial 12345678   # several keys plugged in (Linux, macOS; without it tswap asks)
sudo tswap slot add --fido2            # a key's FIDO2 slot in this vault (Windows: elevated prompt)
tswap slots                            # YubiKey 12345678, FIDO2: PIN + touch, no password
```

- `--password` / `--no-password` work as for the other slot kinds; a FIDO2 password slot mixes the
  vault password into its key derivation, as a YubiKey OTP slot does, and asks for the password
  before the PIN. `init --fido2` takes `--no-recovery`; `slot add --fido2` takes
  `--recovery-key-stdin`.
- A key has at most one FIDO2 slot per vault. On Linux and macOS a second is refused by a silent
  check (no PIN, no touch) before the vault is unlocked: ``YubiKey N: this key already has a FIDO2
  slot in this vault (one per key; `tswap slots` lists them). No slot was added.`` Windows can't
  check keys silently, so there the key itself refuses, once the vault is open, after the dialog;
  Windows names no serial or model, so the text is ``The key you picked: this key already has a
  FIDO2 slot in this vault (one per key; `tswap slots` lists them). No slot was added.`` A key's OTP
  slot and its FIDO2 slot are separate and may both exist.
- After each FIDO2 enrolment tswap prints what a FIDO2 reset does (below).
- If the second key operation fails, nothing is written, and running the command again is safe
  (the key keeps an unused credential, which on a YubiKey takes no space).
- A FIDO2 slot isn't made through `slot request` and `slot approve`: add it with
  `tswap slot add --fido2` on a machine that can open the vault. Once it is in the keyring it opens
  the vault on any machine that has the vault folder and the key, like an OTP slot.
- `tswap slots` shows a FIDO2 slot by its key's serial, or by its model when the key reported no
  serial (`Security Key NFC by Yubico, FIDO2: PIN + touch, no password`). When the vault has a
  password slot, it counts the password-free FIDO2 slots on their own line:
  `N FIDO2 slot(s) open without the vault password (each still needs its key's FIDO2 PIN and a
  touch).`

### Guided `init` on each OS

The guided `tswap init` offers each plugged-in YubiKey as an OTP slot and as a FIDO2 slot. Picking
both gives one key two slots; either opens the vault.

- **Linux:** for each key, `YubiKey N, OTP slot (no PIN)`, then `YubiKey N, FIDO2 slot (PIN +
  touch)`; then the TPM.
- **macOS:** for each key the FIDO2 slot first, `YubiKey N, FIDO2 slot (PIN + touch; preferred on a
  Mac: no Input Monitoring needed)`, then `YubiKey N, OTP slot (no PIN; needs Input Monitoring for
  the terminal)`; then the Secure Enclave.
- **Windows:** the TPM, the OTP slots, then one entry, `a YubiKey's FIDO2 slot (Windows' dialog:
  pick the key, PIN, touch)`. tswap can't list FIDO2 keys on Windows; the dialog picks the key,
  twice per slot (making the credential, then opening it).
- A FIDO-only key (the Security Key series has no OTP interface) is offered as a FIDO2 slot only,
  after the others, by its model name when it reports no serial.
- Under the list, on every OS, when a FIDO2 slot is offered: `Using a key on other machines too? An
  OTP slot needs Input Monitoring for the terminal on a Mac and Yubico's udev rule on Linux. A FIDO2
  slot needs no Input Monitoring on a Mac and, on Linux, no extra rule on current systemd
  distributions (otherwise Yubico's udev rule); it asks for the key's FIDO2 PIN and a touch on every
  unlock, and a FIDO2 slot enrolled on one OS opens the vault on the others. Pick both for one key to
  give it two slots; either opens the vault.`
- FIDO2 slots are made after the chip and the OTP slots. Without a terminal for the PIN, the list
  says `FIDO2 slots: not offered (...)` with the reason.

### OTP, FIDO2, or both

| | OTP slot (`--yubikey`) | FIDO2 slot (`--fido2`) |
|---|---|---|
| Each unlock | A touch if slot 2 requires one; nothing otherwise | The key's FIDO2 PIN and a touch |
| Unattended (scripts, agents, the broker) | Yes, with a no-touch key | Never |
| Linux | Yubico's udev rule | The key's FIDO interface (see [install.md](install.md#yubikey-prerequisites)) |
| macOS | Input Monitoring for the terminal app | Nothing |
| Windows | Nothing | Windows' security key dialog |
| Preparing the key | `tswap yubikey setup` | A FIDO2 PIN (offered at enrolment) |
| What kills the slot | Reprogramming slot 2 | A FIDO2 reset |

With both, an unlock tries the OTP slot first (no PIN) and the FIDO2 slot only when nothing else
opens the vault: on a Mac without Input Monitoring the OTP slot fails and the FIDO2 slot opens it.
Every OTP enrolment ends with a hint to add a FIDO2 slot too if the key will be used on a Mac.

### A FIDO2 reset kills the slot

Resetting a key's FIDO2 application (for example to clear its website passkeys, or after a blocked
PIN) deletes every FIDO2 credential on it, and with it the key's FIDO2 slot in every vault, the
same way reprogramming slot 2 kills an OTP slot. tswap says so after each enrolment:
``A FIDO2 reset of YubiKey N deletes this slot's credential and kills the slot: it can't open the
vault again. Then re-enrol the key with `tswap slot add --fido2`, opening the vault another way.``

At unlock a reset key is reported, not mistaken for a wrong PIN: ``YubiKey N is plugged in but no
longer holds this slot's credential: a FIDO2 reset deleted it, and the slot can't be opened again.
Enrol the key again with `tswap slot add --fido2`.`` To re-enrol, open the vault another way:
another slot, or the recovery key with `--recovery-key-stdin` ([The recovery key](#the-recovery-key)).

The two slot kinds don't touch each other: a FIDO2 reset leaves slot 2 alone, and
`tswap yubikey setup --replace` leaves FIDO2 credentials alone. So `setup --replace` counts a FIDO2
slot, this key's included, as a way in, but only if it opens the vault now: it checks the other
keys' OTP slots first, then says `Checking that the vault's FIDO2 slot still opens it (the key's
FIDO2 PIN and a touch)...` and asks for the PIN and a touch.

### Which keys

- **YubiKeys only, for now.** tswap checks the model id (AAGUID) in each new credential against
  Yubico's published list: the YubiKey 5 series (with NFC, Nano, 5Ci, FIPS, CCN and Enhanced PIN
  models), the Bio series and the Security Key series.
- **FIDO-only YubiKeys** (the Security Key series, the Bio FIDO Edition) have no OTP slot and may
  report no serial; tswap then names them by model. They are supported but not yet tested on real
  hardware. On a Bio, tswap asks for the PIN on Linux and macOS (it doesn't use the fingerprint).
- **Other brands are refused** (issue [#193](https://github.com/stevedcc/TokenSwap/issues/193)). On
  Linux and macOS tswap doesn't list them (`No YubiKey with FIDO2 detected. Please insert
  YubiKey.`); on Windows the refusal comes after the dialog: `This security key is not a YubiKey
  (its FIDO2 model id is ...): FIDO2 slots work with YubiKeys only for now (other keys: issue #193).
  No slot was added.`
- **Windows** needs its WebAuthn API at version 4 or later; an older one is refused before any
  dialog (`Windows' WebAuthn API on this machine is too old for FIDO2 slots (version N; needs 4).`).

### The broker can't use a FIDO2 slot

`broker serve` runs without a terminal, so it refuses to start when this machine's own slot is a
FIDO2 slot: `This machine's slot of the vault is a FIDO2 slot, and FIDO2 slots need a PIN and a
touch on every unlock, so the broker can't use it. The broker needs this machine's own slot to be a
TPM or Secure Enclave slot: give it one with 'tswap slot request --tpm' (or '--secure-enclave'), or
run the broker on a machine that has one.` A broker whose own slot is a TPM or Secure Enclave slot
skips the vault's FIDO2 slots without touching a key.

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
sudo tswap slot add --yubikey     # its OTP slot; or --fido2 for its FIDO2 slot (see FIDO2 slots)
```

Each key becomes its own slot, which opens the vault on its own (for example on a laptop with a
copy of the vault files, or if the TPM is replaced).

## Adding another machine

Another machine joins the vault with four `slot` commands and files you carry yourself: see
[multi-machine.md](multi-machine.md#joining-another-machine).

## The recovery key

The guided `init`, `init --yubikey`, `--tpm` and `--secure-enclave` print a **recovery private
key** once. It opens the vault without any enrolled hardware.

tswap reads it **only from stdin**: never from an argument, the environment or a file path. Pipe it
from wherever you keep it. Stdin must be the base64 key alone; surrounding whitespace is fine.

The examples below keep it as the secret `recovery-key` in **another vault** you can still open,
your main vault, whose config folder `TSWAP_CONFIG_DIR` names on the `get` side. A vault's own
recovery key can't come out of that vault when its hardware is lost: keep the key somewhere that
doesn't depend on that vault (`init` says to store it offline).

```bash
# Total hardware loss (TPM cleared, keys lost): enroll new hardware as a new slot
sudo TSWAP_CONFIG_DIR=<main vault's config folder> tswap get recovery-key | sudo tswap recover --yubikey
#   (or --tpm / --secure-enclave --with-touch|--no-touch)

# Or unlock with it for a keyring change
sudo TSWAP_CONFIG_DIR=<main vault's config folder> tswap get recovery-key | sudo tswap slot add --yubikey --recovery-key-stdin
```

If the vault you recover isn't in the default config folder, set `TSWAP_CONFIG_DIR` on the
`recover` (or `slot add`) side too, to that vault's config folder: a different value from the
`get` side's.

tswap's own messages show the short form `sudo tswap get recovery-key | sudo tswap recover
--yubikey`, with no `TSWAP_CONFIG_DIR`. That form works only when the `get` side can still open the
vault it reads. When that vault's hardware is lost, point the `get` side at another vault, as the
examples do.

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
Claims (a), (b) and (c) below are points 1, 2 and 3 of the `--no-touch` warning, as listed in
[security-model.md](security-model.md#secure-enclave-touch-or-no-touch). Steps 1 and 2 check claim
(a) (no prompt), step 5 checks (b), and no step checks (c).

Run by the owner on a real Mac before release; **every result is recorded, none is predicted**.
**Release gate (v0.1.0):** steps 1-3, 5 (both halves: claim (b)) and 8 had to be recorded before
v0.1.0. The gate was **met** on 2026-10-31 (#157): no result contradicted a claim, and the root half
of step 5 ran on the vault itself, not on a root-owned copy. If a recorded step contradicts a
warning claim (a)-(c), the warning text and its test assertions are corrected before release, not
only the docs.

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
   — does it unlock? (If tswap refuses on a permission or ownership error rather than the Secure
   Enclave, record the message: it is not an answer to (b).)
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

**Brief T12 (under sudo the Secure Enclave runs as the folder's owner), recorded on the same Mac with a Release (NativeAOT) build of `24f584b`:** `sudo tswap names` on a `--with-touch` vault asks for the user's Touch ID (before T12 it showed the "System Administrator" password dialog and failed); `sudo tswap recover --secure-enclave --with-touch` enrols without a root dialog and the new slot unlocks for the user; `--no-touch` under sudo shows no prompt; without sudo nothing changed. A slot made as root by the older build (`recover` under sudo with `eb02143`) still opens under the T12 build, asking for the user's Touch ID with no root dialog, so the remedy in [security-model.md](security-model.md#under-sudo-the-secure-enclave-asks-you-not-root) (run `recover` again) isn't needed for that case. Not run: a second admin account (none on that Mac). So `seteuid` to the owner is enough for LocalAuthentication on the tested paths; the forked-`setuid` fallback (a child process that switches to the owner with a real `setuid`; [design record](design/hardware-backends.md#under-sudo-used-as-the-vault-folders-owner-not-root-brief-t12-issue-157)) is not needed for them (a second admin account was not available to test).
