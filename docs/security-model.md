# Security model

This page is for anyone deciding whether tswap fits their setup, or checking what a given vault
protects against. It covers the sudo split, the threat model and its non-goals, what each kind of
slot needs to unlock, the touch posture, what the vault password does and doesn't protect, and what
a synced vault folder can't detect yet.

The broker has its own threat model: [broker-threat-model.md](broker-threat-model.md).

## The sudo split

tswap draws a privilege boundary with sudo:

- Commands that **use** secrets don't need sudo.
- Commands that **reveal** a value, remove or replace a value that is still good, or administer the
  vault need sudo.

The list of which command needs sudo, subcommand by subcommand, is in
[commands.md](commands.md#which-commands-need-sudo).

An AI agent (Claude Code, Copilot, etc.) can:

- generate strong random passwords with `create`: the value is never displayed;
- see what secrets exist with `names`: just the names, no values;
- use secrets in commands with `run`: tokens are substituted internally, and a file with `# tswap:`
  markers through `{{@file}}` ([below](#files-with-secrets-run-with-file)).

An AI agent **without sudo** (no passwordless sudo for its user, and never given the sudo
password) **cannot**:

- read a secret value (`get` requires sudo);
- set a secret to a known value (`add` requires sudo);
- enumerate secrets with metadata (`list` requires sudo);
- print a file with the values filled in (`apply` requires sudo);
- delete secrets (`delete` requires sudo), or run any other command that needs sudo;
- exfiltrate via `run` in the blocked ways: `echo`, `printf`, pipes, redirects, and inline
  shell/interpreter code (`sh -c`, `python -c`, ...) are blocked. The blocklist is shallow: a
  program such as `curl`, or a script file, can still take a value out (see
  [What tswap does not protect against](#what-tswap-does-not-protect-against)).

Agents should never run sudo. The roles that follow from this split, and an example allowlist, are
in [agent-integration.md](agent-integration.md).

### Which vault a command under sudo uses

- Under `sudo` (tswap running as root), tswap uses the vault of the user who ran sudo:
  `SUDO_USER`'s home folder from the system's user database, used only when `SUDO_UID` matches that
  user's uid (otherwise tswap refuses). That includes `sudo -i`. A tswap that isn't running as root
  ignores `SUDO_USER`, so `sudo -u <another user>` uses that user's own vault.
- `SUDO_USER=root` means root's own folder.
- Without `SUDO_USER` (a root service, or `su`) tswap uses the folder under `HOME`, which with plain
  `su` is still the caller's.
- `TSWAP_CONFIG_DIR` overrides all of this.
- **Windows:** an elevated prompt keeps your `APPDATA`, so it uses your own vault.
- **Linux:** under sudo tswap can't know your `XDG_CONFIG_HOME`, so it uses `<home>/.config/tswap`.
  If you set `XDG_CONFIG_HOME` to something else, set `TSWAP_CONFIG_DIR` to your config folder and
  keep it for sudo commands:

  ```bash
  export TSWAP_CONFIG_DIR="$XDG_CONFIG_HOME/tswap"
  sudo --preserve-env=TSWAP_CONFIG_DIR tswap get ...
  ```

  Keeping a variable this way needs the same sudoers permission as `sudo VAR=value` (implied for an
  `ALL` command); otherwise, if sudoers lets you run `env`, use
  `sudo env TSWAP_CONFIG_DIR="$TSWAP_CONFIG_DIR" tswap ...`, as the
  [broker guide](BROKER.md#setting-up-the-broker) does.

## Threat model and non-goals

tswap prevents **accidental leaks and casual exfiltration**. It does not attempt to confine a
determined local actor. Knowing these boundaries is how you judge whether tswap fits your
deployment.

### What tswap protects against

| Threat | How |
|--------|-----|
| AI agent sees plaintext secrets | Agents use `{{token}}` substitution via `run`; values never appear in the command the agent writes or in shell history, and `run` redacts the value from the program's output, also its base64 and base64url forms and the `\r\n` form of a multi-line value ([redaction forms](broker-threat-model.md#redaction-is-best-effort)) |
| Casual exfiltration via `run` | With a `{{@file}}` token, any word that is a printer, encoder, copier, shell or interpreter is refused too ([limits](#files-with-secrets-run-with-file)). Blocklist rejects `echo`, `printf`, `cat`, `env`, `printenv`, `set`, `tee` (also by path, e.g. `/bin/echo`); pipes (`\|`) and redirects (`>`) are blocked; shells and interpreters given inline code or code from stdin are refused (`sh -c`, `bash -s`, `python -c`, `perl -e`, `node -e`, `bun -e`, `deno eval`, `php -r`, `julia -e`, `Rscript -e`, `osascript -e`, `expect -c`, `pwsh -Command`, `cmd /c`, `tclsh`/`jshell` reading stdin), as are `awk` without `-f`, `xargs`, `busybox`, `watch`, `parallel`, `script`, `ssh host <command>`, and `find -exec` running any of these, including behind wrappers and launchers (`timeout`, `nice`, `sudo`, `uv run`, `poetry run`, `npx`, `bundle exec`, `docker run`, `kubectl exec`), since inline code can transform a value past output redaction (#105). Script files stay allowed |
| Secrets in config files / repos | `tocomment` replaces inline values with `# tswap:` markers; `redact` masks values for safe viewing |
| Single YubiKey loss | Keyring vault: every enrolled key, machine and the recovery key opens it alone. Classic vault: XOR key reconstruction — either key derives the other via the XOR share stored in `config.json` ([how the classic vault worked](upgrading-from-0.1.md#how-the-classic-vault-worked)) |
| Vault access without physical presence | Depends on the slot: a **touch-required YubiKey** needs a button press per unlock; a **`--with-touch` Secure Enclave** slot asks for Touch ID or the password per unlock, a **`--no-touch`** one never does; a **no-touch YubiKey** and a **TPM** slot without a vault password unlock for any process running as you while the key is plugged in / on that machine |
| Another local user (no root) with the hardware or a copy of the vault folder | Optional **vault password** on a slot (0.2): the TPM or Secure Enclave checks it, a YubiKey slot mixes it into the key; held by `tswap agent` or typed per command. A vault is only as strong as the weakest slot usable on that machine. See [What the vault password does and doesn't protect](#what-the-vault-password-does-and-doesnt-protect) |
| Privilege escalation by agents | sudo boundary — `get`, `add`, `list`, `apply`, `delete`, `restore`, `import`, `export`, rotating a secret that isn't burned ([rotating-and-burning.md](rotating-and-burning.md)), and vault administration require sudo; agents should never run sudo |
| Recognising a value in the vault folder | Record format 3 keeps keyed fingerprints of every value only inside AES-GCM-encrypted metadata sections (keys derived from the vault key): no cleartext hash of any value exists to test guesses against |
| A command decrypting values it doesn't use | Since 0.3 each command decrypts only the value versions it prints or substitutes: `redact`, `tocomment`, `check`, `names`, `list` and `burned` decrypt none on format 3 records, `get` and `apply` only the ones they output ([what each command decrypts](#what-each-command-decrypts)) |

### What tswap does not protect against

| Non-goal | Why |
|----------|-----|
| Determined local attacker with root | Root can attach debuggers, read `/proc/*/mem`, or intercept syscalls — no userspace tool can prevent this |
| Sophisticated exfiltration via `run` | The blocklist is shallow by design. Commands like `curl`, a script file, or custom binaries (and `cp` without a file token) can still exfiltrate secrets passed through token substitution |
| Compromised YubiKey firmware | tswap trusts Yubico's .NET SDK (built into the binary) and the YubiKey's HMAC-SHA1 implementation; firmware-level attacks are out of scope |
| Secrets in process memory | During `run`, the substituted command (with plaintext values) exists in the subprocess memory. Memory forensics or core dumps could recover it, and while it runs, its command line can be read through `/proc/<pid>/cmdline` (`ps`), as the broker guide notes for argv |
| Network interception | Once a secret is passed to a legitimate program (e.g., `psql`, `rclone`), tswap has no control over how that program transmits it |
| Silencing the touch notice | The acknowledged postures live in `config.json`, writable by any process running as you; the changed-posture notice is advisory. `tswap slots` shows each slot's recorded posture: a YubiKey's from its slot, a Secure Enclave's from `config.json` |
| Brute-force on encrypted vault | A record vault's key is random (256 bits) and wrapped per slot. A classic vault (`secrets.json.enc`): AES-256-GCM + PBKDF2 (100k iterations) raises the cost, but the file could be attacked offline if both the file and the XOR share (in `config.json`) are obtained without a YubiKey |

### What each command decrypts

Since 0.3 a command decrypts only the values it uses (owner: "unlocking all secrets is bad
practice"). A format 3 record keeps its value versions in separate encrypted sections, so a
command can read a record's name, burns and fingerprints without opening a value. A **format 2**
record (written by tswap 0.1, and kept until `sudo tswap vault reindex` rewrites it) holds name and
both value versions in one encrypted block: a command that must read it decrypts it whole, wipes
the values it doesn't use at once, and prints a warning with the number of such records and the
reindex command.

| Command | Format 3 record | Format 2 record |
|---|---|---|
| `redact`, `tocomment` | No value: metadata sections only, values recognised by their fingerprints | None: the command refuses before it opens the file, and asks for `sudo tswap vault reindex` |
| `names`, `burned`, `list` | No value | Decrypted whole to read its name and burn state; the values are wiped unused; a warning |
| `check` | No value | Only a record a marker names, decrypted whole; a warning |
| `get` | The one value it prints (the current version of that secret) | That record, decrypted whole; a warning |
| `apply` | The value versions it fills in, each once; none for a line already filled | Each record a marker names, decrypted whole; a warning |
| `create`, `ingest`, `burn`, `rotate`, `restore`, `add`, `delete`, `import` | Still every record for now (a later 0.3 change makes them read only the records they write) | The same |
| `export`, `vault merge`, `vault reindex`, `migrate` | Every value, by definition | The same |

What the warning and the refusal say: the count of records and the fix only, never a secret name
(a format 2 tombstone's would reveal a deleted secret), a hashed file name, a value or its length.
The count is what anyone who can list the vault folder can tell anyway: a record's format is a
cleartext byte of its file.

Limits of reading metadata only:

- `redact` and `tocomment` find what the fingerprints describe. A record whose fingerprints don't
  describe its stored value (only a write bug, or someone holding the vault key, can make one) has
  its stored value printed unmasked by `redact`. Detecting that needs the value, which these
  commands must not decrypt; `get` and `apply` still check it and refuse that record.
- `check`, `names`, `list` and `burned` don't open value sections, so they don't notice a damaged
  value section: they list the record as sound. The command that uses the value fails closed,
  naming the file.
- Strings are not zeroed: a value `get` or `apply` prints lives in memory as a string until the
  process exits, as before (there are just fewer of them).

### Files with secrets: `run` with `{{@file}}`

`tswap run helm upgrade --install app ./chart -f {{@values.yaml}}` fills the file's `# tswap:`
markers into a private copy and runs the command with the copy's path. The copy lives in a folder
only your account can open (`0700`, in `$XDG_RUNTIME_DIR` when that is a folder of yours, not a
symlink and not writable by others, else the temporary folder; on Windows an access list for the current user only). tswap
redacts every form it wrote (plain, quoted, base64 and base64url, and for a multi-line value its
`\r\n` and `\n` forms and the form a terminal prints) from the output, overwrites the copy with zeros and deletes the folder when the
command ends, also after Ctrl+C, and removes stale folders of crashed runs at the next `run` with a
file token. Before anything is written, `run` refuses a command with a printer, encoder, copier,
shell or interpreter as any word (`cat`, `cp`, `base64`, `sh`, `python`, … see the blocklist in
`Validation.cs`); `install` is refused only as the program (also behind a wrapper such as `nice`,
or as the command of `find -exec`, `-execdir`, `-ok` or `-okdir`), so `helm install` works. The check runs again on what the
`{{name}}` tokens expand to, before anything is written; that refusal names the token, not the
word. A refusal can be a false one, for a file named like a refused word: rename the file, or pass
the secret with a plain `{{name}}` token.

This replaces `apply` for agents, which now needs sudo. What it does not do:

- **A process running as the same user can read the copy while the child runs.** An agent that
  starts a second command to read the file in that time gets the values. The folder keeps out other
  users, not you.
- **The word check is a shallow guard.** It refuses the obvious one-step printers and copiers, as
  the `run` blocklist does. A program that sends the file over the network (`curl -F f=@{{@f}}`,
  `wget --post-file`, `git`, cloud CLIs), and any transformation beyond the redacted forms (a value
  inside a larger base64 blob, a custom encoding), still gets the values out.
- **A passwordless sudo grant for tswap voids the sudo gate on `apply`**, as it does on `get`.
- **SIGKILL or a power loss leaves the copy** until the next `run` with a file token sweeps it
  (folders older than an hour whose lock is free). The zeroing is best effort: a RAM disk or an SSD
  may keep other copies.
- **Windows cannot pass Ctrl+C to a ConPTY child.** tswap waits 10 seconds for it to end, then ends
  the child's process tree.
- **A `kill -INT` sent to tswap alone** while it is in the terminal's foreground, with a child that
  shares its process group and has no pseudo-terminal, reaches the child only through the same
  10-second grace kill.
- **`run` with a file token refuses to run as root**, so root never creates a secret file in a
  user's folder.

### Design rationale

The `run` command's exfiltration prevention is deliberately a **shallow blocklist, not a sandbox**.
Deep command analysis (parsing shell semantics, detecting indirect exfiltration) would add
complexity without real security: a motivated attacker can always find a bypass. The blocklist
catches honest mistakes and obvious misuse. For stronger containment, combine tswap with OS-level
sandboxing (containers, seccomp, AppArmor) or network-level controls.

## Posture per backend

A vault made by `init` is a keyring vault: each slot opens it on its own (setting each kind up:
[setup.md](setup.md); the kinds of vault: [commands.md](commands.md#files)). The slots don't all offer the same protection. The table says, for each kind of slot, what the sources say today; "not documented"
means no source states it.

| Slot | What unlocks it | Presence needed | Vault password | Reviewed / verified | Sources |
|---|---|---|---|---|---|
| YubiKey, touch required | That YubiKey, plugged in (its challenge-response slot 2) | Yes: a touch per unlock | Optional vault password, mixed into the slot key's derivation: whoever holds the key can guess it offline, one Argon2id (64 MiB, t = 3) per guess | Independent review: not documented. Touch detection: Yubico's .NET SDK 1.18.1 reports when the key waits for a touch (with this SDK, not yet checked on a real touch key) | [1] [2] [3] |
| YubiKey, no touch | That YubiKey, plugged in | No: any process running as you can unlock while the key is plugged in | Optional vault password, as above. It stops another local user (no root) who can use the plugged-in key | As above | [1] [2] [3] |
| YubiKey FIDO2 slot | That YubiKey (its FIDO2 credential for the relying party `tswap.crawford.dev`), plugged in, plus its FIDO2 PIN | Yes: the PIN and a touch on every unlock (user verification required), on every OS | Optional vault password, mixed into the slot key's derivation, as for an OTP slot | New in v0.3.0. Tested against a fake device; the hmac-secret path was run on real hardware in a spike only (Linux and Windows, one key). Independent review: not documented | [12] [13] |
| Linux TPM | This machine's TPM (the machine slot); no PCR policy | No: without a vault password, any process running as you can unseal it | Optional vault password (`--password`). If the TPM's lockout password is empty, anyone who can use the TPM can reset its failed-password counter and keep guessing; tswap warns | Verified on one physical TPM (Intel PTT), single vendor, on 2026-10-29 (#155). Still open: a full host power cycle, `tpm2_clear`, a second TPM vendor. Independent review: not documented | [3] [4] [5] |
| Windows TPM | This machine's TPM (the machine slot); no PCR policy | No: without a vault password, any process running as you can unseal it | Optional vault password. About 4 wrong passwords for one Windows user, or 9 across all standard users, lock **everyone's** TPM use for up to 8 hours | Virtual TPM verified. A physical TPM was run during development (July 2026); its commands and results were not recorded (#156). A re-check of v0.1.0 on two physical machines is open (#156). Independent review: not documented | [3] [5] [6] |
| Secure Enclave, `--with-touch` | This Mac's Secure Enclave; the key never leaves it and works only on this Mac | Yes: Touch ID or the login password on every unlock | Optional vault password (a password Secure Enclave slot) | **PoC-grade.** Verified for correctness (round trips, fails cleanly on denial). The wrapping is a **hand-rolled ECIES equivalent** (ephemeral ECDH + HKDF-SHA256 + AES-GCM) that **has had no independent cryptographic review** (#159). Tested on Apple Silicon only (M4 Pro, macOS 26 and 27.2); Intel T2 Macs untested | [3] [7] [8] [9] |
| Secure Enclave, `--no-touch` | This Mac's Secure Enclave: anything that can run code on this Mac and read this vault's config, from any account, including root | No prompt | Optional vault password, as above | As above (PoC-grade, construction not independently reviewed, Apple Silicon only). Whether it unlocks with the screen locked, over ssh or after a reboot before anyone logs in is not known yet | [3] [7] [8] [9] [10] |
| Recovery key | The recovery private key, printed once at `init`, read only from stdin | Not documented; the key opens the vault without any enrolled hardware | Not documented | Not documented | [11] |

Sources. A date here is when that source's text was written or last changed, not when anything was
checked; dates of checks are in the Reviewed / verified column.

1. [Issue #158](https://github.com/stevedcc/TokenSwap/issues/158), work item 4 (2026-07-28).
2. [YubiKey: touch or no touch](#yubikey-touch-or-no-touch), this page (2026-02-21, changed 2026-10-30).
3. [What the vault password does and doesn't protect](#what-the-vault-password-does-and-doesnt-protect), this page (2026-11-03).
4. [hardware-backends.md, Linux TPM status](design/hardware-backends.md#status-verified-on-one-physical-tpm-intel-ptt-single-vendor) (2026-10-31).
5. [TPM: no presence check](#tpm-no-presence-check), this page (2026-11-03).
6. [hardware-backends.md, Windows TPM status](design/hardware-backends.md#status-virtual-tpm-verified-physical-tpm-tested-during-development-v010-re-check-open) (2026-10-31).
7. [hardware-backends.md, Secure Enclave status](design/hardware-backends.md#status-poc-grade-not-yet-production-hardened) (2026-07-25, changed 2026-10-31).
8. [Issue #159](https://github.com/stevedcc/TokenSwap/issues/159) (2026-07-28).
9. [Secure Enclave: touch or no touch](#secure-enclave-touch-or-no-touch), this page (2026-10-30).
10. [hardware-backends.md, touch or no touch](design/hardware-backends.md#touch-or-no-touch-an-explicit-choice-brief-t11) (2026-10-30).
11. [setup.md, The recovery key](setup.md#the-recovery-key) (2026-10-30).
12. [YubiKey FIDO2 slot: the PIN and a touch](#yubikey-fido2-slot-the-pin-and-a-touch), this page (2026-11-06).
13. [setup.md, FIDO2 slots](setup.md#fido2-slots) (2026-11-06).

A vault is only as strong as the weakest slot usable on that machine: see
[What the vault password does and doesn't protect](#what-the-vault-password-does-and-doesnt-protect).

### TPM: no presence check

The TPM key has no PCR policy, and without a vault password (`--password`) any process running as
you can unseal it (no presence check, unlike a touch-required YubiKey or a `--with-touch` Secure
Enclave slot).

### The Secure Enclave's wrapping has not been reviewed

The Secure Enclave slot's wrapping is an ephemeral-ECDH + HKDF-SHA256 + AES-GCM construction, a
hand-rolled ECIES equivalent. In the words of the
[design record](design/hardware-backends.md#status-poc-grade-not-yet-production-hardened), it has
"been verified for correctness (round-trips, fails cleanly on denial), not reviewed by anyone with
cryptography expertise for subtler issues". It has not had an independent cryptographic review;
`init --secure-enclave` says so too. Tested on Apple Silicon only. The design record lists what
else is open before it should be trusted as a primary vault backend.

### YubiKey FIDO2 slot: the PIN and a touch

A FIDO2 slot ([setup.md](setup.md#fido2-slots)) is opened by the key's hmac-secret output for the
slot's credential, which the key gives only after it has verified its FIDO2 PIN and seen a touch.
To open the vault with it, an attacker needs **the key, its PIN and a touch**: the vault files and
the PIN without the key are not enough, and neither is the key without the PIN. Malware running as
you can't open a FIDO2 slot on its own while the key sits plugged in, unlike a no-touch OTP slot;
it would need the PIN (for example from a keylogger) and someone to touch the key.

- **User verification is required** on every enrolment and every unlock, on every OS. tswap refuses
  a credential made, or an answer given, without it (`... answered without verifying the PIN (no
  user verification); tswap doesn't use such an answer.`).
- **PIN tries are counted by the key.** Eight wrong PINs in all block the key's FIDO2 until a FIDO2
  reset (which deletes every credential on it); after three wrong in a row the key takes no more
  until it is unplugged and plugged in again. tswap never retries a wrong PIN itself, shows the
  tries left, and tries FIDO2 slots last, after every slot that needs no PIN.
- **On Windows the dialog owns PIN entry.** Windows' security key dialog asks for the PIN, so tswap
  can't count the tries there, and the dialog may ask again after a wrong PIN within one unlock:
  those tries are the dialog's, not tswap's. tswap never sees the PIN on Windows.
- **On Linux and macOS the PIN goes through tswap**, typed at the terminal (`/dev/tty`) without
  echo, and sent to the key under CTAP2's PIN protocol; tswap doesn't store it.
- **Relying-party id `tswap.crawford.dev`.** Every tswap credential is bound to it, so a website
  can't ask the key for a tswap slot's output (a site can only use its own domain), and tswap's
  credential is separate from any website login on the key. (Only pages under `tswap.crawford.dev`,
  a domain the project owner holds for a future phone app, could ask, and still only with the PIN
  and a touch.) Programs on the machine talk to the key directly and can name any relying party,
  so this protects against websites, not local malware. The credential is non-discoverable:
  nothing is stored on the key, and only someone holding the slot's credential id (in the vault's
  keyring) can ask for it.
- **No terminal, no FIDO2.** Without a person at a terminal, FIDO2 slots are skipped (no Windows
  dialog pops up for a script or an agent), so a FIDO2 slot never opens a vault unattended.
- **A vault password on a FIDO2 slot** is mixed into the slot key's derivation, as on an OTP slot:
  the key never sees it, so whoever holds the key and its PIN needs one PIN and touch for the key's
  answer, then can guess the password offline at one Argon2id per guess.
- **Not reviewed.** The construction (the PRF transform of a per-slot input, HKDF-SHA256 into the
  slot key; [hardware-backends.md](design/hardware-backends.md#yubikey-fido2-slots-v030-issue-193))
  has had no independent review, and the real-hardware checks are still the owner's.

## Touch posture

### YubiKey: touch or no touch

tswap recommends configuring a YubiKey's slot 2 with a touch requirement
(`tswap yubikey setup --touch`: [Preparing a YubiKey](setup.md#preparing-a-yubikey)). That means:

- **Physical presence required:** touching the YubiKey confirms intent.
- **Protection from local malware:** processes can't silently unlock the vault.
- **Something you have and something you do:** the key, and the touch.

Slots configured without touch let any process running as you unlock the vault while the key is
plugged in. That can be the right choice (a key that lives in an always-on machine, a CI runner),
and tswap treats it as one: it **explains the posture once, where it is chosen, and doesn't repeat
it on every command**.

- **At enrolment** (`init`, `slot add`, `slot request`, `migrate --to-records`, `recover`) tswap
  records each key's posture in its slot and explains it on stderr.
- **How it knows:** it detects the posture from whether the key asked for a touch while it
  answered tswap's challenge, which Yubico's .NET SDK reports. A key can't be asked for a
  configured slot's touch setting (Yubico's tools can't read it either), so slots enrolled before
  v0.1.0 show as "unknown", and `tswap yubikey setup` says "touch: unknown" for a slot 2 that is
  already set up. Over USB only (tswap reaches the key's OTP interface over USB). If
  tswap couldn't check, it says so, with the fix.
- **`tswap slots`** shows each slot's posture at any time.
- **Everyday commands** print nothing about it, except one line on stderr when a slot's posture
  differs from what this machine last acknowledged (for example a no-touch key's slot arriving from
  another machine with `slot merge`). `tswap slots --ack` acknowledges the current postures.
- **The notice is advisory.** The acknowledgement is per machine, in `config.json`
  (`AcknowledgedTouch`). That file is writable by you and by any process running as you. For a
  YubiKey slot, `tswap slots`, which reads the posture from the slot itself, is the reliable view.

**Moving a key to touch-required:** in a keyring vault, one key at a time, with another way into
the vault available (another enrolled YubiKey plugged in, this machine's TPM or Secure Enclave
slot, or the recovery key):

```bash
tswap yubikey setup --replace --touch --serial N   # reprogram key N's slot 2, with a touch requirement
sudo tswap slot add --yubikey                      # enrol key N again (pick it if asked)
tswap names                                        # with only key N plugged in: it opens the vault alone
```

Finish and check one key before you start the next. A vault whose keys still share a pair slot
(made by 0.1's `init --keyring`) first needs each key's own slot:
[upgrading-from-0.1.md](upgrading-from-0.1.md#a-classic-vault-without-touch).

- **Other copies of the vault: before you start.** Reprogramming kills the key's slot in every copy
  of the vault at once, but the new slot goes only into the keyring of the vault you enrol it in.
  Machines that share that vault folder get it with the folder. A machine with its own copy
  doesn't, and there the key no longer opens the vault until the slot is brought in, with
  `sudo tswap vault merge <a copy of this vault folder>` on that machine (or `slot merge`, for a
  vault that keeps its keyring in `config.json`). That merge unlocks the copy first, so the machine
  needs another way in that it can use. How:
  [Copying the folder](multi-machine.md#copying-the-folder-scp-rsync-or-a-usb-stick) and
  [What `slot merge` adds](multi-machine.md#what-slot-merge-adds).
- **Reprogramming kills the key's old slot.** The new secret replaces slot 2's old one, so the
  key's existing slot no longer opens the vault. `tswap slots` still lists that dead slot: slots are
  kept, since keyrings merge as a union and a removed slot would come back from another copy.
  `setup --replace` asks you to type the key's serial, and refuses when the key's slot would be
  the vault's only way in ([Preparing a YubiKey](setup.md#preparing-a-yubikey)).
- **Enrolling it again.** With every plugged-in key already enrolled, `slot add --yubikey` asks
  which key to enrol (with nothing on stdin it takes the first; with `--recovery-key-stdin`, stdin
  carries the recovery key, so plug in only the key being enrolled). It reads the key's slot 2 first (an
  empty one points you to `tswap yubikey setup`, and nothing is challenged), then challenges the
  key against each of its slots in this vault. If one still opens the vault, it refuses: there is
  nothing to enrol again. If the key is busy or doesn't answer, it stops and changes nothing. Only
  when every slot answers wrongly does it open the vault another way (another enrolled YubiKey,
  this machine's TPM or Secure Enclave slot, or a running `tswap agent`) and enrol the key as a
  new slot. A touch key needs up to one touch per old slot for the check, plus two for the new
  slot; when the way in is another key that needs a touch, add its touch. On this machine, unlocks then try the key's new slot first.
- **The vault password is asked at most once.** When a step is known to need it (one of the key's
  slots needs it, or the new slot will get it), `slot add` asks before any challenge. Otherwise it
  asks only if the unlock needs it, which is after the key's checks. When the vault has a vault
  password, the password typed before the checks is compared with the vault's password verifier
  before anything is written: a mismatch always stops the command with nothing written, whether
  or not the new slot was to get the password (with a mistyped password, tswap can't tell whether
  the key's slots that need it still open the vault).
- **When nothing else opens the vault**, `slot add` lists the ways in it looked for and changes
  nothing. The recovery key is then the fallback:
  [adding a key with the recovery key](multi-machine.md#appendix-adding-a-key-with-the-recovery-key).

A classic vault from 0.1 is covered in [upgrading-from-0.1.md](upgrading-from-0.1.md).

### Secure Enclave: touch or no touch

`--secure-enclave` needs exactly one of `--with-touch` or `--no-touch`, on `init`, `slot request`
and `recover` alike; there is no default.

- `--with-touch`: every unlock asks for Touch ID or the login password.
- `--no-touch`: no prompt.
- **The choice lives in the key.** It is fixed into the Secure Enclave key when the key is created
  and can't be read back from it, so tswap records it in `config.json` (`RequiresTouch`), and
  `tswap slots` shows that record. The record only changes what tswap says, never what the Secure
  Enclave enforces.
- **No recurring banner.** There is no per-command banner for a no-touch Secure Enclave slot: you
  chose it with the flag. (A YubiKey's posture is set when its slot 2 is programmed, with
  `tswap yubikey setup --touch` or `--no-touch`.)
- `slot approve` on the approving machine can't see a requesting Mac's choice; `slot request
  --no-touch` says so.

What `--no-touch` trades away, as the warning it prints says:

1. This Mac's slot unlocks the vault without Touch ID or a password.
2. Anything that can run code on this Mac and read this vault's config, from any account, including
   root, can unlock the vault without you noticing. The key still never leaves the Secure Enclave
   and works only on this Mac; the config file's permissions are what keep other accounts out.
3. The slot can't be changed or removed later: tswap can't remove slots, so the only way to drop it
   is a new vault and moving the secrets over.

It exists for unattended use. But whether a no-touch slot unlocks with the screen locked, over ssh
or after a reboot before anyone logs in (which a scheduled job or a separate user for unattended work may need) is
**not known yet**: that depends on the recorded check in
[setup.md](setup.md#checking-a-no-touch-secure-enclave-slot-on-a-mac).

`tswap` and `libtswapse.dylib` beside it ship together: a newer `tswap` with an older dylib refuses
to enrol ("update libtswapse.dylib together with tswap") rather than make a key it can't vouch for.

### Under sudo: the Secure Enclave asks you, not root

- Under sudo, every Secure Enclave call (the unlock, and creating the key in `init`, `slot request`
  and `recover`) runs as the **owner of the vault's config folder**, normally you, so Touch ID asks
  you. The macOS dialog *"Enter the password for the user System Administrator"* under sudo was a
  bug.
- So it opens only that user's own vault, with that user's presence: less privilege than root, not
  more.
- If switching to the folder's owner fails, or the owner can't be read, the command fails: nothing
  runs as root, and no other slot (a one-key YubiKey slot) is tried.
- Without sudo nothing changes. The TPM and YubiKeys are not affected (they still run as root under
  sudo).
- Two cases still can't use a `--with-touch` slot under sudo:
  - a vault folder owned by root (`sudo tswap init` with the vault under `/var/root`) evaluates
    presence for root;
  - a folder owned by a uid with no login (a service account) asks presence of that uid, which
    nobody can give.

  Choose `--no-touch` for such a vault, or keep it in the user's folder.
- A slot enrolled with sudo before v0.1.0 (`sudo tswap recover --secure-enclave`, or `init` /
  `slot request` run with sudo) was created as root. If it doesn't unlock, run `recover` again
  (since v0.1.0, sudo creates the key as the owner).

The design reasoning is in
[hardware-backends.md](design/hardware-backends.md#under-sudo-used-as-the-vault-folders-owner-not-root-brief-t12-issue-157).

## What the vault password does and doesn't protect

Setting the password up, and the agent that holds it: [vault-password-and-agent.md](vault-password-and-agent.md).

- **It stops** another local user without root (including one in group `tss`, or one who can use a
  plugged-in no-touch YubiKey) who has a copy of the vault folder, and anyone with a stolen disk or
  copied folder who later gets the hardware.
- **It doesn't stop** root, a kernel-level attacker, or someone at your unlocked session while the
  agent holds the password (the agent answers your uid; a person at your keyboard *is* your uid).
- **A vault is only as strong as the weakest slot usable on that machine.** A password TPM slot next
  to a plugged-in no-touch YubiKey slot without the password protects nothing against another user
  of that machine. A YubiKey kept in a drawer, or the recovery key, is fine. `tswap slots` warns.
- **Don't reuse the vault password anywhere else.** Two consequences make it worth guessing:
  - whoever can open a mixed vault through a slot **without** the password can read the
    `vault-password` file's verifier and test vault-password guesses offline, at one Argon2id
    (64 MiB, t = 3) per guess;
  - whoever holds a YubiKey with a password slot can guess that slot's password offline the same
    way.

  A long password is the defence in both cases.
- **RAM.** `agent start` and `broker unlock` say it once, verbatim:
  *"The agent keeps your stretched vault password in memory until you stop it or it times out.
  Root, or anything that can read this process's memory, can take it while it runs; it still needs
  this machine's TPM/YubiKey/Secure Enclave to open the vault."*
  - The held copy is in locked memory (never swapped; a failed lock is a warning).
  - The agent makes itself non-dumpable (Linux), denies debugger attachment (macOS) or denies other
    processes' memory access through its DACL (Windows: a speed bump, the process's owner can change
    it back).
  - On a Mac with a password Secure Enclave slot one more line follows: the Secure Enclave library's
    copies of the password during each unlock (a Swift `Data` copy and the `LAContext`'s copy) can't
    be wiped by tswap.
- **The derivation is best effort.** The typed password is a .NET string, which can't be zeroed, and
  Argon2id's 64 MiB working memory and output array live on the managed heap, which may be swapped
  and can't be zeroed reliably. tswap zeroes its own UTF-8 bytes and output buffer. "Locked, never
  swapped" applies to the held stretched password only. On Linux the TPM auth text (`hex:` and the
  stretched bytes in hex) also sits in the kernel's pages of the memfd tpm2-tools reads it from,
  until that child exits; tswap can't wipe those.
- **The tswap CLI stays dumpable** while it holds the vault key during a command, as it always has.
- **The agent's answers are authenticated by the vault folder.** The key check proves an answer is
  this vault's key given a `vault-password` file only the vault's machines can write: someone who
  can write your vault folder could plant a file and a fake agent of their own. Keep the folder's
  owner and mode as tswap sets them (as for the keyring).
- **Windows TPM lockout is a denial of service.** Windows counts wrong TPM passwords per Windows
  user, and across all standard users of the machine: about 4 wrong passwords for one user, or 9
  across all of them, lock TPM use for up to 8 hours (480 minutes). That lock covers **everyone's**
  TPM use, not only tswap's: it also blocks creating TPM keys, and may block slots without a
  password. So another local standard user can lock you out of your TPM for hours with wrong
  passwords against their own keys. They still can't open your vault. Run `tswap agent start` to
  avoid retyping the password.
- **Linux TPM lockout.** When the TPM's lockout password is empty, anyone who can use the TPM can
  reset its failed-password counter and keep guessing. tswap warns at each TPM password enrolment
  (`tpm2_changeauth -c lockout file:-`, as root, with the new lockout password on stdin, sets one,
  and affects every program that uses the TPM; `file:-` keeps the password out of the process list
  and shell history, where an argument would show it).

## A shared vault folder: what a sync provider sees, and what isn't detected

These notes apply to a record vault whose folder is synced, shared or copied between machines.
How to share one, and the merge rules: [multi-machine.md](multi-machine.md#sharing-a-vault-folder).

- **What a sync provider can see:** not names or values, and not which of an edit, a delete or a
  burn a change was, unless the change moves the record across a 256-byte padding bucket (a delete
  empties the value, a burn adds its reason, and a rotation keeps the previous value beside the new
  one, so a long value, reason or retained previous value can change the file's size class).
  - It can see that the file with a given hash changed at a given time, so it can follow when each
    (unnamed) secret is edited; the single-file vault only showed that something changed.
  - Each machine's origin id is in every record it writes; it is per machine and vault, so it
    doesn't link one machine across vaults.
  - If a stamp is more than a year ahead of the clock (a machine with a badly wrong clock), tswap
    warns, and `tswap names` shows "far future".
- **What is not detected yet:** deletes and burns are protected when versions are *merged* (an
  older copy can't undo them). But a sync tool's "restore previous version" of a single file, or
  someone with write access to the folder replacing a record (or the keyring) with an older copy of
  itself, is taken as the current state: **tswap does not yet notice a record or keyring going back
  in time.** Keep the vault folder's write access to your own machines and sync account.
- **Export and import** keep the single-file encrypted format. An export is a snapshot of the
  current values and burn state (no deletes, no history). Importing into a record-store vault
  writes each secret as a new version, so importing an old export **can bring back a secret you
  deleted since**: that is your explicit choice.
- **Permissions:** the vault folder, `records/` and the config folder are created 0700 and their
  files 0600; an existing vault with wider permissions is narrowed on the next write, with a notice.
  Under sudo, tswap does its file work as the folder's owner. (Windows: no change; files inherit
  the profile folder's permissions.)
