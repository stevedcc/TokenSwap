# Command reference

This page is for anyone who runs tswap by hand or from scripts. It lists every command with its usage,
which commands need sudo, the environment variables tswap reads, and the files it writes.

Setting up a vault step by step, with the guided `init`, is in [setup.md](setup.md).

The per-command part is generated from tswap's own help text. A test checks it and the list of
environment variables against the code; the Files section is not checked.

## Which commands need sudo

A command whose usage line below starts with `sudo` needs sudo. Two commands mix the two:

- `slot` is marked `sudo` as a whole, but only some of its subcommands check for it.
- `broker` is marked without `sudo`, but the subcommands that change `broker.json` need it.

This table lists each of their subcommands. "sudo" means it refuses to run without sudo.

| Subcommand | Sudo | Why |
|---|---|---|
| `slot request` | no | Runs on the new machine, which has no usable vault yet; it touches no existing vault's secrets |
| `slot approve` | sudo | Unlocks this vault and writes a file that lets whoever holds the request's private key open it: the same risk as `export` |
| `slot accept` | no | Finishes enrolment on the new machine. On a record-store vault, or with `--vault-dir`, it also writes the new slot into the vault folder's keyring; the human check for that slot was the earlier `sudo tswap slot approve` |
| `slot merge` | sudo | Adds the slots of a receipt or of another copy's `config.json`: each one is a new way to open the vault |
| `slot add` | sudo | Adds a plugged-in YubiKey as a new slot: a new way to open the vault |
| `broker serve` | no | Runs as the vault's own user; it refuses root |
| `broker unlock` | no | Runs as the vault user; it refuses sudo |
| `broker lock` | no | Runs as the vault user; it refuses sudo |
| `broker status` | no | Runs as the vault user; it refuses sudo |
| `broker forward` | no | Runs inside the container; it needs no vault |
| `broker call` | no | Runs inside the container; it needs no vault |
| `broker route add` | sudo | Changes `broker.json`, which decides which credentials containers can use |
| `broker route remove` | sudo | Changes `broker.json`, as above |
| `broker socket add` | sudo | Changes `broker.json`, as above |
| `broker socket bind` | sudo | Changes `broker.json`, as above |
| `broker socket remove` | sudo | Changes `broker.json`, as above |
| `broker template add` | sudo | Changes `broker.json`: a template runs host-side commands with vault secrets |
| `broker template remove` | sudo | Changes `broker.json`, as above |

Three commands marked without `sudo` have one case that needs it, as their descriptions below say:
`rotate` and `ingest --rotate` need sudo unless the secret is burned, and `migrate --to-records` needs sudo.

On Windows there is no sudo: run a command that needs it from an elevated command prompt.

## Commands

<!-- BEGIN GENERATED: commands (TswapTests/Docs/CommandReference.cs) -->

### init

```
tswap init [--yubikey|--tpm|--secure-enclave --with-touch|--no-touch] [--password|--no-password] [--no-recovery] [--folder <dir>] | init --vault-dir <shared folder>
```

Create a record vault (one file per secret, shareable by sync tools) in \<config dir\>/vault, or in --folder \<dir\> (absent or empty, e.g. a sync folder). At a terminal, plain init is a guided setup: it lists this machine's YubiKeys and TPM or Secure Enclave, makes a slot for each one you pick, and shows how to add other machines. Without a terminal, name the slot: --yubikey (one YubiKey; add keys with 'slot add --yubikey'), --tpm (Windows/Linux) or --secure-enclave (macOS; needs --with-touch, Touch ID or password on every unlock, or --no-touch: no prompt, read its warning). Plus a recovery slot unless --no-recovery. --password gives the slot a vault password (asked for on a terminal when neither --password nor --no-password is given). --vault-dir joins a folder another machine shares

### slot

```
sudo tswap slot request [--tpm|--secure-enclave --with-touch|--no-touch] [--password|--no-password] [--vault-dir <folder>] <file> | slot approve <request-file> <approve-file> | slot accept <file> [--receipt <file>] | slot merge <receipt-or-config.json> [--yes] | slot add --yubikey (approve, merge and add take --recovery-key-stdin)
```

Enroll another machine into a keyring vault via hand-carried files (request, approve, accept, merge), or add a plugged-in YubiKey to this machine's keyring as its own slot; slot request --secure-enclave needs --with-touch (Touch ID or password on every unlock) or --no-touch (no prompt; read its warning)

### migrate

```
tswap migrate [--to-records [--vault-dir <dir>]]
```

Guide to upgrade slots for touch requirement; --to-records (sudo) converts the vault to one file per secret, shareable by sync tools

### create

```
tswap create <name> [len]
```

Generate random secret (no display)

### ingest

```
tswap ingest [--rotate] <name>
```

Pipe secret from stdin (no display); --rotate replaces an existing one (sudo unless it is burned)

### rotate

```
tswap rotate <name> [len]
```

Replace a secret with a new random value (no display); sudo unless it is burned

### names

```
tswap names [--json]
```

List secret names (no values)

### slots

```
tswap slots [--ack]
```

List the vault's slots and what protects each one (--ack: acknowledge the YubiKeys' touch settings)

### agent

```
tswap agent <start [--timeout <d>]|serve [--foreground]|stop|status>
```

Hold the vault password in memory so commands need no prompt, like ssh-agent (run as the vault user, never with sudo)

### run

```
tswap run <cmd> [args...]
```

Execute with {{token}} substitution

### check

```
tswap check <path> [--json]
```

Verify # tswap: markers in file/dir

### redact

```
tswap redact <file>
```

Output file with secret values redacted

### tocomment

```
tswap tocomment <file> [--dry-run]
```

Replace inline secrets with # tswap: comments

### apply

```
tswap apply <file>
```

Output file with # tswap: markers substituted

### burn

```
tswap burn <name> [reason]
```

Mark a secret as burned

### burned

```
tswap burned [--json]
```

List all burned secrets

### prompt

```
tswap prompt
```

Show AI agent instructions

### prompt-hash

```
tswap prompt-hash
```

Hash of agent instructions

### installscript

```
tswap installscript
```

Generate a platform install script (redirect to a file, review, then run)

### add

```
sudo tswap add <name>
```

Add a secret (user-provided value)

### get

```
sudo tswap get <name>
```

Get a secret value

### list

```
sudo tswap list
```

List all secrets (names and dates, no values)

### delete

```
sudo tswap delete <name>
```

Delete a secret

### restore

```
sudo tswap restore <name>
```

Put back the value a rotation replaced, as a new version (record store)

### export

```
sudo tswap export <file>
```

Export all secrets to an encrypted backup

### import

```
sudo tswap import [--include-burned] <file>
```

Import secrets from an encrypted backup (burned secrets skipped by default)

### vault

```
sudo tswap vault merge <other-vault-dir> [--yes] (takes --recovery-key-stdin) | vault reindex
```

Merge another copy of this record-store vault folder (scp/rsync/USB) into this one: keyring union, records by the merge rules; reindex: rewrite every record in record format 3 with fingerprints

### recover

```
sudo tswap recover --yubikey|--tpm|--secure-enclave --with-touch|--no-touch [--password|--no-password] [--recovery-key-stdin]  (recovery key on stdin)
```

Break glass: open the vault with the recovery private key (piped on stdin) and enroll this machine's YubiKey, TPM or Secure Enclave as a new slot (--secure-enclave needs --with-touch or --no-touch)

### completion

```
tswap completion <bash|zsh|fish|powershell>
```

Print a shell completion script

### broker

```
tswap broker <serve|unlock|lock|status|forward|call|route|socket|template> ...
```

Credentials for containers that never hold them: HTTP routes, command templates and an ssh-agent (serve, and unlock|lock|status for a broker whose slot has the vault password, as the vault user; forward/call in the container; sudo for route|socket|template add|remove)

<!-- END GENERATED: commands -->

## Environment variables

| Variable | Effect |
|----------|--------|
| `TSWAP_CONFIG_DIR` | The config directory to use; overrides everything else, including the `sudo` home lookup |
| `TSWAP_YUBIKEY_SERIAL` | The YubiKey to unlock with when several are plugged in (see [Several YubiKeys plugged in](setup.md#several-yubikeys-plugged-in)); `sudo` drops it unless kept |
| `XDG_CONFIG_HOME` | Linux: the config base, when it is an absolute path (a relative one is ignored) |
| `TSWAP_AGENT_SOCK` | The tswap agent's socket path (Unix only), for commands and for `agent start\|serve`, like `SSH_AUTH_SOCK`; it picks a path, not a trust level (the server's uid is checked as always). `sudo` drops it: root's commands find the vault owner's agent by the vault folder's owner |

Commands that need no vault (`--help`, `<command> --help`, `prompt`, `prompt-hash`, `completion`,
`installscript`) work without a home folder; the others say "Cannot determine the config folder"
if there is none and `TSWAP_CONFIG_DIR` isn't set.

> **macOS and sudo:** tswap releases before 0.1.0 used `~/.config/tswap/` under `sudo` (and
> `~/Library/Application Support/tswap/` otherwise). If your vault is only in `~/.config/tswap/`,
> tswap stops and tells you to move it (or to set `TSWAP_CONFIG_DIR`); if both folders hold a
> vault, it refuses until you choose. It never moves or picks one by itself.

> **Upgrading from an earlier version?** tswap automatically renames `tswap-poc` to `tswap` on first run if the old directory exists and the new one does not. If both directories are present (e.g. you ran `init` twice), move your files manually: on Linux/macOS rename `~/.config/tswap-poc/` to `~/.config/tswap/`, and on Windows rename `%APPDATA%\tswap-poc\` to `%APPDATA%\tswap\`.

## Files

| Platform | Config directory |
|----------|-----------------|
| Linux | `$XDG_CONFIG_HOME/tswap/` (only an absolute `XDG_CONFIG_HOME` counts), else `~/.config/tswap/` |
| macOS | `~/Library/Application Support/tswap/` (also under sudo; see the macOS note under [Environment variables](#environment-variables)) |
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
├── vault-password       # only with a vault password: Argon2id salt and parameters, verifier, key check
└── records/<hash>       # one encrypted record per secret; the file name is a keyed hash of the name
```

`vault-password` holds nothing usable without the vault key. If a sync tool leaves two different
copies, every password operation refuses until you keep one (`The vault folder has two different
vault-password files (...)`); a byte-identical copy is deleted on the next password write (only a
file matching the sync tools' conflict-copy names, never `vault-password` itself; a sync tool that
propagates that deletion does no harm). A lone conflict copy with no `vault-password` file refuses
too, and asks you to rename it to `vault-password` if it holds this vault's password.

The tswap agent's socket lives in the vault user's run folder, never in the config or vault
folder: `/run/user/<uid>/tswap/agent-<16 hex>.sock` on Linux (else `~/.cache/tswap/run/`),
`~/Library/Caches/tswap/run/` on macOS, a named pipe on Windows; a password broker's control socket
is `broker-<16 hex>/control.sock` in the same folder.

On Linux and macOS the folders are created 0700 and the files 0600; an existing vault with wider
permissions is narrowed on the next write, with a notice (reads change nothing). Windows: the
profile folder's permissions apply.

