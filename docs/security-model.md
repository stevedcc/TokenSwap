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

### libfido2 under sudo: root-owned only

FIDO2 slots on security keys other than YubiKeys go through libfido2 on Linux and macOS, loaded at
run time ([install.md](install.md#libfido2-security-keys-other-than-yubikeys)). The sudo split
above rests on root's code staying root's: a library you can replace, loaded into `sudo tswap` while
the vault is open, would hand code running as you root and every secret. So:

- **Under sudo** (a privileged process) tswap loads libfido2 only from an allow-list of root-owned
  folders: `/usr/lib64`, `/usr/lib` and the multiarch folder of the process's architecture
  (`/usr/lib/x86_64-linux-gnu`, `/usr/lib/aarch64-linux-gnu`) on Linux, `/opt/local/lib`
  (MacPorts) on macOS; never a bare library name, never the folder of the tswap binary, never
  Homebrew or `/usr/local/lib` (either can hold a library that loads its dependencies from the
  user's `/opt/homebrew`). Checking only the library file would not be enough: its dependencies
  (libcbor, libcrypto) load from wherever it says, and a library's initialisers run when it loads,
  so checking afterwards is too late. Hence a list of folders whose whole tree is root's.
- **Before loading**, the candidate is resolved to its real path, which must still lie in an
  allow-listed folder (a link from one to another is fine; a link anywhere else is skipped); then
  the real path and every folder above it up to `/` must be no link, owned by root (uid 0) and
  writable by neither group nor others. tswap loads the real path it checked.
- **A clean loader environment:** with any variable whose name starts with `LD_` or `DYLD_` set (on
  either OS: a prefix, not a list, so a variable a future loader honours is covered too), a
  privileged tswap loads no libfido2. sudo's default `env_reset` removes them, but a `sudo` child is
  not a secure-execution process (its real and effective uid are both 0), so one that survives
  (`env_keep`, `sudo -E`, a root shell) would be honoured when libfido2 loads libcbor.
- **What stays root's to govern:** a library's own RPATH/RUNPATH, `/etc/ld.so.conf*` and the
  loader cache. All are root-owned, so a privileged tswap trusts them as it trusts its own binary
  (which must itself be a root-owned install for sudo use to mean anything).
- **Refused, not worked around:** with only a libfido2 outside the allow-list, or an unclean
  environment, keys of other brands are left out under sudo and tswap names the root-owned way to
  install libfido2 (or another machine, or Windows). It never suggests copying a library into place.
- **Without sudo**, any libfido2 you have is used (next to the binary first): a process running as
  you that swapped it gains nothing it doesn't already have.

YubiKeys never go through libfido2 on Linux and macOS (Yubico's SDK, built into the binary, handles
them; libfido2 skips Yubico's USB vendor id), so none of this applies to them.

### Enrolling over SSH: what `slot enrol --via` trusts

`tswap slot enrol --via <user@host>` ([multi-machine.md](multi-machine.md#enrolling-over-ssh)) runs
`slot request` and `slot accept` on the new machine without sudo, and approve and merge on the host
over SSH, under the host's sudo. By default the host's approve and merge run on a terminal of their own
(`ssh -t`), so the host's sudo and vault can ask there, and the files go through a staging folder on the
host; `--batch` carries the files on the session's stdin and stdout (`slot approve - -`,
`slot merge -`) under `sudo -n`. What it relies on:

- **SSH authenticates the channel**: the host key (checked by ssh, as for any login) and your user key.
  tswap passes the destination after `--` (never an option), builds the remote command from fixed words
  and a checked program path, and handles no password: sudo's and the vault's prompts are the host's
  own, on its terminal.
- **The files are the same reviewed formats** as the hand-carried ones (request, approve file,
  receipt), so nothing new is parsed. The joining side still checks the approve file against its
  pending request (slot id, echoed public key, backend, hardware blob), and the host merges without
  asking only the slot it approved (`slot merge` never gets `--yes`). In batch mode stdin is not a
  terminal, so any other slot is refused; in the interactive mode the host's merge has a terminal and
  asks about any other slot (Yes/No) instead, and with `--expect` the receipt is the one the joining
  machine sent.
- **The staging folder and `--expect`.** In the interactive mode the request and the receipt wait in
  the SSH user's `<config folder>/enrol-staged/<id>/` on the host (0700 on Unix), written by
  `slot stage`, which runs as that user and refuses sudo. `--expect` is the SHA-256 of the file as the
  joining machine sent it: approve and merge read the staged file once, compare that buffer's hash and
  parse that buffer, so a file swapped in the folder, before or during the read, is refused or has no
  effect.
- **The approve file coming back is bound only by a fingerprint you compare.** It rests in the staging
  folder between approve and `slot stage <id> get approve`, where another process of the same user on
  the host could replace it with one it made: everything `slot accept` checks is public, so a crafted
  approve file could wrap a key of its choosing to the joining machine's public key. That gives it no
  way into the real vault, but a joining machine that then wrote secrets would write them under a key
  the attacker knows. The host prints `Approve file fingerprint: ...` over the exact bytes it wrote,
  the joining machine prints `Approve file received: ...` over the exact bytes it got, and waits for
  Enter. Like the requester's fingerprint, this is a human check, not a boundary (a same-user process on
  the host can also write to the session's terminal): it raises the bar from swapping a file to spoofing
  a terminal. It is the same exposure as the hand-carried flow, where `approve.json` sits in your folder
  too. In batch mode the approve file travels on the SSH session and never rests on the host.
- **The host's output is untrusted text.** In batch mode its lines (and ssh's own stderr) are shown
  labelled `[<user@host>] ` with control characters replaced; the interactive steps are the host's raw
  terminal, framed by local `On <user@host>: ...` and `Back on this machine.` lines. No failure message
  quotes what the host printed (only its `--version` line, sanitised, when the versions differ): a
  partial approve file is a way into the vault while this machine's pending private key is in its
  config.
- **The shared SSH connection** (Linux and macOS): during the run, and up to 60 seconds after a crash
  (`ControlPersist`), another process of the same user on the joining machine can reuse the connection
  through its socket (in a 0700 folder of that user's). That gives it the SSH login, not sudo on the
  host and no power over the staged files beyond what the `--expect` binding allows.

**The sudoers trade-off (batch mode only).** The interactive mode needs no sudoers rule: sudo asks for
your password on the host. For `--batch`, the recommended sudoers rule lets the SSH user run exactly
`tswap --version`, `tswap slot approve - -` and `tswap slot merge -` as root without a password. Any
process running as that user on the host can then approve a request, which hands out a way into the
vault: the same class of risk as `export`, and the reason `slot approve` needs sudo at all. Give the
rule only to a host account that runs nothing else untrusted.

## Threat model and non-goals

tswap prevents **accidental leaks and casual exfiltration**. It does not attempt to confine a
determined local actor. Knowing these boundaries is how you judge whether tswap fits your
deployment.

### What tswap protects against

| Threat | How |
|--------|-----|
| AI agent sees plaintext secrets | Agents use `{{token}}` substitution via `run`; values never appear in the command the agent writes or in shell history, and `run` redacts the value from the program's output, also its base64 and base64url forms and the `\r\n` form of a multi-line value ([redaction forms](broker-threat-model.md#redaction-is-best-effort)). Since 0.3 `run` also masks every other fingerprinted value in the vault (current and previous, burned ones included) by its keyed fingerprints ([what `run` masks](#what-run-masks)) |
| Casual exfiltration via `run` | With a `{{@file}}` token, any word that is a printer, encoder, copier, shell or interpreter is refused too ([limits](#files-with-secrets-run-with-file)). Blocklist rejects `echo`, `printf`, `cat`, `env`, `printenv`, `set`, `tee` (also by path, e.g. `/bin/echo`); pipes (`\|`) and redirects (`>`) are blocked; shells and interpreters given inline code or code from stdin are refused (`sh -c`, `bash -s`, `python -c`, `perl -e`, `node -e`, `bun -e`, `deno eval`, `php -r`, `julia -e`, `Rscript -e`, `osascript -e`, `expect -c`, `pwsh -Command`, `cmd /c`, `tclsh`/`jshell` reading stdin, `deno` with no script, which starts its REPL), as is `powershell` unless `-File` comes first (Windows PowerShell 5.1 runs a plain first argument as code; the rule goes by the program's name, so a PowerShell 7 binary or image named `powershell` gets it too: use `-File`, which both accept), and `-File -` or no script at all for both `powershell` and `pwsh` (they read code from stdin); for `powershell`'s own parameters only one `-` or `/` before the full names and the short forms `-ep`, `-ex`, `-nop`, `-noni`, `-nol`, `-noe`, `-w`, `-f`, `-if`, `-of` is trusted. Refused too are `wsl` without `-e` or `--shell-type none` (wsl.exe runs its command line through the Linux shell, `$SHELL -c`, which parses a substituted value again: write `wsl -e ./deploy.sh {{secret}}`) and `wsl` with no command (a login shell reading stdin), `awk` without `-f`, `xargs`, `busybox`, `watch`, `parallel`, `script`, `ssh host <command>`, and `find -exec` running any of these, including behind wrappers and launchers (`timeout`, `nice`, `sudo`, `uv run`, `poetry run`, `npx`, `bundle exec`, `docker run`, `kubectl exec`), since inline code can transform a value past output redaction (#105). Script files stay allowed |
| Secrets in config files / repos | `tocomment` replaces inline values with `# tswap:` markers; `redact` masks values for safe viewing |
| Single YubiKey loss | Keyring vault: every enrolled key, machine and the recovery key opens it alone. Classic vault: XOR key reconstruction — either key derives the other via the XOR share stored in `config.json` ([how the classic vault worked](upgrading-from-0.1.md#how-the-classic-vault-worked)) |
| Vault access without physical presence | Depends on the slot: a **touch-required YubiKey** needs a button press per unlock; a **`--with-touch` Secure Enclave** slot asks for Touch ID or the password per unlock, a **`--no-touch`** one never does; a **no-touch YubiKey** and a **TPM** slot without a vault password unlock for any process running as you while the key is plugged in / on that machine |
| Another local user (no root) with the hardware or a copy of the vault folder | Optional **vault password** on a slot (0.2): the TPM or Secure Enclave checks it, a YubiKey slot mixes it into the key; held by `tswap agent` or typed per command. A vault is only as strong as the weakest slot usable on that machine. See [What the vault password does and doesn't protect](#what-the-vault-password-does-and-doesnt-protect) |
| Privilege escalation by agents | sudo boundary — `get`, `add`, `list`, `apply`, `delete`, `restore`, `import`, `export`, rotating a secret that isn't burned ([rotating-and-burning.md](rotating-and-burning.md)), and vault administration require sudo; agents should never run sudo |
| Recognising a value in the vault folder | Record format 3 keeps keyed fingerprints of every value only inside AES-GCM-encrypted metadata sections (keys derived from the vault key): no cleartext hash of any value exists to test guesses against |
| A reading command decrypting values it doesn't use | Since 0.3 the eight reading commands and `run` decrypt only the value versions they print or substitute (`run`: its `{{name}}` / `{{name:previous}}` tokens and its files' markers): `redact`, `tocomment`, `check`, `names`, `list` and `burned` decrypt none on format 3 records, `get` and `apply` only the ones they output. The write commands do the same: `create`, `ingest`, `rotate`, `burn`, `delete`, `add` and `import` decrypt no value on format 3 records and `restore` only the one it puts back, each reading only the records of the names it is given (`import`: every exported name, to skip the ones the vault holds), except where such a record itself can only be decided or merged by its value ([what each command decrypts](#what-each-command-decrypts)) |

### What tswap does not protect against

| Non-goal | Why |
|----------|-----|
| Determined local attacker with root | Root can attach debuggers, read `/proc/*/mem`, or intercept syscalls — no userspace tool can prevent this |
| Sophisticated exfiltration via `run` | The blocklist is shallow by design. Commands like `curl`, a script file, or custom binaries (and `cp` without a file token) can still exfiltrate secrets passed through token substitution. The inline-code check knows a program by the name in the command, normalised as Windows does (`pwsh.exe.`, `pwsh.exe::$DATA` are `pwsh`); a word with a stream suffix is read by the name before its `:` (`pwsh:s`, `pwsh.:s` are `pwsh`); a Windows 8.3 short name (`POWERS~1.EXE`), a link or a copy under another name can't be matched as text, so it runs an interpreter unchecked. A script path under `/dev` or `/proc` (other than `/dev/null` and `/dev/shm`), in any spelling the system resolves (`/dev/./stdin`, `../../dev/stdin`, `/proc/self/root/dev/stdin`), or a Windows console name (`CON`, `CONIN$`, `CONOUT$`), is refused, because it can read stdin or the terminal. A symbolic link elsewhere is not followed, so an interpreter reading its script through one runs unchecked. A relative path resolved in another context (a container's working folder, `wsl --cd`, `sudo -D`, `chroot`) isn't checked, because the command line doesn't show where it resolves. Behind `docker run` and the other wrappers, an image whose name names an interpreter (`python:3.12`, `mcr.microsoft.com/powershell:7.4`, a digest such as `python@sha256:…`) is checked as that interpreter; an image whose entrypoint is an interpreter but whose name doesn't say so still runs its inline code unchecked, and an image reference given as a plain argument after the command (`docker run img skopeo inspect python:3.12`) may be refused as that interpreter. A flag built from tokens is checked again after substitution (`pwsh -{{a}} {{b}}`). Known gap of the inline-code check, filed: System32's `bash.exe` (WSL's launcher) runs its command line through `/bin/bash -c` (#411). Accepted over-refusals (the check fails closed): any `/dev` or `/proc` word (other than `/dev/null`, `/dev/shm/`) anywhere after `pwsh`, `powershell` or `deno`, or before or at an interpreter's script (`python3 --check-hash-based-pycs /dev/stderr tool.py`, `python3 /proc/self/root/tmp/tool.py`); a file named `con…` up to its first dot, and a `\\.\` path, on every OS; `deno` with no script (`deno --version`, `deno -h` included), `deno fmt -`, run options with no subcommand (`deno -A main.ts`: write `deno run -A main.ts`), `deno -- app.ts`, `deno --env=x run app.ts` and `deno -v x`; `wsl` without `-e`/`--shell-type none` (write `wsl -e ./deploy.sh {{secret}}`), `wsl ~ -e ./x.sh`, `wsl {GUID} -e ./x.sh`, `wsl --install --no-launch` and `wsl -d` with a missing value |
| Compromised YubiKey firmware | tswap trusts Yubico's .NET SDK (built into the binary) and the YubiKey's HMAC-SHA1 implementation; firmware-level attacks are out of scope |
| Secrets in process memory | During `run`, a secret's plaintext exists in the subprocess memory, wherever `run` put it. Memory forensics or core dumps could recover it. Who else can read it while the command runs depends on the form (below): none of them hides a value from the agent's own user, which starts the child and can read all three; against the agent itself that stays the job of output masking and of running work under another user (the broker) |
| Network interception | Once a secret is passed to a legitimate program (e.g., `psql`, `rclone`), tswap has no control over how that program transmits it |
| Another process holding the YubiKey lock | The lock that makes tswap commands take turns at the key (`~/.cache/tswap/yubikey.lock`) is a courtesy between one user's tswap processes, not a boundary: any process running as you can hold it (your tswap commands then wait and time out after 60 s), another user's tswap doesn't take yours, and a program that doesn't take it (ykman, a browser, an older tswap) can still interrupt a command (then the cut-short or busy text). A lock file owned by root (only if your home is root's) is no wedge either: your tswap warns and runs without the lock, but without its protection |
| Silencing the touch notice | The acknowledged postures live in `config.json`, writable by any process running as you; the changed-posture notice is advisory. `tswap slots` shows each slot's recorded posture: a YubiKey's from its slot, a Secure Enclave's from `config.json` |
| Brute-force on encrypted vault | A record vault's key is random (256 bits) and wrapped per slot. A classic vault (`secrets.json.enc`): AES-256-GCM + PBKDF2 (100k iterations) raises the cost, but the file could be attacked offline if both the file and the XOR share (in `config.json`) are obtained without a YubiKey |

### Who can read a secret `run` hands to a command

`run` has three ways to hand a command a secret (brief T26, #71). The agent's prompt prefers them in this
order: a `{{@file}}` copy, then `--env`, then a `{{name}}` in an argument.

| Form | Linux | macOS | Windows |
|---|---|---|---|
| `{{name}}` in an argument (the child's argv) | every local user while the command runs (`/proc/<pid>/cmdline`, `ps`), unless `/proc` is mounted with `hidepid`; also process accounting and audit logs | every local user while the command runs (`ps`) | — |
| `--env NAME={{name}}` (the child's environment) | the same user and root (`/proc/<pid>/environ`) | the same user and root | anyone who can open the child process |
| `{{@file}}` (a filled copy; only its path is in argv) | the same user and root (a private `0700` folder) | the same user and root | the current user (a current-user-only access list) |

The copy is zeroed and deleted when the command ends; SIGKILL or a power loss leaves it until the next
file-token `run` sweeps it ("Files with secrets", below). On a machine with several users, mount `/proc` with
`hidepid=invisible,gid=<group>` ([commands.md, `run --env`](commands.md#run---env)).

### What each command decrypts

Since 0.3 the commands that only read (`redact`, `tocomment`, `check`, `names`, `list`, `burned`,
`get`, `apply`) decrypt only the values they use (owner: "unlocking all secrets is bad practice"),
and so do the write commands, which read only the records of the names they are given (the table). A format 3 record keeps its value versions in separate
encrypted sections, so a command can read a record's name, burns and fingerprints without opening
a value. A **format 2** record (written by tswap 0.1, and kept until `sudo tswap vault reindex`
rewrites it) holds name and both value versions in one encrypted block: a command that must read
it decrypts it whole, wipes the values it doesn't use at once, and prints a warning with the number
of such records and the reindex command. A record counts as format 2 when its main file or any of
its sync-conflict copies is; a copy that is damaged or of another format is skipped with a warning
and doesn't make the record format 2.

| Command | Format 3 record | Format 2 record |
|---|---|---|
| `redact`, `tocomment` | No value: metadata sections only, values recognised by their fingerprints | None: the command refuses before it opens the file, and asks for `sudo tswap vault reindex` |
| `names`, `burned`, `list` | No value | Decrypted whole to read its name and burn state; the values are wiped unused; a warning |
| `check` | No value | Only a record a marker names, decrypted whole; a warning |
| `get` | The one value it prints (the current version of that secret) | That record, decrypted whole; a warning |
| `apply` | The value versions it fills in, each once; none for a line already filled | Each record a marker names, decrypted whole; a warning |
| `run` | The value versions it substitutes (its tokens and its files' markers), each once; every other record's metadata only | Each record a token or marker names, decrypted whole; a warning after the child's output |
| `create`, `ingest`, `rotate`, `ingest --rotate`, `burn`, `delete`, `add`, `import` | No value: only the records of the names given are read, their metadata (`import`: every exported name, so it can skip the ones the vault holds); a new value is encrypted, a kept one copied as it is (exceptions below) | Each format 2 record of those names, decrypted whole (`import`: each exported name the vault holds as format 2, up to the whole vault, though it writes none of them); a warning |
| `restore` | The one value it puts back (the previous version, encrypted again as the new one; exceptions below) | That record, decrypted whole; a warning |
| `field set`, `field unset`; `create`, `ingest`, `rotate`, `ingest --rotate`, `add` with `--field`/`--fields` | No value: every record's metadata, for the check that no field holds a stored value ([fields](#fields-plain-visible-data)); the value command's own value as above | None: the write is refused before anything is written, and asks for `sudo tswap vault reindex` (`field unset` sets no value and isn't refused) |
| `field show` | No value: the one record's metadata | That record, decrypted whole; a warning |
| `field adopt` | The one value it turns into a field (the current version of SECRET), and every record's metadata | None: refused as `field set` is |
| `export`, `migrate` | Every value, by their nature | The same |
| `vault merge`, `vault reindex` | Every value for now (a follow-up, #271, narrows them) | The same |

The write commands' exceptions are confined to a record of a name they are given, and decrypt only
that record's values:
`add` over a secret whose stored fingerprints are of another variant-set version (a machine of an
older or newer tswap wrote it), or missing, compares that one current value to tell "same value"
from a new one (if it can't be decrypted, `add` refuses, naming the file, and writes nothing); a
kept value version without fingerprints (only a planted record has one) is fingerprinted from its
own value, and kept without fingerprints, with a warning naming the file, if that value can't be
decrypted (per kept version: a planted record with neither version fingerprinted gets both
decrypted); and a record whose sync-conflict copies only their plaintext can merge is decrypted
whole, as before, so its copies still converge when it is written (for `restore` that is two values,
not one; `create` or `ingest` of such an existing name, and `import` skipping one, decrypt it whole to
see that it exists).

What the format 2 warning and the `redact`/`tocomment` refusal say: the count of records and the fix
only, never a secret name (a format 2 tombstone's would reveal a deleted secret), a hashed file name,
a value or its length. The count is what anyone who can list the vault folder can tell anyway: a
record's format is a cleartext byte of its file. The texts about one record that can't be read or
used (an unreadable record, `add`'s refusal above, a kept version without fingerprints) are
different: they name that record's hashed file, so the user can restore it, and never a value.

Limits of reading metadata only:

- `redact` and `tocomment` find what the fingerprints describe. A record whose fingerprints don't
  describe its stored value (only a write bug, or someone holding the vault key, can make one) has
  its stored value printed unmasked by `redact`, unless it matches the unknown-secret heuristic, which
  masks it as `[POSSIBLE SECRET]`, and left in place, unmarked, by `tocomment`. Detecting that needs the value, which these
  commands must not decrypt; `get` and `apply` still check it and refuse that record.
- `check`, `names`, `list` and `burned` don't open value sections, so they don't notice a damaged
  value section: they list the record as sound. The command that uses the value fails closed,
  naming the file.
- Merging a record's sync-conflict copies without the plaintext: two copies of one version with
  different ciphertexts can only be shown equal by their fingerprints. Where a copy has none, the
  record can't be read on this path: `list` and `check` refuse it, naming the file, and `names` and
  `burned` warn and leave it out, where the full load would have merged them. A write of that record
  (or `vault merge`, `vault reindex`) converges the copies.
- The write commands don't check a value they keep: a `burn`, `rotate`, `ingest --rotate`, `add`
  (a changed value, or a same value its fingerprints confirm) or `delete` of a record with a damaged
  value section, or fingerprints that don't match its value, succeeds and carries it forward byte for
  byte (a delete drops it); `create` and `ingest` refuse its name as existing. Whoever uses that value
  (`get`, `apply`, `run`, `restore` of it) still fails closed, naming the file.
- A write's time stamps follow this machine's last stamp and the written record's own, no longer
  every stamp in the folder: a machine whose clock lags another's stamps its writes with its own
  time unless that record carries a later one. Ordering within a record, the only ordering the
  merge uses, is unchanged.
- Strings are not zeroed: a value `get` or `apply` prints lives in memory as a string until the
  process exits, as before (there are just fewer of them).

### What `run` masks

`run` masks its own substituted and `--env` values in every form it wrote (as before), and since 0.3 every other
value version in the vault that has fingerprints, by those fingerprints alone: during the child run
only the substituted values, the fingerprints and the fingerprint key are in memory, not the rest of
the vault. Records that can't be matched (format 2 records, a version without fingerprints, an
unreadable record) are counted in a warning printed before the child starts and again after it
exits; `run` keeps working (owner decision).

| Output contains | Masked |
|---|---|
| A substituted value's forms (raw, escaped in a file, base64/base64url padded and unpadded, the `\r\n`, `\n` and PTY-printed forms of a multi-line value and their encodings) | yes¹ |
| Any other vault value, current or previous, burned included: verbatim, whitespace-stripped, base64 padded, base64url unpadded | yes¹ (a value made only of whitespace: when it arrives in one read, see below) |
| … base64url with padding | the unpadded core¹; the `=` stay visible |
| … base64 with its padding removed; wrapped base64; a re-indented PEM (YAML block); JSON, URL or hex encodings; inside a larger base64 blob | no (a later variant-set version) |
| … multi-line, through a pipe (line endings as stored or `\n` only) or a PTY (`\n` printed as `\r\n`), except a value made only of whitespace (see Limits) | yes¹ |
| Records not fully fingerprinted, or unreadable | no; warned before and after the child |
| A secret added while the child runs | no (the matcher is built at the start) |

¹ Short values (under 8 characters): only where they stand alone, see Limits.

Limits:

- **Only complete occurrences are recognised** (recognising prefixes is deliberately not done: it
  would be a prefix oracle). Text that lies in no complete occurrence is written when it leaves the
  redactor's hold window, when held output is released at a prompt, or at exit. So a secret printed
  only in part (cut short, split by an input wait, completed later by another thread or a
  background job) shows that part. The same was true before 0.3.
- **A value made only of whitespace** (spaces, tabs, line breaks) is masked when it arrives in one
  read, also through a terminal, but not when a read boundary splits it: tswap can't tell such a
  record from a single-line one by its fingerprints, and holding back every read's trailing
  whitespace for that would hold every line end. Such a value can only be stored with
  `sudo tswap add` (`ingest` trims trailing whitespace), which warns when a value ends in
  whitespace or is only whitespace.
- **Short values are matched as whole words only** (brief T30, #314). A value version shorter than 8
  characters (UTF-16 code units, `Validation.ShortValueLength`) is masked, in every form of it (plain,
  whitespace-stripped, base64, base64url, and for `run`'s own values every escaped file form and encoding,
  even where that form has 8 characters or more), only where the occurrence stands alone: at each of its
  ends that is a word character, the character beyond is not one, the start and end of the text counting
  as non-word. A word character is what `tocomment`'s `[-\w]` matches: a letter, a non-spacing mark, a
  decimal digit, connector punctuation (`_`), or `-`; an end that is not a word character constrains
  nothing (`#42` is masked in `x#42`). So `465` is masked in `port=465`, `"465"`, `:465/` and `1.465`, but
  not in `65465` or `4650`; `web` is masked in `host: web.example`, but not in `web-ngx`, `webster` or
  `/home/webster`. `name` and `name:previous` are separate versions, each by its own length.
  Values of 8 characters or more are still matched anywhere, inside longer words and numbers too:
  `run` (and the broker) redact output that may be hostile, and whole-word matching for every value
  would let a command leak a secret by gluing it to letters (`echo x{{pw}}x`). What the rule costs: a
  short secret printed inside a longer word or number, or glued to another masked value (neighbours are
  read in the original output, not in the masked one), shows unmasked, with no notice. There is none by
  design: a note that "a short value occurred inside a word" would confirm guesses (a command printing
  candidates and reading the note) and bring back the false burns the rule removes. A short value that
  stands alone (`False` in `x is False`, `465` in `"port": 465`) is still masked, since it can't be told
  from the secret itself; such a value belongs in a field. `add`, `ingest`, `ingest --rotate`, `create`
  and `rotate` warn when they store a value shorter than 8 characters ([commands](commands.md#commands)).
  `redact` follows the same rule; `tocomment` already replaced a value only between `[-\w]` boundaries,
  for every value, and still does; since 0.3.3 it also replaces one only where `apply` can fill it back. The fields guards (a field value containing a secret is refused) and
  the broker (it never emits a known form) still match every value anywhere. Streaming: a read boundary
  counts as a word boundary, and the redactor holds back the trailing word (up to 256 characters) so the
  next read starts on a word's first character; in rare cases (a run of word characters longer than 256
  split by a read with a short value at the split, output held for a long value's prefix, output
  released at a prompt in mid-word) a short value inside a word is masked anyway: extra masks, never
  fewer.
- **A secret split between stdout and stderr** is not recognised when output is redirected
  (RedactingPty's pipe runner redacts each stream on its own).
- **Held output at a prompt.** To catch a value split across reads, the redactor holds back the end
  of the output: for single-line secrets only the trailing word, but a multi-line secret (a PEM key)
  could start anywhere, so up to its length is held on every pause. When `run` substitutes a value
  under 8 characters (in an argument, `--env` or a `{{@file}}`), the trailing run of characters other
  than whitespace is held as for a vault value (up to 255 characters), so a line that ends in a line
  break still shows at once; only when such a value contains a space, tab or line break are at least
  the last 255 characters held on every pause, whatever they are, so streamed output (`logs -f`) then
  arrives in batches. A pending point inside a word is
  moved back to the word's start, so the trailing word may be held up to 256 characters further back
  (brief T30). `run` releases held output
  (masking complete occurrences first) when the child waits for terminal input. **Linux:** when no
  thread of the terminal's foreground process group is running and one is blocked in `read` on the
  terminal (`/proc`); programs that wait in `poll`/`select` (bash's readline prompt) stay held.
  **macOS:** when the terminal's echo is off and canonical mode on (password and passphrase prompts);
  a plain `y/N` prompt stays held until more output or exit. **Windows, and redirected output:**
  never; held output waits for more output or exit. Time alone never releases held output.
- **The hold-back is observable.** A child (or the agent reading the output) can see when output
  appears, so how much is held. What is held depends on the text, on the constant 256-character word
  hold, and on figures each rounded up to a multiple of 256 characters: two vault-wide ones (the
  longest value per character class, and the largest whitespace count of a multi-line value) and, when
  `run` substitutes values under 8 characters, one bucket for their forms without whitespace and one
  for their forms with it, each saying only that such a form exists. So it reveals a 256-character
  bucket of those, whether the vault holds a secret with whitespace and whether this run substituted a
  short value, and one with whitespace, nothing finer than the vault folder's 256-byte record buckets
  already show, and nothing about a guess's prefix.
- **A guessing oracle, as `redact` already is:** a child can test a guess against every vault value
  by printing it and watching for a label; the labels show secret names, which `names` lists anyway.
- **A redaction failure fails closed:** the held text and the rest of the output (of that stream, when
  output is redirected and stdout and stderr are redacted on their own) are discarded, a
  marker `[output truncated: redaction failed]` is written, and `run` ends with an error whose text
  holds no output.

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

A multi-line value (a PEM key, a JSON document) or one with another control character is written as
an escaped double-quoted string (`\n`, `\r`, `\t`, `\uXXXX`, besides `\\` and `\"`), which YAML and
JSON both read back byte for byte; a `''` marker line is written with double quotes for such a value.
A `KEY=` line (`.env` style: `KEY=""`, `KEY=''`, `KEY=`) refuses it, naming the line and the marker,
before anything is written: `.env` parsers disagree on escapes (Docker's `--env-file` reads the quotes
literally), so pass such a value with a `{{name}}` token or use a YAML file.
A filled file is written literally, so if a shell sources it (`source .env`, `. ./.env`), a value
containing `$(...)`, a backtick or another `$` runs a command or expands there (the `\"` and `\\` of a
double-quoted line read back correctly). A shell-sourced file therefore needs single-quoted values
(`KEY=''`), and a value containing `'` breaks even that: the `''` a single-quoted line gets for it
reads back as nothing.

This replaces `apply` for agents, which now needs sudo. What it does not do:

- **A process running as the same user can read the copy while the child runs.** An agent that
  starts a second command to read the file in that time gets the values. The folder keeps out other
  users, not you.
- **The word check is a shallow guard.** It refuses the obvious one-step printers and copiers, as
  the `run` blocklist does. A program that sends the file over the network (`curl -F f=@{{@f}}`,
  `wget --post-file`, `git`, cloud CLIs), and any transformation beyond the redacted forms (a value
  inside a larger base64 blob, a custom encoding), still gets the values out. So does an image's interpreter
  entrypoint given the copy as its script (`docker run -v {{@f}}:/x.py python:3.12 /x.py`): the word check sees an
  image and a path, not a printer.
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
| Linux TPM | This machine's TPM (the machine slot); no PCR policy | No: without a vault password, any process running as you can unseal it | Optional vault password (`--password`). If the TPM's lockout password is empty, anyone who can use the TPM can reset its failed-password counter and keep guessing; tswap warns | Verified on two physical TPMs: an Intel PTT on 2026-10-29 (#155), and on 2026-11-07 (#261) an Infineon SLB 9665 too, each with an RSA-2048 slot made by v0.2.0 and a new ECC slot. Since v0.3.0 new slots seal under an ECC P-256 primary (#261): generating it takes 0.26 s instead of 1.74 s on the Intel PTT and 0.63 s instead of 8.2 s on an Infineon SLB 9665, with the same AES-128-CFB child protection ([hardware-backends.md](design/hardware-backends.md#storage-primary-ecc-p-256-for-new-slots-v030-issue-261)); a whole unlock of an ECC slot takes 1.0 s (PTT) and 2.5 s (SLB 9665), and the v0.2.0 binary refuses a new slot with "needs a newer tswap" (#261). Still open: a full host power cycle, `tpm2_clear`. Independent review: not documented | [3] [4] [5] |
| Windows TPM | This machine's TPM (the machine slot); no PCR policy | No: without a vault password, any process running as you can unseal it | Optional vault password. About 4 wrong passwords for one Windows user, or 9 across all standard users, lock **everyone's** TPM use for up to 8 hours | Virtual TPM verified. A physical TPM was run during development (July 2026); its commands and results were not recorded (#156). A re-check of v0.1.0 on two physical machines is open (#156). Independent review: not documented | [3] [5] [6] |
| Secure Enclave, `--with-touch` | This Mac's Secure Enclave; the key never leaves it and works only on this Mac | Yes: Touch ID or the login password on every unlock | Optional vault password (a password Secure Enclave slot) | **PoC-grade.** Verified for correctness (round trips, fails cleanly on denial). The wrapping is a **hand-rolled ECIES equivalent** (ephemeral ECDH + HKDF-SHA256 + AES-GCM) that **has had no independent cryptographic review** (#159). Tested on Apple Silicon only (M4 Pro, macOS 26 and 27.2); Intel T2 Macs untested | [3] [7] [8] [9] |
| Secure Enclave, `--no-touch` | This Mac's Secure Enclave: anything that can run code on this Mac and read this vault's config, from any account, including root | No prompt | Optional vault password, as above | As above (PoC-grade, construction not independently reviewed, Apple Silicon only). Whether it unlocks with the screen locked, over ssh or after a reboot before anyone logs in is not known yet | [3] [7] [8] [9] [10] |
| Recovery key | The recovery private key, printed once at `init`, read only from stdin | Not documented; the key opens the vault without any enrolled hardware | Not documented | Not documented | [11] |

Sources. A date here is when that source's text was written or last changed, not when anything was
checked; dates of checks are in the Reviewed / verified column.

1. [Issue #158](https://github.com/stevedcc/TokenSwap/issues/158), work item 4 (2026-07-28).
2. [YubiKey: touch or no touch](#yubikey-touch-or-no-touch), this page (2026-02-21, changed 2026-10-30).
3. [What the vault password does and doesn't protect](#what-the-vault-password-does-and-doesnt-protect), this page (2026-11-03).
4. [hardware-backends.md, Linux TPM status](design/hardware-backends.md#status-verified-on-two-physical-tpms-intel-ptt-and-infineon-slb-9665) (2026-11-07).
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

Everything in this section holds for a FIDO2 slot on a security key of any brand (brief T19): the
key's own PIN counter, the relying party and the silent probe are CTAP2's, not Yubico's. On Linux
and macOS a key that isn't a YubiKey goes through libfido2 ([above](#libfido2-under-sudo-root-owned-only)).

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
  tries left, and tries FIDO2 slots last, after every slot that needs no PIN. A key whose PIN is
  blocked, or a YubiKey that needs re-inserting after three wrong PINs, is refused before the PIN
  prompt.
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
  `sudo tswap vault merge <a copy of this vault folder>` on that machine. That merge unlocks the copy first, so the machine
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
- **The tswap CLI writes no core dump** (#297, v0.3.0): it starts with a soft core limit of 0 (Linux, macOS), so a
  crash or Ctrl+\\ at the PIN prompt doesn't put the PIN, the vault key or secret values on disk (systemd-coredump
  honours the limit: measured on Fedora; on macOS the soft limit is already 0 by default and tswap keeps it there).
  Best effort: if the limit can't be set, the command still runs (the agent, which holds the password for hours,
  refuses instead). It stays dumpable otherwise: the agent and the broker check a client through its `/proc`
  links, which a non-dumpable process closes, so another process of the same user can still read its memory, as
  before. Windows is unchanged (Windows Error Reporting follows its own settings). A command that `run` starts gets
  the soft core limit of 0 too (it can raise it).
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

## Fields: plain, visible data

Fields are bundled storage for convenience: everything about a credential is kept in one place next to
its secret (the username, the URL, where the value is used, where its master copy lives, how to rotate
it). They are plain, visible data, not a second kind of secret and not a way into commands. Commands and
formats: [commands.md](commands.md#fields-plain-data-next-to-a-secret).

- **Fields are visible.** They are stored inside the record's encrypted metadata section, so neither the
  vault folder nor a sync provider shows them, but anyone who can run tswap as you reads them with
  `tswap field show`, without sudo, and agents are told to. No command redacts, burns or fingerprints a
  field. A password manager is the place for a person's own credentials; a field can say where the master
  copy lives (`source`).
- **Guard rail 1: no secret in a field.** Every value a write sets is checked against the keyed
  fingerprints of every stored value (every retained version of every live secret, burned ones included;
  no value is decrypted), and with a value command also against the value of that call. A value that
  contains one is refused without naming which secret. A long random-looking value only gets a warning.
  On a vault with records that have no fingerprints yet (format 2) every field write that sets a value is
  refused until `sudo tswap vault reindex`, since the check can't see those values (`field unset` sets
  none and works). Its limits:
  - **Merges and imports are not checked.** `vault merge`, a sync tool's copies and `import` carry fields
    from your own machines and exports as they are; a peer or an export you don't trust can do worse than
    put a value in a field.
  - **Unicode forms.** Since 0.3.3 a stored value is recognised in its stored, NFC and NFD spellings, and
    in the base64 and base64url of each, by `redact`, `tocomment`, `run`, the broker and this check (a
    field is also stored in NFC and checked both in that form and as given). Left out: a mixed spelling
    that is neither normal form (part composed, part not), and compatibility forms (full-width letters,
    ligatures), which are other text. Records fingerprinted by an older tswap get the other spellings with
    `sudo tswap vault reindex`.
  - **Deleted secrets' values are not checked**, so a value `field adopt` moved into a field can be set
    again.
  - **The warning the other way round is narrower.** `add`, `ingest`, `ingest --rotate` and `rotate` warn
    when the value they write already sits in a field (naming `NAME.FIELD`), but only when the same call
    gives `--field` or `--fields`: without them a value write reads only its own record. A plain rotate to
    a value that some field already holds goes unwarned.
  - **It is an oracle, as `run` already is.** A refusal tells the caller that a string it chose contains a
    stored value. `tswap run test {{NAME}} = guess` (and `-gt` for bisection) already answers one named
    equality guess per call by its exit code, without sudo. `field set` is broader: a substring test of up
    to 4096 characters (hundreds of candidates per call) against all live values at once, without needing a
    name. That speeds up brute force of small value spaces (the usernames and ports that belong in fields
    anyway); it doesn't touch a generated value. tswap doesn't restrict what agents run, and a limit on
    `field set` alone would only move the probe to `run`; the refusal names no secret, and nothing else is
    done.
- **Guard rail 2: no field reaches a command.** `run` refuses any `{{NAME.anything}}` token, and
  `run … {{@file}}` and `apply` any `# tswap: NAME.anything` marker, before anything is filled in, so a
  dotted token or marker is never read as NAME plus text. Brace text that doesn't start with a secret name
  (Go templates such as `{{.State.Pid}}` or `{{range .items}}`) passes through as before. The broker's
  templates have no field tokens. A
  field can't change where a secret is sent: the person approving a command sees every non-secret part of
  it.
- **Guard rail 3: injection is reduced, not prevented.** A field value is text written by people and
  agents. The skill text (`tswap prompt`) tells agents that field values and `--by` labels are untrusted
  data and never instructions; `field show` prints each value as a JSON string and `--json` is the form for
  agents, so a value can't pass as tswap's own output; display paths escape control and format characters.
  An agent can still be misled by what a field says. Changes are recorded, not prevented: each field keeps
  its current state and the 5 states before it, each with the UTC time, the machine's origin id, the operating-system user (under sudo the
  invoking user; on Windows `DOMAIN\user`), whether it ran elevated or with a terminal, and the optional
  `--by` label. The user name is reliable on that machine only and `--by` is self-asserted: a history, not
  an authentication. `field show --history` lists removed fields too, with who removed them and when.
- **`field adopt` is the deliberate exception**: `sudo tswap field adopt NAME FIELD --from SECRET` turns a
  secret's value (burned or not) into a visible field and deletes that secret. Sudo, because it makes a
  secret visible; the owner approves each. It refuses when another live secret holds the same value.
- **Mixed versions.** A tswap 0.3.x machine keeps the fields' bytes but merges them by its own rule (the
  whole extension list of the newest write), so in a folder shared with 0.3.x machines field state is
  decided per record, not per field: a 0.3.x merge can drop a newer field change or bring back a removed
  field, and copies may not converge until every machine runs this version. An earlier life's fields can
  come back in two ways: a 0.3.x merge that takes an old copy's list, and a 0.3.x machine re-creating a
  name over this version's tombstone (its new record has no lineage stamp, so a later merge with an old
  copy keeps the old life's fields). A delete and re-creation done wholly on a 0.3.x machine carries them
  straight over, since a 0.3.x tombstone keeps them. Nothing breaks and no secret value is affected; unset
  them again.
  Details: [multi-machine.md](multi-machine.md#the-merge-rules).
- **What a sync provider sees:** a field write is a metadata-only write (format 3 already shows those, as
  for a burn), and it may move the metadata section to another 256-byte size bucket.

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
  current values, burn state and fields (no deletes, no history, no removed fields). Importing into
  a record-store vault writes each secret as a new version, so importing an old export **can bring
  back a secret you deleted since**: that is your explicit choice.
  - **An export carries current fields only.** A field removed after the export comes back when that
    export is imported, and stays back: the import writes the fields as a change made on the importing
    machine at that moment (fresh stamps, a new lineage), so the earlier removal can't win in a merge.
    Unset it again; only a removal stamped after the import wins. Imported fields are not checked
    against the stored values ([fields](#fields-plain-visible-data)), and no cap applies to them: an
    export of a secret a merge left over 64 fields or 64 KiB imports with every field, as the merge kept them.
- **Permissions:** the vault folder, `records/` and the config folder are created 0700 and their
  files 0600; an existing vault with wider permissions is narrowed when a command opens it (the vault
  folder; the config folder before the first write), with a notice; only files you own. Under sudo,
  tswap does its file work as the folder's owner. (Windows: no change; files inherit
  the profile folder's permissions.)
