# tswap broker: credentials for containers that never hold them

This guide is for operators who set up `tswap broker` on a host: the vault user, sockets and routes,
systemd, SELinux, the ssh agent and command templates, and the platforms and limits. What the broker
protects against, and what it doesn't, is in [the broker's threat model](broker-threat-model.md).

`tswap broker` is a credential-adding HTTP proxy. A container sends a plain HTTP request to a
loopback port inside itself; the broker, running on the host as the vault's user, unlocks the
vault, adds the route's credential to the request and sends it to that route's HTTPS upstream.
The container never sees the credential, the vault files or the TPM.

```
container                                  host (vault user)                     internet
---------                                  -----------------                     --------
git / podman / SDK                         tswap broker serve
  -> http://127.0.0.1:8080/<route>/...       /srv/tswap-broker/<socket>.sock
tswap broker forward  --(bind-mounted Unix socket)-->  peer uid check, route check,
                                             fresh unlock, add header  --HTTPS-->  upstream
```

- `tswap broker serve` runs as the vault's own user (a systemd user unit) and listens on one Unix
  socket per client.
- `tswap broker forward --listen 127.0.0.1:<port> [--socket /run/tswap.sock]` runs inside the
  container and relays each TCP connection on that loopback port to the socket, byte for byte.
- `sudo tswap broker route|socket add|remove` and `sudo tswap broker socket bind` change `broker.json`.
  Each socket names the container it serves, or says it is `uid_only` (see [Limits of the identity
  check](broker-threat-model.md#limits-of-the-identity-check)).
- **Command templates** (Linux only): `tswap broker call <template> [name=value ...]` inside the
  container asks the broker to run an operator-defined command on the host, in a `bwrap` sandbox,
  with a secret in its environment or a read-only file. See [Command templates](#command-templates).
  `sudo tswap broker template add|remove` changes them.

Linux and macOS only. On Windows, `tswap broker` says it is not supported.

## Costs

- **Every request unlocks the vault afresh** (no cached key, by design). On the router's TPM that
  is about 2 s: a model API call through the broker gets about 2 s slower, and so does every git
  or registry request (a `git push` makes two or three).
- Unlocks are serialised, so concurrent requests queue for the TPM.
- One request per connection: the broker answers every request with `Connection: close`.

## Redaction confirms whole guesses

A caller whose input comes back in a response can test whole guesses at a secret: a match comes back as
`[REDACTED]`. Use generated values (`tswap create`) for routes and templates; `serve` logs a warning for a
secret shorter than 16 bytes. The full text: [Redaction confirms whole guesses](broker-threat-model.md#redaction-confirms-whole-guesses).

## Setting up the broker

**Two rules before you start** (the threat model explains both):

- **The vault user is root-equivalent for its secrets:** it must run nothing but `tswap broker serve`
  ([why](broker-threat-model.md#the-vault-user-is-root-equivalent-for-its-secrets)).
- **No container may run with the vault user's uid:** never start containers as the vault user
  ([why](broker-threat-model.md#the-load-bearing-assumption-no-container-runs-with-the-vault-users-uid)).

You run the `sudo tswap broker ...` commands from your own account. Under `sudo`, tswap uses the vault of
the user who ran sudo, so each of them sets `TSWAP_CONFIG_DIR` to the vault user's config folder
(here `/home/vault/.config/tswap`). `sudo VAR=value` needs a sudoers rule that allows setting
variables (implied for an `ALL` command); otherwise use `sudo env TSWAP_CONFIG_DIR=… tswap ...`.

### 1. The vault user

A dedicated user (here `vault`) holds the vault and is the only member of `tss` that does. Its
vault is a TPM vault (`tswap init --tpm`), so it unlocks unattended. `init` makes a record store
(one file per secret), so a request decrypts only its own record. `init` asks whether the slot
gets a vault password; with one, the broker starts locked (see
[A broker with a vault password](#a-broker-with-a-vault-password)).

```bash
sudo useradd -m vault
sudo usermod -aG tss vault
sudo loginctl enable-linger vault      # its user units run without a login session
sudo -iu vault tswap init --tpm
sudo -iu vault tswap ingest github-token < token-file    # or create; or add, with sudo as in step 3
```

**A vault made by tswap 0.1** (a classic single-file vault) must be converted first: `serve` refuses
it. `migrate --to-records` needs root (it unlocks the vault and rewrites it), so it can't run as
`sudo -u vault`:

```bash
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap migrate --to-records
```

Run as root on the vault user's folder, tswap does every file write in that
folder **as the folder's owner** (it switches to the owner's effective uid and gid, with no
supplementary groups), so the keyring, the records and `config.json` come out owned by `vault`,
mode 0600, and a link `vault` planted in its own folder gets no further than `vault`'s own rights.
The test suite checks this. The `sudo VAR=value` note above applies here too.

### 2. The socket folder

Owned by the vault user, mode `0711` (others can reach a socket file they know the name of, but
can't list or create entries), not a symlink. `serve` resolves its real path (following any
symlinked parent) and checks **every folder above it**: each must be owned by root (or the vault
user) and not writable by group or others, so nobody else can swap a parent for one of their
own; a root-owned folder with the sticky bit, such as `/tmp`, is accepted. `serve` refuses to
start otherwise. Every folder above it must also be traversable by the user that starts the
containers (so `/run/user/<uid>`, which is `0700`, won't do).

```bash
sudo install -d -m 0711 -o vault -g vault /srv/tswap-broker
```

#### SELinux

With the `tswap-broker` module (`contrib/selinux/tswap-broker.cil`), the broker runs in its own
domain, `tswap_broker_t`, and containers may connect to the broker's sockets and to nothing else of
the vault user's. Only a dedicated copy of the binary (`/usr/local/libexec/tswap-broker`) is labelled
to enter it; the `tswap` everyone runs stays `unconfined_t`. What the module allows, attribute by
attribute, and why: [SELinux in the threat model](broker-threat-model.md#selinux).

On Fedora and Fedora CoreOS, with SELinux enforcing and no
`--security-opt label=disable` on the containers, two things stand between a rootless container
and the socket:

1. The socket *file*: a container can't reach a socket labelled `var_t`, and Podman's `:z`/`:Z`
   can't relabel a socket file the container's user doesn't own. The socket folder is labelled
   `container_file_t` once, so every socket `serve` creates there inherits the label; mount the
   socket **without** `:z`.
2. The *connection*: `container_t` may not `connectto` a socket of an unconfined process. The
   `tswap-broker` module runs the broker in `tswap_broker_t` and allows exactly
   `container_t` → `tswap_broker_t` `unix_stream_socket connectto`. It enters that domain only
   from a dedicated, labelled copy of the binary, which the systemd unit runs.

The module is CIL, so `semodule` installs it without a compiler (Fedora CoreOS has no
`checkmodule`), and it carries its own file contexts, so no `semanage` is needed either (Fedora
CoreOS doesn't ship it): the libexec copy is `tswap_broker_exec_t`, and `/srv/tswap-broker` (and
`/var/srv/tswap-broker`, the real path on Fedora CoreOS, where `/srv` links to `/var/srv`) is
`container_file_t`. The whole setup:

```bash
sudo semodule -i contrib/selinux/tswap-broker.cil
# the labelled copy of the binary; after every tswap upgrade, copy it again AND run restorecon
# again: a fresh copy is bin_t, serve then silently runs as unconfined_t, and containers can't connect
sudo install -D -m 0755 /usr/local/bin/tswap /usr/local/libexec/tswap-broker
sudo restorecon -v /usr/local/libexec/tswap-broker
sudo restorecon -Rv /srv/tswap-broker
```

**After every tswap upgrade** the copy and the module must follow the binary. The script `tswap installscript`
generates does both on Linux: where `/usr/local/libexec/tswap-broker` exists it replaces it and runs `restorecon` on
it, and where the `tswap-broker` module is loaded it reinstalls the module embedded in the binary; then restart the
broker (`systemctl --user restart tswap-broker` as the vault user; the script names a running broker but restarts
nothing). It warns when it can't list the SELinux modules or can't find `restorecon` (the new copy would be
`bin_t`), and if it stops between the module and the copy it says so: run it again, since the two must match. By hand: the module first (`sudo semodule -i contrib/selinux/tswap-broker.cil`; the file must be named
`tswap-broker.cil`, since semodule names a module after its file), then both lines for the copy (`install -D …` and
`restorecon -v /usr/local/libexec/tswap-broker`). A new copy without `restorecon` is labelled `bin_t`: `serve` then
starts as `unconfined_t` without any error, and containers can no longer connect (the AVC log shows `connectto`
denied). `ps -eZ | grep tswap-broker` tells.

A `socket_dir` other than `/srv/tswap-broker` isn't covered by the module's file contexts: label it
with `sudo chcon -R -t container_file_t <socket_dir>` (a later `restorecon` on it would undo that),
or add a matching `filecon` line to the module before installing it.

Check, once `serve` runs: `ps -eZ | grep tswap-broker` shows `tswap_broker_t`, and a container
started with SELinux enforcing and without `--security-opt label=disable` gets answers through its
socket (`ausearch -m avc -ts recent` shows no denial).

### 3. Routes and sockets (`broker.json`)

`broker.json` lives next to the vault's `config.json` (mode `0600`). Changing it needs sudo;
under sudo it is written as the vault folder's owner. `TSWAP_CONFIG_DIR` names that folder (see
[Setting up the broker](#setting-up-the-broker)).

```bash
# git over HTTPS (GitHub, basic auth with a fixed user name and a token)
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker route add github --upstream https://github.com --auth basic \
    --user x-access-token --secret github-token --path 'stevedcc/[A-Za-z0-9._-]+\.git/' --methods GET,POST

# a registry with basic auth, under a route named v2 (registry clients always ask for /v2/...)
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker route add v2 --upstream https://registry.crawford.dev/v2 --auth basic \
    --user lane --secret registry-password --path '(?:$|stevedcc/)' --methods GET,HEAD,POST,PUT,PATCH

# a model API with a bearer key (OpenAI-compatible) or a named header
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker route add openai --upstream https://api.openai.com/v1 --auth bearer --secret openai-key --path ''
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker route add anthropic --upstream https://api.anthropic.com/v1 --auth header \
    --header x-api-key --secret anthropic-key --path 'messages'

# one socket per container (or purpose): which host uids may connect, which routes it may use, and
# which container it serves (here a user Quadlet unit lane1.service of host user 1001; see step 7)
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker socket add lane1 --uids 100999 --routes github,v2,openai --socket-dir /srv/tswap-broker \
    --cgroup /user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service
```

`socket add` requires exactly one of `--cgroup <path>`, `--pid <pid>` (a running container's
process; step 7) or `--uid-only` (any process with a listed uid, as in v0.1). A container that
isn't running yet and isn't a Quadlet unit can start as `--uid-only` and be bound in step 7.

Rules (checked on every load, not only on `add`):

- route and socket names are `[a-z0-9-]{1,32}`; names starting with `_` are reserved;
- `upstream` is an `https://` URL (an `http://` one is refused), optionally with a base path;
- `auth` is `bearer`, `basic` (with a fixed user, no `:`) or `header` (an RFC 7230 token, not a
  framing, hop-by-hop, `Host`, `Cookie`, `Content-*`, `Accept*`, `Range` or `If-Range`
  header); the secret is named as `{{name}}` in the file. A stored value
  containing CR, LF or NUL is a hard error, never a header;
- `methods` default to `GET`, `HEAD`, `POST`; `CONNECT` and `TRACE` are never allowed;
- `path` is a regex the decoded path after `/<route>/` must match **as a prefix**: the broker
  compiles it as `\A(?:<pattern>)`, case-sensitive, culture-invariant, never multiline, with a
  match timeout. Inline option groups (`(?i)`, `(?m)`, `(?s)`, `(?x)`, …) are refused. Anchor the
  end yourself (`$`) when a prefix is too wide. The regex never sees the query. The query is
  forwarded unchanged; one containing a raw `#` is refused (the uniform `404`);
- `idle_timeout_sec` (default 120) ends a stream with no bytes moving;
- every socket has exactly one of `container` (`{ "cgroup": "<unit path>" }`, optionally with
  `"selinux_label"`) and `"uid_only": true`. A socket with neither (a v0.1 file) is refused with
  `socket <name> names no container: run "sudo tswap broker socket bind <name> --pid <pid>" or "sudo
  tswap broker socket bind <name> --uid-only"`; the editing commands still write such a file and
  print `still to bind before serve starts: <names>`, so a v0.1 file can be fixed one socket at a
  time. `container.cgroup` is an absolute cgroup v2 path of printable ASCII, at most 1024 bytes,
  ending in a `.service` or `.scope` unit that is not a user manager (`user@<uid>.service`,
  `init.scope`, `manager.scope`), a login session (`session-*.scope`) or the root scope (`-.scope`);
- unknown fields are refused, and `version` must be 1.

A hand edit is allowed but gets the same checks: `serve` refuses an invalid file at start, and on
a reload keeps the config it has.


### 4. The systemd unit

`contrib/systemd/tswap-broker.service` is a user unit for the vault user. It runs the labelled
copy, `/usr/local/libexec/tswap-broker broker serve` (see the SELinux note in step 2; on a host
without SELinux, install the copy anyway, or point `ExecStart` at `tswap`):

```bash
# run from the folder holding contrib/ (a tswap checkout): your shell reads the file, vault writes the copy
sudo -iu vault install -D -m 0644 /dev/stdin .config/systemd/user/tswap-broker.service < contrib/systemd/tswap-broker.service
sudo -iu vault systemctl --user daemon-reload
sudo -iu vault systemctl --user enable --now tswap-broker
```

After a `route` change or a change to a socket's uids, routes or binding:
`systemctl --user reload tswap-broker` (SIGHUP; the new file is validated completely, then
swapped in; a request keeps the config it started with). A new or removed socket, or a new
`socket_dir`, needs `systemctl --user restart tswap-broker`.

Logs: one line per request in the journal and in `broker.log` (mode `0600`) next to
`broker.json`: time, socket, peer uid and pid, route, method, decoded path (escaped,
length-capped), status, bytes both ways, unlock count and duration, and a reason for refusals.
Never a credential, a header value or a body. If `broker.log` can't be written (disk full, an
I/O error), serving goes on: the failure is reported once and lines go to the journal only.
At start `serve` logs one line per socket, `socket <name>: container <cgroup>[ label <label>]` or
`socket <name>: uid-only (any process with a listed uid is admitted)`, and any warnings (a socket
whose `uids` include 0).

### 5. Finding a container's uid

The broker sees the **host** uid of the process that connects. With rootless Podman:

- a process running as root inside the container is the host user that started it (for
  `lane`, `id -u lane`);
- a process running as uid `N > 0` inside the container is `subuid_start + N - 1`, where
  `subuid_start` is `lane`'s first entry in `/etc/subuid`;
- check with `podman top <container> user huser` while it runs, or
  `podman unshare cat /proc/self/uid_map` as `lane`;
- with `--userns=keep-id` the container user *is* the host user's uid.

Allow exactly the uid(s) the container's `forward` and clients run as, or a range
(`--uids 100000-165535`) for every uid of that user's containers: on a socket bound to a container
(step 7) the cgroup check then tells the containers apart; on a `uid_only` socket the bind-mount is
the only boundary (see [Limits of the identity check](broker-threat-model.md#limits-of-the-identity-check)).

### 6. Starting a container

Bind-mount **only that container's socket file**, at `/run/tswap.sock` by convention, and run
`forward` inside:

```bash
podman run -d --name lane1 -v /srv/tswap-broker/lane1.sock:/run/tswap.sock <image> \
    sh -c 'tswap broker forward --listen 127.0.0.1:8080 & exec <agent>'
```

No `:z` or `:Z` on the socket mount (see [SELinux](#selinux) in step 2). `forward` needs no vault,
home folder, YubiKey or TPM (it reads nothing but its arguments).

### 7. Bind the socket to its container

A socket names the container it serves by the cgroup of the container's systemd unit. The broker
admits a connection only from a process in that cgroup or below it (and with a listed uid).

**A Quadlet container (recommended):** its unit name is stable, so the path is known before it
starts. For a user Quadlet `lane1.container` (unit `lane1.service`) of host user 1001:

```bash
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker socket bind lane1 \
    --cgroup /user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service
```

The formula is `/user.slice/user-<owner uid>.slice/user@<owner uid>.service/app.slice/<unit>.service`;
a system Quadlet is `/system.slice/<unit>.service`. Check with
`systemctl --user show -p ControlGroup lane1.service` as the owner. The container's processes sit in
`<unit>/libpod-payload-<id>`, which is under the bound path.

**Anything else:** bind to a running container's process:

```bash
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker socket bind lane1 --pid "$(podman inspect -f '{{.State.Pid}}' lane1)"   # as the owner's podman
```

`--pid` reads `/proc/<pid>/cgroup` and binds the first `.service` or `.scope` unit in it (after the
user manager). A plain `podman run` container's binding is its `libpod-<id>.scope`, so it changes
when the container is recreated: re-run `socket bind` then (the command says so). `--with-label`
also records the process's SELinux label; it changes on every container start unless the unit pins
`SecurityLabelLevel=`.

`--uid-only` makes a socket uid-only again. `socket bind` writes the file the same way as the other
socket commands; reload the broker afterwards (`systemctl --user reload tswap-broker`).
`<name>.ssh.sock` uses `<name>`'s binding.

**Upgrading a v0.1 `broker.json`:** `serve` refuses it until every socket is bound. Bind each socket
in turn (`socket bind <name> --cgroup ...`, `--pid ...` or `--uid-only`); each run names the sockets
still to bind.

### 8. Using it from inside the container

**git** (the route's name is the first path segment):

```bash
git config --global url."http://127.0.0.1:8080/github/".insteadOf https://github.com/
git clone https://github.com/stevedcc/croft.git      # goes to the broker; it adds the token
git push origin my-branch
```

**A registry** (basic auth), as an insecure local endpoint, through a route named `v2` so the
client's `/v2/...` requests map onto the upstream's `/v2/...`:

```bash
podman push --tls-verify=false localhost-image 127.0.0.1:8080/stevedcc/croft:latest
# Docker: add "127.0.0.1:8080" to "insecure-registries" in daemon.json
```

The registry must hand out **relative** upload `Location`s (distribution:
`http: relativeurls: true`); otherwise the client follows the absolute URL to the registry
directly, without a credential, and the push fails (safely).

**Model APIs** (an OpenAI-compatible base URL):

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/openai
export OPENAI_API_KEY=unused          # the SDK insists on one; the broker replaces Authorization
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080/anthropic
```

## A broker with a vault password

Setting up the vault password itself (`init --password`, `slot add --yubikey --password`, the
choice, joining with it) is in [vault-password-and-agent.md](vault-password-and-agent.md); this
section is what the broker adds.

When the vault user's slot on this machine has the vault password, `serve` starts **locked**:
after a reboot, a restart, or with the disk copied, the broker opens nothing until a human unlocks it. A broker whose slot has no password behaves exactly as
before. Only this machine's own slot decides: a broker whose own slot has no password never prompts
and never asks an agent, so it can't use the vault's password YubiKey slots; give the broker machine
a password slot of its own if it should serve through one. A slot that needs a newer tswap, or whose blob is corrupt, stops `serve` with that slot's id
and text.

```bash
sudo -iu vault tswap broker unlock [--timeout 8h]   # asks for the vault password at the terminal
sudo -iu vault tswap broker status                  # locked, or unlocked until <time>; refused peers: <n>
sudo -iu vault tswap broker lock
```

- **As the vault user, never as root.** All three refuse euid 0 before connecting
  (`Run 'tswap broker unlock' as the vault user (<name>), without sudo.`); `sudo -iu vault` is fine.
  On a broker whose slot has no password they say `This broker's slot has no vault password; it is
  never locked.` and connect to nothing.
- **`broker unlock` needs a terminal.** Without one it refuses with `broker unlock reads the vault
  password from a terminal; there is none. Run 'tswap broker unlock' from your session.` Before it
  asks for the password it checks that the broker answers (`No 'tswap broker serve' answers at <path>;
  is it running?` otherwise) and prints, on stderr, the RAM disclosure with "The broker keeps" for its
  first words (and, on a Mac with a Secure Enclave slot, the line about the Secure Enclave library's
  copy). `--timeout` takes the agent's durations ([`agent start --timeout`](vault-password-and-agent.md#the-tswap-agent));
  without it the broker stays unlocked until `broker lock` or a restart.
- **The proof.** `serve` checks the password with one real unlock through **this machine's password
  slot only** (never a password-free slot, never an agent), then the `vault-password` verifier, and
  holds a copy of the stretched password. Every later unlock (a route's secret, an ssh key, a
  template) uses that copy; `serve` never asks a tswap agent, so its behaviour doesn't depend on one.
- **Wrong passwords** answer with the backend's wrong-password text and the broker stays locked. A
  password this machine's slot accepts but the `vault-password` file refuses is not a wrong password:
  `broker unlock` (like `agent start`) answers `The vault password opened this machine's slot but does
  not match the vault's vault-password file (it may belong to another vault or be out of sync). Copy
  vault-password from a machine where the password works, or re-enrol this slot.` and doesn't count it.
  Wrong passwords count towards the
  unlock guard under the key `control`: after 3 in a row, `broker unlock` is refused for a few minutes
  (`Too many wrong vault passwords for this broker; wait a few minutes and try again.`) before the
  password is even read. On a TPM each wrong password also counts towards the TPM's
  dictionary-attack lockout (see [The TPM's dictionary-attack counter](broker-threat-model.md#the-tpms-dictionary-attack-counter)).
- **While locked** every request gets the refusal a busy or rate-limited request gets: HTTP `503`,
  `SSH_AGENT_FAILURE` for every ssh-agent message (the identities list too), and `broker call` exit
  125, with `reason=locked` in the log only. A locked request is not an unlock failure and never counts
  towards any guard. It is refused at once, like a busy one; the timing difference from a served
  request is the one that already separates busy from served (see [Timing](broker-threat-model.md#timing)).
- **ssh keys load after the first unlock.** `serve` checks what it can without an unlock at start; the
  keys themselves load on the first successful `broker unlock`. A key that can't load fails that
  unlock (`ssh key '<name>' can't be loaded: <reason>`) and the broker locks again: no half-working
  broker. That failure doesn't count towards the guard (the password was right); fix the key and
  unlock again.
- **Back to locked** (`broker lock`, the timeout, or a failed ssh-key load): the broker stops taking
  new unlocks, waits for every unlock in flight to finish and drop its copy, zeroes the held password,
  unloads the ssh keys, and only then becomes dumpable again (see [Memory and dumpability of a password broker](broker-threat-model.md#memory-and-dumpability-of-a-password-broker)). An unlock caught by it gets
  `The broker was locked while unlocking; run 'tswap broker unlock' again.` A second `broker unlock`
  of an unlocked broker is refused before its password is read (`The broker is already unlocked.`).
  A hung unlock (a wedged TPM) holds `broker lock` until it returns or the client's 120 s deadline
  passes, and the held password stays in memory until then, past the unlock's timeout; `serve`'s exit
  after repeated unlock timeouts is the backstop.

The control socket, whom it trusts and what it doesn't stop, memory and dumpability, and the SELinux
rules for the control socket: [A broker with a vault password in the threat model](broker-threat-model.md#a-broker-with-a-vault-password).

## SSH: an agent that signs with vault keys

Containers need SSH too (git over ssh, deploys). Handing them a private key would break the
broker's rule, so the broker is also an **ssh-agent**: the client asks for signatures, and the key
stays on the host. The wire formats are pinned in [ssh-agent-wire.md](design/ssh-agent-wire.md).

- For each socket that lists `ssh_keys`, `serve` also listens on **`<name>.ssh.sock`** next to
  `<name>.sock`: same folder, lock, mode `0666`, peer-uid list and connection limits. The
  container mounts that one file and sets `SSH_AUTH_SOCK` to it.
- It answers `REQUEST_IDENTITIES` (only this socket's keys; each identity's comment is the key's
  name), `SIGN_REQUEST`, and the `session-bind@openssh.com` extension. Adding, removing, locking
  and smartcard requests get `SSH_AGENT_FAILURE`, and so does every other extension.
- **Clients need OpenSSH 8.9 or newer**, which sends `session-bind@openssh.com` on its own. A
  client that doesn't (older OpenSSH, libssh2- or libssh-based tools, agent clients of other SSH
  libraries) gets no signature at all: the agent fails closed.

How a signature is allowed, what the host restriction does and doesn't do, and what a compromised
container can do with the agent: [The SSH agent in the threat model](broker-threat-model.md#the-ssh-agent).

### Setting up the SSH agent

1. **The key, as a vault secret.** An unencrypted OpenSSH private key (`openssh-key-v1`) or
   unencrypted PKCS#8 PEM: Ed25519, ECDSA P-256/P-384/P-521, or RSA of at least 3072 bits (RSA
   signs only `rsa-sha2-256` / `rsa-sha2-512`, never SHA-1). The vault is the protection, so
   the key itself has no passphrase; a passphrase-protected or encrypted key is refused.

   ```bash
   ssh-keygen -t ed25519 -N '' -C '' -f deploy        # in a private temp folder
   sudo -iu vault tswap ingest deploy-key < deploy
   shred -u deploy                                     # keep deploy.pub for the server
   ```

2. **The hosts it may sign in to.** Every key lists `allowed_host_keys`: the `SHA256:`
   fingerprints of the server host keys, exactly as `ssh-keygen -lf` prints them. Get them with
   `ssh-keyscan` and **check them against the provider's published fingerprints** (GitHub's are in
   its docs):

   ```bash
   ssh-keyscan -t ed25519 github.com > github.keys
   ssh-keygen -lf github.keys        # 256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)
   ```

   List each host key the server may present (a server with several key types presents the one
   the client negotiates; listing all of them is fine).

3. **`broker.json`** (no `broker` subcommand edits ssh keys yet: edit the file with `sudo`, it
   stays mode `0600`, and every load validates it):

   ```json
   "ssh_keys": [
     { "name": "github-deploy", "secret": "deploy-key",
       "allowed_host_keys": ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"] }
   ],
   "sockets": [
     { "name": "lane1", "uids": ["100999"], "routes": ["openai"], "ssh_keys": ["github-deploy"] }
   ]
   ```

   A key's name follows the route and socket rule (`[a-z0-9-]{1,32}`); `secret` is a plain
   secret name; `allowed_host_keys` must not be empty, and an entry that isn't a `SHA256:`
   fingerprint stops `serve`. A socket lists at most 64 keys, and two keys may not use the same
   secret or hold the same private key (list one key with every host it may sign in to);
   `serve` refuses to start otherwise. (A reload can't be refused for that: if one lists more than
   64 keys on a socket, it is logged once and only the first 64 by name are offered.)

4. **Restart `serve`** (`systemctl --user restart tswap-broker`). At start, `serve` unlocks the
   vault **once per key**, reading only that key's record, to derive its public key; it keeps only
   the public key. **A key that can't be loaded stops `serve`** with an error naming it (missing
   secret, unparsable, encrypted, an `openssh-key-v1` file whose embedded public key differs from
   the derived one, an unsupported type, RSA under 3072 bits): it is never silently left out. A
   reload (SIGHUP) never unlocks, so a new key, or a socket that gains its first key, needs a
   restart; a reload that removes a key from a socket's list, or a host from a key's list, applies
   to the next request. A reload that removes a client socket, or its last key, removes its
   `<name>.ssh.sock` too (open connections are closed at their next request; the process keeps the
   listener on the removed file, unreachable, until restart, since Kestrel can't close one
   endpoint of a running server); it comes back with a restart.

5. **Register the public key** with the server (`deploy.pub`), preferably narrowly (see [What
   the restriction does and doesn't do](broker-threat-model.md#what-the-restriction-does-and-doesnt-do)).

6. **The container.** Bind-mount only its own agent socket, and give it its own `known_hosts`:

   ```bash
   podman run -d --name lane1 \
       -v /srv/tswap-broker/lane1.sock:/run/tswap.sock \
       -v /srv/tswap-broker/lane1.ssh.sock:/run/tswap-ssh.sock \
       -e SSH_AUTH_SOCK=/run/tswap-ssh.sock <image> ...
   # inside: the verified host keys from step 2, and strict checking
   cat github.keys >> ~/.ssh/known_hosts
   git clone git@github.com:stevedcc/croft.git
   ```

   The agent restricts where its key can sign in, but it doesn't make the container's ssh check
   whom it is talking to: **the container still needs its own `known_hosts`** for each server
   (and `StrictHostKeyChecking yes`), or a man in the middle gets its session, though never the
   key.

### Memory, limits and logging

- **One unlock per signature,** reading **only that key's record** (as for a route, one record per request),
  serialised with every other unlock of the broker; the key is parsed, checked against the public
  key loaded at start (a key replaced in the vault since is refused, not used), used once, and the
  byte arrays are zeroed and the key objects disposed. Key material is **not kept beyond the
  request, and the buffers tswap holds are cleared** — not "never in memory": BouncyCastle's and
  the platform crypto library's internal copies, and the .NET `BigInteger`s an `openssh-key-v1` RSA
  key's CRT values are computed with, can't be zeroed by tswap. `serve` is non-dumpable
  (`PR_SET_DUMPABLE 0`; see [The vault user is root-equivalent for its secrets](broker-threat-model.md#the-vault-user-is-root-equivalent-for-its-secrets)).
- **Limits:** the broker's connection limits (an agent socket counts as `<name>.ssh`), a connection idle
  for 120 s between messages is closed, messages are at most 256 KiB (a larger, empty or truncated
  frame closes the connection), one request at a time per connection, in order. **At most 30
  successful signatures a minute per socket** (each is a TPM unlock); beyond that a sign request
  is refused and logged (`reason=sign-rate`) with no unlock. The broker's unlock-failure lockout, the
  per-socket unlock budget (20 a minute) and the global unlock limit (30) apply too, so in practice
  a socket gets at most 20 signatures a minute (`reason=socket-unlock-rate` beyond that); the
  lockout and the budget are shared with the client's HTTP socket.
- **Parser hygiene:** the agent parses bytes from the container in the vault user's process: every
  length is checked against what is left, nothing is sized by the peer on the stack, a key secret
  over 16 KiB is refused unparsed, and an exception on one connection closes that connection,
  never `serve`.
- **The same-uid limits** of [Limits of the identity check](broker-threat-model.md#limits-of-the-identity-check) hold here too: containers must not run
  as the vault user (the agent refuses a peer with the broker's own uid), and the single socket-file
  mount is what separates one container from another: **mount the agent socket file, never the
  socket folder.**
- **Logging:** one line per bind and per sign request, for example

  ```
  ... event ssh-bind socket=lane1.ssh uid=100999 pid=4242 host=SHA256:+DiY3wvv... result=ok
  ... event ssh-sign socket=lane1.ssh uid=100999 pid=4242 key=github-deploy host=SHA256:+DiY3wvv... result=ok unlocks=1 ms=2041
  ... event ssh-sign socket=lane1.ssh uid=100999 pid=4242 key=github-deploy host=SHA256:+DiY3wvv... result=refused reason=not-userauth unlocks=0 ms=0
  ```

  Never key material or the data signed.

## Command templates

A template is a **host-side command that uses a credential**: a deploy trigger, a database CLI,
signing with a key file. The operator defines it (with sudo); a container can only call it, with
the arguments the template declares and validates. The program never comes from the caller, and
there is no shell.

```bash
# inside the container (the socket bind-mounted at /run/tswap.sock, as for routes)
tswap broker call deploy env=staging
echo $?    # the template's own exit code; 125 = the broker refused or failed; 124 = timeout
```

`broker call` prints the command's stdout and stderr as they arrive and exits with its exit code.
Any broker-side error (an unknown or not-allowed template, a bad argument, the rate limit, the
sandbox unavailable, the socket unreachable) exits **125**, so it can't be mistaken for a tool's
own 1 or 2.

What a compromised container can do with a template, and what a template author must not do:
[Command templates in the threat model](broker-threat-model.md#command-templates).

### What the sandbox gives

Every template runs under `bwrap` (bubblewrap), started by the broker, never without it. The child
keeps the vault user's uid and its `tss` group membership, **but has nothing to use them on**:

| What | How (`bwrap` option or broker step) |
|---|---|
| No TPM device | `--dev /dev`: a new minimal `/dev` (null, zero, full, random, urandom, tty, pts, shm); no `/dev/tpm*` |
| No vault folder, `broker.json`, socket folder or home | a new, empty root: only `--ro-bind /usr`, the `/bin`, `/sbin`, `/lib*` links as on the host, `--ro-bind-try` of `/etc/{resolv.conf,hosts,nsswitch.conf,ssl,pki,ca-certificates,passwd,group}`, `--tmpfs /tmp`, the template's binds and its secret files |
| Not the broker's process | `--unshare-pid` and `--proc /proc`: the broker's pid doesn't exist inside (no `kill`, no `/proc/<pid>`); and `serve` is non-dumpable (`PR_SET_DUMPABLE 0`), so even a same-uid process outside can't `ptrace` it |
| No new privileges, no device nodes | `--unshare-user` and `--cap-drop ALL`; `mknod` needs `CAP_MKNOD`, and filesystems mounted inside a user namespace are `nodev` anyway |
| Its own IPC, hostname, cgroup view, session | `--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup-try`, `--new-session` (no terminal injection) |
| Dies with the broker | `--die-with-parent` |
| No network unless asked | `--unshare-net` (the default, `"network": "none"`); `"network": "host"` is an explicit per-template opt-in |
| No broker handles | the broker spawns `bwrap` itself (`posix_spawn` with `closefrom`): only stdin (`/dev/null`), stdout, stderr and the descriptors `bwrap` uses (`--info-fd`, `--block-fd`, one per `--ro-bind-data`) reach it, and `bwrap` closes those before the command starts |
| Resource limits | `RLIMIT_NPROC` 64, `RLIMIT_AS` 2 GiB, `RLIMIT_NOFILE` 256, `RLIMIT_FSIZE` 256 MiB, `RLIMIT_CORE` 0 (a template may lower them): set with `prlimit` on the sandbox's first process while `bwrap` waits on `--block-fd`, i.e. inside the new user namespace, where `RLIMIT_NPROC` counts the sandbox's processes only |
| A timeout | `timeout_sec` (default 120, at most 3600): the broker kills the sandbox's pid 1, which ends every process in its pid namespace, detached ones included; reported as exit 124 |
| A fixed environment | exactly the template's `env` plus `PATH=/usr/bin:/bin`, `LC_ALL=C` and the `PWD` `bwrap` sets; no `HOME`, nothing inherited; umask 077 |

**`bwrap` fails closed.** It runs from a fixed absolute path (`bwrap_path` in `broker.json`,
default `/usr/bin/bwrap`), never through `PATH`. It must resolve to a regular file owned by root and
not writable by group or others, and every folder above it (above the configured path and above
the resolved one) must be root's and not writable by group or others, with no sticky exception;
a symlink at the configured path must be root's. So no other user can swap it between checks; the
rule is checked at start and again before every call. Since v0.2 the effective `bwrap_path` (after
the default) may also not be at or under any template's bind, read-only or not: a replaced `bwrap`
would run outside the sandbox. That is checked when `broker.json` loads, on the configured path and
on its resolved one (for a `bwrap` that doesn't exist yet, through its nearest existing folder); a
missing `bwrap` outside the binds still loads, and calls are refused as below. `serve` also checks
at start that it makes a sandbox with every option the broker uses. If `bwrap` is missing, fails these checks, is too
old (0.5 or later is needed for `--perms`), the C library is older than glibc 2.36
(`posix_spawn_file_actions_addclosefrom_np`, `pidfd_open`), or user namespaces are disabled, template calls are refused (`503`,
`broker call` exits 125) and logged. **A template never runs unsandboxed.** On Ubuntu 24.04,
unprivileged user namespaces are restricted by AppArmor
(`sysctl kernel.apparmor_restrict_unprivileged_userns=0`, or an AppArmor profile for `bwrap`).

The broker signals the sandbox only through pidfds (`pidfd_open`), so a kill can never reach a
process that later got a finished run's pid, and it starts every `bwrap` from one dedicated thread
that lives as long as `serve`: `--die-with-parent` is `PR_SET_PDEATHSIG`, which fires when the
*thread* that started `bwrap` ends, so a pool thread retiring would otherwise kill a running
template. On every way out of a call (a refusal, a broken response, the client going away) the
sandbox is killed and reaped and the redactor's copies are zeroed.

### Secrets reach the child through env or a read-only file only

- `"env": {"PGPASSWORD": "{{db-pw}}"}`: the value goes into the environment block the broker hands
  to `bwrap` as its process environment, **never `--setenv`** (that would put it in `bwrap`'s argv,
  readable by every local user in `/proc/<pid>/cmdline`). An env value is a literal or exactly one
  `{{secret}}`.
- `"files": [{"path": "/run/secrets/signing-key", "secret": "signing-key"}]`: the broker writes the
  value into a pipe (bounded, before `bwrap` starts) whose read end goes to `bwrap` only, as
  `--perms 0400 --ro-bind-data <fd> <path>`. The path must be a file directly under `/run/secrets/`;
  a secret file holds at most 1 MiB.
- A `{{secret}}` in `argv`, `cwd`, a bind or a `files` path is refused when the config loads.

**Limits of this:** while the child runs, its `/proc/<pid>/environ` (and the open pipe) are
readable by processes of the same uid. Env narrows the leak to the vault user's uid; it doesn't
remove it, which is one more reason the vault user runs nothing else (see [the load-bearing
assumption](broker-threat-model.md#the-load-bearing-assumption-no-container-runs-with-the-vault-users-uid)). The secret's bytes are zeroed once they are in the environment block or the
pipe, but that is best effort: .NET strings can't be zeroed, and the real mitigation is
`PR_SET_DUMPABLE 0`.

### The bind rule (`binds`, `cwd`)

A template sees only what it binds (read-only unless `"rw": true`), at the same (resolved) path.
Each bind must, after symlink resolution:

- be an absolute path to a **regular file or a folder**, never a device node, socket or FIFO, and
  never at or under `/dev`, `/proc`, `/sys` or `/run` (sockets for systemd, D-Bus and Podman live
  there);
- be owned by the vault user or root and not writable by group or others, with every folder above
  it root's or the vault user's and not writable by group or others (a root-owned sticky folder
  such as `/tmp` is accepted above it, as for `socket_dir`; that exception waives the folder's
  write bits entirely, which is safe because the sticky bit keeps others from renaming or removing
  what they don't own);
- never be the vault folder, `broker.json`'s folder, the socket folder or sudo's configuration
  (`/etc/sudoers`, `/etc/sudo.conf`, `/etc/sudoers.d`), nor a folder above or inside one of them,
  **compared by `st_dev:st_ino`**, so a bind-mount alias or a hard link doesn't get past a name
  check; and never the vault user's home or a folder above it (a folder inside it is fine);
- never be, contain or be inside the broker's run folder, where its control socket lives (since
  v0.2): `/run/user/<uid>/tswap`, already refused as under `/run`, or `~/.cache/tswap/run` when the
  vault user has no `/run/user/<uid>`. Which one `serve` uses can change between a load and a start,
  so both are protected, **whether or not they exist yet**: compared by name (the folder's nearest
  existing ancestor resolved) and by `st_dev:st_ino` when it exists. A bind of `~/.cache` would let a
  template delete the control socket or connect to it (it admits the vault uid, which the template's
  child has).

`cwd` must be inside one of the binds (`/tmp` when unset). The checks run when a template is added,
on every load, and again **before every run** (a path can change owner).

**Why:** this excludes container-controlled folders (worktrees with hooks and config, a shared
build folder) by construction. A template never runs in, or reads, a folder a container can write,
so nothing a container plants (a git hook, a filter driver, a config file) runs with the vault
user's uid. The rule checks the bind and the path to it, not every file inside it: **don't bind a
folder holding entries others can write**, or anything else of the vault user's you wouldn't hand
the template.

### Defining a template

`sudo tswap broker template add <file.json>` (or `-` for stdin) adds one; `sudo tswap broker
template remove <name>` removes it (refused while a socket allows it); like the setup's
commands, they take `TSWAP_CONFIG_DIR` pointing at the vault user's folder. A socket's `templates` list
is the only gate: a socket without one may call none. A template's secrets don't also need to be on
any route. `sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap broker socket add <name> --uids ... --templates deploy,sign`
(with its binding, as in step 3) allows them.

| Field | Meaning |
|---|---|
| `name` | `[a-z0-9-]{1,32}`, not starting with `_` |
| `argv` | the command, run directly (no shell). `argv[0]` a **literal** absolute path under `/usr`, `/bin`, `/sbin` or `/lib*`, never a placeholder, and never at or under one of the template's binds (read-only ones too), as configured or resolved (symlinks followed, a dangling one too; a program not installed yet through its nearest existing folder; it still loads, and its calls fail until it is installed), checked at load and again before every call; no `.` or `..` segment; on a template with binds, a program (or `bwrap_path`) whose path can't be resolved (a symlink loop, more than 40 links, a link that can't be read) is refused at load: a container that can write a bound folder (through another mount) could replace the program. Since v0.2 a program may no longer live in a bind: install it under `/usr` or ship it in the image. `{arg}` placeholders in `argv[1..]` only. Inline interpreter code (`sh -c`, `python -c`, `env`, `xargs`, ...) is refused (#105) |
| `args` | per argument: `pattern` (wrapped as `\A(?:...)\z`, culture-invariant, never multiline, no inline option groups, 100 ms match timeout), `max_length` (default 256), `allow_leading_dash` (default false). Every placeholder must be declared and every declared argument used |
| `env`, `files` | the secrets, as above. Refused env names: `PATH`, `LC_ALL`, `PWD` (the baseline), `LD_*`, and those that make a shell, an interpreter, a library or a tool run code, or load, trust or write files, they name: `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `PROMPT_COMMAND`, `IFS`, `CDPATH`, `GLIBC_TUNABLES`, `MALLOC_CHECK_`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_EXEC_PATH`, `GIT_PROXY_COMMAND`, `GIT_TEMPLATE_DIR`, `GIT_EDITOR`, `EDITOR`, `VISUAL`, `PAGER`, `GIT_PAGER`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `REQUESTS_CA_BUNDLE`, `NETRC`, `HOSTALIASES`, `LOCALDOMAIN`, `RES_OPTIONS`, `TMPDIR`, `HOME` (the sandbox sets none, so a template's `HOME` would choose the `~/.gitconfig`, `~/.netrc` and `~/.curlrc` its tool reads), `CLASSPATH`, `SSLKEYLOGFILE`, `INPUTRC`, `TERMINFO`, `TERMINFO_DIRS`, `MAVEN_OPTS`, `GRADLE_OPTS`, `GIT_DIR`, `GIT_WORK_TREE` (a repo whose hooks would run), `LESSOPEN`, `LESSCLOSE`, `BROWSER`, and every name starting with `GIT_CONFIG`, `BASH_FUNC_`, `PYTHON`, `PERL`, `RUBY`, `GEM_`, `NODE_`, `DOTNET_`, `JAVA`, `_JAVA_`, `JDK_JAVA_`, `OPENSSL_`, `LUA_`, `XDG_`, `SSL_` or `CURL_`. The prefixes knowingly refuse harmless names too (`JAVA_HOME`, `NODE_ENV`, `PYTHONUNBUFFERED`, `DOTNET_CLI_TELEMETRY_OPTOUT`); a tool that needs one gets it from a wrapper script under `/usr` or from the image. `KUBECONFIG`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `GNUPGHOME` and `GRADLE_USER_HOME` name a config file or folder that can name a command to run (a kubeconfig `exec`, AWS `credential_process`, GnuPG's `pinentry-program`, Gradle's `init.d`): they are allowed, but a literal value at or under one of the template's binds (read-only ones too; as configured and resolved, a relative value against `cwd`, each `KUBECONFIG` list entry) is refused, at load and again before every call, because a container could plant such a file there. Point them under `/run/secrets/` (a `files` entry) or outside every bind. The list catches mistakes; it isn't complete, so choose tools you know |
| `binds`, `cwd` | as above |
| `network` | `none` (default) or `host` |
| `limits` | `nproc` (≤ 64), `as_mib` (≤ 2048), `nofile` (≤ 256), `fsize_mib` (≤ 256) |
| `timeout_sec` | 1 to 3600, default 120 |
| `max_output_bytes` | 1 byte to 64 MiB, default 1 MiB |
| `rate` | calls a minute for each socket that may call the template (counted per socket and template, so a socket listing two templates may make both rates of calls), 1 to 60, default 6; over it `429` and nothing runs or unlocks (each call is a TPM unlock and has real side effects). A call refused before it could run (bad arguments, the sandbox or a bind) doesn't count |

**`allow_leading_dash` with a loose pattern is flag injection:** a value like
`--checkpoint-action=exec=sh` handed to `tar`, or `--upload-pack=...` to `git`, turns an argument
into code. Keep the default, or anchor the pattern so a dash can't start an option.

The worst case of every `argv` entry (each argument at its `max_length`) must fit `execve`'s
limit of 128 KiB per entry, and the whole command 1 MiB; a template that could exceed them is
refused at load rather than failing at a call.

At call time every declared argument is required and an undeclared one is refused. A value with a
NUL or another control character is refused before its pattern runs (a NUL would truncate the
string `execve` sees). An unknown template and one the socket may not call get the same uniform
`404`, byte for byte (also the same as an unknown route); nothing unlocks for a refused call.

Before you write one, read [What a template author must not do](broker-threat-model.md#what-a-template-author-must-not-do).

### Examples

A deploy trigger (no network inside except the one API it calls; the token in env):

```json
{
  "name": "deploy",
  "argv": ["/usr/bin/curl", "-fsS", "-X", "POST", "-H", "@/run/secrets/auth-header",
           "https://deploy.example/api/deploy/{env}"],
  "args": { "env": { "pattern": "staging|production" } },
  "files": [ { "path": "/run/secrets/auth-header", "secret": "deploy-auth-header" } ],
  "network": "host",
  "timeout_sec": 60
}
```

(`deploy-auth-header` holds the whole line `Authorization: Bearer ...`; `curl -H @file` reads it
from the file, so the token never appears in argv.)

`psql` with `PGPASSWORD`:

```json
{
  "name": "db-report",
  "argv": ["/usr/bin/psql", "-h", "db.internal", "-U", "report", "-d", "app", "-f", "/srv/reports/{report}.sql"],
  "args": { "report": { "pattern": "[a-z0-9_]{1,40}" } },
  "env": { "PGPASSWORD": "{{db-report-pw}}" },
  "binds": [ { "path": "/srv/reports" } ],
  "network": "host"
}
```

Signing with a key held in the vault, handed over as a read-only file:

```json
{
  "name": "sign",
  "argv": ["/usr/bin/openssl", "dgst", "-sha256", "-sign", "/run/secrets/signing-key",
           "-out", "/srv/release/{file}.sig", "/srv/release/{file}"],
  "args": { "file": { "pattern": "[A-Za-z0-9._-]{1,64}" } },
  "files": [ { "path": "/run/secrets/signing-key", "secret": "release-signing-key" } ],
  "binds": [ { "path": "/srv/release", "rw": true } ]
}
```

### One unlock per call, reading only the template's secrets

A call takes one of its socket's request slots for its whole duration (the broker's connection limits), then **one
unlock**, and decrypts only the records of the secrets the template names, each on its own
(`records/HMAC(K_names, name)`), never the whole vault; a template with no secrets doesn't unlock
at all. The vault key is zeroed straight after, the secret bytes once they are in the environment
block or the pipe. The unlock-failure limits and the unlock timeout are the routes' (see [The TPM's
dictionary-attack counter](broker-threat-model.md#the-tpms-dictionary-attack-counter)).

### Output

- stdout and stderr are **streamed** back through **one shared redactor**, in the order the
  broker read them. A secret split between the two streams is caught **only when its halves are
  read in the order they were written**: the two are separate pipes with no common order, so
  when the second half is read first (the tool wrote them close together and the reads raced),
  neither half matches a known form and both pass. Ordering them for certain would mean holding
  back all output, which the broker doesn't. Within one stream, a secret split across reads is
  always caught. The forms redacted are the routes' (see [Redaction is best-effort](broker-threat-model.md#redaction-is-best-effort), including
  what it doesn't cover) for every secret the template uses.
- The output is counted, never buffered whole: beyond `max_output_bytes` the rest is read and
  discarded while the child runs on to its end or timeout. A cut never ends inside the held-back
  window: the window is dropped at the cut, so no fragment of a secret the cut separated from its
  end gets out. The result says when output was truncated.
- The answer is NDJSON: `{"stream":"stdout"|"stderr","data":"<base64>"}` frames, then
  `{"ended":"exit"|"timeout"|"signal"|"refused","exit_code":N,"truncated":bool}`. The redactor works
  on bytes and the frames carry base64, so binary output (a signature) survives byte for byte.
- The exit code is passed through; a timeout reports 124 (as `timeout(1)` does). `bwrap` reports a
  command killed by signal N as exit 128+N, so that is what the caller sees, as `"ended": "exit"`:
  **a caller can't tell a tool that exited 143 from one killed by SIGTERM.** `"signal"` means
  `bwrap` itself was killed (then the code is 128+N of that signal).

**Be honest about output:** whatever the tool prints goes to the caller, including anything it
derives from the secret (a decryption, a signature, a token it exchanged for). The broker redacts
only the secret's known forms. A template that prints derived secret material is the operator's
choice.

### Logging

One line per call in the journal and `broker.log`: socket, peer uid and pid, template, the argument
values (escaped, length-capped), status, exit code, how it ended, bytes in and out, whether it was
truncated, unlocks, duration and a reason for refusals. Never a secret, an env value, or argv after
substitution.

A failure inside the broker during a call (a bug, a failed write) never reaches the caller as a
`500`: before any output it gets the uniform `502` (`broker call` exits 125), after the first frame
the connection is closed without the last frame. Its one log line has
`reason=internal-error type=<exception type>`, never the exception's message.

### Changed in v0.2.0 (breaking)

v0.2.0 tightened the template rules; a `broker.json` that breaks one no longer loads. The list is in
[the v0.2.0 release notes](release-notes/v0.2.0.md#broker-each-socket-names-its-container-breaking);
one rule is not in them: a bind may not be, contain or be inside the broker's run folder
(`~/.cache/tswap/run` for a vault user without `/run/user/<uid>`), existing or not (see
[The bind rule](#the-bind-rule-binds-cwd)). A program that lived in a bind moves under `/usr` or into
the image; drop the bind if it was there only for the program. A template that sets a newly refused env
name, even a harmless one such as `JAVA_HOME`, must drop it (or set it in a wrapper script under `/usr`):
check templates before upgrading.

## Platforms

**Tested on real hardware:** Fedora CoreOS 44 (selinux-policy-targeted 44.6, Podman 5.8, Intel
PTT as the TPM), 2026-10-30, with the `tswap-broker` SELinux module installed with only
`semodule -i` and `restorecon` (no `semanage`). The results:

- `serve` ran as `tswap_broker_t`, and the socket inherited `container_file_t`;
- a rootless container with SELinux **enforcing**, no `--security-opt label=disable` and no `:z`
  on the socket mount got the credential added upstream and the echoed value redacted;
- a `..` traversal, a not-allowed route and an unknown route were each refused, with no unlock;
- no new AVC denials;
- the TPM's lockout counter stayed 0.

On Fedora CoreOS `/usr/local` is `/var/usrlocal`: `restorecon` reports
`/var/usrlocal/libexec/tswap-broker`, and the module's `/usr/local/libexec/tswap-broker` file
context still applies through the policy's path equivalence rule. Nothing extra is needed.

Elsewhere:

- **Current Fedora and RHEL-family hosts with container-selinux:** expected to work the same way.
  Attribute names may differ on older RHEL releases; `semodule -i` reports any it doesn't know.
- **Debian and Ubuntu (AppArmor):** Podman's and Docker's default AppArmor profiles don't block
  connecting to a bind-mounted Unix socket, so no module is needed. **Untested.**
- **Hosts without a mandatory access control system** need nothing extra.
- **macOS and Windows:** not supported in v1. The broker identifies clients by kernel peer
  credentials on a Unix socket, so it must run on the same Linux kernel as the containers, for
  example inside the Podman machine VM, not on the macOS or Windows host.

**Binding a socket to a container** (v0.2.0) needs, besides the above:

- Linux with `SO_PEERPIDFD`, which arrived in **Linux 6.5**. `serve` probes for it once at start (on
  a `socketpair()`) and refuses a config with a bound socket when the kernel doesn't give it; the
  probe decides, not the version number;
- a pure cgroup v2 host (`/proc/self/cgroup` is one `0::/...` line; cgroup v1 and hybrid hosts are
  refused at start) and `serve` in the host's root cgroup namespace;
- SELinux enabled (`/sys/fs/selinux/enforce` exists) when a socket also binds a `selinux_label`;
- a `/proc` the vault user can see the containers' processes in (no `hidepid` without `gid=`).

Each refusal names the socket and the reason; on a reload the running config is kept. Sockets marked
`uid_only` start everywhere `serve` starts. On macOS `socket bind --pid`, `--cgroup` and
`--with-label` refuse (`binding a socket to a container needs Linux; use --uid-only`).

## Limits (v1)

- `tswap broker` is Unix only (Linux and macOS); on Windows every subcommand refuses with "not
  supported on Windows". So Windows' sharing-violation errors are never mapped: the lock files'
  "another serve/change is running" messages come from `flock`'s EWOULDBLOCK only.
- **Registries that issue tokens from a separate realm URL** (GHCR, Docker Hub: `401` with
  `WWW-Authenticate: Bearer realm=https://ghcr.io/token`) are not covered: the client would fetch
  a token from the realm itself. Basic-auth registries are covered.
- No TLS on the socket (it is a local Unix socket), no arbitrary `run` over the socket, no key
  caching.
- A socket's container binding needs Linux 6.5 or later (`SO_PEERPIDFD`), cgroup v2 and `serve` in
  the host's root cgroup namespace; elsewhere sockets are `uid_only`. The binding separates
  containers from each other, not from the host user who runs them (see [Limits of the identity
  check](broker-threat-model.md#limits-of-the-identity-check)).
- Templates run on Linux only (they need `bwrap`), always as the vault user's uid (in a sandbox);
  running them as another uid would need root or capabilities.
- Request and response trailers are never forwarded; `Range` requests are dropped (no partial
  reads); compressed responses fail closed.
- The client's `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, `Connection` and every
  header it names, the other hop-by-hop headers, `Expect`, `Range`, `If-Range` and
  `Accept-Encoding` never reach the upstream; `Set-Cookie`, hop-by-hop headers and any header
  holding a redaction form never reach the client.

<details>
<summary>Moved sections</summary>

| Old section | Now |
|---|---|
| <a id="threat-model"></a>Threat model | [the broker's threat model](broker-threat-model.md) |
| <a id="redaction-is-best-effort"></a>Redaction is best-effort | [Redaction is best-effort](broker-threat-model.md#redaction-is-best-effort), in the threat model |
| <a id="timing"></a>Timing | [Timing](broker-threat-model.md#timing), in the threat model |
| <a id="what-a-compromised-container-can-and-cant-do"></a>What a compromised container can and can't do | [What a compromised container can and can't do](broker-threat-model.md#what-a-compromised-container-can-and-cant-do), in the threat model |
| <a id="limits-of-the-identity-check"></a>Limits of the identity check | [Limits of the identity check](broker-threat-model.md#limits-of-the-identity-check), in the threat model |
| <a id="the-vault-user-is-root-equivalent-for-its-secrets"></a>The vault user is root-equivalent for its secrets | [The vault user is root-equivalent for its secrets](broker-threat-model.md#the-vault-user-is-root-equivalent-for-its-secrets), in the threat model |
| <a id="the-load-bearing-assumption-no-container-runs-with-the-vault-users-uid"></a>The load-bearing assumption: no container runs with the vault user's uid | [The load-bearing assumption: no container runs with the vault user's uid](broker-threat-model.md#the-load-bearing-assumption-no-container-runs-with-the-vault-users-uid), in the threat model |
| <a id="the-tpms-dictionary-attack-counter"></a>The TPM's dictionary-attack counter | [The TPM's dictionary-attack counter](broker-threat-model.md#the-tpms-dictionary-attack-counter), in the threat model |
| <a id="memory"></a>Memory | [Memory](broker-threat-model.md#memory), in the threat model |
| <a id="a-broker-with-a-vault-password-brief-t17"></a>A broker with a vault password (brief T17) | [A broker with a vault password](#a-broker-with-a-vault-password), on this page |
| <a id="the-control-socket-and-its-trust-model"></a>The control socket and its trust model | [The control socket and its trust model](broker-threat-model.md#the-control-socket-and-its-trust-model), in the threat model |
| <a id="memory-and-dumpability-of-a-password-broker"></a>Memory and dumpability of a password broker | [Memory and dumpability of a password broker](broker-threat-model.md#memory-and-dumpability-of-a-password-broker), in the threat model |
| <a id="selinux-for-the-control-socket"></a>SELinux for the control socket | [SELinux for the control socket](broker-threat-model.md#selinux-for-the-control-socket), in the threat model |
| <a id="ssh-an-agent-that-signs-with-vault-keys-brief-t10"></a>SSH: an agent that signs with vault keys (brief T10) | [SSH: an agent that signs with vault keys](#ssh-an-agent-that-signs-with-vault-keys), on this page |
| <a id="setup"></a>Setup (of the ssh agent) | [Setting up the SSH agent](#setting-up-the-ssh-agent), on this page |
| <a id="how-a-signature-is-allowed"></a>How a signature is allowed | [How a signature is allowed](broker-threat-model.md#how-a-signature-is-allowed), in the threat model |
| <a id="what-the-restriction-does-and-doesnt-do"></a>What the restriction does and doesn't do | [What the restriction does and doesn't do](broker-threat-model.md#what-the-restriction-does-and-doesnt-do), in the threat model |
| <a id="what-a-compromised-container-can-and-cant-do-ssh"></a>What a compromised container can and can't do (ssh) | [What a compromised container can and can't do (ssh)](broker-threat-model.md#what-a-compromised-container-can-and-cant-do-ssh), in the threat model |
| <a id="setup-1"></a>Setup (of the broker) | [Setting up the broker](#setting-up-the-broker), on this page |
| <a id="what-a-compromised-container-can-do-with-a-template"></a>What a compromised container can do with a template | [What a compromised container can do with a template](broker-threat-model.md#what-a-compromised-container-can-do-with-a-template), in the threat model |
| <a id="what-a-template-author-must-not-do"></a>What a template author must not do | [What a template author must not do](broker-threat-model.md#what-a-template-author-must-not-do), in the threat model |

</details>
