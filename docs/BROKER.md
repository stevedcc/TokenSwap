# tswap broker: credentials for containers that never hold them

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
- `sudo tswap broker route|socket add|remove` changes `broker.json`.

Linux and macOS only. On Windows, `tswap broker` says it is not supported.

## Threat model

### Redaction is best-effort

Every response body passes through a streaming redactor and every response header is checked
before it reaches the container. **That is best-effort:** a hostile upstream can obfuscate a
value past any window (reverse it, split it over two responses, encode it some other way).

**The guarantee** is narrower and holds regardless:

- the broker never emits a *known form* of the value (the list below);
- it only ever sends the value to that route's upstream, over TLS, inside the route's path and
  method envelope.

**The forms redacted**, longest first, each replaced by `[REDACTED]`:

- the raw value (this is also what `tswap run`'s output redaction covers);
- base64 with padding, without padding, and base64url (with and without padding);
- the value's base64 at the two other byte alignments (as found inside a longer base64 stream),
  when that core is 8 characters or more;
- for `basic` routes: the exact `base64(user:secret)` the broker sent, its other base64 forms,
  and `user:secret` itself;
- hex, upper and lower case;
- percent-encoded: upper- and lower-case hex escapes, and form encoding (`+` for space);
- JSON-escaped: the default .NET escaping, relaxed escaping and minimal escaping, each also with
  `/` written as `\/`.

The redactor holds back a sliding window of (longest form − 1) bytes between chunks and flushes
it at the end; it never buffers a body. That window is roughly 100 bytes, so a stream of small
pieces (server-sent events from a model API, a progress feed) reaches the client up to that many
bytes late: each piece arrives once more data follows it, or at the end. Response headers are
never held back. A response with any `Content-Encoding` other than
`identity` can't be redacted, so it fails closed: `502`, the body is not forwarded, and it is
logged (the broker asks every upstream for `Accept-Encoding: identity`).

### What a compromised container can and can't do

**It can**, while it runs:

- use its own socket's routes, within each route's path regex and methods;
- for example, push to any repository the route's path regex allows, or spend the model API key
  the route carries.

**It can't:**

- read a credential (the value never enters the container; known forms are redacted on the way
  back);
- use another socket's routes, or a route its socket doesn't list (the same `404` as a route that
  doesn't exist);
- reach another container's socket (only its own is bind-mounted, and the peer uid must be on
  that socket's list);
- push or fetch where the path regex excludes, or step outside the upstream's base path with
  `..`, `%2e%2e`, `%2f`, `..;`, `//host` or double encoding (each a uniform `404`: every refusal
  of a route, socket, method or path gets the same bytes, headers included, except the `Date`
  header, which says when it was sent);
- send the credential anywhere but the route's upstream (the broker builds the outbound URL
  itself and asserts the scheme, host, port and base path before sending; redirects are passed
  back, never followed, and a client that follows one elsewhere carries no credential).

### Limits of the identity check

- **The bind-mount is the boundary between containers of the same host user.** The broker
  identifies a client by the socket the connection arrived on and the peer uid the kernel
  reports for it (`SO_PEERCRED` on Linux, `getpeereid` on macOS). Rootless Podman gives all
  containers of one host user the same subuid range unless the operator separates them, so two
  such containers can have the same uids: what keeps container A off container B's socket is
  that only B's socket file is mounted into B.
- **Credentials are fixed at `connect()`.** An allowed process can relay for another (pass the
  connected fd, or proxy bytes). The uid is not a delegation boundary.
- **Any process in the container's network namespace can use the forwarded port.** `forward`
  listens on a literal `127.0.0.1` or `::1` only (never `0.0.0.0`, a host name or a LAN
  address), but inside the container every process can connect to it.
- The socket files are `0666` (a rootless container's uid is not the vault user's), so any
  process on the host that can reach the path could connect. **The peer-uid check is the real
  gate:** a uid not on the socket's list is closed before anything is parsed, unanswered, and
  logged. `socket_dir` must be owned by the vault user, not group- or world-writable, and not a
  symlink, and every folder above its real path must be root's (or the vault user's) and not
  group- or world-writable; `serve` refuses to start otherwise.

### SELinux

With the `tswap-broker` module (`contrib/selinux/tswap-broker.cil`), the broker runs in its own
domain, `tswap_broker_t`, and **containers may connect to the broker's sockets and to nothing
else of the vault user's**: the module's only rule for containers is `container_t` →
`tswap_broker_t` `unix_stream_socket connectto`. Only a dedicated copy of the binary
(`/usr/local/libexec/tswap-broker`) is labelled to enter it; the `tswap` everyone runs stays
`unconfined_t`.

The module does **not** try to confine the broker much. `tswap_broker_t` gets a deliberate
subset of `unconfined_service_t`'s attributes, the ones `serve` needs (in Fedora's policy,
`unconfined_domain_type` alone is not enough: the router test denied `/proc/meminfo`, `getattr` on
cgroup2 and search on the vault user's home):

| Included | Why |
|---|---|
| `domain`, `unconfined_domain_type` | a process type; the base unconfined rules |
| `files_unconfined_type` | the vault user's home and vault folder, `broker.json`, `broker.log`, the socket folder, the runtime's files |
| `filesystem_unconfined_type` | cgroup2 `getattr` (the .NET runtime reads its limits), proc, tmpfs |
| `devices_unconfined_type` | the TPM (`/dev/tpmrm0`), `/dev/urandom` |
| `corenet_unconfined_type`, `corenet_unlabeled_type` | outbound HTTPS and DNS; unlabelled packets |
| `kern_unconfined` | `/proc` and `/sys` (meminfo, self) |
| `userdom_filetrans_type`, `named_filetrans_domain` | files it creates get the usual labels |
| `mcssetcats` | any MCS category, like the vault user's own processes |
| `process_uncond_exempt` | the process constraints unconfined processes are exempt from |

**Excluded on purpose** (the rest of `unconfined_service_t`'s attributes):

| Excluded | Why the broker never needs it |
|---|---|
| `can_load_policy`, `can_setenforce`, `can_setbool`, `can_setsecparam`, `selinux_unconfined_type` | administering SELinux itself |
| `can_relabelto_binary_policy`, `can_change_object_identity` | relabelling policy files, changing files' SELinux users |
| `can_load_kernmodule` | loading kernel modules |
| `can_read_shadow_passwords`, `can_write_shadow_passwords`, `can_relabelto_shadow_passwords` | the password database |
| `storage_unconfined_type` | raw disks |
| `rpm_transition_domain` | running the package manager's domains |
| `x_domain`, `xserver_unconfined_type`, `dbusd_unconfined`, `sepgsql_unconfined_type` | X, D-Bus and PostgreSQL policy it has nothing to do with |
| `mmap_low_domain_type`, `set_curr_context`, `ubacproc` | mapping low memory, changing its own context, user-based access control exemptions |

### The vault user is root-equivalent for its secrets

The vault user can unlock the vault (it is in group `tss` for the TPM) and can edit
`broker.json`. The `sudo` gate on `broker route|socket add|remove` protects against the
containers (other uids), **not** against the vault user. So the vault user must run nothing but
`tswap broker serve`: no agents, no shells for other work, no other services.

`serve` refuses to run as root, and makes itself non-dumpable at start
(`prctl(PR_SET_DUMPABLE, 0)` on Linux): no same-uid `ptrace`, and no core dumps holding secrets.

### The TPM's dictionary-attack counter

Every request unlocks the vault afresh. On the router's TPM that does not move the TPM's lockout
counter: the TPM's dictionary-attack protection counts only **failed authorisations**
(TCG, *TPM 2.0 Library, Part 1: Architecture*, "Dictionary Attack Protection"), and the
router's sealed key has no authValue (it unseals unattended), so an unseal can't fail an
authorisation. **This stops being true if a PIN (authValue) is ever added to the sealed key:**
then every failed unlock counts towards a TPM lockout.

**A hung unlock** (a wedged TPM or `tpm2-tools` call) is abandoned after 30 s: that request gets
`503` and a log line (`reason=unlock-timeout`), and the next unlock may start. After 3 such
timeouts in a row `serve` exits non-zero, and the unit's `Restart=on-failure` makes systemd
start it again. A client that gives up while queued for the unlock is logged too
(`status=499 reason=client-closed`).

The broker limits unlocks anyway: after 3 failed unlocks in a row a socket is refused for
5 minutes (only failures count there), and no more than 30 unlock attempts a minute are made in
total, successful or not, so no client keeps the TPM busy (refusals never count).

**The busy bound:** unlocks are serialised and the TPM takes about 2 s each, so one hostile
socket can hold 4 of the 8 request slots and keep the TPM busy for its share of the time. The
other sockets still get the remaining slots; a request waits at most 30 s for one (a queue of
16), then gets `503`.

### Memory

As little is unlocked, for as short a time, as the request needs. Per request, in this order:

- the vault key (K_v) is unsealed;
- the names key derived from it gives the route's record file name, `records/HMAC(K_names, name)`,
  and is zeroed at once;
- **only that one record** (and its sync-conflict copies, folded by the merge rules) is
  decrypted; no other record is read. A record that can't be read or authenticated fails closed
  (the uniform `502`);
- the record key is zeroed inside the decoder, K_v right after the record is read, the record's
  other bytes (a previous value) at once;
- the secret's bytes are zeroed once the outbound headers are written, and the redaction forms
  when the response ends.

**.NET strings can't be zeroed:** the header value built from the secret (`Bearer …`,
`Basic …`) is a string and stays in memory until the garbage collector reuses it.

This needs a **record-store vault** (one file per secret). `serve` refuses a classic single-file
vault, since that would be decrypted whole for every request; convert it with
`sudo tswap migrate --to-records`.

## Costs

- **Every request unlocks the vault afresh** (no cached key, by design). On the router's TPM that
  is about 2 s: a model API call through the broker gets about 2 s slower, and so does every git
  or registry request (a `git push` makes two or three).
- Unlocks are serialised, so concurrent requests queue for the TPM.
- One request per connection: the broker answers every request with `Connection: close`.

## Setup

### 1. The vault user

A dedicated user (here `vault`) holds the vault and is the only member of `tss` that does. Its
vault is a TPM keyring vault (`tswap init --tpm`), so it unlocks unattended, converted to a
record store (`sudo tswap migrate --to-records`), so a request decrypts only its own record.

```bash
sudo useradd -m vault
sudo usermod -aG tss vault
sudo loginctl enable-linger vault      # its user units run without a login session
sudo -iu vault tswap init --tpm
sudo -iu vault tswap ingest github-token < token-file    # or create / sudo tswap add
sudo TSWAP_CONFIG_DIR=/home/vault/.config/tswap tswap migrate --to-records
```

`migrate --to-records` needs root (it unlocks the vault and rewrites it), so it can't run as
`sudo -u vault`. Run as root on the vault user's folder, tswap does every file write in that
folder **as the folder's owner** (T5's identity switch, `DirectoryOwnerMatcher`: effective uid
and gid of the owner, no supplementary groups), so the keyring, the records and `config.json`
come out owned by `vault`, mode 0600, and a link `vault` planted in its own folder gets no further
than `vault`'s own rights. Tests:
`BrokerSetup_MigrateAsRootIntoTheVaultUsersFolder_WritesEverythingAsThatUser` and
`RecordStoreFileLayerTests`. `sudo VAR=value` needs a sudoers rule that
allows setting variables (implied for an `ALL` command); otherwise use
`sudo env TSWAP_CONFIG_DIR=… tswap migrate --to-records`.

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

**SELinux (Fedora, Fedora CoreOS)**, with SELinux enforcing and no
`--security-opt label=disable` on the containers. Two things stand between a rootless container
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

**After every tswap upgrade** run both lines for the copy again (`install -D …` and
`restorecon -v /usr/local/libexec/tswap-broker`). A new copy without `restorecon` is labelled
`bin_t`: `serve` then starts as `unconfined_t` without any error, and containers can no longer
connect (the AVC log shows `connectto` denied). `ps -eZ | grep tswap-broker` tells.

A `socket_dir` other than `/srv/tswap-broker` isn't covered by the module's file contexts: label it
with `sudo chcon -R -t container_file_t <socket_dir>` (a later `restorecon` on it would undo that),
or add a matching `filecon` line to the module before installing it.

Check, once `serve` runs: `ps -eZ | grep tswap-broker` shows `tswap_broker_t`, and a container
started with SELinux enforcing and without `--security-opt label=disable` gets answers through its
socket (`ausearch -m avc -ts recent` shows no denial).

### 3. Routes and sockets (`broker.json`)

`broker.json` lives next to the vault's `config.json` (mode `0600`). Changing it needs sudo;
under sudo it is written as the vault folder's owner.

```bash
# git over HTTPS (GitHub, basic auth with a fixed user name and a token)
sudo tswap broker route add github --upstream https://github.com --auth basic \
    --user x-access-token --secret github-token --path 'stevedcc/[A-Za-z0-9._-]+\.git/' --methods GET,POST

# a registry with basic auth, under a route named v2 (registry clients always ask for /v2/...)
sudo tswap broker route add v2 --upstream https://registry.crawford.dev/v2 --auth basic \
    --user lane --secret registry-password --path '(?:$|stevedcc/)' --methods GET,HEAD,POST,PUT,PATCH

# a model API with a bearer key (OpenAI-compatible) or a named header
sudo tswap broker route add openai --upstream https://api.openai.com/v1 --auth bearer --secret openai-key --path ''
sudo tswap broker route add anthropic --upstream https://api.anthropic.com/v1 --auth header \
    --header x-api-key --secret anthropic-key --path 'messages'

# one socket per container (or purpose): which host uids may connect, which routes it may use
sudo tswap broker socket add lane1 --uids 100999 --routes github,v2,openai --socket-dir /srv/tswap-broker
```

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
- unknown fields are refused, and `version` must be 1.

A hand edit is allowed but gets the same checks: `serve` refuses an invalid file at start, and on
a reload keeps the config it has.

### 4. The systemd unit

`contrib/systemd/tswap-broker.service` is a user unit for the vault user. It runs the labelled
copy, `/usr/local/libexec/tswap-broker broker serve` (see the SELinux note in step 2; on a host
without SELinux, install the copy anyway, or point `ExecStart` at `tswap`):

```bash
sudo -iu vault install -D -m 0644 tswap-broker.service ~vault/.config/systemd/user/tswap-broker.service
sudo -iu vault systemctl --user daemon-reload
sudo -iu vault systemctl --user enable --now tswap-broker
```

After a `route` change or a change to a socket's uids or routes:
`systemctl --user reload tswap-broker` (SIGHUP; the new file is validated completely, then
swapped in; a request keeps the config it started with). A new or removed socket, or a new
`socket_dir`, needs `systemctl --user restart tswap-broker`.

Logs: one line per request in the journal and in `broker.log` (mode `0600`) next to
`broker.json`: time, socket, peer uid and pid, route, method, decoded path (escaped,
length-capped), status, bytes both ways, unlock count and duration, and a reason for refusals.
Never a credential, a header value or a body. If `broker.log` can't be written (disk full, an
I/O error), serving goes on: the failure is reported once and lines go to the journal only.

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
(`--uids 100000-165535`) when you accept every uid of that user's containers (see "Limits of the
identity check").

### 6. Starting a container

Bind-mount **only that container's socket file**, at `/run/tswap.sock` by convention, and run
`forward` inside:

```bash
podman run -d --name lane1 -v /srv/tswap-broker/lane1.sock:/run/tswap.sock <image> \
    sh -c 'tswap broker forward --listen 127.0.0.1:8080 & exec <agent>'
```

No `:z` or `:Z` on the socket mount (see the SELinux note in step 2). `forward` needs no vault,
home folder, YubiKey or TPM (it reads nothing but its arguments).

### 7. Using it from inside the container

**git** (the route's name is the first path segment):

```bash
git config --global url."http://127.0.0.1:8080/github/".insteadOf https://github.com/
git clone https://github.com/stevedcc/croft.git      # goes to the broker; it adds the token
git push origin brief/t8
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

## Limits (v1)

- `tswap broker` is Unix only (Linux and macOS); on Windows every subcommand refuses with "not
  supported on Windows". So Windows' sharing-violation errors are never mapped: the lock files'
  "another serve/change is running" messages come from `flock`'s EWOULDBLOCK only.
- **Registries that issue tokens from a separate realm URL** (GHCR, Docker Hub: `401` with
  `WWW-Authenticate: Bearer realm=https://ghcr.io/token`) are not covered: the client would fetch
  a token from the realm itself. Basic-auth registries are covered.
- No TLS on the socket (it is a local Unix socket), no command templates, no arbitrary `run`
  over the socket, no key caching.
- Request and response trailers are never forwarded; `Range` requests are dropped (no partial
  reads); compressed responses fail closed.
- The client's `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, `Connection` and every
  header it names, the other hop-by-hop headers, `Expect`, `Range`, `If-Range` and
  `Accept-Encoding` never reach the upstream; `Set-Cookie`, hop-by-hop headers and any header
  holding a redaction form never reach the client.
