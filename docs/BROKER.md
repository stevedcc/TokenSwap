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
- **Command templates** (Linux only): `tswap broker call <template> [name=value ...]` inside the
  container asks the broker to run an operator-defined command on the host, in a `bwrap` sandbox,
  with a secret in its environment or a read-only file. See [Command templates](#command-templates).
  `sudo tswap broker template add|remove` changes them.

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
  `/` written as `\/`;
- the shapes common tools print the value alone in: its base64 wrapped at 76 columns (GNU
  `base64`; LF and CRLF) and at 64 (`openssl base64`), hex with a space between bytes (`od -An
  -tx1`, `xxd -g1`, within one line, upper and lower case) and plain hex wrapped at 60 (`xxd -p`).

**Not covered** (a fixed list of byte forms can't express them): the value inside a *longer*
wrapped base64 or hex stream (the line breaks fall at unknown places), and dumps that split it over
lines with offsets and an ASCII column between (`xxd`, `hexdump -C`, `od` with its default 16 bytes
a line). Anything else that re-encodes the value (compression, encryption, reversal) is out of reach
too; that is what "best-effort" means.

The redactor holds back a sliding window of (longest form − 1) bytes between chunks and flushes
it at the end; it never buffers a body. That window is roughly 100 to 200 bytes (the wrapped base64
form of a long value is the longest), so a stream of small
pieces (server-sent events from a model API, a progress feed) reaches the client up to that many
bytes late: each piece arrives once more data follows it, or at the end. Response headers are
never held back. A response with any `Content-Encoding` other than
`identity` can't be redacted, so it fails closed: `502`, the body is not forwarded, and it is
logged (the broker asks every upstream for `Accept-Encoding: identity`).

### Redaction confirms whole guesses

A caller whose input comes back in a response can test a complete guess of a secret: a match is
replaced by `[REDACTED]`. When `serve` reads a secret shorter than 16 bytes for a route or a
template, it says so once in its log. (Filled in by brief T13 item 4.)

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

### The load-bearing assumption: no container runs with the vault user's uid

Everything above, and the template sandbox below, assumes that **no container runs with the vault
user's uid**:

- Containers run as another user (here `lane`), so files a container writes into a shared folder
  are owned by that user's uids. The template bind rule (owned by the vault user or root) refuses
  them, so a template never reads or runs in a folder a container can write.
- Under rootless Podman a container's root *is* its invoking user. A container started by the vault
  user would therefore have the vault user's uid: it could read `broker.json`, the vault folder and
  (in group `tss`) the TPM directly, and it would pass both the bind rule and the uid check.
- With `--userns=keep-id`, run by the vault user, every vault-owned folder would be writable from
  the container.

So never start containers as the vault user. The socket layer enforces the part it can see: **a
peer whose uid is the broker's own is closed before anything is parsed, unanswered, and logged
(`reason=own-uid`), even when that uid is on the socket's list.**

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

## SSH: an agent that signs with vault keys (brief T10)

Containers need SSH too (git over ssh, deploys). Handing them a private key would break the
broker's rule, so the broker is also an **ssh-agent**: the client asks for signatures, and the key
stays on the host. The wire formats are pinned in [ssh-agent-wire.md](ssh-agent-wire.md).

- For each socket that lists `ssh_keys`, `serve` also listens on **`<name>.ssh.sock`** next to
  `<name>.sock`: same folder, lock, mode `0666`, peer-uid list and connection limits. The
  container mounts that one file and sets `SSH_AUTH_SOCK` to it.
- It answers `REQUEST_IDENTITIES` (only this socket's keys; each identity's comment is the key's
  name), `SIGN_REQUEST`, and the `session-bind@openssh.com` extension. Adding, removing, locking
  and smartcard requests get `SSH_AGENT_FAILURE`, and so does every other extension.
- **Clients need OpenSSH 8.9 or newer**, which sends `session-bind@openssh.com` on its own. A
  client that doesn't (older OpenSSH, libssh2- or libssh-based tools, agent clients of other SSH
  libraries) gets no signature at all: the agent fails closed.

### Setup

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

5. **Register the public key** with the server (`deploy.pub`), preferably narrowly (see "What
   the restriction does and doesn't do").

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

### How a signature is allowed

Every sign request passes all of these, in this order, **before any unlock**; a refusal is
`SSH_AGENT_FAILURE`, costs no unlock and is logged:

1. the key blob byte-matches a key on **this socket's** list (in the config in force now);
2. the flags fit the key (Ed25519 and ECDSA none; RSA exactly one of the SHA-2 flags);
3. this connection has a verified `session-bind@openssh.com`;
4. that bind's host-key fingerprint is on **the requested key's** `allowed_host_keys` (a bind
   allowed for key A never lets key B sign);
5. the data to sign parses completely as an SSH publickey userauth request (RFC 4252 §7, or
   OpenSSH's host-bound variant) whose session identifier is the bound one, for service
   `ssh-connection`, with this key's blob and algorithm, and (host-bound) the bound host key;
   nothing may follow it. So the agent signs **logins only**: not SSHSIG documents (`git commit -S`
   with an ssh key), not arbitrary data.

The bind itself: the server host key's signature over the session identifier is verified
(Ed25519, ECDSA, RSA with SHA-256/512; a SHA-1 RSA signature or any other key type is refused and
logged); a bind with `is_forwarding` set, a second bind on the connection, or a host that no key
of this socket allows is refused. **A failed bind closes the connection.** Bind state belongs to
one connection; it is never shared with another connection or socket.

### What the restriction does and doesn't do

- **It limits where the key can sign in** (which servers, identified by their host keys), **not
  what the server then allows.** A key accepted by GitHub for all of an account's repositories
  can push to any of them. Scope the key on the server: a per-repository deploy key, read-only
  where possible; on your own servers an `authorized_keys` line with `restrict` and, where it
  fits, `command=` and `from=`.
- **`is_forwarding` is the client's own flag.** Standard clients mark binds for a forwarded agent
  and are refused, but a modified client, or a process relaying the socket, can't be stopped
  cryptographically from claiming otherwise. A relay still never extends the set of allowed hosts:
  every bind is anchored by a host-key signature over that session's identifier, so it can only
  get signatures for a session with a listed host.
- **Why:** a stolen or misused socket can sign only into the hosts the operator listed, not into
  any server.

### What a compromised container can and can't do (ssh)

**It can**, while it runs: log in, with its socket's keys, to the listed hosts, and do there
whatever those keys are allowed to do.

**It can't:**

- read a private key (it never enters the container; the agent returns signatures only);
- sign in to a host that isn't on that key's list, or use another socket's keys;
- use the agent as a general signing service (only this session's login request is signed);
- forward the agent: binds marked as forwarding are refused (see above for what that flag can't
  promise).

### Memory, limits and logging

- **One unlock per signature,** reading **only that key's record** (T8's single-record read),
  serialised with every other unlock of the broker; the key is parsed, checked against the public
  key loaded at start (a key replaced in the vault since is refused, not used), used once, and the
  byte arrays are zeroed and the key objects disposed. Key material is **not kept beyond the
  request, and the buffers tswap holds are cleared** — not "never in memory": BouncyCastle's and
  the platform crypto library's internal copies, and the .NET `BigInteger`s an `openssh-key-v1` RSA
  key's CRT values are computed with, can't be zeroed by tswap. `serve` is non-dumpable
  (`PR_SET_DUMPABLE 0`, as above).
- **Limits:** T8's connection limits (an agent socket counts as `<name>.ssh`), a connection idle
  for 120 s between messages is closed, messages are at most 256 KiB (a larger, empty or truncated
  frame closes the connection), one request at a time per connection, in order. **At most 30
  successful signatures a minute per socket** (each is a TPM unlock); beyond that a sign request
  is refused and logged (`reason=sign-rate`) with no unlock. T8's unlock-failure lockout and its
  global unlock limit apply too; the lockout is shared with the client's HTTP socket.
- **Parser hygiene:** the agent parses bytes from the container in the vault user's process: every
  length is checked against what is left, nothing is sized by the peer on the stack, a key secret
  over 16 KiB is refused unparsed, and an exception on one connection closes that connection,
  never `serve`.
- **The same-uid limits** of "Limits of the identity check" hold here too: containers must not run
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

## Command templates

A template is a **host-side command that uses a credential**: a deploy trigger, a database CLI,
signing with a key file. The operator defines it (with sudo); a container can only call it, with
the arguments the template declares and validates. The program never comes from the caller, and
there is no shell.

```bash
# inside the container (the socket bind-mounted at /run/tswap.sock, as for routes)
tswap broker call deploy branch=brief/t9
echo $?    # the template's own exit code; 125 = the broker refused or failed; 124 = timeout
```

`broker call` prints the command's stdout and stderr as they arrive and exits with its exit code.
Any broker-side error (an unknown or not-allowed template, a bad argument, the rate limit, the
sandbox unavailable, the socket unreachable) exits **125**, so it can't be mistaken for a tool's
own 1 or 2.

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
rule is checked at start and again before every call. `serve` also checks at start that it makes
a sandbox with every option the broker uses. If `bwrap` is missing, fails these checks, is too
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
remove it, which is one more reason the vault user runs nothing else (see the load-bearing
assumption above). The secret's bytes are zeroed once they are in the environment block or the
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
  check; and never the vault user's home or a folder above it (a folder inside it is fine).

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
template remove <name>` removes it (refused while a socket allows it). A socket's `templates` list
is the only gate: a socket without one may call none. A template's secrets don't also need to be on
any route. `sudo tswap broker socket add <name> --uids ... --templates deploy,sign` allows them.

| Field | Meaning |
|---|---|
| `name` | `[a-z0-9-]{1,32}`, not starting with `_` |
| `argv` | the command, run directly (no shell). `argv[0]` a **literal** absolute path inside the sandbox (under `/usr`, `/bin`, `/sbin`, `/lib*` or a bind), never a placeholder; `{arg}` placeholders in `argv[1..]` only. Inline interpreter code (`sh -c`, `python -c`, `env`, `xargs`, ...) is refused (#105) |
| `args` | per argument: `pattern` (wrapped as `\A(?:...)\z`, culture-invariant, never multiline, no inline option groups, 100 ms match timeout), `max_length` (default 256), `allow_leading_dash` (default false). Every placeholder must be declared and every declared argument used |
| `env`, `files` | the secrets, as above. Refused env names: `PATH`, `LC_ALL`, `PWD` (the baseline), `LD_*`, and those that make a shell, an interpreter or git run code they name (`BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `PROMPT_COMMAND`, `IFS`, `CDPATH`, `BASH_FUNC_*`, `PYTHONSTARTUP`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONINSPECT`, `PERL5OPT`, `PERL5LIB`, `PERLLIB`, `PERL5DB`, `RUBYOPT`, `RUBYLIB`, `NODE_OPTIONS`, `NODE_PATH`, `GLIBC_TUNABLES`, `MALLOC_CHECK_`, `GIT_CONFIG*`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_EXEC_PATH`, `GIT_PROXY_COMMAND`, `GIT_TEMPLATE_DIR`, `GIT_EDITOR`, `EDITOR`, `VISUAL`, `PAGER`, `GIT_PAGER`). The list catches mistakes; it isn't complete, so choose tools you know |
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

A call takes one of its socket's request slots for its whole duration (T8's limits), then **one
unlock**, and decrypts only the records of the secrets the template names, each on its own
(`records/HMAC(K_names, name)`), never the whole vault; a template with no secrets doesn't unlock
at all. The vault key is zeroed straight after, the secret bytes once they are in the environment
block or the pipe. The unlock-failure limits and the unlock timeout are the routes' (see "The TPM's
dictionary-attack counter").

### Output

- stdout and stderr are **streamed** back through **one shared redactor**, in the order the
  broker read them. A secret split between the two streams is caught **only when its halves are
  read in the order they were written**: the two are separate pipes with no common order, so
  when the second half is read first (the tool wrote them close together and the reads raced),
  neither half matches a known form and both pass. Ordering them for certain would mean holding
  back all output, which the broker doesn't. Within one stream, a secret split across reads is
  always caught. The forms redacted are the routes' (see "Redaction is best-effort", including
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

### What a compromised container can do with a template

**It can** call the templates its socket lists, with arguments that pass validation, within the
rate limit, while it runs: for example, deploy to `staging` or `production`, or sign another file in
`/srv/release`.

**It can't** choose the program, add an argument the template doesn't declare, pass a value outside
its pattern, read the secret (it never leaves the sandbox except as redacted output), call another
socket's templates, or make the template run in or read a folder it can write.

### What a template author must not do

- Bind a folder that others can write, or that holds entries others can write (the rule checks the
  path, not every file in it).
- Use a tool that writes the secret to disk or to a cache: `git -c credential.helper=store`,
  `docker login` (writes `config.json`), `npm login`, `aws configure`, anything that persists a
  token in a writable bind. Inside the private `/tmp` it vanishes with the sandbox; in a writable
  bind it doesn't.
- Print the secret or something derived from it (see Output).
- Loosen `allow_leading_dash` without a tight pattern.
- Put code-running options in the template's own literals: `find ... -exec`, `git -c alias.x=!...`,
  `git -c core.sshCommand=...`, `tar --checkpoint-action=exec=...`, `rsync -e ...`. The inline-code
  check (#105) looks at the shape of `argv`, not at every tool's options.

### Logging

One line per call in the journal and `broker.log`: socket, peer uid and pid, template, the argument
values (escaped, length-capped), status, exit code, how it ended, bytes in and out, whether it was
truncated, unlocks, duration and a reason for refusals. Never a secret, an env value, or argv after
substitution.

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
- No TLS on the socket (it is a local Unix socket), no arbitrary `run` over the socket, no key
  caching.
- Templates run on Linux only (they need `bwrap`), always as the vault user's uid (in a sandbox);
  running them as another uid would need root or capabilities.
- Request and response trailers are never forwarded; `Range` requests are dropped (no partial
  reads); compressed responses fail closed.
- The client's `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, `Connection` and every
  header it names, the other hop-by-hop headers, `Expect`, `Range`, `If-Range` and
  `Accept-Encoding` never reach the upstream; `Set-Cookie`, hop-by-hop headers and any header
  holding a redaction form never reach the client.
