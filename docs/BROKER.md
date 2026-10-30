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
it at the end; it never buffers a body. A response with any `Content-Encoding` other than
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
  `..`, `%2e%2e`, `%2f`, `..;`, `//host` or double encoding (each a uniform `404`);
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
  symlink; `serve` refuses to start otherwise.

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

The unsealed key and the secret's bytes are zeroed as soon as they are no longer needed (the key
right after decrypting, the secret once the outbound headers are written), and the redaction
forms when the response ends. **.NET strings can't be zeroed:** the header value built from the
secret (`Bearer …`, `Basic …`) is a string and stays in memory until the garbage collector
reuses it. The vault's secrets database is decrypted as a whole for each unlock and only the
route's secret is kept; the rest is dropped at once.

## Costs

- **Every request unlocks the vault afresh** (no cached key, by design). On the router's TPM that
  is about 2 s: a model API call through the broker gets about 2 s slower, and so does every git
  or registry request (a `git push` makes two or three).
- Unlocks are serialised, so concurrent requests queue for the TPM.
- One request per connection: the broker answers every request with `Connection: close`.

## Setup

### 1. The vault user

A dedicated user (here `vault`) holds the vault and is the only member of `tss` that does. Its
vault is a TPM keyring vault (`tswap init --tpm`), so it unlocks unattended.

```bash
sudo useradd -m vault
sudo usermod -aG tss vault
sudo loginctl enable-linger vault      # its user units run without a login session
sudo -iu vault tswap init --tpm
sudo -iu vault tswap ingest github-token < token-file    # or create / sudo tswap add
```

### 2. The socket folder

Owned by the vault user, mode `0711` (others can reach a socket file they know the name of, but
can't list or create entries), not a symlink. Every folder above it must be traversable by the
user that starts the containers (so `/run/user/<uid>`, which is `0700`, won't do).

```bash
sudo install -d -m 0711 -o vault -g vault /srv/tswap-broker
```

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
  framing or hop-by-hop header); the secret is named as `{{name}}` in the file. A stored value
  containing CR, LF or NUL is a hard error, never a header;
- `methods` default to `GET`, `HEAD`, `POST`; `CONNECT` and `TRACE` are never allowed;
- `path` is a regex the decoded path after `/<route>/` must match **as a prefix**: the broker
  compiles it as `\A(?:<pattern>)`, case-sensitive, culture-invariant, never multiline, with a
  match timeout. Inline option groups (`(?i)`, `(?m)`, `(?s)`, `(?x)`, …) are refused. Anchor the
  end yourself (`$`) when a prefix is too wide. The regex never sees the query;
- `idle_timeout_sec` (default 120) ends a stream with no bytes moving;
- unknown fields are refused, and `version` must be 1.

A hand edit is allowed but gets the same checks: `serve` refuses an invalid file at start, and on
a reload keeps the config it has.

### 4. The systemd unit

`contrib/systemd/tswap-broker.service` is a user unit for the vault user:

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
Never a credential, a header value or a body.

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

`forward` needs no vault, home folder, YubiKey or TPM (it reads nothing but its arguments).

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

## Limits (v1)

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
