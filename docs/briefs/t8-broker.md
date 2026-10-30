# Brief T8: a credential-adding proxy so containers use a host vault's credentials without ever holding them (#162)

Read AGENTS.md first, then issue #162 **and its 2026-10-29 comment** (the design this brief settles
and changes), #167, #168 and #71. One commit per item, test first (watch it fail for the right
reason), a break-it-once check per item named in its commit message, `./runtests.sh --unit` after
each item, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys
or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only. Sudo-refusal
tests return early when `Environment.IsPrivilegedProcess` and assert "requires" (Windows CI runs
elevated). No new NuGet packages (Kestrel comes with the ASP.NET Core shared framework).

**NativeAOT:** tswap publishes NativeAOT.
- Adding `<FrameworkReference Include="Microsoft.AspNetCore.App" />` with Kestrel's slim builder
  must stay AOT- and trim-clean: source-generated JSON for `broker.json`, `LibraryImport` for
  P/Invoke, no reflection.
- Run `dotnet publish TswapCli -c Release -r linux-x64` once, and put its warning count in the
  report.
- If it can't be made clean, stop and propose the alternative (a separate small host project)
  instead of disabling the analysers.

**Parallel work:** brief T7 runs at the same time. T8 owns new files only:
- `TswapCore/Broker/`;
- `TswapCli/Commands/BrokerCommand.cs`;
- tests named `Broker*`;
- `docs/BROKER.md`;
- `contrib/systemd/`.

Its only shared edits are registering `broker` in `TswapCli/CommandRegistry.cs` (keep it to that
line) and the `FrameworkReference` in the project file. Do not touch `CliEnvironment.cs`,
`Program.cs`, `CommandContext.cs`, `SecurityWarnings.cs`, the YubiKey selection code, `Prompt.cs`,
`README.md` or `AGENTS.md` (T7 owns them). If you need a change there, stop and say what.

## Why

The owner's router runs a Fedora CoreOS VM with a TPM-backed vault (user `vault`). Agents and an
orchestrator will run there in rootless Podman containers. They need credentials for work they do
**from inside the container**:
- `git push` of their own worktree over HTTPS;
- pushes to the registry (`registry.crawford.dev`, basic auth);
- model APIs (bearer keys).

No container may get the TPM, the vault files, or a credential's value. The #162 comment's command
templates can't serve this (they run on the host, not in the container's work) and, as two reviews
showed, are unsafe as specified. So **this brief is the credential proxy only** (owner decision
2026-10-30). Templates are a later brief.

## Decisions (owner, 2026-10-30, and settled here with the GLM and MiMo brief reviews)

1. **One process, as the vault's user:** `tswap broker serve`, run by the vault's own user (a
   systemd user unit in `contrib/systemd/`).
   - **Every HTTP request unlocks the vault afresh** (owner: "unlock per request, the delay is
     livable"; about 2 s on the router's TPM). It reads only that route's secret.
   - Drop the secret's reference as soon as the outbound headers are written, and zero the byte
     arrays (the unsealed key, the secret's bytes).
   - `BROKER.md` states the cost (a model API call gets about 2 s slower) and that .NET header
     strings can't be zeroed.
   - At start, `serve` calls `prctl(PR_SET_DUMPABLE, 0)` (Linux): no same-uid ptrace, and no core
     dumps holding secrets.
2. **One Unix socket per client** (one container, or one purpose).
   - Created by `serve` in a configured `socket_dir` and removed on exit.
   - **One `serve` per `socket_dir`:** `flock` on a lock file there. Stale socket files are
     removed only under that lock, only after `lstat` shows a socket owned by the vault user.
   - The container starter bind-mounts **only that socket file**, at `/run/tswap.sock` by
     convention.
3. **Identity comes from the socket and the kernel, never from the client:**
   - **The socket the connection arrived on** decides which routes it may use (allow-list per
     socket in the config).
   - **The peer's uid:**
     - read with `SO_PEERCRED` on Linux or `getpeereid` on macOS, from the **accepted** socket
       (verify that Kestrel's `IConnectionSocketFeature` gives you exactly that socket; if creds
       can't be read, close the connection: fail closed);
     - it must be in that socket's `uids` list or range;
     - another uid is closed before anything is parsed, unanswered, and logged.
   - **Why the uid check is the real gate:**
     - A rootless container's uid is not the vault user, so the socket file is created 0666.
     - Any process that knows the path could reach it.
     - `socket_dir` must be owned by the vault user, not group- or world-writable, and not a
       symlink (resolve it); `serve` refuses to start otherwise. The operator makes it 0711.
   - **`BROKER.md` states the limits of this:**
     - **The bind-mount is the boundary between containers of the same host user.** Rootless
       Podman gives them the same subuid range unless the operator separates them.
     - **Credentials are fixed at `connect()`.** An allowed process can relay for another (fd
       passing); uid is not a delegation boundary.
4. **Routes.** Kestrel listens on each socket (HTTP/1.1, no TLS on the socket). A route has:
   - `name`: `[a-z0-9-]{1,32}`, matched ordinally; names starting with `_` are reserved. The client
     asks for `/<route>/<rest>`; `/<route>` with no rest is the uniform `404`.
   - `upstream`: an `https://` base URL only (an `http://` upstream is refused). It may include a
     base path.
   - `auth`, one of:
     - `bearer` (`Authorization: Bearer <secret>`);
     - `basic` with a fixed user name (no `:`, no control characters):
       `Authorization: Basic base64(user:<secret>)`;
     - `header` with a header name (an RFC 7230 token): `<name>: <secret>`.
     The secret is named by `{{secret}}`. A stored value containing CR, LF or NUL is a hard error,
     never a header.
   - `methods` (default `GET`, `HEAD`, `POST`). `CONNECT`, absolute-form and asterisk-form request
     targets are refused (`400`).
   - `path`: a regex the decoded path after `/<route>/` must match.
     - **The broker wraps it** as `\A(?:<pattern>)` (prefix match) and adds no other anchors.
     - It uses `RegexOptions.CultureInvariant`, never `Multiline`, is case-sensitive, and has a
       match timeout.
     - Inline option groups (`(?m)`, `(?s)`, `(?x)`, …) in the pattern are refused.
     - The path regex never sees the query.
5. **Building the upstream request** (the brief reviews' B1, the most important part):
   - **Split the raw request target's path** (not ASP.NET's decoded `Request.Path`) on `/`.
   - **Percent-decode each segment exactly once.** Refuse (uniform `404`) a segment that:
     - is empty (`//`);
     - decodes to `.` or `..`;
     - contains `/`, `\`, `;`, `%`, NUL or a control character after decoding (this catches
       `%2f`, `%5c`, `..;` and double encoding such as `%252e`).
   - **Match the route's regex against the decoded, `/`-joined segments.**
   - **Build the outbound path yourself:** the upstream's base path, then each segment re-encoded.
     - **Never `new Uri(base, rest)`:** a `rest` of `//evil.com/x` would change the authority, and
       a leading `/` drops the base path.
     - Append the original query string unchanged.
   - **Before sending, assert** that the outbound URI's scheme, host and port equal the configured
     upstream's, and that its path starts with the base path. Otherwise it is the uniform `404`
     and logged.
6. **Headers and framing** (B2, B3, I1):
   - **Request: dropped.**
     - `Authorization`, `Proxy-Authorization`, `Cookie`;
     - `Connection` **and every header it names**;
     - `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Expect`,
       `Proxy-Connection`;
     - `Content-Length` (re-framed by `HttpClient`);
     - `Range` and `If-Range` (no partial reads of a response);
     - `Accept-Encoding`, replaced by `Accept-Encoding: identity`.
   - **Request: set.** `Host` is the upstream's authority (a client `Host` never survives), and the
     route's auth header.
   - **Response: dropped.**
     - hop-by-hop headers;
     - `Set-Cookie`;
     - trailers (never forwarded);
     - `Content-Length` (re-framed as chunked, since redaction may change the length; HEAD, 204
       and 304 keep their empty bodies and get no fabricated body);
     - any header whose value contains a redaction form, except the framing headers the broker
       sets itself.
   - **Response: compressed bodies.** A response with any `Content-Encoding` other than `identity`
     fails closed: `502`, the body is not forwarded, and it is logged.
   - Redirects are passed back, never followed. The client's next request comes back through the
     broker and its route checks. A client that follows a `Location` elsewhere carries no
     credential, because it has none.
7. **Streaming and limits:**
   - Request and response bodies stream in both directions without being buffered whole (a
     registry layer can be gigabytes).
   - **Set, and asserted in a test:**
     - `HttpClient.Timeout` is infinite;
     - a per-route `idle_timeout_sec` (default 120) ends a stream with no bytes moving;
     - Kestrel's `MaxRequestBodySize` is unlimited;
     - `MinRequestBodyDataRate` and `MinResponseDataRate` are relaxed for slow links;
     - a request with no complete headers within 10 s is closed.
   - **Concurrency:**
     - per socket at most 4 requests in flight, in total 8;
     - the queue for a slot is bounded (16) and a request waits at most 30 s, then gets `503`;
     - unlocks are serialised.
   - **Unlock failures:**
     - counted per socket: after 3 in a row, that socket is refused for 5 minutes, logged;
     - a global limit as well: no more than 30 unlock attempts a minute, then `503`;
     - only failed unlocks count, never refusals.
   - **The TPM's dictionary-attack counter** counts failed authorisations only. The router's
     sealed key has no authValue (an unattended unseal), so unseals can't move it.
     - `BROKER.md` states this, citing TCG TPM 2.0 Part 1 "Dictionary-attack Protection", and
       that it stops being true if a PIN is ever added.
     - It also states the busy bound: one hostile socket can hold 4 of 8 slots and the TPM's time.
   - **All waits use an injectable clock** (no sleeps in tests).
8. **The redactor** (B5). Every response body is passed through a streaming redactor before it
   reaches the client.
   - **Forms**, listed in `BROKER.md`:
     - the raw value;
     - base64 with and without padding, and base64url;
     - for `basic` routes, the exact `base64(user:secret)` composite the broker sent;
     - hex, upper and lower case;
     - percent-encoded;
     - JSON-escaped;
     - every form `run`'s redaction covers.
   - **Window:** a sliding window of (longest form − 1) bytes, flushed at the end. Never buffer the
     body.
   - **`BROKER.md` leads its threat model with this:** redaction is best-effort, since a hostile
     upstream can obfuscate a value past any window. The guarantee is that the broker never emits
     a known form of the value, and only ever sends the value to that route's upstream, over TLS,
     inside the route's path and method envelope.
9. **The config** (`broker.json` next to the vault's `config.json`, 0600):
   - It has a `version` field; unknown fields are refused.
   - It holds `socket_dir`, `sockets` (name, `uids`, `routes` allow-list) and `routes`.
   - **Changing it needs sudo:** `sudo tswap broker route|socket add|remove`. Under sudo it is
     written as the vault folder's owner through T5's file layer (atomic, owner-only).
   - **`serve` reloads on SIGHUP:**
     - the new file is validated completely, then swapped in atomically;
     - an invalid or missing file keeps the current config, logged;
     - each request keeps the config it started with.
   - **Validation runs on every load**, not only on `add`.
   - **`BROKER.md` is explicit that the vault user is root-equivalent for its secrets.** It can
     edit `broker.json` and is in `tss`. The sudo gate protects against the containers (other
     uids), not against the vault user, so the vault user must run nothing but `serve`.
10. **Logging** (#168): one line per request on stderr (journald) and in `broker.log` (0600):
    - time, socket name, peer uid and pid, route, method, path (decoded, length-capped, control
      characters escaped), status, bytes both ways, unlock count and duration;
    - never a credential, a header value or a body.
11. **The client:** `tswap broker forward --listen 127.0.0.1:<port> [--socket /run/tswap.sock]`,
    run inside the container.
    - It relays each TCP connection on that loopback port to the socket, byte for byte.
    - The listen address must be a literal `127.0.0.1` or `::1`.
    - It needs no vault, home folder, YubiKey or TPM.
    - `BROKER.md`:
      - any process in the container's network namespace can use the port;
      - examples: git (`url.http://127.0.0.1:<port>/<route>/.insteadOf https://github.com/`), a
        registry client set for an insecure local endpoint, an OpenAI-compatible base URL.
12. **Unix only** (Linux and macOS). On Windows, `broker` says it isn't supported.

## Items

1. **Config, routes, sockets and validation** (decisions 4 and 9).
   - **Tests:**
     - valid entries round-trip;
     - each of these is refused:
       - an `http://` upstream;
       - an inline option group in a path regex;
       - a reserved or invalid name;
       - a `basic` user with `:`;
       - an invalid header name;
       - unknown fields;
     - a hand-edited invalid file is refused at load, and on SIGHUP the old config stays;
     - without sudo, changes are refused and nothing is written;
     - after a (simulated) sudo `route add`, `broker.json` is owned by the vault folder's owner,
       0600, written atomically, and loads in `serve`.
   - **Break-it-once:** skip the wrap (use the pattern as given); a "regex matches only at the
     start" test fails.
2. **The socket server and identity** (decisions 2, 3 and 7). Real Unix sockets in a temp folder,
   this process's uid allowed or not.
   - **Tests:**
     - an allowed uid gets an answer;
     - a uid not on the list is closed with nothing returned, and logged;
     - `socket_dir` that is group-writable, wrong-owner or a symlink makes `serve` refuse to start;
     - a second `serve` on the same `socket_dir` refuses;
     - a stale socket from a killed `serve` is cleaned up under the lock;
     - the sockets are gone after a stop;
     - per-socket and total limits, the bounded queue and the 30 s wait give `503` (injectable
       clock);
     - three unlock failures lock out that socket, and the global unlock limit holds.
   - **Break-it-once:** skip the uid check; the wrong-uid test fails.
3. **Building and forwarding** (decisions 5 and 6).
   - **Tests** against a local HTTPS test upstream (a self-signed certificate trusted **only**
     through a test seam on the forwarder's handler; a test proves the seam is off by default).
     The upstream counts its hits.
   - **Allowed requests:**
     - the upstream gets the right auth header (bearer, basic, header) and `Host`;
     - a client `Authorization` and `Host` are replaced;
     - `Connection: x-secret-header` drops that header;
     - CL+TE and bare `Transfer-Encoding: chunked` requests don't reach the upstream with the
       client's framing;
     - `Range` and `Accept-Encoding` don't reach it, and it sees `identity`.
   - **Refusals, each with zero upstream hits and zero unlocks:**
     - **Path tricks**, each the uniform `404`: `..`, `%2e%2e`, `..%2f`, `%252e%252e`, `//evil.com`,
       `..;`, `%2f` inside a segment, `\` and `%5c`, a `..` crossing the upstream's base path;
     - **Route and method:** an unknown route, another socket's route, a method outside the route,
       `CONNECT`, an absolute-form target.
   - **The uniform `404`:** all of these are byte-identical, headers included.
   - **Redirects:** a redirect is passed back with exactly one upstream hit.
   - **Assertions:** the outbound authority equals the upstream's, even for `//evil.com/x`.
   - **Break-it-once:**
     - build with `new Uri(base, rest)`; the `//evil.com` test fails;
     - skip the segment checks; the `%2e%2e` test fails;
     - forward `Accept-Encoding`; its test fails.
4. **Responses: framing and redaction** (decisions 6 and 8).
   - **Tests:**
     - the upstream echoes each redaction form in a header, in the body, split across two chunks,
       and in a trailer: the client receives none of them;
     - a body with `Content-Length` whose redaction changes its length arrives intact and correctly
       framed;
     - gzip and brotli bodies containing the value: `502`, nothing forwarded;
     - HEAD, 204 and 304 pass with empty bodies;
     - a 50 MB response streams: the first byte reaches the client before the upstream has
       finished sending, and memory stays bounded (a body larger than any buffer you use);
     - a bidirectional case (a large request body while the response starts) completes;
     - timeouts and sizes have their set values;
     - every request unlocks afresh (count the simulated unlocks), also under 8 concurrent
       requests.
   - **Break-it-once:** skip the redactor; the echo test fails. Forward `Content-Length`; the
     framing test fails.
5. **The client and logging** (decisions 10 and 11).
   - **Tests:**
     - `forward` relays a request end to end (forward → socket → broker → test upstream);
     - `forward` refuses `0.0.0.0`, a hostname and a LAN address;
     - the log lines have their fields;
     - CR and LF in a path can't forge a log line;
     - no credential appears in the log (search the log for the value and every redaction form)
       after requests that used one.
   - **Break-it-once:** drop the loopback check; its test fails.
6. **Docs:**
   - `docs/BROKER.md`:
     - **setup:** vault user, `socket_dir`, the systemd unit, `podman run -v
       <socket>:/run/tswap.sock`, finding a container's mapped uid, `forward`, and the git,
       registry and API examples;
     - **costs;**
     - **the threat model,** leading with "redaction is best-effort":
       - what a compromised container **can** do (use its own routes, within their paths and
         methods, while it runs) and **can't** (read a credential, use other routes, reach other
         sockets, push where the path regex excludes);
       - the same-subuid and fd-passing limits;
       - the vault user being root-equivalent;
       - the TPM note with its citation;
       - the forms list;
     - **limits:** registries that issue tokens from a separate realm URL (GHCR) aren't covered in
       v1; basic-auth registries are.
   - The `THREAT_MODEL.md` lines.
   - `contrib/systemd/tswap-broker.service`.
   - Don't edit `README.md` (T7 owns it); put the README line in your report.

## Real test after merge (the orchestrator, not you)

On the router:
- The `vault` user runs `serve` with a throwaway secret.
- A rootless Podman container (user `lane`), with only its socket mounted, runs `forward`.
  Through it:
  - an HTTPS echo service sees the right header, and the container gets the echo redacted;
  - `git ls-remote` of a private repository works through a git route, and a `..` path to another
    repository is refused;
  - a disallowed route gets the same `404` as an unknown one.
- A process with the wrong uid is refused.
- The TPM lockout counter stays 0.

## Out of scope

- **Command templates** (owner decision: a later brief, with children under a separate non-`tss`
  uid, secrets via env or fd only, and git hardening).
- Caching the key (#64): decided against.
- Arbitrary `run` over the socket.
- Token-realm registries such as GHCR.
- TLS on the socket.
- Windows.
- Changes to Chargehand: its container starter mounts the socket and runs `forward`, in a later
  Chargehand plan.
