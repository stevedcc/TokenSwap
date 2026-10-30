# Brief T8: a broker so containers use a host vault's credentials without ever holding them (#162)

Read AGENTS.md first, then issue #162 **and its 2026-10-29 comment** (the design this brief
settles and changes), #167, #168 and #71. One commit per item, test first (watch it fail for the
right reason), a break-it-once check per item named in its commit message, `./runtests.sh --unit`
after each item, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real
YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only.
Sudo-refusal tests return early when `Environment.IsPrivilegedProcess` and assert "requires"
(Windows CI runs elevated). No new NuGet packages (ASP.NET Core's Kestrel comes with the shared
framework; say so if you find you need one, don't add it).

**Parallel work:** brief T7 runs at the same time. T8 owns new files only:
- `TswapCore/Broker/`;
- `TswapCli/Commands/BrokerCommand.cs`;
- tests named `Broker*`;
- `docs/BROKER.md`;
- `contrib/systemd/`.

Its only shared edits are registering `broker` in `TswapCli/CommandRegistry.cs` and the project
file reference for Kestrel. Do not touch `CliEnvironment.cs`, `Program.cs`, `CommandContext.cs`,
`SecurityWarnings.cs`, the YubiKey selection code, `Prompt.cs`, `README.md` or `AGENTS.md` (T7 owns
them). If you need a change there, stop and say what.

## Why

The owner's router runs a Fedora CoreOS VM with a TPM-backed vault (user `vault`). Agents and an
orchestrator will run there in rootless Podman containers. They need credentials for work they do
**from inside the container**:
- `git push` of their own worktree over HTTPS;
- pushes to the registry (`registry.crawford.dev`, basic auth);
- model APIs (bearer keys).

No container may get the TPM, the vault files, or a credential's value. The #162 comment's command
templates alone can't do this: they run on the host and can't act on the container's own worktree
or its API calls. So the main mechanism here is a **credential-adding HTTP proxy** (the comment's
kind b), and command templates are the smaller second part.

## Decisions (owner, 2026-10-30, and settled here)

1. **One process, as the vault's user:** `tswap broker serve`, run by the vault's own user (a
   systemd user unit, example in `contrib/systemd/`).
   - It keeps no key between uses: **every credential use unlocks the vault afresh** (owner:
     "unlock per request, the delay is livable"; about 2 s on the router's TPM), reads only the
     secrets that route or template needs, and zeroes keys and values afterwards.
   - For the proxy, "a use" is **one HTTP request**.
   - State the cost in `BROKER.md`: a model API call gets about 2 s slower.
2. **One Unix socket per client** (one container, or one purpose).
   - Defined in the broker config, created by `serve` in a configured `socket_dir` and removed on
     exit.
   - The container starter bind-mounts **only that socket file**, at `/run/tswap.sock` by
     convention.
3. **Identity comes from the socket and the kernel, never from the client:**
   - **The socket the connection arrived on** decides which routes and templates it may use: the
     client's name and allow-lists come from the config.
   - **The peer's uid:** read with `SO_PEERCRED` on Linux and `getpeereid` on macOS (P/Invoke,
     `LibraryImport`, NativeAOT-safe), on the accepted socket (Kestrel's `IConnectionSocketFeature`
     gives it). It must be in that socket's `uids` list or range. Under rootless Podman a
     container's processes have the container user's mapped host uids; the operator writes those.
     A connection from another uid is closed, unanswered, and logged.
   - **Why the uid check is the real gate:**
     - A rootless container's uid is not the vault user, so the socket file can't be 0600.
     - It is created 0666 inside a `socket_dir` that must be owned by the vault user and not
       group- or world-writable; `serve` refuses to start otherwise. The operator makes it 0711,
       so nobody can list it.
     - Any process that knows the path could reach the socket file; the uid check is what keeps
       them out.
4. **The credential proxy (routes).** Kestrel listens on each socket (HTTP/1.1, no TLS on the
   socket). A route is:
   - `name`: the first path segment. The client asks for `/<route>/<rest>`.
   - `upstream`: an `https://` base URL only. Plain `http` upstreams are refused when the route is
     added.
   - `auth`, one of:
     - `bearer` (`Authorization: Bearer <secret>`);
     - `basic` with a fixed user name (`Authorization: Basic base64(user:<secret>)`);
     - `header` with a header name (`<name>: <secret>`).
     The secret is named by `{{secret}}`.
   - `methods` (default `GET`, `HEAD`, `POST`) and `path` (an anchored regex the `<rest>` must
     match, e.g. `^stevedcc/croft(\.git)?/` so a git route can't push to another repository).
   - **Forwarding:**
     - The broker strips any `Authorization`, `Proxy-Authorization` and `Cookie` header the client
       sent, sets its own `Authorization` (or header) and `Host`, and drops hop-by-hop headers.
     - It sends the request with `HttpClient` over TLS, with system trust, and streams request
       and response bodies in both directions without buffering them whole (a registry layer can
       be gigabytes).
     - It doesn't follow redirects; it passes them back.
   - **The response never carries the credential:**
     - response headers holding the secret value (or its base64 form) are dropped;
     - the response body is passed through a streaming redactor for the secret's value and the
       encoded forms `run`'s redaction covers (keep a sliding window of the longest form; don't
       buffer the body).
   - A route the socket may not use, an unknown route, a path or method outside the route: the
     same `404` with the same body. They are indistinguishable (#167). Nothing is unlocked for a
     refused request.
5. **Command templates.** A template is:
   - `argv`: a list of strings, run directly (never through a shell). Strings may hold
     `{{secret}}` tokens (as in `run`) and `{arg}` placeholders.
   - `args`: per declared argument, an anchored regex and a max length. A value starting with
     `-` is refused unless the template allows it.
   - `cwd`, `env` (literal values or `{{secret}}`), `timeout_sec` (default 120) and
     `max_output_bytes` (default 1 MiB).
   - Adding or changing a template runs `Validation.GetBlockedInvocation` on its argv (#105: no
     inline interpreter code) and refuses tokens in the program name.
   - The client gets the exit code and the redacted stdout and stderr, through `POST
     /_template/<name>` on the same socket (JSON in, JSON out). Unknown and not allowed are
     indistinguishable here too.
6. **The config** (`broker.json` next to the vault's `config.json`, 0600):
   - holds `socket_dir`, `sockets` (name, `uids`, `routes` and `templates` allow-lists), `routes`
     and `templates`.
   - Changing it needs sudo: `sudo tswap broker route|template|socket add|remove`. Under sudo it is
     written as the vault folder's owner (T5's file layer).
   - `serve` reloads it on SIGHUP. Say in `BROKER.md` that the vault user can edit the file
     directly: the sudo gate protects against agents running as **other** users (the
     containers), not against the vault user, who owns the vault anyway.
7. **Logging** (#168): every request is one line on stderr (journald under systemd) and in
   `broker.log` (0600): time, socket name, peer uid and pid, route or template, method and path
   (for routes) or declared argument values (for templates), status or exit code, bytes, and
   duration. Never a credential value, never `argv` after substitution, never a body.
8. **Clients** (they need no vault, home folder, YubiKey or TPM):
   - **`tswap broker forward --listen 127.0.0.1:<port> [--socket /run/tswap.sock]`**, run inside
     the container:
     - relays each TCP connection on that loopback port to the socket, byte for byte;
     - refuses a non-loopback listen address.
     - Apps then use `http://127.0.0.1:<port>/<route>/...` as their base URL. `BROKER.md` shows
       git (`url.<base>.insteadOf`), a registry client configured for an insecure local endpoint,
       and an OpenAI-compatible base URL.
   - **`tswap broker call <template> [name=value ...]`** calls a template, prints its output and
     exits with its exit code (2 with the error).
9. **Limits:**
   - one template at a time;
   - the proxy limits concurrent requests per socket (default 4) and in total (default 8);
   - the vault unlocks are serialised (the TPM is serial).
   - A request over its limit waits up to 30 s, then gets `503`.
   - Unlock failures are counted per socket: after 3 in a row, that socket is refused for
     5 minutes and it is logged. That way a flood can't drive the TPM towards its
     dictionary-attack lockout. Note whether an unseal can count against it at all, and cite the
     source.
10. **Unix only** (Linux and macOS). On Windows, `broker` says it isn't supported.

## Items

1. **Config, routes, templates, sockets, and validation** (decisions 4, 5 and 6).
   - The model, loading and validation.
   - `sudo tswap broker route|template|socket add|remove`.
   - **Tests:**
     - valid entries round-trip;
     - each is refused:
       - an `http://` upstream;
       - an unanchored path or argument regex;
       - an inline-interpreter argv;
       - a token in a program name;
     - without sudo, changes are refused and nothing is written.
   - **Break-it-once:** allow `http://` upstreams; its test fails.
2. **The socket server and identity** (decisions 2, 3 and 9). `serve`:
   - creates the sockets;
   - checks `socket_dir`;
   - runs Kestrel on them;
   - maps each connection to its socket and peer uid;
   - applies the limits and the unlock-failure backoff;
   - removes the sockets on SIGTERM or SIGINT.
   - **Tests** (real Unix sockets in a temp folder; this process's uid allowed or not):
     - an allowed uid gets an answer;
     - a uid not on the list is closed with nothing returned, and logged;
     - a group-writable `socket_dir` makes `serve` refuse to start;
     - the sockets are gone after a stop;
     - the limits give `503` after the wait;
     - three unlock failures lock that socket out.
   - **Break-it-once:** skip the uid check; the wrong-uid test fails.
3. **The credential proxy** (decision 4), the main item.
   - **Tests** against a local HTTPS test upstream (a self-signed certificate trusted **only**
     through a test seam on the forwarder's handler; production uses system trust, and a test
     proves the seam is off by default):
     - **the upstream receives the right auth header** (bearer, basic and header kinds) and the
       right `Host`;
     - **the client receives no credential**, even when the upstream echoes it in a header and in
       the body, also split across two chunks;
     - a client-supplied `Authorization` is replaced;
     - a disallowed route, an unknown route, a path or method outside its route: identical `404`s,
       and no unlock;
     - a 50 MB request body and a 50 MB response body stream through, and the broker's memory
       stays bounded (assert with a body larger than any buffer you use);
     - a redirect is passed back, not followed;
     - an `http://` upstream can't be configured;
     - every request unlocks afresh (count the simulated unlocks).
   - **Break-it-once:** skip the response redactor; the echo test fails.
4. **Command templates** (decision 5).
   - **Tests:**
     - a template runs with the secret substituted, and the output is redacted;
     - each of these refuses with nothing run and no unlock:
       - a missing argument;
       - a non-matching argument;
       - an over-long argument;
       - an argument starting with `-`;
     - unknown and not-allowed give identical answers;
     - the timeout kills the child;
     - over-limit output is cut and says so.
   - **Break-it-once:** drop the `-` check; its test fails.
5. **Clients and logging** (decisions 7 and 8).
   - **Tests:**
     - `forward` relays a request end to end (forward → socket → broker → test upstream);
     - `forward` refuses a non-loopback address;
     - `call` returns the template's output and exit code;
     - the log lines have their fields, and no credential value appears in the log after
       requests that used one (search the log for the value and its base64 form).
   - **Break-it-once:** log the substituted header; the log test fails.
6. **Docs:**
   - `docs/BROKER.md`:
     - **setup:** vault user, `socket_dir`, the systemd unit, `podman run -v
       <socket>:/run/tswap.sock`, finding a container's mapped uid, `forward` inside the container,
       and the git, registry and API base-URL examples;
     - **costs:** about 2 s per request;
     - **threat model:** what a compromised container **can** do (use its own routes, within
       their paths and methods, while it runs; call its templates with valid arguments) and
       **can't** (read a credential, use other routes, reach other sockets, push to another
       repository the path regex excludes);
     - **limits:** registries that hand out tokens from a separate realm URL (e.g. GHCR) need that
       realm routed too, so v1 documents basic-auth registries only.
   - The `THREAT_MODEL.md` lines.
   - `contrib/systemd/tswap-broker.service`.
   - Don't edit `README.md` (T7 owns it); put the README line in your report.

## Real test after merge (the orchestrator, not you)

On the router:
- The `vault` user runs `serve` with a throwaway secret.
- A rootless Podman container (user `lane`), with only its socket mounted, runs `forward`.
  Through it:
  - a request to an HTTPS echo service gets a redacted echo, and the service saw the right header;
  - a `git ls-remote` of a private repository works through a git route;
  - a disallowed route gets the same `404` as an unknown one.
- A process with the wrong uid is refused.
- The TPM lockout counter stays 0.

## Out of scope

- Caching the key (#64): decided against.
- Arbitrary `run` over the socket.
- Token-realm registries such as GHCR.
- TLS on the socket.
- Windows.
- Changes to Chargehand (its container starter mounts the socket and runs `forward`, in a later
  Chargehand plan).
