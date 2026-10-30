# Brief T8: a broker so containers use one host vault through named templates, never seeing a secret (#162)

Read AGENTS.md first, then issue #162 **and its 2026-10-29 comment** (the design this brief settles),
#167, #168 and #71. One commit per item, test first (watch it fail for the right reason), a
break-it-once check per item named in its commit message, `./runtests.sh --unit` after each item,
the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or
`~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only. Sudo-refusal tests
return early when `Environment.IsPrivilegedProcess` and assert "requires" (Windows CI runs
elevated).

**Parallel work:** brief T7 runs at the same time. T8 owns new files only:
- `TswapCore/Broker/`;
- `TswapCli/Commands/BrokerCommand.cs`;
- tests named `Broker*`;
- `docs/BROKER.md`;
- `contrib/systemd/`.

Its only shared edit is the one line registering `broker` in `TswapCli/CommandRegistry.cs`. Do not
touch `CliEnvironment.cs`, `Program.cs`, `CommandContext.cs`, `SecurityWarnings.cs`, the YubiKey
selection code, `Prompt.cs`, `README.md` or `AGENTS.md` (T7 owns them). If you need a change there,
stop and say what.

## Why

The owner's router runs a Fedora CoreOS VM with a TPM-backed vault (user `vault`). Agents and an
orchestrator will run there in rootless Podman containers and need secrets: git pushes, registry
pushes, later model APIs. No container may get the TPM, the vault files or a secret value.

## Decisions (owner, 2026-10-30, and settled here)

1. **One process, as the vault's user:** `tswap broker serve`, run by the vault's own user (a
   systemd user unit, example in `contrib/systemd/`). It holds no key between requests:
   **every request unlocks the vault afresh** (owner: "unlock per request, the delay is livable";
   about 2 s on the router's TPM), uses what it needs, and zeroes keys and values.
2. **One Unix socket per client** (one container, or one purpose).
   - Defined in the broker config, created by `serve` in a configured `socket_dir` and removed on
     exit.
   - The container starter bind-mounts **only that socket file**. The client finds it through
     `TSWAP_BROKER`, default `/run/tswap.sock`.
3. **Identity comes from the socket and the kernel, never from the client:**
   - **The socket the connection arrived on** decides which templates it may call: the client's
     name and allow-list come from the config.
   - **`SO_PEERCRED`:** the peer's uid must be in that socket's `uids` list (or range). Under
     rootless Podman a container's processes have the container user's mapped host uid
     (subuids); the operator writes those. A connection from any other uid is closed, no answer,
     and logged.
   - **Why the uid check is the real gate:**
     - A rootless container's uid is not the vault user, so the socket file can't be 0600.
     - It is created 0666 inside a `socket_dir` the operator makes 0711 (owner vault), so nobody
       can list it.
     - Any process that knows the path could reach the socket file; the uid check is what keeps
       them out.
   - `serve` refuses to start if `socket_dir` is group- or world-writable, or not owned by the
     vault user.
4. **Templates only, no arbitrary command.** A client names a template and supplies only the
   arguments the template declares. A template is:
   - `argv`: a list of strings, run directly (never through a shell). Strings may hold
     `{{secret}}` tokens (as in `run`) and `{arg}` placeholders.
   - `args`: per declared argument, an anchored regex and a max length; a missing or
     non-matching argument refuses the request.
   - `cwd`, `env` (literal values or `{{secret}}`), `timeout_sec` (default 120) and
     `max_output_bytes` (default 1 MiB).
   - Adding or changing a template runs `Validation.GetBlockedInvocation` on its argv (#105: no
     inline interpreter code), and refuses tokens in the program name.
5. **What comes back:** the exit code and the command's stdout and stderr, with every secret value
   used in the request redacted (the existing `run` redaction, incl. the encoded variants it
   covers). Never a value.
6. **The config** (`broker.json` next to the vault's `config.json`, 0600):
   - holds `socket_dir`, `sockets` (name, `uids`, `allow` list of template names) and `templates`.
   - Changing it needs sudo: `sudo tswap broker template add|remove`, `sudo tswap broker socket
     add|remove`. Under sudo it is written as the vault folder's owner (T5's file layer).
   - `serve` reloads on SIGHUP and on a file change.
   - A template that doesn't exist and one the socket may not call give **the same** answer
     (#167).
7. **Logging** (#168): every request is one line on stderr (journald under systemd) and in
   `broker.log` (0600): time, socket name, peer uid and pid, template, the declared argument
   values (non-secret by declaration), exit code and duration. Never a value, never `argv` after
   substitution.
8. **Protocol:**
   - One JSON request per connection: `{"template": "...", "args": {...}}`, at most 64 KiB.
   - One JSON response: `{"exit": n, "stdout": "...", "stderr": "...", "error": "..."}`.
   - Requests are served one at a time, in a queue (the TPM is serial anyway).
   - A client that sends nothing for 10 s is closed.
9. **Client:** `tswap broker call <template> [name=value ...]` works with no vault and no home
   folder. It connects to `TSWAP_BROKER`, prints stdout and stderr as received, and exits with the
   template's exit code (or 2 with the error). It needs no YubiKey, TPM or config.
10. **Unix only** (Linux and macOS; `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` / `getpeereid` on
    macOS). On Windows, `broker` says it isn't supported.

## Items

1. **Config, templates and validation** (decisions 4 and 6).
   - The model, loading and validation.
   - `sudo tswap broker template add|remove` and `socket add|remove`.
   - **Tests:**
     - a valid template round-trips;
     - an inline-interpreter argv is refused;
     - a token in the program name is refused;
     - an argument regex that isn't anchored is refused (or anchored for the user, say which);
     - without sudo, changes are refused and nothing is written.
   - **Break-it-once:** skip `GetBlockedInvocation`; the inline-code test fails.
2. **Request handling without sockets** (decisions 1, 4, 5 and 8). A `BrokerHandler` takes
   (socket name, peer uid, request bytes) and returns the response.
   - **Tests** (simulated vault, a real child process such as `printf`/`sh` scripts in a temp
     folder):
     - a request runs the template with the secret substituted, and the output is redacted;
     - each failure gives an error, runs nothing, and the vault is not unlocked:
       - a missing argument;
       - a non-matching argument;
       - an over-long argument;
       - an unknown template;
       - a template not on the socket's allow-list;
       - a uid not in the socket's list;
     - "unknown" and "not allowed" give byte-identical responses;
     - the timeout kills the child and reports it;
     - output over the limit is cut and says so;
     - every request unlocks afresh (count the simulated unlocks);
     - an oversize request is refused.
   - **Break-it-once:** return "not allowed" with a different message; the identical-response
     test fails.
3. **The socket server** (decisions 2, 3, 8 and 9).
   - `serve`:
     - creates the sockets;
     - checks `socket_dir`'s owner and mode;
     - reads the peer's uid via `SO_PEERCRED` (P/Invoke `getsockopt`, `LibraryImport`,
       NativeAOT-safe) or `getpeereid`;
     - serves requests through the item 2 handler, one at a time;
     - closes idle clients;
     - removes its sockets on SIGTERM or SIGINT.
   - `broker call` is the client.
   - **Tests** (real Unix sockets in a temp folder; this process's own uid allowed or not):
     - call → output and exit code;
     - a uid not on the list → closed with nothing returned, logged;
     - a group-writable `socket_dir` → `serve` refuses to start;
     - the sockets are gone after a stop;
     - an idle client is closed.
   - **Break-it-once:** skip the peer-uid check; the wrong-uid test fails.
4. **Logging** (decision 7). **Tests:** the log line's fields, and that no secret value appears
   in the log for a request whose template uses one (search the log for the value).
5. **Docs:**
   - `docs/BROKER.md`: the setup on a host (vault user, `socket_dir` 0711, the systemd unit,
     `podman run -v <socket>:/run/tswap.sock`, finding a container's mapped uid), what a
     compromised container can do (its own templates with valid arguments) and can't (read a
     value, call other templates, reach other sockets), and the threat model lines for
     `THREAT_MODEL.md`.
   - `contrib/systemd/tswap-broker.service` (a user unit).
   - Don't edit `README.md` (T7 owns it); put one line for the README in your report and the
     orchestrator adds it at merge.

## Real test after merge (the orchestrator, not you)

On the router:
- The `vault` user runs `serve`.
- A rootless Podman container (user `lane`) with only its socket mounted calls:
  - a template that uses a throwaway secret: output redacted, exit code passed;
  - a template not on its list: same answer as an unknown one;
- A process with the wrong uid is refused.
- The TPM lockout counter stays 0.

## Out of scope

- The HTTP header proxy (#162 comment, kind b): a later brief.
- Caching the key (#64): decided against.
- Arbitrary `run` over the socket.
- Windows.
- Changes to Chargehand (its container starter mounts the socket in a later Chargehand plan).
