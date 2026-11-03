# Brief I224: the broker knows which container is calling (v0.2.0)

Issue: https://github.com/stevedcc/TokenSwap/issues/224. Base: `origin/main` at 2dbec89 (T17 merged).
Read AGENTS.md and CLAUDE.md first, then `docs/BROKER.md` ("Threat model", "Limits of the identity check",
"SELinux", "Setup", "The bind rule") and `TswapCore/Agent/PeerIdentity.cs` (T17's pidfd method, which this brief
extends). One commit per task, TDD, break-it-once per key test, full `./runtests.sh` once per lane at the end.

## Why

A broker socket admits a client by two facts today: which socket file it reached and the uid `SO_PEERCRED` reports.
Two rootless containers of one host user share that user's subuid block, so they present the same host uids; the
documented `--uids 100000-165535` admits every container of that user. A container that gets hold of another
container's socket file (the folder mounted instead of the file, a shared volume, a copy) gets all of that socket's
routes, ssh keys and templates. All four adversarial reviews (GLM and MiMo, parts A and B, 2026-11-03, in
`~/RiderProjects/tswap-wt/tools/i224-review-*.md`) rank this blocking.

The fix: each socket names the container it serves, and the broker checks the kernel's answer for "which cgroup is
this process in" on every connection. The owner decided (2026-11-03) that the binding is **required**: a socket
must either name its container or say explicitly that it is uid-only.

## Design (decided; do not change without asking)

### D1. What a socket says about its client (`broker.json`)

Each socket gets exactly one of two new fields:

```json
{ "name": "lane1", "uids": ["100999"], "routes": ["github"],
  "container": { "cgroup": "/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service",
                 "selinux_label": "system_u:system_r:container_t:s0:c12,c34" } }

{ "name": "legacy", "uids": ["100999"], "routes": ["github"], "uid_only": true }
```

- `container.cgroup` (required inside `container`): the cgroup v2 path of the container's systemd unit, as the
  host's root cgroup namespace shows it. Load validation: starts with `/`; no empty, `.` or `..` segment; no trailing
  `/`; printable ASCII only (0x21-0x7E, so no spaces or controls); at most 1024 bytes; the **last** segment ends in
  `.service` or `.scope` (a unit, so `/user.slice/user-1001.slice` - every process of a user - can't be bound).
- `container.selinux_label` (optional): an exact, whole SELinux label (`user:role:type:level`). Corroboration only:
  any container of the same host user can ask Podman for another container's MCS level (GLM review, part A, I2), and
  the level changes on every container start unless the unit pins it (`SecurityLabelLevel=` in Quadlet). Validation:
  four or more `:`-separated parts, printable ASCII, at most 256 bytes.
- `uid_only: true`: today's behaviour, chosen on purpose. `uid_only: false` is refused (say `true` or leave it out).
- Both fields, or neither: the config is invalid. The message for "neither" names both fixes:
  `socket <name> names no container: run "sudo tswap broker socket bind <name> --pid <pid>" or set "uid_only": true`.
- `broker.json` stays `version: 1`. A v0.1 tswap refuses the new fields as unknown, which is the wanted outcome.
- `uids` stays and is still required: the uid check and the cgroup check must **both** pass. The own-uid refusal
  stays exactly as it is.
- A `uids` entry that includes 0 is accepted with a warning at load (owner rule: warn, don't refuse):
  `socket <name> admits uid 0: every root process and rootful container on this host has it`.

### D2. Where `serve` refuses to start

`serve` refuses a config (at start; on SIGHUP the old config is kept and the reason logged, as today) when:
- a socket has `container` and the platform is not Linux;
- a socket has `container` and the kernel lacks `SO_PEERPIDFD` (Linux < 6.5): probe once at start, on the first
  listening socket or a socketpair;
- a socket has `container` and `/proc/self/cgroup` is not one `0::/...` line (cgroup v1 or hybrid);
- a socket has `container.selinux_label` and SELinux is not enabled (no `/sys/fs/selinux/enforce`).

Each refusal names the socket and the reason. `uid_only` sockets start everywhere `serve` starts today.
At start `serve` logs one line per socket: `socket <name>: container <cgroup>[ label <label>]` or
`socket <name>: uid-only (any process with a listed uid is admitted)`.

### D3. Reading the peer's identity

On every accepted connection to a socket with `container`, after the existing own-uid and uid checks pass, in this
order (T17's method, extended):

1. `SO_PEERPIDFD` -> pidfd. Missing -> refuse `no-pidfd` (D2 makes this rare).
2. `/proc/<pid>` as a directory fd (`PeerIdentity.DefaultOpenPeer`). ENOENT while the pidfd is alive means the
   broker can't see the peer (`hidepid`) -> refuse `proc-hidden`; log once per serve as a start-style event:
   `can't see client processes in /proc (hidepid?): mount /proc with gid=<group> and add the vault user to it`.
3. Through the dirfd: `status` (effective uid must equal `SO_PEERCRED`'s, as T17 does) and `cgroup`.
   `cgroup` must be exactly one line `0::<path>\n`; `<path>` must start with `/` and contain no empty, `.` or `..`
   segment (a `..` means the broker is in a different cgroup namespace). Anything else -> `identity-unreadable`.
4. `SO_PEERSEC` from the socket (`PeerIdentity.DefaultReadPeerLabel`), only when `selinux_label` is configured.
   Missing or not an SELinux label -> `identity-unreadable`. Never `/proc/<pid>/attr/current`.
5. `pidfd_send_signal(pidfd, 0)` **after** the reads. Dead -> `peer-exited`.
6. Compare: the peer's path equals `container.cgroup` **or** starts with `container.cgroup + "/"` (Quadlet puts the
   payload in `<unit>/libpod-payload-<id>`; plain Podman in `libpod-<id>.scope/container`). Ordinal, segment-wise,
   never `Contains` and never a bare prefix (`lane1.service` must not admit `lane1.service-x`). Mismatch ->
   `cgroup-mismatch`. Label configured and not ordinal-equal -> `label-mismatch`.

Do not read `/proc/<pid>/ns/user` for client sockets: `readlink` of a namespace link of another uid's process is
ptrace-gated and would refuse every container (GLM part A).

Observed on this dev machine (Fedora 44, kernel 7.2, rootless Podman, uid 1000): `/proc/<pid>/cgroup` of a container
process is mode 0444 and readable by the container's owner;
`0::/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_<id>.slice/libpod-<cid>.scope/container`;
label `system_u:system_r:container_t:s0:c168,c863`. Whether `tswap_broker_t` may read a `container_t` process's
`/proc` entries is not known: task 5 adds the CIL rules and the owner checks on the router.

### D4. When it is checked

- At accept, in `BrokerServer.GateAsync` (HTTP socket) and in the ssh agent listener's accept path, before any byte
  is parsed. The observed facts (cgroup path, label or null) are stored on the connection (`BrokerPeer` gains them).
- Again per request (`BrokerRequestHandler.HandleAsync`, where `AllowsUid` is re-checked today) and per ssh message
  (`SshAgentListener.Refusal`): the **stored** facts against the **current** policy, never a fresh `/proc` read. A
  SIGHUP that rebinds or unbinds a socket thus refuses the next request of an open connection, unanswered.
- `<name>.sock` and `<name>.ssh.sock` use the same binding (the config binds the container, not the file).
- The control socket and the agent socket are untouched.

### D5. How it refuses and logs

Exactly like `uid-not-allowed` today: closed unanswered at accept; the per-request re-check refuses the way the
existing uid re-check does. No new bytes reach the client, so a client can't tell which check failed. Identity
refusals never count toward any unlock guard or rate. Log line: the existing `refused-connection` line plus
`cgroup=<observed, escaped, capped at 256>` and, when read, `label=<observed>`; reason words exactly:
`no-pidfd`, `proc-hidden`, `identity-unreadable`, `peer-exited`, `cgroup-mismatch`, `label-mismatch`.
Successful connections log nothing new.

### D6. Commands

- `sudo tswap broker socket bind <name> (--pid <pid> | --cgroup <path> | --uid-only) [--with-label]`:
  - `--pid`: reads `/proc/<pid>/cgroup` and derives the unit path: the path up to and including the **first**
    segment ending in `.service` or `.scope` that is not `user@<digits>.service`. None found -> refuse, printing the
    path it read. Prints `socket <name> bound to <path>`.
  - `--cgroup`: takes the path as given (D1 validation).
  - `--with-label` (only with `--pid`): also records `/proc/<pid>/attr/current` (trailing NUL/newline stripped);
    prints a note that the label changes on each container start unless the unit pins `SecurityLabelLevel=`.
  - `--uid-only`: removes `container`, sets `uid_only: true`.
  - Writes `broker.json` like the other socket commands (atomic, 0600, as the folder's owner, config lock).
    Ends with the existing "reload the broker" hint.
- `broker socket add` takes the same three options and requires exactly one of them.
- `broker socket list` (if it exists; otherwise wherever sockets are printed) shows the binding or `uid-only`.

### D7. Also fixed in v0.2.0 (found by the same reviews, independent of identity)

- H1 (MiMo B, S-2): the vault user's run folder (`AgentSocketPath.Folder(vaultUid, forBroker: true)`, which falls
  back to `~/.cache/tswap/run` when the user has no `/run/user/<uid>`) holds `control.sock`. The template bind rule
  doesn't protect it, so a template with `binds: [{"path": "/home/vault/.cache", "rw": true}]` can delete the control
  socket. Add it to the protected set: a bind may not be it, contain it or be inside it, **whether or not the folder
  exists yet** (compare its path, after resolving the nearest existing ancestor, as well as `st_dev:st_ino`).
- H2 (both B reviews): `BrokerTemplateCalls` skips `RecheckBinds` when `policy.Host` is null
  (`if (policy.Host is { } host && ...)`). Fail closed: a null `Host` refuses the call with the existing "binds" refusal.
- H3 (GLM B, PB-4): a template's program may lie inside one of its binds. Refuse at validation:
  `template <name>: program <path> is inside bind <bind>; a container may be able to replace it`.
- H4 (MiMo B, S-5): add to the template env-name denylist (`BrokerTemplateValidator.CodeEnvNames` or its prefix
  list): `OPENSSL_CONF`, `OPENSSL_ENGINES`, `OPENSSL_MODULES`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
  `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`,
  `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `CURL_HOME`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`,
  `NODE_OPTIONS`, `NETRC`, `HOSTALIASES`, `TMPDIR`. (Check which are already covered by a prefix rule; add the rest.)
- H5 (MiMo B, S-4): an exception escaping `BrokerRequestHandler.HandleAsync` or the template handler becomes
  Kestrel's 500, which differs from the uniform refusals. Catch at the top of both handlers (not
  `OperationCanceledException` from an aborted request): if nothing was sent yet, answer the uniform 502; log reason
  `internal-error` with the exception type name only (no message: it may hold a header value).

### Not in this brief (filed as issues)

Fair sharing of request slots, queue and unlock budget between sockets; per-route forwarded-header allow-list;
`broker.log` size and repeated-refusal aggregation; `socket_dir` mode exactly 0711, `--socket-dir` moving every
socket, two `serve`s on one vault, reload ignoring a changed `socket_dir`; two templates sharing a writable folder;
secret header values with C0 controls; first-request-only `Connection` capture; redaction of a secret split across two
headers; the `cwd` re-check.

## Global constraints

- Fail closed everywhere: any read, parse or platform problem on a `container` socket refuses; nothing falls back to
  uid-only.
- Kernel-attested facts only (`SO_PEERCRED`, `SO_PEERPIDFD`, `SO_PEERSEC`, `/proc` through the pidfd-pinned dirfd).
  Nothing the client sends influences its identity.
- Exact matching: ordinal string equality and the segment-wise "equal or under" rule of D3.6, nothing else.
- Reuse `PeerIdentity`'s seams (`OpenPeer`, `ReadStatusUid`, `PidfdAlive`, `ReadPeerLabel`); add `ReadCgroup` beside
  them in the same style. Don't duplicate the pidfd/dirfd code.
- NativeAOT: new config fields go through the existing source-generated JSON context; strict parsing (unknown
  fields, duplicate keys) stays.
- Tests that need Linux-only kernel features skip with a stated reason elsewhere; macOS and Windows CI must stay green.
- Never touch `~/.config/tswap`, never run `sudo tswap`. Never `rm` with wildcards; delete only files you created,
  by name.

## Review focus (inputs no task's happy path covers)

1. A Quadlet container: peer in `<unit>/libpod-payload-<id>`, bound to `<unit>` -> admitted; a sibling unit whose
   name has the bound one as a prefix (`lane1.service-x`, `lane10.service`) -> refused.
2. A client that connects and exits at once (and a pid reused in between) -> refused (`peer-exited` or a mismatch),
   never admitted.
3. A SIGHUP that rebinds a socket while a client holds an open HTTP keep-alive or ssh agent connection -> its next
   request/message is refused.
4. A v0.1-shaped `broker.json` (no `container`, no `uid_only`) -> `serve` refuses with the D1 message; a
   `broker.json` with `container` on macOS -> refused with the platform reason.
5. A host process with a listed uid (no container) on a `container` socket -> refused `cgroup-mismatch`.

## Lanes

Two lanes run in parallel from `brief/i224` (this brief's commit), each a Claude subagent in its own worktree:

| Lane | Worktree | Branch | Tasks | Files (only these lanes edit them) |
|---|---|---|---|---|
| A identity | ~/RiderProjects/tswap-wt/i224-a | i224/lane-a | 1-5 | `BrokerConfig*.cs`, `BrokerPolicy.cs`, `BrokerServer.cs`, `BrokerRequestHandler.cs`, `SshAgent/*`, `Agent/PeerIdentity.cs`, `BrokerNative.cs`, `BrokerLog.cs`, `TswapCli/Commands/BrokerCommand.cs`, `contrib/selinux/*`, BROKER.md outside "Command templates" |
| B hardening | ~/RiderProjects/tswap-wt/i224-b | i224/lane-b | 6-9 | `Templates/*`, BROKER.md "Command templates" section only |

H5's template-handler half lives in `Templates/BrokerTemplateCalls.cs` (lane B, task 9); the request-handler half is
lane A's (task 3). Both use the same reason word and the uniform 502.

## Task 1 (A): config fields, validation, start-time refusals

- `BrokerSocketConfig` gains `Container` (`BrokerContainerConfig { required string Cgroup; string? SelinuxLabel }`,
  JSON `container`/`cgroup`/`selinux_label`) and `bool? UidOnly` (JSON `uid_only`). `BrokerSocketPolicy` gains
  `BrokerContainerIdentity? Container` (null = uid-only).
- Validation per D1 (in `BrokerPolicy`'s socket validation, run on every load); uid-0 warning through the existing
  warnings path (find how short-secret warnings reach the log; reuse it).
- D2 start checks in `serve` (with seams for the platform/kernel/cgroup/SELinux probes so they're testable).
- D2 start log lines.
- **Existing tests and fixtures** that build sockets without either field must gain `uid_only: true` (this brief
  changes the rules; say so in the commit message). Don't change any assertion.
- Tests: each D1 validation rule (accepted and refused examples, including `/a/b.service/` trailing slash,
  `/a/../b.service`, `/a//b.service`, `/user.slice/user-1001.slice`, 1025 bytes, a space, both fields, neither,
  `uid_only: false`); uid-0 warning text; each D2 refusal via its seam; a v0.1 `broker.json` fixture refused with the
  exact D1 message.
- Break-it-once: drop the "last segment is a unit" rule; the `/user.slice/user-1001.slice` test must fail.

## Task 2 (A): reading and matching the peer's cgroup

- `PeerIdentity.ReadCgroup` seam (`Func<PeerProcess, string?>`, default reads `cgroup` through the dirfd) and a pure
  parser `ParseCgroupV2(string content) -> string?` implementing D3.3.
- A pure matcher `BrokerContainerMatch.Check(BrokerContainerIdentity bound, string? observedCgroup, string?
  observedLabel) -> string?` returning null or the D5 reason word (D3.6).
- `BrokerContainerMatch.Observe(Socket socket, uint credsUid) -> (ObservedIdentity? Identity, string? Reason)`
  implementing D3.1-5 with the seams.
- Tests (pure): parser accepts the observed Fedora line and a Quadlet-shaped line; refuses two lines, `1:name=systemd:`
  v1 lines, no trailing newline is fine or not (decide, document, test), relative path, `..`, empty segment.
  Matcher: equal, under, the prefix-sibling cases of review focus 1, label equal/different/missing.
- Tests (seams): pidfd missing -> `no-pidfd`; dirfd ENOENT with live pidfd -> `proc-hidden`; status uid differs ->
  refused; pidfd dead after reads -> `peer-exited` (review focus 2).
- Test (real, Linux only): a socketpair or a listening socket in the test process; `Observe` from the server side
  returns the test process's own `/proc/self/cgroup` path.
- Break-it-once: make the matcher use `StartsWith(bound)` without the `/`; the `lane1.service-x` test must fail.

## Task 3 (A): the gate, the re-checks, the log

- Wire D4 into `GateAsync`, the ssh listener accept path, `BrokerRequestHandler.HandleAsync` and
  `SshAgentListener.Refusal`; `BrokerPeer` carries the observed identity.
- D5 log fields and reasons (`BrokerLog`), including the once-per-serve `proc-hidden` event.
- H5's request-handler half (D7).
- Tests (end-to-end, Linux only, through a real `serve` the way existing `BrokerServer` tests run it):
  1. socket bound to the test process's own cgroup (`/proc/self/cgroup`, trimmed to D6's derivation, or the exact
     path) -> a request is forwarded;
  2. bound to another unit path -> the connection is closed with no response bytes; log has `cgroup-mismatch` and
     the observed path;
  3. `uid_only` socket -> behaves as before (one existing test re-run is enough);
  4. rebind by rewriting `broker.json` + reload while a keep-alive connection is open -> next request refused
     (review focus 3), and the same for an ssh agent connection's next message;
  5. H5: a forwarder seam that throws `InvalidOperationException` -> response is byte-identical to the uniform 502;
     log has `internal-error` and the type name, not the message.
- Break-it-once: remove the per-request re-check of the stored identity; test 4 must fail.

## Task 4 (A): `socket bind`, `socket add`, listing

- D6. The `--pid` derivation as a pure function with tests: the Fedora plain-Podman path above ->
  `.../libpod-<cid>.scope`; `/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service/libpod-payload-x`
  -> `.../app.slice/lane1.service`; `/system.slice/lane1.service/libpod-payload-x` -> `/system.slice/lane1.service`;
  `/user.slice/user-1001.slice/user@1001.service/init.scope`... decide whether `init.scope` (the user manager itself)
  must be refused (it should: it is not a container) and test it; a path with no unit -> refused with the path shown.
- CLI tests in the style of `BrokerCommandTests` (they use a fake ownership/sudo seam; follow them).
- Break-it-once: drop the `user@<digits>.service` skip; the Quadlet derivation test must fail.

## Task 5 (A): SELinux module and docs

- `contrib/selinux/tswap-broker.cil`: allow `tswap_broker_t` to search `container_t` process directories and read
  their `cgroup` and `status` files (`dir (search getattr)`, `file (read open getattr)` on `container_t`, plus
  `lnk_file read` only if `/proc/<pid>` needs it). Explain each rule in a comment. The owner verifies on the router;
  say in the report that CI can't.
- `docs/BROKER.md`:
  - "Limits of the identity check": rewrite for the new model; what the binding closes (another container of the same
    user, another user's container, host processes) and the residual risks, each one sentence: an admitted container
    can relay for others (credentials and identity are fixed at `connect()`), everything inside the admitted
    container (`podman exec`, sidecars, every process in its network namespace reaching `forward`'s port) is that
    container, the container owner can start a replacement with the same unit name, MCS labels can be copied by the
    same host user and change per start, root and the vault user are above the model, privileged containers and
    `--userns=host` are out of scope, Linux < 6.5 and non-Linux can't bind (`uid_only` only), `hidepid` needs `gid=`.
  - "Setup": a new step "Bind the socket to its container" with Quadlet as the main example (the unit path formula
    `/user.slice/user-<owner uid>.slice/user@<owner uid>.service/app.slice/<unit>.service` for a user Quadlet, and
    `socket bind --pid` for anything else), and `socket add` gaining the option.
  - "Platforms" and "Limits (v1)": the kernel and platform requirements.
- No test; show the rendered sections in the report.

## Task 6 (B): H1, protect the run folder

- `BrokerHostContext.ForVault` adds the run folder; the bind check per D7 H1.
- Tests: bind `~/.cache` (rw and ro) refused when the run folder is `~/.cache/tswap/run`, existing and not yet
  existing; bind `~/.cache/tswap/run` itself refused; bind `~/.cache/other` (sibling, not containing it) accepted;
  when the run folder is `/run/user/<uid>/tswap`, binding `/run/user/<uid>` refused.
- Break-it-once: drop the not-yet-existing case; its test must fail.

## Task 7 (B): H2, null host fails closed

- Test: a policy with `Host = null` and a template with a bind -> the call is refused with the "binds" refusal and
  the sandbox is never started. Break-it-once: restore the old condition; the test must fail.

## Task 8 (B): H3 and H4, template validation

- H3: refuse a program inside any of the template's binds (resolved paths, also when the bind is read-only).
- H4: the env names.
- Tests: H3 refused for `rw` and read-only binds, accepted for `/usr/bin/x` with a bind `/srv/x`; H4 each new name
  refused (a table test). Break-it-once: remove one name (`OPENSSL_CONF`); its row must fail.

## Task 9 (B): H5, template handler

- The template handler's half of H5 (D7), same reason word and uniform 502 as task 3.
- Test: a sandbox-runner seam that throws `InvalidOperationException` before any output -> uniform 502 bytes;
  log `internal-error`. Break-it-once: remove the catch; the test must fail.

## Lane rules

`~/RiderProjects/tswap-wt/tools/t17-lane-rules.md`'s "Rules" and "Report" sections apply unchanged (suite lock for
every test run, run_in_background for long runs, no `pgrep` self-matching loops, explicit-path commits ending with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and nothing about sessions, no push/merge/rebase, stop and
report when the brief can't be built as written). Reports: `~/RiderProjects/tswap-wt/tools/i224-impl-report-<a|b>.md`.
