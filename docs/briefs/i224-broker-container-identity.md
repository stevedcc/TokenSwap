# Brief I224: the broker knows which container is calling (v0.2.0)

Issue: https://github.com/stevedcc/TokenSwap/issues/224. Base: `origin/main` at 2dbec89 (T17 merged).
Read AGENTS.md and CLAUDE.md first, then `docs/BROKER.md` ("Threat model", "Limits of the identity check",
"SELinux", "Setup", "The bind rule") and `TswapCore/Agent/PeerIdentity.cs` (T17's pidfd method, which this brief
extends). One commit per task, TDD, break-it-once per key test, full `./runtests.sh` once per lane at the end.

Review history: brief round 1 by GLM and MiMo (2026-11-03, `~/RiderProjects/tswap-wt/tools/i224-brief-{glm,mimo}.md`),
both "request changes"; round 2 (`i224-brief-r2-{glm,mimo}.md`), both "request changes" on a few points; this version
folds in every finding. "(MiMo B3)" points to round 1, "(r2 GLM N1)" / "(r2 MiMo F3)" to round 2.

## Why

A broker socket admits a client by two facts today: which socket file it reached and the uid `SO_PEERCRED` reports.
Two rootless containers of one host user share that user's subuid block, so they present the same host uids; the
documented `--uids 100000-165535` admits every container of that user. A container that gets hold of another
container's socket file (the folder mounted instead of the file, a shared volume, a copy) gets all of that socket's
routes, ssh keys and templates. All four adversarial reviews (GLM and MiMo, parts A and B, 2026-11-03, in
`~/RiderProjects/tswap-wt/tools/i224-review-*.md`) rank this blocking.

The fix: each socket names the container it serves, and the broker checks the kernel's record of "which cgroup is
this process in" on every connection. The owner decided (2026-11-03) that the binding is **required**: a socket
must either name its container or say explicitly that it is uid-only.

What it protects against, honestly: a container (a process running as a mapped subuid, with cgroupfs read-only, the
rootless Podman default) can't change its cgroup, so it can't pass as another container. The **host user who runs
the containers** can: systemd delegates the `user@<uid>.service` subtree to them, so they can move any of their
processes (even one thread, via `cgroup.threads`) into the bound cgroup. The uid is unforgeable; the cgroup is
kernel-recorded but writable by the delegatee (MiMo I1, GLM I5). The docs say so (task 5).

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
  `/`; printable ASCII only (0x21-0x7E); at most 1024 bytes; and the last segment passes **one shared predicate**
  `BrokerContainerUnit.Refusal(string lastSegment) -> string?` (null = not a reserved unit), used by this validation
  and by `socket bind --pid` alike (GLM B1, MiMo B1). It is a deny-list of units known not to be containers, not a
  proof that a unit is one. It refuses, each with its own reason:
  - a last segment not ending in `.service` or `.scope` (`/user.slice/user-1001.slice` would be every process of a
    user): `not a systemd unit`;
  - `user@<digits>.service`: `the user manager: every process of that user`;
  - `init.scope`, `manager.scope`: `the user manager itself`;
  - `session-<anything>.scope` (logind uses `session-3.scope` and `session-c2.scope`; both exist on the dev
    machine): `a login session` (r2 MiMo F1);
  - `-.scope`: `the root scope`.
  Message shape: `socket <name>: container.cgroup <path> is not a container (<reason>)`.
- `container.selinux_label` (optional): an exact, whole SELinux label (`user:role:type:level`). Corroboration only:
  any container of the same host user can ask Podman for another container's MCS level (GLM review A, I2), and the
  level changes on every container start unless the unit pins it (`SecurityLabelLevel=` in Quadlet). Validation
  is at least as strict as what `PeerIdentity.SelinuxLabel` accepts from the kernel, and stricter on purpose (a
  container's label carries a level) (MiMo I9, r2 GLM N3, r2 MiMo F8): four or more `:`-separated parts, each
  non-empty, printable ASCII without whitespace, at most 256 bytes.
- `uid_only: true`: today's behaviour, chosen on purpose. `uid_only: false` is refused (say `true` or leave it out).
- Neither field: `socket <name> names no container: run "sudo tswap broker socket bind <name> --pid <pid>" or "sudo
  tswap broker socket bind <name> --uid-only"`. Both: `socket <name> has both "container" and "uid_only": remove one`.
- The neither-field rule must not lock the operator out of the fix (r2 GLM N1): `socket bind`, `socket add` and any other socket command that mutates the file (r3 MiMo R4) load
  `broker.json` with that one rule suspended, apply their change, and validate the result with every other rule
  before writing. If sockets with neither field remain, they still write and then print
  `still to bind before serve starts: <names>`. `serve` and every other load apply the rule.
- `broker.json` stays `version: 1`: field presence tells v0.1 and v0.2 configs apart and both directions refuse
  loudly (a v0.1 tswap refuses the new fields as unknown; v0.2 refuses a socket with neither). Don't bump it.
- `uids` stays and is still required: the uid check and the cgroup check must **both** pass. The own-uid refusal
  stays exactly as it is.
- A `uids` entry that includes 0 is accepted with a warning (owner rule: warn, don't refuse):
  `socket <name> admits uid 0: every root process and rootful container on this host has it`. Delivery (MiMo I8):
  `BrokerPolicy` gains `IReadOnlyList<string> Warnings`, filled by socket validation; `serve` logs them at start
  (next to D2's lines) and after a successful reload. `BrokerShortSecretWarnings` is not touched.

### D2. Where `serve` refuses to start

`serve` refuses a config (at start; on SIGHUP the old config is kept and the reason logged, as today) when:
- a socket has `container` and the platform is not Linux;
- a socket has `container` and the kernel gives no `SO_PEERPIDFD`: probe once at start on a **`socketpair()`**
  (a listening socket has no peer and always fails, MiMo B3). The flag was added in Linux **6.5**. The round-1
  reviews disagreed (GLM 6.5, MiMo 6.3); the controller checked the kernel list: the series was still "PATCH net-next
  v7 0/4 Add SCM_PIDFD and SO_PEERPIDFD" in June 2023, after 6.3's release (April 2023), so it merged for 6.5. The
  probe, not the number, decides;
- a socket has `container` and `/proc/self/cgroup` is not exactly one `0::/...` line (cgroup v1 or hybrid), or its
  path contains a `..` segment. That is the whole start check (r2 MiMo F9): a `serve` in a nested cgroup namespace
  is not detected at start but fails closed anyway (peers outside its namespace root show `..` and are refused as
  `identity-unreadable`), and BROKER.md says `serve` must run in the host's root cgroup namespace;
- a socket has `container.selinux_label` and SELinux is not enabled (no `/sys/fs/selinux/enforce`).

Each refusal names the socket and the reason. `uid_only` sockets start everywhere `serve` starts today.
At start `serve` logs one line per socket: `socket <name>: container <cgroup>[ label <label>]` or
`socket <name>: uid-only (any process with a listed uid is admitted)`.

### D3. Reading the peer's identity

On every accepted connection to a socket with `container`, after the existing own-uid and uid checks pass, in this
order (T17's method, extended):

1. `SO_PEERPIDFD` -> pidfd. `PeerIdentity.DefaultOpenPeer` falls back to the dirfd alone when the kernel gives no
   pidfd; for a `container` socket that is **not** a pass: no pidfd -> refuse `no-pidfd` (MiMo B3). The agent and
   control sockets keep their fallback unchanged.
2. `/proc/<pid>` as a directory fd. Failure with ENOENT or EACCES while the pidfd is alive -> the broker can't see
   the peer (`hidepid`) -> `proc-hidden`; with the pidfd dead -> `peer-exited` (MiMo M2);
   any other failure -> `identity-unreadable` (r3). Today `OpenPeer` returns
   `PeerProcess?` and disposes the pidfd when the dirfd open fails, so a caller can't tell these apart (r2 MiMo F3).
   Add a richer opener beside it: `PeerIdentity.OpenPeerDetailed` (seam `Func<Socket, PeerOpenResult>`), where
   `PeerOpenResult` carries the `PeerProcess?` on success, or on failure whether a pidfd was obtained, whether it was
   alive when the dirfd open failed, and the errno. `OpenPeer` keeps its signature and behaviour (build it on the new
   one or leave it); `PeerIdentity.Check`'s refusal words and their tests must not change. Log
   `proc-hidden` once per serve also as an event: `can't see client processes in /proc (hidepid?): mount /proc with
   gid=<group> and add the vault user to it`.
3. Through the dirfd: `status` (effective uid must equal `SO_PEERCRED`'s, as T17 does) and `cgroup`, read as bytes
   (MiMo M4) and decoded as UTF-8 with replacement characters (r2 MiMo F5: a bound path is 0x21-0x7E only and a
   replacement character can't produce ASCII, so decoding can't create a false match). Parse: exactly one line `0::<path>`, with or without the trailing `\n` (the kernel always writes one;
   accept both); `<path>` must start with `/` and contain no empty, `.` or `..` segment (a `..` means the peer is
   outside the broker's cgroup-namespace root). Anything else -> `identity-unreadable`. A path with bytes outside
   0x21-0x7E is kept (it can't equal a validated bound path, so it ends as `cgroup-mismatch`).
4. `SO_PEERSEC` from the socket (`PeerIdentity.DefaultReadPeerLabel`), only when `selinux_label` is configured.
   Missing or not an SELinux label -> `identity-unreadable`. Never `/proc/<pid>/attr/current`.
5. `pidfd_send_signal(pidfd, 0)` **after** the reads. Dead -> `peer-exited`. (A zombie still passes; that is the
   same class as the documented fd-relay residual.)
   Any exception anywhere in steps 1-5 -> `identity-unreadable`, never propagated into the gate.
6. Compare, byte-exact (ordinal): the peer's path equals `container.cgroup` **or** starts with
   `container.cgroup + "/"` (Quadlet puts the payload in `<unit>/libpod-payload-<id>`; plain Podman in
   `libpod-<id>.scope/container`). Never `Contains`, never a bare prefix (`lane1.service` must not admit
   `lane1.service-x`). Mismatch -> `cgroup-mismatch`. Label configured and not equal -> `label-mismatch`.

`Observe` returns an explicit result (`bool Allowed`, `string? Reason`, the observed facts), not a nullable string
whose null means "allowed" (MiMo M5).

Do not read `/proc/<pid>/ns/user` for client sockets: `readlink` of a namespace link of another uid's process is
ptrace-gated and would refuse every container (GLM review A).

Observed on this dev machine (Fedora 44, kernel 7.2, rootless Podman, uid 1000): `/proc/<pid>/cgroup` of a container
process is mode 0444 and readable by the container's owner;
`0::/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_<id>.slice/libpod-<cid>.scope/container`;
label `system_u:system_r:container_t:s0:c168,c863`. Whether `tswap_broker_t` may do steps 2, 3 and 5 on a
`container_t` process is not known: task 5 adds the CIL rules and the owner checks on the router.

### D4. When it is checked

- One gate function, used by both listeners (MiMo I10): `BrokerServer.GateAsync` (HTTP socket) and the ssh agent
  listener's accept path both call it, before any byte is parsed. It reads `Policy.Current` **once** and uses that
  snapshot for the own-uid, uid and container checks (GLM M9). It returns the refusal reason or the observed
  identity; the observed facts (cgroup path, label or null) are stored on the connection (`BrokerPeer` gains them).
- Again per request (`BrokerRequestHandler.HandleAsync`, where `AllowsUid` is re-checked today) and per ssh message
  (`SshAgentListener.Refusal`, which now takes the `BrokerPeer`): the **stored** facts against the **current**
  policy, never a fresh `/proc` read. One shared function does this comparison for both.
- A SIGHUP that rebinds a socket refuses the next request/message of an already-open connection. Unbinding
  (`container` replaced by `uid_only`) takes effect the same way: stored facts are then ignored. Binding a socket
  that was `uid_only` refuses the next request/message of a connection accepted before (it has no stored facts):
  reason `identity-unreadable` (r3 MiMo R1); task 3 test 5 gets that row too.
- `<name>.sock` and `<name>.ssh.sock` use the same binding (the config binds the container, not the file).
- The control socket and the agent socket are untouched.

### D5. How it refuses and logs

Exactly like `uid-not-allowed` today: closed unanswered at accept; the per-request re-check refuses the way the
existing uid re-check does. No new bytes reach the client, so a client can't tell which check failed. Identity
refusals never count toward any unlock guard or rate. Log line: the existing `refused-connection` line plus
`cgroup=<observed>` and, when read, `label=<observed>`, each through `BrokerLog.Escape` **then** capped at 256
characters (the observed name is attacker-influenced, MiMo M3); reason words exactly: `no-pidfd`, `proc-hidden`,
`identity-unreadable`, `peer-exited`, `cgroup-mismatch`, `label-mismatch`. Successful connections log nothing new.

### D6. Commands

- `sudo tswap broker socket bind <name> (--pid <pid> | --cgroup <path> | --uid-only) [--with-label]`:
  - `--pid`: reads `/proc/<pid>/cgroup` and derives the unit path: the path up to and including the **first**
    segment ending in `.service` or `.scope` that is not `user@<digits>.service`. Refuse, printing the path it read,
    when none is found, when the path contains `..` (MiMo M1), or when the result fails D1's shared predicate.
    Prints `socket <name> bound to <path>`. When the result's last segment starts with `libpod-` or the path contains
    `user-libpod_` (plain `podman run`), also prints: `warning: this binds one container instance; it changes when the
    container is recreated (re-run socket bind then). A Quadlet unit gives a stable name.` (GLM I1, MiMo I9)
  - `--cgroup`: takes the path as given (D1 validation).
  - `--with-label` (only with `--pid`): also records `/proc/<pid>/attr/current` (trailing NUL/newline stripped);
    prints that the label changes on each container start unless the unit pins `SecurityLabelLevel=`, and that the
    broker compares it with `SO_PEERSEC`, which reports the same label for a container's sockets (MiMo M8).
  - `--uid-only`: removes `container`, sets `uid_only: true`.
  - Writes `broker.json` with the existing socket-command write path (atomic temp file + rename, 0600, temp and final
    file owned by the folder's owner, config lock, nothing root-owned left on failure). Ends with the existing
    "reload the broker" hint.
- `broker socket add` takes the same options and requires exactly one of `--pid`, `--cgroup`, `--uid-only`. This is a
  breaking CLI change; task 5 puts it in BROKER.md "Setup" and the release notes list.
- On macOS/Windows, `--pid`, `--cgroup` and `--with-label` refuse (`binding a socket to a container needs Linux; use
  --uid-only`); `--uid-only` works.
- Wherever sockets are listed (`broker socket list` if it exists, `broker status` otherwise; check), show the binding
  or `uid-only`.

### D7. Also fixed in v0.2.0 (found by the same reviews, independent of identity)

- H1 (MiMo B, S-2): the vault user's run folder holds `control.sock`; when the user has no `/run/user/<uid>` it is
  `~/.cache/tswap/run`, which the template bind rule doesn't protect. A template with
  `binds: [{"path": "/home/vault/.cache", "rw": true}]` could delete the control socket or connect to it (it admits
  the vault uid, which a bwrap child has). Protect **both** candidate run folders (`/run/user/<uid>/tswap` and
  `~/.cache/tswap/run`; which one is used can change between load and serve): a bind may not be one, contain one or
  be inside one, **whether or not the folder exists yet** (compare paths after resolving the nearest existing
  ancestor, as well as `st_dev:st_ino` when it exists). Message names both risks: `bind <path> contains the broker's
  run folder <folder> (a template could delete or use the control socket)`. Only the `~/.cache/tswap/run` candidate
  is new work: `/run/user/<uid>/tswap` is already covered by the `/run` forbidden root (r2 MiMo F10). `Folder` with
  the machine's inputs returns the `/run` path whenever that folder exists, so it can't name the home candidate:
  build it as `Folder` does (`<home of vault uid>/.cache/tswap/run`; templates are Linux-only) or call `Folder` with
  synthetic `Inputs` whose run-user folder is absent. Don't edit `AgentSocketPath.cs`.
- H2 (both B reviews): `BrokerTemplateCalls` skips `RecheckBinds` when `policy.Host` is null. Fail closed: a null
  `Host` refuses **every** template call, with or without binds (r2 MiMo F6), with the existing "binds" refusal.
  `Validate` sets `Host` whenever templates exist, so this is hardening (GLM M7, MiMo I4); the test builds such a
  policy through an `internal` test-only factory. MiMo I4's type-level alternative (non-null `Host` by type) is
  deliberately not done: `BrokerPolicy`'s constructor is private and `Validate` is its only producer.
- H3 (GLM B, PB-4; GLM I2; MiMo I5): refuse at validation a template program that, **resolved** (symlinks followed;
  unresolvable -> refused), is at or under any of that template's binds (resolved and configured paths, `rw` or
  read-only: a read-only bind is still a folder a container may be able to write through another mount). Message:
  `template <name>: program <path> is inside bind <bind>; a program may no longer live in a bind: install it under
  /usr or ship it in the image`. The same for `bwrap_path` at or under **any** template's bind (worse: a replaced
  bwrap runs outside the sandbox): `bwrap_path <path> is inside template <name>'s bind <bind>`, checked on the
  **effective** path (after defaulting to `/usr/bin/bwrap`). For `bwrap_path` only, an unresolvable path is not a
  load error (today a missing bwrap refuses template calls with a logged reason and `serve` starts; keep that,
  r2 MiMo F7): compare the configured path and its nearest existing ancestor instead. When the bind covers a system
  root (`/usr`, `/opt`), the message adds `bind <bind> covers system programs; bind a narrower folder`. Today a program
  outside `/usr /bin /sbin /lib /lib64` must be inside a bind; after H3 such a program is invalid outright. Both are
  v0.2 breaking changes; BROKER.md's "Command templates" section says so.
- H4 (MiMo B, S-5; MiMo I6): the template env-name denylist (`CodeEnvNames`/`CodeEnvPrefixes` in
  `BrokerTemplatePolicy.cs`) grows. New prefixes: `PYTHON`, `PERL`, `RUBY`, `GEM_`, `NODE_`, `DOTNET_`, `JAVA`,
  `_JAVA_`, `JDK_JAVA_`, `OPENSSL_`, `LUA_`, `XDG_`, `SSL_`, `CURL_`. New names: `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
  `REQUESTS_CA_BUNDLE`, `NETRC`, `HOSTALIASES`, `LOCALDOMAIN`, `RES_OPTIONS`, `TMPDIR`, `HOME` (the sandbox doesn't
  set it, so a template's `HOME` would redirect `~/.gitconfig`, `~/.netrc`, `~/.curlrc`), `CLASSPATH`, `SSLKEYLOGFILE`,
  `INPUTRC`, `TERMINFO`, `TERMINFO_DIRS`, `MAVEN_OPTS`, `GRADLE_OPTS`. The prefixes knowingly also refuse harmless
  names (`JAVA_HOME`, `NODE_ENV`, `PYTHONUNBUFFERED`, `DOTNET_CLI_TELEMETRY_OPTOUT`); the doc comment and BROKER.md
  say so. Drop names a new prefix now covers.
- H5 (MiMo B, S-4; GLM M4; MiMo I11): an exception escaping `BrokerRequestHandler.HandleAsync` or the template
  handler becomes Kestrel's 500, which differs from the uniform refusals. Catch at the top of both handlers. Not
  caught: `OperationCanceledException` from an aborted request; `OutOfMemoryException` and the other exceptions the
  files' existing catch filters rethrow (follow them). If the response has not started: the existing
  `WriteUniformAsync` 502 (no second 502 shape); if it has: abort the connection (as `WriteUniformAsync` does when
  `HasStarted`). Log exactly once (the inner template catch and the outer request catch must not both log): reason
  `internal-error`, then `type=<exception type name>`, no message (it may hold a header value). Request path logs
  through `log.Request`, template path through `log.Template`.

### Not in this brief (filed as #226, #227, #228, #229, #230)

Fair sharing of request slots, queue and unlock budget between sockets; per-route forwarded-header allow-list;
`broker.log` size and repeated-refusal aggregation; `socket_dir` mode exactly 0711, `--socket-dir` moving every
socket, two `serve`s on one vault, reload ignoring a changed `socket_dir`; two templates sharing a writable folder;
secret header values with C0 controls; first-request-only `Connection` capture; redaction of a secret split across two
headers; the `cwd` re-check.

## Global constraints

- Fail closed everywhere: any read, parse or platform problem on a `container` socket refuses; nothing falls back to
  uid-only.
- Kernel facts only (`SO_PEERCRED`, `SO_PEERPIDFD`, `SO_PEERSEC`, `/proc` through the pidfd-pinned dirfd). Nothing
  the client sends influences its identity.
- Exact matching: ordinal equality and the "equal or under" rule of D3.6, nothing else.
- Reuse `PeerIdentity`'s seams (`OpenPeer`, `ReadStatusUid`, `PidfdAlive`, `ReadPeerLabel`); add `ReadCgroup` beside
  them in the same style. Don't duplicate the pidfd/dirfd code.
- NativeAOT: new config fields go through the existing source-generated JSON context; strict parsing (unknown
  fields, duplicate keys) stays.
- Linux-only tests key off `OperatingSystem.IsLinux()` and **fail** (not skip) on a Linux kernel without
  `SO_PEERPIDFD` (MiMo, tests): CI's ubuntu-latest runner runs them. macOS and Windows CI must stay green.
- End-to-end identity tests need a client in a cgroup that passes D1 (r2 GLM N2, MiMo F4): the test process itself
  may sit in a `session-*.scope` (an ssh login) or an unbindable CI path. The client side of those tests runs as a
  child started with `systemd-run --user --scope --unit=tswap-test-<random> <client>` (checked on the dev machine:
  the child sits in `.../user@1000.service/app.slice/tswap-test-<x>.scope`), and the socket is bound to that scope.
  When `systemd-run --user` is unavailable (no user manager, as on some CI runners), fall back to the test process's
  own cgroup if it passes D1; if neither works, skip with the exact reason. Report which path CI and the dev machine
  took. The pure and seam tests never depend on this.
- Never touch `~/.config/tswap`, never run `sudo tswap`. Never `rm` with wildcards; delete only files you created,
  by name.

## Review focus (inputs no task's happy path covers)

1. A Quadlet container: peer in `<unit>/libpod-payload-<id>`, bound to `<unit>` -> admitted; a sibling unit whose
   name has the bound one as a prefix (`lane1.service-x`, `lane10.service`) -> refused.
2. A client that connects and exits at once (and a pid reused in between) -> refused (`peer-exited` or a mismatch),
   never admitted.
3. A SIGHUP that rebinds a socket after a client connected but before its request (HTTP), or between two messages
   (ssh agent) -> refused.
4. A v0.1-shaped `broker.json` (no `container`, no `uid_only`) -> `serve` refuses with the D1 message; a
   `broker.json` with `container` on macOS -> refused with the platform reason.
5. A host process with a listed uid (no container) on a `container` socket -> refused `cgroup-mismatch`.

## Lanes

Two lanes, each a Claude subagent in its own worktree:

| Lane | Worktree | Branch | Tasks | Files only this lane edits |
|---|---|---|---|---|
| A identity | ~/RiderProjects/tswap-wt/i224-a | i224/lane-a | 1-5 | `BrokerConfig*.cs`, `BrokerPolicy.cs`, `BrokerServer.cs`, `BrokerRequestHandler.cs`, `BrokerLog.cs`, `BrokerNative.cs`, `SshAgent/*`, `Agent/PeerIdentity.cs`, new `BrokerContainer*.cs`, `TswapCli/Commands/BrokerCommand.cs`, `contrib/selinux/*`, BROKER.md outside "Command templates"; tests of those files; every existing test fixture or test that builds a socket (task 1's `uid_only` sweep) |
| B hardening | ~/RiderProjects/tswap-wt/i224-b | i224/lane-b | 6-9 | `Templates/*`, BROKER.md "Command templates" section; tests of those files (new test files, or test classes that only cover templates) |

**Order:** lane A does task 1 first and commits it; lane B starts from that commit (the `uid_only` sweep touches
fixtures lane B's tests use). Lane A then continues with tasks 2-5.

**Exceptions to the split** (lane B, each the smallest possible hunk): task 8 changes the one call in
`BrokerPolicy.Validate` that hands the template validator its inputs, to pass `bwrap_path` too; task 7 adds an
`internal` test-only factory to `BrokerPolicy.cs` that builds a policy with `Host = null`. Lane B reads
`Agent/AgentSocketPath.cs` but doesn't edit it. BROKER.md: keep every hunk inside your lane's sections, in a commit
of its own at the end of the lane.

H5's two halves: request handler in task 3 (A), template handler in task 9 (B); both call `WriteUniformAsync`.

## Task 1 (A): config fields, validation, warnings, start-time refusals

- `BrokerSocketConfig` gains `Container` (`BrokerContainerConfig { required string Cgroup; string? SelinuxLabel }`,
  JSON `container`/`cgroup`/`selinux_label`) and `bool? UidOnly` (JSON `uid_only`). `BrokerSocketPolicy` gains
  `BrokerContainerIdentity? Container` (null = uid-only).
- `BrokerContainerUnit.Refusal` (D1's shared predicate) and the D1 validation, run on every load.
- `BrokerPolicy.Warnings` and the uid-0 warning (D1); `serve` logs warnings at start and after a successful reload.
- D2 start checks in `serve`, each behind a seam (platform, `socketpair` pidfd probe, own cgroup, SELinux).
- D2 start log lines.
- **Existing tests and fixtures** that build sockets without either field gain `uid_only: true` (this brief changes
  the rules; say so in the commit message). Don't change any assertion.
- Tests: the predicate on each refused unit and on `lane1.service`, `libpod-abc.scope` accepted; each D1 rule
  (accepted and refused: `.../user@1001.service`, `.../user@1001.service/init.scope`,
  `/user.slice/user-1001.slice/session-3.scope`, `.../session-c2.scope`, `/user.slice/user-1001.slice`, `/a/b.service/`, `/a/../b.service`,
  `/a//b.service`, 1025 bytes, a space, both fields, neither, `uid_only: false`, labels `a::b:c`, `a:b:c` and with a space
  refused) with their exact messages; uid-0 warning text and that `serve` logs it; each D2 refusal via its seam;
  the real `socketpair` probe succeeds on Linux CI; a v0.1 `broker.json` fixture refused with the exact D1 message.
- Break-it-once: remove `user@<digits>.service` from the predicate; the `.../user@1001.service` test must fail. Then
  narrow `session-*` back to digits only; the `session-c2.scope` test must fail.

## Task 2 (A): reading and matching the peer's cgroup

- `PeerIdentity.ReadCgroup` seam (`Func<PeerProcess, byte[]?>`, default reads `cgroup` through the dirfd) and a pure
  parser `ParseCgroupV2(ReadOnlySpan<byte> content) -> string?` (D3.3).
- A pure matcher `BrokerContainerMatch.Check(BrokerContainerIdentity bound, string observedCgroup, string?
  observedLabel)` returning an explicit allowed/reason result (D3.6).
- `BrokerContainerMatch.Observe(Socket socket, uint credsUid)` implementing D3.1-5 with the seams, returning
  `bool Allowed`, `string? Reason` and the observed facts; exception-safe.
- Tests (pure): parser accepts the observed Fedora line and a Quadlet-shaped line, with and without the trailing
  newline; refuses two lines, a `1:name=systemd:` v1 line, a relative path, `..`, an empty segment; a path with a
  space parses and then mismatches. Matcher: equal, under, the prefix-sibling cases of review focus 1, label
  equal/different/missing.
- `PeerIdentity.OpenPeerDetailed` and `PeerOpenResult` (D3.2); T17's `PeerIdentity` tests pass unchanged.
- Tests (seams): no pidfd -> `no-pidfd` (the fallback is not a pass); dirfd ENOENT and EACCES with live
  pidfd -> `proc-hidden`; dirfd ENOENT with dead pidfd -> `peer-exited`; status uid differs -> refused; pidfd dead
  after reads -> `peer-exited` (review focus 2); a seam that throws -> `identity-unreadable`.
- Test (real, Linux): a `socketpair` in the test process; `Observe` on one end returns the test process's own
  `/proc/self/cgroup` path and `Allowed` when bound to it.
- Break-it-once: make the matcher use `StartsWith(bound)` without the `/`; the `lane1.service-x` test must fail.

## Task 3 (A): the gate, the re-checks, the log

- The shared gate and the shared re-check (D4), wired into `GateAsync`, the ssh listener accept path,
  `BrokerRequestHandler.HandleAsync` and `SshAgentListener.Refusal`; `BrokerPeer` carries the observed identity.
- D5 log fields and reasons (`BrokerLog`), including the once-per-serve `proc-hidden` event.
- H5's request-handler half (D7).
- Tests (end-to-end, Linux, through a real `serve` the way existing `BrokerServer` tests run it):
  1. socket bound to the client's cgroup (Global constraints: a transient scope, or the fallback) -> a request is
     forwarded;
  2. bound to another unit path -> the connection is closed with no response bytes; log has `cgroup-mismatch` and
     the observed path;
  2b. review focus 5, named so: the socket is bound to a transient scope and the client is the test process itself
     (a host process with a listed uid, outside that scope) -> refused `cgroup-mismatch`;
  3. the ssh agent socket of a mismatching socket -> closed before the first frame, log `cgroup-mismatch` (MiMo I7);
  4. `uid_only` socket -> behaves as before (one existing test re-run is enough);
  5. rebind (rewrite `broker.json`, reload) after an HTTP connection is accepted and before its request is sent ->
     the request gets zero response bytes; the same between two messages of one ssh agent connection; an unbind
     (`container` -> `uid_only`) between two ssh messages -> the second is answered. (Every HTTP response carries
     `Connection: close`, so there is no second HTTP request to test, MiMo I7.)
  6. H5: a forwarder seam that throws `InvalidOperationException` -> response byte-identical to the uniform 502;
     one log line with `internal-error` and `type=InvalidOperationException`, not the message.
  7. if the runner can create a child cgroup under its own (cgroup delegation), a process in it is admitted on a
     socket bound to the parent; otherwise skip with that reason.
- Break-it-once: remove the per-message re-check of the stored identity; test 5's ssh rebind case must fail.

## Task 4 (A): `socket bind`, `socket add`, listing

- D6. The `--pid` derivation as a pure function with tests: the Fedora plain-Podman path above ->
  `.../libpod-<cid>.scope` plus the per-instance warning;
  `/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service/libpod-payload-x` ->
  `.../app.slice/lane1.service`, no warning; `/system.slice/lane1.service/libpod-payload-x` ->
  `/system.slice/lane1.service`; `/user.slice/user-1001.slice/user@1001.service/init.scope` -> refused (the user
  manager); a path with no unit -> refused with the path shown; a path with `..` -> refused.
- CLI tests in the style of `BrokerCommandTests` (they use a fake ownership/sudo seam; follow them): bind with each
  option writes the expected `broker.json`; bind with each option on a **v0.1 fixture** (sockets with neither field)
  succeeds and leaves a config that loads once every socket is bound (r2 GLM N1); with two v0.1 sockets, binding one
  writes the file and the message names the other socket still to bind; `socket add` without one of the three options refused; platform refusals
  via the existing platform seam; the written file and its temp file are 0600 and owned as the existing socket
  commands' are.
- Break-it-once: drop the `user@<digits>.service` skip in the derivation; the Quadlet derivation test must fail.

## Task 5 (A): SELinux module and docs

- `contrib/selinux/tswap-broker.cil` (MiMo B2, GLM I3), each rule with a comment naming the step it serves:
  - `allow tswap_broker_t container_t (process (signull))`: D3.5, `pidfd_send_signal(pidfd, 0)` is checked as
    `signull`; without it every container is refused as `peer-exited`.
  - `allow tswap_broker_t container_t (dir (open read search getattr))`: D3.2, opening `/proc/<pid>` as a dirfd.
  - `allow tswap_broker_t container_t (file (open read getattr))`: D3.3, `status` and `cgroup`.
  - A comment that `/proc/<pid>/` entries carry the task's own label, so `container_t` (not `proc_t`) is the right
    target, and that no `lnk_file` rule is needed (D3 never reads `ns/*`).
  - A comment naming the second thing the router check must look for: the broker runs at `s0` and containers at
    `s0:cX,cY`, so an MCS constraint may deny these reads; if it does, the fix is an MCS exemption attribute for
    `tswap_broker_t` (name the candidate after checking what the Fedora policy defines, e.g. by searching the
    installed policy's CIL if readable without root; otherwise say you couldn't).
  - The owner verifies on the router; say in the report that CI can't.
- `PeerIdentity.cs`: its comments say `SO_PEERPIDFD` is Linux >= 6.3; it is 6.5 (D2 has the evidence). Fix the
  number and add that the code's behaviour depends on the probe or the error, not the number.
- `docs/BROKER.md` (outside "Command templates"):
  - "Limits of the identity check": rewrite for the new model. What the binding closes: another container of the
    same user, another user's container, host processes. Residual risks, one sentence each: an admitted container can
    relay for others (credentials and identity are fixed at `connect()`); everything inside the admitted container
    (`podman exec`, sidecars, every process in its network namespace reaching `forward`'s port) is that container;
    the binding separates containers from each other but **not from their owner**: the uid is unforgeable but the
    cgroup is writable by the delegatee, so the host user who runs the containers can move any of their processes
    (even one thread) into the bound cgroup or start a replacement with the same unit name; binding a pod unit
    admits every container in the pod; MCS labels can be copied by the same host user and change per start; root and
    the vault user are above the model; `--privileged`, `--userns=host`, `--userns=keep-id` and `--cgroupns=host`
    with a writable cgroupfs are out of scope; non-Linux and kernels without `SO_PEERPIDFD` can't bind
    (`uid_only` only); `hidepid` needs `gid=`; `serve` must run in the host's root cgroup namespace.
  - "Setup": a new step "Bind the socket to its container" with Quadlet as the main example (the unit path formula
    `/user.slice/user-<owner uid>.slice/user@<owner uid>.service/app.slice/<unit>.service` for a user Quadlet, and
    `socket bind --pid` for anything else, with the sentence: a plain `podman run` container's binding changes when
    the container is recreated; re-run `socket bind` then); `socket add` now requires one of the three options.
  - "Platforms" and "Limits (v1)": the kernel and platform requirements.
  - A "Changes in v0.2.0" list (or the existing equivalent; check the README/CHANGELOG convention) naming the
    breaking changes: required binding, `socket add`'s new required option, H3's program/bwrap rule, H4's prefixes.
- No test; show the rendered sections in the report.

## Task 6 (B): H1, protect the run folders

- `BrokerHostContext.ForVault` adds both candidate run folders; the bind check per D7 H1.
- Tests: bind `~/.cache` (rw and ro) refused when the run folder is `~/.cache/tswap/run`, existing and not yet
  existing; bind `~/.cache/tswap/run` itself refused; a bind inside it (`~/.cache/tswap/run/x`) refused; bind
  `~/.cache/other` accepted; a run folder whose nearest existing ancestor is a symlink -> the resolved comparison
  still refuses; the message names both risks. (`/run/user/<uid>` is already refused by the `/run` forbidden root,
  so that case is not a test of this task.)
- Break-it-once: drop the not-yet-existing case; its test must fail.

## Task 7 (B): H2, null host fails closed

- The runtime refusal in `BrokerTemplateCalls`, and the `internal` test-only factory in `BrokerPolicy.cs` (the
  allowed exception). Say in the report whether any production path can produce a null `Host` with templates.
- Tests: a policy with `Host = null`, a template with a bind and one without -> both calls refused with the "binds"
  refusal and the sandbox never started. Break-it-once: restore the old condition; the test must fail.

## Task 8 (B): H3 and H4, template validation

- H3 and the one-call change in `BrokerPolicy.Validate` for `bwrap_path`.
- Existing template fixtures whose program sits inside a bind (the only way a non-system program was valid before)
  point it at a program under `/usr` (and drop the bind if it was there only for the program) (r2 GLM N4,
  r3 MiMo R3): a test-input change the brief requires; say so in the
  commit message. No assertion changes.
- H4.
- Tests: H3 refused for `rw` and read-only binds; a program reached through a symlink that resolves into a bind
  refused; an unresolvable program refused; `/usr/bin/x` with a bind `/srv/x` accepted; `bwrap_path` inside a
  template's bind refused, outside accepted, missing-but-outside still loads; a bind `/opt` with a program in it
  gets the "narrower folder" clause. H4: a table test with every new name and one name per new prefix
  refused, and `LANG`/`TZ`/`PGPASSWORD` still accepted.
- Break-it-once: remove `OPENSSL_` from the prefixes; its row must fail.

## Task 9 (B): H5, template handler

- The template handler's half of H5 (D7).
- Tests: a sandbox-runner seam that throws `InvalidOperationException` before any output -> uniform 502 bytes, one
  `log.Template` line with `internal-error` and the type name; the same after the first NDJSON frame -> connection
  aborted, no 502, one `internal-error` line. Break-it-once: remove the catch; the first test must fail.

## Lane rules

`~/RiderProjects/tswap-wt/tools/t17-lane-rules.md`'s "Rules" and "Report" sections apply unchanged (suite lock for
every test run, run_in_background for long runs, no `pgrep` self-matching loops, explicit-path commits ending with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and nothing about sessions, no push/merge/rebase, stop and
report when the brief can't be built as written). Reports: `~/RiderProjects/tswap-wt/tools/i224-impl-report-<a|b>.md`.
