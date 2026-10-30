# Brief T9: hardened command templates in the broker (the host-side half of #162)

Read AGENTS.md first, then `docs/BROKER.md` and the broker code as merged by brief T8 (the
credential proxy), issue #162 and its 2026-10-29 comment, #105 and #71. **This brief starts after
T8 is merged; merge `main` into this branch first.** One commit per item, test first (watch it fail
for the right reason), a break-it-once check per item named in its commit message, `./runtests.sh
--unit` after each item, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`,
real YubiKeys or `~/.config/tswap`. Sudo-refusal tests return early when
`Environment.IsPrivilegedProcess` and assert "requires". No new NuGet packages. NativeAOT stays
clean (report the warning count of one `dotnet publish TswapCli -c Release -r linux-x64`).

**Parallel work:** brief T10 (an ssh-agent endpoint in the broker) may run at the same time.
**T9 owns the broker config model** and adds the fields for both briefs, in item 1, as its first
commit:
- `templates`, and each socket's `templates` allow-list;
- `ssh_keys`, and each socket's `ssh_keys` allow-list, with the shape T10's brief gives: `name`,
  `secret`, `allowed_host_keys` (a list of `SHA256:` fingerprints).

T10 only reads those fields. T9 owns `TswapCore/Broker/Templates/` and the template parts of
`BrokerCommand.cs`. Don't touch `TswapCore/Broker/SshAgent/` (T10's).

## Why

The proxy (T8) covers HTTP credentials. The owner also needs **host-side commands that use a
credential**: deploy triggers, database CLIs, signing with a key file, other host tools. The #162
comment's templates did this, and two external brief reviews (GLM 5.3 and MiMo v2.6 Pro on T8)
showed why they can't be built as first specified:

- **A template's child runs as the broker's user, the vault user.** That user is in `tss` and owns
  `broker.json`. A child, or anything it runs (a git hook, a filter driver, a config file in a
  folder it reads), could:
  - read the broker's memory;
  - rewrite the broker config to send every secret elsewhere;
  - unseal the TPM directly;
  - kill the broker.
- **A `{{secret}}` in argv is readable by every local user** in `/proc/<pid>/cmdline`.

## Decisions (owner, 2026-10-30, and settled here)

1. **Isolation comes from a sandbox, not a uid.** The broker runs as an ordinary user and can't
   switch uids, so every template child runs under `bwrap` (Linux only; templates are refused on
   other OSes), started by the broker, with:
   - `--unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup-try`;
   - `--new-session --die-with-parent --cap-drop ALL`;
   - **The environment is built by the broker and handed to `bwrap` as its process environment
     (envp)** (GLM B1).
     - Never `--setenv`: that puts values in bwrap's argv, readable by every user in
       `/proc/<pid>/cmdline`.
     - The broker starts `bwrap` with exactly the template's env plus a fixed baseline, nothing
       inherited: `PATH=/usr/bin:/bin`, `LC_ALL=C`, umask 077, and no `HOME` (MiMo I8).
     - Docs: the child's `/proc/<pid>/environ` is still readable by same-uid processes while it
       runs. Env narrows the leak to the same uid; it doesn't remove it (see the uid assumption
       below).
   - a minimal filesystem:
     - `/usr` read-only, plus the `/bin`, `/lib`, `/lib64` symlinks as on the host;
     - `/etc` read-only, limited to what DNS and TLS need: `resolv.conf`, `hosts`, `nsswitch.conf`,
       `ssl`/`pki`/`ca-certificates`, `passwd`, `group`;
     - a private `/tmp`;
     - `/proc` and `/dev` minimal **with no `/dev/tpm*`**;
     - the template's declared `binds` and nothing else. **Never** the vault folder, the broker's
       config or socket folder, the user's home, `/etc/sudoers` or `sudo.conf`.
     - Secret files from `files` (decision 3), via `--ro-bind-data`.
   - Only stdin, stdout and stderr, plus the descriptors `bwrap` needs for `--ro-bind-data`,
     reach `bwrap`. The broker passes no other handle (sockets, other clients' pipes). Test it.
   - **Resource limits on the child** (GLM I3; `setrlimit`, P/Invoke):
     - `RLIMIT_NPROC` 64, `RLIMIT_AS` 2 GiB, `RLIMIT_NOFILE` 256, `RLIMIT_FSIZE` 256 MiB, and
       `RLIMIT_CORE` 0;
     - per-template overrides within the maximums.
   - Network: the template's `network` setting, **`none` by default** (`--unshare-net`), or `host` as
     an explicit, per-template opt-in (GLM I6).
   - The broker itself keeps `PR_SET_DUMPABLE 0` (from T8), so even a same-uid process outside the
     sandbox can't ptrace it.
   - Note in `BROKER.md` that the child keeps the vault user's uid and its `tss` group
     membership, but without a TPM device node, the vault folder or the broker's process it has
     nothing to use them on. Cite which `bwrap` options give each of those.
     - Why `mknod` inside isn't a way round this: `--cap-drop ALL`, and filesystems inside a user
       namespace are `nodev`.
   - **`bwrap` fails closed** (MiMo B4):
     - it is executed at a fixed absolute path (`/usr/bin/bwrap`, configurable), never through
       `PATH`;
     - `serve` checks at start that it exists and supports every option used;
     - if `bwrap` is missing, too old, or user namespaces are disabled, a template call is
       refused (125, logged). **Never run a template unsandboxed.**
   - **The load-bearing assumption, stated in `BROKER.md` and `THREAT_MODEL.md` (GLM I2; MiMo B1/B2,
     whose findings assume the opposite): no container runs with the vault user's uid.**
     - Containers run as another user (here `lane`), so files a container writes into a shared
       folder are owned by that user's uids. The bind rule (owned by the vault user or root)
       refuses them.
     - Under rootless Podman a container's root is its invoking user, so a container started by
       the vault user would break both the bind rule and the uid check.
     - With `--userns=keep-id`, run by the vault user, every vault-owned folder would be
       container-writable.
     - T8's socket layer must refuse a peer uid equal to the broker's own uid. Add that check
       here if T8 lacks it, as its own small commit with a test.
2. **Paths a template may see** (`binds`, read-only by default; `rw` per bind):
   - Each must be an absolute path that, after symlink resolution, is owned by the vault user or
     root, with every component on the way not writable by group or others.
   - **Never at or under `/dev`, `/proc` or `/sys`, and never a device node, socket or FIFO** (GLM
     B4: `/dev/tpmrm0` is root-owned and would otherwise pass). Only regular files and directories.
   - **Never the vault folder, the broker's config or its socket folder, compared by
     `st_dev:st_ino`** and not by name (MiMo I1: a bind-mount alias or a hardlink would pass a name
     check). The same holds for anything above or below them.
   - `cwd` must be inside one of the binds.
   - The checks run when a template is added and again before every run (a path can change
     owner).
   - **Why:** this excludes container-controlled folders (worktrees with hooks and config) by
     construction. A template can never run in, or read, a folder a container can write.
3. **Secrets go to the child only through env or a read-only file:**
   - `env: {"PGPASSWORD": "{{db-pw}}"}` (in the envp the broker builds, decision 1); or
   - `files: [{"path": "/run/secrets/signing-key", "secret": "signing-key"}]`, passed with bwrap's
     `--ro-bind-data <fd> <path>` (GLM B2: bwrap closes inherited descriptors, so a pipe on fd 3
     would never arrive).
     - The broker writes the secret into a pipe or memfd whose read end goes to `bwrap` only.
     - The write is bounded, and EPIPE is handled.
     - The path must be under `/run/secrets/`.
   - **`{{secret}}` in `argv`, `cwd`, `binds` or a `files` path is refused** at validation.
4. **Templates:**
   - `name` follows T8's naming rules;
   - `argv`: a list run directly, never through a shell;
     - `argv[0]` is a **literal** absolute path inside the sandbox, with no `{arg}` and no
       `{{secret}}` (GLM B3: a placeholder there would let the caller choose the program);
     - `{arg}` placeholders are allowed in `argv[1..]` only;
     - `Validation.GetBlockedInvocation` refuses inline interpreter code (#105).
   - `args`: per declared argument, a pattern the broker wraps as `\A(?:…)\z` (CultureInvariant,
     no `Multiline`, inline option groups refused, match timeout of 100 ms), a max length, and
     `allow_leading_dash` (default false).
     - Every placeholder must be declared, and every declared argument used.
     - At call time every declared argument is required, and an undeclared name is refused.
     - **NUL and control characters in an argument value or an env literal are refused** before
       the pattern runs (MiMo I3: a NUL truncates the C string execve sees).
     - `BROKER.md` warns that `allow_leading_dash` with a loose pattern is flag injection
       (`tar --checkpoint-action=exec=…`).
   - `env` (literal or `{{secret}}`), `files`, `binds`, `cwd`, `network`, `limits`, `timeout_sec`
     (default 120, 1–3600) and `max_output_bytes` (default 1 MiB, 1 byte to 64 MiB).
   - `rate`: at most N calls a minute per socket (default 6, at least 1). Over the limit the
     answer is `429` and nothing runs or unlocks (GLM I4: a template has real side effects and
     each call is a TPM unlock).
   - **Allow-lists deny by default:** a socket without a `templates` (or `ssh_keys`) entry may
     use none (MiMo I6). Test it.
   - The template allow-list per socket is the only gate for templates. A template's secrets
     don't also need to be on any proxy list (GLM I1). Say so in the docs.
5. **Calling one:**
   - `POST /_template/<name>` on the client's socket (T8's reserved `_` prefix), JSON
     `{"args": {...}}` of at most 64 KiB, method-exact.
   - `tswap broker call <template> [name=value ...]` is the client. It prints stdout and stderr and
     exits with the template's exit code; a broker-side error exits 125 (documented, so it can't
     be confused with a tool's own 1 or 2).
   - An unknown template and one the socket may not call give byte-identical answers. No unlock
     happens for a refused call.
6. **Output:**
   - stdout and stderr are **streamed** through **one shared** redactor state (MiMo I2: a secret
     split across the two streams must be caught) and counted, never buffered whole (GLM I5):
     - beyond `max_output_bytes` the rest is read and discarded;
     - the child keeps running until it exits or times out;
   - a cut never ends inside a held-back window (drop the window at the cut);
   - the response says when it was truncated;
   - **Encoding:** the redactor works on bytes. The response carries stdout and stderr as base64,
     so binary output (a signature) survives intact; `broker call` decodes it.
   - **`BROKER.md` is honest about output:** whatever the tool prints, including anything it derives
     from the secret (a decryption, a signature), goes to the caller. The broker redacts only the
     secret's known forms, so a template that prints derived secret material is the operator's
     choice.
   - The secret's handling in memory is best-effort (managed strings can't be zeroed); say so (MiMo
     I4). `PR_SET_DUMPABLE 0` is the real mitigation.
   - the exit code is passed through. A timeout kill reports 124 (as `timeout(1)` does), and a
     death by signal N reports 128+N. The response says which (`"ended": "exit"|"timeout"|"signal"`).
7. **One unlock per call, reading only the template's own secrets** (owner, 2026-10-30: "keep as
   little data unlocked for as short a time as possible"). Use T8's single-record read
   (`RecordVaultStore.ReadSecret`) for each secret the template names, never a whole-vault decrypt.
   Test with a decryption counter: a template using 2 of 50 secrets decrypts 2 records. The secret's byte arrays are zeroed once written to the env
   block or the pipe. A call holds one of the socket's request slots (T8's limits) for its
   duration.
8. **Logging:** one line per call: socket, peer uid and pid, template, the declared argument values
   (escaped, length-capped), exit code, bytes, duration. Never a secret, env values or argv after
   substitution.
9. **Config changes need sudo:** `sudo tswap broker template add|remove`, through T8's
   load-validate-swap path. Validation runs on every load.

## Items

1. **The config model for T9 and T10** (contract first, its own commit).
   - The fields above, loaded and validated. Unknown fields are still refused, so T10 needs these
     fields to exist.
   - **Tests:**
     - valid templates and ssh-key entries round-trip;
     - each of these is refused:
       - a `{{secret}}` in argv, cwd or binds;
       - an undeclared or an unused placeholder;
       - a relative `argv[0]`;
       - an inline-code argv;
       - an inline option group in a pattern;
       - a bind that is group-writable or owned by another user;
       - a symlinked bind whose target fails the check;
       - a `cwd` outside the binds;
       - a bad ssh-key fingerprint;
       - a placeholder or a `{{secret}}` in `argv[0]`;
       - a bind at or under `/dev`, `/proc` or `/sys`, or a device node;
       - a `files` path outside `/run/secrets/`;
       - out-of-range `timeout_sec`, `max_output_bytes`, `rate` or `limits`;
       - a duplicate template name;
     - without sudo, changes are refused.
   - **Break-it-once:** allow `{{secret}}` in argv; its test fails.
2. **The sandbox runner.** Starts the child under `bwrap` as decision 1, with env, fds, binds, cwd,
   network and timeout. It doesn't touch the network itself.
   - **Tests** (Linux, needs `bwrap`; skip with a message if it is missing). Each runs a small
     script as the template:
     - it can't see the vault folder, `broker.json`, the socket folder or `/dev/tpmrm0`;
     - `kill -0 <broker pid>` fails (PID namespace);
     - `/proc/<broker pid>` is absent;
     - it sees its binds and nothing else of the home folder;
     - the env holds only what the template set;
     - a `files` secret is readable at its path, and the file is read-only;
     - **no secret appears in `/proc/<pid>/cmdline` of `bwrap` or the child** (read both while
       the child runs);
     - the child's `/proc/self/fd` holds only 0, 1 and 2 (no broker handles);
     - a read-only bind refuses writes;
     - `/etc/sudoers` and `/dev/tpmrm0` are absent;
     - the resource limits are in effect (`ulimit -u` and `ulimit -v` in the child);
     - `/tmp` is private: a file the child writes there is absent on the host;
     - the timeout kills a **detached grandchild** too (checked from the host);
     - with `bwrap` made unusable (a test seam pointing at a missing binary), the call is refused
       with 125 and nothing runs;
     - **every negative check also asserts a positive**, so it can't pass for the wrong reason
       (e.g. the child's own `/proc/self` exists while the broker's pid doesn't).
     - `network: none` can't reach a loopback listener on the host;
     - the timeout kills the whole process tree.
   - **Break-it-once:** bind the vault folder; the "can't see the vault" test fails. Also pass a
  secret with `--setenv`; the cmdline test fails. Also run unsandboxed when `bwrap` is missing;
  the fail-closed test fails.
- **CI:** these tests must run on the Linux CI runner, not skip there.
  - Add a step to `.github/workflows/ci.yml` that installs `bubblewrap` and allows unprivileged
    user namespaces (Ubuntu 24.04 restricts them through AppArmor:
    `kernel.apparmor_restrict_unprivileged_userns=0`).
  - Say what you changed. On a machine without `bwrap` the tests skip with a message, but the
    report must state whether they ran.
3. **Calling, output and refusals** (decisions 5–8).
   - **Tests:**
     - a call runs with the secret in env, and output echoing it is redacted (also split across
       a pipe boundary, and split between stdout and stderr);
     - binary output survives the round trip byte for byte;
     - a NUL or a control character in an argument is refused;
     - a socket with no `templates` entry can call none;
     - truncation at a mid-secret boundary leaks no fragment;
     - each of these refuses with nothing run and no unlock: a missing, non-matching, over-long or
       leading-dash argument, an extra undeclared argument, an unknown template, a template not
       allowed, a call over the rate limit (`429`, injectable clock);
     - unknown and not-allowed answers are identical;
     - the exit code passes through, and a broker error exits 125 from `call`;
     - the log has its fields and no secret.
   - **Break-it-once:** truncate before redacting; the mid-secret test fails.
4. **Docs:**
   - `docs/BROKER.md`, a templates section:
     - what the sandbox gives (decision 1, with the option citations);
     - the bind rule and why;
     - env and fd only;
     - examples: a deploy trigger, `psql` with `PGPASSWORD`, signing with a key on fd 3;
     - what a compromised container can do with a template: call it with valid arguments, and
       nothing else;
     - what a template author must not do: bind a folder others can write; use a tool that
       writes the secret to disk (`credential.helper=store` and similar).
   - The `THREAT_MODEL.md` lines.
   - Don't edit `README.md`; give the line in your report.

## Out of scope

- The ssh-agent endpoint (T10).
- Templates on macOS or Windows.
- Running templates as a different uid (would need root or capabilities; revisit if the broker
  ever runs as a system service).
- Arbitrary `run` over the socket.
