# Brief T18: `tswap --version` (#276, for 0.3.0)

**Goal.** A user or a bug reporter can ask any tswap binary which version it is, and get the answer
with no vault, no hardware, no sudo and no side effects. The release pipeline then checks that every
shipped binary reports the tag's version.

**Base.** Branch `feat/version` from `origin/main` (`cae3bf0`, net10). Worktree
`~/RiderProjects/tswap-wt/version`. brief/t15 (.NET 11) merges `main` later; keep the change small
and free of anything .NET-version-specific so that merge is clean.

## Behaviour (the contract; tests pin each line)

1. `tswap --version` and `tswap version` print exactly one line, `tswap <version>\n`, on stdout,
   and exit 0. `<version>` is the assembly's `AssemblyInformationalVersionAttribute` with any build
   metadata (`+…`, e.g. the source revision the SDK appends) cut off, so it equals `<Version>` in
   `TswapCli/TswapCli.csproj`. No `-V` / `-v` alias (`-v` could be read as verbose). Only
   `+metadata` is cut: a prerelease suffix (`0.3.0-rc.1`) is part of the version and is printed.
   "One line" means one line with the platform's line ending (`\r\n` on Windows): every test and
   CI check trims a trailing `\r`/`\n` before comparing, and asserts nothing else follows.
2. Nothing else is printed: no touch/security banner, no warnings, no stderr output, whatever
   YubiKeys, TPM, vault or config are present or absent. It must not open, create or read the
   vault, config, keyring or any lock file, must not contact the agent or broker, and must not touch
   PC/SC, the TPM, the Secure Enclave or FIDO2. Find where startup does any of those today (the
   touch banner, config/vault discovery, sudo checks) and make sure `--version` is dispatched before
   all of it. Two kinds of proof: (a) a behavioural test proves the no-file half (no vault, config,
   keyring or lock read or created) with an empty, unwritable `HOME`/config directory or the
   existing test seams; (b) the no-agent/broker/hardware half is proved by a test that the version
   dispatch happens before startup reaches any of those (e.g. through the seams that already record
   agent/broker contact or hardware probing, if they exist; otherwise a test that the dispatch
   returns before the startup path, and say which seam you used). Don't claim more than the test shows.
3. Works the same under `sudo` and as root: no sudo check, no refusal. Prove it structurally, with
   no sudo execution (you must never run `sudo tswap`): the test from 2(b) shows the dispatch comes
   before any sudo/root check, so that check is never reached.
4. Extra arguments: `tswap --version anything` and `tswap version anything` are a usage error (the
   same exit code and stderr shape the CLI uses today for a command given unexpected arguments).
   Check what that convention is and follow it; say which in the commit.
5. `--version` given after another command (`tswap names --version`) is NOT the version command:
   it behaves exactly as today for an unknown option on that command. Pin today's behaviour first.
6. Listed in `tswap help` (and in each place commands are enumerated: shell completions, the command
   reference docs, `docs/` command lists, README if it lists commands). The existing doc/command
   reference consistency tests must cover it; if a list has no such test, say so.
7. **The agent prompt is unchanged**: `tswap prompt` text and `prompt-hash`
   (`c145260b…cde1` on main? check the actual value before and after) stay identical. `version` is
   for humans; agents don't need it. If any test or generator forces it into the prompt, stop and
   report rather than changing the prompt.
8. NativeAOT-safe: read the attribute from the entry assembly (no reflection over types, no
   trimming warnings). 0 build warnings, 0 AOT warnings in the Release publish.

## Release pipeline

9. In `release.yml` (and `ci.yml` if it has smoke tests of the built binary), each build leg's
   smoke test runs the built binary's `--version` and checks it equals the expected version: the
   tag without its `v` on a tag run; the csproj `<Version>` on a dispatch or PR run (reuse the
   existing `version=` logic at `release.yml:302-306`). A prerelease tag (`v0.3.0-rc.1`) expects
   `0.3.0-rc.1`, the same rule `verify-version` uses. The comparison trims the trailing line ending
   (a git-bash `$(...)` capture keeps a `\r` on Windows). A mismatch fails the leg. Cover every
   platform leg (linux x64/arm64, macOS, Windows), using each leg's own shell. Extend
   `ReleasePackagingTests` so a workflow without this check fails a test (the existing
   workflow-shape tests are the pattern), and break it once to show the test catches a removed
   check.
10. The pkg postinstall / install docs: if `docs/install.md` tells users how to check what's
    installed, point it at `tswap --version`.

## Not in scope

The version bump to 0.3.0 (a separate version PR), changelog/release notes beyond one line under
the unreleased section if the release notes file has one, any `--version` for the agent/broker
daemons' own protocol.

## Rules

- TDD (superpowers `test-driven-development`): each behaviour line above gets a failing test first,
  watched red for the right reason. Unit tests in-process; plus one E2E test against the AOT binary
  (the E2E suite's existing pattern) checking line 1 and 2 on the real binary.
- `writing-dotnet10-code` for C# (main is net10).
- One commit per item group (dispatch + tests; docs/help/completions; release workflow + tests),
  explicit path lists, messages saying what was done and anything left undone, with the break-it-
  once checks reported.
- Suite through `~/RiderProjects/tswap-wt/tools/with-suite-lock.sh ./runtests.sh 9>&-`: `--unit`
  during the work, then the full suite + E2E against a Debug AOT publish at the end; 0 warnings;
  prompt-hash before/after.
- Never run `sudo tswap`, never read secret values, never download toolchains. Don't push.
- Stop and report if something in the contract can't be met as written.
