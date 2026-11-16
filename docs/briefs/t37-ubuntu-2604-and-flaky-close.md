# Brief T37: Ubuntu 26.04 in CI and the tests (#339); a send that meets the broker's close counts as closed (#332)

Issues: https://github.com/stevedcc/TokenSwap/issues/339 (one comment: the ruleset note from the T31 merge) and
https://github.com/stevedcc/TokenSwap/issues/332 (no comments). Base: `origin/main` at 51b0b37. Read AGENTS.md and
CLAUDE.md first, then:
- for Task 1: `evals/skill/lib/runner.py` (`SHIMMED`, `READERS`, `passthrough_names`, `SYSTEM_DIRS`, `LogServer.genuine`,
  `bwrap_args`, its shim loop and the `EVAL_TEST_EXTRA_RO_BIND` hook), `evals/skill/lib/isolation_check.sh`,
  `evals/skill/shims/shim.py` (its header and `main`'s dispatch on `os.path.basename(sys.argv[0])`), `evals/skill/README.md`
  ("What it cannot see"), `TswapTests/SkillEvalTests.cs` (`CanRun`, `RunEval`, `IsolationCheck_AbortsWhenARealTswapIsReachable`,
  `Sandbox_TheAgentCannotUnmountOrRebindTheShims`, `ReadingTheShimItself_IsACleanRead`);
- for Task 2: `TswapCore/Broker/Templates/BrokerTemplatePolicy.cs` (`CheckProgramOutsideBinds`, `Narrower`,
  `SystemProgramFolders`), `TswapTests/BrokerTemplateProgramAndEnvTests.cs` (`InsideBind`, `Refused`,
  `AProgramReachedThroughASymlinkIntoABind_IsRefused`, `ABindOverUsr_WithTheProgramInIt_AsksForANarrowerFolder`),
  `TswapCore/Broker/BrokerNative.cs` (`RealPath`);
- for Task 3: `TswapCore/InstallScript.cs` (`install_binary`, both copies), `TswapTests/InstallScriptUpgradeTests.cs`
  (`InstallBinary_ReplacesARunningBinary_AndTheRunningProcessKeepsGoing`, `FunctionText`, `Bash`);
- for Task 4: `TswapTests/SshAgentTestSupport.cs` (`SshAgentTestClient`), `TswapTests/SshAgentFramingTests.cs`,
  `TswapTests/BrokerContainerGateTests.cs` (`ExchangeAsync`, `TheSshAgentSocketOfAMismatchingSocket_ClosesBeforeTheFirstFrame`),
  `TswapTests/BrokerTestSupport.cs` (`SendRawAsync` and commit 90ddf8d, the same fix for the HTTP sockets),
  `TswapCore/Broker/BrokerContainerGate.cs` (`Admit`, `Recheck`), `TswapCore/Broker/SshAgent/SshAgentListener.cs`
  (the connection loop around `Admit` and `Refusal`, `Reloaded`);
- for Task 5: `.github/workflows/ci.yml`, `.github/workflows/release.yml` (`test`, `build`'s matrix), AGENTS.md's skill-eval
  paragraph.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task and the full `./runtests.sh` at the end, both
run as `flock ~/.cache/tswap-suite.lock ./runtests.sh ...` (another implementer may run a suite at the same time). No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Tests never use the real clock or sleeps. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion unless this brief sanctions
it by name (it sanctions the input changes in Tasks 2, 3 and 4 and the one added assertion in Task 3, nothing else).
British spelling in new text.

**Containers.** Reproducing 26.04 uses rootless Podman on this machine (oort: Fedora, SELinux enforcing) with the public
`docker.io/library/ubuntu:26.04` image, and only like this: `podman run --rm ...`, or
`podman run --rm -d --name t37-u2604 docker.io/library/ubuntu:26.04 sleep infinity` followed by `podman cp`,
`podman exec` and `podman stop t37-u2604` (the `--rm` removes it). Get the source in with `podman cp` of a
`git archive HEAD` tarball, never a bind mount of the worktree (a `:Z` mount relabels it and breaks other users of the
folder), and never `--privileged`, `--security-opt`, `--cap-add`, `--device` or `--userns`. Run tests in the container as
a non-root user made there (`useradd -m tester`, `podman exec --user tester ...`): the broker refuses root and several
tests behave differently as root. Stop every container you started before you finish.

**Review history.** Round 1 (MiMo: not ready, 1 Important and 6 Minors; GLM: ready, 1 Important and 3 Minors), folded:
- MiMo Important 1 (Task 1's expected `shim_paths` set didn't follow its own rule): valid. A1 gives the full 12-entry
  set, asserted exactly, with sorted JSON lists.
- MiMo Minor 2 (90ddf8d didn't touch `ExchangeAsync`): valid. Why now names d997c77 for `ExchangeAsync`.
- MiMo Minor 3 (the python3 test fails on a host without python3): valid. A3: it skips with a message, and fails under
  `CI_REQUIRE_BWRAP=1`.
- MiMo Minor 4 (the isolation lines need Contains): valid. A2.
- MiMo Minor 5 (the repro needs `gh`, egress and a guessed `libicu78`): partly valid. `libicu78` isn't a guess (the
  controller read its candidate, 78.2-2ubuntu1, in the 26.04 image), and the container has egress (apt worked there).
  The anonymous logs endpoint isn't a fallback, because job logs need auth. A missing `gh` is A4 (below).
- MiMo Minor 6 (the 26.04 move isn't confirmable from runner-images' README): valid. A6: the report quotes the job's
  runner-image line.
- MiMo Minor 7 (the trailer names a model): invalid. The trailer is the controller's house rule for every brief.
- GLM Important 1 (Task 3's teardown, a stdin close followed by `Kill`): valid as an ambiguity. A7 keeps today's
  `Kill(); WaitForExit();` and drops the stdin close. MiMo checked that `Kill` on an exited process doesn't throw on
  Unix, so it was never a failure, but the close bought nothing.
- GLM Minor 2 (the parallel-briefs paragraph said `BrokerContainerGateTests.cs` was shared with no counterpart):
  valid. A5: T37 owns that line, and no other brief touches the file.
- GLM Minor 3 (the out-of-scope `su` bullet could read as excluding same-named cargo links): valid. A9 rewords it;
  on 26.04 `/usr/bin/su` is util-linux's own file (checked in the container).
- GLM Minor 4 (`gh` may be unavailable): valid. A4: say so in the report and don't fetch the log another way.
- GLM coverage note (`BrokerContainerGateTests` is `Category=E2E`): taken as A8, run by filter in Task 4.

**Parallel briefs.** T34 (enrol follow-ups: `SlotEnrol*.cs`, `SlotStage.cs`, `ProcessSshTransport.cs`, `SlotCommand.cs`'s
request/accept output, `docs/multi-machine.md`'s enrolling-over-SSH section, `SlotEnrolTests`/`SlotStdioTests`), T35
(Windows output: `run`'s hints and refusals, console encoding and glyphs, ConPTY, `InitCommand`'s `--yubikey` Windows
header, `docs/install.md`'s Windows notes, `docs/agent-integration.md`, `Prompt.cs`'s Windows note) and T36 (the `slots`
listing, loose record-vault files, `docs/multi-machine.md`'s Sync transports section) touch none of T37's files. T37 owns
`evals/skill/**`, `SkillEvalTests.cs`, `BrokerTemplateProgramAndEnvTests.cs`, `InstallScriptUpgradeTests.cs`,
`SshAgentTestSupport.cs`, `SshAgentFramingTests.cs`, the new `SshAgentTestClientTests.cs` and `.github/workflows/*`,
plus one line of `TswapTests/BrokerContainerGateTests.cs` (in `TheSshAgentSocketOfAMismatchingSocket_ClosesBeforeTheFirstFrame`),
which no other brief tonight touches (A5). One shared file, said so the merge is expected: AGENTS.md (one phrase in the
skill-eval paragraph, "the Linux CI job" becomes "the Linux CI jobs"; T35 and T36 may edit other paragraphs). No production code changes in this brief unless Task 5's CI run turns up a real 26.04 bug
(then see Task 5).

## Why

**#339.** GitHub moved `ubuntu-latest` to Ubuntu 26.04 on 2026-11-16 (image `ubuntu-26.04`, 20261103.629). On it, run
43868884283 (PR #338) failed the unit-test step with `Failed: 14, Passed: 5862`: twelve `SkillEvalTests` (the eight
`FakeAgent_PassVariantPasses_EveryOtherVariantFailsOnTheRuleItBreaks` cases, `IsolationCheck_PassesWithTheShimsOnly`,
`ReadingTheShimItself_IsACleanRead`, `Sandbox_TheAgentCannotUnmountOrRebindTheShims`,
`Shim_IgnoresStatePathsFromTheEnvironment`; the issue says 11, the log has 12),
`BrokerTemplateProgramAndEnvTests.ABindOverUsr_WithTheProgramInIt_AsksForANarrowerFolder` and
`InstallScriptUpgradeTests.InstallBinary_ReplacesARunningBinary_AndTheRunningProcessKeepsGoing`. Both workflows' Linux
runners were pinned to `ubuntu-24.04` the same day. The failing step stopped the job, so the later steps (AOT publish,
package smoke, E2E) have **never run on 26.04**; Task 5 is where they first do.

The controller checked the 26.04 layout in a throwaway `ubuntu:26.04` container (`Ubuntu 26.04.1 LTS`). The three
causes are:

1. **sudo-rs: a shimmed name that is a symlink into another folder gets no shim.** With the `sudo` package installed,
   `/usr/bin/sudo -> /etc/alternatives/sudo -> /usr/lib/cargo/bin/sudo` (sudo-rs 0.2.13). `bwrap_args` loops over every
   shimmed name and system folder. When `path` is a symlink, it binds nothing: it only adds `shim_paths` entries when the
   link's target is in the **same** folder (the `awk -> gawk` case, where `gawk` is shimmed under its own name), and it
   `continue`s otherwise. So inside the sandbox `/usr/bin/sudo` and `/bin/sudo` still reach the real sudo-rs. The
   isolation check is **right** to abort: its loop over `dirs` reads `/usr/bin/sudo` through the link and finds no
   `TSWAP-EVAL-SHIM` line, so it prints `isolation: /usr/bin/sudo exists and is not the eval shim` (and `/bin/sudo`).
   The fix is the runner's binds; the check stays as it is. The same gap affects the readers: 26.04's `cat` and `head` are
   `/usr/bin/cat -> ../lib/cargo/bin/coreutils/cat`, which are hard links (116 of them) to the uutils multi-call binary.
   So an absolute `/usr/bin/cat` would pass through unlogged. The isolation check doesn't look at readers, so this
   doesn't abort, but it is a blind spot in the eval.
2. **Rust coreutils: `/usr/bin/true` is a symlink.** On 26.04 `/usr/bin/true -> gnutrue`. `CheckProgramOutsideBinds`
   resolves the program (`BrokerNative.RealPath`) and, when the resolved path differs, shows it:
   `program /usr/bin/true (resolves to /usr/bin/gnutrue) is inside bind /usr; ...`. **The broker is right.** That form
   is intended and is pinned with a test-made symlink by `AProgramReachedThroughASymlinkIntoABind_IsRefused` and
   `AMissingProgramBelowASymlinkIntoABind_IsRefused`. The test is what's wrong: it assumes `/usr/bin/true` is a plain
   file, so it pins one distribution's coreutils layout.
3. **The install test's stand-in program is a copy of `/usr/bin/sleep`, which on 26.04 is the multi-call binary.**
   `/usr/bin/sleep -> ../lib/cargo/bin/coreutils/sleep`. `File.Copy` follows the link, so `<temp>/tswap` is the uutils
   multi-call binary, which picks the tool by its own file name. Checked in the container: `cp /usr/bin/sleep /tmp/tswap;
   /tmp/tswap 30` prints `coreutils: unknown program 'tswap'` and exits 1 at once. So `running.HasExited` is true before
   `install_binary` even runs, and the test reports "the running process was killed". **Not an installer bug** (the
   controller's reading, which the implementer confirms in the reproduction below): the same run's `Assert.True(exit == 0)`
   and the new-contents assertion passed, so `install_binary` (uutils `mkdir`, `mktemp`, `cp`, `chmod`, `mv`) worked.

**#332.** `ThePeerWithTheBrokersOwnUid_IsClosed` failed once on the Fedora CoreOS test VM with
`SocketException: Broken pipe` from `SshAgentTestClient.SendRawAsync`, called from `SendFrameAsync` at
SshAgentFramingTests.cs:180. With `allowOwnUid: false`, `BrokerContainerGate.Admit` refuses the peer at accept
(`own-uid`) and the listener returns, which closes the socket before any frame is read. A slow machine lets that close
reach the client before its first send, and the send then fails with EPIPE. The outcome the test checks (closed
without a reply, `reason=own-uid` logged) happened. The test client just can't take the close arriving first. The HTTP
side had the same race: `BrokerHarness.SendRawAsync` (BrokerTestSupport.cs, fixed in 90ddf8d) and
`BrokerContainerGateTests.ExchangeAsync` (which has had the same catch since d997c77) count a send that fails with
`SocketException { SocketErrorCode: SocketError.Shutdown or SocketError.ConnectionReset }` as "nothing answered" (.NET
reports EPIPE as `SocketError.Shutdown`).

Which `ClosedWithoutReplyAsync` users have this shape: only tests where the broker refuses **at accept** can see the
close before their send. `Admit` runs before the first frame is read. A reload's refusal (`Refusal(peer)` in the
connection loop) runs only after a frame has been read, and `Reloaded` closes no connection of a kept socket. So:
- **the race is possible in:** `SshAgentFramingTests.ThePeerWithTheBrokersOwnUid_IsClosed`,
  `SshAgentFramingTests.UidNotOnTheList_IsClosedBeforeAnythingIsParsed_AndLogged` and
  `BrokerContainerGateTests.TheSshAgentSocketOfAMismatchingSocket_ClosesBeforeTheFirstFrame`;
- **the race is not possible in:** `OversizeOrEmptyFrame_...` and `TruncatedFrame_...` (the broker reads what was sent
  first); `AReloadThatDropsTheUid_ClosesAnOpenConnection_AtItsNextRequest`, `ARebindBetweenTwoSshMessages_RefusesTheSecond`
  and `BindingAUidOnlySocketBetweenTwoSshMessages_RefusesTheSecond_IdentityUnreadable` (refused after the frame is read);
  `SshAgentBindTests.AssertBindRefusedAndClosedAsync` and `SshAgentRecordedFramesTests.ReplayedSession_...` (a reply
  first, then the close). These keep `SendFrameAsync`, so an early close there would still fail loudly.

## Reproduce first (before any task's change; evidence in the report)

What can be reproduced where:

| Cause | In the `ubuntu:26.04` container | Only on a real `ubuntu-26.04` runner |
|---|---|---|
| 1, sudo-rs | the layout (`apt-get install -y sudo`, then `ls -l` and `readlink -f /usr/bin/sudo /bin/sudo /usr/bin/cat`) and Task 1's `shim_mounts` run against it with `python3` | the eval itself: bwrap can't make its sandbox in a rootless container (the controller saw `bwrap: Can't mount proc on /newroot/proc: Permission denied`), so `SkillEvalTests` skip there |
| 2, `/usr/bin/true` | fully: the layout, and the test class run in the container | — |
| 3, the install test | fully: the `coreutils: unknown program 'tswap'` line, `install_binary` against a running program, and the test class run in the container | — |
| 4, #332 | — (a timing race; Task 4's own tests make it deterministic) | — |

Steps:
1. Record the 26.04 layout: `podman run --rm docker.io/library/ubuntu:26.04 bash -c 'apt-get update -qq && apt-get install -y -qq sudo >/dev/null; ls -l /usr/bin/sudo /etc/alternatives/sudo /usr/bin/true /usr/bin/sleep /usr/bin/cat; readlink -f /usr/bin/sudo /usr/bin/true /usr/bin/sleep /usr/bin/cat'`.
2. Cause 3 by hand in the same kind of container: `cp /usr/bin/sleep /tmp/tswap; /tmp/tswap 30; echo $?` (expect the
   `unknown program` line and 1). Then the installer with a program that really keeps running: paste `install_binary`
   (from `InstallScript.GetBashScript`'s output, as the test does), `cp /bin/bash /tmp/d/tswap`, start
   `/tmp/d/tswap -c 'read -r _' < <(tail -f /dev/null) &`, run `install_binary /tmp/new /tmp/d/tswap`, then show that the
   process is still alive (`kill -0 $!`) and that `readlink /proc/$!/exe` ends in ` (deleted)`. If the process died, or
   `install_binary` failed under uutils, **stop and report**: that is a real installer bug for 26.04 users and needs
   its own design.
3. Causes 2 and 3 as tests, before the fixes: a `t37-u2604` container as above, `apt-get install -y curl ca-certificates
   libicu78 python3 git` (as root), the SDK from `https://dot.net/v1/dotnet-install.sh --version 11.0.100` into the
   tester's home (controller default: the official install script inside the container, not a copy of `~/dotnet`;
   owner may change), the source via `git archive`, then as `tester`:
   `TSWAP_TEST_KEY=<64 hex> dotnet test TswapTests/TswapTests.csproj --filter "FullyQualifiedName~BrokerTemplateProgramAndEnvTests|FullyQualifiedName~InstallScriptUpgradeTests|FullyQualifiedName~SkillEvalTests"`.
   Expected: the two #339 failures with the CI run's messages, and `SkillEvalTests` reporting SKIPPED (bwrap). Keep the
   container (stop it only at the end) and re-run the same filter after Tasks 1 to 3 as the "after" evidence (the
   `SkillEvalTests` still skip there; Task 1's new `shim_mounts` test does not skip, it needs only `python3`).
4. The CI log: `gh run view 43868884283 -R stevedcc/TokenSwap --log-failed`, the 14 failure lines, the two
   `isolation:` lines and the job's runner-image line (`Image: ubuntu-26.04` and its version, from the "Set up job"
   step: `gh run view --job <id> --log`), quoted in the report (A6). If `gh` is missing or refused, don't fetch the log
   another way: say so in the report and quote the issue's failure lines instead (A4).

## Task 1: the eval's shim goes over a link's target (#339 cause 1)

**Change, `evals/skill/lib/runner.py`.** Take the bind planning out of `bwrap_args` into a new module-level function:

`def shim_mounts(names, system_dirs):` returns `(targets, shim_paths)`. `targets` is a sorted list of host paths to
bind the shim over, each once. `shim_paths` is the set of paths at which the shim then runs inside the sandbox (host
and sandbox paths are the same, since the folders are bound at the same place). For each `name`, and each `d` in
`system_dirs`, take `path = os.path.join(os.path.realpath(d), name)`, skipping paths that don't `lexists` and
directories:
- **A regular file:** bind over `path` (as today). Add to `shim_paths` `os.path.join(dd, name)` for every `dd` in
  `system_dirs` with `os.path.realpath(dd) == os.path.dirname(path)` (as today's second loop does).
- **A symlink:** `target = os.path.realpath(path)`. Bind over `target` when it is a regular file and its basename is
  `name` or another of `names` (sudo-rs's `/usr/lib/cargo/bin/sudo`, uutils' `.../coreutils/cat`, `gawk` for `awk`).
  Then add to `shim_paths` the `target` itself and `os.path.join(dd, name)` for every `dd` in `system_dirs` with
  `os.path.realpath(dd) == os.path.dirname(path)`. These are the link's own paths (`/usr/bin/sudo`, `/bin/sudo`), which
  is what `LogServer.genuine` sees in `argv[2]`, because the interpreter gets the path that was executed, not the
  resolved one.
- **A symlink to a file under another name that isn't in `names`** (a busybox-style multi-call binary): bind nothing
  and add nothing. Ruling: shimming such a binary would turn every other tool that links to it into the shim. Leaving
  it is safe: for `tswap`, `sudo`, `su`, `doas` and `pkexec` the isolation check then aborts the run (exit 2), and for a
  reader it is the blind spot below (controller default; owner may change).

`bwrap_args` calls `shim_mounts(SHIMMED + PASSTHROUGH + CANNED, SYSTEM_DIRS)`. It adds `--ro-bind <shim> <target>` for
each target, keeps the `/eval/bin/<name>` entries and the `HOME/.local/bin` part as they are, and keeps the
`EVAL_TEST_EXTRA_RO_BIND` hook **after** the shim binds (as now, so a test bind can override a shim). Keep the old
comment about bwrap not mounting on a symlink, reworded for the new rule. Ruling: links met along the way
(`/etc/alternatives/sudo`) are not added to `shim_paths`. Running `/etc/alternatives/sudo` directly reaches the shim,
but its record is dropped as forged and the scenario fails (`forged_log`). That fails closed, so no extra handling is
needed. `isolation_check.sh` is not changed.

**`evals/skill/README.md`**, "What it cannot see", a new bullet: "**A tool linked to a multi-call binary under another
name** (busybox style). It isn't shimmed, because shimming the binary would shim every tool linked to it. For `tswap`,
`sudo`, `su`, `doas` and `pkexec` the isolation check then aborts the run; for a reader, calling it by its system path
(`/usr/bin/cat`) leaves no record."

**Tests (`SkillEvalTests`):**
- `ShimMounts_FollowLinksIntoOtherFolders_ButNotIntoAMultiCallBinary` (`[LinuxFact]`, no bwrap needed, so not behind
  `CanRun`): it builds a tree under a temp folder taken through `realpath`:
  - `usr/bin/` with `bin -> usr/bin`;
  - `usr/lib/cargo/bin/sudo` (a file), `etc/alternatives/sudo -> <root>/usr/lib/cargo/bin/sudo` and
    `usr/bin/sudo -> <root>/etc/alternatives/sudo`;
  - `usr/lib/cargo/bin/coreutils/cat` (a file) and `usr/bin/cat -> ../lib/cargo/bin/coreutils/cat`;
  - `usr/bin/gawk` (a file) and `usr/bin/awk -> gawk`;
  - `usr/lib/busybox` (a file) and `usr/bin/su -> ../lib/busybox`;
  - `usr/bin/pkexec` (a file).

  It runs `/usr/bin/python3 -I -B -c` with a snippet that puts `evals/skill/lib` on `sys.path`, imports `runner`, calls
  `shim_mounts(["sudo","cat","awk","gawk","su","pkexec"], [<root>/usr/bin, <root>/bin])` and prints both results as
  JSON, each as a sorted list (a Python `set` doesn't serialise). The test asserts both sets exactly (A1):
  - targets, 4 entries: `<root>/usr/lib/cargo/bin/sudo`, `<root>/usr/lib/cargo/bin/coreutils/cat`, `<root>/usr/bin/gawk`,
    `<root>/usr/bin/pkexec`;
  - `shim_paths`, 12 entries: `<root>/usr/bin/sudo`, `<root>/bin/sudo`, `<root>/usr/lib/cargo/bin/sudo`,
    `<root>/usr/bin/cat`, `<root>/bin/cat`, `<root>/usr/lib/cargo/bin/coreutils/cat`, `<root>/usr/bin/awk`,
    `<root>/bin/awk`, `<root>/usr/bin/gawk`, `<root>/bin/gawk`, `<root>/usr/bin/pkexec`, `<root>/bin/pkexec`;
  - so nothing under `<root>/usr/lib/busybox` and no `.../su` is in either set.

  Without `/usr/bin/python3` the test writes `SKIPPED: no /usr/bin/python3 here` and returns, except under
  `CI_REQUIRE_BWRAP=1` (every Linux CI leg), where it fails instead, as `CanRun` does (A3).

  Break-it-once: restore the `continue` for a symlink whose target is in another folder. The test fails on the missing
  cargo `sudo` and `cat` targets.
- `IsolationCheck_AbortsWhenARealSudoIsReachable` (behind `CanRun`): this is "a real sudo is still refused". It writes
  a stand-in `#!/bin/sh` script in a temp folder and binds it with `EVAL_TEST_EXTRA_RO_BIND` over
  `realpath("/usr/bin/sudo")` (`/usr/bin/sudo` on Fedora and 24.04, `/usr/lib/cargo/bin/sudo` on 26.04, so the test works
  on both layouts). It runs scenario `01-secret-in-log` and asserts exit 2 and, with `Assert.Contains` as
  `IsolationCheck_AbortsWhenARealTswapIsReachable` does (the check prints one line per path, so `/bin/sudo` too where
  `/bin` links to `/usr/bin`), `ABORT 01-secret-in-log/pass: isolation check failed` and
  `isolation: /usr/bin/sudo exists and is not the eval shim`, and `Assert.DoesNotContain("PASS ", ...)` (A2). Without `/usr/bin/sudo` on the
  host it writes `SKIPPED: no /usr/bin/sudo here` and returns. Break-it-once: comment out the `for dir in "${dirs[@]}"`
  loop in `isolation_check.sh`. The test fails (no abort, because `command -v sudo` still finds `/eval/bin/sudo`).
- The twelve existing `SkillEvalTests` that failed on 26.04 are the end-to-end measure, on the PR's 26.04 job
  (`CI_REQUIRE_BWRAP=1` there, so they can't skip). On 26.04, `Sandbox_TheAgentCannotUnmountOrRebindTheShims` also shows
  that `/usr/bin/sudo` through the link is shimmed **and** logged (its `never[sudo]` needs the record accepted, which
  needs the link path in `shim_paths`).
- Container evidence: in the 26.04 container with `sudo` and `python3` installed, run `shim_mounts(runner.SHIMMED +
  runner.PASSTHROUGH + runner.CANNED, runner.SYSTEM_DIRS)` against the real layout and quote the targets (expected to
  include `/usr/lib/cargo/bin/sudo` and `/usr/lib/cargo/bin/coreutils/cat`).

## Task 2: the `/usr` bind test takes a real program under `/usr` (#339 cause 2)

No production change: the broker's message is right (see Why). In
`BrokerTemplateProgramAndEnvTests.ABindOverUsr_WithTheProgramInIt_AsksForANarrowerFolder`, **sanctioned input change**:
the program becomes `var program = BrokerNative.RealPath("/usr/bin/true")!;` (on 26.04 `/usr/bin/gnutrue`, elsewhere
`/usr/bin/true`), with the precondition `Assert.StartsWith("/usr/", program)`. The config and the expected text use
`program`: `Assert.Equal(InsideBind(program, "/usr") + "; bind /usr covers system programs; bind a narrower folder",
Refused(Config(program, "/usr")))`. The assertion's form stays exactly as it was. Only the input is now a non-link
file the test resolved itself, so no "(resolves to ...)" part is expected on any layout. The resolved-path form stays
pinned by the two symlink tests named in Why, which make their own links in a temp folder. A test that needs a
program under `/usr` can't make one there without root. Write that in a one-line comment on the test.

Break-it-once: make `Narrower` return `""`. The test fails (the hint is missing). Evidence: the test passes in the 26.04
container and here.

## Task 3: the install test runs a program that doesn't pick its tool by name (#339 cause 3)

No production change: `install_binary` is right (see Why; step 2 of the reproduction confirms it on 26.04). In
`InstallScriptUpgradeTests.InstallBinary_ReplacesARunningBinary_AndTheRunningProcessKeepsGoing`, **sanctioned input
change**: the running stand-in is a copy of `/bin/bash`, not `/usr/bin/sleep`. bash is a plain ELF on every Linux the
tests run on, and the helper `Bash` already needs it. Start it as
`new ProcessStartInfo(target) { UseShellExecute = false, RedirectStandardInput = true }` with arguments `-c` and
`read -r _`. It blocks on its open stdin, has no time limit, and `Process.Start` returns only after the exec. The
existing assertions stay. **One sanctioned added assertion**, after `Assert.False(running.HasExited, ...)`:
`Assert.Equal(target + " (deleted)", new FileInfo($"/proc/{running.Id}/exe").LinkTarget)`. It shows that the process
still running is the old binary, whose file the rename replaced, rather than some other process at that path. Update
the test's comment: the stand-in is a copy of bash because a multi-call binary (26.04's uutils `sleep`) picks its tool
from its own file name and exits at once under the name `tswap`. The teardown stays exactly as now,
`running.Kill(); running.WaitForExit();`, with no stdin close before it: the kill ends the blocked `read` at once and
the `using` disposes the pipe (A7).

Break-it-once: in the Linux script's `install_binary` (`InstallScript.cs`; the test reads that copy), change
`mv -f "$tmp" "$dest"` to `cat "$tmp" > "$dest"`. That is the in-place rewrite the function exists to avoid. The test
must fail on `install_binary failed: ... Text file busy`. Don't use `cp -f` for this check: GNU cp unlinks and recreates
a busy target, so it would pass (the test's existing comment says so). Evidence: the test passes in the 26.04 container
and here.

## Task 4: a send that meets the broker's close counts as closed (#332)

**`TswapTests/SshAgentTestSupport.cs`, `SshAgentTestClient`, new member:**
`public async Task<bool> SendFrameUnlessClosedAsync(byte[] body)`. It sends exactly as `SendFrameAsync` and returns
true. It returns false when the send throws
`SocketException { SocketErrorCode: SocketError.Shutdown or SocketError.ConnectionReset }` (EPIPE or ECONNRESET: the
broker closed the connection before the frame was written). Any other exception propagates. Its doc comment says when
to use it: only where the broker may refuse the connection at accept, before reading anything. Everywhere else
`SendFrameAsync` stays, so an early close fails loudly. Ruling: an opt-in member, not a change to
`SendRawAsync`/`SendFrameAsync`, so that tests expecting a reply never treat a close as a send (controller default;
owner may change).

**Sanctioned input changes.** The send line of these three tests becomes `_ = await client.SendFrameUnlessClosedAsync(...)`
(`agent.` in the third); their assertions stay:
- `SshAgentFramingTests.ThePeerWithTheBrokersOwnUid_IsClosed`;
- `SshAgentFramingTests.UidNotOnTheList_IsClosedBeforeAnythingIsParsed_AndLogged`;
- `BrokerContainerGateTests.TheSshAgentSocketOfAMismatchingSocket_ClosesBeforeTheFirstFrame`.

Either outcome of the send is correct there, so the result is discarded on purpose. The outcome the test cares about is
`ClosedWithoutReplyAsync()` and the broker's log line. `ReadExactlyAsync` already reads ECONNRESET as a close, and after
EPIPE the receive sees end of stream. No catch anywhere else, no retries, no waits.

**New tests**, in a new `TswapTests/SshAgentTestClientTests.cs` (`[UnixFact]`; own `Socket` listener on a
`UnixDomainSocketEndPoint` in a temp folder, no broker):
- `SendFrameUnlessClosed_AfterThePeerClosed_ReturnsFalse_AndReadsAsClosed`: accept, dispose the accepted socket, then
  `SendFrameUnlessClosedAsync([11])` returns false and `ClosedWithoutReplyAsync()` returns true. This makes #332's race
  certain: on a Unix stream socket a send after the peer's close fails with EPIPE every time. Break-it-once: remove the
  `when` filter's `SocketError.Shutdown`. The test fails with `SocketException: Broken pipe`. If it fails with another
  error code instead, stop and report it, because the EPIPE mapping is then not what 90ddf8d assumed.
- `SendFrameUnlessClosed_ToAnOpenPeer_ReturnsTrue_AndThePeerGetsTheFrame`: the accepted side reads exactly
  `00 00 00 01 0B`. Break-it-once: return false unconditionally. The test fails.
- `SendFrameUnlessClosed_OnADisposedClient_StillThrows`: after `client.Dispose()`, the call throws
  `ObjectDisposedException`. This guards against the catch growing into a blanket one. Break-it-once: widen the catch to
  `catch (Exception)`. The test fails.

macOS runs these in CI's macOS job, where EPIPE is reported the same way. `BrokerContainerGateTests` is
`Category=E2E`, so `--unit` doesn't run it: run it during this task with
`--filter "FullyQualifiedName~BrokerContainerGateTests"` (it skips without a usable cgroup client, as it does now), and
the final full `./runtests.sh` covers it (A8).

## Task 5: CI runs Ubuntu 24.04 and 26.04

**`.github/workflows/ci.yml`**, `build-test-publish`'s matrix becomes
`os: [ubuntu-24.04, ubuntu-26.04, macos-latest, windows-latest]`. The three existing names, which are required checks
in ruleset 27270067, stay exactly `build-test-publish (ubuntu-24.04)`, `build-test-publish (macos-latest)` and
`build-test-publish (windows-latest)`. The new job is `build-test-publish (ubuntu-26.04)`, **not** required, and the
ruleset is left alone (the controller and the owner add it later). Ruling: the explicit `ubuntu-26.04` label, not
`ubuntu-latest`, so that the next move of `ubuntu-latest` can't change what the job tests without anyone noticing, and
the job name stays stable (the issue comment's concern) (controller default; owner may change). Every `runner.os ==
'Linux'` step already applies to both legs. The artifacts stay distinct (`tswap-${{ matrix.os }}`). Replace the
"Pinned to 24.04 ..." comment with: both Ubuntu LTS images run, 24.04 because release.yml builds the Linux binaries
there (glibc), 26.04 for sudo-rs and Rust coreutils (#339); a new job name needs adding to ruleset 27270067 to become
required. `macos-older` keeps `needs: build-test-publish`, so a failing 26.04 leg skips it too. That is intended,
because the leg is meant to pass.

**`.github/workflows/release.yml`**: unchanged apart from comments (controller default; owner may change). The `test`
job stays on `ubuntu-24.04`, as the release's one test leg, matching the build images. ci.yml's 26.04 leg has already
run on every PR before a tag. `build`'s `linux-x64` stays on `ubuntu-24.04` (glibc), and its comment stays. Change the
`test` job's comment to: "24.04, the image the Linux binaries are built on; ci.yml also runs 26.04 (#339)."

**AGENTS.md**: "set by the Linux CI job" becomes "set by the Linux CI jobs".

**Verification** is the PR's CI run, which the controller starts by pushing the branch. You can't push. Your report
says that every 26.04 step (unit tests, AOT publish, package smoke, E2E) is still to be seen on the runner. When the
controller passes the run's results back as a fix round: root-cause each new 26.04 failure first. A test that pins a
distribution's layout gets its input from the test itself, as in Tasks 2 and 3. A real tswap bug, or anything that
needs a design decision, stops the work with the evidence. No 26.04 skip, no `continue-on-error`, no test excluded on
26.04.

Commit message evidence: `git diff` of the job names, plus `actionlint` on both workflows if it is installed (say if
it isn't).

## Report

Write `t37-report.md` at the worktree's parent folder (`../t37-report.md`). It contains:
- the commits;
- the reproduction: the layout listing, the cause 3 by-hand result, the container's before and after test summary
  lines, the `shim_mounts` output on the real 26.04 layout, and the CI log lines with the runner-image line;
- which causes were reproduced in the container and which are left to the runner (expected: cause 1's eval run);
- the red counts and each break-it-once (the line reverted, the test that failed and how);
- the tests whose input changed (sanctioned) and the one added assertion;
- the full `./runtests.sh` summary lines;
- what the PR's 26.04 job must show (the twelve `SkillEvalTests` passing, then the AOT publish, package smoke and E2E
  steps, which have never run there), and anything left undone;
- the containers you started, and that each was stopped.

## Out of scope

- the ruleset (required checks), and renaming any existing job;
- moving release.yml's build or test jobs to 26.04;
- shimming tools linked to a multi-call binary under another name (busybox style), and a setuid binary at a path that
  no shimmed name resolves to (on 26.04 `/usr/bin/su` is util-linux's own file, so sudo-rs's
  `/usr/lib/cargo/bin/su` is reached by no system name). bwrap's sandbox sets no-new-privileges, so such a binary
  gains nothing. A same-named cargo link (`/usr/bin/sudo`, or a `/usr/bin/su` that links into `/usr/lib/cargo/bin`) is
  covered by Task 1's rule (A9);
- `InstallScript` changes (unless the reproduction shows a real bug: then stop);
- the HTTP-side send helpers (fixed in 90ddf8d) and the ssh-agent tests listed in Why as not affected;
- the Fedora CoreOS VM's missing `python3` (#332's other 14 failures there).

## Owner questions

1. Make `build-test-publish (ubuntu-26.04)` a required check once it has passed on main? (The controller asks after
   the merge.)
2. Should release.yml's `test` job also run on 26.04 (a matrix, renaming it `Test (ubuntu-24.04)`), or is ci.yml's leg
   enough? The brief says enough.
