# Brief T23: tests that don't flake, don't claim coverage they don't have, and catch every leak

Issues: #262, #300, #288, #181, #258 (stevedcc/TokenSwap). Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then each issue (`gh issue view <n> -R stevedcc/TokenSwap`) and the files each task
names.

One commit per task, test first where there is a behaviour to pin, a break-it-once check per key test (name in the
commit message which line you reverted and which test failed), `./runtests.sh --unit` after each task, the full
`./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated
services, `TSWAP_CONFIG_DIR` and temp folders only. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written.

**Never change an existing test's assertion.** Tasks 1-4 change how tests wait, where they run and how they report;
each says exactly what may change. If a task seems to need a changed assertion, stop and report why.

**Project rules that bind every task:** no `Thread.Sleep`, `Task.Delay` or wall-clock waits in tests; wait on a
concrete condition. Tests never read the real clock for anything they assert (owner rule, 2026-11-11).

**Parallel work:** the #311 fields branch and brief T22 run at the same time. T23 touches only test files, the test
project, `runtests.sh` and `.github/workflows/ci.yml` (Task 2 only), plus broker source if Task 3 finds a real bug
(`TswapCore/Broker/`, which neither touches). Neither other branch touches the test files named here.

## Task 1: the zombie test waits for the exec (#262)

`TswapTests/PeerIdentityLivenessTests.cs`, `AZombie_ExitedButNotReaped_IsNotAlive`. The race (issue #262): the
grandchild is killed after the shell's `echo` but possibly before its `exec`, while the parent is still the shell,
which reaps it; the test then waits for a zombie that never appears.

Fix: before the kill, wait (with the test's existing `SpinWait.SpinUntil` style and timeout) until the parent has
exec'd, i.e. `/proc/<parent.Id>/comm` reads `sleep` (trimmed). Only then kill the grandchild. The assertion lines
stay exactly as they are.

Break-it-once: you can't make a race fire on demand; instead show the condition is load-bearing: replace
`exec sleep 300` with `sleep 300` in the shell script (the parent stays a shell that reaps), and the new wait times
out with its own message, not the zombie assertion. Name that in the commit message. Then run the test 30 times in a
row (`for i in $(seq 30); do dotnet test … --filter FullyQualifiedName~AZombie_ExitedButNotReaped_IsNotAlive …; done`)
while a full `./runtests.sh --unit` runs alongside, and quote the counts.

## Task 2: the Argon2 timing budget stops gating shared CI runners (#300)

`TswapTests/StretchedPasswordTests.cs`, `Stretch_UnderOneSecond`, measures wall-clock time against a 1 s budget
(T17 ruling 1: unlocking with the vault password stays under a second on the owner's machines). On a busy shared CI
runner it failed at 1005 ms with no code change.

- Move `Stretch_UnderOneSecond` (and `Stretch_AtTheMaximum_CompletesAndIsMeasured`, if it also asserts a time; read
  it) into `[Trait("Category", "Perf")]`, the category `RunRedactionThroughputTests` already uses. Its assertion and
  its budget stay exactly as they are.
- Exclude `Category=Perf` from the default runs: `runtests.sh`'s default and `--unit` filters, and the `dotnet test`
  filter in `.github/workflows/ci.yml` (:117). Add `./runtests.sh --perf` (filter `Category=Perf`) so the owner runs
  the budget on their own machines; document it in the script's header comment beside the other modes.
- Check how `RunRedactionThroughputTests` gates itself today (`TSWAP_PERF=1`): it stays as it is, and `--perf` must
  not change what it does without that variable.
- What keeps guarding the parameters in every run: confirm a test outside `Perf` already pins
  `VaultPasswordParams.Default` to m 65536, t 3, p 1 (the issue says one does; name it in the commit message). If none
  does, add `Default_IsTheRuledParameters`.
- `docs/` or the README, wherever the test modes are listed: add `--perf` there too (grep for `--unit`).

Break-it-once: put `Stretch_UnderOneSecond` back in the default run's filter and show `./runtests.sh --unit` lists it
(`--list-tests`); then restore.

## Task 3: the broker test that timed out on macOS (#288)

`TswapTests/BrokerServerTests.cs`, `AFailedUnlock_AlsoEndsTheRunOfTimeouts` (:648), failed once on `macos-latest`
(run 43210413982): the third request, whose unlock should fail at once, got no answer within the harness's 30 s guard
while two earlier unlocks hang on an incomplete `TaskCompletionSource`.

Use the superpowers `systematic-debugging` skill: find the root cause **before** changing anything. Two candidates
from the issue:

1. **A real broker bug:** the broker serialises unlocks, so a new unlock waits behind a cancelled one that is still
   running. Then a failing TPM answer can't get through while an earlier unlock hangs: fix the broker so a timed-out
   unlock no longer blocks the next one (or document why it must), with a test that reproduces the wait
   deterministically (a hang source the test controls, no timing).
2. **A missing wait in the test:** the test sends the third request before the broker has finished handling the
   timeouts (a clock advance it needs, the cancelled unlocks' completion). Then the test waits on that concrete
   condition first.

Reproduce it deterministically before fixing (for example by holding the earlier unlocks longer, or by stepping the
fake clock in a different order), and say in the commit message which it was and how you showed it. If you can't
reproduce it and can't find the cause from the code, stop and report what you checked; don't add a longer guard or a
retry.

## Task 4: platform-only tests report Skipped, not Passed (#181)

48 tests in `TswapTests` start with `if (OperatingSystem.IsWindows()) return;`, `if (!OperatingSystem.IsLinux())
return;` or similar (`git grep -n -E 'if \(!?OperatingSystem\.Is(Windows|Linux|MacOS)\(\)\)\s*return;' -- TswapTests`;
recount on the base). On the other platforms they report **Passed** while asserting nothing, so a Windows or macOS run
claims coverage it doesn't have.

- Add attributes in the test project (no new package; the suite is on xUnit 2): `[UnixFact]`/`[UnixTheory]`
  (skipped on Windows), `[LinuxFact]`/`[LinuxTheory]` (skipped except on Linux), and `[WindowsFact]`/`[MacFact]` only
  if a guard needs them. Each is a `FactAttribute`/`TheoryAttribute` subclass that sets `Skip` to a reason when the
  platform doesn't match. The reason names the platform and, where the test's comment says why (SUDO_USER is
  Unix-only; macOS resolves ApplicationData through the OS), that too.
- Convert every guard that is the **first statement** of a test: remove the guard, change `[Fact]`/`[Theory]` to the
  matching attribute. Nothing else in the test changes. A guard that is **not** the first statement (a test that
  asserts something on every platform and only part of it is platform-specific) stays as it is; list those in the
  commit message.
- Tests with other skip conditions (an environment variable, a hardware category) stay as they are.

Tests: a self-test class for the attributes (`PlatformFactTests`): on each platform, the attribute's `Skip` is null
exactly where it should run and a non-empty reason elsewhere (assert on the attribute instance's `Skip` property,
which needs no platform switching). Then the evidence: the Linux run's totals don't change (same number of passed
tests, quote before and after); CI's Windows and macOS jobs will show the skips (you can't run those here; say so).

Break-it-once: make `UnixFactAttribute` never set `Skip`; the self-test fails.

## Task 5: the leak check catches secrets next to punctuation (#258)

`TswapTests/KeyMaterial.cs`, `AssertNone`: the hex and base64 checks are anchored (`^…$`), and the joined check strips
only `-` and `:`, so `key 0123…EF.` or `(q83v-…-7xI=)` passes; a token whose last `/`-segment has a `.` is treated as
path-shaped and skipped.

- Trim leading and trailing punctuation (`.,;:!?()[]{}"'` and backtick) from each token before every check, then also
  check the `/`-segments of the trimmed token.
- A token that is path-shaped only because of trailing sentence punctuation is checked like any other token.

Tests (`TswapTests/KeyMaterialTests.cs`, additions only): `AssertNone` throws for a 32-hex key followed by `.`, for a
base64 key in parentheses, for a `-`-grouped key in parentheses with a trailing `=`, and for `/`-grouped key material
ending a sentence; `LetsOrdinaryOutputThrough` gains a bare hyphenated identifier case (`record-name-hash` style) and a
path ending in `.` that must still pass.

Then run the whole suite: a stronger check can find a real leak in existing output. If an existing test now fails,
**stop**: that is either a real leak (report it with the test name and what was printed, without printing any real
key material) or a false positive of the new rule (report the shape). Don't loosen the new rule to get green.

Break-it-once: remove the trim; the punctuation tests fail.

## Out of scope

Moving to xUnit v3, changing the 1 s budget, other flaky tests not named here, broker behaviour beyond what Task 3's
root cause needs.
