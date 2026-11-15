# Brief T23: tests that don't flake, don't claim coverage they don't have, and catch every leak

Issues: #262, #300, #288, #181, #258 (stevedcc/TokenSwap). Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then each issue (`gh issue view <n> -R stevedcc/TokenSwap --json title,body,comments`)
and the files each task names.

**Review history.** Round 1: MiMo and GLM-5.3, both "ready to implement: no". Both found Task 4's census wrong (the
one-line `git grep` sees 48 of about 684 guards; the house style puts `return;` on the next line), its break-it-once
unfireable on Linux and one guard (`if (OperatingSystem.IsLinux())`) that no attribute could express. Both refuted
Task 3's first candidate from `UnlockAsync`; MiMo also showed the trace's line 673 is the fourth request (the 503, not
the 502) and named a race between the fake clock and the arming of the unlock timeout. Changed: Task 3 now starts
from that race and must reproduce it deterministically before any fix, in test support only; Task 4 covers every
first-statement guard, in three commits, with a fifth attribute, the combined guards spelt out, a corrected evidence
line and a break-it-once that fails on Linux; Task 2 also moves `Argon2id_CompletesWithinBudget` (and pins its
parameters), puts the trait on the methods, adds AGENTS.md to the scope and fixes its break-it-once; Task 5 pins the
`/`-segment rule to "as it is" (degrouped, `tswap-fleet-reenrol-d0ae5afb` would be flagged) and trims segments too.
Round 2: MiMo and GLM-5.3, both "no" again. Both found Task 4's census still blind to combined and braced guards
(recounted: 727 sites, about 700 first statements) and the combined rule wrong for two shapes (`[LinuxFact]`,
`[MacFact]`, not `[UnixFact]`); GLM showed Task 3's "count of armed timers" can hang (checked: `WaitAsync` on a
completed task arms no timer) and its "event" variant can miss an arming that comes before the start. Changed: Task 3
now prescribes a baseline taken before each send (one added line per site) and a deterministic kept test; Task 4
gives the full census rule, a mapping for every combined shape, carves out `RecordStoreSelectiveReadTests:293`, adds
a sixth `[WindowsFact]`, the 50 `SshTestSkip.OnWindows` and 2 `OffLinux` guards, the CA1416 rule and the expected
Linux delta (16); smaller fixes in Tasks 1, 2 and 5.

One commit per task (Task 4: three, see there), test first where there is a behaviour to pin, a break-it-once check
per key test (name in the commit message which line you reverted and which test failed), `./runtests.sh --unit` after
each task, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or
`~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written.

**Never change an existing test's assertion.** Tasks 1-4 change how tests wait, where they run and how they report;
each says exactly what may change. If a task seems to need a changed assertion, stop and report why.

**Project rules that bind every task:** no `Thread.Sleep`, `Task.Delay` or wall-clock waits in tests; wait on a
concrete condition. Tests never read the real clock for anything they assert (owner rule, 2026-11-11). The one
standing exception is `Category=Perf` (Task 2): a performance requirement can only be measured on the real clock, so
those tests stay out of every default and CI run and are run on purpose on the owner's machines. Record that in
Task 2's commit message.

**Parallel work:** the #311 fields branch and brief T22 run at the same time. T23 touches only test files, the test
project, `runtests.sh`, `.github/workflows/ci.yml` and AGENTS.md's test paragraph (the last three Task 2 only); no
product source. The other branches' test files don't meet Task 4: `FieldMergeTests`, `FieldRulesTests` and
`FieldsCodecTests` don't exist at the base, and `RecordMergeV3Tests`, `RecordStoreV3Tests`, `RecordWritesTests`,
`ToCommentBlockScalarTests`, `RedactTests` and `RedactEngineTests` carry no platform guard (checked at f75be2b).

## Task 1: the zombie test waits for the exec (#262)

`TswapTests/PeerIdentityLivenessTests.cs`, `AZombie_ExitedButNotReaped_IsNotAlive`. The race (issue #262): the
grandchild is killed after the shell's `echo` but possibly before its `exec`, while the parent is still the shell,
which reaps it; the test then waits for a zombie that never appears.

Fix: before the kill, wait (with the test's existing `SpinWait.SpinUntil` style and timeout) until the parent has
exec'd, i.e. `/proc/<parent.Id>/comm` reads `sleep` (trimmed). Only then kill the grandchild. The assertion lines
stay exactly as they are.

Break-it-once: you can't make a race fire on demand; instead show the condition is load-bearing: replace
`exec sleep 300` with `sleep 300` in the shell script (the parent stays a shell that reaps), and the new wait times
out with its own message, not the zombie assertion. Name that in the commit message. Then build once
(`dotnet build TokenSwap.slnx`), start the unit tests as load in the background with `--no-build` (`runtests.sh`
always builds, which would rewrite `bin/` under the loop: `TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet test
TswapTests/TswapTests.csproj --no-build --filter '<runtests.sh's --unit filter>' &`), and while it runs, run the test
30 times in a row (`for i in $(seq 30); do TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet test
TswapTests/TswapTests.csproj --no-build --filter FullyQualifiedName~AZombie_ExitedButNotReaped_IsNotAlive; done`).
Quote the counts.

## Task 2: the Argon2 timing budgets stop gating shared CI runners (#300)

`TswapTests/StretchedPasswordTests.cs`, `Stretch_UnderOneSecond`, measures wall-clock time against a 1 s budget
(T17 ruling 1: unlocking with the vault password stays under a second on the owner's machines). On a busy shared CI
runner it failed at 1005 ms with no code change. The budget stays a requirement; this task moves where it is checked.

- Put `[Trait("Category", "Perf")]` on the **method** `Stretch_UnderOneSecond`, not the class (a class trait would
  take `Defaults_AreTheRulingOneParameters` and the behaviour tests out of every run). Its assertion and budget stay
  exactly as they are. `Stretch_AtTheMaximum_CompletesAndIsMeasured` asserts no time (length and non-zero only; it
  prints the measurement), so it stays where it is.
- `TswapTests/Argon2idTests.cs`, `Argon2id_CompletesWithinBudget` (the export KDF) is the same kind of check
  (`Elapsed < 3 s`) and would be the last wall-clock gate in CI: give it the same method trait, assertion unchanged.
  Nothing pins the export parameters today, so add a test in `Argon2idTests` that `ExportCrypto.DefaultArgon2idParams`
  is Argon2id, m 19456 (`19 * 1024`), t 2, p 1.
- Exclude `Category=Perf` from the default runs: `runtests.sh`'s default and `--unit` filters, and the `dotnet test`
  filter in `.github/workflows/ci.yml` (:117). Add `./runtests.sh --perf` (filter `Category=Perf`,
  `TARGET=./TswapTests/TswapTests.csproj`, like the other on-purpose modes) and add it to the usage line.
- `RunRedactionThroughputTests` (class-level `Perf` trait, gated on `TSWAP_PERF=1`) stays as it is. Without the
  variable it writes "Not measured" and passes; today it does that in every default run, afterwards only in `--perf`.
  Say in the header comment that `--perf` alone runs the Argon2 budgets and that the throughput measurement also needs
  `TSWAP_PERF=1` (and a Release build, per its doc comment).
- Document `--perf` in `runtests.sh`'s header comment beside the other modes, and in AGENTS.md's "Tests live in
  `TswapTests/`" paragraph (the only other living list of modes; the README has none): run it on the owner's machines
  before a release and after any change to `VaultPasswordParams` or the KDFs. Leave the `docs/briefs/` and
  `docs/superpowers/plans/` hits alone: they are records.
- What keeps guarding the parameters in every run: `StretchedPasswordTests.Defaults_AreTheRulingOneParameters`
  (m 65536, t 3, p 1) and the new export pin. Name both in the commit message.

Break-it-once: `./runtests.sh` reads only its first argument, so use `TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet
test TswapTests/TswapTests.csproj --no-build` directly (AGENTS.md's direct-run form), and run rather than
`--list-tests` (check first whether `--list-tests` honours `--filter` here; don't rely on it). `--filter "(<runtests.sh's new default filter>)&(FullyQualifiedName~Stretch_UnderOneSecond|FullyQualifiedName~Argon2id_CompletesWithinBudget)"`
runs no test; the same with `Category=Perf` in place of the default filter runs both. Then take the `Perf` exclusion
out of the default filter and show the first command runs both again; restore. Quote the summary lines.

## Task 3: the broker test that timed out on macOS (#288)

`TswapTests/BrokerServerTests.cs`, `AFailedUnlock_AlsoEndsTheRunOfTimeouts` (:648), failed once on `macos-latest`
(run 43210413982, commit e9ad3cc; the file there differs from the base only in two collection expressions above this
test). The trace's test frame is **:673**, `Assert.Equal(503, BrokerHarness.StatusOf(await again))`: the **fourth**
request, the one that must be abandoned at the unlock timeout, got no answer within the harness's 30 s real-time
guard. The issue reads that line as the 502 request; it isn't.

Use the superpowers `systematic-debugging` skill: find the root cause **before** changing anything. What the code
already rules out (both reviews checked it): the broker does **not** queue a new unlock behind a timed-out one.
`BrokerRequestHandler.UnlockAsync` releases `_unlock` in its `finally` on the timeout path before the 503 is written,
and the abandoned `Task.Run(read)` holds no gate. That an unlock holds the one-at-a-time gate for at most
`UnlockTimeout` is decision 1 (T8), not a bug; don't change it.

The hypothesis to confirm or refute (round 1, MiMo): a race between the test and the fake clock.
`FakeBrokerSecrets.Read` raises `UnlockStarted` inside the `Task.Run` read, and `WaitForUnlocksStartedAsync` resolves
there, but the unlock timeout's timer is created later, on the handler's thread, at
`await task.WaitAsync(_limits.UnlockTimeout, time)`. If the test's `_h.Clock.Advance(30 s)` runs first,
`BrokerManualClock.ManualTimer.Change` sets `Due` to the **already advanced** time plus 30 s; nothing advances again,
the timeout never fires and `await again` hangs until the guard. The fake read blocks a pool thread on `hang`
(`GetAwaiter().GetResult()`), so by the fourth request two abandoned reads hold pool threads on a 3-core runner, which
makes a preempted handler thread likelier; note that, but don't change the fake's blocking.

1. **Reproduce deterministically**, with a hang source the test controls and no timing: a `BrokerManualClock`
   option that holds `CreateTimer` for timers whose due time is the unlock timeout (`new BrokerLimits().UnlockTimeout`;
   `MaxQueueWait` is also 30 s but only arms for a queued request, which this block never makes), signals when the
   hold is entered and when the creation returns. Take the hold **before** `CreateTimer`'s `lock (_gate)`, or the
   test's own `Advance` deadlocks. Advance by 30 s while the creation is held, release, wait for "creation returned",
   and show the request is still pending and answers 503 only after a second `Advance` (the first advance was lost).
   If the hypothesis is wrong the repro shows it; then stop and report what you checked.
2. **Fix in test support only**, with a signal that has no hole. `BrokerManualClock` counts the timers created with
   the unlock timeout as due time (read under `_gate`). Each site reads that count **before** its send, and the
   helper (rename it, e.g. `WaitForUnlockArmedAsync(count, armedBefore)`) waits until `Unlocks >= count` **and** the
   count is above `armedBefore`, subscribing to both signals before checking either (as the current helper does for
   the start). Why this one and not the others: a bare "armed count ≥ unlocks" hangs, because `Task.WaitAsync` on a
   task that has already completed returns at once and arms no timer (checked on SDK 11.0.100:
   `Task.CompletedTask.WaitAsync(30 s, provider)` calls `CreateTimer` zero times), so the ungated 200/502 unlocks
   (:633, :667, :704) arm one or not by luck; "the next arming after subscribing" misses an arming that comes before
   the read starts (the handler can reach `WaitAsync` before the pool thread runs the read). With the baseline, every
   earlier timer was created before its response was read, so before the baseline, and the target unlock is gated, so
   it always arms. Making the fake's ungated reads wait for an arming instead would change a fake that eight test files
   share. The sites (each gains one line before the send; no other line changes): :569-570, :599-600, :626-627,
   :635-636, :659-660, :670-671, the `TimeoutAsync` local at :694-695 (used at :700 and :707), and :710-711 (advanced
   at :722). The helper's doc comment says it needs a gated read (an ungated one may never arm). No broker source
   change: a deadline armed microseconds after the read starts has no effect a user can see.
3. Keep the repro as a test of the helper, shaped so it is deterministic: with the creation held and the read
   started (both awaited on their signals), call the helper and assert its task **is not complete**; release, await
   it, `Advance` once, assert 503. Break-it-once: take the armed-count condition out of the helper; it then completes
   at once (its start condition already holds), and the "not complete" assertion fails every time.

If you can't reproduce it and can't find the cause from the code, stop and report what you checked; don't add a longer
guard or a retry. No test in the block changes an assertion.

## Task 4: platform-only tests report Skipped, not Passed (#181)

Platform guards in `TswapTests` make a test report **Passed** on the other platforms while asserting nothing. A
guard is an `if` whose condition calls `OperatingSystem.IsWindows()`, `IsLinux()` or `IsMacOS()` (alone or combined
with `||`/`&&`) and whose body is a bare `return;`: on the same line, on the next line (the house style), or as a
braced block that ends in `return;` (in `RunFileTokenTests` and `Libfido2SmokeTests` the block first writes a
`SKIPPED: …` note). Census at f75be2b (round 2): **727** sites in 73 files (47 one-line, 670 two-line, 10 braced);
688 test one platform (531 `IsWindows()`, 149 `!IsLinux()`, 6 `!IsWindows()`, 1 `!IsMacOS()`, 1 `IsLinux()`) and
39 combine; **about 700** are the first statement of a `[Fact]`/`[Theory]`. A line-based `git grep`, or one that
anchors on a single call, misses the combined and braced forms; inventory with a search that matches any condition
containing the call (`git grep -n -A1 -P '^\s*if \(.*OperatingSystem\.Is(Windows|Linux|MacOS)\(\)' -- TswapTests`,
keeping hits whose same line, next line or braced block ends in `return;`). Recount and quote yours; if it differs
from these by more than a handful, explain. Besides these, 50 tests start with `if (SshTestSkip.OnWindows(output))
return;` and 2 with `if (SshTestSkip.OffLinux(output)) return;` (`SshAgentTestSupport.cs`: true exactly on Windows,
exactly off Linux): platform guards behind a helper, converted too.

- Add attributes in the test project (no new package; the suite is on xUnit 2.9.3): `[UnixFact]`/`[UnixTheory]`
  (skip on Windows), `[LinuxFact]`/`[LinuxTheory]` (skip except on Linux), `[WindowsFact]` (`AgentServerTests:1166`,
  `BrokerCommandTests:226`, `CliEnvironmentTests:416`, `InitRecoveryKeyOutTests:371`, `InstallScriptUpgradeTests:261`,
  `RunFileTokenTests:439`), `[MacFact]` (`CliEnvironmentTests:388`, and the eight combined ones below) and
  `[NotLinuxFact]` (`BrokerContainerConfigTests:448`,
  `RealProbe_OffLinux_IsFalse`, which runs on Windows and macOS), plus the `Theory` form of any that a theory needs.
  Each is a `FactAttribute`/`TheoryAttribute` subclass whose `Skip` comes from one internal static method that takes
  the platform as an argument, so the self-test can ask it about every platform. The reason names the platform and,
  where the test's comment says why (SUDO_USER is Unix-only; macOS resolves ApplicationData through the OS), that too.
- Convert every guard that is the **first statement** of a test: remove the guard (its comment, or a braced block's
  `SKIPPED:` note, goes into the reason where it says why; drop any "until #181: reported as Passed …" part, which
  the conversion makes untrue, here and in `EndToEndTests:106`'s doc comment) and change `[Fact]`/`[Theory]` to the
  matching attribute. Nothing else in the test changes. A first-statement guard followed by other skip logic (an
  environment variable, a hardware category, a `CI_REQUIRE_*` check, as in `SecureEnclaveOwnerScopeTests` and
  `Libfido2SmokeTests`, or a second guard, as in `BrokerCommandTests`' `WithoutSudo_*` tests) converts too; the other
  logic stays in the body as it is. `SshTestSkip.OnWindows` converts to `[UnixFact]`, `OffLinux` to `[LinuxFact]`, the
  helper's note into the reason; delete either helper once nothing calls it. `SshTestSkip.WithoutKeyTools` and
  `SkillEvalTests.CanRun` (a tool or bubblewrap check, not only a platform) stay.
- **Combined guards** that are the first statement: the platform half moves to **the attribute that half means**,
  the other half stays as an early return with the same comment.
  - `IsWindows() || X` → `[UnixFact]` + `if (X) return;`: `|| Environment.IsPrivilegedProcess` in the sudo-refusal
    tests (AGENTS.md requires that half: Windows CI runs elevated), `|| !Socket.OSSupportsIPv6` in
    `BrokerClientTests:73`, `|| new UnixOwnership().EffectiveUid == 0` in `RunFileTokenTests:922`.
  - `!IsLinux() && !IsMacOS()` (13: `CommandTests`, `EndToEndTests`, `HelpTests`, `TouchNoticeTests`,
    `TwoYubiKeysTests`, `Libfido2SmokeTests`) → `[UnixFact]`: on the three platforms the suite runs on, "Linux or
    macOS" is "not Windows".
  - `!IsLinux() || !File.Exists("/dev/full")` (`BrokerServerTests:909`, `:926`) → `[LinuxFact]` +
    `if (!File.Exists("/dev/full")) return;`.
  - `!CanRun() || !IsMacOS()` (`SecureEnclaveNoTouchRoundTripTests:69/96/117/140`,
    `SecureEnclavePasswordRoundTripTests:75/98/127/154`; in the default and `--unit` runs) → `[MacFact]` +
    `if (!CanRun()) return;`.
  - `RecordStoreSelectiveReadTests:293` (`unreadableCopy && (IsWindows() || IsPrivilegedProcess)`) **stays as it is**:
    it skips one theory row, and an attribute covers the whole method, so converting would stop the other row running
    on Windows. List it.
  - The one inside a `switch` (`YubiKeyReenrolTests:1234`) is not a first statement.
- Guards that are **not** the first statement of a test (a test that asserts something on every platform, or a guard
  inside a branch, e.g. `EndToEndTests:334`, `InitRecoveryKeyOutTests:214`), and guards in helpers, constructors and
  `InitializeAsync`/`DisposeAsync` (about 27 sites), stay as they are; list them in the commit message.
- **CA1416.** A guard also tells the platform analyser the code below runs only there; an attribute doesn't. Where a
  conversion makes CA1416 warn (a `[MacFact]` test calling a `[SupportedOSPlatform("macos")]` helper, a `[UnixFact]`
  test calling `File.SetUnixFileMode`), put the matching `[SupportedOSPlatform(…)]`/`[UnsupportedOSPlatform("windows")]`
  on the test method (as `RunFileTokenTests:436` does). Never restore a guard or add a `NoWarn` for it. Quote the
  build's warning count on the base and after each commit: it doesn't rise.
- #181's second point (a Windows counterpart of the end-to-end APPDATA case) is out of scope: Windows resolves
  `ApplicationData` through the known-folder API, so the fresh-user case can't be set up from the environment there;
  `FreshUserWithoutDotConfig_VaultIsUnderHome_AndFoundFromAnotherFolder`'s skip reason says so.

Commits (the exception to one per task, so the diff stays reviewable): **4a** the attributes, `PlatformFactTests`, the
three tests named in #181 (`EndToEndTests:100`, `CliEnvironmentTests:47`, `StorageTests:53`) and the three
`// until #181` guards in `CliEnvironmentTests` (:388, :401, :416); **4b** the `Broker*` and `Agent*` files; **4c** the
rest (the `SshTestSkip` helpers go with their last caller). 4b and 4c are mechanical: no other edit in those files
beyond the CA1416 attributes.

Tests: `PlatformFactTests` asks the decision method about Linux, macOS and Windows for every attribute and asserts
`Skip` is null exactly where the test should run and a non-empty reason elsewhere; it also checks each attribute
instance on the current platform agrees with the method. Evidence per conversion commit: the Linux totals before and
after (`./runtests.sh --unit` and the full run). Expected: the total is unchanged apart from the new
`PlatformFactTests` cases, and **passed falls and skipped rises by exactly the converted tests (theory rows included)
whose guard returns on Linux** (the `WindowsFact`, `MacFact` and `NotLinuxFact` ones); nothing else moves. By the
census these are 16 facts: 2 in 4a (`CliEnvironmentTests:388`, `:416`), 3 in 4b (`AgentServerTests:1166`,
`BrokerCommandTests:226`, `BrokerContainerConfigTests:448`), 11 in 4c (`InitRecoveryKeyOutTests:371`,
`InstallScriptUpgradeTests:261`, `RunFileTokenTests:439` and the eight `SecureEnclave*RoundTripTests`), each counted
in the runs that include its class. Explain any other difference or stop. CI's Windows and macOS jobs will show
their skips (you can't run those here; say so).

Break-it-once: make the decision method never skip for `UnixFact`; the self-test's Windows case fails on Linux. Then
make `WindowsFactAttribute` never set `Skip`; the current-platform check fails. Restore both.

## Task 5: the leak check catches secrets next to punctuation (#258)

`TswapTests/KeyMaterial.cs`, `AssertNone`: the hex and base64 checks are anchored (`^…$`), and the joined check strips
only `-` and `:`, so `key 0123…EF.` or `(q83v-…-7xI=)` passes. A token whose last `/`-segment has a `.` counts as
path-shaped, so it gets only the per-segment check (each segment as it is, the trailing `.` still attached), never the
joined one, and `q83v-EjRW/eJCr-ze8S.` escapes.

- Trim leading and trailing punctuation (`.,;:!?()[]{}"'` and backtick; not `=`, so base64 padding survives) from each
  token before every check. Then apply the existing rules to the trimmed token: as it is; if path-shaped, each `/` or
  `\` segment; otherwise joined. A token that was path-shaped only because of trailing sentence punctuation is now
  checked like any other token.
- Segments are checked **as they are, never degrouped** (the rule the doc comment already states): degrouped,
  `tswap-fleet-reenrol-d0ae5afb` becomes 25 base64-alphabet characters and three of the five
  `LetsOrdinaryOutputThrough` cases would fail. Trim each segment's punctuation too (so `/tmp/(0123…EF)/x.json` is
  caught), and check the segments of a token that is not path-shaped as well (so `secret_name/0123…EF.` is caught).
  Update the doc comment to say exactly this, and that the trim set is closed: `=`, `<`, `>` and `*` are not trimmed,
  so a key printed as `<0123…EF>` or `**…**` is outside this check.

Tests (`TswapTests/KeyMaterialTests.cs`, additions only): `AssertNone` throws for a 32-hex key followed by `.`, for a
base64 key in parentheses, for a `-`-grouped key in parentheses with a trailing `=`, for `/`-grouped key material
ending a sentence, for a hex key in parentheses inside a path, and for `secret_name/<32 hex>.`;
`LetsOrdinaryOutputThrough` gains a bare hyphenated identifier that degroups to under 24 characters
(`record-name-hash` style; a bare `tswap-fleet-reenrol-d0ae5afb` outside a path is flagged today and stays flagged:
say so in a comment) and a path ending in `.` that must still pass.

Then run the whole suite: a stronger check can find a real leak in existing output. Shapes it newly exposes: a
relative path with a 32+-hex or 24+-base64 segment (`records/<64-hex>` record file names) and a quoted or bracketed
24+-character alphanumeric run; the two callers (`YubiKeySetupTests`, `YubiKeyReenrolTests`) print neither today. If
an existing test now fails, **stop**: that is either a real leak (report it with the test name and what was printed,
without printing any real key material) or a false positive of the new rule (report the shape). Don't loosen the new
rule to get green.

Break-it-once: remove the trim; the punctuation tests fail.

## Out of scope

Moving to xUnit v3, changing the 1 s budget, a CI step that runs `--perf` (a step that can't fail gates nothing, and a
shared runner's number says nothing about the owner's machines), other flaky tests not named here, any broker source
change, the Windows APPDATA counterpart of #181.
