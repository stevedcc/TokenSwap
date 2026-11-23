# Brief T53: the broker test log is thread-safe, and PTY tests fail or skip instead of passing silently (#383, #362)

Issues: https://github.com/stevedcc/TokenSwap/issues/383 and https://github.com/stevedcc/TokenSwap/issues/362 (with its
comment). Milestone 0.3.3. Base: `origin/main` at 3e22bcb. Read AGENTS.md and CLAUDE.md first, then
`TswapTests/BrokerTestSupport.cs` (`ObservedLog`, `BrokerHarness`), `TswapCore/Broker/BrokerLog.cs` (`Write`, lines
166-200), `TswapTests/PlatformFacts.cs`, `TswapTests/PlatformFactTests.cs`, and in `TswapTests/EndToEndTests.cs`:
`RunTswapUnderOuterPty`, `OpenPty`, `RunTswapWithPtyCtrlC`, `EnrolOnPty`, `OpenPtyUnavailable`, the ten tests named
below and the four `*_WindowsConPty` tests.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change**, except the one message named
in Task 3 (same condition, more text). Test-only: no file outside `TswapTests/` changes except the docs in Task 4; if a
task seems to need product code, stop and report.

## What is wrong (evidence)

**#383.** CI run 44895802497 (ubuntu-24.04) failed
`BrokerContainerGateTests.AForwarderThatThrowsAfterTheHeaders_AbortsTheConnection_AndLogsTheStatusSent` with
`ArgumentOutOfRangeException: Operations that change non-concurrent collections must have exclusive access` at
`StringBuilder.ToString()` in `ObservedLog.WaitForAsync`. `ObservedLog` (`BrokerTestSupport.cs:139-166`) is a
`StringWriter`: `WriteLine` calls `base.WriteLine(value)` outside `lock (_waiters)` (line 145), so the broker's thread
appends while a test thread reads. The issue's one-line fix (move the write into the lock) is not enough:

- 89 call sites in `TswapTests` read `LogText.ToString()` directly (e.g. `BrokerContainerGateTests.cs:644`,
  `BrokerShortSecretWarningTests.cs:50`), which `StringWriter` does without any lock, while the broker may still be
  logging another request.
- `BrokerTemplateNullHostTests.cs:70` clears it with `_h.LogText.GetStringBuilder().Clear()`, also unlocked.
- More than one writer can share one `ObservedLog`: `BrokerContainerConfigTests.cs:426` builds a second `BrokerLog`
  over `h.LogText`, and each `BrokerLog` serialises only its own lines (`BrokerLog.cs:172`).

All writers use `WriteLine(string)`: `BrokerLog.Write` (`BrokerLog.cs:176`, `:194`) and `YubiKeyLock`
(`TswapCore/Vault/YubiKeyLock.cs:127`, `:141`, `:199`; `YubiKeyLockWiringTests.cs:355` gives it an `ObservedLog` written
from a second thread).

**#362.** Seven `[UnixFact]`/`[LinuxFact]` tests in `EndToEndTests.cs` return with no assertion when `OpenPty`
(`:783-792`) finds neither libc's nor libutil's `openpty` and returns its `int.MinValue` sentinel:
`Run_FirstLineOfStdoutNotDropped_UnixPty` (`:461`, return at `:471`), `EndToEnd_Run_OtherSecretMasked_RealPty`
(`:595`, `:604`), `EndToEnd_Run_PromptVisible_WithPemInVault` (`:619`, `:628`),
`Run_CommandNotFound_UnixPty_Exits127WithDiagnostic` (`:639`, `:645`) through `RunTswapUnderOuterPty` returning null
(`:493-494`); `Add_`/`Export_`/`Import_CtrlC_…_PrintsCancelledAndExits130` (`:1277`, `:1290`, `:1306`; returns at
`:1283`, `:1298`, `:1315`) through `RunTswapWithPtyCtrlC` returning -2 (`:809`). On Linux and macOS `openpty` always
exists, so its absence is a broken environment; T34's three `Enrol_*_OnARealTerminal_*` tests (`:1204`, `:1223`,
`:1243`) already fail there via `OpenPtyUnavailable()` (`:1180`), and they pass on main's CI legs, so CI does reach
`openpty`.

The same silent pass exists on the other side: the four ConPTY tests, `Run_CompoundCommand_RedactedOutput_WindowsConPty`
(`:1332`), `Glyphs_ReachTheConsole_WindowsConPty` (`:1381`), `NonAsciiValue_Redacted_WindowsConPty` (`:1408`) and
`Run_NoChildTitle_WindowsConPty` (`:1445`), are plain `[Fact]`s that `return` when not on Windows 10 1809+ (`:1334`,
`:1383`, `:1410`, `:1447`), so Linux and macOS report them Passed. ConPTY genuinely cannot exist there or on Windows
before build 17763; that is a skip with a reason (#181's rule, `PlatformFacts.cs:28-31`), not a pass. xUnit here is
2.9.3 (`TswapTests.csproj:16`): a test cannot skip itself at run time, so the decision goes in the attribute, as
`PlatformFacts` does.

Kill and reap (the issue's question): neither `RunTswapUnderOuterPty` nor `RunTswapWithPtyCtrlC` asserts anything
inside (checked: no `Assert` between `:486-584` and `:804-929`); the callers assert after the child was waited for or
killed (`:581-585`, `:915-919`). But the kill sits after the loop, not in a `finally`, so an exception in the loop
leaves the child running (`using` only disposes the `Process`), and `RunTswapUnderOuterPty` starts the process
(`:531`) before its `try`, so a throw from `Process.Start` leaks both fds. `EnrolOnPty.Run` (`:1051-1081`) has the
right shape. And `EnrolOnPty.SetUp`'s `Assert.Equal(0, init.ExitCode)` (`:967`) reports only `0 ≠ N`, without the
output it has just read (the issue's comment).

## Task 1: `ObservedLog` is a locked `TextWriter` (#383)

Replace `ObservedLog` in `BrokerTestSupport.cs` (same name, same file) with `public sealed class ObservedLog : TextWriter`
that owns its text:

- fields `private readonly Lock _gate = new();`, `private readonly StringBuilder _text = new();`, the existing
  `_waiters` list;
- `Encoding => Encoding.Unicode` (what `StringWriter` reports);
- overrides, each doing its whole work inside `lock (_gate)`: `Write(char)`, `Write(string?)`,
  `Write(char[] buffer, int index, int count)`, `WriteLine(string?)` (appends `value` and `NewLine`, then completes and
  removes every waiter whose text `value` contains, ordinal: today's matching rule), `ToString()` (a snapshot);
  `TextWriter`'s other overloads (spans, formats, async) all end in these, so nothing reaches `_text` unlocked;
- `public void Clear()` (locked), and `BrokerTemplateNullHostTests.cs:70` calls `_h.LogText.Clear()`;
- `WaitForAsync(string text)` keeps its shape: under the lock, complete at once if the text is already there, else
  register; the `TaskCompletionSource` keeps `RunContinuationsAsynchronously`, so no continuation runs under the lock;
  the 30 s `WaitAsync` stays as the hang guard. This is the way to wait on a log line; a test that asserts a line after
  `WaitForLogAsync` for it now reads a consistent snapshot.

A plain `lock` on `System.Threading.Lock`, not `SemaphoreSlim` (the project prefers awaitable locks where awaiting is
possible): `TextWriter.WriteLine` is synchronous, product code calls it while holding its own lock (`BrokerLog.cs:172`)
or inside `YubiKeyLock`'s synchronous wait, and the critical section is an in-memory append with no I/O or await.
Say so in a comment above `_gate`, as `BrokerLog.cs:44` does.

Tests, a new `TswapTests/ObservedLogTests.cs` (unit suite, no trait):

| Test | Steps | Outcome |
|---|---|---|
| `WaitForAsync_TextAlreadyWritten_CompletesAtOnce` | `WriteLine("alpha beta")`, then `WaitForAsync("beta")` | the task `IsCompletedSuccessfully` without awaiting |
| `WaitForAsync_TextWrittenLater_CompletesOnThatLine` | `t = WaitForAsync("gamma")`; `WriteLine("other")`; then `WriteLine("x gamma y")` | `t` not completed after the first line (checked before the second write); `await t` completes |
| `EveryWriteOverload_ReachesTheText` | `Write('a')`, `Write("b")`, `Write(new[] {'c','d'}, 1, 1)`, `Write("e".AsSpan())`, `WriteLine("f")`, `WriteLine(42)` | `ToString()` equals `"abde" + "f" + NewLine + "42" + NewLine` |
| `Clear_EmptiesTheText` | `WriteLine("x")`, `Clear()` | `ToString()` is `""`; a later `WaitForAsync("x")` is not completed |
| `ConcurrentWritersAndAReader_KeepEveryLineWhole` | 4 writer threads, started together by a `Barrier`, each `WriteLine($"w{i}-{j}")` for j in 0..4999, while a fifth thread calls `ToString()` in a loop until the writers are joined and a sixth awaits `WaitForAsync("w3-4999")` | no thread threw (collect exceptions, assert the list empty); `ToString()` split on `NewLine` (empty entries removed) is exactly the 20,000 expected lines as a set; the waiter completed |

Break-it-once: move the append in `WriteLine(string?)` out of the lock; `ConcurrentWritersAndAReader_KeepEveryLineWhole`
must fail. It is a race: run it up to five times and report how many failed (at least one must). Second: drop the lock
from `ToString()`; same test, same report.

## Task 2: PTY harnesses fail when `openpty` is missing, and reap on every path (#362)

- Extract the probe order from `OpenPty` into `internal static int OpenPtyThrough(Func<int> libc, Func<int> libutil)`
  in `EndToEndTests`: call `libc`; on `DllNotFoundException` or `EntryPointNotFoundException` call `libutil`; on either
  again, `throw OpenPtyUnavailable()`; any other exception propagates; a returned value (including < 0) is returned.
  `OpenPty` calls it with lambdas over local fds and copies them to its `ref` parameters. The `int.MinValue` sentinel
  and every check of it go.
- `RunTswapUnderOuterPty` returns `(int ExitCode, string Output)` (not nullable); `RunTswapWithPtyCtrlC` no longer has
  a -2 result; `EnrolOnPty.Run` returns `(int ExitCode, string Output, bool Killed)` (not nullable). Update their doc
  comments and `OpenPtyUnavailable`'s (no sentinel any more; its message stays exactly as it is).
- Callers: the four `RunTswapUnderOuterPty` tests deconstruct directly (`var (exitCode, output) = …`), the three
  `*_CtrlC_*` tests lose their `if (exitCode == -2) return;` line, T34's three `Enrol_*` tests deconstruct directly
  instead of `is not var … throw OpenPtyUnavailable()`. No assertion in any of the ten changes.
- Reaping: in `RunTswapUnderOuterPty` and `RunTswapWithPtyCtrlC`, follow `EnrolOnPty.Run`: `Process? process = null`
  declared before a `try` that starts it; the `finally` kills the tree if it has not exited, waits up to 10 s, disposes
  it, then closes the fds. The normal path's waits (`:581`, `:915`) stay as they are.

Tests, a new `TswapTests/OpenPtyProbeTests.cs` (unit suite, no trait; it calls the static method, so no binary is
needed):

| libc probe | libutil probe | Outcome |
|---|---|---|
| returns 0 | counts calls | 0; libutil not called |
| returns -1 | counts calls | -1; libutil not called |
| throws `EntryPointNotFoundException` | returns 0 | 0 |
| throws `DllNotFoundException` | returns 0 | 0 |
| throws `EntryPointNotFoundException` | throws `DllNotFoundException` | `Xunit.Sdk.FailException` whose message contains `openpty is not available here` |
| throws `InvalidOperationException` | counts calls | that exception; libutil not called |

Break-it-once: (a) make `OpenPtyThrough` return `int.MinValue` instead of throwing; the fifth row must fail. (b) The
real check: in `OpenPty`, replace both lambdas with `() => throw new EntryPointNotFoundException()`, then run
`dotnet test TswapTests/TswapTests.csproj --filter "Category=E2E&(FullyQualifiedName~UnixPty|FullyQualifiedName~RealPty|FullyQualifiedName~WithPemInVault|FullyQualifiedName~CtrlC_|FullyQualifiedName~OnARealTerminal)"`
(`TswapBinaryFixture` builds the binary): all ten tests must fail with the `openpty is not
available` message (on Linux `EndToEnd_Run_PromptVisible_WithPemInVault` is the `[LinuxFact]` one). Do the same on the
base commit first and record that the seven passed there: that is #362 reproduced.

## Task 3: ConPTY tests skip where ConPTY can't exist; `SetUp` shows init's output

In `PlatformFacts.cs`:

- `public static string? ConPtySkipReason(Version windowsVersion)`: null when `windowsVersion >= new Version(10, 0,
  17763)`, else exactly `$"Needs ConPTY (Windows 10 1809, build 17763, or later); this Windows is {windowsVersion}."`
- `public sealed class WindowsConPtyFactAttribute : FactAttribute` with
  `Skip = PlatformFacts.SkipHere(PlatformRequirement.Windows, why) ?? PlatformFacts.ConPtySkipReason(Environment.OSVersion.Version)`
  (the second part is reached only on Windows, where .NET reports the real version). `PlatformRequirement` and
  `SkipReason` do not change.

The four `*_WindowsConPty` tests change `[Fact]` to `[WindowsConPtyFact]`, and their early `return` becomes
`if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) throw new UnreachableException("[WindowsConPtyFact] runs this test only on Windows 10 1809 or later");`
(it keeps the platform analyser satisfied and can never pass silently). Their assertions do not change.
`WindowsLegs` and T46's batch legs (`:1531`, `:1621`) stay as they are: off ConPTY they still run and assert the
redirected leg.

`EnrolOnPty.SetUp` (`:967`): replace `Assert.Equal(0, init.ExitCode)` with
`if (init.ExitCode != 0) Assert.Fail($"the host's init exited {init.ExitCode}\nstdout:\n{stdout.Result}\nstderr:\n{stderr.Result}");`.
This is the one changed assertion: the same condition, with the output in its message (the issue's comment asks for
it). The output carries no secret: test mode with `--tpm --no-password --no-recovery`.

Tests, in `PlatformFactTests.cs` (new tests only):

| Input | Outcome |
|---|---|
| `ConPtySkipReason(new Version(10, 0, 17763))`, `(10, 0, 26100)`, `(10, 0, 20348, 1)` | null |
| `(10, 0, 17134)`, `(10, 0, 14393)`, `(6, 3, 9600)` | the exact message with that version |
| `new WindowsConPtyFactAttribute("w").Skip` on this machine | equals `SkipReason(Windows, Current, "w") ?? (Current is Windows ? ConPtySkipReason(Environment.OSVersion.Version) : null)` |

Break-it-once: change 17763 to 17764 in `ConPtySkipReason`; the `(10, 0, 17763)` row must fail. On Linux, list the four
ConPTY tests with `--logger "console;verbosity=normal"` before and after: Passed before, Skipped with "Runs on
Windows only" after; put both lines in the commit message. The Windows leg is CI's; say in the report that the four
must show Passed there.

## Task 4: docs

AGENTS.md, after the "Sudo-refusal tests" paragraph, a new paragraph: "**PTY tests**: on Linux and macOS `openpty`
must exist, so the PTY harnesses in `EndToEndTests` fail (never return early) when it is missing; ConPTY tests use
`[WindowsConPtyFact]`, which skips with a reason off Windows and before Windows 10 1809. Broker tests read the log
through `ObservedLog` (thread-safe; wait for a line with `WaitForLogAsync` before asserting on it)." In the report,
no release-note line (tests only).

## Out of scope

- Tests that assert a log line without waiting for it first (none is known to flake; file an issue if one does).
- `YubiKeyLockTests`' own `StringWriter` (`YubiKeyLockTests.cs:21`, single-threaded).
- Moving to xUnit v3 for run-time skips; the RedactingPty package's own PTY code; any product code.

## Amendments (round 1; GLM and MiMo: ready to implement)

- **A1 (MiMo I1): the other ten silent passes, same pattern.** `TswapTests/ControllingTerminalPtyTests.cs`'s eight
  `[Fact]`s (`ReadSecret_AfterDotNetReadLine_EnterEndsThePin`, `…_BackspaceErases`, `ReadSecret_PutsTheTerminalBackAsItWas`,
  `ReadSecret_Resume_DiscardsWhatWasTypedBeforeTheStop`, `ReadLine_AfterDotNetReadLine_EnterEndsTheAnswerAndItIsEchoed`,
  `Typeahead_DiscardUnix_DropsWhatWasTypedBeforeIt`, `ReadLine_DiscardsWhatWasTypedBeforeTheRead`,
  `ReadSecret_DiscardsWhatWasTypedBeforeTheRead`) become `[UnixFact("no pseudo-terminals on Windows")]`;
  `EndToEndTests.Run_SecretRedactedFromErrorOutput` becomes `[UnixFact(...)]` and `RunEnv_ValueNotInArgv`
  `[LinuxFact("/proc/<pid>/cmdline is Linux's")]` (use the attribute names `PlatformFacts.cs` actually has; if `LinuxFact`
  doesn't exist, use the existing mechanism for a Linux-only fact or stop and report). Each early `return;` becomes
  `throw new UnreachableException(...)` as in Task 3. No assertion changes. One commit (Task 3b). Evidence instead of a break-it-once (the skips only show off Linux): the
  Linux test list still runs all ten (show their Passed lines), and the report names the skips the controller checks in
  the Windows and macOS CI logs.
- **A2 (MiMo M1).** Update the doc comments of the four ConPTY tests (`EndToEndTests.cs` near 1376, 1405, 1441, and the
  fourth) to say they are skipped off Windows and before 1809 by `[WindowsConPtyFact]`.
- **A3 (MiMo M2, GLM M1).** The flaky test's class is `BrokerInternalErrorTests` (declared inside
  `BrokerContainerGateTests.cs`); use the class name in commit messages and the report.
- **A4 (MiMo M3).** `ObservedLog.Encoding` returns `new UnicodeEncoding(false, false)` (what `StringWriter` reports).
- **A5 (MiMo M4).** `[WindowsConPtyFact]` takes an optional `why` like `UnixFactAttribute(string? why = null)`; call sites
  pass none. `ConPtySkipReason` lives in `PlatformFacts`. Task 2's base-commit break-it-once forces `OpenPty`'s
  `int.MinValue` path (the base has no `OpenPtyThrough`).
- **A6 (MiMo M5).** `SpellingTests` scans `.cs` comments too: British spelling in new comments.
- **A7 (GLM M3).** In `RunTswapWithPtyCtrlC`, the `using var process` goes; mirror `EnrolOnPty.Run` exactly (process
  declared before the `try`, the normal-path wait inside it, kill/wait/dispose in `finally` before the descriptors close).
- **A8 (GLM M4).** `Clear()` keeps registered waiters (today's behaviour); say so in the report.
