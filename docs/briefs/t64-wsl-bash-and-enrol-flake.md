# Brief T64: `run` refuses WSL's `bash.exe`; the Enter-gate test waits for the real key read (#411, #413)

Milestone 0.3.3. **Base: `origin/main` after T58 (PR #433) merges.** This brief was drafted on `brief/t58` at a0836c2
(this brief's branch, `brief/t64`, starts there), and every line number below is T58's version of the file. T58 edits
`Validation.cs`, `RunCommand.cs` and `EndToEndTests.cs`. If T58 changes again before it merges, look the cited lines up
again before you start.

Read AGENTS.md and CLAUDE.md first, then:
- `TswapCore/Validation.cs`: `GetBlockedInvocation` (`:672-800`), its `bash` entry (`:488`), `CheckWsl` (`:940-1027`),
  `ProgramPositions` (`:269-312`), `WindowsFileName` (`:1437-1450`), `ProgramName` (`:1457-1464`).
- `TswapCore/MsysTarget.cs`: `Probe`, `Resolve` (`:43-60`), `IsMsys2` (`:86-97`). You only call these. The file
  belongs to T62.
- `TswapCli/Commands/RunCommand.cs`: the pre-unlock check (`:87-89`), the check after substitution (`:254-269`), the
  MSYS2 start (`:283-298`), `Reason` and `ThrowIfBlocked` (`:636-648`).
- `TswapCli/SystemConsole.cs`: `ReadLineWithoutEcho` (`:55-95`).
- Tests: `TswapTests/EndToEndTests.cs` (`PtyDriver`, `:1285-1367`; the three `Enrol_*AtTheEnterGate_*` tests and
  `Enrol_CtrlCAsSoonAsThePromptShows_…`, `:1400-1524`), `RunMsysTargetTests`, and `MsysTargetTests.FakeProbe`
  (`:22-33`).

One commit per task, test first, and a break-it-once check per key test: name in the commit message the line you
changed and the test that failed. Run `./runtests.sh --unit` after each task and the full `./runtests.sh` at the end.
No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Commit with explicit paths. No push, merge or rebase. If the
brief can't be built as written, stop and report. **No existing test's assertions change.** If an existing test fails
on an assertion, stop and list it. (The search for Windows-OS run tests with a `bash` word finds only
`RunMsysTargetTests`. Its probe has no WSL `bash.exe` and resolves `bash` to Git's, so those tests are unaffected.)

**File ownership.** T62 owns `MsysTarget.cs`, `SecretVariants.cs`, `MsysQuotingTests`, `DependencyPinningTests`,
`ReleasePackagingTests` and `SignWindowsScriptTests`, plus `docs/scripts.md:46-64` and
`docs/security-model.md:765-772`. T63 owns `SecretMatcher.cs`, `BrokerRedactor.cs`, `BrokerTemplateOutput`,
`FieldSecretCheck` and `docs/broker-threat-model.md`. Do not edit any of these, with one exception: Task 4 changes one
sentence in `docs/scripts.md:53-54`. New tests go in new test classes.

## What is wrong (evidence)

### #413: the second key-read wait returns before the read has started

The measurement was repeated for this brief, on .NET 11.0.100, Linux, a pty under `setsid`. A scratch program repeats
the gate's steps twice: write the prompt, set `Console.TreatControlCAsInput = true`, run `ReadKey` until Enter, then
reset the setting. A driver read the slave's `c_lflag` at each step:

| Step | Round 1 | Round 2 |
|---|---|---|
| prompt written | `ICANON ISIG ECHO` | **`-icanon ISIG -echo`** |
| after `TreatControlCAsInput = true` | `-icanon -isig -echo` | `-icanon -isig -echo` |
| inside `ReadKey` | `-icanon -isig -echo` | `-icanon -isig -echo` |
| after the reset | `-icanon ISIG -echo` | `-icanon ISIG -echo` |

The first `TreatControlCAsInput = true` turns ICANON off, and ICANON stays off. Only ISIG comes back on between reads.
`ReadLineWithoutEcho` discards typeahead at `SystemConsole.cs:60` and turns ISIG off at `:62`. `PtyDriver.WaitForKeyRead`
(`EndToEndTests.cs:1331-1340`) waits only for ICANON off (`:1334`, `Icanon` at `:1342`). In
`Enrol_TypedTextAtTheEnterGate_OnARealTerminal_IsNotShownAndAsksAgain` (`:1438`), that is already true for the second
wait (`:1454`) as soon as the second prompt shows, because the first round left ICANON off. The Ctrl-C at `:1455` can
then arrive before `:62`:
- **Linux** (a controlling terminal, `setsid`): ISIG makes the Ctrl-C a SIGINT, and tswap dies without "wasn't
  confirmed". This is the 2026-11-23 failure ("never appeared before tswap exited").
- **macOS** (no controlling terminal): the byte is dropped or eaten by the discard at `:60`. The gate then waits until
  the test's 60 s deadline: the 2026-11-24 CI failure ("never appeared").

ICANON and ISIG are both off only after `:62`, which comes after the discard. ISIG is back on before the next prompt is
written (`SlotEnrol.cs:293-310`: the reset runs in `ReadLineWithoutEcho`'s `finally`, before the retry text and the
prompt). The product is correct. Only the test's wait is wrong.

### #411: WSL's `bash.exe` reparses `run`'s command line with `bash -c`

**Parser-first**, from microsoft/WSL at 65719878ad3c (the commit T51 used), `src/windows/common/WslClient.cpp`:
- `WslClient::Main` (`:1847`) gets `GetCommandLineW()` (`src/windows/wsl/main.cpp:19`). It takes the **stem of the
  command line's first word**, lowercased (`:1887-1890`), and for `bash` calls `BashMain` (`:1900-1904`). The entry
  point is chosen by the name used, not by the file: one binary, started as `bash`.
- `BashMain` (`:157-206`) calls `ParseLegacyArguments` (`:1029-1064`). That function strips the program word, then
  optionally a distribution GUID, then optionally `~`. With nothing left, it starts `/bin/bash` as a login shell
  (`-bash`), which reads stdin. Otherwise it runs **`/bin/bash -c "/bin/bash <the rest of the raw command line>"`**:
  bash parses the Windows command line text as shell code. There is no exec mode and no option that avoids it.
- So any argument tswap passes, a substituted value included, is parsed again by a Linux shell. `$(…)`, backticks,
  `;` and globs in a value run or expand. `bash.exe ./x.sh {{pw}}` is as unsafe as `wsl ./x.sh {{pw}}`, which T51
  refuses. Every use of WSL's `bash.exe` must be refused.
- Where it lives: System32's `bash.exe` (Windows' WSL component), and an **App Execution Alias** `bash.exe` for
  `wsl.exe` declared by the WSL app package (`msixgluepackage/AppxManifest.in:45-47`), which sits in
  `%LOCALAPPDATA%\Microsoft\WindowsApps` on `PATH`. A WSL `bash.exe` can therefore live outside System32. Telling the
  two apart by folder name would fail open.

**How `run` finds it.** Both of `run`'s Windows start paths use `CreateProcess` with no application name
(`Validation.cs:369-372`; T55 relies on the same). `MsysTarget.Resolve` (`:43-60`) models that search: tswap's folder,
the current folder, **System32**, `System`, the Windows folder, then `PATH`, with `.exe` appended to a name without a
dot. A bare `bash` (or `BASH`, `bash.exe`, `Bash.EXE`) therefore resolves to System32's `bash.exe` wherever WSL is
installed, ahead of Git on `PATH`. An absolute or relative path is taken as is: `C:\Windows\System32\bash.exe`,
`c:/windows/system32/BASH`, and `C:\Windows\Sysnative\bash.exe` (Sysnative is visible only to 32-bit processes; tswap
ships win-x64 only). `SysWOW64` has no `bash.exe`.

**Telling it from Git Bash and MSYS2.** `MsysTarget.IsMsys2` (`:86-97`) is the positive test T55 already relies on:
`msys-2.0.dll` beside the file, or Git's `bin\bash.exe`/`bin\sh.exe` launcher with `usr\bin\msys-2.0.dll` under its
parent. WSL's launcher can't be recognised positively, because it is `wsl.exe` under another name. The rule is
therefore **fail closed: on Windows a `bash` is allowed only when it resolves to a file `IsMsys2` accepts.**

**Today.** `bash` is a plain shell to the guard (`Validation.cs:488`, `ShellSyntax`), so `bash ./x.sh {{pw}}` passes.
Only `wsl` gets wsl.exe's walk (`:859-861`, `CheckWsl`). The MSYS2 start (`RunCommand.cs:288-298`) quotes for Git
Bash. For any other `bash.exe` it does nothing (`docs/scripts.md:53-54`: "which `run` leaves alone").
`docs/security-model.md:186` lists #411 as a known gap.

**Off Windows.** Inside WSL, `PATH` includes `/mnt/c/Windows/system32` by default (`appendWindowsPath`). A Linux tswap
running `bash.exe` (or `/mnt/c/Windows/System32/bash.exe`) therefore starts the same launcher through WSL's interop.
On Linux and macOS a `bash.exe` word is never the Linux shell, so refusing it costs nothing.

## Task 1 (#413): `WaitForKeyRead` waits for ICANON and ISIG off

New file `TswapTests/TerminalLocalFlags.cs`:

```csharp
/// <summary>Brief T64 (#413): the c_lflag bits the PTY tests read. Linux: ISIG 0x1, ICANON 0x2; macOS: ISIG 0x80, ICANON 0x100.</summary>
internal static class TerminalLocalFlags
{
    internal static ulong Icanon(bool macOS) => macOS ? 0x100UL : 0x2UL;
    internal static ulong Isig(bool macOS) => macOS ? 0x80UL : 0x1UL;

    /// <summary>
    /// Inside <c>ReadLineWithoutEcho</c>'s (or <c>ReadPassword</c>'s) key read: ICANON and ISIG both off. ISIG goes off
    /// only after the type-ahead discard (SystemConsole.cs:60-62) and comes back on between reads, while ICANON stays off
    /// after the first read, so ICANON alone doesn't show that a later read has started.
    /// </summary>
    internal static bool InKeyRead(ulong localFlags, bool macOS) => (localFlags & (Icanon(macOS) | Isig(macOS))) == 0;
}
```

In `PtyDriver`, `WaitForKeyRead` loops `while (LocalFlags() is var flags && !TerminalLocalFlags.InKeyRead(flags,
OperatingSystem.IsMacOS()))`. Remove the private `Icanon` (`:1342`). Keep the deadline and the assertion message as
they are. The deadline is a poll timeout, not a sleep, and stays as it is. Rewrite the summary (`:1326-1330`): "Reads
until tswap is inside a key read: ICANON and ISIG both off (`TerminalLocalFlags.InKeyRead`). After the first read
ICANON stays off, so only ISIG, which the read turns off after its type-ahead discard (#293), shows that a later read
has started. A key typed before that is discarded, or, with ISIG on, a Ctrl-C becomes a SIGINT (#413)." No test body
changes. All five callers (`:1410`, `:1428`, `:1449`, `:1454`, `:1504`) are at the Enter gate and keep their calls.

Tests (`TswapTests/TerminalLocalFlagsTests.cs`, a unit class with no category):

| `localFlags` | macOS | `InKeyRead` |
|---|---|---|
| `0x8a3b` (a new terminal: ISIG ICANON ECHO …) | false | false |
| `0x8a31` (between reads: -icanon ISIG -echo) | false | false |
| `0x8a3a` (ICANON on, ISIG off) | false | false |
| `0x8a30` (inside a read: -icanon -isig -echo) | false | true |
| `0x5cb` | true | false |
| `0x4c3` (between reads) | true | false |
| `0x54b` (ICANON on, ISIG off) | true | false |
| `0x443` (inside a read) | true | true |

Break-it-once: drop `Isig(macOS)` from the mask. Both "between reads" rows must fail.

**Evidence that the race is gone** (Linux, here). This step is not committed. In `SystemConsole.ReadLineWithoutEcho`,
insert `Thread.Sleep(2000);` before `_input.DiscardTypeahead();` (`:60`). That widens the window between the prompt and
ISIG off, and the sleep is in product code, never in a test. Then run
`dotnet test TswapTests --filter "FullyQualifiedName~Enrol_TypedTextAtTheEnterGate_OnARealTerminal_IsNotShownAndAsksAgain"`
twice:
- with this task's `EndToEndTests.cs` change stashed: it must fail ("'wasn't confirmed' (x1) never appeared before
  tswap exited");
- with the change: it must pass.

Remove the sleep and confirm with `git diff --stat -- TswapCli/SystemConsole.cs` that nothing is left. Put both results
in the commit message. The macOS landing (no controlling terminal) is confirmed only by macOS CI.

## Task 2 (#411): `Validation.BashLauncherRefusal`

In `TswapCore/Validation.cs`, next to `GetBlockedInvocation`:

```csharp
/// <summary>
/// Brief T64 (#411): the refusal of a bash that may be WSL's launcher, or null. WSL's bash.exe (System32's, or the WSL
/// app's bash.exe alias) runs its whole command line as /bin/bash -c "/bin/bash <command line>" (microsoft/WSL
/// 65719878ad3c, WslClient.cpp BashMain), so a substituted value is parsed again. It looks at every program position
/// (ProgramPositions) up to the first wsl, whose command runs inside the distribution.
/// </summary>
public static BlockedInvocation? BashLauncherRefusal(IReadOnlyList<string> argv, bool windows, MsysTarget.Probe? probe)
```

For each position `i` from `ProgramPositions(argv)`, in order:
- `ProgramName(argv[i])` equals `wsl` (ignoring case): stop and return null.
- **Windows** (`windows` true), when `ProgramName(argv[i])` equals `bash` (ignoring case, so `bash`, `BASH.EXE`,
  `bash.exe.` and `bash.com` all count):
  - `probe` is null: refused (run can't tell which file starts).
  - `i > 0` and the word holds none of `\`, `/` and `:`: refused. A wrapper (Windows' own `sudo`, or an MSYS2
    `timeout.exe`) searches by its own rules, which run can't see.
  - otherwise allowed only when `MsysTarget.Resolve(argv[i], probe)` is not null **and** `MsysTarget.IsMsys2(that,
    probe.FileExists)`. The raw word is resolved, as `RunCommand.cs:289` resolves it, so what is checked is what T55
    starts. Anything else is refused: not found, WSL's launcher, a planted `bash.exe` in the current folder, Cygwin's.
- **Off Windows**: refused when `WindowsFileName(argv[i])` equals `bash.exe` (ignoring case).

The refusals, exact (`{{secret}}` literally; no word from the command and no value in them):
- Windows, `Program` `bash`:
  `'bash' here is not a bash.exe that 'run' recognises as Git Bash or MSYS2 (msys-2.0.dll beside it, or Git's bin\bash.exe launcher). It may be WSL's launcher (System32's bash.exe, or the WSL app's bash.exe alias), which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. For WSL give the command after -e: 'wsl -e ./deploy.sh {{secret}}'; for Git Bash name it by its path: 'run "C:\Program Files\Git\bin\bash.exe" ./deploy.sh {{secret}}'.`
- Off Windows, `Program` `bash.exe`:
  `'bash.exe' is a Windows program: under WSL it is System32's bash.exe, WSL's launcher, reached through Windows interop, which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. Run the Linux shell instead: 'run bash ./deploy.sh {{secret}}'.`

Neither reason contains `WayOutFor(false)`, so `RunCommand.Reason` leaves them as they are. `GetBlockedInvocation`
does not change, so the broker's template check (`BrokerTemplatePolicy.cs:265`) doesn't change either.

Tests (`TswapTests/BashLauncherRefusalTests.cs`; in-process, every OS). "WSL probe" is
`MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"])`. "Git probe" is `MsysTargetTests.FakeProbe([])`. The
script argument is `./x.sh {{x}}` unless shown otherwise.

| argv | windows | probe | outcome |
|---|---|---|---|
| `bash` | true | WSL | refused (System32 before `PATH`) |
| `BASH.EXE`, `Bash`, `bash.exe` | true | WSL | refused |
| `bash` (no arguments) | true | WSL | refused |
| `C:\Windows\System32\bash.exe`, `c:/windows/system32/BASH` | true | WSL | refused |
| `C:\Windows\Sysnative\bash.exe` | true | WSL plus that file | refused |
| `C:\Windows\Sysnative\bash.exe`, `C:\Windows\SysWOW64\bash.exe` | true | Git (files absent) | refused (not found) |
| `C:\Users\u\AppData\Local\Microsoft\WindowsApps\bash.exe` | true | Git plus that file | refused (the alias, not MSYS2) |
| `bash` | true | Git | null (resolves to Git's `bin\bash.exe`) |
| `C:\Program Files\Git\bin\bash.exe`, `C:/msys64/usr/bin/bash` | true | WSL | null |
| `bash` | true | Git plus `C:\work\bash.exe` | refused (the current folder comes first; not MSYS2) |
| `bash` | true | Git plus `C:\tools\bash.exe` | refused (tswap's folder comes first) |
| `bash` | true | `new MsysTarget.Probe(@"C:\tools", @"C:\work", @"C:\Windows\System32", @"C:\Windows", _ => null, _ => false)` | refused (not found) |
| `bash.exe.` | true | Git | refused (`Resolve` finds no `bash.exe.`) |
| `sudo bash ./x.sh {{x}}` | true | Git | refused (bare, behind a wrapper) |
| `sudo "C:\Program Files\Git\bin\bash.exe" ./x.sh {{x}}` | true | Git | null |
| `timeout 5 C:\Windows\System32\bash.exe ./x.sh {{x}}` | true | WSL | refused |
| `wsl -e bash ./x.sh {{x}}`, `wsl -d Ubuntu --exec bash ./x.sh {{x}}` | true | WSL | null (inside the distribution) |
| `tool bash ./x.sh`, `bashful ./x.sh`, `C:\tools\bash-5.exe ./x.sh` | true | WSL | null |
| `bash`, `C:\Program Files\Git\bin\bash.exe` | true | null | refused |
| `bash.exe`, `BASH.EXE`, `bash.exe.`, `/mnt/c/Windows/System32/bash.exe`, `/mnt/c/Program Files/Git/bin/bash.exe` | false | null | refused |
| `sudo bash.exe ./x.sh {{x}}` | false | null | refused |
| `bash`, `/bin/bash`, `/usr/bin/bash` | false | null | null |
| `wsl.exe -e bash.exe ./x.sh {{x}}` | false | null | null (stops at `wsl`) |

Also test: each exact message once (Windows and off Windows), with `Program` `bash` and `bash.exe`. A refusal for
`bash ./x.sh 'v$(id)k7Qz'` never contains `k7Qz`.

Break-it-once:
1. Make the Windows branch return null when `Resolve` returns a file, MSYS2 or not. The `bash`/WSL row must fail.
2. Replace "not `IsMsys2`" with "folder is System32" (the tempting design). The `WindowsApps`, `C:\work` and not-found
   rows must fail.
3. Drop the stop at `wsl`. The `wsl -e bash` rows must fail.
4. Drop the off-Windows branch. The `bash.exe` rows must fail.

## Task 3 (#411): `run` applies it before unlock and after substitution

In `RunCommand.cs`:
- After `:89`: `var msysProbe = windows ? ctx.MsysProbe() : null;` then
  `ThrowIfBlocked(Validation.BashLauncherRefusal(commandArgs, windows, msysProbe), windows);`. The refusal comes before
  unlock, so no key touch is asked for.
- At `:258`: `if ((Validation.GetBlockedInvocation(argv) ?? Validation.BashLauncherRefusal(argv, windows, msysProbe)) is { } blocked)`,
  and the `NameCulprit` predicate (`:263`) becomes
  `a => Validation.GetBlockedInvocation(a) is not null || Validation.BashLauncherRefusal(a, windows, msysProbe) is not null`.
  The message there is unchanged: it names the token and never the word.
- At `:288`: `if (msysProbe is { } probe && MsysTarget.Resolve(…)…`. It is the same probe and the same behaviour, read
  once (`windows` is already part of `msysProbe`).

Tests (`TswapTests/RunBashLauncherTests.cs`, with the harness of `RunMsysTargetTests`: `FleetMachine`, `RecordingPty`,
`MsysProbe = () => probe`, `_m.Os = os`; secret `pw` = `a\b"c`):

| OS | probe | command | outcome |
|---|---|---|---|
| Windows | WSL | `run bash ./capture.sh {{pw}}` | exit 1, 0 starts; stderr holds the Windows reason, then `ViewSecretLine(true)`; no value in stdout or stderr |
| Windows | WSL | `run --env PW={{pw}} -- bash ./capture.sh` | exit 1, 0 starts, the Windows reason |
| Windows | WSL | `run "C:\Program Files\Git\bin\bash.exe" ./capture.sh {{pw}}` | exit 0, 1 start, argv `[GitBash]`, `WindowsArguments` as in `GitBash_StartsByItsResolvedPath_…` |
| Windows | WSL | `run {{prog}} ./capture.sh {{pw}}` with `prog` = `bash` | exit 1, 0 starts; stderr holds `After substitution, the value of {{prog}} makes this a command 'run' refuses` (`RunCommand.cs:262-265`, `:496-504`); stderr holds no `bash` word from the value (assert `DoesNotContain("'bash'")`) |
| Linux | null | `run bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts, the off-Windows reason then `ViewSecretLine(false)` |
| Linux | null | `run bash ./capture.sh {{pw}}` | exit 0, 1 start, argv as given |
| Windows | WSL | `run wsl -e bash ./capture.sh {{pw}}` | exit 0, 1 start |

Break-it-once: remove **both** new calls. The first two rows must fail. (Removing only the `:89` call is not
enough: the check after substitution still refuses those rows, with the token-naming message.) Then put the `:89` call
back and remove only the call after substitution. The `{{prog}}` row must fail.

**Windows E2E** (`EndToEndTests`; only Windows CI runs it):
`[WindowsFact("WSL's bash.exe and CreateProcess's search order exist only on Windows")] Run_WslBashLauncher_IsRefused_Windows`.
Set up as `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows` does (`:2170-2178`): `ScriptWork`, `capture.sh`, `init`,
one ingested value `v$(echo pwned)k7Qz`.
- Leg 1: `run <Environment.SystemDirectory>\bash.exe ./capture.sh {{v}}`: exit 1, stderr holds the Windows reason, no
  `out.txt`, no `k7Qz` in the output. This holds whether or not WSL is installed (not found is refused too).
- Leg 2: bare `run bash ./capture.sh {{v}}`. If `File.Exists(Path.Combine(Environment.SystemDirectory, "bash.exe"))`,
  it is refused as in leg 1. Otherwise it resolves to Git's (assert `FindGitBash()` is not null) and `out.txt` holds the
  value exactly. Write which branch ran with `_output.WriteLine`.

**Only Windows CI can confirm:** `Probe.ForThisProcess` on a real machine; whether the runner has System32's
`bash.exe` (the leg-2 branch); that `File.Exists` is true for an App Execution Alias (0-byte reparse point); and that
the real `CreateProcess` order matches `Resolve`. WSL's re-parse comes from source, not from a run, because the runners
have no WSL distribution to run it in. Name the CI branch in the report once it has run.

## Task 4: docs

- `docs/security-model.md:186`: replace "Known gap of the inline-code check, filed: System32's `bash.exe` (WSL's
  launcher) runs its command line through `/bin/bash -c` (#411)." with "On Windows `run` refuses a `bash` (in the
  program position and behind a wrapper) unless it resolves, by Windows' search order, to a file it recognises as Git
  Bash or MSYS2. WSL's launcher (System32's `bash.exe`, or the WSL app's `bash.exe` alias) runs its whole command line
  through `/bin/bash -c` and can't be recognised positively (#411). Off Windows a `bash.exe` word is refused, since
  under WSL it reaches that launcher through interop." In the same cell's "Accepted over-refusals" list, add: "on
  Windows, a `bash` that isn't MSYS2 (Cygwin's included), a bare `bash` behind a wrapper, and a `bash` not found; any
  `bash.exe` off Windows".
- `docs/scripts.md:53-54` (only this sentence; T62 edits `:55-58` of the same paragraph): replace "A bare `bash` can
  still start WSL's `bash.exe` in System32, which `run` leaves alone, so name Git Bash by its path:" with "Where WSL is
  installed, a bare `bash` starts WSL's `bash.exe` in System32 (Windows searches System32 before `PATH`), which `run`
  refuses, as it refuses any `bash` it can't recognise as MSYS2 (#411), so name Git Bash by its path:".
- `TswapCore/Prompt.cs` does not change (its text is hashed by `prompt-hash`).
- In the report, a release-note line: "`run` refuses WSL's `bash.exe` (and, on Windows, any `bash` it can't recognise
  as Git Bash or MSYS2), which parses its command line again with `bash -c`; use `wsl -e` or Git Bash's path (#411)."

## Out of scope

- A copy, link or 8.3 short name of `wsl.exe` under another name. WSL picks its entry point by the name used
  (`bash` → `BashMain`; any other name → `WslMain`'s shell mode). The existing residual "a link or a copy under
  another name" covers it.
- `sh.exe` off Windows through interop (Git's MSYS2 `sh`, with interop's quoting rather than MSYS2's).
- Cygwin as a recognised target (its `cygwin1.dll` and quoting rules): refused here, see the open questions.
- The broker's template check on Windows (#306). `GetBlockedInvocation` is unchanged.
- The product's own window between the prompt and ISIG off (#413). A person's Ctrl-C there ends tswap by SIGINT, which
  leaves no approve file (T56).
- `MsysTarget.cs` (T62) and #426.
