# Brief T64: `run` refuses WSL's `bash.exe`; the Enter-gate test waits for the real key read (#411, #413)

Milestone 0.3.3. **Base: `origin/main` after T58 (PR #433) merges.** This brief's branch, `brief/t64`, starts on
`brief/t58` at a0836c2. Every line number below was checked at T58's head **653f701**. Since a0836c2, T58's later
commits changed `RunCommand.cs` by one line (`26fc3e1`, the burned-value warning at `:152-158`, so everything after it
is one line lower than at a0836c2), as well as `TotpCommand.cs`, `Apply.cs`, `TswapCore/Totp/*`, the Totp tests and
`docs/commands.md`. `Validation.cs`, `EndToEndTests.cs`, `SystemConsole.cs`, `SlotEnrol.cs`, `MsysTarget.cs`,
`MsysTargetTests.cs`, `RunMsysTargetTests.cs`, `docs/scripts.md` and `docs/security-model.md` did not change. If T58
changes again before it merges, look the cited lines up again before you start.

Read AGENTS.md and CLAUDE.md first, then:
- `TswapCore/Validation.cs`: `GetBlockedInvocation` (`:672-800`), its `bash` entry (`:488`), `CheckWsl` (`:940-1027`),
  `ProgramPositions` (`:269-312`), `WindowsFileName` (`:1437-1450`), `ProgramName` (`:1457-1464`).
- `TswapCore/MsysTarget.cs`: `Probe`, `Resolve` (`:43-60`), `IsMsys2` (`:86-97`). You only call these. The file
  belongs to T62.
- `TswapCli/Commands/RunCommand.cs`: the pre-unlock check (`:86-89`), the check after substitution (`:255-270`), the
  MSYS2 start (`:283-298`), `NameCulprit` (`:497-505`), `Reason` and `ThrowIfBlocked` (`:636-649`).
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
  refuses. Every use of WSL's `bash.exe` that the name check can see must be refused: under its own name, reached by a
  bare `bash`, behind a wrapper, and inside a `wsl` exec command (review F1). Copies under other names are a residual
  (Out of scope).
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
Only `wsl` gets wsl.exe's walk (`:859-861`, `CheckWsl`). The MSYS2 start (`RunCommand.cs:283-298`) quotes for Git
Bash. For any other `bash.exe` it does nothing (`docs/scripts.md:53-54`: "which `run` leaves alone").
`docs/security-model.md:186` lists #411 as a known gap.

**Off Windows, and inside `wsl -e`.** Inside WSL, `PATH` includes `/mnt/c/Windows/system32` by default
(`appendWindowsPath`). A Linux tswap running `bash.exe` (or `/mnt/c/Windows/System32/bash.exe`) therefore starts the
same launcher through WSL's interop. The same holds for the command a Windows tswap hands to `wsl` in exec mode:
`run wsl -e bash.exe ./x.sh {{pw}}` reaches `BashMain` through interop. `CheckWsl`'s exec mode
(`Validation.cs:1023-1024`) checks that command as Linux `bash` with a script, so it passes today. On Linux and macOS,
and inside a distribution, a `bash.exe` word is never the Linux shell, so refusing it costs nothing.

**Spellings that reach the launcher** (parser-first: CreateProcess, .NET's process start and WSL's dispatch):
- **Trailing dots or spaces** (`bash.exe.`, `bash.exe `, `bash `). Win32 path normalisation drops them, so
  `CreateProcess` starts System32's `bash.exe`. WSL then picks its entry point from the stem of the first word
  (`std::filesystem::path("bash.exe.").stem()` is `bash.exe`, so `WslMain`'s shell mode; `"bash.exe "` has stem
  `bash`, so `BashMain`). Both re-parse the command line. `ProgramName` already reduces these to `bash`
  (`WindowsFileName` trims trailing dots and spaces, `:1449`), so they are checked: refused.
- **Leading white space** (` bash`). .NET's process start trims `FileName` (RedactingPty's FallbackPty), so it can
  reach the launcher. `ProgramName` does not trim leading white space, so the new check trims it first: refused.
- **A quoted path** (a word that holds `"`, such as `"C:\Windows\System32\bash.exe"` with the quotes in the word, which
  PowerShell 5.1 can pass through). .NET passes a `FileName` that starts and ends with `"` to `CreateProcess` as it is,
  which starts the file. No Windows file name holds `"`, so the check removes every `"` before naming the word. Such a
  word is then refused **outright**, even when it names Git's bash: T55's start (`RunCommand.cs:289`) resolves the raw
  word, would not find it, and would quote for the C runtime instead of MSYS2.
- **A stream or a dotted folder** (`bash.exe::$DATA`, `C:\Windows\System32\.\bash.exe`,
  `C:\Windows\System32\..\System32\bash.exe`, `\\?\C:\Windows\System32\bash.exe`). `ProgramName` gives `bash`. `Resolve`
  takes the path as it is, so it is either not found or not MSYS2: refused.
- **Extra text in one word** (`bash ./x.sh`). Both start paths quote a word with white space whole, so `CreateProcess`
  looks for a file of that whole name and doesn't start bash. The check still treats a word whose first
  white-space-delimited part names bash as naming bash, which fails closed. A path with a space in a folder name
  (`C:\Program Files\Git\bin\bash.exe`) is unaffected: its first part, `C:\Program`, doesn't name bash.
- **8.3 short names** (review F6). `Resolve` does not canonicalise them: it only joins strings and calls `FileExists`.
  `bash.exe` is already an 8.3 name, so System32's file and the alias have no separate short name. A short folder name
  (`C:\WINDOW~1\System32\bash.exe`) still ends in `bash.exe`, so it is checked: refused. A short name such as
  `BASH~1.EXE` exists only for a copy with a longer name, which is the copy residual: declared in the docs (Task 4) and
  out of scope.

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
/// (ProgramPositions) up to the first wsl; in wsl's exec mode it goes on into wsl's command, which runs inside the
/// distribution, where a bash.exe word is the launcher again through interop.
/// </summary>
public static BlockedInvocation? BashLauncherRefusal(IReadOnlyList<string> argv, bool windows, MsysTarget.Probe? probe)
```

**The wsl walk, shared.** Extract `CheckWsl`'s option walk (`Validation.cs:975-1017`: its two variables and the loop) unchanged into
`private static WslWalk WalkWsl(string program, List<string> args)`, with
`private readonly record struct WslWalk(bool Ended, BlockedInvocation? Verdict, bool Exec, int Command);`. `Ended` is
true where the loop returns today (an unknown option or `--shell-type` value, a management option, `--debug-shell` or
`--install`), and `Verdict` is what it returns. `CheckWsl` becomes `var walk = WalkWsl(program, args); if (walk.Ended)
return walk.Verdict;` followed by its tail (`:1019-1024`) on `walk.Exec` and `walk.Command`. This is a refactor:
every `wsl` row of `InlineCodeBlockTests` (the refused, allowed and `WslShell`/`WslInner`/`WslUnknown` rows) must
pass unchanged.

**Naming a word.** For a word `w`, let `n` be `w` with every `"` removed and then trimmed of white space
(`char.IsWhiteSpace`), and let `t` be `n` up to its first white-space character (all of `n` if it has none).
- On Windows, `w` **names bash** when `ProgramName(n)` or `ProgramName(t)` equals `bash` (ignoring case, so `bash`,
  `BASH.EXE`, `bash.exe.`, `bash.exe::$DATA` and `bash.com` all count).
- Off Windows, `w` **names bash.exe** when `WindowsFileName(n)` or `WindowsFileName(t)` equals `bash.exe` (ignoring
  case).

For each position `i` from `ProgramPositions(argv)`, in order:
- `ProgramName(argv[i])` equals `wsl` (ignoring case): `var walk = WalkWsl("wsl", argv.Skip(i + 1).ToList())`. If `walk.Ended`,
  or not `walk.Exec`, or `walk.Command` is past the end, return null. `GetBlockedInvocation`'s `CheckWsl` already
  decides those cases (T51), and its shell-mode refusal is unchanged. Otherwise check wsl's command,
  `argv.Skip(i + 1 + walk.Command).ToList()`, with this same function and the **off-Windows rule**
  (`BashLauncherRefusal(inner, windows: false, probe: null)`), whatever `windows` is, because that command runs inside
  the distribution. Nested `wsl` recurses the same way. A refusal from there comes back as
  `inner with { Reason = $"'wsl' runs '{inner.Program}': {inner.Reason}" }`, as `CheckWsl` words its own (`:1024`).
  Return that result (null or the refusal): the walk ends at the first `wsl`.
- **Windows** (`windows` true), when `argv[i]` names bash:
  - `probe` is null: refused (run can't tell which file starts).
  - `n != argv[i]` (the word held `"` or leading or trailing white space): refused. T55's start would not recognise it.
  - `ProgramName(n)` isn't `bash` (only `t` named it, as in `bash ./x.sh` in one word): refused.
  - `i > 0` and the word holds none of `\`, `/` and `:`: refused. A wrapper (Windows' own `sudo`, or an MSYS2
    `timeout.exe`) searches by its own rules, which run can't see.
  - otherwise allowed only when `MsysTarget.Resolve(argv[i], probe)` is not null **and** `MsysTarget.IsMsys2(that,
    probe.FileExists)`. The raw word is resolved, as `RunCommand.cs:289` resolves it, so what is checked is what T55
    starts. Anything else is refused: not found, WSL's launcher, a planted `bash.exe` in the current folder, Cygwin's.
- **Off Windows**, when `argv[i]` names bash.exe: refused.

The refusals, exact (`{{secret}}` literally; no word from the command and no value in them):
- Windows, `Program` `bash`:
  `'bash' here is not a bash.exe that 'run' recognises as Git Bash or MSYS2 (msys-2.0.dll beside it, or Git's bin\bash.exe launcher). It may be WSL's launcher (System32's bash.exe, or the WSL app's bash.exe alias), which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. For WSL give the command after -e: 'wsl -e ./deploy.sh {{secret}}'; for Git Bash name it by its path: 'run "C:\Program Files\Git\bin\bash.exe" ./deploy.sh {{secret}}'.`
- Off Windows, `Program` `bash.exe`:
  `'bash.exe' is a Windows program: under WSL it is System32's bash.exe, WSL's launcher, reached through Windows interop, which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. Run the Linux shell instead: 'run bash ./deploy.sh {{secret}}'.`

Neither reason contains `WayOutFor(false)`, so `RunCommand.Reason` leaves them as they are. `GetBlockedInvocation`
does not change, so the broker's template check (`BrokerTemplatePolicy.cs:265`) doesn't change either.

Tests (`TswapTests/BashLauncherRefusalTests.cs`; in-process, every OS). "WSL probe" is
`MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"])`. "Git probe" is `MsysTargetTests.FakeProbe([])`. The
script argument is `./x.sh {{x}}` unless shown otherwise. A path shown in `"…"` is shell quoting: the word holds no
`"`. The exception is a row marked "(quotes in the word)".

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
| `bash.exe.` | true | Git | refused: not MSYS2. On Windows `Resolve` finds `…\bash.exe.` (the trailing dot is dropped) and `IsMsys2` rejects the dotted name (`MsysTarget.cs:93-97`); the fake probe's `FileExists` is exact, so here it is not found |
| `bash.exe `, ` bash`, `bash.exe::$DATA` | true | WSL | refused |
| `"C:\Windows\System32\bash.exe"` (quotes in the word) | true | WSL | refused |
| `"C:\Program Files\Git\bin\bash.exe"` (quotes in the word) | true | WSL | refused (outright: T55 would not recognise it) |
| `C:\Windows\System32\.\bash.exe`, `\\?\C:\Windows\System32\bash.exe`, `C:\WINDOW~1\System32\bash.exe` | true | WSL | refused (not found by the exact fake probe; on Windows not MSYS2) |
| `bash ./x.sh` (one word), then `{{x}}` | true | Git | refused |
| `sudo bash ./x.sh {{x}}` | true | Git | refused (bare, behind a wrapper) |
| `sudo "C:\Program Files\Git\bin\bash.exe" ./x.sh {{x}}` | true | Git | null |
| `timeout 5 C:\Windows\System32\bash.exe ./x.sh {{x}}` | true | WSL | refused |
| `wsl -e bash ./x.sh {{x}}`, `wsl -d Ubuntu --exec bash ./x.sh {{x}}`, `wsl -e ./deploy.sh {{x}}`, `wsl --shell-type none bash ./x.sh {{x}}` | true | WSL | null (Linux bash inside the distribution) |
| `wsl -e bash.exe ./x.sh {{x}}`, `wsl --exec BASH.EXE ./x.sh {{x}}`, `wsl --shell-type none bash.exe ./x.sh {{x}}`, `wsl -d Ubuntu -e /mnt/c/Windows/System32/bash.exe ./x.sh {{x}}`, `wsl -e sudo bash.exe ./x.sh {{x}}` | true | WSL | refused; the reason starts `'wsl' runs 'bash.exe': ` |
| `wsl -e wsl.exe -e bash.exe ./x.sh {{x}}` | true | WSL | refused (nested) |
| `wsl -e wsl.exe -e bash ./x.sh {{x}}` | true | WSL | null |
| `wsl bash.exe ./x.sh {{x}}` (shell mode), `wsl --list`, `wsl --bogus bash.exe` | true | WSL | null here (`GetBlockedInvocation` refuses shell mode and unknown options; `--list` runs nothing) |
| `tool bash ./x.sh`, `bashful ./x.sh`, `C:\tools\bash-5.exe ./x.sh` | true | WSL | null |
| `bash`, `C:\Program Files\Git\bin\bash.exe` | true | null | refused |
| `bash.exe`, `BASH.EXE`, `bash.exe.`, `/mnt/c/Windows/System32/bash.exe`, `/mnt/c/Program Files/Git/bin/bash.exe` | false | null | refused |
| `sudo bash.exe ./x.sh {{x}}` | false | null | refused |
| `bash`, `/bin/bash`, `/usr/bin/bash` | false | null | null |
| `wsl.exe -e bash.exe ./x.sh {{x}}`, `wsl.exe -e /mnt/c/Windows/System32/bash.exe ./x.sh {{x}}`, `wsl.exe -e wsl.exe -e bash.exe ./x.sh {{x}}` | false | null | refused |
| `wsl.exe -e bash ./x.sh {{x}}` | false | null | null |
| `"bash.exe"` (quotes in the word), ` bash.exe`, `bash.exe ./x.sh` (one word) | false | null | refused |

Also test: each exact message once (Windows and off Windows), with `Program` `bash` and `bash.exe`. A refusal for
`bash ./x.sh 'v$(id)k7Qz'` never contains `k7Qz`.

Break-it-once:
1. Make the Windows branch return null when `Resolve` returns a file, MSYS2 or not. The `bash`/WSL row must fail.
2. Replace "not `IsMsys2`" with "folder is System32" (the tempting design). The `WindowsApps`, `C:\work` and not-found
   rows must fail.
3. Make the `wsl` branch return null without walking into the exec command (the round-1 design). The
   `wsl -e bash.exe` rows must fail.
4. Make it check the inner command with the caller's `windows` instead of the off-Windows rule. The Windows
   `wsl -e bash.exe` rows must fail, and `wsl -e bash` must still pass.
5. Drop the off-Windows branch. The off-Windows `bash.exe` rows must fail.
6. Remove the `"` removal and trimming from `n`. The quoted and ` bash` rows must fail.

## Task 3 (#411): `run` applies it before unlock and after substitution

In `RunCommand.cs`:
- After `:89`: `var msysProbe = windows ? ctx.MsysProbe() : null;` then
  `ThrowIfBlocked(Validation.BashLauncherRefusal(commandArgs, windows, msysProbe), windows);`. The refusal comes before
  unlock, so no key touch is asked for.
- At `:259`: `if ((Validation.GetBlockedInvocation(argv) ?? Validation.BashLauncherRefusal(argv, windows, msysProbe)) is { } blocked)`,
  and the `NameCulprit` predicate (`:264`) becomes
  `a => Validation.GetBlockedInvocation(a) is not null || Validation.BashLauncherRefusal(a, windows, msysProbe) is not null`.
  **The message there (`:266-270`) stays the generic one, on purpose** (review F5). It names the token and never the
  word or the value, and it doesn't describe WSL's re-parse. Do not add the word or the specific reason: the word came
  from a secret's value.
- At `:289`: `if (msysProbe is { } probe && MsysTarget.Resolve(…)…`. It is the same probe and the same behaviour, read
  once (`windows` is already part of `msysProbe`).

Tests (`TswapTests/RunBashLauncherTests.cs`, with the harness of `RunMsysTargetTests`: `FleetMachine`, `RecordingPty`,
`MsysProbe = () => probe`, `_m.Os = os`; its `Run` takes a `MsysTarget.Probe?` so the "null" rows can be written;
secret `pw` = `a\b"c`; `"…"` around a path is shell quoting, as in Task 2's table):

| OS | probe | command | outcome |
|---|---|---|---|
| Windows | WSL | `run bash ./capture.sh {{pw}}` | exit 1, 0 starts; stderr holds the Windows reason, then `ViewSecretLine(true)`; no value in stdout or stderr |
| Windows | WSL | `run --env PW={{pw}} -- bash ./capture.sh` | exit 1, 0 starts, the Windows reason |
| Windows | WSL | `run "C:\Program Files\Git\bin\bash.exe" ./capture.sh {{pw}}` | exit 0, 1 start, argv `[GitBash]`, `WindowsArguments` as in `GitBash_StartsByItsResolvedPath_…` |
| Windows | WSL | `run {{prog}} ./capture.sh {{pw}}` with `prog` = `bash` | exit 1, 0 starts; stderr holds `After substitution, the value of {{prog}} makes this a command 'run' refuses` (`RunCommand.cs:266-270`, `:497-505`); stderr holds no `bash` word from the value (assert `DoesNotContain("'bash'")`) |
| Linux | null | `run bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts, the off-Windows reason then `ViewSecretLine(false)` |
| Linux | null | `run bash ./capture.sh {{pw}}` | exit 0, 1 start, argv as given |
| Windows | WSL | `run wsl -e bash ./capture.sh {{pw}}` | exit 0, 1 start |
| Windows | WSL | `run wsl -e bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts; stderr holds `'wsl' runs 'bash.exe': ` and the off-Windows reason |
| Windows | WSL | `run wsl -e {{prog}} ./capture.sh {{pw}}` with `prog` = `bash.exe` | exit 1, 0 starts; the generic message naming `{{prog}}`; no `bash.exe` in stderr |

Break-it-once: remove **both** new calls. The first two rows must fail. (Removing only the `:89` call is not
enough: the check after substitution still refuses those rows, with the token-naming message.) Then put the `:89` call
back and remove only the call after substitution. The `{{prog}}` row must fail.

**Windows E2E** (`EndToEndTests`; only Windows CI runs it):
`[WindowsFact("WSL's bash.exe and CreateProcess's search order exist only on Windows")] Run_WslBashLauncher_IsRefused_Windows`.
Set up as `Ingest_RawUtf8Bytes_StoresTheValueExactly_Windows` does (`:2170-2178`): `ScriptWork`, `capture.sh`, `init`,
one ingested value `v$(echo pwned)k7Qz`.
- Leg 1: `run <Environment.SystemDirectory>\bash.exe ./capture.sh {{v}}`: exit 1, stderr holds the Windows reason, no
  `out.txt`, no `k7Qz` in the output. This holds whether or not WSL is installed (not found is refused too).
- Leg 2 (review F2): bare `run bash ./capture.sh {{v}}`, with the expected outcome computed the way the product
  computes it. Build the probe as tswap sees the machine, not as the test host does:
  `new MsysTarget.Probe(Path.GetDirectoryName(_binaryPath), work.FullName, Environment.SystemDirectory, Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetEnvironmentVariable, File.Exists)`.
  `Probe.ForThisProcess()` would use the test host's folder and current folder. Let
  `resolved = MsysTarget.Resolve("bash", probe)` and `msys = resolved is not null && MsysTarget.IsMsys2(resolved, probe.FileExists)`.
  If `!msys`, it is refused as in leg 1 (System32's `bash.exe`, the WSL alias, anything else, or not found). If `msys`,
  `out.txt` holds the value exactly. Write the branch and `resolved` with `_output.WriteLine`.

**Only Windows CI can confirm:** the probe on a real machine; which file a bare `bash` resolves to on the runner (the
leg-2 branch); that .NET passes a quoted or space-padded `FileName` to `CreateProcess` as described; that `File.Exists` is true for an App Execution Alias (0-byte reparse point); and that
the real `CreateProcess` order matches `Resolve`. WSL's re-parse comes from source, not from a run, because the runners
have no WSL distribution to run it in. Name the CI branch in the report once it has run.

## Task 4: docs

- `docs/security-model.md:186`: replace "Known gap of the inline-code check, filed: System32's `bash.exe` (WSL's
  launcher) runs its command line through `/bin/bash -c` (#411)." with "On Windows `run` refuses a `bash` (in the
  program position and behind a wrapper) unless it resolves, by Windows' search order, to a file it recognises as Git
  Bash or MSYS2. WSL's launcher (System32's `bash.exe`, or the WSL app's `bash.exe` alias) runs its whole command line
  through `/bin/bash -c` and can't be recognised positively (#411). Off Windows, and in the command of `wsl -e`, a
  `bash.exe` word is refused, since there it reaches that launcher through interop. A copy or link of the launcher (or
  of `wsl.exe`) under another name, or that name's 8.3 short name, still re-parses its command line unchecked." In the same cell's "Accepted over-refusals" list, add: "on
  Windows, a `bash` that isn't MSYS2 (Cygwin's included), a bare `bash` behind a wrapper, a `bash` not found, and a
  program word holding `"` or leading or trailing white space that names `bash`; any `bash.exe` off Windows".
- `docs/scripts.md:53-54` (only this sentence; T62 edits `:55-58` of the same paragraph): replace "A bare `bash` can
  still start WSL's `bash.exe` in System32, which `run` leaves alone, so name Git Bash by its path:" with "Where WSL is
  installed, a bare `bash` starts WSL's `bash.exe` in System32 (Windows searches System32 before `PATH`), which `run`
  refuses, as it refuses any `bash` it can't recognise as MSYS2 (#411), so name Git Bash by its path:".
- `TswapCore/Prompt.cs` does not change (its text is hashed by `prompt-hash`).
- In the report, a release-note line: "`run` refuses WSL's `bash.exe` (and, on Windows, any `bash` it can't recognise
  as Git Bash or MSYS2), which parses its command line again with `bash -c`; use `wsl -e` or Git Bash's path (#411)."

## Out of scope

- A copy or link of `wsl.exe` or the launcher under another name, and that name's 8.3 short name (review F6). WSL
  picks its entry point by the name used (`bash` → `BashMain`; any other name → `WslMain`'s shell mode,
  `WslClient.cpp:1918-1922`). This is declared in the docs (Task 4), next to the existing residual "a link or a copy
  under another name".
- `sh.exe` off Windows through interop (Git's MSYS2 `sh`, with interop's quoting rather than MSYS2's).
- Cygwin as a recognised target (its `cygwin1.dll` and quoting rules): refused here, see the open questions.
- The broker's template check on Windows (#306). `GetBlockedInvocation` is unchanged.
- The product's own window between the prompt and ISIG off (#413). A person's Ctrl-C there ends tswap by SIGINT, which
  leaves no approve file (T56).
- `MsysTarget.cs` (T62) and #426.

## Amendments

- **Round 1 (MiMo; controller's rulings).** F1: the walk no longer stops at `wsl`. In exec mode it checks wsl's
  command by the off-Windows rule, recursively (`WalkWsl` shared with `CheckWsl`), and the old `null` row for
  `wsl.exe -e bash.exe` is now refused. F2: E2E leg 2 computes its branch with `Resolve` and `IsMsys2` over a probe of
  tswap's view. F3: citations re-checked at T58's 653f701 (`RunCommand.cs` +1 after `:158`), and the header corrected.
  F4: the `bash.exe.` row's comment says what Windows does. F5: the generic message after substitution is kept on
  purpose. F6: 8.3 short names declared as a residual (`Resolve` doesn't canonicalise them). Parser-first rule: trailing
  dots and spaces, leading white space, quoted paths, streams and extra text in one word are covered and refused.
