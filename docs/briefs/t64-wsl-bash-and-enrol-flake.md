# Brief T64: `run` refuses WSL's `bash.exe`; the Enter-gate test waits for the real key read (#411, #413)

Milestone 0.3.3. **Base: `origin/main` after T58 (PR #433) merges.** This brief's branch, `brief/t64`, starts on
`brief/t58` at a0836c2. Every line number below was checked at T58's head **653f701**. Since a0836c2, T58's later
commits changed `RunCommand.cs` by one line (`26fc3e1`, the burned-value warning at `:152-158`, so everything after it
is one line lower than at a0836c2), as well as `TotpCommand.cs`, `Apply.cs`, `TswapCore/Totp/*`, the Totp tests and
`docs/commands.md`. `Validation.cs`, `EndToEndTests.cs`, `SystemConsole.cs`, `SlotEnrol.cs`, `MsysTarget.cs`,
`MsysTargetTests.cs`, `RunMsysTargetTests.cs`, `docs/scripts.md` and `docs/security-model.md` did not change. If T58
changes again before it merges, look the cited lines up again before you start.

Read AGENTS.md and CLAUDE.md first, then:
- `TswapCore/Validation.cs`: `GetBlockedInvocation` (`:672-800`), its `bash` entry (`:488`), `CheckWsl` (`:940-1025`),
  `ProgramPositions` (`:269-312`), `WindowsFileName` (`:1437-1450`), `ProgramName` (`:1457-1464`).
- `TswapCore/MsysTarget.cs`: `Probe`, `Resolve` (`:43-61`), `IsMsys2` (`:86-98`). You only call these. The file
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
on an assertion, stop and list it. Checked: the in-process run tests with a `bash` word are
`RunMsysTargetTests` (its probe has no WSL `bash.exe` and resolves `bash` to Git's), `CommandTests.cs:921` (refused
earlier by `GetBlockedInvocation`, unchanged), and `RunFileTokenTests.cs:764` and `:1003` (the file-token refusal
comes first, see Task 3; in `:1003`'s `helm template -f {{@f}} --post-renderer bash`, `bash` is an argument, not a
program position). Task 2a's `runuser` change touches no existing row: `InlineCodeBlockTests.cs:105`, `:129`, `:261`
and `:269` go through the same branch as before, and no file-token row uses `runuser`. On Windows CI every in-process test runs with `Os` Windows and a null probe (`FleetMachine.cs:213-217`), so the
order in Task 3 matters there.

**File ownership.** T62 owns `MsysTarget.cs`, `SecretVariants.cs`, `MsysQuotingTests`, `DependencyPinningTests`,
`ReleasePackagingTests` and `SignWindowsScriptTests`, plus `docs/scripts.md:46-64` and
`docs/security-model.md:765-772`. T63 owns `SecretMatcher.cs`, `BrokerRedactor.cs`, `BrokerTemplateOutput`,
`FieldSecretCheck` and `docs/broker-threat-model.md`. Do not edit any of these, with one exception: Task 4 changes one
sentence in `docs/scripts.md:53-54`. New unit and in-process tests go in new test classes. The exception is the E2E
tests (Task 1's `WaitForKeyRead` change and Task 3's Windows test): they live in `EndToEndTests`, because their harness
(`PtyDriver`, `ScriptWork`, `RunTswapIn`, `FindGitBash`, `_binaryPath`) is that class's own and private.

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
written (the reset runs in `ReadLineWithoutEcho`'s `finally`, before the retry text at `SlotEnrol.cs:311` and the
next prompt at `:293`). The product is correct. Only the test's wait is wrong.

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
  refuses. Every use of WSL's `bash.exe` at a **program position** must be refused: run's own program, the command
  of a wrapper or runner (`sudo`, `timeout`, `npx`, `uv run`, `npm exec`, …, the positions `run`'s other guards
  already check), and the command of `wsl -e` (review F1, round 2 I1). Run's guards check program positions, not text
  that another program later parses as a command line. A runner that hands a whole argument to cmd.exe or sh, and
  expansion that forms a bash name, are residuals shared by every guard (Out of scope). Copies under other names are a
  residual too.
- Where it lives: System32's `bash.exe` (Windows' WSL component), and an **App Execution Alias** `bash.exe` for
  `wsl.exe` declared by the WSL app package (`msixgluepackage/AppxManifest.in:45-47`), which sits in
  `%LOCALAPPDATA%\Microsoft\WindowsApps` on `PATH`. A WSL `bash.exe` can therefore live outside System32. Telling the
  two apart by folder name would fail open.

**How `run` finds it.** Both of `run`'s Windows start paths use `CreateProcess` with no application name
(`Validation.cs:369-372`; T55 relies on the same). `MsysTarget.Resolve` (`:43-61`) models that search: tswap's folder,
the current folder, **System32**, `System`, the Windows folder, then `PATH`, with `.exe` appended to a name without a
dot. A bare `bash` (or `BASH`, `bash.exe`, `Bash.EXE`) therefore resolves to System32's `bash.exe` wherever WSL is
installed, ahead of Git on `PATH`. An absolute or relative path is taken as is: `C:\Windows\System32\bash.exe`,
`c:/windows/system32/BASH`, and `C:\Windows\Sysnative\bash.exe` (Sysnative is visible only to 32-bit processes; tswap
ships win-x64 only). Whatever folder a `bash.exe` is in, it is refused unless it is MSYS2.

**Telling it from Git Bash and MSYS2.** `MsysTarget.IsMsys2` (`:86-98`) is the positive test T55 already relies on:
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
and inside a distribution, a `bash.exe` at a program position is never the Linux shell, so refusing it costs nothing.

**Spellings that reach the launcher** (parser-first: CreateProcess, .NET's process start and WSL's dispatch):
- **Trailing dots or spaces** (`bash.exe.`, `bash.exe `, `bash `). Win32 path normalisation drops them, so
  `CreateProcess` starts System32's `bash.exe`. WSL then picks its entry point from the stem of the first word
  (`std::filesystem::path("bash.exe.").stem()` is `bash.exe`, so `WslMain`'s shell mode; `"bash.exe "` has stem
  `bash`, so `BashMain`). Both re-parse the command line. `ProgramName` already reduces these to `bash`
  (`WindowsFileName` trims trailing dots and spaces, `:1450`). Such a word is refused outright (Task 2).
- **Leading white space** (` bash`). .NET's process start trims `FileName` (RedactingPty's FallbackPty), so it can
  reach the launcher. The check trims before naming and refuses a padded word outright.
- **Quotes** (`"C:\Windows\System32\bash.exe"` with the quotes in the word, which PowerShell 5.1 can pass through,
  and `"ba"sh`). .NET passes a `FileName` that starts and ends with `"` to `CreateProcess` as it is, and cmd.exe
  toggles quoting at every `"` and drops the quote characters (review round 3 I-1). The check removes every `"`
  before naming, as that toggling does, so `"ba"sh` names `bash`. A word with quotes is then refused **outright**,
  even when it names Git's bash: T55's start (`RunCommand.cs:289`) resolves the raw word, would not find it, and
  would quote for the C runtime instead of MSYS2.
- **A trailing separator or dot segment** (`bash\.`, `bash\`, `bash/`; review round 3 M-2). `ProgramName` of these is
  empty. Whether CreateProcess normalises `bash\.` to `bash` and then appends `.exe` is a question only Windows CI
  could answer, so the check doesn't depend on it. Before naming, it trims trailing `\`, `/` and `.` as well, so these
  name `bash`, and the word is refused outright as padded.
- **A stream or a dotted folder** (`bash.exe::$DATA`, `bash.exe:stream`, `C:\Windows\System32\.\bash.exe`,
  `C:\Windows\System32\..\System32\bash.exe`, `\\?\C:\Windows\System32\bash.exe`). `ProgramName` gives `bash`.
  `Resolve` takes the path as it is, so it is either not found or not MSYS2: refused.
- **Extra text in one word** (`bash ./x.sh`, `bash;x`). At a program position these don't start bash. Both start paths
  quote a word with white space whole, and `CreateProcess` looks for `bash;x.exe` (no dot, so `.exe` is appended).
  `ProgramName` of them isn't `bash`, so they aren't checked.
- **Residuals shared by every guard** (not checked here; Task 4 declares them). A runner that hands a whole argument
  to cmd.exe or sh: `npm exec "x&bash ./x.sh"`, where npm's script shell starts `bash` after `&`, or `uv run sh -c`.
  Expansion by such a shell that forms a bash name: `%X%`, `$X`, `~`, globs (review round 3 I-2). Every other `run`
  guard has the same limits: it reads `run`'s argv, not a command line another program builds and parses later.
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
`TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet test TswapTests --filter "FullyQualifiedName~Enrol_TypedTextAtTheEnterGate_OnARealTerminal_IsNotShownAndAsksAgain"`
(AGENTS.md's direct form, `:57`; round 5 M6)
twice:
- with this task's `EndToEndTests.cs` change stashed: it must fail ("'wasn't confirmed' (x1) never appeared before
  tswap exited");
- with the change: it must pass.

Remove the sleep and confirm with `git diff --stat -- TswapCli/SystemConsole.cs` that nothing is left. Put both results
in the commit message. The macOS landing (no controlling terminal) is confirmed only by macOS CI.

## Task 2a (shared walk): `runuser` joins `Wrappers` (round 4 I-1)

**The gap.** `ProgramPositions` (`:269-312`) walks only through `Wrappers` (`:525-531`). `runuser` is in `ShellAsUser`
(`:534`), not in `Wrappers`, although `GetBlockedInvocation` already checks its command with `CheckWrapper` (`:699`).
So every guard built on `ProgramPositions` skips `runuser`'s command: today `GetFileTokenRefusal`'s program-position
printers (`FileProgramPrinters`, `:222`, `install`), and after this brief the bash check
(`runuser -u root bash.exe ./x.sh {{x}}` under WSL interop). `CheckWrapper` is reached from only two places, the
`Wrappers` branch (`:684-685`) and `runuser` (`:699`), so `runuser` is the only wrapper with this shape. `su` is refused
outright (`:700`). Wrappers that no guard knows (`pkexec`, `setpriv`, `prlimit`, `numactl`, `cgexec`, `sg`,
Windows' `runas`) are the unknown-runner residual (Out of scope).

**Parser-first** (util-linux at e57914591653, `login-utils/su-common.c`, shared by `su` and `runuser`):
`getopt_long(argc, argv, "c:fg:G:lmpPTs:u:hVw:", longopts)` (`:1093`), with long options (`:1060-1076`) `--command`,
`--session-command`, `--group`, `--supp-group`, `--shell`, `--user`, `--whitelist-environment` taking a value, and
`--fast`, `--login`, `--preserve-environment`, `--pty`, `--no-pty`, `--help`, `--version` not. There is no leading `+`,
so GNU getopt permutes: options may also follow the command, and `--` ends them. A lone `-` after the options means
`--login` (`:1172-1175`). With `-u USER` the first non-option word is the command, run directly (`:1184-1198`).
Without `-u`, the first non-option word is the user, and the rest go to that user's shell (`:1200-1203`).

**Change**, in `Validation.cs`:
- Add `"runuser"` to `Wrappers`.
- Move the `ShellAsUser` branch (`:687-701`) **above** the `Wrappers` branch (`:684-685`). Otherwise `runuser` would
  reach `CheckWrapper` first and skip its `-c`/`--command` refusal, which would fail open. `GetBlockedInvocation`
  then behaves exactly as today for every word: `runuser` reaches the same branch as before, and no other word is in
  both sets.
- Add `-w` and `--whitelist-environment` (valued in util-linux) to `WrapperValued["runuser"]` (`:820`), so their value
  is never taken for the command. `runuser` stays out of `TrustedWrappers`, so its later words are still scanned (F22).
  That covers permuted options and `-lu USER` clusters, whose value the walk can't see.
- `IsCheckedProgram` (`:1424`) already includes `ShellAsUser`, so nothing changes there.

Tests (`TswapTests/RunuserWalkTests.cs`, in-process):

| call | outcome |
|---|---|
| `ProgramPositions(["runuser", "-u", "app", "install", "a", "b"])` | `[0, 3]` |
| `ProgramPositions(["runuser", "-w", "PATH", "-u", "app", "--", "tool"])` | `[0, 6]` |
| `GetBlockedInvocation(["runuser", "-c", "echo {{x}}"])`, `(["runuser", "root", "--command=echo {{x}}"])`, `(["runuser", "-lc", "echo {{x}}"])` | refused with `InlineReason` (unchanged) |
| `GetFileTokenRefusal(["runuser", "-u", "app", "install", "{{@f}}", "/tmp/x"])` | refused, `'install' copies files` (new: it was allowed) |

Break-it-once: put the `ShellAsUser` branch back below the `Wrappers` branch. The three `-c` rows must fail
(allowed). `runuser` then reaches `CheckWrapper` first, and `echo {{x}}` is one word, so it names no checked program
and nothing refuses it. (DeepSeek's round-1 note expected the echo check to refuse them. That holds only if `echo` were
a word of its own.) Then remove `runuser` from `Wrappers`. The `ProgramPositions` and `install` rows must fail.

## Task 2 (#411): `Validation.BashLauncherRefusal`

In `TswapCore/Validation.cs`, next to `GetBlockedInvocation`:

```csharp
/// <summary>
/// Brief T64 (#411): the refusal of a bash that may be WSL's launcher, or null. WSL's bash.exe (System32's, or the WSL
/// app's bash.exe alias) runs its whole command line as /bin/bash -c "/bin/bash <command line>" (microsoft/WSL
/// 65719878ad3c, WslClient.cpp BashMain), so a substituted value is parsed again. It looks at program positions only,
/// the ones CheckWrapper checks (run's program, a wrapper's or runner's command), and, in wsl's exec mode, at wsl's
/// command, which runs inside the distribution, where a bash.exe is the launcher again through interop.
/// </summary>
public static BlockedInvocation? BashLauncherRefusal(IReadOnlyList<string> argv, bool windows, MsysTarget.Probe? probe)
```

**The wsl walk, shared.** Extract `CheckWsl`'s option walk (`Validation.cs:975-1017`: its two variables and the loop) unchanged into
`private static WslWalk WalkWsl(string program, List<string> args)`, with
`private readonly record struct WslWalk(bool Ended, BlockedInvocation? Verdict, bool Exec, int Command);`. `Ended` is
true where the loop returns today (an unknown option, a `--shell-type` value other than `none`, `login` or
`standard`, a management option, `--debug-shell` or `--install`), and `Verdict` is what it returns. `CheckWsl` becomes `var walk = WalkWsl(program, args); if (walk.Ended)
return walk.Verdict;` followed by its tail (`:1019-1024`) on `walk.Exec` and `walk.Command`. This is a refactor:
every `wsl` row of `InlineCodeBlockTests` (the refused, allowed and `WslShell`/`WslInner`/`WslUnknown` rows) must
pass unchanged.

**Naming a word at a program position.** Let `n` be the word with every `"` removed (cmd.exe's quote toggling drops
them; review round 3 I-1), then trimmed of white space (`char.IsWhiteSpace`, fail closed) at both ends, and of
trailing `.`, `\` and `/`.
- On Windows the word **names bash** when `ProgramName(n)` is `bash` (ignoring case, so `bash`, `BASH.EXE`,
  `bash.exe.`, `bash.exe::$DATA`, `"ba"sh`, `bash\.` and `bash.com` all count). It is **padded** when the word holds `"`, starts or
  ends with white space, or ends with `.`, `\` or `/`.
- Off Windows the word **names bash.exe** when `WindowsFileName(n)` is `bash.exe` (ignoring case).
- On both, the word **names wsl** when `ProgramName(n)` is `wsl` (round 5 I2). A word that names wsl and is padded
  (`"wsl.exe"`, `"w"sl`, ` wsl`, `wsl.exe.`) is **refused outright**, as padded bash words are. Neither T51's
  `CheckWsl` nor this walk can see what it runs: `GetBlockedInvocation` names programs from the raw word, so
  `ProgramName("\"wsl.exe\"")` is `"wsl.exe"` and `CheckWsl` never runs. Yet `CreateProcess` starts `wsl.exe`, whose
  dispatcher reads `CommandLineToArgvW`'s unquoted `wsl.exe`, stem `wsl`, and enters `WslMain`'s shell mode
  (`WslClient.cpp:1887-1891`, `:1918-1922`). This closes a gap that predates T64 (T51). The reason (constant, `Program`
  `wsl`): `'wsl' written with quote characters, surrounding white space or a trailing dot can't be checked: run reads it as another program, but Windows starts wsl.exe, which runs its command line through the Linux shell. Write it plainly: 'wsl -e ./deploy.sh {{secret}}'.`

A word is **absolute** when it starts with a drive letter, `:` and `\` or `/` (`C:\…`, `c:/…`), or with two separators
(`\\server\…`, `\\?\C:\…`). `\Program Files\…` (rooted on the current drive) and `.\bash`, `sub\bash.exe` are not.

**The program positions** are the ones `run`'s existing guards check, as `CheckWrapper` (`:848-940`) reaches them
("names bash" below means "names bash.exe" off Windows):
1. `argv[0]`, and then each command `ProgramPositions` (`:269-312`) finds: through a simple wrapper (`Wrappers`,
   `:525-531`, not in `SubcommandTools`; `runuser` included since Task 2a), skipping its options, the values in
   `WrapperValued` and a leading positional (`WrapperLeadingPositional`, `:830-831`: `timeout 5`, `flock FILE`, …),
   and through `find -exec`. At a `command` position with `-v` or `-V` among its arguments the walk stops, as
   `CheckWrapper` does (`:856-857`): `command -v` only looks the name up (round 4 M-4).
2. After a **simple** wrapper (in `Wrappers`, not in `SubcommandTools`) that is **not** in `TrustedWrappers`
   (`:1064-1066`; for example `npx`, `strace`, `bwrap`, `unbuffer`, `systemd-run`, `runuser`): **every word after
   the wrapper** that names bash (round 5 M2, M4). This is the fail-closed extent: `CheckWrapper`'s own scan
   (`:929-933`, review F22) starts after the first positional, but an unknown option's value can hide the command
   either way.
3. After a `SubcommandTools` word (`:834-837`):
   - if the word right after it starts with `-` (an option comes before the first non-option word), the subcommand
     can't be located reliably: `CheckWrapper`'s probe (`:882`) would take an option's value (`uv --directory /x run`,
     `npm --prefix /x exec`) for the subcommand. Then **every later word** that names bash is checked, as under rule 2
     (round 5 I1; fail closed, without a per-runner option table);
   - otherwise, when its first word is in `ExecSubcommands` (`:839-840`: `run`, `exec`, `x`, `dlx`, `shell`, …):
     every later word that names bash, as `CheckWrapper` checks them (`:888-890`); when it isn't (`uv pip install`),
     nothing. The host-side runners `uv`, `poetry`, `pipenv`, `pdm`, `hatch`, `conda`,
   `pixi`, `npm`, `pnpm`, `yarn` and `bundle` get the rule of the OS. The container, remote and sandbox tools
   `docker`, `podman`, `nerdctl`, `kubectl`, `oc`, `lxc`, `incus`, `machinectl`, `toolbox`, `distrobox`, `flatpak`
   and `snap` run the command elsewhere, so their words get the off-Windows rule. That rule **assumes a Linux
   target**: there `bash` is Linux bash, and `bash.exe` would be the launcher only through interop. A Windows
   container or node would start `bash` through its own `CreateProcess`. No Windows container image is known to carry
   WSL's launcher, so this is declared rather than handled (round 4 M-2).
4. A word that names wsl at any of these positions (`argv[0]` included), or reached by a later-word scan: if it is
   padded, refused outright (above). Otherwise the walk ends there.
   `var walk = WalkWsl("wsl", argv.Skip(k + 1).ToList())`. If `walk.Ended`, or not `walk.Exec`, or `walk.Command` is
   past the end, return null. `GetBlockedInvocation`'s `CheckWsl` refuses shell mode wherever `CheckWrapper` reaches
   the `wsl`: at `argv[0]`, behind a simple wrapper (`npx wsl bash.exe …` is refused there, because `wsl` is a checked
   program at `npx`'s command position, `:921`), and behind a runner whose exec subcommand it locates
   (`npm exec wsl …`, `:888-890`). It does **not** reach a `wsl` behind a runner whose subcommand it can't locate
   (`uv --directory /x run wsl bash.exe …`, rule 3's first case). That shell-mode `wsl` is a declared residual: the
   runner-location gap of `CheckWrapper`, shared by every guard (DeepSeek round 1 M1, corrected). Otherwise check wsl's command,
   `argv.Skip(k + 1 + walk.Command).ToList()`, with `BashLauncherRefusal(inner, windows: false, probe: null)`. A
   refusal from there comes back as `inner with { Reason = $"'wsl' runs '{inner.Program}': {inner.Reason}" }`, as
   `CheckWsl` words its own (`:1024`). This applies on both OSes.

**Order** (round 5 M3). Process rule 1's positions in order. At the first word that names wsl, apply rule 4 and
return; never check a later position as an ordinary one. `ProgramPositions` walks *through* `wsl` (it is in
`Wrappers`), so `wsl -e bash ./x.sh` yields `[0, 2]`, and only this order keeps its `bash` Linux bash.

Rules 2 to 4 apply at every position rule 1 yields, those inside a `find -exec` command included; there a later-word
scan runs to that command's `;` or `+`. **Once a `wsl` walk starts, its command is checked only by the walk** (round 4
M-5): the later-word scans of rules 2 and 3 stop at the first word that names wsl, which is then
handled as rule 4. So in `npx wsl -e bash ./x.sh {{x}}`, `bash` is Linux bash inside the distribution (null), and in
`npx wsl -e bash.exe …` it is refused by the walk.

Nothing else is checked: an ordinary argument (`git commit -m bash`, a passphrase holding the word) is not a program
position. A program `run` doesn't know as a wrapper or runner (`pipx run`, `dotnet tool run`) has no positions after
its own, as for every other guard. `argv.Count == 0` returns null, as `GetBlockedInvocation` does (`:674-675`).

**The rule at a position `k`:**
- **Windows**, a word that names bash:
  - padded (it holds `"`, white space at either end, or a trailing `.`, `\` or `/`): refused outright;
  - `probe` is null: refused (run can't tell which file starts);
  - `k == 0` (run's own program): allowed only when `MsysTarget.Resolve(argv[0], probe)` is not null **and**
    `MsysTarget.IsMsys2(that, probe.FileExists)`. The raw word is resolved, as `RunCommand.cs:289` resolves it, so what
    is checked is what T55 starts. Anything else is refused: not found, WSL's launcher, a planted `bash.exe` in the
    current folder, Cygwin's.
  - `k >= 1`: allowed only when the word is absolute **and** `Resolve` plus `IsMsys2` accept it. A bare or relative
    word is refused, because the program that starts it searches by its own rules and from its own folder (round 2
    M1: `sudo --chdir`, `chroot`).
- **Off Windows** (and every word that gets the off-Windows rule), a word that names bash.exe: refused.

`Program` is always the literal `bash` (Windows) or `bash.exe` (off Windows), never the word, so the `'wsl' runs '…'`
prefix can't echo text from the command. Write the reasons as constant verbatim (`@"…"`, non-interpolated) strings:
they contain `{{secret}}` and `C:\Program Files\…` literally.

The refusals, exact (`{{secret}}` literally; no word from the command and no value in them):
- Windows, `Program` `bash`:
  `'bash' here is not a bash.exe that 'run' recognises as Git Bash or MSYS2 (msys-2.0.dll beside it, or Git's bin\bash.exe launcher). It may be WSL's launcher (System32's bash.exe, or the WSL app's bash.exe alias), which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. A bash at a program position (run's own program, or the command of a wrapper or runner such as sudo or uv run) is refused unless it is Git Bash or MSYS2's bash; behind a wrapper or runner it must be given by its full path. For WSL give the command after -e: 'wsl -e ./deploy.sh {{secret}}'; for Git Bash name it by its path: 'run "C:\Program Files\Git\bin\bash.exe" ./deploy.sh {{secret}}'.`
- Off Windows, `Program` `bash.exe`:
  `'bash.exe' is a Windows program: under WSL it is System32's bash.exe, WSL's launcher, reached through Windows interop, which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. Run the Linux shell instead: 'run bash ./deploy.sh {{secret}}'.`

Neither reason contains `WayOutFor(false)`, so `RunCommand.Reason` leaves them as they are. `GetBlockedInvocation`
does not change, so the broker's template check (`BrokerTemplatePolicy.cs:265`) doesn't change either.

Tests (`TswapTests/BashLauncherRefusalTests.cs`; in-process, every OS). "WSL probe" is
`MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"])`. "Git probe" is `MsysTargetTests.FakeProbe([])`.
"Win32 probe" is the Git probe with `FileExists` normalising as Win32 does, trailing dots and spaces of the path
dropped: `var git = MsysTargetTests.FakeProbe([]); var win32 = git with { FileExists = path => git.FileExists(path.TrimEnd('.', ' ')) };`
(round 4 I-3). The
script argument is `./x.sh {{x}}` unless shown otherwise. A path shown in `"…"` is shell quoting: the word holds no
`"`. The exception is a row marked "(quotes in the word)".

| argv | windows | probe | outcome |
|---|---|---|---|
| `bash` | true | WSL | refused (System32 before `PATH`) |
| `BASH.EXE`, `Bash`, `bash.exe` | true | WSL | refused |
| `bash` (no arguments) | true | WSL | refused |
| (no words at all) | true | WSL | null |
| `C:\Windows\System32\bash.exe`, `c:/windows/system32/BASH` | true | WSL | refused |
| `C:\Windows\Sysnative\bash.exe` | true | WSL plus that file | refused |
| `C:\Windows\Sysnative\bash.exe`, `C:\Windows\SysWOW64\bash.exe` | true | Git (files absent) | refused (not found) |
| `C:\Users\u\AppData\Local\Microsoft\WindowsApps\bash.exe` | true | Git plus that file | refused (the alias, not MSYS2) |
| `bash` | true | Git | null (resolves to Git's `bin\bash.exe`) |
| `C:\Program Files\Git\bin\bash.exe`, `C:/msys64/usr/bin/bash` | true | WSL | null |
| `bash` | true | Git plus `C:\work\bash.exe` | refused (the current folder comes first; not MSYS2) |
| `bash` | true | Git plus `C:\tools\bash.exe` | refused (tswap's folder comes first) |
| `bash` | true | `new MsysTarget.Probe(@"C:\tools", @"C:\work", @"C:\Windows\System32", @"C:\Windows", _ => null, _ => false)` | refused (not found) |
| `bash.exe.`, `bash.exe `, ` bash`, `bash\.`, `bash\`, `bash/` | true | Git | refused (padded, outright; the row asserts only "refused") |
| `C:\msys64\usr\bin\bash.exe` | true | Win32 | null (the control) |
| `C:\msys64\usr\bin\bash.exe.`, `C:\msys64\usr\bin\bash.exe ` | true | Win32 | refused (padded, outright; without that rule these would resolve to MSYS2 and be allowed) |
| `"C:\Windows\System32\bash.exe"`, `"ba"sh` (quotes in the word) | true | WSL | refused (padded) |
| `"C:\Program Files\Git\bin\bash.exe"` (quotes in the word) | true | WSL | refused (outright: T55 would not recognise it) |
| `bash.exe::$DATA`, `bash.exe:stream`, `C:\Windows\System32\.\bash.exe`, `\\?\C:\Windows\System32\bash.exe`, `C:\WINDOW~1\System32\bash.exe` | true | WSL | refused (not found by the exact fake probe; on Windows not found or not MSYS2) |
| `bash ./x.sh` (one word), then `{{x}}`; `bash;x` then `{{x}}` | true | WSL | null (doesn't start bash at a program position) |
| `sudo bash ./x.sh {{x}}`, `timeout 5 bash ./x.sh {{x}}`, `npx bash ./x.sh {{x}}` | true | Git | refused (bare, behind a wrapper) |
| `sudo "C:\Program Files\Git\bin\bash.exe" ./x.sh {{x}}` | true | Git | null |
| `sudo .\bash ./x.sh {{x}}`; `sudo sub\bash.exe ./x.sh {{x}}` with `C:\work\sub\bash.exe` and `C:\work\sub\msys-2.0.dll` in the probe; `sudo \Program Files\Git\bin\bash.exe ./x.sh {{x}}` | true | Git (plus those files) | refused (not absolute, MSYS2 or not) |
| `timeout 5 C:\Windows\System32\bash.exe ./x.sh {{x}}` | true | WSL | refused |
| `bwrap --tmpfs /x bash ./x.sh {{x}}` | true | WSL | refused (an untrusted wrapper: later words scanned) |
| `runuser -u x bash ./x.sh {{x}}`, `runuser -w PATH -u x bash ./x.sh {{x}}` | true | Git | refused (bare, behind a wrapper; Task 2a) |
| `command bash ./x.sh {{x}}` | true | WSL | refused |
| `command -v bash`, `command -V bash` | true | WSL | null (only looks the name up) |
| `npx wsl -e bash ./x.sh {{x}}` | true | WSL | null (the walk decides: Linux bash) |
| `npx wsl -e bash.exe ./x.sh {{x}}` | true | WSL | refused (by the walk) |
| `find . -exec bwrap --tmpfs /x bash ./x.sh {{x}} ;` | true | WSL | refused |
| `uv run bash.exe ./x.sh {{x}}`, `poetry run bash ./x.sh {{x}}`, `conda run -n x bash.exe ./x.sh {{x}}`, `npm exec bash.exe ./x.sh {{x}}`, `uv run "ba"sh ./x.sh {{x}}` (quotes in the word) | true | WSL | refused |
| `uv run "C:\Program Files\Git\bin\bash.exe" ./x.sh {{x}}` | true | WSL | null |
| `uv pip install bash`, `uv pip install requests` | true | WSL | null (`pip` is not an exec subcommand) |
| `uv --directory /x run bash.exe ./x.sh {{x}}`, `pnpm --dir /x exec bash.exe ./x.sh {{x}}`, `poetry -C /x run bash ./x.sh {{x}}`, `npm --prefix /x exec bash.exe ./x.sh {{x}}` | true | WSL | refused (an option before the subcommand: every later word scanned) |
| `uv --x y pip install bash` | true | WSL | refused (declared over-refusal of that scan) |
| `"wsl.exe" ./deploy.sh {{x}}`, `"w"sl -e ./deploy.sh {{x}}` (quotes in the word), ` wsl ./deploy.sh {{x}}`, `wsl.exe. ./deploy.sh {{x}}` | true | WSL | refused (padded wsl, outright; `Program` `wsl`) |
| `npx wsl bash.exe ./x.sh {{x}}` (shell mode) | true | WSL | null here: the walk returns null for shell mode; `GetBlockedInvocation` refuses it (Task 3 row) |
| `uv --directory /x run wsl bash.exe ./x.sh {{x}}` (shell mode) | true | WSL | null (declared residual: `CheckWrapper` can't locate that runner's subcommand, so no guard sees this `wsl`) |
| `docker run img bash ./x.sh {{x}}`, `kubectl exec pod -- bash ./x.sh {{x}}` | true | WSL | null (Linux bash in the container) |
| `docker run img bash.exe ./x.sh {{x}}` | true | WSL | refused (off-Windows rule) |
| `pipx run bash ./x.sh {{x}}`, `dotnet tool run bash ./x.sh {{x}}` | true | WSL | null (not a wrapper or runner the guards know; residual) |
| `npm exec "x&bash ./x.sh" {{x}}`, `npm exec bash;x {{x}}` (one word each) | true | WSL | null (declared residual: a runner that hands an argument to cmd.exe) |
| `git commit -m bash {{x}}`, `git commit -m "fix the bash script" {{x}}`, `tool bash ./x.sh`, `tool "correct horse bash staple"` | true | WSL | null (arguments, not program positions) |
| `wsl -e bash ./x.sh {{x}}`, `wsl -d Ubuntu --exec bash ./x.sh {{x}}`, `wsl -e ./deploy.sh {{x}}`, `wsl --shell-type none bash ./x.sh {{x}}` | true | WSL | null (Linux bash inside the distribution) |
| `wsl -e bash.exe ./x.sh {{x}}`, `wsl --exec BASH.EXE ./x.sh {{x}}`, `wsl --shell-type none bash.exe ./x.sh {{x}}`, `wsl -d Ubuntu -e /mnt/c/Windows/System32/bash.exe ./x.sh {{x}}`, `wsl -e sudo bash.exe ./x.sh {{x}}` | true | WSL | refused; the reason starts `'wsl' runs 'bash.exe': ` |
| `wsl -e wsl.exe -e bash.exe ./x.sh {{x}}` | true | WSL | refused (nested) |
| `wsl -e wsl.exe -e bash ./x.sh {{x}}` | true | WSL | null |
| `wsl bash.exe ./x.sh {{x}}` (shell mode), `wsl --list`, `wsl --bogus bash.exe` | true | WSL | null here (`GetBlockedInvocation` refuses shell mode and unknown options; `--list` runs nothing) |
| `bashful ./x.sh`, `C:\tools\bash-5.exe ./x.sh`, `tool ./bashrc.d {{x}}` | true | WSL | null |
| `bash`, `C:\Program Files\Git\bin\bash.exe` | true | null | refused |
| `bash.exe`, `BASH.EXE`, `bash.exe.`, `/mnt/c/Windows/System32/bash.exe`, `/mnt/c/Program Files/Git/bin/bash.exe`, `"bash.exe"` (quotes in the word), ` bash.exe`, `"ba"sh.exe` | false | null | refused |
| `runuser -u x bash.exe ./x.sh {{x}}`, `runuser -u x -- bash.exe ./x.sh {{x}}` | false | null | refused (Task 2a) |
| `sudo bash.exe ./x.sh {{x}}`, `uv run bash.exe ./x.sh {{x}}`, `wsl.exe -e bash.exe ./x.sh {{x}}`, `wsl.exe -e /mnt/c/Windows/System32/bash.exe ./x.sh {{x}}`, `wsl.exe -e wsl.exe -e bash.exe ./x.sh {{x}}` | false | null | refused |
| `bash`, `/bin/bash`, `/usr/bin/bash`, `sudo bash ./x.sh {{x}}`, `uv run bash ./x.sh {{x}}`, `wsl.exe -e bash ./x.sh {{x}}` | false | null | null (Linux bash) |
| `tool bash.exe`, `bash.exe ./x.sh` (one word) | false | null | null (an argument; not a bash.exe name) |

Also test: each exact message once (Windows and off Windows), with `Program` `bash` and `bash.exe`. A refusal for
`bash ./x.sh 'v$(id)k7Qz'` never contains `k7Qz`.

Break-it-once:
1. Make the Windows branch return null when `Resolve` returns a file, MSYS2 or not. The `bash`/WSL row must fail.
2. Replace the rule with "allowed unless the resolved file's folder is System32, not found allowed" (the tempting
   design; round 5 M1). The `WindowsApps`, `C:\work` and not-found rows must fail.
3. Make the `wsl` branch return null without walking into the exec command (the round-1 design). The
   `wsl -e bash.exe` rows must fail.
3a. Drop the runner positions (3 in the list). The `uv run bash.exe`, `poetry run bash` and `npm exec bash.exe` rows
   must fail.
3b. Accept a relative word with a separator at `k >= 1`. The `sudo sub\bash.exe` row must fail.
3c. Name the word without removing `"`. The `"ba"sh` rows must fail.
3d. Give the container tools the Windows rule. The `docker run img bash` row must fail (refused).
4. Make it check the inner command with the caller's `windows` instead of the off-Windows rule. The `wsl -e bash`
   rows must fail (refused, because the inner call passes `probe: null`), and the `wsl -e bash.exe` rows must still be
   refused (round 4 M-1).
5. Drop the off-Windows branch. The off-Windows `bash.exe` rows must fail.
6. Skip the outright refusal of padded words. The Win32-probe rows `C:\msys64\usr\bin\bash.exe.` and
   `…\bash.exe ` must fail (allowed: the normalising `FileExists` finds them and `msys-2.0.dll` lies beside). With the
   exact Git probe no row can flip, because the raw word is resolved and isn't found (round 4 I-3).
7. Let the later-word scans run past a `wsl`. The `npx wsl -e bash` row must fail (refused).
8. Drop the `command -v` stop. The `command -v bash` rows must fail (refused).
9. Locate the subcommand as `:882` does even when an option precedes it. The `uv --directory /x run bash.exe`,
   `pnpm --dir /x exec bash.exe`, `poetry -C /x run bash` and `npm --prefix /x exec bash.exe` rows must fail
   (allowed).
10. Drop the outright refusal of padded wsl words. The `"wsl.exe"` and ` wsl` rows must fail (allowed: the raw
    word names no wsl and no bash).

## Task 3 (#411): `run` applies it before unlock and after substitution

In `RunCommand.cs`:
- After the file-token check (`:92-93`): `var msysProbe = windows ? ctx.MsysProbe() : null;` then
  `ThrowIfBlocked(Validation.BashLauncherRefusal(commandArgs, windows, msysProbe), windows);`. After it, so the
  existing refusals keep their precedence. `RunFileTokenTests.cs:764` doesn't pin that, because its assertion holds
  for either text (round 3 M-1), so a new row below does. The refusal comes before unlock (`:133`), so
  no key touch is asked for.
- At `:259`: `if ((Validation.GetBlockedInvocation(argv) ?? Validation.BashLauncherRefusal(argv, windows, msysProbe)) is { } blocked)`,
  and the `NameCulprit` predicate (`:264`) becomes
  `a => Validation.GetBlockedInvocation(a) is not null || Validation.BashLauncherRefusal(a, windows, msysProbe) is not null`.
  **The message there (`:266-270`) stays the generic one, on purpose** (review F5). It names the token and never the
  word or the value, and it doesn't describe WSL's re-parse. Do not add the word or the specific reason: the word came
  from a secret's value.
- At `:289`: `if (msysProbe is { } probe && MsysTarget.Resolve(…)…`. It is the same probe and the same behaviour, read
  once (`windows` is already part of `msysProbe`).

Tests (`TswapTests/RunBashLauncherTests.cs`, with the harness of `RunMsysTargetTests`: `FleetMachine`, `RecordingPty`,
`MsysProbe = () => probe`, `_m.Os = os`. The new class defines its own `Run(OSPlatform, MsysTarget.Probe?, params
string[])` helper over `FleetMachine` and `RecordingPty`, so the "null" rows can be written. `RunMsysTargetTests` does
not change: its `Run` takes a non-null probe (round 5 M5);
secret `pw` = `a\b"c`; `"…"` around a path is shell quoting, as in Task 2's table):

| OS | probe | command | outcome |
|---|---|---|---|
| Windows | WSL | `run bash ./capture.sh {{pw}}` | exit 1, 0 starts; stderr holds the Windows reason, then `ViewSecretLine(true)`; no value in stdout or stderr; **no key asked** (`_m.Keys.Challenges` cleared after the setup's `ingest`, then empty) |
| Windows | WSL | `run --env PW={{pw}} -- bash ./capture.sh` | exit 1, 0 starts, the Windows reason, no key asked |
| Windows | WSL | `run uv run bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts, the Windows reason, no key asked |
| Windows | WSL | `run "C:\Program Files\Git\bin\bash.exe" ./capture.sh {{pw}}` | exit 0, 1 start, argv `[GitBash]`, `WindowsArguments` as in `GitBash_StartsByItsResolvedPath_…` |
| Windows | WSL | `run tool {{pw}}` with `pw` = `bash` | exit 0, 1 start (an argument is not a program position) |
| Windows | WSL | `run bash {{@values.yaml}}` (the file written as `RunFileTokenTests` writes it) | exit 1, 0 starts; stderr holds `'bash' is a shell or interpreter, which can print the filled copy of a {{@file}} token past redaction.` (`GetFileTokenRefusal`'s interpreter branch, `Validation.cs:253-254`) and not `'bash' here is not` (the file-token refusal comes first; round 4 I-2) |
| Windows | WSL | `run {{prog}} ./capture.sh {{pw}}` with `prog` = `bash` | exit 1, 0 starts; stderr holds `After substitution, the value of {{prog}} makes this a command 'run' refuses` (`RunCommand.cs:266-270`, `:497-505`); stderr holds no `bash` word from the value (assert `DoesNotContain("'bash'")`) |
| Linux | null | `run bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts, the off-Windows reason then `ViewSecretLine(false)`, no key asked |
| Linux | null | `run bash ./capture.sh {{pw}}` | exit 0, 1 start, argv as given |
| Windows | WSL | `run wsl -e bash ./capture.sh {{pw}}` | exit 0, 1 start |
| Windows | WSL | `run npx wsl bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts; stderr holds `'npx' runs 'wsl': ` and `WslShellModeReason`'s text (T51's refusal, reached through `npx`) |
| Windows | WSL | `run "wsl.exe" ./deploy.sh {{pw}}` (quotes in the word) | exit 1, 0 starts, the padded-wsl reason, no key asked |
| Windows | WSL | `run wsl -e bash.exe ./capture.sh {{pw}}` | exit 1, 0 starts; stderr holds `'wsl' runs 'bash.exe': ` and the off-Windows reason |
| Windows | WSL | `run wsl -e {{prog}} ./capture.sh {{pw}}` with `prog` = `bash.exe` | exit 1, 0 starts; the generic message naming `{{prog}}`; no `bash.exe` in stderr |

Break-it-once: remove the new call before unlock. The first two rows must fail on their message assertion: the
check after substitution still refuses them (exit 1, 0 starts), but with the generic token-naming message, and only
after unlock, so the "no key asked" assertion fails too. Record which assertion failed. Then put it back and remove
only the call after substitution. The `{{prog}}` row must fail.

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
leg-2 branch); that .NET passes a quoted or space-padded `FileName` to `CreateProcess` as described; whether `bash\.` would start `bash.exe` (refused either way); that `File.Exists` is true for an App Execution Alias (0-byte reparse point); and that
the real `CreateProcess` order matches `Resolve`. WSL's re-parse comes from source, not from a run, because the runners
have no WSL distribution to run it in. Name the CI branch in the report once it has run.

## Task 4: docs

- `docs/security-model.md:186`: replace "Known gap of the inline-code check, filed: System32's `bash.exe` (WSL's
  launcher) runs its command line through `/bin/bash -c` (#411)." with "On Windows `run` refuses a `bash` at a program
  position (its own program, and the command of a wrapper or runner such as `sudo`, `timeout`, `npx`, `uv run`,
  `npm exec`) unless it resolves, by Windows' search order, to a file it recognises as Git Bash or MSYS2; behind a
  wrapper or runner it must be an absolute path. WSL's launcher (System32's `bash.exe`, or the WSL app's `bash.exe`
  alias) runs its whole command line through `/bin/bash -c` and can't be recognised positively (#411). Off Windows,
  inside a container and in the command of `wsl -e`, a `bash.exe` at a program position is refused, since there it
  reaches that launcher through interop. Like every check of `run`, this reads program positions, not text that
  another program later parses as a command line: a runner that hands a whole argument to cmd.exe or sh
  (`npm exec "x&bash"`, `uv run sh -c …`), and environment or glob expansion that forms a bash name (`%X%`, `$X`,
  `~`, `*`), are not checked. A copy or link of the launcher (or of `wsl.exe`) under another name, or that name's 8.3
  short name, still re-parses its command line unchecked. So does a copy named `bash.exe` with a `msys-2.0.dll`
  planted beside it, which passes the MSYS2 test. Inside a container `bash` is taken to be Linux bash: the rule
  assumes a Linux target. Git Bash given by an absolute path behind a wrapper or
  runner gets the runner's quoting, not T55's MSYS2 quoting, so a value can still arrive altered there (as before)."
  In the same cell's "Accepted over-refusals" list, add: "on Windows, a `bash` at a program position that isn't MSYS2
  (Cygwin's included) or isn't found; such a `bash` that holds `"`, white space at either end, or a trailing `.`, `\`
  or `/`; a relative or bare Git Bash behind a wrapper or runner (`sudo .\bash`): give its absolute path; a word
  naming bash that is really an untrusted wrapper's argument (`npx tool --name bash ./x.sh`), as the other guards'
  later-word scans already over-refuse; after a runner with an option before its subcommand, any later bash word,
  even under a subcommand that runs nothing (`uv --x y pip install bash`); and `wsl` written with quote characters,
  surrounding white space or a trailing dot". Also add to the residuals: "behind a runner whose subcommand follows an
  option (`uv --directory /x run wsl …`), `wsl`'s shell mode is not refused: the guards can't locate that subcommand".
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
- A runner that hands a whole argument to cmd.exe or sh (`npm exec "x&bash"`, `uv run sh -c …`), and environment or
  glob expansion that forms a bash name (`%X%`, `$X`, `~`, globs). Both are shared by every `run` guard, which checks
  program positions, not text another program later parses as a command line. The controller files one issue for
  runner pass-through across all guards. Declared in the docs (Task 4).
- Programs the guards don't know as wrappers or runners (`pipx run`, `dotnet tool run`, `pkexec`, `setpriv`,
  `prlimit`, `numactl`, `cgexec`, `sg`, Windows' `runas`): no positions after their own, as for every other guard.
  That issue covers them too.
- A copy of `wsl.exe` named `bash.exe` with a planted `msys-2.0.dll` beside it (round 4 M-3), and Windows containers
  or nodes behind the container tools (M-2): declared in the docs.
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
- **Round 2 (MiMo; controller's rulings).** I1: on Windows every word before the first `wsl` that names bash is
  checked, not only `ProgramPositions` (command runners `uv run`, `poetry run`, `conda run`, `npm exec`, `pipx run`,
  `dotnet tool run`). After `run`'s own program only an absolute MSYS2 path is accepted; off Windows any `bash.exe` word
  is refused. The over-refusals are declared. M1: relative words behind a wrapper are refused. M2: Task 3's
  break-it-once note corrected. M3: the `bash.exe.` row asserts only "refused". M4: the E2E exception stated. M5: "no
  key asked" asserted. M6: `:1450` and `SlotEnrol.cs:311`. Parser-first: words with extra text (`bash;x`, `x&bash`,
  `bash.exe:stream`) are split at cmd.exe's and sh's delimiters and refused. The pre-unlock call moved after the
  file-token check.
- **Round 3 (controller's ruling on the round-2 open question).** A word is no longer refused for merely containing
  `bash`. Only its would-be programs count: the pieces split at cmd.exe's command starts (`& | < > ( )`, line breaks;
  off Windows also sh's `;`, backtick and `$(`), each read up to the first separator or as a quoted name. So
  `git commit -m "fix the bash script"` and a passphrase are allowed, and `x & bash -c y` and `bash` are refused. Two
  parser-first details go beyond the ruling's wording, both failing closed: a quoted program is read to its closing
  `"` (cmd.exe's rule, so `"C:\…\bash.exe"` is caught), and `"`/`^` inside a name are ignored, as cmd.exe ignores them.
  The over-refusal list in the docs task is narrowed to match.
- **Round 5 (MiMo round 3: I-1 quote-toggled names, I-2 expansion; controller's ruling).** This round **reverts the
  per-word model of rounds 3-4**: the scan of every word, the command-start splitting, the quoted-program reading and
  the `"`/`^` stripping across all words go, with their rows and break-it-once checks. Three patches to the same
  property had each opened a new fail-open, because no per-word model can match what another program's parser later
  does with an argument. The check now uses the model every other `run` guard uses: program positions, as
  `CheckWrapper` reaches them (`argv[0]`, simple wrappers via `ProgramPositions`, later words behind untrusted wrappers,
  words after a runner's exec subcommand, container tools with the off-Windows rule), plus round 2's wsl exec walk. At
  a position, `"` is removed by toggling before naming (so `"ba"sh` is refused), and a quoted, padded or trailing-dot
  word is refused outright. Runner pass-through to cmd.exe or sh, and expansion, are declared residuals shared by all
  guards. Round 2's M1 (absolute only behind a wrapper), M2-M6 and the "no key asked" assertion stay. MiMo round 3's
  minors: M-1 (a row pins the file-token precedence), M-2 (`bash\.`, `bash\`, `bash/` trimmed and refused), M-3
  (`WslWalk` wording), M-4 (`char.IsWhiteSpace`, fail closed), M-5 (the SysWOW64 claim dropped), M-6 (docs line:
  Git Bash behind a runner gets the runner's quoting), M-7 (empty argv; verbatim literals).
- **Round 6 (MiMo round 4; controller's rulings).** I-1: `runuser` was missing from the shared `Wrappers` list, so
  every `ProgramPositions` guard skipped its command. New Task 2a adds it, with util-linux's valued options (`-w` added
  to `WrapperValued`). The `ShellAsUser` branch moves above the `Wrappers` branch, so the `-c` refusal still runs
  first and `GetBlockedInvocation` is unchanged. No existing row changes; the file-token guard gains `runuser`
  (tightening). I-2: the precedence row asserts the file-token refusal's real text. I-3: break-it-once 6 uses a probe
  whose `FileExists` normalises as Win32 does, so it can fail. M-1: break-it-once 4's rows corrected. M-2: the
  container rule assumes a Linux target, declared. M-3: the planted-`msys-2.0.dll` copy declared. M-4: `command -v`/`-V`
  stops the walk, as in `CheckWrapper`. M-5: a `wsl` walk owns its command. M-6: `RunFileTokenTests.cs:1003` added to
  the checked list.
- Controller confirmations (2026-11-27): round 5's M1 kept (behind a wrapper or runner only an absolute Git Bash path is accepted); `pipx run`, `dotnet tool run` and the other unknown runners and wrappers go to #438; Task 2a's reorder of `GetBlockedInvocation` (ShellAsUser above Wrappers) is sanctioned, because it keeps every existing refusal and is needed to add `runuser` without a fail-open.
- **Round 7 (MiMo round 5, DeepSeek round 1; controller's rulings).**
  - I1: after a runner whose first word is an option, every later bash word is checked (no per-runner option table),
    with rows for `uv --directory`, `pnpm --dir`, `poetry -C` and `npm --prefix`. The over-refusal is declared. Break-it-once 9.
  - I2: a padded or quoted word that names `wsl` is refused outright. This closes a pre-existing T51 gap:
    `GetBlockedInvocation` names the raw word, so `"wsl.exe"` never reached `CheckWsl`, yet Windows starts wsl.exe
    in shell mode. Break-it-once 10.
  - MiMo M1-M7: break-it-once 2 reworded; rule 2 is simple wrappers only and covers every word after the wrapper;
    processing order stated; the new test class has its own `Run`; `TSWAP_TEST_KEY` in the evidence command; the
    untrusted-wrapper argument over-refusal declared.
  - DeepSeek M1: rule 4's wording corrected. Its premise was wrong for `npx`: `npx` is a simple wrapper, so
    `CheckWrapper` reaches `wsl` and T51 refuses `npx wsl bash.exe …` (now a Task 3 row). The real gap is a runner
    whose subcommand can't be located, pinned as a declared residual row.
  - DeepSeek M2: annotated. With the branch moved back, the `-c` rows are allowed, not refused by the echo check,
    because `echo {{x}}` is one word.
  - Citations corrected: `Resolve` `:43-61`, `IsMsys2` `:86-98`, `CheckWsl` to `:1025`.
