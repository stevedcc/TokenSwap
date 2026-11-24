# Brief T55: `run` passes its arguments to Git Bash (MSYS2) on Windows exactly (#402)

Issue: #402 (read it with its comment: non-ASCII was tswap's own stdin bug, fixed by T48; the line-break cut on the
ConPTY leg may be RedactingPty's). Milestone 0.3.3. Base: `origin/main` at 666336c; branch `brief/t55`. Read AGENTS.md and
CLAUDE.md first, then `TswapCli/Commands/RunCommand.cs` (from the substitution at line 239 to the start at line 311),
`TswapCli/CommandContext.cs` (the seams at lines 136-145), `TswapTests/EndToEndTests.cs` (lines 2119-2280: `FindGitBash`,
the two Git Bash tests, `GitBashExtras`, `RunGitBashCases`, the skipped `Finding3`-`Finding5` facts),
`TswapTests/EvilValues.cs` (`KnownFindings`, lines 176-197), `TswapTests/RecordingPty.cs` and `docs/scripts.md` (the Git
Bash paragraph, lines 47-57).

One commit per task, test first, a break-it-once check per key test (name in the commit message the line you changed and
the test that failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and report
when the brief can't be built as written. **No existing test's assertions change.** The sanctioned test edits are Task 5's:
the deletion of the eight skipped `Finding3`-`Finding5` facts with their `KnownFindings` entries, constants and helper (as
T50a retired finding 1), the `glob-star` exclusion line, and the added `GitBashExtras` rows and work-folder files. If any
other existing test fails because of a rule here, stop and list it. **Do not touch `TswapCore/Validation.cs`** (T51 owns
its checks); this brief's code goes in a new file. No message and no test failure text contains a value.

## Owner decisions (2026-11-23)

- **RedactingPty 1.3.0 first.** The RedactingPty change below (`RedactionOptions.WindowsArguments` and `WindowsPty`
  quoting any whitespace) is briefed, built and released before Task 4; Tasks 1-3 don't wait for it.
- **R1-R3 stay refusals, not warnings.** A secret that silently arrives altered counts as data loss, so `run` refuses
  rather than starting the child with a value it can't pass exactly.

## Review round 1 amendments (GLM, MiMo; 2026-11-24) — these bind and win over the text below

Folded into the text: Task 1 hard-codes the code page 932 bytes (no `CodePagesEncodingProvider`, no new package) and gains the
`t55probe2` row; Task 2's `.exe` rule follows CreateProcess's documented rule (no `.exe` for a name holding a path) unless
that row says otherwise; Task 5's break-it-once reverts the whole Task 4 commit and names the cases that really change.
The rest:

1. **Line references** were taken at 666336c; T50b and T56 moved `EndToEndTests.cs` (~+120 lines) and `EvilValues.cs`
   (~3). Find each place by the name the brief gives; names win over numbers. `max-length` is a `Cases` entry.
2. **"No message holds a value"** means tswap's own output and refusal texts. Test failure text and the spike's table may
   show values: they are test data.
3. **R1** refuses when an argument holds `\` or `"` and the `MSYS` variable changes the glob option: one of its words
   (split at whitespace, ignoring case) is `noglob` or starts with `glob:`. A plain `glob` is the default and does not
   refuse. Word R1's message and Task 6's sentence as "`MSYS` changes the glob option and an argument holds a backslash or
   double quote" (not "sets a glob option").
4. **Rule 4 (globify)** calls `glob` with `GLOB_TILDE | GLOB_NOCHECK | GLOB_BRACE | GLOB_QUOTE`; `GLOB_QUOTE` is what makes
   the escape-every-character step produce literals. A pattern with an illegal byte sequence matches nothing even with
   `GLOB_NOCHECK`, and the word then keeps its quotes: unreachable for values `ingest` stores (well-formed text), noted only.
5. **`{what}`**: rules in the order R1, R2, R3; the first rule that finds anything decides; within it, every argument in
   argv order, and the tokens whose substituted text the rule found, each named once (as `BatchArgumentRefusal` does).
6. **R2 and R3 skip the program** because it is not a value (after `Resolve`, argv[0] is the path P). Don't "fix" that.
7. **R2 keeps refusing a locale with no charset part** (`LANG=de_DE`): deliberate, fail closed. The spike records
   `de_DE`; if it shows such values pass, the controller may relax it later in its own change.
8. **`ForThisProcess()` is null off Windows**: that test is `[UnixFact]` (or skips on Windows), beside the `[WindowsFact]` rows.
9. **`Run_GitBashScript_EvilValues_ArriveExactly_Windows`**: its child environment removes `LC_ALL`, `LC_CTYPE` and `LANG`,
   so a runner's locale can't make R2 refuse the non-ASCII cases. A test-input change; say so in the commit.
10. **`Resolve` divergences accepted** (documented in its XML comment): an empty `PATH` entry is skipped, and a
    drive-relative name (`C:file.exe`) is taken as is.
11. **Accepted as written:** `IsMsys2` recognises the two shapes only (a bash.exe that finds `msys-2.0.dll` through PATH is
    not detected; Task 6 says "recognises"); R1/R2 also refuse when the trigger is in a literal argument (fail closed);
    `Prompt.cs`'s "(its arguments may arrive altered)" stays (still true for refused and undetected setups; prompt hash).
12. **Release note**: add "and with RedactingPty 1.3.0 a value holding a line break reaches any Windows program whole".

## What is wrong (evidence)

`run` hands the child its argv through RedactingPty (`RunCommand.cs:303-311`, `CommandContext.cs:136`, package
`[1.2.0]` at `TswapCli.csproj:31`), which on Windows builds the command line itself: the redirected leg through .NET's
`ProcessStartInfo.ArgumentList` (RedactingPty v1.2.0 `FallbackPty.cs:39-47`), the ConPTY leg through its own
`WindowsQuoteArg` (`WindowsPty.cs:417-450`, then `CreateProcess(null, cmdLine, ...)` at line 251). Both quote for
Microsoft's C runtime: an argument without a space, tab or `"` (WindowsPty) or without whitespace or `"` (.NET) goes
unquoted. Git Bash's `bash.exe` is an MSYS2 program, and MSYS2 parses that command line by its own rules. T47 Task 2f's
findings (CI run 45021236991), skipped at `EndToEndTests.cs:2257-2279`, entries `EvilValues.cs:182-189`:

- **3:** `'` is removed (`single-quote`, `owner-escaping-set`); **4:** braces are expanded (`{{other-secret}}` arrives as
  `other-secret`); and `glob-star` (`abc*def-value-2`) matches a file, so `EndToEndTests.cs:2154-2155` leaves it out;
- **5:** on the ConPTY leg only, a value holding CR or LF arrives cut at the break.

### MSYS2's parser (the source, not examples)

msys2-runtime `msys2-3.6.12` (commit 50c44b7), `winsup/cygwin/`; Git for Windows' fork (`git-for-windows/msys2-runtime`
main, d25c02b) has the same `dcrt0.cc` except the conversion call named below.

1. **Conversion.** At startup the runtime reads `GetCommandLineW()` and converts it to the locale's multibyte charset
   (`dcrt0.cc:914-917`, `sys_wcstombs_no_path`; Git's fork calls `sys_wcstombs`, which is the same non-path conversion in
   its `local_includes/wchar.h:183-187`). The locale comes from `LC_ALL`, `LC_CTYPE`, `LANG` (`initial_setlocale`,
   `nlsfuncs.cc:1790-1795`, before `build_argv`); unset or `C` converts as UTF-8 (`strfuncs.cc:962-963`). In a non-UTF-8
   charset a character becomes that charset's bytes; in Shift-JIS, GBK or Big5 a second byte can be `0x5C` (`\`).
   Runtimes before Cygwin commit 01e6f6b742 (2015-12-18, "Make paths' WCS->MBS conversion explicit") used the path
   conversion here, which turns U+F000-U+F07F back into ASCII (`"`, space, `*`, control characters...) and U+F080-U+F0FF
   into single raw bytes (`strfuncs.cc:986-992`, table at lines 64-96).
2. **Words** (`build_argv`, `dcrt0.cc:305-375`; with a non-Cygwin parent `winshell` is 1, and `glob` is 1 unless `MSYS`
   sets a glob option, `dcrt0.cc:921-923`). A word ends at an unquoted space, tab, **CR or LF** (`issep`,
   `winsup.h:137`). `"` and `'` open a quoted run (`quoted`, `dcrt0.cc:157-196`): inside `"`, a `\` makes the next byte
   ordinary (it never ends the run) and `""` stands for one `"`; inside `'` nothing is special. The first word (the
   program) only has its quotes stripped and is never expanded.
3. **@file.** A later word that starts with an unquoted `@` is replaced by the named file's contents, which are parsed
   as more words (`dcrt0.cc:351-358`, `insert_file` at lines 88-143). A word that starts with a quote never is.
4. **Expansion** (`globify`, `dcrt0.cc:207-300`), for every later word that holds `? * [ " ' ( ) { }` or starts with
   `~`: outside quotes the word is a glob, brace and tilde pattern (`GLOB_TILDE | GLOB_NOCHECK | GLOB_BRACE`);
   **inside quotes** every character is escaped (literal), except that `\\` becomes `\` and `\` before the run's own quote
   character becomes that character; any other `\` stays. This holds for drive and UNC paths too (lines 240-251: the
   older "don't use \ quoting in a DOS path" rule was removed).
5. **Glob off.** `MSYS=noglob` (or `glob:` with nothing after it) sets `glob` to 0 (`environ.cc:55-71`, option table at
   line 127, read from `MSYS=` at line 941); `quoted` then only strips the quote characters, with no `\` handling
   (`dcrt0.cc:163-170`).
6. **Git's launcher.** `Git\bin\bash.exe` and `Git\bin\sh.exe` are not MSYS2 programs: both are copies of
   `compat-bash.exe` (git-for-windows/MINGW-packages 560c0dc, `mingw-w64-git/PKGBUILD:571-572`), the Git wrapper
   configured to start `@@EXEPATH@@\..\usr\bin\bash.exe` (`compat-bash.rc`), which copies the rest of its own command line
   after `argv[0]` verbatim (`git-wrapper.c:215-305`, `fixup_commandline`). MSYS2 programs (`Git\usr\bin\*.exe`,
   `C:\msys64\usr\bin\*.exe`) load `msys-2.0.dll` from their own folder.

So findings 3 and 4 are MSYS2 expanding unquoted words. **Finding 5's cause is RedactingPty's `WindowsPty`:** it leaves an
argument holding CR or LF unquoted (only space, tab and `"` trigger quoting), and MSYS2 ends a word at CR and LF; .NET
quotes any whitespace, so the redirected leg is intact. That is fixed in RedactingPty (below), and tswap's own MSYS2
quoting (Task 3) covers it for every target tswap detects.

### Prerequisite: RedactingPty 1.3.0 (a separate RedactingPty change, not this brief)

tswap can't pass a command line of its own today: `IPtyRunner.Run` takes argv only. The controller briefs this in
stevedcc/RedactingPty and releases it as 1.3.0 before Task 4:

- **`RedactionOptions.WindowsArguments`** (`string?`, default null). When set, the runner starts `argv[0]` (argv must then
  have exactly one element) with this text as the arguments part of the command line, verbatim: `WindowsPty` passes
  `argv[0]` quoted as today, a space and the text (no space when the text is empty) to `CreateProcess`; `FallbackPty`
  sets `ProcessStartInfo.Arguments` to it. Set on Linux or macOS, or with more than one argv element: an
  `ArgumentException` before anything starts.
- **`WindowsPty` quotes like .NET:** an argument that is empty or holds any `char.IsWhiteSpace` character or `"` is
  quoted (today only space, tab and `"`), so both legs build the same command line and an MSYS2 child tswap doesn't
  detect still gets a value holding a line break as one word.

## Task 1: spike round 2 (throwaway, the controller runs it on Windows CI)

On a branch `t55-spike` from 666336c (never merged, separate from `brief/t55`), add `TswapTests/MsysSpike2Tests.cs`: one
`[WindowsFact("spike: Git Bash on Windows")]` that builds a results table and ends with
`Assert.Fail("SPIKE TABLE\n" + table)` (and writes it to `%TEMP%\msys-spike-2.txt`). Commit it there, then **stop and
report**; the controller pushes the branch, runs CI, posts the table on #402 and records it in an amendment here. Tasks
2-6 then go on `brief/t55`.

The spike starts Git Bash with `ProcessStartInfo` (`UseShellExecute = false`, output redirected, a 30 s
`WaitForExit` that kills and records `TIMEOUT`), in a temporary work folder holding `capture.sh`
(`printf '%s' "$#" > n.txt; printf '%s' "$1" > out.txt`), an empty `abcXdef-value-2`, an empty `a-value` and
`at-file.txt` holding `INJECTED`. Two programs: `bin\bash.exe` (the test's `FindGitBash` rule: the first `bash.exe` in a
PATH folder under `\Git\`) and `..\usr\bin\bash.exe` beside it. A cell is `ok` when `n.txt` is `1` and `out.txt` holds the
value's UTF-8 bytes exactly; otherwise it shows `n=<count>` and what arrived, every character outside U+0020-U+007E as
`\uXXXX` (raw bytes as hex for the locale rows). Before the table: the runner's `MSYS`, `LC_ALL`, `LC_CTYPE` and `LANG`.

Strategies (the arguments part of the command line; argument 1 is `./capture.sh`):
- **M** (the proposal): each argument in `"`, every `\` and `"` inside preceded by `\` (Task 3's `QuoteArguments`);
- **W**: RedactingPty 1.2.0's `WindowsQuoteArg` copied verbatim (the ConPTY leg);
- **N**: `ArgumentList` (the redirected leg);
- **R**: the value raw, unquoted.

Values: the corpus (`EvilValues.Cases` and `BatchCases` without `max-length`), and these (C# literals):
`"a\\b"`, `"a\\\\b"`, `"a\\\\\\b"`, `"a\\"`, `"a\\\\"`, `"\\"`, `"\\\""`, `"a\\\"b"`, `"a\\\\\"b"`, `"\""`, `"\"\""`,
`"a\"\"b"`, `"C:\\x\\y"`, `"C:\\x\"y\\"`, `"c:\"x"`, `"\\\\srv\\share\\x"`, `"@at-file.txt"`, `"@missing-file"`, `"~"`,
`"~/x"`, `"*"`, `"abc*def-value-2"`, `"[ab]-value"`, `"{a,b}-value"`, `"a b"`, `"a\tb"`, `"a\nb"`, `"a\rb"`,
`"a\r\nb"`, `"a\vb"`, `"a\fb"`, `"caf\u00E9"`, `"\u8868x"`, `"\u30BDx"`, `"x\uF022 \uF020y"`, `"x\uF02Ay"`,
`"x\uF080y"`; and an empty argument (M and N only).

Runs: every value with M, W, N and R through `bin\bash.exe`; every value with M through `usr\bin\bash.exe`; M with
`MSYS=noglob`; M with `LANG=ja_JP.SJIS` (expected bytes hard-coded, no code-page provider: `\u8868x` is `95 5C 78` and `\u30BDx` is `83 5C 78` in code page 932; the second byte of each is `\`); M with
`LANG=de_DE` (record only). One more row, the program search: copy `System32\whoami.exe` to the work folder as
`t55probe.exe` and start `FileName = "t55probe"` (working folder the work folder) once as is and once with
`NoDefaultCurrentDirectoryInExePath=1` set in the spike's own process (restored after); record started or not. And
once more with a path and no extension: copy it again as `t55probe2.exe` and start `FileName = "<work>\t55probe2"`
(full path, no `.exe`); record started or not (it settles `Resolve`'s `.exe` rule, Task 2).

Expected, and what changes if CI disagrees:

| Question | Expected | If not |
|---|---|---|
| M, default environment, both programs | every value `ok` | Task 3's quoting changes to the observed rule; a value no encoding passes becomes a refusal (stop, the controller decides) |
| M through `bin\bash.exe` and through `usr\bin\bash.exe` | identical columns | stop: the launcher rule (Task 2) is wrong |
| Line breaks: W cut (`n=2`), N and M `ok` | W cut, N `ok` | if W is intact, finding 5's cause is not the quoting: stop |
| R and W on `@at-file.txt` | `INJECTED` arrives | none (M is what counts) |
| M under `MSYS=noglob` | only values holding `\` or `"` altered | if others are altered, refusal R1 drops its `\`/`"` condition |
| M under `ja_JP.SJIS` on `\u8868x`, `\u30BDx` | altered or split | if intact, stop: the source reading is wrong somewhere, the controller decides R2 |
| M on U+F0xx values, default | `ok` (current runtimes) | R3 stays either way (older runtimes) |
| `<work>\t55probe2` (path, no extension) | not started (CreateProcess's documented rule: no `.exe` for a name holding a path) | `Resolve` appends `.exe` to path names too, and the `C:/msys64/usr/bin/bash` row becomes `C:\msys64\usr\bin\bash.exe`, yes |
| `t55probe` with the variable | not started | if started, Task 2's search keeps the current folder when the variable is set |

## Task 2: detect an MSYS2 target

New file `TswapCore/MsysTarget.cs`, `public static class MsysTarget`. Everything works on Windows path strings without
`System.IO.Path` (the unit tests run on Linux): a folder and a name are joined with one `\` (the folder's trailing `\` and
`/` trimmed), and a folder's parent is the text before its last `\` or `/` (trailing separators trimmed first).

```csharp
public sealed record Probe(string? ExeDirectory, string CurrentDirectory, string SystemDirectory, string WindowsDirectory,
    Func<string, string?> GetVariable, Func<string, bool> FileExists)
{
    // Off Windows null; on Windows the real machine: Environment.ProcessPath's folder, the current directory,
    // Environment.SystemDirectory, the Windows folder, Environment.GetEnvironmentVariable, File.Exists.
    public static Probe? ForThisProcess();
}
public static string? Resolve(string program, Probe probe);
public static bool IsMsys2(string path, Func<string, bool> fileExists);
```

**`Resolve`** returns the file `CreateProcess` starts for `program` (its documented search for a command line with no
application name), or null. Both methods first turn every `/` into `\` (Windows reads them alike) and check paths only
through `FileExists` (the tests' fake ignores case, as Windows does). The name gets `.exe` appended when its last
component has no `.` and the name holds no `\` or `:` (CreateProcess's documented rule; the spike's `t55probe2`
row confirms it or changes it, see Task 1). A program holding `\` or `:` is not searched: one that starts with `\` or with a letter and `:` is
taken as is, any other is joined to `CurrentDirectory`. Otherwise the first folder, in this order,
where `FileExists(folder\name)` is true: `ExeDirectory` (when not null), `CurrentDirectory` (skipped when
`GetVariable("NoDefaultCurrentDirectoryInExePath")` is not null, unless the spike says otherwise), `SystemDirectory`,
`WindowsDirectory\System`, `WindowsDirectory`, then each non-empty entry of `GetVariable("PATH")` split at `;` (surrounding
`"` removed).

**`IsMsys2`** is true when `fileExists(<path's folder>\msys-2.0.dll)`, or when the path's last component is `bash.exe` or
`sh.exe` (ignoring case), its folder's last component is `bin` (ignoring case) and
`fileExists(<the folder's parent>\usr\bin\msys-2.0.dll)` (Git's launcher). Anything else, including WSL's
`System32\bash.exe`, is false.

Tests (`MsysTargetTests`, a fake file set; `CurrentDirectory` `C:\work`, `ExeDirectory` `C:\tools`, `SystemDirectory`
`C:\Windows\System32`, `WindowsDirectory` `C:\Windows`, `PATH` `C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin`;
Git's files `C:\Program Files\Git\bin\bash.exe`, `...\Git\bin\sh.exe`, `...\Git\usr\bin\bash.exe`,
`...\Git\usr\bin\msys-2.0.dll`; `C:\msys64\usr\bin\bash.exe` and its `msys-2.0.dll`):

| Program | Extra files | `Resolve` | MSYS2 |
|---|---|---|---|
| `bash` | `C:\Windows\System32\bash.exe` | `C:\Windows\System32\bash.exe` | no (WSL) |
| `bash` | none | `C:\Program Files\Git\bin\bash.exe` | yes (launcher) |
| `sh.exe` | none | `C:\Program Files\Git\bin\sh.exe` | yes (launcher) |
| `C:\Program Files\Git\usr\bin\bash.exe` | none | itself | yes (dll beside) |
| `C:/msys64/usr/bin/bash` | none | null (a path gets no `.exe`) | no: started as today |
| `C:/msys64/usr/bin/bash.exe` | none | `C:\msys64\usr\bin\bash.exe` | yes |
| `bash` | `C:\work\bash.exe` | `C:\work\bash.exe` | no |
| `bash`, `NoDefaultCurrentDirectoryInExePath=1` | `C:\work\bash.exe` | `C:\Program Files\Git\bin\bash.exe` | yes |
| `bash` | `C:\tools\bash.exe` | `C:\tools\bash.exe` | no |
| `.\x\bash.exe` | `C:\work\.\x\bash.exe` | `C:\work\.\x\bash.exe` | no |
| `C:\Program Files\Git\mingw64\bin\git.exe` | itself | itself | no |
| `C:\Windows\System32\bin\bash.exe` | itself | itself | no (no `usr\bin\msys-2.0.dll` above) |
| `nosuch` | none | null | no |

And `ForThisProcess()` is null off Windows. Plus one `[WindowsFact]` on the real machine:
`IsMsys2(FindGitBash's path, File.Exists)` and `IsMsys2(<that>\..\..\usr\bin\bash.exe, File.Exists)` are true,
`IsMsys2(Path.Combine(Environment.SystemDirectory, "bash.exe"), File.Exists)` is false (whether or not WSL is there).
Break-it-once: drop the launcher rule, the `bash`-with-no-extra-files row must fail; search `PATH` before
`SystemDirectory`, the WSL row must fail.

## Task 3: quoting and refusals for an MSYS2 target

In `MsysTarget`:

```csharp
public static string QuoteArguments(IReadOnlyList<string> arguments);
public static string? Refusal(IReadOnlyList<string> arguments, IReadOnlyList<Validation.SubstitutedToken> tokens,
    Func<string, string?> childVariable);
```

**`QuoteArguments`**: each argument in `"`, with every `\` and every `"` in it preceded by one `\`; the arguments joined by
one space. By rules 2-4 above that is exactly one word, never split (CR and LF are inside quotes), never an @file (it
starts with `"`), never expanded, and `\\` and `\"` decode to `\` and `"`. Rows (C# literal argument, expected text):

| Argument(s) | Quoted |
|---|---|
| `"abc"` | `"abc"` |
| `""` | `""` |
| `"a b"` | `"a b"` |
| `"a\\b"` | `"a\\b"` (2 backslashes) |
| `"a\\\\b"` | `"a\\\\b"` (4) |
| `"a\\"` | `"a\\"` |
| `"a\"b"` | `"a\"b"` |
| `"a\\\"b"` | `"a\\\"b"` (3 then the quote) |
| `"'"`, `"{{x}}"`, `"@f"`, `"*"` | each in `"`, unchanged inside |
| `"a\nb"` | `"a`, LF, `b"` |
| `"./capture.sh"`, `"a\"b"` | `"./capture.sh" "a\"b"` |

(In the right column, quotes and backslashes are the text's own characters.) Also a property test: for every corpus value
and Task 1's values, a small C# decoder of rules 2 and 4 (inside `"`: `\\` to `\`, `\"` to `"`, other `\` kept) applied
to `QuoteArguments([v])` gives back `[v]`. Break-it-once: leave `\` alone (escape only `"`), the `"a\\b"` row and the
property test must fail.

**`Refusal`** checks every argument (the program excluded) against the child's environment (`childVariable`: run's
`--env` pairs first, then tswap's own variables; names compared ignoring case, as Windows does) and returns the first of:

- **R1 (glob option):** `MSYS` holds `glob` (ignoring case) and an argument holds `\` or `"`.
  `Refused: MSYS sets a glob option, with which Git Bash (MSYS2) reads backslashes and double quotes in its arguments differently, so tswap can't pass {what} exactly. Remove the glob option from MSYS for this command, or pass the secret in the environment ('run --env PW={{name}} -- <bash.exe> ./script.sh', read as "$PW").`
- **R2 (locale):** the first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG` is set and is neither `C` nor `POSIX` nor has a
  charset part (after the first `.`, up to an `@`) equal to `UTF-8` or `utf8` ignoring case, and an argument holds a
  character above U+007F.
  `Refused: the locale (LC_ALL, LC_CTYPE or LANG) is not UTF-8, and in it Git Bash (MSYS2) can read part of a non-ASCII character as a backslash, so tswap can't pass {what} exactly. Use a UTF-8 locale for this command, or pass the secret in the environment ('run --env PW={{name}} -- <bash.exe> ./script.sh', read as "$PW").`
- **R3 (private use):** an argument holds a character in U+F000-U+F0FF.
  `Refused: {what} holds a character from U+F000 to U+F0FF, which older MSYS2 runtimes turn into ASCII such as a quote or a space before reading the command line. Pass the secret in the environment ('run --env PW={{name}} -- <bash.exe> ./script.sh', read as "$PW").`

`{what}` is `the argument(s) from 'a', '{{@f.yaml}}'` (the tokens whose substituted text holds what the rule found, secret
names as `'name'`, file tokens as `'{{@path}}'`, in argv order, each once) or `an argument` when no token's text does.
Never a value, a variable's value or the character. Rows: R1 with `MSYS=noglob` and `a\b` (refused), with `MSYS=noglob`
and `abc` (null), with `MSYS=winsymlinks:nativestrict` and `a\b` (null), `msys=GLOB:ignorecase` and `a"b` (refused); R2
with `LANG=ja_JP.SJIS` and `caf\u00E9` (refused), `LANG=ja_JP.SJIS` and `abc` (null), `LC_ALL=` empty and
`LANG=de_DE` and `\u00E9` (refused), `LC_ALL=C.UTF-8`, `LANG=en_US.utf8`, `LANG=C`, `LANG` unset (each null with
`\u00E9`), `LC_CTYPE=en_GB.UTF-8@euro` (null); R3 with `x\uF022y` and `x\uF0FFy` (refused), `x\uEFFFy` and `x\uF100y`
(null); the `{what}` forms (one secret, two secrets and a file, none); no message holds the value (value
`a"b$c&d'e\u00E9\uF022`). Break-it-once: drop R1's check, its first row must fail.

If Task 1 disagrees with any rule here, the amendment recording it replaces the rule; build what it says.

## Task 4: `run` uses it (needs RedactingPty 1.3.0)

If RedactingPty 1.3.0 with `WindowsArguments` is not on NuGet when you reach this task, stop and report. Pin it
(`[1.3.0]`, `TswapCli.csproj:31`). Add the seam to `CommandContext`, beside `StdoutConsoleMode`:
`internal Func<MsysTarget.Probe?> MsysProbe { get; init; } = MsysTarget.Probe.ForThisProcess;`.

In `RunCommand`, right after the batch check (`RunCommand.cs:265-267`), when `windows` and `ctx.MsysProbe()` is not
null and `Resolve(argv[0], probe)` is a path `P` with `IsMsys2(P, probe.FileExists)`:
`MsysTarget.Refusal(argv[1..], Validation.SubstitutedTokens(commandArgs, secretValues, filePaths), childVariable)` throws
a `TswapException` with its text when not null; otherwise the child is started with argv `[P]` (the resolved path, so
what was detected is what starts) and `options with { WindowsArguments = MsysTarget.QuoteArguments(argv[1..]) }`.
`childVariable` looks a name up in the `environment` dictionary (`RunCommand.cs:157-166`) ignoring case, then in
`probe.GetVariable`. Every other program, and every OS but Windows, starts exactly as today (`WindowsArguments` null).
The verbose `Executing:` line is unchanged.

Tests (`RunMsysTargetTests`, in process, `FleetMachine.Os = OSPlatform.Windows`, a `RecordingPty`, a fake `Probe` with
Task 2's Git files): `run bash ./capture.sh {{pw}}` with `pw` = `a\b"c` starts once with argv
`[C:\Program Files\Git\bin\bash.exe]` and `WindowsArguments` `"./capture.sh" "a\\b\"c"`; `run tool {{pw}}` (not found)
starts with `[tool, a\b"c]` and null; the same `bash` command with `FleetMachine.Os = OSPlatform.Linux` starts with
`[bash, ./capture.sh, a\b"c]` and null; with `MSYS=noglob` in the probe's variables it exits 1, the child never starts
(`Starts == 0`), stderr holds the R1 text with `'pw'` and not the value; `run --env MSYS={{g}} -- bash ./capture.sh {{pw}}` (`g` =
`noglob`) the same (the `--env` pair counts); `run --env PW={{pw}} -- bash ./capture.sh` starts with `WindowsArguments` `"./capture.sh"`.
Break-it-once: start with the original argv and no `WindowsArguments`; the first test must fail.

## Task 5: the acceptance tests

Delete the eight skipped facts `Finding3_SingleQuote_GitBashExact` ... `Finding5_CrInside_GitBashExact`
(`EndToEndTests.cs:2256-2279`), the helper `AssertGitBashArrivesExactly` (2245-2254), the eight `GitBashExact` entries of
`KnownFindings` (`EvilValues.cs:180-189`, with their comment) and the constants `Finding3`-`Finding5` (194-197):
`Run_GitBashScript_EvilValues_ArriveExactly_Windows` now runs those cases with its full assertion, and
`KnownFindings_NameRealCasesAndInvariants_AndEachHasItsSkippedFact` stays green because table and facts change together.
In that test, drop the `glob-star` exclusion (lines 2152-2155: the comment, the output line and the `Where`), so every
extra runs. Add to `GitBashExtras` (class `git-bash`): `double-backslash` `"abc\\\\def-value"`, `trailing-backslash`
`"abc-value\\"`, `backslash-quote` `"abc\\\"def-value"`, `drive-path-backslash` `"C:\\abc\\def-value"`, `unc-path`
`"\\\\srv\\share\\def-value"`, `at-file` `"@abcXdef-value-2"`, `brace-list` `"{a,b}-value"`, `glob-class` `"[ab]-value"`,
`tilde` `"~/x-value"`; and in `RunGitBashCases` also create an empty `a-value` in the work folder (so `[ab]-value` has a
match). The `--env` test runs the new extras too. No assertion changes.

Break-it-once (the controller's, on Windows CI): revert Task 4's whole commit, the `[1.3.0]` pin included (with 1.3.0
kept, its whitespace quoting alone already passes the line-break values). Then `single-quote`, `owner-escaping-set`,
`token-syntax`, `file-token-syntax`, `embedded-token-syntax`, `glob-star`, `at-file`, `brace-list`, `glob-class`,
`tilde`, and `lf-inside`, `crlf-inside` and `cr-inside` (ConPTY leg) must be listed as altered. `double-backslash`
and the other backslash extras are not: they prove M's quoting does not break values that already pass.

## Task 6: docs

- `docs/scripts.md`, the Git Bash paragraph (lines 47-57), replaced: on Windows, `run` recognises an MSYS2 program (one
  with `msys-2.0.dll` beside it, or Git's `bin\bash.exe`/`bin\sh.exe` launcher) as the program it starts and quotes each
  argument by MSYS2's rules, so `"$1"` holds the value exactly (tested by
  `EndToEndTests.Run_GitBashScript_EvilValues_ArriveExactly_Windows`); a bare `bash` can still be WSL's
  `System32\bash.exe`, which `run` leaves alone, so name Git Bash by its path; `run` refuses when `MSYS` sets a glob
  option, when the locale isn't UTF-8 and an argument is non-ASCII, and for U+F000-U+F0FF characters; the `--env` way stays
  the one that works in every case (and through a program that starts Git Bash in turn), with its test; keep the path
  conversion sentence.
- `TswapCore/Prompt.cs` stays as it is: the `--env` advice still holds in every case above, and the prompt hash doesn't
  change.
- In the report: a release-note line ("`run` passes its arguments to Git Bash and other MSYS2 programs on Windows exactly:
  quotes, braces, globs, backslashes and line breaks no longer change the value (#402)").

## Out of scope

- Cygwin programs (`cygwin1.dll`, option variable `CYGWIN`): the same parser family, not verified here; a follow-up issue.
- A Windows program that starts Git Bash itself (`pwsh -File x.ps1` calling `bash`): its own command line is out of
  tswap's hands; `--env` covers it.
- MSYS2's path conversion when the script passes a value on to a Windows `.exe` (documented already).
- The command line's 32,767-character limit (`max-length` stays left out; quoting adds a `\` per `\` and `"`).
- Validation.cs's checks (T51), `pwsh`, batch files.
