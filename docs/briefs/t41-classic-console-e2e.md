# Brief T41: an E2E test of `run` in a real classic console window, read back from its screen buffer (#349)

Issue: https://github.com/stevedcc/TokenSwap/issues/349 (closed by T35; this is its missing test), owner checks
https://github.com/stevedcc/TokenSwap/issues/367 ("Before the final v0.3.1"). Milestone 0.3.1. Base: `origin/main`
at 3fba65a. Read AGENTS.md and CLAUDE.md first, then `TswapCli/WindowsVirtualTerminal.cs`,
`TswapCli/TerminalTitleMatcher.cs`, the T35 block in `TswapCli/Commands/RunCommand.cs` that uses
`StdoutConsoleMode`, `TswapTests/RunWindowsConsoleTests.cs`, and in `TswapTests/EndToEndTests.cs` the fixture
(lines 23-90), the "Windows ConPTY coverage" section (`Run_NoChildTitle_WindowsConPty` in particular) and the
P/Invoke helpers below it.

One commit for the test. Its proof is three break-it-once CI runs (below), each named in the commit message with the
test and assertion that failed. `./runtests.sh --unit` and the E2E category locally before committing (the new test
returns early off Windows, as its neighbours do). No hardware suites, `ykman`, `sudo`, real YubiKeys or
`~/.config/tswap`. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path
commits, no push, merge or rebase: **the controller pushes `brief/t41`, runs Windows CI and the break runs, and
hands you the logs.** Stop and report when the brief can't be built as written. No product code changes
(`TswapCli/`, `TswapCore/`), and no existing test changes.

**Review history.** Round 1 (GLM and MiMo, 516ed76): both "no". GLM's Critical: the brief asserted that the
screen isn't cleared, but T35 decided the pseudo console's clear passes through (documented in `docs/install.md`,
accepted in the owner's check 3 on 2026-11-20), so the test could never pass → A1. MiMo I1-I3 → A2, A3 (I3 is void
with A1). Minors → A4-A9. Where Task 1 and an amendment differ, the amendment wins.

## Why

T35 fixed #349 in two parts: `WindowsVirtualTerminal.AroundChild` turns `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on
for tswap's stdout while the child runs (and puts the old mode back), and `TerminalTitleMatcher` drops the child's
OSC 0/1/2 window titles. The existing tests don't catch the first part where it matters. Measured on CI on
2026-11-17 (logs `t41-break-vt-windows.log`, `t41-break-title-windows.log` in the controller's folder):

- **AroundChild disabled:** only the fake-mode unit tests failed (`WindowsConsole_VtOnWhileTheChildRuns_RestoredAfter`,
  `WindowsConsole_ChildThrows_ModeRestored`). **All 46 E2E tests passed**, the ConPTY ones included: under an
  outer pseudo console, tswap's stdout already interprets VT, so the bug the owner saw can't show there.
- **The title matcher dropped:** `Run_NoChildTitle_WindowsConPty` failed, as it should.

The owner's bug lived in the **classic console window (conhost) with Windows PowerShell 5.1**, where VT
processing is off unless the writer turns it on: `tswap run choice ...` printed `←[?9001h←[?1004h←[?25l←[2J...`
as text and retitled the window. Only a test that runs tswap in such a console and reads what the console
**shows** (its screen buffer, title and mode) measures what the owner sees.

## Task 1: `Run_ClassicConsole_ShowsNoEscapeText_WindowsConsole`

In `EndToEndTests.cs`, in the "Windows ConPTY coverage" section, with the same early return as its neighbours
(`if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return;`), in category E2E like the class.

**Setup**, as `Run_NoChildTitle_WindowsConPty` does: `init --yubikey --no-recovery`, ingest
`s3cr3t-classic-value` as `my-secret`, and the child script `print3.ps1` (`param($v)`, `before`, `$v`, `after`,
`Start-Sleep -Milliseconds 1500`).

**The console.** The test writes a Windows PowerShell 5.1 script `classic.ps1` into `_tempDir` and starts
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File <classic.ps1> -Result <result.json>` with
`CreateProcess(..., CREATE_NEW_CONSOLE, ...)` (`0x00000010`; a new console, not the test's, never `AttachConsole`
in the test process). Add the `CreateProcess` overload with a plain `STARTUPINFO` that this needs next to the
existing helpers. Wait at most 90 s for it to exit (`WaitForSingleObject`); on timeout terminate it and fail with
whatever `result.json` holds. `classic.ps1`, in order:

1. Sets `$env:TSWAP_TEST_KEY`, `$env:TSWAP_TEST_SUDO_BYPASS = '1'` and `$env:TSWAP_CONFIG_DIR` to the test's values
   (written into the script by the test, so the test process's environment is never changed).
2. Reads the console output mode before the run: `Add-Type` with `GetStdHandle(-11)` and `GetConsoleMode`.
3. Runs `& '<tswap binary>' run pwsh -NoProfile -File '<print3.ps1>' '{{my-secret}}'` **without** piping or
   assigning it (so tswap's stdout is the console itself), then keeps `$LASTEXITCODE`.
4. Writes the line `T41-AFTER-TSWAP` with `Write-Host`.
5. Reads the mode again, the window title (A2: `GetConsoleTitle`, as `titleAfter`), and the screen buffer from row 0 to the
   cursor's row (`$Host.UI.RawUI.GetBufferContents` over the buffer's full width; each row's characters joined and
   right-trimmed, rows joined with `\n`).
6. Writes `{ "modeBefore", "modeAfter", "exit", "titleBefore", "titleAfter", "buffer" }` to `result.json` with
   `ConvertTo-Json` and A5's BOM-less `WriteAllText`, and exits 0.

**Assertions**, each with a dump of the whole result (the buffer with `EscapeVt`) in its message:

| What | Expected | Why |
|---|---|---|
| precondition: `modeBefore & 0x4` | 0 | VT was off, so the console is the one the owner used. If it is on, fail with "the new console already interprets VT; this test can't show #349": report it, never loosen it. |
| `exit` | 0 | |
| buffer contains | `[REDACTED: my-secret]`, `before`, `after`, `T41-AFTER-TSWAP` | the child's output reached the screen, redacted |
| buffer doesn't contain | `s3cr3t-classic-value` | |
| buffer doesn't contain | the ESC character (`\u001b`), `[?9001h`, `[?1004h`, `[?25l`, `[2J`, `]0;` | #349's first half: no sequence printed as text |
| `titleAfter` | equals `titleBefore` | #349's second half: the window wasn't retitled (A2) |
| `titleAfter` | doesn't contain `pwsh` (ignore case) | the child's title didn't reach the window |
| `modeAfter` | equals `modeBefore` | AroundChild put the mode back |

**If the unchanged product fails an assertion**, the first CI run will show it. Then stop and report the dump:
don't change product code or the assertion. (The pseudo console's screen clear is intended and documented in
`docs/install.md`; this test doesn't assert anything about it.)

**Break-it-once** (three CI runs on throwaway branches, which the controller runs from commits you prepare, each one
line, never committed to `brief/t41`):

- **B1:** `AroundChild` returns `Unchanged.Instance` as its first statement. The new test must fail on the escape
  assertion (and `Run_NoChildTitle_WindowsConPty` is expected to pass, as on 2026-11-17).
- **B2:** `RunCommand` leaves `TerminalTitleMatcher` out of the matcher list. The new test must fail on the title.
- **B3:** `Restore.Dispose` does nothing. The new test must fail on `modeAfter`.

Write the three one-line diffs into your report. The commit message names each break, the test that failed and
the assertion's message. The test must also pass in **three** separate Windows CI runs of the unchanged tree (it
starts a real window, so timing matters).

## Amendments (round 1)

- **A1 (GLM Critical + Important 2, MiMo I3).** Drop step 3 (`T41-BEFORE-TSWAP`) and the assertion row
  "buffer contains `T41-BEFORE-TSWAP`". T35 decided the screen clear: it passes through on purpose and is documented
  ("The pseudo console clears the window before the command's output", `docs/install.md`). This test covers #349's
  `←[` half and the title half only, as #367 scopes it. Task 1 has been edited accordingly.
- **A2 (MiMo I1).** Read the window title **before** the run as well (step 2), both times with `GetConsoleTitle`
  (`kernel32`, in the same `Add-Type` block), not `$Host.UI.RawUI.WindowTitle`. Write `titleBefore` and
  `titleAfter`. The title rows become: `titleAfter` **equals** `titleBefore`; and `titleAfter` doesn't contain
  `pwsh` (ignore case). B2 must fail on the first of these.
- **A3 (MiMo I2).** Step 2 checks `GetStdHandle` and `GetConsoleMode`'s results. If either fails, the script writes
  `{ "error": "<which call failed, with the Win32 error>" }` to `result.json` and exits 2, and the test fails with
  that message. The precondition is never read from a failed call.
- **A4 (GLM Minor 3).** The escape row also checks for `←` (U+2190): the classic console shows ESC as that glyph,
  and the buffer may hold the glyph instead of `\u001b`.
- **A5 (GLM Minor 4 + 5, MiMo Minor 2).** The script writes `result.json` without a BOM:
  `[IO.File]::WriteAllText($Result, $json, (New-Object Text.UTF8Encoding $false))`. The test reads it with
  `File.ReadAllText`. If it is missing, empty or doesn't parse, the test fails with "the console script never wrote
  a usable result.json", plus the exit code, or "timed out after 90 s".
- **A6 (MiMo Minor 1).** On timeout, kill the whole tree:
  `Process.GetProcessById((int)pi.dwProcessId).Kill(entireProcessTree: true)`, then wait for it.
- **A7 (MiMo Minor 3).** The test writes `classic.ps1` as UTF-8 **with** a BOM (Windows PowerShell 5.1 reads a
  BOM-less script as ANSI), doubles every `'` in the paths it embeds in single quotes, starts
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` by its full path, and builds the command line with
  the file's `QuoteWindowsArg`. The struct to pass is the file's `WinStartupInfo` (the plain one).
- **A8 (MiMo Minor 4).** Each table row is its own `Assert.True(..., dump)`, in table order.
- **A9 (MiMo Minor 5).** The header's "rule 7" is the break-it-once requirement spelled out in Task 1: three CI
  breaks, each failing the named row.

## Amendments (round 2: both reviewers ready, Minors folded in)

- **A10 (GLM Minor 1).** Guard the timeout kill (check `HasExited`, or catch around the kill alone, never around
  the assertions) so A5's "timed out after 90 s" message is the failure, not a stack trace.
- **A11 (GLM Minor 2).** `GetConsoleTitle` with `CharSet.Unicode` and a 1024-character buffer, both reads the same.
- **A12 (MiMo Minor 2).** For the new `CreateProcess` call: `cb = Marshal.SizeOf<WinStartupInfo>()`, `dwFlags = 0`
  (don't copy the ConPTY helper's `STARTF_USESTDHANDLES` with null handles: that is the pseudo console's pattern),
  `bInheritHandles: false`, `CREATE_NEW_CONSOLE` as the only creation flag.
- MiMo Minor 1 (stale Task 1 text) is fixed in Task 1 itself.

## Out of scope

- Any change to `run`, `WindowsVirtualTerminal`, `TerminalTitleMatcher` or RedactingPty, even if the test finds
  something (report instead).
- Windows Terminal: it interprets VT itself, so it can't show #349.
- The code page and glyph checks (T35 task 3, T43 task 2).
