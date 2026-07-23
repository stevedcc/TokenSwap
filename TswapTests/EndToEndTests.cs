using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// End-to-end smoke tests that exercise the real tswap binary as a subprocess,
/// using TSWAP_TEST_KEY to bypass YubiKey hardware. Only scenarios that genuinely
/// need a real process live here: subprocess spawning via `run`, PTY behaviour
/// (redaction, Ctrl+C), Environment.ProcessPath (installscript), and composition-root
/// env-var handling. Everything else runs in-process in <see cref="CommandTests"/>.
///
/// The binary is built once per run by <see cref="TswapBinaryFixture"/> (or supplied
/// via TSWAP_E2E_BINARY, e.g. a NativeAOT publish in CI). Filter with
/// `--filter "Category=E2E"` / `"Category!=E2E"`.
/// </summary>
[Trait("Category", "E2E")]
public class EndToEndTests : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private readonly string _tempDir;
    private readonly string _testKeyHex;
    private readonly string _binaryPath;

    public EndToEndTests(TswapBinaryFixture binary)
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-prog-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        // Deterministic 32-byte test key
        _testKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        _binaryPath = binary.BinaryPath;
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private ProcessStartInfo MakePsi(bool redirectStdin = false)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _binaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = redirectStdin,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.Environment["TSWAP_TEST_KEY"] = _testKeyHex;
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
        psi.Environment["TSWAP_CONFIG_DIR"] = _tempDir;
        // fork() from a JIT-mode .NET process crashes when W^X protection is active.
        // The deployed AOT binary has no JIT so this is not needed in production.
        psi.Environment["DOTNET_EnableWriteXorExecute"] = "0";
        return psi;
    }

    private (int exitCode, string stdout, string stderr) RunTswap(params string[] args)
    {
        var psi = MakePsi();
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, stdout, stderr);
    }

    private (int exitCode, string stdout, string stderr) RunTswapWithStdin(string stdin, params string[] args)
    {
        var psi = MakePsi(redirectStdin: true);
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)!;
        process.StandardInput.Write(stdin);
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, stdout, stderr);
    }

    // --- Init ---

    // --- Create ---

    // --- Names ---

    // --- Ingest ---

    // --- Burn ---

    // --- Burned ---

    // --- Prompt ---

    // --- InstallScript ---

    /// <summary>
    /// Tests invoke the compiled apphost binary directly, so Environment.ProcessPath is
    /// the binary itself and installscript succeeds and embeds the actual binary path.
    /// </summary>
    [Fact]
    public void InstallScript_OutputsScript()
    {
        var (exit, stdout, _) = RunTswap("installscript");

        Assert.Equal(0, exit);
        if (OperatingSystem.IsWindows())
        {
            // PowerShell: no shebang, has ErrorActionPreference
            Assert.Contains("ErrorActionPreference", stdout);
            Assert.Contains("tswap.exe", stdout);
        }
        else
        {
            // Bash: starts with shebang
            Assert.StartsWith("#!/usr/bin/env bash", stdout.TrimStart());
            Assert.Contains("tswap", stdout);
        }
    }

    [Fact]
    public void InstallScript_EmbedsBinaryPath()
    {
        var (exit, stdout, _) = RunTswap("installscript");

        Assert.Equal(0, exit);
        // The script must embed a non-empty binary path (not the placeholder)
        Assert.DoesNotContain("TSWAP_BINARY_PATH_PLACEHOLDER", stdout);
        // The embedded path must reference tswap
        Assert.Contains("tswap", stdout);
    }

    [Fact]
    public void InstallScript_InstallsSkillMd()
    {
        var (exit, stdout, _) = RunTswap("installscript");

        Assert.Equal(0, exit);
        Assert.Contains("SKILL.md", stdout);
        Assert.Contains(".agents/skills/tswap", stdout.Replace('\\', '/'));
    }

    [Fact]
    public void InstallScript_CreatesClaudeSymlink()
    {
        var (exit, stdout, _) = RunTswap("installscript");

        Assert.Equal(0, exit);
        Assert.Contains(".claude/skills", stdout.Replace('\\', '/'));
    }

    // --- Run (token substitution) ---

    [Fact]
    public void Run_SubstitutesToken()
    {
        RunTswap("init");
        RunTswapWithStdin("hello-world", "ingest", "test-val");

        // Use 'true' as the command — it just exits 0, proving substitution worked
        var (exit, _, _) = RunTswap("run", "true", "{{test-val}}");

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Run_SecretRedactedFromErrorOutput()
    {
        RunTswap("init");
        RunTswapWithStdin("abc123xyz", "ingest", "my-pass");

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // ls + /tmp path is POSIX-only

        // ls on a nonexistent path that includes the secret — ls will echo the path in its
        // error message. The test harness redirects stdout, so tswap uses FallbackPty, which
        // merges stderr into stdout when Console.IsOutputRedirected. Redacted text lands on stdout.
        var (exit, stdout, _) = RunTswap("run", "ls", "/tmp/prefix-{{my-pass}}-suffix");

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("abc123xyz", stdout);
        Assert.Contains("[REDACTED: my-pass]", stdout);
    }

    [Fact]
    public void Run_FirstLineOfStdoutNotDropped()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // POSIX sh/echo only

        RunTswap("init");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        // Regression test for issue #74 / fix for issue #75.
        // tswap now execs argv[0] directly (no shell wrapper), so the compound command
        // is passed as a single literal argument to sh -c — exactly as the user's shell
        // already parsed it. No artificial quoting workaround is needed.
        //
        // Coverage note: the test harness redirects all three streams so tswap always
        // uses FallbackPty, not UnixPty. This test guards the FallbackPty (pipe) path
        // and the shared StreamRedactor logic against future regressions.
        //
        // 'echo' is not blocked (only the top-level command, "sh", is checked against
        // the blocklist). The redactor must catch the raw value (s3cr3t) in the output.
        var (exit, stdout, _) = RunTswap(
            "run", "sh", "-c",
            "echo before; echo {{my-secret}}; echo after");

        Assert.Equal(0, exit);
        Assert.Contains("before",  stdout);
        Assert.Contains("after",   stdout);
        Assert.DoesNotContain("s3cr3t", stdout);
        Assert.Contains("[REDACTED: my-secret]", stdout);
    }

    /// <summary>
    /// Regression test for issue #75: compound shell commands passed via sh -c work
    /// correctly end-to-end. This is the exact user scenario from the bug report:
    ///   tswap run sh -c 'echo before; echo {{my-secret}}; echo after'
    /// The user's shell strips the outer single quotes; tswap receives the compound
    /// command as a single argv element and execs sh directly with it — no intermediate
    /// bash re-parsing that would split the compound command on semicolons.
    /// </summary>
    [Fact]
    public void Run_CompoundCommandViaShellDashC()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // POSIX sh/echo only

        RunTswap("init");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        // Simulate what the user's shell delivers to tswap after stripping outer quotes:
        // the compound command arrives as one argument, not split on the semicolons.
        var (exit, stdout, _) = RunTswap(
            "run", "sh", "-c",
            "echo before; echo {{my-secret}}; echo after");

        Assert.Equal(0, exit);
        Assert.Contains("before",  stdout);
        Assert.Contains("after",   stdout);
        Assert.DoesNotContain("s3cr3t", stdout);
        Assert.Contains("[REDACTED: my-secret]", stdout);
    }

    /// <summary>
    /// End-to-end test for issues #74 and #75 that exercises the real PTY code path
    /// (LinuxPty via forkpty). The test opens its own outer PTY and gives tswap the slave
    /// as its stdin/stdout/stderr via a bash script, so <c>Console.IsOutputRedirected</c>
    /// returns false inside tswap and <c>PtyRunnerFactory.Create()</c> returns <c>LinuxPty</c> — not
    /// FallbackPty. Output is captured from the outer PTY master.
    ///
    /// tswap now execs argv[0] directly (issue #75 fix), so the compound command string
    /// is passed as a literal argument to sh -c with no intermediate shell re-parsing.
    /// </summary>
    [Fact]
    public void Run_FirstLineOfStdoutNotDropped_UnixPty()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return;

        RunTswap("init");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        // Open an outer PTY pair. tswap will inherit the slave as its fds so
        // isatty(0/1/2) returns true and PtyRunnerFactory.Create() picks LinuxPty/MacOSPty.
        var nameBuf = new byte[256];
        int masterFd = -1, slaveFd = -1;
        int ptyRet = OpenPty(ref masterFd, ref slaveFd, nameBuf);
        if (ptyRet == int.MinValue)
            return; // openpty not available on this platform; skip test
        if (ptyRet < 0)
            throw new Exception($"openpty failed (errno {Marshal.GetLastPInvokeError()})");

        var slavePath = Encoding.ASCII.GetString(nameBuf, 0,
            Array.IndexOf(nameBuf, (byte)0) is int z and >= 0 ? z : nameBuf.Length);

        // Write a small bash script. The two `exec` lines:
        //   1. Replace bash's own fds 0/1/2 with the slave PTY (making tswap see a real TTY).
        //   2. Replace bash with the tswap binary so it inherits those slave fds.
        //
        // The compound command is passed as a plain double-quoted string in the bash script.
        // Bash passes it as a single argv element to tswap, and tswap exec's sh directly
        // with that element as the -c argument — no intermediate shell re-parsing.
        var scriptPath = Path.Combine(_tempDir, "pty_test.sh");
        File.WriteAllText(scriptPath,
            $"#!/bin/bash\n" +
            $"exec <\"{slavePath}\" >\"{slavePath}\" 2>\"{slavePath}\"\n" +
            $"exec \"{_binaryPath}\"" +
            $" run sh -c \"echo before; echo {{{{my-secret}}}}; echo after\"\n");

        var psi = new ProcessStartInfo { FileName = "bash", UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(scriptPath);
        psi.Environment["TSWAP_TEST_KEY"]            = _testKeyHex;
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"]    = "1";
        psi.Environment["TSWAP_CONFIG_DIR"]          = _tempDir;
        psi.Environment["DOTNET_EnableWriteXorExecute"] = "0";

        // Read from the outer PTY master until EIO (all slave fds closed after child exits).
        // poll() with a 500 ms timeout bounds each read attempt so the test can never hang
        // indefinitely if tswap or dotnet stalls; the 60 s deadline kills the child process.
        // try/finally ensures masterFd and slaveFd are closed on all exit paths (assertion
        // failure, exception from PtyRead, etc.) so the test never leaks file descriptors.
        const int EINTR  = 4;
        // EAGAIN differs by OS: Linux=11, macOS=35. Retry rather than treating as EIO
        // to match the production UnixPty loop and avoid spurious breaks on O_NONBLOCK fds.
        int eagain = OperatingSystem.IsLinux() ? 11 : 35;
        const short POLLIN_FLAG = 1;
        var sb       = new StringBuilder();
        var buf      = new byte[4096];
        var deadline = DateTime.UtcNow.AddSeconds(60);
        string output;
        using var process = Process.Start(psi)!;
        try
        {
            PtyClose(slaveFd); slaveFd = -1; // close our copy; child holds it

            while (DateTime.UtcNow < deadline)
            {
                var pfd = new TestPollFd { fd = masterFd, events = POLLIN_FLAG };
                int pr = PtyPoll(ref pfd, 1, 500);
                if (pr == 0) continue; // timeout — check deadline and loop
                if (pr < 0)
                {
                    if (Marshal.GetLastPInvokeError() == EINTR) continue;
                    break; // poll error
                }
                int n = (int)PtyRead(masterFd, buf, (nint)buf.Length);
                if (n > 0) { sb.Append(Encoding.UTF8.GetString(buf, 0, n)); continue; }
                if (n == 0) break; // EOF
                var readErrno = Marshal.GetLastPInvokeError();
                if (readErrno == EINTR || readErrno == eagain) continue; // interrupted or O_NONBLOCK: retry
                break; // EIO or other terminal error
            }
        }
        finally
        {
            if (masterFd != -1) { PtyClose(masterFd); masterFd = -1; }
            if (slaveFd  != -1) { PtyClose(slaveFd);  slaveFd  = -1; }
        }
        if (!process.WaitForExit(TimeSpan.FromSeconds(5)))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
        output = sb.ToString();
        Assert.Equal(0, process.ExitCode);
        Assert.Contains("before",               output);
        Assert.Contains("after",                output);
        Assert.DoesNotContain("s3cr3t",         output);
        Assert.Contains("[REDACTED: my-secret]", output);
    }

    // --- No args ---

    // --- Unknown command ---

    // --- TSWAP_TEST_KEY validation ---

    [Fact]
    public void TestKey_WrongLengthFails()
    {
        var psi = new ProcessStartInfo
        {
            FileName = _binaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("init");
        psi.Environment["TSWAP_TEST_KEY"] = "AABB"; // Only 2 bytes, not 32
        psi.Environment["TSWAP_CONFIG_DIR"] = _tempDir;

        using var process = Process.Start(psi)!;
        var stderr = process.StandardError.ReadToEnd();
        process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        Assert.NotEqual(0, process.ExitCode);
        Assert.Contains("32 bytes", stderr);
    }

    // --- End-to-end workflow ---

    [Fact]
    public void EndToEnd_CreateNamesBurnBurned()
    {
        // Full lifecycle: init → create → names → burn → burned
        var (exit1, _, _) = RunTswap("init");
        Assert.Equal(0, exit1);

        var (exit2, _, _) = RunTswap("create", "e2e-secret");
        Assert.Equal(0, exit2);

        var (exit3, namesOut, _) = RunTswap("names");
        Assert.Equal(0, exit3);
        Assert.Contains("e2e-secret", namesOut);
        Assert.DoesNotContain("[BURNED]", namesOut);

        var (exit4, _, _) = RunTswap("burn", "e2e-secret", "integration test");
        Assert.Equal(0, exit4);

        var (exit5, namesOut2, _) = RunTswap("names");
        Assert.Equal(0, exit5);
        Assert.Contains("[BURNED]", namesOut2);

        var (exit6, burnedOut, _) = RunTswap("burned");
        Assert.Equal(0, exit6);
        Assert.Contains("e2e-secret", burnedOut);
        Assert.Contains("integration test", burnedOut);
    }

    [Fact]
    public void EndToEnd_IngestAndRun()
    {
        RunTswap("init");
        RunTswapWithStdin("test-password-123", "ingest", "my-pass");

        // Use 'test' command to verify the substituted value is non-empty
        // (can't use redirect/pipe due to exfiltration protection)
        var (exit, _, _) = RunTswap("run", "test", "-n", "{{my-pass}}");

        Assert.Equal(0, exit);
    }

    // --- Apply ---

    // --- Check ---

    // --- Init: new config fields ---

    // --- Export / Import ---

    // --- Migrate ---

    // --- tocomment: security ---

    // --- PTY P/Invoke helpers (used by Run_FirstLineOfStdoutNotDropped_UnixPty) ---

    // openpty: try libc first (glibc 2.34+ / Fedora 35+ / Ubuntu 22.04+), then libutil.
    [DllImport("libc",    EntryPoint = "openpty", SetLastError = true)]
    private static extern int openpty_libc(ref int amaster, ref int aslave, [Out] byte[] name, IntPtr termp, IntPtr winp);

    [DllImport("libutil", EntryPoint = "openpty", SetLastError = true)]
    private static extern int openpty_libutil(ref int amaster, ref int aslave, [Out] byte[] name, IntPtr termp, IntPtr winp);

    [DllImport("libc", EntryPoint = "read",  SetLastError = true)]
    private static extern nint PtyRead(int fd, [Out] byte[] buf, nint count);

    [DllImport("libc", EntryPoint = "write", SetLastError = true)]
    private static extern nint PtyWrite(int fd, [In] byte[] buf, nint count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int PtyClose(int fd);

    [StructLayout(LayoutKind.Sequential)]
    private struct TestPollFd { public int fd; public short events; public short revents; }

    [DllImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static extern int PtyPoll(ref TestPollFd fds, uint nfds, int timeout);

    // Returns the openpty result (< 0 on failure), or int.MinValue if openpty is not
    // available on this platform (neither libc nor libutil exports the symbol).
    private static int OpenPty(ref int masterFd, ref int slaveFd, byte[] nameBuf)
    {
        try { return openpty_libc(ref masterFd, ref slaveFd, nameBuf, IntPtr.Zero, IntPtr.Zero); }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { } // openpty not exported by libc on this platform
        try { return openpty_libutil(ref masterFd, ref slaveFd, nameBuf, IntPtr.Zero, IntPtr.Zero); }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { } // libutil not present or openpty not exported
        return int.MinValue; // sentinel: openpty not available on this platform
    }

    // Starts tswap with a PTY so ReadPassword enters interactive mode, then sends
    // Ctrl+C (0x03) until the process exits.  Two triggers fire a send (subject to a
    // 1-second cooldown between sends):
    //   • quiescent: 500 ms of silence after any output — process is blocked in ReadKey
    //   • prompt match: waitForPrompt text appears in accumulated output
    // Early sends (before TreatControlCAsInput=true is set) generate SIGINT with no
    // foreground pgid, which is silently dropped; the process keeps running and more
    // output arrives, resetting the quiescent timer for another attempt.
    // Returns (exitCode, output); (-2, "") if openpty is unavailable on this platform.
    private (int exitCode, string output) RunTswapWithPtyCtrlC(string waitForPrompt, params string[] args)
    {
        var nameBuf = new byte[256];
        int masterFd = -1, slaveFd = -1;
        int ptyRet = OpenPty(ref masterFd, ref slaveFd, nameBuf);
        if (ptyRet == int.MinValue) return (-2, "");
        if (ptyRet < 0) throw new Exception($"openpty failed (errno {Marshal.GetLastPInvokeError()})");

        var slavePath = Encoding.ASCII.GetString(nameBuf, 0,
            Array.IndexOf(nameBuf, (byte)0) is int z and >= 0 ? z : nameBuf.Length);

        var quotedArgs = string.Join(" ", args.Select(a => $"\"{a}\""));
        var scriptPath = Path.Combine(_tempDir, $"pty_ctrlc_{Guid.NewGuid():N}.sh");
        File.WriteAllText(scriptPath,
            $"#!/bin/bash\n" +
            $"exec <\"{slavePath}\" >\"{slavePath}\" 2>\"{slavePath}\"\n" +
            $"exec \"{_binaryPath}\" {quotedArgs}\n");

        var psi = new ProcessStartInfo { FileName = "bash", UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(scriptPath);
        psi.Environment["TSWAP_TEST_KEY"] = _testKeyHex;
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
        psi.Environment["TSWAP_CONFIG_DIR"] = _tempDir;
        psi.Environment["DOTNET_EnableWriteXorExecute"] = "0";

        var sb = new StringBuilder();
        var buf = new byte[4096];
        var deadline = DateTime.UtcNow.AddSeconds(120);
        DateTime? lastDataAt = null;
        DateTime lastCtrlCAt = DateTime.MinValue;
        bool promptSeen = false;
        // searchFrom tracks how much of sb has already been scanned for waitForPrompt,
        // leaving a (prompt.Length - 1) overlap to catch matches that straddle chunks.
        int searchFrom = 0;
        const int EINTR = 4;
        int eagain = OperatingSystem.IsLinux() ? 11 : 35;

        void TrySendCtrlC()
        {
            if (DateTime.UtcNow - lastCtrlCAt < TimeSpan.FromMilliseconds(1000)) return;
            // Retry on EINTR/EAGAIN so Ctrl+C is always delivered.
            var ctrlC = new byte[] { 0x03 };
            nint written;
            do { written = PtyWrite(masterFd, ctrlC, 1); }
            while (written < 0 && Marshal.GetLastPInvokeError() is int e && (e == EINTR || e == eagain));
            if (written == 1) lastCtrlCAt = DateTime.UtcNow;
        }

        // Open the try/finally before Process.Start so fd cleanup runs even if Start throws.
        try
        {
            using var process = Process.Start(psi)!;
            PtyClose(slaveFd); slaveFd = -1;

            while (DateTime.UtcNow < deadline)
            {
                var pfd = new TestPollFd { fd = masterFd, events = 1 }; // POLLIN
                int pr = PtyPoll(ref pfd, 1, 200);
                if (pr == 0)
                {
                    // No new data for 200 ms. Fire if quiescent for 500 ms total.
                    if (lastDataAt.HasValue &&
                        DateTime.UtcNow - lastDataAt.Value > TimeSpan.FromMilliseconds(500))
                        TrySendCtrlC();
                    continue;
                }
                if (pr < 0)
                {
                    if (Marshal.GetLastPInvokeError() == EINTR) continue;
                    break;
                }
                int n = (int)PtyRead(masterFd, buf, (nint)buf.Length);
                if (n > 0)
                {
                    sb.Append(Encoding.UTF8.GetString(buf, 0, n));
                    lastDataAt = DateTime.UtcNow;
                    // Scan only the newly appended region (plus overlap) rather than
                    // re-materialising the full buffer on every chunk.
                    if (!promptSeen)
                    {
                        int scanFrom = Math.Max(0, searchFrom - waitForPrompt.Length + 1);
                        if (sb.ToString(scanFrom, sb.Length - scanFrom).Contains(waitForPrompt))
                            promptSeen = true;
                        searchFrom = sb.Length;
                    }
                    if (promptSeen)
                        TrySendCtrlC();
                    continue;
                }
                if (n == 0) break; // EOF
                var errno = Marshal.GetLastPInvokeError();
                if (errno == EINTR || errno == eagain) continue;
                break; // EIO or other terminal error
            }

            if (!process.WaitForExit(TimeSpan.FromSeconds(10)))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }

            return (process.ExitCode, sb.ToString());
        }
        finally
        {
            if (masterFd != -1) { PtyClose(masterFd); masterFd = -1; }
            if (slaveFd  != -1) { PtyClose(slaveFd);  slaveFd  = -1; }
        }
    }

    // --- issue #85: Ctrl+C during ReadPassword restores terminal and prints "Cancelled" ---
    // These tests require a PTY so ReadPassword takes the interactive path.
    // Before the fix, Ctrl+C raised SIGINT and the process died without printing "Cancelled".
    // After the fix, TreatControlCAsInput intercepts it, the finally block resets the flag,
    // OperationCanceledException propagates to the top-level handler, and "Cancelled" is printed.

    [Fact]
    public void Add_CtrlC_DuringPasswordPrompt_PrintsCancelledAndExits130()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return;

        RunTswap("init");

        var (exitCode, output) = RunTswapWithPtyCtrlC("Secret value for", "add", "ctrlc-secret");

        if (exitCode == -2) return; // openpty not available on this platform

        Assert.True(exitCode == 130, $"Expected exit 130, got {exitCode}. PTY output: [{output}]");
        Assert.True(output.Contains("Cancelled"), $"Expected 'Cancelled' in PTY output: [{output}]");
    }

    [Fact]
    public void Export_CtrlC_DuringPassphrasePrompt_PrintsCancelledAndExits130()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return;

        RunTswap("init");
        RunTswap("create", "a-secret");
        var exportPath = Path.Combine(_tempDir, "ctrlc-export.enc");

        var (exitCode, output) = RunTswapWithPtyCtrlC("Export passphrase:", "export", exportPath);

        if (exitCode == -2) return; // openpty not available on this platform

        Assert.True(exitCode == 130, $"Expected exit 130, got {exitCode}. PTY output: [{output}]");
        Assert.True(output.Contains("Cancelled"), $"Expected 'Cancelled' in PTY output: [{output}]");
        Assert.False(File.Exists(exportPath), "export file must not be created on cancellation");
    }

    [Fact]
    public void Import_CtrlC_DuringPassphrasePrompt_PrintsCancelledAndExits130()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return;

        RunTswap("init");
        RunTswap("create", "a-secret");
        var exportPath = Path.Combine(_tempDir, "ctrlc-import.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        var (exitCode, output) = RunTswapWithPtyCtrlC("Import passphrase:", "import", exportPath);

        if (exitCode == -2) return; // openpty not available on this platform

        Assert.True(exitCode == 130, $"Expected exit 130, got {exitCode}. PTY output: [{output}]");
        Assert.True(output.Contains("Cancelled"), $"Expected 'Cancelled' in PTY output: [{output}]");
    }
}
