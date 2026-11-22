using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;
using Xunit;
using Xunit.Abstractions;

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
    private readonly ITestOutputHelper _output;

    public EndToEndTests(TswapBinaryFixture binary, ITestOutputHelper output)
    {
        _output = output;
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
        return psi;
    }

    /// <summary>Brief T46 (A13): <see cref="MakePsi(bool)"/> with tswap (and so its child) started in <paramref name="workingDirectory"/>.</summary>
    private ProcessStartInfo MakePsi(DirectoryInfo workingDirectory, bool redirectStdin = false)
    {
        var psi = MakePsi(redirectStdin);
        psi.WorkingDirectory = workingDirectory.FullName;
        return psi;
    }

    /// <summary>Brief T46 (A13): <see cref="RunTswap"/> started in <paramref name="workingDirectory"/>.</summary>
    private (int exitCode, string stdout, string stderr) RunTswapIn(DirectoryInfo workingDirectory, params ReadOnlySpan<string> args)
    {
        var psi = MakePsi(workingDirectory);
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, stdout, stderr);
    }

    private (int exitCode, string stdout, string stderr) RunTswap(params ReadOnlySpan<string> args)
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

    private (int exitCode, string stdout, string stderr) RunTswapWithStdin(string stdin, params ReadOnlySpan<string> args)
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

    /// <summary>
    /// Issue #175: a fresh user with no ~/.config (a new `useradd -m` account, XDG_CONFIG_HOME
    /// unset) must get the vault under ~/.config/tswap — not in a "tswap" folder relative to
    /// wherever init happened to run — and find it again from any other folder.
    /// </summary>
    [LinuxFact("the XDG rule is the Linux path; macOS resolves ApplicationData through the OS, not from $HOME, so a temp HOME isolates nothing and init would touch the real profile; Windows resolves it through the known-folder API, so the fresh-user case can't be set up from the environment there")]
    public void FreshUserWithoutDotConfig_VaultIsUnderHome_AndFoundFromAnotherFolder()
    {
        // Linux only. The XDG rule ($XDG_CONFIG_HOME, else $HOME/.config) is the Linux path:
        // on macOS .NET resolves ApplicationData to ~/Library/Application Support through the
        // OS (NSApplicationSupportDirectory), not from $HOME, so a temp HOME isolates nothing
        // there and init would touch the real profile's vault folder. Windows uses %APPDATA%.

        var home = Path.Combine(_tempDir, "home");
        var initFolder = Path.Combine(_tempDir, "init-here");
        var otherFolder = Path.Combine(_tempDir, "elsewhere");
        foreach (var d in new[] { home, initFolder, otherFolder })
            Directory.CreateDirectory(d);

        (int exit, string stdout, string stderr) RunIn(string folder, params ReadOnlySpan<string> args)
        {
            var psi = MakePsi();
            psi.Environment.Remove("TSWAP_CONFIG_DIR");
            psi.Environment.Remove("XDG_CONFIG_HOME");
            psi.Environment.Remove("SUDO_USER");
            psi.Environment["HOME"] = home;
            psi.WorkingDirectory = folder;
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi)!;
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, stdout, stderr);
        }

        var init = RunIn(initFolder, "init", "--yubikey", "--no-recovery");
        Assert.True(init.exit == 0, $"init failed: {init.stdout}{init.stderr}");

        Assert.True(File.Exists(Path.Combine(home, ".config", "tswap", "config.json")),
            "the vault config belongs under $HOME/.config/tswap");
        Assert.False(Directory.Exists(Path.Combine(initFolder, "tswap")),
            "nothing may be written relative to the folder init ran in");

        var names = RunIn(otherFolder, "names");
        Assert.True(names.exit == 0, $"names from another folder failed: {names.stdout}{names.stderr}");
        Assert.DoesNotContain("Not initialised", names.stdout + names.stderr);
    }

    /// <summary>
    /// X25519 (SlotKeyPair, the .NET 11 BCL's X25519DiffieHellman) inside the published binary,
    /// which CI runs as NativeAOT: <c>init</c> wraps the vault key to a fresh recovery keypair
    /// (generate, import, derive), and <c>recover --yubikey</c> unwraps it again with the recovery
    /// key init wrote to <c>--recovery-key-out</c>.
    /// </summary>
    [Fact]
    public void InitKeyring_ThenRecoverWithTheRecoveryKey_TheSecretReadsBack()
    {
        // init --keyring is gone on main (every vault is a keyring now), and since #253 an init whose stdout is not a
        // terminal writes the recovery key to --recovery-key-out instead of printing it.
        // The key file must be outside the config folder (init refuses one inside it).
        var keyFile = _tempDir + "-recovery.key";
        string recoveryKey;
        try
        {
            var init = RunTswapWithStdin("", "init", "--yubikey", "--no-password", "--recovery-key-out", keyFile);
            Assert.True(init.exitCode == 0, $"init --yubikey --recovery-key-out failed: {init.stdout}{init.stderr}");
            Assert.True(File.Exists(keyFile), $"init wrote no recovery key file: {init.stdout}{init.stderr}");
            recoveryKey = File.ReadAllText(keyFile).TrimEnd('\n', '\r');
        }
        finally
        {
            File.Delete(keyFile);
        }
        var recoveryKeyBytes = Convert.FromBase64String(recoveryKey);
        Assert.Equal(32, recoveryKeyBytes.Length);
        // Stored in RFC 7748 §5-clamped form, as v0.1.0 stored it (SlotKeyPair.Generate). Checked
        // here too because this runs on every CI OS; the unit test cannot fail on Linux, where
        // OpenSSL already clamps at key generation.
        Assert.Equal(0, recoveryKeyBytes[0] & 0x07);
        Assert.Equal(0, recoveryKeyBytes[31] & 0x80);
        Assert.Equal(0x40, recoveryKeyBytes[31] & 0x40);

        var ingest = RunTswapWithStdin("e2e-recovered-value", "ingest", "e2e-secret");
        Assert.True(ingest.exitCode == 0, $"ingest failed: {ingest.stdout}{ingest.stderr}");

        var recover = RunTswapWithStdin(recoveryKey + "\n\n\n", "recover", "--yubikey");
        Assert.True(recover.exitCode == 0, $"recover failed: {recover.stdout}{recover.stderr}");
        // ASCII part of "✓ Recovered: ... now opens this vault as its own slot": redirected stdout
        // on Windows is not UTF-8, so the check mark itself does not survive there (CI, #216).
        Assert.True(recover.stdout.Contains("now opens this vault as its own slot", StringComparison.Ordinal),
            $"recover did not report the new slot: {recover.stdout}{recover.stderr}");

        var get = RunTswap("get", "e2e-secret");
        Assert.True(get.exitCode == 0, $"get failed: {get.stdout}{get.stderr}");
        Assert.Contains("e2e-recovered-value", get.stdout);
    }

    // --- Create ---

    // --- Names ---

    // --- Ingest ---

    // --- Burn ---

    // --- Burned ---

    // --- Prompt ---

    // --- Version ---

    /// <summary>
    /// Brief T18 lines 1 and 2 on the real binary: one line, <c>tswap &lt;csproj Version&gt;-pre-&lt;HEAD&gt;</c> (a development
    /// build, see <see cref="VersionCommandTests.ExpectedVersion"/>), nothing on stderr,
    /// exit 0, with no test key, no config folder override and an empty, unwritable HOME that stays empty.
    /// </summary>
    [Theory]
    [InlineData("--version")]
    [InlineData("version")]
    public void Version_PrintsOneLine_AndTouchesNoFiles(string form)
    {
        var home = Path.Combine(_tempDir, "home");
        Directory.CreateDirectory(home);
        var psi = MakePsi();
        psi.Environment.Remove("TSWAP_TEST_KEY");
        psi.Environment.Remove("TSWAP_TEST_SUDO_BYPASS");
        psi.Environment.Remove("TSWAP_CONFIG_DIR");
        psi.Environment.Remove("XDG_CONFIG_HOME");
        psi.Environment["HOME"] = home;
        psi.ArgumentList.Add(form);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            using var process = Process.Start(psi)!;
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            Assert.Equal(0, process.ExitCode);
            var line = stdout.TrimEnd('\r', '\n');
            Assert.Equal(line + Environment.NewLine, stdout);
            Assert.Equal($"tswap {VersionCommandTests.ExpectedVersion()}", line); // a Debug publish: a development build
            Assert.Equal("", stderr);
            Assert.Empty(Directory.EnumerateFileSystemEntries(home));
        }
        finally
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

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
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("hello-world", "ingest", "test-val");

        // A command that ignores its arguments and exits 0 — proving substitution worked.
        // 'true' is POSIX-only; on Windows a PowerShell script file that exits 0 (#105 refuses
        // inline 'cmd /c' / 'pwsh -Command' code, so the Windows child is a script file).
        var noop = Path.Combine(_tempDir, "noop.ps1");
        if (OperatingSystem.IsWindows())
            File.WriteAllText(noop, "exit 0\n");
        var (exit, _, _) = OperatingSystem.IsWindows()
            ? RunTswap("run", "pwsh", "-NoProfile", "-File", noop, "{{test-val}}")
            : RunTswap("run", "true", "{{test-val}}");

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Run_SecretRedactedFromErrorOutput()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
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

    [UnixFact("POSIX sh/echo only")]
    public void Run_FirstLineOfStdoutNotDropped()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        // Regression test for issue #74: the first line of the child's stdout must not be
        // dropped. Since #105 inline shell code (`sh -c`) is refused, so the child is a
        // script file that prints before / the secret / after; the redactor must catch the
        // raw value (s3cr3t) in the output.
        //
        // Coverage note: the test harness redirects all three streams so tswap always
        // uses FallbackPty, not UnixPty. This test guards the FallbackPty (pipe) path
        // and the shared StreamRedactor logic against future regressions.
        var script = Path.Combine(_tempDir, "print3.sh");
        File.WriteAllText(script, "echo before\necho \"$1\"\necho after\n");
        var (exit, stdout, _) = RunTswap("run", "sh", script, "{{my-secret}}");

        Assert.Equal(0, exit);
        Assert.Contains("before",  stdout);
        Assert.Contains("after",   stdout);
        Assert.DoesNotContain("s3cr3t", stdout);
        Assert.Contains("[REDACTED: my-secret]", stdout);
    }

    /// <summary>
    /// Brief T26: <c>run --env X={{name}}</c> hands the value to a real child in its environment, not in
    /// its argv. The script checks its own <c>/proc/$$/cmdline</c> for <c>$X</c> and prints only
    /// value-free markers: a value in argv would show up masked in the output, not raw.
    /// </summary>
    [Fact]
    public void RunEnv_ValueNotInArgv()
    {
        if (!OperatingSystem.IsLinux())
            return; // /proc/<pid>/cmdline is Linux's
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t-env-value", "ingest", "my-secret");
        var script = Path.Combine(_tempDir, "argv-check.sh");
        File.WriteAllText(script,
            "if tr '\\0' '\\n' < /proc/$$/cmdline | grep -qF -- \"$X\"; then echo IN-ARGV; else echo NOT-IN-ARGV; fi\n" +
            "echo \"env:${X:+set}\"\n");

        var (exit, stdout, stderr) = RunTswap("run", "--env", "X={{my-secret}}", "--", "sh", script);

        Assert.True(exit == 0, $"exit {exit}: {stdout}{stderr}");
        Assert.Contains("NOT-IN-ARGV", stdout);
        Assert.Contains("env:set", stdout);
        Assert.DoesNotContain("s3cr3t-env-value", stdout + stderr);
    }

    /// <summary>
    /// Issue #105 (owner decision, 2026-10-29): inline shell code is refused, reversing the
    /// compound-command support of #75. The exact #75 scenario,
    ///   tswap run sh -c 'echo before; echo {{my-secret}}; echo after'
    /// must now fail before anything runs and point to a script file. (The redaction and
    /// first-line coverage #75's test also gave lives on in the two
    /// Run_FirstLineOfStdoutNotDropped tests, which use a script file.)
    /// </summary>
    [Fact]
    public void Run_CompoundCommandViaShellDashC_IsRefused()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        var (exit, stdout, stderr) = RunTswap(
            "run", "sh", "-c",
            "echo before; echo {{my-secret}}; echo after");

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("before", stdout);
        Assert.DoesNotContain("s3cr3t", stdout + stderr);
        Assert.Contains("inline code", stderr);
        Assert.Contains("script file", stderr);
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
    [UnixFact]
    public void Run_FirstLineOfStdoutNotDropped_UnixPty()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        // The child is a script file printing before / the secret / after (#105 refuses
        // inline `sh -c` code); tswap execs sh directly with the script and the secret as $1.
        var childScript = Path.Combine(_tempDir, "print3.sh");
        File.WriteAllText(childScript, "echo before\necho \"$1\"\necho after\n");
        if (RunTswapUnderOuterPty($"run sh \"{childScript}\" {{{{my-secret}}}}") is not var (exitCode, output))
            return; // openpty not available on this platform; skip test
        Assert.Equal(0, exitCode);
        Assert.Contains("before",               output);
        Assert.Contains("after",                output);
        Assert.DoesNotContain("s3cr3t",         output);
        Assert.Contains("[REDACTED: my-secret]", output);
    }

    /// <summary>
    /// Runs the tswap binary with <paramref name="tswapArgs"/> (a bash-quoted argument string) under
    /// an outer PTY, so isatty(0/1/2) is true and <c>PtyRunnerFactory.Create()</c> picks
    /// LinuxPty/MacOSPty. Returns tswap's exit code and everything it wrote to the terminal, or null
    /// where openpty isn't available. With <paramref name="reply"/>, its text is typed into the terminal
    /// once (and only once) the output contains <c>WhenSeen</c>: input is sent only after a prompt shows.
    /// </summary>
    private (int ExitCode, string Output)? RunTswapUnderOuterPty(string tswapArgs, (string WhenSeen, string Type)? reply = null)
    {
        // Open an outer PTY pair. tswap will inherit the slave as its fds so
        // isatty(0/1/2) returns true and PtyRunnerFactory.Create() picks LinuxPty/MacOSPty.
        var nameBuf = new byte[256];
        int masterFd = -1, slaveFd = -1;
        int ptyRet = OpenPty(ref masterFd, ref slaveFd, nameBuf);
        if (ptyRet == int.MinValue)
            return null; // openpty not available on this platform
        if (ptyRet < 0)
            throw new Exception($"openpty failed (errno {Marshal.GetLastPInvokeError()})");

        var slavePath = Encoding.ASCII.GetString(nameBuf, 0,
            Array.IndexOf(nameBuf, (byte)0) is int z and >= 0 ? z : nameBuf.Length);

        // Write a small bash script. The two `exec` lines:
        //   1. Replace bash's own fds 0/1/2 with the slave PTY (making tswap see a real TTY).
        //   2. Replace bash with the tswap binary so it inherits those slave fds.
        //
        var scriptPath = Path.Combine(_tempDir, "pty_test.sh");
        File.WriteAllText(scriptPath,
            $"#!/bin/bash\n" +
            $"exec <\"{slavePath}\" >\"{slavePath}\" 2>\"{slavePath}\"\n" +
            $"exec \"{_binaryPath}\"" +
            $" {tswapArgs}\n");

        var psi = new ProcessStartInfo { FileName = "bash", UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(scriptPath);
        psi.Environment["TSWAP_TEST_KEY"]            = _testKeyHex;
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"]    = "1";
        psi.Environment["TSWAP_CONFIG_DIR"]          = _tempDir;

        // Read from the outer PTY master until the child has exited and the master is drained (the parent holds a
        // slave fd, so EOF/EIO is not the normal end, #234). poll() with a 500 ms timeout bounds each read attempt so the test can never hang
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
        using var process = Process.Start(psi)!;
        try
        {
            // The parent keeps its copy of the slave open until it is done (#234). On macOS CI the master reported
            // EOF (revents POLLIN|POLLHUP) tens of ms after start, before tswap printed anything; why is not proven
            // (#210 found that a 1 s delay before the child opens the slave does not reproduce it). The master
            // reports a hang-up only when no slave fd is open, so holding one rules out any early EOF; the slave is
            // held only as that anchor (the parent never reads or writes it). The loop therefore ends when the
            // child has exited, after a last drain of the master.
            while (DateTime.UtcNow < deadline)
            {
                var pfd = new TestPollFd { fd = masterFd, events = POLLIN_FLAG };
                int pr = PtyPoll(ref pfd, 1, 500);
                if (pr == 0)
                {
                    if (process.HasExited)
                    {
                        DrainMaster(masterFd, sb, buf); // whatever it wrote after this poll timed out
                        break;
                    }
                    continue; // timeout — check deadline and loop
                }
                if (pr < 0)
                {
                    if (Marshal.GetLastPInvokeError() == EINTR) continue;
                    break; // poll error
                }
                int n = (int)PtyRead(masterFd, buf, (nint)buf.Length);
                if (n > 0)
                {
                    sb.Append(Encoding.UTF8.GetString(buf, 0, n));
                    if (reply is var (whenSeen, type) && sb.ToString().Contains(whenSeen))
                    {
                        var typed = Encoding.UTF8.GetBytes(type);
                        PtyWrite(masterFd, typed, typed.Length);
                        reply = null;
                    }
                    continue;
                }
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
        return (process.ExitCode, sb.ToString());
    }

    /// <summary>
    /// Brief T16-S3: through a real PTY and the published binary (NativeAOT in CI, so trimming and the
    /// default-interface dispatch of RedactingPty's options overload are exercised), a vault secret the
    /// command never named is masked by its fingerprints.
    /// </summary>
    [UnixFact]
    public void EndToEnd_Run_OtherSecretMasked_RealPty()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");
        RunTswapWithStdin("other-vault-value-42", "ingest", "other");
        var childScript = Path.Combine(_tempDir, "print-other.sh");
        File.WriteAllText(childScript, "echo \"got $1\"\necho \"log other-vault-value-42 end\"\n");

        if (RunTswapUnderOuterPty($"run sh \"{childScript}\" {{{{my-secret}}}}") is not var (exitCode, output))
            return; // openpty not available on this platform; skip test
        Assert.Equal(0, exitCode);
        Assert.DoesNotContain("other-vault-value-42", output);
        Assert.DoesNotContain("s3cr3t", output);
        Assert.Contains("log [REDACTED: other] end", output);
        Assert.Contains("got [REDACTED: my-secret]", output);
    }

    /// <summary>
    /// Brief T16-S3 (owner decision D2), Linux: with a multi-line secret in the vault the redactor holds
    /// back the end of the output, so a prompt would hide behind it; run releases it when the child waits
    /// for terminal input. The answer is typed only after the prompt has shown; without the release the
    /// child waits forever and the harness's deadline ends the test without the answer.
    /// </summary>
    [LinuxFact]
    public void EndToEnd_Run_PromptVisible_WithPemInVault()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("token-value-7", "ingest", "token");
        RunTswapWithStdin("-----BEGIN KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END KEY-----", "ingest", "pem");
        var prompt = Path.Combine(_tempDir, "prompt.sh");
        File.WriteAllText(prompt, "printf 'Continue? [y/N] '\nread x\necho \"answer-$x\"\n");

        if (RunTswapUnderOuterPty($"run sh \"{prompt}\" {{{{token}}}}", ("Continue? [y/N] ", "y\n")) is not var (exitCode, output))
            return; // openpty not available on this platform; skip test
        Assert.Contains("answer-y", output);
        Assert.Equal(0, exitCode);
    }

    /// <summary>
    /// RedactingPty 1.0.0's forked child crashed (exit 139, no diagnostic) when the command didn't
    /// exist, on JIT hosts with W^X on (stevedcc/RedactingPty#3, fixed in 1.0.2). tswap's test
    /// binary is a JIT host and its tests used to set DOTNET_EnableWriteXorExecute=0, which hid it.
    /// </summary>
    [UnixFact]
    public void Run_CommandNotFound_UnixPty_Exits127WithDiagnostic()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        if (RunTswapUnderOuterPty("run tswap-test-no-such-command {{my-secret}}") is not var (exitCode, output))
            return; // openpty not available on this platform; skip test
        Assert.Equal(127, exitCode);
        Assert.Contains("redactingpty: exec failed (command not found or not executable)", output);
        Assert.DoesNotContain("s3cr3t", output);
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
        var (exit1, _, _) = RunTswap("init", "--yubikey", "--no-recovery");
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
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("test-password-123", "ingest", "my-pass");

        // Verify the substituted value is non-empty (can't use redirect/pipe due to
        // exfiltration protection). POSIX: test -n; Windows: a PowerShell script file that
        // checks its argument's length (#105 refuses inline 'pwsh -Command' code).
        var check = Path.Combine(_tempDir, "check.ps1");
        if (OperatingSystem.IsWindows())
            File.WriteAllText(check, "param($v)\nif ($v.Length -gt 0) { exit 0 } else { exit 1 }\n");
        var (exit, _, _) = OperatingSystem.IsWindows()
            ? RunTswap("run", "pwsh", "-NoProfile", "-File", check, "{{my-pass}}")
            : RunTswap("run", "test", "-n", "{{my-pass}}");

        Assert.Equal(0, exit);
    }

    // --- Apply ---

    // --- Check ---

    // --- Init: new config fields ---

    // --- Export / Import ---

    // --- Migrate ---

    // --- tocomment: security ---

    // --- PTY P/Invoke helpers (used by Run_FirstLineOfStdoutNotDropped_UnixPty) ---

    /// <summary>Reads what is left in <paramref name="masterFd"/> without waiting (the child has exited).</summary>
    private static void DrainMaster(int masterFd, StringBuilder sb, byte[] buf)
    {
        while (true)
        {
            var pfd = new TestPollFd { fd = masterFd, events = 1 }; // POLLIN
            if (PtyPoll(ref pfd, 1, 0) <= 0)
                return;
            int n = (int)PtyRead(masterFd, buf, (nint)buf.Length);
            if (n <= 0)
                return;
            sb.Append(Encoding.UTF8.GetString(buf, 0, n));
        }
    }

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
    // Returns (exitCode, output, loopEnd); (-2, "", "") if openpty is unavailable on this platform.
    // loopEnd says why the read loop ended (for failure messages; macOS flake, #210).
    private (int exitCode, string output, string loopEnd) RunTswapWithPtyCtrlC(string waitForPrompt, params IEnumerable<string> args)
    {
        var nameBuf = new byte[256];
        int masterFd = -1, slaveFd = -1;
        int ptyRet = OpenPty(ref masterFd, ref slaveFd, nameBuf);
        if (ptyRet == int.MinValue) return (-2, "", "");
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

        var sb = new StringBuilder();
        var buf = new byte[4096];
        var deadline = DateTime.UtcNow.AddSeconds(120);
        DateTime? lastDataAt = null;
        DateTime lastCtrlCAt = DateTime.MinValue;
        bool promptSeen = false;
        // Why the read loop ended, reported in the test's failure message (macOS flake, #210).
        string loopEnd = "deadline";
        var started = DateTime.UtcNow;
        // searchFrom tracks how much of sb has already been scanned for waitForPrompt,
        // leaving a (prompt.Length - 1) overlap to catch matches that straddle chunks.
        int searchFrom = 0;
        const int EINTR = 4;
        int eagain = OperatingSystem.IsLinux() ? 11 : 35;

        void TrySendCtrlC()
        {
            if (DateTime.UtcNow - lastCtrlCAt < TimeSpan.FromMilliseconds(1000)) return;
            // Retry on EINTR/EAGAIN so Ctrl+C is always delivered.
            byte[] ctrlC = [0x03];
            nint written;
            do { written = PtyWrite(masterFd, ctrlC, 1); }
            while (written < 0 && Marshal.GetLastPInvokeError() is int e && (e == EINTR || e == eagain));
            if (written == 1) lastCtrlCAt = DateTime.UtcNow;
        }

        // Open the try/finally before Process.Start so fd cleanup runs even if Start throws.
        try
        {
            using var process = Process.Start(psi)!;
            // The parent keeps its copy of the slave open until it is done (#234). On macOS CI the master reported
            // EOF (revents POLLIN|POLLHUP) tens of ms after start, before tswap printed anything; why is not proven
            // (#210 found that a 1 s delay before the child opens the slave does not reproduce it). The master
            // reports a hang-up only when no slave fd is open, so holding one rules out any early EOF; the slave is
            // held only as that anchor (the parent never reads or writes it). The loop therefore ends when the
            // child has exited, after a last drain of the master.
            while (DateTime.UtcNow < deadline)
            {
                var pfd = new TestPollFd { fd = masterFd, events = 1 }; // POLLIN
                int pr = PtyPoll(ref pfd, 1, 200);
                if (pr == 0)
                {
                    if (process.HasExited)
                    {
                        DrainMaster(masterFd, sb, buf); // whatever it wrote after this poll timed out
                        loopEnd = "child exited, master drained";
                        break;
                    }
                    // No new data for 200 ms. Fire if quiescent for 500 ms total.
                    if (lastDataAt.HasValue &&
                        DateTime.UtcNow - lastDataAt.Value > TimeSpan.FromMilliseconds(500))
                        TrySendCtrlC();
                    continue;
                }
                if (pr < 0)
                {
                    var pollErrno = Marshal.GetLastPInvokeError();
                    if (pollErrno == EINTR) continue;
                    loopEnd = $"poll error errno={pollErrno}";
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
                if (n == 0) { loopEnd = $"EOF (revents=0x{pfd.revents:x})"; break; }
                var errno = Marshal.GetLastPInvokeError();
                if (errno == EINTR || errno == eagain) continue;
                loopEnd = $"read error errno={errno} (revents=0x{pfd.revents:x})";
                break; // EIO or other terminal error
            }

            loopEnd += $" after {(DateTime.UtcNow - started).TotalMilliseconds:F0} ms, child exited: {process.HasExited}, prompt seen: {promptSeen}, Ctrl-C sent: {lastCtrlCAt != DateTime.MinValue}";
            if (!process.WaitForExit(TimeSpan.FromSeconds(10)))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }

            return (process.ExitCode, sb.ToString(), loopEnd);
        }
        finally
        {
            if (masterFd != -1) { PtyClose(masterFd); masterFd = -1; }
            if (slaveFd  != -1) { PtyClose(slaveFd);  slaveFd  = -1; }
        }
    }

    // --- brief T34 review round 1: the Enter gate of 'slot enrol' on a real terminal ---

    /// <summary>
    /// The joining machine's view of an interactive <c>slot enrol --via</c> on a real pseudo-terminal: a fake <c>ssh</c>
    /// first on PATH (it drops ssh's options and the destination and runs the remote command), and a host whose
    /// <c>--remote-tswap</c> wrapper runs this binary with the host's own config folder. Both sides use the simulated TPM
    /// of test mode, so nothing asks a question before the Enter gate. Where <c>setsid</c> exists (Linux), the terminal
    /// is tswap's controlling terminal, so a Ctrl-C the line discipline doesn't pass through is a real SIGINT.
    /// </summary>
    private sealed class EnrolOnPty(string tempDir, string binaryPath, string testKeyHex)
    {
        public string HostDir { get; } = Path.Combine(tempDir, "host");
        public string JoinerDir { get; } = Path.Combine(tempDir, "joiner");
        private string BinDir => Path.Combine(tempDir, "bin");
        private string HostWrapper => Path.Combine(BinDir, "host-tswap");
        public string HostKeyringPath => Path.Combine(HostDir, "vault", "keyring");

        /// <summary>The host's TPM vault, the fake ssh and the host wrapper.</summary>
        public void SetUp()
        {
            Directory.CreateDirectory(HostDir);
            Directory.CreateDirectory(JoinerDir);
            Directory.CreateDirectory(BinDir);
            using (var init = Start(HostDir, binaryPath, ["init", "--tpm", "--no-password", "--no-recovery"]))
            {
                init.StandardInput.Close();
                // Review round 3 (3): both pipes read at once (neither can fill and block init), and a bounded wait.
                var stdout = init.StandardOutput.ReadToEndAsync();
                var stderr = init.StandardError.ReadToEndAsync();
                if (!init.WaitForExit(TimeSpan.FromSeconds(30)))
                {
                    init.Kill(entireProcessTree: true);
                    init.WaitForExit(TimeSpan.FromSeconds(10));
                    Assert.Fail("the host's init didn't finish within 30 s");
                }
                init.WaitForExit(); // the exit is known; this only lets the two reads finish
                Assert.True(Task.WaitAll([stdout, stderr], TimeSpan.FromSeconds(10)), "the host's init output wasn't read to its end");
                Assert.Equal(0, init.ExitCode);
            }

            // ProcessSshTransport's two shapes (BuildArgv, EndSession): 'ssh -T|-t [-o ControlMaster=auto -o ControlPath=<p>
            // -o ControlPersist=60] -- <destination> <remote command as one word>', and 'ssh -o ControlPath=<p> -O exit --
            // <destination>', which ends a shared session. Review round 3 (4): anything else fails loudly (exit 97), and the
            // command is passed on whole ("$*", so no word after the first is dropped should it ever come split).
            var ssh = Path.Combine(BinDir, "ssh");
            File.WriteAllText(ssh,
                "#!/bin/sh\n" +
                "argv=\"$*\"\n" +
                "found=0\nend=0\n" +
                "while [ $# -gt 0 ]; do\n" +
                "  a=\"$1\"; shift\n" +
                "  if [ \"$a\" = \"--\" ]; then found=1; break; fi\n" +
                "  if [ \"$a\" = \"-O\" ] && [ \"${1:-}\" = \"exit\" ]; then end=1; fi\n" +
                "done\n" +
                "if [ $found -eq 0 ] || [ $# -lt 1 ]; then echo \"fake ssh: unexpected argv: $argv\" >&2; exit 97; fi\n" +
                "shift\n" + // the destination
                "if [ $# -eq 0 ]; then\n" +
                "  if [ $end -eq 1 ]; then exit 0; fi\n" +
                "  echo \"fake ssh: unexpected argv: $argv\" >&2; exit 97\n" +
                "fi\n" +
                "exec sh -c \"$*\"\n");
            File.WriteAllText(HostWrapper,
                $"#!/bin/sh\nTSWAP_CONFIG_DIR='{HostDir}' exec '{binaryPath}' \"$@\"\n");
            if (OperatingSystem.IsWindows())
                return; // the callers are Unix-only ([UnixFact]); this keeps the analyser satisfied
            const UnixFileMode Exec = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(ssh, Exec);
            File.SetUnixFileMode(HostWrapper, Exec);
        }

        private Process Start(string configDir, string program, string[] args)
        {
            var psi = new ProcessStartInfo(program)
            {
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true,
            };
            foreach (var a in args)
                psi.ArgumentList.Add(a);
            Environment(psi.Environment, configDir);
            return Process.Start(psi)!;
        }

        private void Environment(IDictionary<string, string?> env, string configDir)
        {
            env["TSWAP_TEST_KEY"] = testKeyHex;
            env["TSWAP_TEST_SUDO_BYPASS"] = "1";
            env["TSWAP_CONFIG_DIR"] = configDir;
            env["PATH"] = BinDir + ":" + System.Environment.GetEnvironmentVariable("PATH");
            // The shared-connection socket folder: inside the test's folder, never the user's runtime folder.
            var run = Path.Combine(tempDir, "run");
            Directory.CreateDirectory(run);
            env["XDG_RUNTIME_DIR"] = run;
            env.Remove("SUDO_USER");
        }

        /// <summary>
        /// Runs <c>slot enrol</c> on the joining side with its stdin, stdout and stderr on a new pseudo-terminal's slave,
        /// and hands <paramref name="drive"/> a session on the master. Null where openpty isn't available.
        /// </summary>
        public (int ExitCode, string Output, bool Killed)? Run(Action<PtyDriver> drive)
        {
            var nameBuf = new byte[256];
            int masterFd = -1, slaveFd = -1;
            int ptyRet = OpenPty(ref masterFd, ref slaveFd, nameBuf);
            if (ptyRet == int.MinValue)
                return null;
            if (ptyRet < 0)
                throw new Exception($"openpty failed (errno {Marshal.GetLastPInvokeError()})");
            var slavePath = Encoding.ASCII.GetString(nameBuf, 0, Array.IndexOf(nameBuf, (byte)0) is int z and >= 0 ? z : nameBuf.Length);
            var script = Path.Combine(tempDir, "enrol-on-pty.sh");
            File.WriteAllText(script,
                "#!/bin/bash\n" +
                $"exec <\"{slavePath}\" >\"{slavePath}\" 2>\"{slavePath}\"\n" +
                $"exec \"{binaryPath}\" slot enrol --via me@host --tpm --no-password --no-remote-sudo --remote-tswap \"{HostWrapper}\"\n");
            // setsid: a new session, whose leader (bash, then tswap) takes the slave it opens as its controlling terminal.
            var setsid = File.Exists("/usr/bin/setsid") ? "/usr/bin/setsid" : null;
            var psi = new ProcessStartInfo(setsid ?? "bash") { UseShellExecute = false, CreateNoWindow = true };
            if (setsid is not null)
                psi.ArgumentList.Add("bash");
            psi.ArgumentList.Add(script);
            Environment(psi.Environment, JoinerDir);
            Process? process = null;
            try
            {
                process = Process.Start(psi)!;
                var driver = new PtyDriver(masterFd, slaveFd, process);
                drive(driver);
                var killed = !driver.WaitForExit(TimeSpan.FromSeconds(60));
                if (killed)
                {
                    process.Kill(entireProcessTree: true);
                    Assert.True(process.WaitForExit(TimeSpan.FromSeconds(10)), "tswap's process tree didn't end after the kill");
                }
                return (process.ExitCode, driver.Output, killed);
            }
            finally
            {
                // Review round 3 (2): on every path, a failed assertion in drive included, the tree is killed and reaped
                // before the terminal's fds close, so no tswap, bash or setsid outlives the test.
                if (process is not null)
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        process.WaitForExit(TimeSpan.FromSeconds(10));
                    }
                    process.Dispose();
                }
                if (masterFd != -1) PtyClose(masterFd);
                if (slaveFd != -1) PtyClose(slaveFd); // held as the anchor against an early EOF (#234)
            }
        }
    }

    /// <summary>
    /// A pseudo-terminal's master side: what the child wrote so far, and typing into it. Every wait is poll() on the
    /// master with a deadline, never a sleep.
    /// </summary>
    private sealed class PtyDriver(int masterFd, int slaveFd, Process process)
    {
        private readonly MemoryStream _output = new();
        private readonly byte[] _buf = new byte[4096];

        /// <summary>Everything read so far, decoded at once (review round 3 (6): a UTF-8 sequence split across reads stays whole).</summary>
        public string Output => Encoding.UTF8.GetString(_output.GetBuffer(), 0, (int)_output.Length);

        /// <summary>Reads what is ready within <paramref name="waitMs"/>; true when something was read.</summary>
        private bool Pump(int waitMs)
        {
            var pfd = new TestPollFd { fd = masterFd, events = 1 };
            int pr = PtyPoll(ref pfd, 1, waitMs);
            if (pr <= 0)
                return false;
            int n = (int)PtyRead(masterFd, _buf, (nint)_buf.Length);
            if (n <= 0)
                return false;
            _output.Write(_buf, 0, n);
            return true;
        }

        private static int Count(string text, string part) => text.Split(part).Length - 1;

        /// <summary>Reads until <paramref name="text"/> has appeared <paramref name="times"/> times (or tswap exited, or the deadline).</summary>
        public void WaitFor(string text, int times = 1, int seconds = 60)
        {
            var deadline = DateTime.UtcNow.AddSeconds(seconds);
            while (Count(Output, text) < times)
            {
                if (process.HasExited)
                {
                    while (Pump(0)) { }
                    Assert.True(Count(Output, text) >= times, $"'{text}' (x{times}) never appeared before tswap exited; the terminal showed:\n{Output}");
                    return;
                }
                Assert.True(DateTime.UtcNow < deadline, $"'{text}' (x{times}) never appeared; the terminal showed:\n{Output}");
                Pump(200);
            }
        }

        /// <summary>
        /// Reads until the terminal is in .NET's key-read mode (ICANON off: tswap is inside <c>Console.ReadKey</c>, after
        /// its type-ahead discard, #293). Keys typed before that could be discarded, or, before the read has switched ISIG
        /// off, turned into a SIGINT by the line discipline, as for a person typing Ctrl-C before the prompt's read starts.
        /// </summary>
        public void WaitForKeyRead(int seconds = 60)
        {
            var deadline = DateTime.UtcNow.AddSeconds(seconds);
            while (LocalFlags() is var flags && (flags & Icanon) != 0)
            {
                Assert.True(!process.HasExited && DateTime.UtcNow < deadline,
                    $"tswap never entered a key read (c_lflag 0x{flags:x}); the terminal showed:\n{Output}");
                Pump(50);
            }
        }

        private static ulong Icanon => OperatingSystem.IsMacOS() ? 0x100UL : 0x2UL;

        /// <summary>The terminal's c_lflag (Linux: 32 bits at byte 12; macOS: 64 bits at byte 24).</summary>
        private ulong LocalFlags()
        {
            var termios = new byte[256];
            Assert.Equal(0, PtyGetAttr(slaveFd, termios));
            return OperatingSystem.IsMacOS() ? BitConverter.ToUInt64(termios, 24) : BitConverter.ToUInt32(termios, 12);
        }

        public void Type(string keys)
        {
            var bytes = Encoding.UTF8.GetBytes(keys);
            Assert.Equal(bytes.Length, (int)PtyWrite(masterFd, bytes, bytes.Length));
        }

        /// <summary>Reads until the child has exited (true) or the timeout; then drains the master.</summary>
        public bool WaitForExit(TimeSpan timeout)
        {
            var deadline = DateTime.UtcNow + timeout;
            while (!process.HasExited && DateTime.UtcNow < deadline)
                Pump(200);
            while (Pump(0)) { }
            return process.HasExited;
        }
    }

    [DllImport("libc", EntryPoint = "tcgetattr", SetLastError = true)]
    private static extern int PtyGetAttr(int fd, [Out] byte[] termios);

    /// <summary>
    /// Review round 3 (1): these tests run on Linux and macOS only ([UnixFact]), where openpty must exist; its absence
    /// (neither libc nor libutil exports it, <see cref="OpenPty"/>'s sentinel) is a failure, never a silent pass.
    /// </summary>
    private static Exception OpenPtyUnavailable()
    {
        Assert.Fail("openpty is not available here (neither libc nor libutil exports it), on a platform this test covers");
        return new UnreachableException();
    }

    private const string EnterGatePrompt = "Press Enter to accept it here. ";
    private const string NotConfirmed = "The approve file's fingerprint wasn't confirmed, so it was not accepted. This machine's pending request is kept;";

    /// <summary>The joining side's state after a gate that didn't accept: the request kept, no approve file, the host unchanged.</summary>
    private static void AssertTheRequestIsKept(EnrolOnPty enrol, byte[] hostKeyring, int exitCode, string output, bool killed)
    {
        Assert.False(killed, "tswap didn't exit by itself; the terminal showed:\n" + output);
        Assert.Contains(NotConfirmed, output.ReplaceLineEndings(" ").Replace("  ", " "));
        Assert.Equal(1, exitCode); // not 130 or a signal: the gate's own refusal
        var folder = Assert.Single(Directory.GetDirectories(Path.Combine(enrol.JoinerDir, "enrol")));
        Assert.True(File.Exists(Path.Combine(folder, "request.json")));
        Assert.False(File.Exists(Path.Combine(folder, "approve.json")), "approve.json was left behind");
        using var config = JsonDocument.Parse(File.ReadAllText(Path.Combine(enrol.JoinerDir, "config.json")));
        Assert.Equal(JsonValueKind.String, config.RootElement.GetProperty("PendingSlotId").ValueKind);
        Assert.Equal(hostKeyring, File.ReadAllBytes(enrol.HostKeyringPath));
    }

    [UnixFact]
    public void Enrol_CtrlCAtTheEnterGate_OnARealTerminal_KeepsTheRequest()
    {
        var enrol = new EnrolOnPty(_tempDir, _binaryPath, _testKeyHex);
        enrol.SetUp();
        var hostKeyring = File.ReadAllBytes(enrol.HostKeyringPath);

        if (enrol.Run(pty =>
            {
                pty.WaitFor(EnterGatePrompt);
                pty.WaitForKeyRead();
                pty.Type("\x03");
                pty.WaitFor("wasn't confirmed");
            }) is not var (exitCode, output, killed))
            throw OpenPtyUnavailable();

        AssertTheRequestIsKept(enrol, hostKeyring, exitCode, output, killed);
    }

    [UnixFact]
    public void Enrol_CtrlDOnAnEmptyLineAtTheEnterGate_OnARealTerminal_KeepsTheRequest()
    {
        var enrol = new EnrolOnPty(_tempDir, _binaryPath, _testKeyHex);
        enrol.SetUp();
        var hostKeyring = File.ReadAllBytes(enrol.HostKeyringPath);

        if (enrol.Run(pty =>
            {
                pty.WaitFor(EnterGatePrompt);
                pty.WaitForKeyRead();
                pty.Type("\x04");
                pty.WaitFor("wasn't confirmed");
            }) is not var (exitCode, output, killed))
            throw OpenPtyUnavailable();

        AssertTheRequestIsKept(enrol, hostKeyring, exitCode, output, killed);
    }

    /// <summary>Typed text at the gate is not echoed and is not the Enter: the retry text, then the gate again (ended with Ctrl-C).</summary>
    [UnixFact]
    public void Enrol_TypedTextAtTheEnterGate_OnARealTerminal_IsNotShownAndAsksAgain()
    {
        var enrol = new EnrolOnPty(_tempDir, _binaryPath, _testKeyHex);
        enrol.SetUp();
        var hostKeyring = File.ReadAllBytes(enrol.HostKeyringPath);
        var afterGate = "";

        if (enrol.Run(pty =>
            {
                pty.WaitFor(EnterGatePrompt);
                var before = pty.Output.Length;
                pty.WaitForKeyRead();
                pty.Type("zq7x\r");
                pty.WaitFor("Nothing was typed in, just press Enter");
                pty.WaitFor(EnterGatePrompt, times: 2);
                afterGate = pty.Output[before..];
                pty.WaitForKeyRead();
                pty.Type("\x03");
                pty.WaitFor("wasn't confirmed");
            }) is not var (exitCode, output, killed))
            throw OpenPtyUnavailable();

        Assert.Contains("(what you typed was not shown or used).", afterGate);
        Assert.DoesNotContain("zq7x", output);
        AssertTheRequestIsKept(enrol, hostKeyring, exitCode, output, killed);
    }

    // --- issue #85: Ctrl+C during ReadPassword restores terminal and prints "Cancelled" ---
    // These tests require a PTY so ReadPassword takes the interactive path.
    // Before the fix, Ctrl+C raised SIGINT and the process died without printing "Cancelled".
    // After the fix, TreatControlCAsInput intercepts it, the finally block resets the flag,
    // OperationCanceledException propagates to the top-level handler, and "Cancelled" is printed.

    [UnixFact]
    public void Add_CtrlC_DuringPasswordPrompt_PrintsCancelledAndExits130()
    {
        RunTswap("init", "--yubikey", "--no-recovery");

        var (exitCode, output, loopEnd) = RunTswapWithPtyCtrlC("Secret value for", "add", "ctrlc-secret");

        if (exitCode == -2) return; // openpty not available on this platform

        Assert.True(exitCode == 130, $"Expected exit 130, got {exitCode}. PTY output: [{output}]. Read loop: {loopEnd}");
        Assert.True(output.Contains("Cancelled"), $"Expected 'Cancelled' in PTY output: [{output}]. Read loop: {loopEnd}");
    }

    [UnixFact]
    public void Export_CtrlC_DuringPassphrasePrompt_PrintsCancelledAndExits130()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswap("create", "a-secret");
        var exportPath = Path.Combine(_tempDir, "ctrlc-export.enc");

        var (exitCode, output, loopEnd) = RunTswapWithPtyCtrlC("Export passphrase:", "export", exportPath);

        if (exitCode == -2) return; // openpty not available on this platform

        Assert.True(exitCode == 130, $"Expected exit 130, got {exitCode}. PTY output: [{output}]. Read loop: {loopEnd}");
        Assert.True(output.Contains("Cancelled"), $"Expected 'Cancelled' in PTY output: [{output}]. Read loop: {loopEnd}");
        Assert.False(File.Exists(exportPath), $"export file must not be created on cancellation. Read loop: {loopEnd}");
    }

    [UnixFact]
    public void Import_CtrlC_DuringPassphrasePrompt_PrintsCancelledAndExits130()
    {
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswap("create", "a-secret");
        var exportPath = Path.Combine(_tempDir, "ctrlc-import.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        var (exitCode, output, loopEnd) = RunTswapWithPtyCtrlC("Import passphrase:", "import", exportPath);

        if (exitCode == -2) return; // openpty not available on this platform

        Assert.True(exitCode == 130, $"Expected exit 130, got {exitCode}. PTY output: [{output}]. Read loop: {loopEnd}");
        Assert.True(output.Contains("Cancelled"), $"Expected 'Cancelled' in PTY output: [{output}]. Read loop: {loopEnd}");
    }

    // --- Windows ConPTY coverage ---

    /// <summary>
    /// Exercises the real WindowsPty (ConPTY) code path, which no other test reaches:
    /// the test creates an *outer* pseudoconsole and launches tswap attached to it, so
    /// tswap's stdio is a genuine console (IsOutputRedirected == false) and
    /// PtyRunnerFactory selects WindowsPty for the child it spawns. Output is captured
    /// from the outer ConPTY pipe — it carries VT sequences, so assertions use
    /// substring checks on the rendered text.
    /// </summary>
    [Fact]
    public void Run_CompoundCommand_RedactedOutput_WindowsConPty()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return; // ConPTY requires Win10 1809+

        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t-conpty-value", "ingest", "my-secret");

        // The child prints everything and then stays alive briefly: Server 2022's
        // conhost doesn't paint very short sessions until client disconnect, and that
        // teardown flush races pseudoconsole close at both nesting levels — an
        // instantly-exiting child can render as a blank session. The trailing sleep
        // gives the paint timers at both levels time to emit the text while the
        // sessions are alive (also the realistic shape of production commands).
        // -v makes tswap print verbose lines directly to its stdout (the outer console)
        // BEFORE any PTY work — separating "tswap's console writes are lost" from "the
        // inner ConPTY pipeline lost the child's output" in a single capture. Note the
        // verbose 'Executing:' line contains the literal command words, so assertions
        // use only strings unique to each pipeline stage: the verbose token line
        // (pre-PTY) and the redaction marker (only ever emitted from redacted child
        // output). The raw secret never appears in verbose output (it is masked).
        // #105 refuses inline 'pwsh -Command' code, so the child is a script file taking the
        // secret as its argument; the printed sequence and the assertions are unchanged.
        // Brief T7 item 2 (#182): -v is tswap's only before the command name, so it moved there.
        var printScript = Path.Combine(_tempDir, "print3.ps1");
        File.WriteAllText(printScript,
            "param($v)\nWrite-Output before\nWrite-Output $v\nWrite-Output after\nStart-Sleep -Milliseconds 1500\n");
        var (exitCode, output) = RunTswapInConPty(waitForOutput: "[REDACTED: my-secret]",
            "-v", "run", "pwsh", "-NoProfile", "-File", printScript, "{{my-secret}}");

        // Assert via Assert.True with the full escaped capture: xunit truncates the
        // haystack in Contains failures, which hides the VT stream needed to diagnose
        // ConPTY behaviour on CI machines we can't reproduce on locally.
        var dump = $"exit={exitCode} ConPTY output ({output.Length} chars): [{EscapeVt(output)}]";
        Assert.True(exitCode == 0, $"Expected exit 0. {dump}");
        Assert.True(output.Contains("Found tokens: my-secret"),
            $"verbose marker missing — tswap's own console writes are not reaching the outer ConPTY. {dump}");
        Assert.False(output.Contains("s3cr3t-conpty-value"), $"raw secret leaked. {dump}");
        Assert.True(output.Contains("[REDACTED: my-secret]"),
            $"redaction marker missing — the inner ConPTY pipeline lost the child's output. {dump}");
    }

    /// <summary>
    /// Brief T35 Task 3 (#348.2, #294.4): tswap's glyphs reach a console as themselves. Before the change tswap
    /// wrote the OEM code page's best fit, which the outer pseudo console renders as '?' and 'V'. Windows only
    /// (CI); returns early elsewhere, as <see cref="Run_CompoundCommand_RedactedOutput_WindowsConPty"/> does.
    /// Two captures, each waiting for an ASCII sentinel printed before and after the change (A8); short fragments
    /// only, since ConPTY may wrap long lines, and no banner wording (A18).
    /// </summary>
    [Fact]
    public void Glyphs_ReachTheConsole_WindowsConPty()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return; // ConPTY requires Win10 1809+

        // A refused run (no token, nothing is opened): the error line's ❌.
        var (refusedExit, refused) = RunTswapInConPty(waitForOutput: "No {{tokens}}", "run", "tool", "{x}");
        var refusedDump = $"exit={refusedExit} ConPTY output ({refused.Length} chars): [{EscapeVt(refused)}]";
        Assert.True(refusedExit == 1, $"Expected exit 1. {refusedDump}");
        Assert.True(refused.Contains("Error: No {{tokens}}"), $"error line missing. {refusedDump}");
        Assert.True(refused.Contains('❌'), $"'❌' missing. {refusedDump}");
        Assert.False(refused.Contains("? Error"), $"'❌' shown as '?'. {refusedDump}");

        // init's closing banner: ✓ and the box lines.
        var (initExit, init) = RunTswapInConPty(waitForOutput: "COMPLETE", "init", "--yubikey", "--no-recovery", "--no-password");
        var initDump = $"exit={initExit} ConPTY output ({init.Length} chars): [{EscapeVt(init)}]";
        Assert.True(initExit == 0, $"Expected exit 0. {initDump}");
        Assert.True(init.Contains("COMPLETE"), $"banner missing. {initDump}");
        Assert.True(init.Contains('✓'), $"'✓' missing. {initDump}");
        Assert.True(init.Contains("╔═"), $"box lines missing. {initDump}");
    }

    /// <summary>
    /// Brief T35 Task 3 (#355, A4): a secret value with non-ASCII characters is redacted on the ConPTY path.
    /// RedactingPty's WindowsPty decodes ConPTY's UTF-8 with Console.OutputEncoding; before the change that was the
    /// OEM code page, so the value didn't match and its bytes reached the console. Windows only (CI).
    /// </summary>
    [Fact]
    public void NonAsciiValue_Redacted_WindowsConPty()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return; // ConPTY requires Win10 1809+

        const string value = "pässwört-conpty";
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin(value, "ingest", "umlaut");
        // A16: the stored value is the one typed ('ä' and 'ö' exist in code pages 437, 850 and 1252); if this fails,
        // the ingest leg is what to fix, not the redaction.
        var get = RunTswap("get", "umlaut");
        Assert.True(get.exitCode == 0, get.stderr);
        Assert.Equal(value, get.stdout.Trim());

        // A13: print3.ps1 as the existing ConPTY test writes it; its trailing sleep is existing child behaviour (a
        // child that exits at once can render as a blank session), not a test wait.
        var printScript = Path.Combine(_tempDir, "print3.ps1");
        File.WriteAllText(printScript,
            "param($v)\nWrite-Output before\nWrite-Output $v\nWrite-Output after\nStart-Sleep -Milliseconds 1500\n");
        var (exitCode, output) = RunTswapInConPty(waitForOutput: "[REDACTED: umlaut]",
            "run", "pwsh", "-NoProfile", "-File", printScript, "{{umlaut}}");

        var dump = $"exit={exitCode} ConPTY output ({output.Length} chars): [{EscapeVt(output)}]";
        Assert.True(exitCode == 0, $"Expected exit 0. {dump}");
        Assert.True(output.Contains("[REDACTED: umlaut]"), $"redaction marker missing. {dump}");
        Assert.False(output.Contains("pässwört"), $"raw secret leaked. {dump}");
        // An unredacted value mis-decoded on the way still carries its ASCII tail.
        Assert.False(output.Contains("-conpty"), $"the value's ASCII tail leaked (mis-decoded, unredacted). {dump}");
    }

    /// <summary>
    /// Brief T35 Task 4 (#349): the child's pseudo console sets the window title to the child's path (OSC 0); on a
    /// Windows console run drops it, so it reaches the outer capture neither as text (VT off) nor re-emitted by the
    /// outer pseudo console (VT on). No ESC printed as the '←' glyph either (A3; the outer pseudo console's own
    /// start-up sequences are in every capture, so those fragments can't be asserted). Windows only (CI). If the
    /// outer pseudo console turns out to emit a title naming pwsh by itself, report the dump; never loosen this.
    /// </summary>
    [Fact]
    public void Run_NoChildTitle_WindowsConPty()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return; // ConPTY requires Win10 1809+

        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("s3cr3t-title-value", "ingest", "my-secret");
        var printScript = Path.Combine(_tempDir, "print3.ps1");
        File.WriteAllText(printScript,
            "param($v)\nWrite-Output before\nWrite-Output $v\nWrite-Output after\nStart-Sleep -Milliseconds 1500\n");

        var (exitCode, output) = RunTswapInConPty(waitForOutput: "[REDACTED: my-secret]",
            "run", "pwsh", "-NoProfile", "-File", printScript, "{{my-secret}}");

        var dump = $"exit={exitCode} ConPTY output ({output.Length} chars): [{EscapeVt(output)}]";
        Assert.True(exitCode == 0, $"Expected exit 0. {dump}");
        Assert.True(output.Contains("[REDACTED: my-secret]"), $"redaction marker missing. {dump}");
        Assert.False(output.Contains("s3cr3t-title-value"), $"raw secret leaked. {dump}");
        Assert.False(System.Text.RegularExpressions.Regex.IsMatch(output, "\\]0;[^\\x07\\x1b\\r\\n]*pwsh",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase), $"the child's window title reached the console. {dump}");
        Assert.False(output.Contains("←["), $"an escape sequence was printed as text. {dump}");
    }

    // --- Brief T46 Task 3 (#392): Windows batch files, "BatBadBut" (CVE-2024-24576) ---

    /// <summary>
    /// Brief T46 Task 3 (A6, A9, A10, A12): <c>tswap run &lt;batch&gt; {{name}}</c> with each of
    /// <see cref="EvilValues.BatchCases"/>, through two legs: the redirected harness (tswap's stdout a pipe, so its child
    /// starts through .NET's process start, FallbackPty) and an outer pseudo console (tswap's stdout a console, so
    /// RedactingPty's WindowsPty builds the child's command line). Two batch files:
    /// <list type="bullet">
    /// <item><c>inert.cmd</c> and its twin <c>inert.bat</c> (<c>@exit /b 0</c>) never expand an argument, so a
    /// <c>marker.txt</c> can only come from how the batch was launched. Invariant (batch-inert): <c>marker.txt</c> never
    /// exists, whether tswap ran the batch or refused it.</item>
    /// <item><c>capture.cmd</c>, for the values without <c>"</c> only (no batch can capture a quote-bearing argument
    /// safely): reads <c>%~1</c> with delayed expansion off, then prints it with delayed expansion on, which parses no
    /// character of the expanded text. Invariant (batch-capture): <c>out.txt</c> holds exactly the value, or tswap refused
    /// the run with a message naming batch files; an altered value (e.g. <c>%PATH%</c> expanded at launch) fails.</item>
    /// </list>
    /// tswap starts in the test's work folder, the batch files' folder (A6), so a marker lands where the test looks;
    /// the test process's own folder is checked too. Every failure names the case, the leg and the batch, and whether
    /// <c>marker.txt</c> appeared; the outcome of every run (ran, refused) goes to the test output for the report.
    /// </summary>
    /// <remarks>
    /// Break-it-once (the controller's, on Windows CI; A6, A9): in place of the tswap run, start the batch with the
    /// vulnerable wrapping, outside tswap (wrapper quotes added, embedded quotes not escaped):
    /// <code>
    /// using var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c inert.cmd \"" + value + "\"")
    ///     { WorkingDirectory = work.FullName, UseShellExecute = false })!;   // A9: Process.Start("cmd.exe", "/c inert.cmd \"" + value + "\"")
    /// p.WaitForExit();
    /// var (exit, output) = (p.ExitCode, "");
    /// </code>
    /// With it the two quote-bearing values (<c>batch-quote-ampersand</c>, <c>batch-quote-spaced</c>) must create
    /// <c>marker.txt</c>: that proves the detector works on the runner. A marker from <c>batch-caret-ampersand</c> would be
    /// a stray redirection at launch (cmd.exe reading <c>&gt;marker.txt</c> as a redirection of the batch's own output):
    /// the same invariant fails, by another mechanism.
    /// </remarks>
    [WindowsFact("batch files and cmd.exe's argument parsing exist only on Windows (BatBadBut, CVE-2024-24576)")]
    public void Run_BatchFile_EvilValues_NeverInject_Windows()
    {
        var work = Directory.CreateDirectory(Path.Combine(_tempDir, "work"));
        var inertCmd = Path.Combine(work.FullName, "inert.cmd");
        var inertBat = Path.Combine(work.FullName, "inert.bat");
        var capture = Path.Combine(work.FullName, "capture.cmd");
        File.WriteAllText(inertCmd, "@exit /b 0\r\n");
        File.WriteAllText(inertBat, "@exit /b 0\r\n");
        File.WriteAllText(capture,
            "@echo off\r\nsetlocal DisableDelayedExpansion\r\nset \"arg=%~1\"\r\nsetlocal EnableDelayedExpansion\r\n>\"%~dp0out.txt\" echo(!arg!\r\n");
        var outFile = Path.Combine(work.FullName, "out.txt");
        // Anywhere under the test folder, and in the test process's folder (where a launch that ignored the working
        // directory would put it).
        (string Folder, SearchOption Depth)[] markerPlaces =
            [(_tempDir, SearchOption.AllDirectories), (Environment.CurrentDirectory, SearchOption.TopDirectoryOnly)];
        IEnumerable<string> Markers() =>
            markerPlaces.SelectMany(place => Directory.EnumerateFiles(place.Folder, "marker.txt", place.Depth));
        Assert.Empty(Markers());
        void RemoveMarkers()
        {
            foreach (var marker in Markers().ToList())
                File.Delete(marker);
        }

        var (initExit, _, initErr) = RunTswap("init", "--yubikey", "--no-recovery");
        Assert.True(initExit == 0, $"init failed: {initErr}");

        // A12: the ConPTY leg only where ConPTY exists (Windows 10 1809+).
        List<string> legs = ["redirected"];
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            legs.Add("conpty");
        else
            _output.WriteLine("T46 batch: no ConPTY (before Windows 10 1809), the conpty leg is not run");

        List<string> failures = [];
        var index = 0;
        foreach (var c in EvilValues.BatchCases)
        {
            // A secret per case (A11: 'b1'… holds no part of any batch value).
            var name = $"b{++index}";
            var (ingestExit, _, ingestErr) = RunTswapWithStdin(c.Value, "ingest", name);
            Assert.True(ingestExit == 0, $"{c.Name}: ingest failed: {ingestErr}");

            List<string> batches = [inertCmd, inertBat];
            if (!c.Value.Contains('"'))
                batches.Add(capture);
            foreach (var leg in legs)
            foreach (var batch in batches)
            {
                RemoveMarkers();
                File.Delete(outFile);
                var where = $"{c.Name} [{leg} leg, {Path.GetFileName(batch)}]";

                int exit;
                string output;
                if (leg == "redirected")
                {
                    var (e, stdout, stderr) = RunTswapIn(work, "run", batch, "{{" + name + "}}");
                    (exit, output) = (e, stdout + stderr);
                }
                else
                    (exit, output) = RunTswapInConPty(work, waitForOutput: $"Found tokens: {name}", "-v", "run", batch, "{{" + name + "}}");

                var marker = Markers().Any();
                var refusedForBatch = exit != 0 && output.Contains("batch", StringComparison.OrdinalIgnoreCase);
                var outcome = exit == 0 ? "ran" : refusedForBatch ? "refused, naming batch files" : $"exit {exit}";
                if (marker)
                    failures.Add($"{where}: marker.txt APPEARED (an injection; {outcome})");
                if (batch == capture)
                {
                    if (File.Exists(outFile))
                    {
                        var captured = File.ReadAllText(outFile);
                        outcome += captured == c.Value + "\r\n" ? ", out.txt holds the value exactly" : ", out.txt holds an ALTERED value";
                        if (captured != c.Value + "\r\n")
                            failures.Add($"{where}: out.txt holds an altered value ({captured.Length} chars, expected {c.Value.Length + 2}); marker.txt {(marker ? "appeared" : "did not appear")}");
                    }
                    else if (!refusedForBatch)
                        failures.Add($"{where}: neither out.txt nor a refusal naming batch files (exit {exit}); marker.txt {(marker ? "appeared" : "did not appear")}");
                }
                _output.WriteLine($"T46 batch: {where}: {outcome}; marker.txt {(marker ? "APPEARED" : "absent")}");
            }
        }
        RemoveMarkers();

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    // --- Brief T47 Tasks 2b-2d: the ways out of the batch refusal, and the Unix shells ---

    /// <summary>
    /// Brief T47: a work folder under the test folder (tswap starts there, so a relative script and a marker resolve
    /// there), the <c>marker.txt</c> finder T46's batch test uses (anywhere under the test folder and in the test
    /// process's own folder) and its remover.
    /// </summary>
    private (DirectoryInfo Work, Func<bool> AnyMarker, Action RemoveMarkers) ScriptWork()
    {
        var work = Directory.CreateDirectory(Path.Combine(_tempDir, "work"));
        (string Folder, SearchOption Depth)[] places =
            [(_tempDir, SearchOption.AllDirectories), (Environment.CurrentDirectory, SearchOption.TopDirectoryOnly)];
        IEnumerable<string> Markers() => places.SelectMany(p => Directory.EnumerateFiles(p.Folder, "marker.txt", p.Depth));
        Assert.Empty(Markers());
        return (work, () => Markers().Any(), () =>
        {
            foreach (var marker in Markers().ToList())
                File.Delete(marker);
        });
    }

    /// <summary>Brief T47: T46's two Windows legs, redirected always and ConPTY where it exists (A12 of T46).</summary>
    private List<string> WindowsLegs(string tag)
    {
        List<string> legs = ["redirected"];
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            legs.Add("conpty");
        else
            _output.WriteLine($"{tag}: no ConPTY (before Windows 10 1809), the conpty leg is not run");
        return legs;
    }

    /// <summary>Brief T47: <c>tswap run …</c> in <paramref name="work"/> through one of <see cref="WindowsLegs"/>.</summary>
    private (int Exit, string Output) RunWindowsLeg(DirectoryInfo work, string leg, string name, params string[] runArgs)
    {
        if (leg == "redirected")
        {
            var (exit, stdout, stderr) = RunTswapIn(work, ["run", .. runArgs]);
            return (exit, stdout + stderr);
        }
        return RunTswapInConPty(work, waitForOutput: $"Found tokens: {name}", ["-v", "run", .. runArgs]);
    }

    /// <summary>Brief T47: ingests each case under its own name (<c>v1</c>, … : A11 of T46, checked), returning the names.</summary>
    private List<(EvilValues.Case Case, string Name)> IngestEach(IEnumerable<EvilValues.Case> cases, string prefix)
    {
        List<(EvilValues.Case, string)> named = [];
        foreach (var c in cases)
        {
            var name = $"{prefix}{named.Count + 1}";
            Assert.True(EvilValues.NameIsSafeFor(name, c.Value), $"{c.Name}: the name {name} holds part of the value");
            var (exit, _, err) = RunTswapWithStdin(c.Value, "ingest", name);
            Assert.True(exit == 0, $"{c.Name}: ingest failed: {err}");
            named.Add((c, name));
        }
        return named;
    }

    /// <summary>
    /// Brief T47 Task 2b: the refusal's first way out, a PowerShell script run with <c>-File</c>, on real Windows.
    /// <c>capture.ps1</c> writes <c>$args[0]</c> to <c>out.txt</c> exactly (no newline added); it runs as
    /// <c>tswap run powershell -File capture.ps1 {{name}}</c> and the same with <c>pwsh</c>, on both legs, for every
    /// T46 batch case and the corpus's quote and shell-character cases. Invariant: <c>out.txt</c> holds exactly the
    /// value, and <c>marker.txt</c> never appears. Every failure names the case, the leg and the host; if either
    /// PowerShell re-parses a value, the refusal's advice is wrong: report it at once (the brief).
    /// </summary>
    /// <remarks>
    /// Break-it-once (A18, A23; the controller's, on Windows CI): with this <c>capture.ps1</c>, and the one value
    /// <c>;New-Item -Path marker.txt;</c> in place of the cases, <c>marker.txt</c> must appear:
    /// <code>
    /// File.WriteAllText(capture, "Invoke-Expression \"Write-Output $($args[0])\"\r\n");
    /// // cases: [new EvilValues.Case("break-new-item", ";New-Item -Path marker.txt;", "break")]
    /// </code>
    /// </remarks>
    [WindowsFact("PowerShell -File as the way out of the batch-file refusal is a Windows path (powershell and pwsh on the runners)")]
    public void Run_PowerShellFile_EvilValues_ArriveExactly_Windows()
    {
        var (work, anyMarker, removeMarkers) = ScriptWork();
        var capture = Path.Combine(work.FullName, "capture.ps1");
        File.WriteAllText(capture, "[IO.File]::WriteAllText(\"$PSScriptRoot\\out.txt\", $args[0])\r\n");
        var outFile = Path.Combine(work.FullName, "out.txt");

        var (initExit, _, initErr) = RunTswap("init", "--yubikey", "--no-recovery");
        Assert.True(initExit == 0, $"init failed: {initErr}");
        var legs = WindowsLegs("T47 powershell");
        var named = IngestEach(EvilValues.BatchCases.Concat(EvilValues.Cases.Where(c => c.Class == "shell")), "v");

        List<string> failures = [];
        foreach (var (c, name) in named)
        foreach (var host in new[] { "powershell", "pwsh" })
        foreach (var leg in legs)
        {
            removeMarkers();
            File.Delete(outFile);
            var where = $"{c.Name} [{leg} leg, {host}]";
            var (exit, output) = RunWindowsLeg(work, leg, name, host, "-File", "capture.ps1", "{{" + name + "}}");
            var marker = anyMarker();
            if (marker)
                failures.Add($"{where}: marker.txt APPEARED (exit {exit})");
            if (!File.Exists(outFile))
                failures.Add($"{where}: no out.txt (exit {exit}): {EscapeVt(output)}");
            else if (File.ReadAllText(outFile) is var captured && captured != c.Value)
                failures.Add($"{where}: out.txt holds an ALTERED value ({captured.Length} chars, expected {c.Value.Length})");
            _output.WriteLine($"T47 powershell: {where}: exit {exit}; marker.txt {(marker ? "APPEARED" : "absent")}");
        }
        removeMarkers();

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>
    /// Brief T47 Task 2c: the refusal's second way out, for an existing batch script: <c>run --env PW={{name}}
    /// capture-env.cmd</c>, read inside with <c>setlocal EnableDelayedExpansion</c> and <c>!PW!</c> (delayed expansion
    /// never parses the value as command text). For every T46 batch case (<c>x&amp;echo.&gt;marker.txt</c>, unquoted,
    /// included), on both legs. Invariant: <c>out.txt</c> holds the value exactly, T46's comparison
    /// (<c>captured == value + "\r\n"</c>: <c>echo(</c> appends CRLF, A17), and <c>marker.txt</c> never appears.
    /// </summary>
    /// <remarks>
    /// Break-it-once (A18; the controller's, on Windows CI): the batch reading <c>%PW%</c> instead of <c>!PW!</c>, which
    /// cmd.exe expands before it parses the line, so the quote-bearing and the unquoted ampersand values must create
    /// <c>marker.txt</c>:
    /// <code>
    /// File.WriteAllText(capture, "@echo off\r\nsetlocal EnableDelayedExpansion\r\n&gt;\"%~dp0out.txt\" echo(%PW%\r\n");
    /// </code>
    /// </remarks>
    [WindowsFact("batch files and cmd.exe's delayed expansion exist only on Windows")]
    public void Run_EnvWithDelayedExpansion_BatchCases_ArriveExactly_Windows()
    {
        var (work, anyMarker, removeMarkers) = ScriptWork();
        var capture = Path.Combine(work.FullName, "capture-env.cmd");
        File.WriteAllText(capture, "@echo off\r\nsetlocal EnableDelayedExpansion\r\n>\"%~dp0out.txt\" echo(!PW!\r\n");
        var outFile = Path.Combine(work.FullName, "out.txt");

        var (initExit, _, initErr) = RunTswap("init", "--yubikey", "--no-recovery");
        Assert.True(initExit == 0, $"init failed: {initErr}");
        var legs = WindowsLegs("T47 batch env");
        var named = IngestEach(EvilValues.BatchCases, "e");

        List<string> failures = [];
        foreach (var (c, name) in named)
        foreach (var leg in legs)
        {
            removeMarkers();
            File.Delete(outFile);
            var where = $"{c.Name} [{leg} leg, capture-env.cmd]";
            var (exit, output) = RunWindowsLeg(work, leg, name, "--env", "PW={{" + name + "}}", "--", capture);
            var marker = anyMarker();
            if (marker)
                failures.Add($"{where}: marker.txt APPEARED (exit {exit})");
            if (!File.Exists(outFile))
                failures.Add($"{where}: no out.txt (exit {exit}): {EscapeVt(output)}");
            else if (File.ReadAllText(outFile) is var captured && captured != c.Value + "\r\n")
                failures.Add($"{where}: out.txt holds an ALTERED value ({captured.Length} chars, expected {c.Value.Length + 2})");
            _output.WriteLine($"T47 batch env: {where}: exit {exit}; marker.txt {(marker ? "APPEARED" : "absent")}");
        }
        removeMarkers();

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>A program on PATH (no extension search: these tests are Unix-only), or null.</summary>
    private static string? FindOnPath(string program) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, program))
            .FirstOrDefault(File.Exists);

    /// <summary>
    /// Brief T47 Task 2d (A24): bash, and zsh where installed (macOS has it; a Linux runner may not, and then the zsh
    /// leg is left out with a line saying why, never an early return).
    /// </summary>
    private List<string> UnixShells(string tag)
    {
        List<string> shells = ["bash"];
        if (FindOnPath("zsh") is not null)
            shells.Add("zsh");
        else
            _output.WriteLine($"{tag}: zsh is not installed on this host, the zsh leg is not run");
        return shells;
    }

    /// <summary>
    /// Brief T47 Task 2d, the target: <c>capture.sh</c> and <c>capture.zsh</c> write <c>"$1"</c> to <c>out.txt</c>
    /// exactly (<c>printf '%s' "$1" &gt; out.txt</c>), run as <c>tswap run bash ./capture.sh {{name}}</c> and
    /// <c>tswap run zsh -f ./capture.zsh {{name}}</c>, for every corpus value (T46's cases and its batch cases).
    /// Invariant: <c>out.txt</c> holds exactly the stored value (ingest trims trailing whitespace, T46's A3), and no
    /// <c>marker.txt</c> appears. Every failure names the case and the shell.
    /// </summary>
    /// <remarks>
    /// Break-it-once (A18; the controller's): a <c>capture.sh</c> that runs the value, so <c>x&amp;echo.&gt;marker.txt</c>
    /// must create <c>marker.txt</c> (bash makes the redirection's file before it finds no <c>echo.</c>):
    /// <code>
    /// File.WriteAllText(Path.Combine(work.FullName, "capture.sh"), "eval \"$1\"\nprintf '%s' \"$1\" &gt; out.txt\n");
    /// </code>
    /// </remarks>
    [UnixFact("bash and zsh as the targets of run")]
    public void Run_UnixShellScripts_EvilValues_ArriveExactly()
    {
        var (work, anyMarker, removeMarkers) = ScriptWork();
        File.WriteAllText(Path.Combine(work.FullName, "capture.sh"), "printf '%s' \"$1\" > out.txt\n");
        File.WriteAllText(Path.Combine(work.FullName, "capture.zsh"), "printf '%s' \"$1\" > out.txt\n");
        var outFile = Path.Combine(work.FullName, "out.txt");

        var (initExit, _, initErr) = RunTswap("init", "--yubikey", "--no-recovery");
        Assert.True(initExit == 0, $"init failed: {initErr}");
        // The tswap-syntax cases name the corpus's other secret.
        var (otherExit, _, otherErr) = RunTswapWithStdin(EvilValues.OtherSecretValue, "ingest", EvilValues.OtherSecretName);
        Assert.True(otherExit == 0, otherErr);
        var shells = UnixShells("T47 unix target");
        var named = IngestEach(EvilValues.Cases.Concat(EvilValues.BatchCases), "u");

        List<string> failures = [];
        foreach (var (c, name) in named)
        foreach (var shell in shells)
        {
            removeMarkers();
            File.Delete(outFile);
            var where = $"{c.Name} [{shell}]";
            string[] command = shell == "bash"
                ? ["run", "bash", "./capture.sh", "{{" + name + "}}"]
                : ["run", "zsh", "-f", "./capture.zsh", "{{" + name + "}}"];
            var (exit, stdout, stderr) = RunTswapIn(work, command);
            var expected = c.Value.TrimEnd();
            if (anyMarker())
                failures.Add($"{where}: marker.txt APPEARED (exit {exit})");
            if (!File.Exists(outFile))
                failures.Add($"{where}: no out.txt (exit {exit}): {stderr}{stdout}");
            else if (File.ReadAllText(outFile, Encoding.UTF8) is var captured && captured != expected)
                failures.Add($"{where}: out.txt holds an ALTERED value ({captured.Length} chars, expected {expected.Length})");
        }
        removeMarkers();

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>
    /// Brief T47 Task 2e: Git Bash's <c>bash.exe</c> (MSYS2) from PATH: the first one under a <c>\Git\</c> folder, never
    /// System32's <c>bash.exe</c> (WSL's launcher), or null.
    /// </summary>
    private static string? FindGitBash() =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Where(dir => dir.Contains(@"\Git\", StringComparison.OrdinalIgnoreCase) || dir.EndsWith(@"\Git", StringComparison.OrdinalIgnoreCase))
            .Select(dir => Path.Combine(dir, "bash.exe"))
            .FirstOrDefault(File.Exists);

    /// <summary>
    /// Brief T47 Task 2e (owner: "And bash on Windows"): <c>tswap run &lt;Git Bash&gt; ./capture.sh {{name}}</c>, where
    /// <c>capture.sh</c> writes <c>"$1"</c> to <c>out.txt</c> exactly (<c>printf '%s' "$1"</c>), on both legs (redirected
    /// and ConPTY, as T46's batch test), for every corpus value (T46's cases and batch cases) and three built here: an
    /// absolute Unix-looking path, a glob star and a glob question mark (with <c>abcXdef-value-2</c> in the work folder,
    /// so a glob has something to match). Invariant (git-bash-exact): <c>out.txt</c> holds exactly the stored value, and
    /// <c>marker.txt</c> never appears. MSYS2 converts path-like arguments when a non-MSYS program starts it, and may
    /// glob: an alteration is a finding (T46's mechanism, <see cref="EvilValues.KnownFindings"/>, pairs left out here),
    /// never a reason to weaken this test; the failure lists every altered case with its leg, for the controller's ruling.
    /// </summary>
    /// <remarks>
    /// <para>Git Bash is started by its full path: CreateProcess searches System32 before PATH, where <c>bash.exe</c> is
    /// WSL's launcher. Without Git Bash on PATH the legs are left out with a line saying why (never an early return).
    /// <c>max-length</c> (65,536 characters) is left out: a Windows command line holds at most 32,767.</para>
    /// <para>Break-it-once (the controller's, on Windows CI): a <c>capture.sh</c> that runs the value, so the ampersand
    /// batch values must create <c>marker.txt</c>:</para>
    /// <code>
    /// File.WriteAllText(Path.Combine(work.FullName, "capture.sh"), "eval \"$1\"\nprintf '%s' \"$1\" &gt; out.txt\n");
    /// </code>
    /// </remarks>
    [WindowsFact("Git Bash (MSYS2) started by a Windows program exists only on Windows")]
    public void Run_GitBashScript_EvilValues_ArriveExactly_Windows()
    {
        // Task 2f: the extras are local to this test, outside the corpus KnownFindings checks, so glob-star (altered
        // on CI, #402) is left out here with a line, not registered.
        _output.WriteLine("T47 git bash: glob-star is left out (Git Bash expands the glob, #402; T47 Task 2f)");
        var cases = EvilValues.Cases.Concat(EvilValues.BatchCases).Concat(GitBashExtras.Where(c => c.Name != "glob-star"))
            .Where(c => !EvilValues.KnownFindings.ContainsKey((c.Name, EvilValues.GitBashExact)));
        var failures = RunGitBashCases(cases, viaEnv: false);
        Assert.True(failures.Count == 0, $"{failures.Count} finding(s):\n" + string.Join("\n", failures));
    }

    /// <summary>
    /// Brief T47 Task 2f: the guide's and the prompt's way with Git Bash, <c>tswap run --env PW={{name}} -- &lt;Git
    /// Bash&gt; ./capture-env.sh</c>, where <c>capture-env.sh</c> writes <c>"$PW"</c> to <c>out.txt</c> exactly
    /// (<c>printf '%s' "$PW"</c>), on both legs, for every corpus value, the batch cases and the three extras (#402's spike:
    /// all 73 values intact). Invariant: <c>out.txt</c> holds exactly the stored value, and <c>marker.txt</c> never
    /// appears. Left out, with lines (<see cref="RunGitBashCases"/>): max-length, and the non-ASCII values, which wait
    /// on the stdin-encoding question.
    /// </summary>
    /// <remarks>
    /// Break-it-once (the controller's, on Windows CI): a <c>capture-env.sh</c> that runs the value, so the ampersand
    /// batch values must create <c>marker.txt</c>:
    /// <code>
    /// File.WriteAllText(Path.Combine(work.FullName, "capture-env.sh"), "eval \"$PW\"\nprintf '%s' \"$PW\" &gt; out.txt\n");
    /// </code>
    /// </remarks>
    [WindowsFact("Git Bash (MSYS2) started by a Windows program exists only on Windows")]
    public void Run_GitBashScript_EnvValue_EvilValues_ArriveExactly_Windows()
    {
        var failures = RunGitBashCases(EvilValues.Cases.Concat(EvilValues.BatchCases).Concat(GitBashExtras), viaEnv: true);
        Assert.True(failures.Count == 0, $"{failures.Count} failure(s):\n" + string.Join("\n", failures));
    }

    /// <summary>Brief T47 Task 2e: the three values built for Git Bash (a Unix-looking path, a glob star, a glob question mark).</summary>
    private static readonly EvilValues.Case[] GitBashExtras =
    [
        new("unix-absolute-path", "/abc/def-value-1", "git-bash"),
        new("glob-star", "abc*def-value-2", "git-bash"),
        new("glob-question-mark", "abc?def-value-3", "git-bash"),
    ];

    /// <summary>
    /// Brief T47 Tasks 2e and 2f: runs Git Bash through tswap for each case on both Windows legs and returns every
    /// failure (marker.txt, no out.txt, an altered value), naming case and leg. With <paramref name="viaEnv"/> the value
    /// goes in <c>--env PW</c> to <c>capture-env.sh</c> (<c>"$PW"</c>), else as an argument to <c>capture.sh</c>
    /// (<c>"$1"</c>). An empty <c>abcXdef-value-2</c> in the work folder gives a glob something to match. Without Git
    /// Bash on PATH no leg runs (a line says why). <c>max-length</c> is always left out, with a line: a Windows command
    /// line holds at most 32,767 characters.
    /// </summary>
    private List<string> RunGitBashCases(IEnumerable<EvilValues.Case> cases, bool viaEnv)
    {
        var (work, anyMarker, removeMarkers) = ScriptWork();
        var script = viaEnv ? "capture-env.sh" : "capture.sh";
        File.WriteAllText(Path.Combine(work.FullName, script), viaEnv ? "printf '%s' \"$PW\" > out.txt\n" : "printf '%s' \"$1\" > out.txt\n");
        File.WriteAllText(Path.Combine(work.FullName, "abcXdef-value-2"), "");
        var outFile = Path.Combine(work.FullName, "out.txt");

        var (initExit, _, initErr) = RunTswap("init", "--yubikey", "--no-recovery");
        Assert.True(initExit == 0, $"init failed: {initErr}");
        var (otherExit, _, otherErr) = RunTswapWithStdin(EvilValues.OtherSecretValue, "ingest", EvilValues.OtherSecretName);
        Assert.True(otherExit == 0, otherErr);

        var tag = viaEnv ? "T47 git bash env" : "T47 git bash";
        var bash = FindGitBash();
        List<string> legs = [];
        if (bash is null)
            _output.WriteLine($"{tag}: no Git Bash (a bash.exe under a \\Git\\ folder) on PATH, its legs are not run");
        else
            legs = WindowsLegs(tag);
        _output.WriteLine($"{tag}: max-length is left out (a Windows command line holds at most 32,767 characters)");
        // T47 Task 2f (controller's correction): a non-ASCII value may already be altered by ingest's stdin on Windows
        // (the console code page), not by Git Bash; those cases wait on that question and are left out here.
        var all = cases.Where(c => c.Name != "max-length").ToList();
        var nonAscii = all.Where(c => c.Value.Any(ch => ch > '\x7F')).Select(c => c.Name).ToList();
        if (nonAscii.Count > 0)
            _output.WriteLine($"{tag}: left out, waiting on the stdin-encoding question (ingest's stdin on Windows): {string.Join(", ", nonAscii)}");
        var named = IngestEach(all.Where(c => !nonAscii.Contains(c.Name)), "g");

        static string Shown(string s) => EscapeVt(s).Length <= 80 ? EscapeVt(s) : EscapeVt(s)[..80] + "...";
        List<string> failures = [];
        foreach (var (c, name) in named)
        foreach (var leg in legs)
        {
            removeMarkers();
            File.Delete(outFile);
            var where = $"{c.Name} [{leg} leg, git bash{(viaEnv ? ", --env" : "")}]";
            var (exit, output) = viaEnv
                ? RunWindowsLeg(work, leg, name, "--env", "PW={{" + name + "}}", "--", bash!, "./" + script)
                : RunWindowsLeg(work, leg, name, bash!, "./" + script, "{{" + name + "}}");
            var expected = c.Value.TrimEnd();
            var marker = anyMarker();
            if (marker)
                failures.Add($"{where}: marker.txt APPEARED (exit {exit})");
            if (!File.Exists(outFile))
                failures.Add($"{where}: no out.txt (exit {exit}): {Shown(output)}");
            else if (File.ReadAllText(outFile, Encoding.UTF8) is var captured && captured != expected)
                failures.Add($"{where}: ALTERED: expected [{Shown(expected)}] ({expected.Length} chars), got [{Shown(captured)}] ({captured.Length} chars)");
            _output.WriteLine($"{tag}: {where}: exit {exit}; marker.txt {(marker ? "APPEARED" : "absent")}");
        }
        removeMarkers();
        return failures;
    }

    /// <summary>
    /// Brief T47 Task 2f: a git-bash-exact finding's full assertion, the one case through <see cref="RunGitBashCases"/>
    /// as an argument. Its facts are plain skipped <c>[Fact]</c>s (T46's protocol); un-skipping one means making it a
    /// <c>[WindowsFact]</c> as well (#402).
    /// </summary>
    private void AssertGitBashArrivesExactly(string caseName)
    {
        var failures = RunGitBashCases([EvilValues.Get(caseName)], viaEnv: false);
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    // Brief T47 Task 2f: the git-bash-exact findings of CI run 45021236991 (#402), one fact per (case, invariant).
    [Fact(Skip = "T46 finding 3: " + EvilValues.Finding3)]
    public void Finding3_SingleQuote_GitBashExact() => AssertGitBashArrivesExactly("single-quote");

    [Fact(Skip = "T46 finding 3: " + EvilValues.Finding3)]
    public void Finding3_OwnerEscapingSet_GitBashExact() => AssertGitBashArrivesExactly("owner-escaping-set");

    [Fact(Skip = "T46 finding 4: " + EvilValues.Finding4)]
    public void Finding4_TokenSyntax_GitBashExact() => AssertGitBashArrivesExactly("token-syntax");

    [Fact(Skip = "T46 finding 4: " + EvilValues.Finding4)]
    public void Finding4_FileTokenSyntax_GitBashExact() => AssertGitBashArrivesExactly("file-token-syntax");

    [Fact(Skip = "T46 finding 4: " + EvilValues.Finding4)]
    public void Finding4_EmbeddedTokenSyntax_GitBashExact() => AssertGitBashArrivesExactly("embedded-token-syntax");

    [Fact(Skip = "T46 finding 5: " + EvilValues.Finding5)]
    public void Finding5_LfInside_GitBashExact() => AssertGitBashArrivesExactly("lf-inside");

    [Fact(Skip = "T46 finding 5: " + EvilValues.Finding5)]
    public void Finding5_CrlfInside_GitBashExact() => AssertGitBashArrivesExactly("crlf-inside");

    [Fact(Skip = "T46 finding 5: " + EvilValues.Finding5)]
    public void Finding5_CrInside_GitBashExact() => AssertGitBashArrivesExactly("cr-inside");

    /// <summary>
    /// Brief T47 Task 2d, the calling shell (A11): a script that itself runs <c>tswap -v run true {{pw}}</c>, the token
    /// written literally in its source, unquoted and quoted (<c>'{{pw}}'</c>). tswap substitutes; the calling shell only
    /// decides whether the token arrives. bash (plain, <c>set -B</c>, <c>shopt -s extglob</c>) and zsh (<c>zsh -f</c>,
    /// plain): the token arrives unchanged either way (tswap's <c>-v</c> line <c>Found tokens: pw</c>). zsh with
    /// <c>setopt BRACE_CCL</c> expands the unquoted <c>{pw}</c> to its characters (zsh's documentation, Brace
    /// Expansion), so unquoted the token does not arrive; quoted it does. Every failure names the shell, its options and
    /// the quoting.
    /// </summary>
    [UnixFact("bash and zsh as the shell that calls tswap")]
    public void Run_TheCallingShell_PassesTheTokenOn_UnlessZshBraceCcl()
    {
        var (work, _, _) = ScriptWork();
        var (initExit, _, initErr) = RunTswap("init", "--yubikey", "--no-recovery");
        Assert.True(initExit == 0, $"init failed: {initErr}");
        var (ingestExit, _, ingestErr) = RunTswapWithStdin("calling-shell-value-7Hq", "ingest", "pw");
        Assert.True(ingestExit == 0, ingestErr);

        // (shell, its options' line, whether the unquoted token arrives)
        List<(string Shell, string Options, bool UnquotedArrives)> variants =
        [
            ("bash", "", true),
            ("bash", "set -B", true),
            ("bash", "shopt -s extglob", true),
        ];
        if (UnixShells("T47 calling shell").Contains("zsh"))
            variants.AddRange([("zsh", "", true), ("zsh", "setopt BRACE_CCL", false)]);

        List<string> failures = [];
        foreach (var (shell, options, unquotedArrives) in variants)
        foreach (var (quoting, token, arrives) in new[] { ("unquoted", "{{pw}}", unquotedArrives), ("quoted", "'{{pw}}'", true) })
        {
            var where = $"{shell}{(options.Length > 0 ? $" ({options})" : "")}, {quoting}";
            var script = Path.Combine(work.FullName, "call." + shell);
            File.WriteAllText(script, $"{options}\n\"$TSWAP_BIN\" -v run true {token}\n");
            var psi = MakePsi(work);
            psi.FileName = shell;
            if (shell == "zsh")
                psi.ArgumentList.Add("-f");
            psi.ArgumentList.Add(script);
            psi.Environment["TSWAP_BIN"] = _binaryPath;
            using var process = Process.Start(psi)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            var lines = stdout.Result.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
            var found = lines.Contains("Found tokens: pw");
            if (arrives && (!found || process.ExitCode != 0))
                failures.Add($"{where}: the token did not arrive unchanged (exit {process.ExitCode}): {stdout.Result}{stderr}");
            if (!arrives && found)
                failures.Add($"{where}: the token arrived, though the shell should have expanded it: {stdout.Result}");
            _output.WriteLine($"T47 calling shell: {where}: exit {process.ExitCode}; Found tokens: pw {(found ? "seen" : "not seen")}");
        }

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    // --- ConPTY P/Invoke helpers (used by Run_CompoundCommand_RedactedOutput_WindowsConPty) ---

    [StructLayout(LayoutKind.Sequential)]
    private struct WinCoord { public short X, Y; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinStartupInfo
    {
        public int    cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinStartupInfoEx
    {
        public WinStartupInfo StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinProcessInformation { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinSecurityAttributes { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref WinSecurityAttributes lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(WinCoord size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    // lpValue carries the HPCON handle value itself for the pseudoconsole attribute
    // (not a pointer to it) — matching WindowsPty and Microsoft's ConPTY sample.
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string? lpApplicationName, [In] char[] lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref WinStartupInfoEx lpStartupInfo, out WinProcessInformation lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    /// <summary>
    /// Launches tswap attached to a fresh pseudoconsole and returns its exit code plus
    /// everything rendered to the ConPTY output pipe (VT sequences included).
    /// <paramref name="waitForOutput"/> is the sentinel the caller expects to see last;
    /// the ConPTY is held open until it renders (bounded by a deadline) because closing
    /// early can discard un-painted frames. Test env vars are passed by temporarily
    /// setting them on this process (inherited by the child); safe because the suite
    /// runs with parallelism disabled.
    /// </summary>
    private (int exitCode, string output) RunTswapInConPty(string waitForOutput, params string[] args) =>
        RunTswapInConPty(workingDirectory: null, waitForOutput, args);

    /// <summary>Brief T46 (A13): <see cref="RunTswapInConPty(string, string[])"/> with tswap started in <paramref name="workingDirectory"/>.</summary>
    private (int exitCode, string output) RunTswapInConPty(DirectoryInfo? workingDirectory, string waitForOutput, params string[] args)
    {
        const uint EXTENDED_STARTUPINFO_PRESENT        = 0x00080000;
        const int  PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;

        var inRd = IntPtr.Zero; var inWr = IntPtr.Zero;
        var outRd = IntPtr.Zero; var outWr = IntPtr.Zero;
        var hPC = IntPtr.Zero; var attrList = IntPtr.Zero; var hProcess = IntPtr.Zero;
        bool attrInit = false;
        var savedEnv = new Dictionary<string, string?>();

        void SetEnv(string name, string? value)
        {
            savedEnv[name] = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }

        try
        {
            var sec = new WinSecurityAttributes { nLength = Marshal.SizeOf<WinSecurityAttributes>() };
            if (!CreatePipe(out inRd, out inWr, ref sec, 0))
                throw new Exception($"CreatePipe(stdin) failed ({Marshal.GetLastWin32Error()})");
            if (!CreatePipe(out outRd, out outWr, ref sec, 0))
                throw new Exception($"CreatePipe(stdout) failed ({Marshal.GetLastWin32Error()})");

            // Wide enough that the redaction marker never wraps mid-token.
            int hr = CreatePseudoConsole(new WinCoord { X = 120, Y = 30 }, inRd, outWr, 0, out hPC);
            if (hr != 0)
                throw new Exception($"CreatePseudoConsole failed (HRESULT 0x{hr:X8})");
            CloseHandle(inRd);  inRd = IntPtr.Zero;   // ConPTY owns these ends now
            CloseHandle(outWr); outWr = IntPtr.Zero;

            var attrSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
            attrList = Marshal.AllocHGlobal(attrSize);
            if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize))
                throw new Exception("InitializeProcThreadAttributeList failed");
            attrInit = true;
            if (!UpdateProcThreadAttribute(attrList, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE),
                    hPC, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw new Exception("UpdateProcThreadAttribute failed");

            // STARTF_USESTDHANDLES with null handles (Windows Terminal's ConptyConnection
            // pattern): without it the child receives this process's std handle VALUES
            // (pipes under `dotnet test`, invalid in the child since bInheritHandles is
            // false), and Windows only swaps std handles for fresh console handles when
            // the old ones were console handles — leaving the child writing to nothing.
            const int STARTF_USESTDHANDLES = 0x00000100;
            var six = new WinStartupInfoEx
            {
                StartupInfo = new WinStartupInfo
                {
                    cb = Marshal.SizeOf<WinStartupInfoEx>(),
                    dwFlags = STARTF_USESTDHANDLES, // hStdInput/Output/Error stay null
                },
                lpAttributeList = attrList,
            };

            var cmdStr = string.Join(' ', new[] { _binaryPath }.Concat(args).Select(QuoteWindowsArg));
            var cmdLine = new char[cmdStr.Length + 1];
            cmdStr.CopyTo(0, cmdLine, 0, cmdStr.Length);

            // Child inherits this process's environment (lpEnvironment = null).
            SetEnv("TSWAP_TEST_KEY", _testKeyHex);
            SetEnv("TSWAP_TEST_SUDO_BYPASS", "1");
            SetEnv("TSWAP_CONFIG_DIR", _tempDir);

            if (!CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
                    EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, workingDirectory?.FullName, ref six, out var pi))
                throw new Exception($"CreateProcess failed ({Marshal.GetLastWin32Error()})");
            hProcess = pi.hProcess;
            CloseHandle(pi.hThread);

            var sb = new StringBuilder();
            var sbLock = new object();
            var readTask = Task.Run(() =>
            {
                var buf = new byte[4096];
                while (ReadFile(outRd, buf, (uint)buf.Length, out uint n, IntPtr.Zero) && n > 0)
                {
                    var chunk = Encoding.UTF8.GetString(buf, 0, (int)n);
                    lock (sbLock) sb.Append(chunk);
                }
            });

            if (WaitForSingleObject(hProcess, 60_000) != 0)
            {
                TerminateProcess(hProcess, 1);
                WaitForSingleObject(hProcess, 5_000);
            }
            GetExitCodeProcess(hProcess, out uint exitCode);

            // ConPTY paints frames on its own schedule, and ClosePseudoConsole can discard
            // frames not yet written to the output pipe — a fast child can exit before its
            // text is rendered. Keep the ConPTY open until the caller's sentinel text has
            // been captured (or a deadline passes on genuine failure), then close.
            var drainDeadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < drainDeadline)
            {
                string snapshot;
                lock (sbLock) snapshot = sb.ToString();
                if (snapshot.Contains(waitForOutput)) break;
                Thread.Sleep(100);
            }
            Thread.Sleep(250); // grace period for trailing frames after the sentinel

            // Closing the ConPTY releases the output pipe so the read task sees EOF.
            ClosePseudoConsole(hPC); hPC = IntPtr.Zero;
            readTask.Wait(TimeSpan.FromSeconds(10));

            lock (sbLock) return ((int)exitCode, sb.ToString());
        }
        finally
        {
            foreach (var (name, value) in savedEnv)
                Environment.SetEnvironmentVariable(name, value);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            if (hPC     != IntPtr.Zero) ClosePseudoConsole(hPC);
            if (inWr    != IntPtr.Zero) CloseHandle(inWr);
            if (outRd   != IntPtr.Zero) CloseHandle(outRd);
            if (inRd    != IntPtr.Zero) CloseHandle(inRd);
            if (outWr   != IntPtr.Zero) CloseHandle(outWr);
            if (attrInit)               DeleteProcThreadAttributeList(attrList);
            if (attrList != IntPtr.Zero) Marshal.FreeHGlobal(attrList);
        }
    }

    // Renders a VT stream printable for assertion messages (ESC → \e), truncated to
    // keep CI logs readable.
    private static string EscapeVt(string s)
    {
        var escaped = s.Replace("\u001b", "\\e").Replace("\r", "\\r").Replace("\n", "\\n");
        return escaped.Length <= 3000 ? escaped : escaped[..3000] + $"…(+{escaped.Length - 3000} more)";
    }

    // CommandLineToArgvW-compatible quoting (mirrors WindowsPty.WindowsQuoteArg).
    private static string QuoteWindowsArg(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny([' ', '\t', '"']) < 0)
            return arg;

        var sb = new StringBuilder("\"");
        int backslashes = 0;
        foreach (char c in arg)
        {
            if (c == '\\') { backslashes++; }
            else if (c == '"')
            {
                sb.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
            }
            else
            {
                if (backslashes > 0) { sb.Append('\\', backslashes); backslashes = 0; }
                sb.Append(c);
            }
        }
        sb.Append('\\', backslashes * 2).Append('"');
        return sb.ToString();
    }
}
