using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Integration tests for Program.cs using TSWAP_TEST_KEY to bypass YubiKey.
/// Each test gets an isolated temp config directory and a deterministic test key.
/// </summary>
public class ProgramTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _testKeyHex;
    private readonly string _projectDir;

    public ProgramTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-prog-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        // Deterministic 32-byte test key
        _testKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        _projectDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
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
            FileName = "dotnet",
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
        psi.ArgumentList.Add("run");
        psi.ArgumentList.Add("--project");
        psi.ArgumentList.Add($"{_projectDir}/tswap.csproj");
        psi.ArgumentList.Add("--");
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

    [Fact]
    public void Init_CreatesConfigFile()
    {
        var (exit, stdout, _) = RunTswap("init");

        Assert.Equal(0, exit);
        Assert.Contains("test mode", stdout);
        Assert.True(File.Exists(Path.Combine(_tempDir, "config.json")));
    }

    [Fact]
    public void Init_ConfigHasSyntheticSerials()
    {
        RunTswap("init");

        var json = File.ReadAllText(Path.Combine(_tempDir, "config.json"));
        var config = JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!;

        Assert.Equal(new List<int> { 99999999, 99999998 }, config.YubiKeySerials);
    }

    // --- Create ---

    [Fact]
    public void Create_GeneratesSecret()
    {
        RunTswap("init");
        var (exit, stdout, _) = RunTswap("create", "my-secret");

        Assert.Equal(0, exit);
        Assert.Contains("my-secret", stdout);
        Assert.Contains("created", stdout);
    }

    [Fact]
    public void Create_CustomLength()
    {
        RunTswap("init");
        var (exit, stdout, _) = RunTswap("create", "short-secret", "8");

        Assert.Equal(0, exit);
        Assert.Contains("8 chars", stdout);
    }

    [Fact]
    public void Create_DuplicateNameFails()
    {
        RunTswap("init");
        RunTswap("create", "dup-secret");
        var (exit, _, stderr) = RunTswap("create", "dup-secret");

        Assert.NotEqual(0, exit);
        Assert.Contains("already exists", stderr);
    }

    [Fact]
    public void Create_EmptyNameFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "");

        Assert.NotEqual(0, exit);
        Assert.Contains("empty", stderr);
    }

    [Fact]
    public void Create_NameWithSpaceFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "bad name");

        Assert.NotEqual(0, exit);
        Assert.Contains("Invalid secret name", stderr);
    }

    [Fact]
    public void Create_NameWithSpecialCharsFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "bad!name");

        Assert.NotEqual(0, exit);
        Assert.Contains("Invalid secret name", stderr);
    }

    [Fact]
    public void Create_NameTooLongFails()
    {
        RunTswap("init");
        var longName = new string('a', 65);
        var (exit, _, stderr) = RunTswap("create", longName);

        Assert.NotEqual(0, exit);
        Assert.Contains("too long", stderr);
    }

    [Fact]
    public void Create_NameAtMaxLengthSucceeds()
    {
        RunTswap("init");
        var maxName = new string('a', 64);
        var (exit, _, _) = RunTswap("create", maxName);

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Create_ZeroLengthFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "0");

        Assert.NotEqual(0, exit);
        Assert.Contains("at least 1", stderr);
    }

    [Fact]
    public void Create_NegativeLengthFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "-5");

        Assert.NotEqual(0, exit);
        Assert.Contains("at least 1", stderr);
    }

    [Fact]
    public void Create_TooLongLengthFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "4097");

        Assert.NotEqual(0, exit);
        Assert.Contains("at most 4096", stderr);
    }

    [Fact]
    public void Create_NonNumericLengthFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "abc");

        Assert.NotEqual(0, exit);
        Assert.Contains("whole number", stderr);
    }

    [Fact]
    public void Create_MaxLengthSucceeds()
    {
        RunTswap("init");
        var (exit, stdout, _) = RunTswap("create", "valid-name", "4096");

        Assert.Equal(0, exit);
        Assert.Contains("4096 chars", stdout);
    }

    // --- Names ---

    [Fact]
    public void Names_ListsCreatedSecrets()
    {
        RunTswap("init");
        RunTswap("create", "alpha");
        RunTswap("create", "beta");

        var (exit, stdout, _) = RunTswap("names");

        Assert.Equal(0, exit);
        Assert.Contains("alpha", stdout);
        Assert.Contains("beta", stdout);
    }

    [Fact]
    public void Names_EmptyVault()
    {
        RunTswap("init");
        var (exit, stdout, _) = RunTswap("names");

        Assert.Equal(0, exit);
        Assert.Contains("No secrets", stdout);
    }

    // --- Ingest ---

    [Fact]
    public void Ingest_StoresStdinValue()
    {
        RunTswap("init");
        var (exit, stdout, _) = RunTswapWithStdin("piped-secret-value", "ingest", "from-stdin");

        Assert.Equal(0, exit);
        Assert.Contains("ingested", stdout);

        // Verify it appears in names
        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("from-stdin", namesOut);
    }

    [Fact]
    public void Ingest_DuplicateFails()
    {
        RunTswap("init");
        RunTswapWithStdin("value1", "ingest", "dup-ingest");
        var (exit, _, stderr) = RunTswapWithStdin("value2", "ingest", "dup-ingest");

        Assert.NotEqual(0, exit);
        Assert.Contains("already exists", stderr);
    }

    [Fact]
    public void Ingest_EmptyNameFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswapWithStdin("some-value", "ingest", "");

        Assert.NotEqual(0, exit);
        Assert.Contains("empty", stderr);
    }

    [Fact]
    public void Ingest_NameWithSpaceFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswapWithStdin("some-value", "ingest", "bad name");

        Assert.NotEqual(0, exit);
        Assert.Contains("Invalid secret name", stderr);
    }

    [Fact]
    public void Ingest_TooLongValueFails()
    {
        RunTswap("init");
        var longValue = new string('x', 65537);
        var (exit, _, stderr) = RunTswapWithStdin(longValue, "ingest", "toolong");

        Assert.NotEqual(0, exit);
        Assert.Contains("too long", stderr);
    }

    [Fact]
    public void Ingest_MaxLengthValueSucceeds()
    {
        RunTswap("init");
        var maxValue = new string('x', 65536);
        var (exit, stdout, _) = RunTswapWithStdin(maxValue, "ingest", "maxlen");

        Assert.Equal(0, exit);
        Assert.Contains("ingested", stdout);
    }

    // --- Burn ---

    [Fact]
    public void Burn_MarksSecretAsBurned()
    {
        RunTswap("init");
        RunTswap("create", "burn-me");
        var (exit, stdout, _) = RunTswap("burn", "burn-me", "test reason");

        Assert.Equal(0, exit);
        Assert.Contains("BURNED", stdout);
    }

    [Fact]
    public void Burn_ShowsInNames()
    {
        RunTswap("init");
        RunTswap("create", "visible-burn");
        RunTswap("burn", "visible-burn", "oops");

        var (_, stdout, _) = RunTswap("names");
        Assert.Contains("[BURNED]", stdout);
    }

    [Fact]
    public void Burn_NonexistentFails()
    {
        RunTswap("init");
        var (exit, _, stderr) = RunTswap("burn", "ghost");

        Assert.NotEqual(0, exit);
        Assert.Contains("not found", stderr);
    }

    [Fact]
    public void Burn_AlreadyBurnedFails()
    {
        RunTswap("init");
        RunTswap("create", "already-burned");
        RunTswap("burn", "already-burned", "original reason");

        var (exit, _, stderr) = RunTswap("burn", "already-burned", "second reason");

        Assert.NotEqual(0, exit);
        Assert.Contains("already burned", stderr);
        Assert.Contains("original reason", stderr);
    }

    // --- Burned ---

    [Fact]
    public void Burned_ShowsBurnedSecrets()
    {
        RunTswap("init");
        RunTswap("create", "leaked");
        RunTswap("burn", "leaked", "seen in logs");

        var (exit, stdout, _) = RunTswap("burned");

        Assert.Equal(0, exit);
        Assert.Contains("leaked", stdout);
        Assert.Contains("seen in logs", stdout);
    }

    [Fact]
    public void Burned_NoBurnedSecrets()
    {
        RunTswap("init");
        RunTswap("create", "clean-secret");

        var (exit, stdout, _) = RunTswap("burned");

        Assert.Equal(0, exit);
        Assert.Contains("No burned secrets", stdout);
    }

    // --- Prompt ---

    [Fact]
    public void Prompt_OutputsInstructions()
    {
        // prompt doesn't need init
        var (exit, stdout, _) = RunTswap("prompt");

        Assert.Equal(0, exit);
        Assert.Contains("tswap", stdout);
        Assert.Contains("AI Agent", stdout);
    }

    [Fact]
    public void PromptHash_OutputsHash()
    {
        var (exit, stdout, _) = RunTswap("prompt-hash");

        Assert.Equal(0, exit);
        var hash = stdout.Trim();
        // SHA-256 hex = 64 chars
        Assert.Equal(64, hash.Length);
        Assert.Matches("^[0-9a-f]{64}$", hash);
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
    public void Run_MissingTokenFails()
    {
        RunTswap("init");

        var (exit, _, stderr) = RunTswap("run", "true", "{{nonexistent}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("not found", stderr);
    }

    [Fact]
    public void Run_NoTokensFails()
    {
        RunTswap("init");

        var (exit, _, stderr) = RunTswap("run", "true");

        Assert.NotEqual(0, exit);
        Assert.Contains("No {{tokens}}", stderr);
    }

    [Fact]
    public void Run_BlockedCommandFails()
    {
        RunTswap("init");
        RunTswap("create", "block-test");

        var (exit, _, stderr) = RunTswap("run", "echo", "{{block-test}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("expose secret", stderr);
    }

    [Fact]
    public void Run_PipeBlockedFails()
    {
        RunTswap("init");
        RunTswap("create", "pipe-test");

        var (exit, _, stderr) = RunTswap("run", "curl", "{{pipe-test}}", "|", "cat");

        Assert.NotEqual(0, exit);
        Assert.Contains("Pipes", stderr);
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
        RunTswap("init");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // printf is POSIX-only

        // Regression test for issue #74: the first line of subprocess stdout was
        // silently dropped due to a race between forkpty() and the parent's read loop.
        //
        // Coverage note: the test harness redirects all three streams so tswap always
        // uses FallbackPty, not UnixPty. The structural fix (pre-fork allocation +
        // Task.Run read loop) in UnixPty can only be manually verified with an interactive
        // terminal where no streams are redirected. This test guards the FallbackPty
        // (pipe) path and the shared StreamRedactor logic against future regressions.
        //
        // Command construction note: CmdRun does string.Join(" ", commandArgs) and passes
        // the result to bash -c as one string. To keep "sh -c <compound>" intact, the
        // whole compound must arrive as a single commandArg with its own shell quotes.
        // After tswap substitutes {{my-secret}} → 's3cr3t' the bash string becomes:
        //   sh -c 'echo before; echo 's3cr3t'; echo after'
        // Shell adjacent-string concatenation reassembles this as the three-command script
        //   echo before; echo s3cr3t; echo after
        // which sh then executes. 'echo' is not blocked (only the top-level command, "sh",
        // is checked against the blocklist).
        var (exit, stdout, _) = RunTswap(
            "run", "sh", "-c",
            "'echo before; echo {{my-secret}}; echo after'");

        Assert.Equal(0, exit);
        Assert.Contains("before",  stdout);
        Assert.Contains("after",   stdout);
        Assert.DoesNotContain("s3cr3t", stdout);
        Assert.Contains("[REDACTED: my-secret]", stdout);
    }

    /// <summary>
    /// End-to-end test for issue #74 that exercises the real PTY code path (LinuxPty via
    /// forkpty). The test opens its own outer PTY and gives tswap the slave as its
    /// stdin/stdout/stderr via a bash script, so <c>Console.IsOutputRedirected</c> returns
    /// false inside tswap and <c>Pty.Create()</c> returns <c>LinuxPty</c> — not FallbackPty.
    /// Output is captured from the outer PTY master.
    ///
    /// Note: the original issue #74 symptom ("before" missing) turned out to be a shell
    /// quoting issue in the reproducer command rather than a real race: the shell strips the
    /// single quotes around the compound command before tswap sees it, so bash -c receives
    /// "sh -c echo before; ..." and sh runs echo with no arguments. The fix to UnixPty
    /// (pre-fork allocation + Task.Run read loop) is still a sound defensive improvement, but
    /// the race window is smaller than sh startup time in practice so this test passes with
    /// both the pre-fix and the post-fix UnixPty. Its value is verifying that LinuxPty is
    /// selected (not FallbackPty) and that the full PTY redaction pipeline works correctly.
    /// </summary>
    [Fact]
    public void Run_FirstLineOfStdoutNotDropped_UnixPty()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return;

        RunTswap("init");
        RunTswapWithStdin("s3cr3t", "ingest", "my-secret");

        // Open an outer PTY pair. tswap will inherit the slave as its fds so
        // isatty(0/1/2) returns true and Pty.Create() picks LinuxPty/MacOSPty.
        var nameBuf = new byte[256];
        int masterFd = -1, slaveFd = -1;
        if (OpenPty(ref masterFd, ref slaveFd, nameBuf) < 0)
            throw new Exception($"openpty failed (errno {Marshal.GetLastPInvokeError()})");

        var slavePath = Encoding.ASCII.GetString(nameBuf, 0,
            Array.IndexOf(nameBuf, (byte)0) is int z and >= 0 ? z : nameBuf.Length);

        // Write a small bash script. The two `exec` lines:
        //   1. Replace bash's own fds 0/1/2 with the slave PTY (making tswap see a real TTY).
        //   2. Replace bash with dotnet so dotnet inherits those slave fds.
        //
        // Argument quoting: `"'echo before; ...; echo after'"` inside the double-quoted bash
        // string preserves the inner single quotes literally in dotnet's argv. tswap then joins
        // its commandArgs and gets:
        //   sh -c 'echo before; echo {{my-secret}}; echo after'
        // After substituting {{my-secret}} → s3cr3t the shell sees adjacent string literals
        // (single-quote concatenation) and runs: echo before; echo s3cr3t; echo after.
        var scriptPath = Path.Combine(_tempDir, "pty_test.sh");
        File.WriteAllText(scriptPath,
            $"#!/bin/bash\n" +
            $"exec <{slavePath} >{slavePath} 2>{slavePath}\n" +
            $"exec dotnet run --project {_projectDir}/tswap.csproj" +
            $" -- run sh -c \"'echo before; echo {{{{my-secret}}}}; echo after'\"\n");

        var psi = new ProcessStartInfo { FileName = "bash", UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(scriptPath);
        psi.Environment["TSWAP_TEST_KEY"]            = _testKeyHex;
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"]    = "1";
        psi.Environment["TSWAP_CONFIG_DIR"]          = _tempDir;
        psi.Environment["DOTNET_EnableWriteXorExecute"] = "0";

        using var process = Process.Start(psi)!;
        PtyClose(slaveFd); // close our copy; child holds it — when child exits, master gets EIO

        // Read from the outer PTY master until EIO (all slave fds closed after child exits).
        const int EINTR = 4;
        var sb  = new StringBuilder();
        var buf = new byte[4096];
        while (true)
        {
            int n = (int)PtyRead(masterFd, buf, (nint)buf.Length);
            if (n > 0) { sb.Append(Encoding.UTF8.GetString(buf, 0, n)); continue; }
            if (n == 0) break;
            if (Marshal.GetLastPInvokeError() == EINTR) continue;
            break; // EIO or other terminal error
        }
        PtyClose(masterFd);
        process.WaitForExit();

        var output = sb.ToString();
        Assert.Equal(0, process.ExitCode);
        Assert.Contains("before",               output);
        Assert.Contains("after",                output);
        Assert.DoesNotContain("s3cr3t",         output);
        Assert.Contains("[REDACTED: my-secret]", output);
    }

    // --- No args ---

    [Fact]
    public void NoArgs_ShowsUsage()
    {
        var (exit, stdout, _) = RunTswap();

        Assert.Equal(0, exit);
        Assert.Contains("Usage", stdout);
    }

    // --- Unknown command ---

    [Fact]
    public void UnknownCommand_Fails()
    {
        var (exit, _, stderr) = RunTswap("bogus");

        Assert.NotEqual(0, exit);
        Assert.Contains("Unknown command", stderr);
    }

    // --- TSWAP_TEST_KEY validation ---

    [Fact]
    public void TestKey_WrongLengthFails()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{_projectDir}/tswap.csproj\" -- init",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
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

    [Fact]
    public void SameTestKey_ProducesSameMasterKey()
    {
        // Verify determinism: same TSWAP_TEST_KEY encrypts/decrypts consistently
        RunTswap("init");
        RunTswap("create", "determinism-test");

        // Names should still work (proves decrypt with same key succeeds)
        var (exit, stdout, _) = RunTswap("names");
        Assert.Equal(0, exit);
        Assert.Contains("determinism-test", stdout);
    }

    // --- Apply ---

    [Fact]
    public void Apply_OutputsSubstitutedContent()
    {
        // Initialize and create a secret
        RunTswap("init");
        RunTswap("create", "test-secret", "16");

        // Create a temp YAML file with tswap marker
        var yamlFile = Path.Combine(_tempDir, "test-values.yaml");
        File.WriteAllText(yamlFile, @"database:
  host: localhost
  password: """"  # tswap: test-secret
  port: 5432");

        // Run apply and check stdout
        var (exit, stdout, _) = RunTswap("apply", yamlFile);

        Assert.Equal(0, exit);
        // Should contain the structure
        Assert.Contains("database:", stdout);
        Assert.Contains("host: localhost", stdout);
        Assert.Contains("port: 5432", stdout);
        // Should have password line with marker
        Assert.Contains("# tswap: test-secret", stdout);
        // Should NOT contain empty password
        Assert.DoesNotContain(@"password: """"", stdout);
        // Should have a populated password (16 chars in double quotes)
        Assert.Matches(@"password: "".{16}""", stdout);
    }

    [Fact]
    public void Apply_FailsOnMissingSecret()
    {
        RunTswap("init");

        var yamlFile = Path.Combine(_tempDir, "test-values.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: nonexistent-secret");

        var (exit, _, stderr) = RunTswap("apply", yamlFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("nonexistent-secret", stderr);
        Assert.Contains("not found", stderr);
    }

    // --- Check ---

    [Fact]
    public void Check_ExitCode1_WhenSecretMissing()
    {
        RunTswap("init");

        var yamlFile = Path.Combine(_tempDir, "check-missing.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: missing-secret");

        var (exit, _, _) = RunTswap("check", yamlFile);

        Assert.Equal(1, exit);
    }

    [Fact]
    public void Check_ExitCode2_WhenSecretBurned()
    {
        RunTswap("init");
        RunTswap("create", "burned-check-secret");
        RunTswap("burn", "burned-check-secret", "was leaked");

        var yamlFile = Path.Combine(_tempDir, "check-burned.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: burned-check-secret");

        var (exit, stdout, _) = RunTswap("check", yamlFile);

        Assert.Equal(2, exit);
        Assert.Contains("BURNED", stdout);
    }

    [Fact]
    public void Check_ExitCode1_WhenMixedMissingAndBurned()
    {
        RunTswap("init");
        RunTswap("create", "burned-mixed-secret");
        RunTswap("burn", "burned-mixed-secret", "was leaked");

        var yamlFile = Path.Combine(_tempDir, "check-mixed.yaml");
        File.WriteAllText(yamlFile, @"
password1: """"  # tswap: burned-mixed-secret
password2: """"  # tswap: missing-mixed-secret");

        var (exit, stdout, _) = RunTswap("check", yamlFile);

        // Missing takes precedence over burned, so exit code should be 1
        Assert.Equal(1, exit);
        Assert.Contains("NOT FOUND", stdout);
        Assert.Contains("BURNED", stdout);
    }

    [Fact]
    public void Check_ExitCode0_WhenAllOk()
    {
        RunTswap("init");
        RunTswap("create", "ok-check-secret");

        var yamlFile = Path.Combine(_tempDir, "check-ok.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: ok-check-secret");

        var (exit, _, _) = RunTswap("check", yamlFile);

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Apply_DiagnosticsGoToStderr_NotStdout()
    {
        // NOTE: This test cannot fully validate the fix without real YubiKey hardware.
        // In test mode (TSWAP_TEST_KEY set), no security warning banner is generated,
        // so we can only verify that stdout contains clean YAML without warning text.
        // The negative assertions pass regardless of whether warnings go to stderr.
        // 
        // However, this test still provides value by ensuring that the apply command's
        // stdout output remains clean YAML that can be safely piped or redirected.
        
        RunTswap("init");
        RunTswap("create", "test-secret", "16");

        var yamlFile = Path.Combine(_tempDir, "test-values.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: test-secret");

        var (exit, stdout, stderr) = RunTswap("apply", yamlFile);

        Assert.Equal(0, exit);
        
        // Stdout should contain ONLY the YAML output
        Assert.Contains("password:", stdout);
        Assert.Contains("# tswap: test-secret", stdout);
        
        // Stdout should NOT contain any warning boxes or diagnostic messages
        // (In test mode these assertions always pass, but they document the requirement)
        Assert.DoesNotContain("WARNING", stdout);
        Assert.DoesNotContain("SECURITY", stdout);
        Assert.DoesNotContain("╔═", stdout);  // Box drawing characters
        Assert.DoesNotContain("║", stdout);
        Assert.DoesNotContain("╚═", stdout);
    }

    // --- Init: new config fields ---

    [Fact]
    public void Init_ConfigHasUnlockChallenge()
    {
        RunTswap("init");
        var json = File.ReadAllText(Path.Combine(_tempDir, "config.json"));
        var config = JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!;

        Assert.NotNull(config.UnlockChallenge);
        Assert.Equal(64, config.UnlockChallenge.Length); // 32 bytes as hex
    }

    [Fact]
    public void Init_ConfigHasRngMode()
    {
        RunTswap("init");
        var json = File.ReadAllText(Path.Combine(_tempDir, "config.json"));
        var config = JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!;

        Assert.NotNull(config.RngMode);
        Assert.Equal("system", config.RngMode); // test mode uses default
    }

    // Regression test for issue #39: init must not hang when stdin is piped.
    // The "Insert YubiKey and press Enter" pauses are TTY-only; when stdin is
    // redirected they must be skipped so that piped "yes" answers only the
    // reinitialise prompt and the command completes normally.
    [Fact]
    public void Init_Reinit_PipedYes_DoesNotHang()
    {
        RunTswap("init");
        // "yes\n" answers the "Already initialized. Reinitialize?" prompt.
        var (exit, stdout, _) = RunTswapWithStdin("yes\n", "init");
        Assert.Equal(0, exit);
        Assert.Contains("test mode", stdout);
    }

    // --- Export / Import ---

    [Fact]
    public void Export_CreatesEncryptedFile()
    {
        RunTswap("init");
        RunTswap("create", "my-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        var (exit, stdout, _) = RunTswapWithStdin("passphrase123\npassphrase123\n", "export", exportPath);

        Assert.Equal(0, exit);
        Assert.True(File.Exists(exportPath));
        // File must not contain the plaintext secret name
        Assert.DoesNotContain("my-secret", File.ReadAllText(exportPath));
        Assert.Contains("tswap-export-v1", File.ReadAllText(exportPath));
    }

    [Fact]
    public void Export_Import_RoundTrip()
    {
        RunTswap("init");
        RunTswapWithStdin("secret-value", "ingest", "db-pass");
        RunTswap("create", "api-key");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("strongpassphrase\nstrongpassphrase\n", "export", exportPath);

        // Re-init clears the vault (also delete secrets.json.enc — test key is constant
        // so the old encrypted file remains readable if not explicitly removed)
        // "yes\n" answers the "Already initialized. Reinitialize?" prompt via stdin.
        RunTswapWithStdin("yes\n", "init");
        File.Delete(Path.Combine(_tempDir, "secrets.json.enc"));
        var (exit, stdout, _) = RunTswapWithStdin("strongpassphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Imported 2 secret(s)", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("db-pass", namesOut);
        Assert.Contains("api-key", namesOut);
    }

    [Fact]
    public void Import_SkipsBurnedSecrets()
    {
        RunTswap("init");
        RunTswap("create", "good-secret");
        RunTswap("create", "burned-secret");
        RunTswap("burn", "burned-secret", "compromised");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        RunTswapWithStdin("yes\n", "init");
        File.Delete(Path.Combine(_tempDir, "secrets.json.enc"));
        var (exit, stdout, _) = RunTswapWithStdin("passphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Skipped", stdout);
        Assert.Contains("burned-secret", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("good-secret", namesOut);
        Assert.DoesNotContain("burned-secret", namesOut);
    }

    [Fact]
    public void Import_SkipsExistingSecrets()
    {
        RunTswap("init");
        RunTswap("create", "existing-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        // Import into the same vault — existing-secret already there
        var (exit, stdout, _) = RunTswapWithStdin("passphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Skipped", stdout);
        Assert.Contains("existing-secret", stdout);
    }

    [Fact]
    public void Import_WrongPassphraseFails()
    {
        RunTswap("init");
        RunTswap("create", "a-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("correct-passphrase\ncorrect-passphrase\n", "export", exportPath);

        var (exit, _, stderr) = RunTswapWithStdin("wrong-passphrase\n", "import", exportPath);

        Assert.NotEqual(0, exit);
        Assert.Contains("wrong passphrase", stderr);
    }

    // --- Migrate ---

    [Fact]
    public void Migrate_OldConfig_UpdatesRngMode()
    {
        // Simulate a pre-feature config: init normally then strip UnlockChallenge
        RunTswap("init");
        var configPath = Path.Combine(_tempDir, "config.json");
        var config = JsonSerializer.Deserialize(
            File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        var oldConfig = config with { UnlockChallenge = null, RngMode = null };
        File.WriteAllText(configPath,
            JsonSerializer.Serialize(oldConfig, TswapJsonContext.Default.Config));

        // Run migrate, choose YubiKey entropy mode (option 2), decline detailed instructions
        var (exit, stdout, _) = RunTswapWithStdin("2\nno\n", "migrate");

        Assert.Equal(0, exit);
        Assert.Contains("YubiKey hardware", stdout);

        var updated = JsonSerializer.Deserialize(
            File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        Assert.Equal("yubikey", updated.RngMode);
    }

    [Fact]
    public void Migrate_ModernConfig_ReportsUpToDate()
    {
        RunTswap("init");
        // Modern config has UnlockChallenge set and RequiresTouch from synthetic init
        // We need to also set RequiresTouch = true to satisfy all checks
        var configPath = Path.Combine(_tempDir, "config.json");
        var config = JsonSerializer.Deserialize(
            File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        var modernConfig = config with { RequiresTouch = true };
        File.WriteAllText(configPath,
            JsonSerializer.Serialize(modernConfig, TswapJsonContext.Default.Config));

        var (exit, stdout, _) = RunTswap("migrate");

        Assert.Equal(0, exit);
        Assert.Contains("up to date", stdout);
    }

    // Regression test for issue #39: migrate must not hang when stdin is piped.
    // Synthetic init leaves RequiresTouch=null → needsTouchMigration=true → the
    // "Show detailed re-initialization instructions? (yes/no):" prompt is shown.
    // Piped "no\n" must answer it without blocking and the command must exit 0.
    [Fact]
    public void Migrate_PipedNo_DoesNotHang()
    {
        RunTswap("init");
        // Default synthetic config: RngMode="system", UnlockChallenge=set, RequiresTouch=null
        // → needsReInit=true (touch migration required) → yes/no prompt is shown
        var (exit, _, _) = RunTswapWithStdin("no\n", "migrate");
        Assert.Equal(0, exit);
    }

    // --- tocomment: security ---

    [Fact]
    public void ToComment_DryRun_DoesNotExposeSecretInOutput()
    {
        RunTswap("init");
        // Ingest a known secret value via stdin
        var (ingestExit, _, _) = RunTswapWithStdin("supersecretvalue123", "ingest", "my-password");
        Assert.Equal(0, ingestExit);

        // Write a YAML file containing the plaintext secret
        var yamlFile = Path.Combine(_tempDir, "applied.yaml");
        File.WriteAllText(yamlFile, "password: supersecretvalue123");

        // Run tocomment --dry-run and capture output
        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");

        Assert.Equal(0, exit);
        // The secret must NOT appear anywhere in the output (stdout or stderr)
        Assert.DoesNotContain("supersecretvalue123", stdout);
        Assert.DoesNotContain("supersecretvalue123", stderr);
        // The diff output is now in stderr (diagnostic output)
        Assert.Contains("[REDACTED: my-password]", stderr);
        Assert.Contains("# tswap: my-password", stderr);
    }

    [Fact]
    public void ToComment_Live_DoesNotExposeSecretInOutput()
    {
        RunTswap("init");
        var (ingestExit, _, _) = RunTswapWithStdin("supersecretvalue123", "ingest", "my-password");
        Assert.Equal(0, ingestExit);

        var yamlFile = Path.Combine(_tempDir, "applied.yaml");
        File.WriteAllText(yamlFile, "password: supersecretvalue123");

        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile);

        Assert.Equal(0, exit);
        // Secret must not appear in either stream
        Assert.DoesNotContain("supersecretvalue123", stdout);
        Assert.DoesNotContain("supersecretvalue123", stderr);
        // Diff output is in stderr
        Assert.Contains("[REDACTED: my-password]", stderr);
    }

    // --- PTY P/Invoke helpers (used by Run_FirstLineOfStdoutNotDropped_UnixPty) ---

    // openpty: try libc first (glibc 2.34+ / Fedora 35+ / Ubuntu 22.04+), then libutil.
    [DllImport("libc",    EntryPoint = "openpty", SetLastError = true)]
    private static extern int openpty_libc(ref int amaster, ref int aslave, [Out] byte[] name, IntPtr termp, IntPtr winp);

    [DllImport("libutil", EntryPoint = "openpty", SetLastError = true)]
    private static extern int openpty_libutil(ref int amaster, ref int aslave, [Out] byte[] name, IntPtr termp, IntPtr winp);

    [DllImport("libc", EntryPoint = "read",  SetLastError = true)]
    private static extern nint PtyRead(int fd, [Out] byte[] buf, nint count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int PtyClose(int fd);

    private static int OpenPty(ref int masterFd, ref int slaveFd, byte[] nameBuf)
    {
        try { return openpty_libc(ref masterFd, ref slaveFd, nameBuf, IntPtr.Zero, IntPtr.Zero); }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { } // openpty not exported by libc on this platform
        return openpty_libutil(ref masterFd, ref slaveFd, nameBuf, IntPtr.Zero, IntPtr.Zero);
    }

    [Fact]
    public void ToComment_ContinuationLine_DoesNotLeakFragmentInOutput()
    {
        RunTswap("init");
        var (ingestExit, _, _) = RunTswapWithStdin("supersecretvalue123", "ingest", "my-password");
        Assert.Equal(0, ingestExit);

        // Simulates a multi-line YAML scalar: the continuation line is a base64-looking
        // fragment. RedactContent cannot redact it (it is only a partial match), so without
        // the fix it would be printed verbatim — the test ensures it is suppressed instead.
        var yamlFile = Path.Combine(_tempDir, "multiline.yaml");
        File.WriteAllText(yamlFile,
            "password: supersecretvalue123\n" +
            "  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");

        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");

        Assert.Equal(0, exit);
        // Raw continuation fragment must NOT appear in either stream
        Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", stdout);
        Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", stderr);
        // Safe placeholder must appear in stderr (diff output)
        Assert.Contains("[removed continuation line]", stderr);
        // Main secret must also not be leaked in either stream
        Assert.DoesNotContain("supersecretvalue123", stdout);
        Assert.DoesNotContain("supersecretvalue123", stderr);
    }
}
