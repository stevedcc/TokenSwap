using System.Diagnostics;
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

    private (int exitCode, string stdout, string stderr) RunTswap(params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{_projectDir}/tswap.csproj\" -- {string.Join(" ", args)}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.Environment["TSWAP_TEST_KEY"] = _testKeyHex;
        psi.Environment["TSWAP_CONFIG_DIR"] = _tempDir;

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, stdout, stderr);
    }

    private (int exitCode, string stdout, string stderr) RunTswapWithStdin(string stdin, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{_projectDir}/tswap.csproj\" -- {string.Join(" ", args)}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.Environment["TSWAP_TEST_KEY"] = _testKeyHex;
        psi.Environment["TSWAP_CONFIG_DIR"] = _tempDir;

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

    // --- No args ---

    [Fact]
    public void NoArgs_ShowsUsage()
    {
        var (exit, stdout, _) = RunTswap();

        Assert.Equal(1, exit);
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
}
