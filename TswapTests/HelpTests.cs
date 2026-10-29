using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #177: `--help` / `-h` print usage and never run the command. Before, `tswap init
/// --help` fell through to a YubiKey initialisation and `tswap --help` was "Unknown command".
/// In-process through CliRunner, like <see cref="CommandTests"/>.
/// </summary>
public class HelpTests : IDisposable
{
    private readonly string _tempDir;
    private readonly byte[] _testKey =
        Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");

    public HelpTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-help-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private (int exitCode, string stdout, string stderr) Run(bool sudoBypass, params string[] args)
    {
        var console = new FakeConsole("");
        var env = new CliEnvironment
        {
            Prefix = "tswap",
            ConfigDir = _tempDir,
            Verbose = false,
            CommandArgs = args,
        };
        var storage = new Storage(_tempDir);
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: _testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, _testKey, SudoBypass: sudoBypass);

        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    private bool VaultExists => File.Exists(Path.Combine(_tempDir, "config.json"));

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public void InitHelp_PrintsUsage_AndDoesNotInitialise(string flag)
    {
        var (exit, stdout, stderr) = Run(sudoBypass: true, "init", flag);

        Assert.True(exit == 0, $"exit {exit}: {stdout}{stderr}");
        Assert.Contains(new TswapCli.Commands.InitCommand().HelpUsage, stdout);
        Assert.False(VaultExists, "init --help must not create a vault");
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("help")]
    public void TopLevelHelp_PrintsTheHelpScreen(string arg)
    {
        var (exit, stdout, stderr) = Run(sudoBypass: true, arg);

        Assert.True(exit == 0, $"exit {exit}: {stdout}{stderr}");
        Assert.Contains("Usage:", stdout);
        Assert.Contains("get <name>", stdout);
    }

    [Fact]
    public void GetHelp_NeedsNeitherSudoNorAVault()
    {
        var (exit, stdout, stderr) = Run(sudoBypass: false, "get", "--help");

        Assert.True(exit == 0, $"exit {exit}: {stdout}{stderr}");
        Assert.Contains("get <name>", stdout);
        Assert.DoesNotContain("sudo", stderr);
        Assert.DoesNotContain("Not initialized", stderr);
    }

    [Fact]
    public void FlagAmongOptionsBeforeAnyPositional_PrintsUsage()
    {
        var (exit, stdout, _) = Run(sudoBypass: true, "init", "--tpm", "--help");

        Assert.Equal(0, exit);
        Assert.Contains(new TswapCli.Commands.InitCommand().HelpUsage, stdout);
        Assert.False(VaultExists);
    }

    [Fact]
    public void DashHAfterAPositional_IsAValue_NotHelp()
    {
        // Reviewer finding: `burn leaked-key -h` must burn (reason "-h"), not print usage and
        // exit 0 with the secret unburned.
        Run(sudoBypass: true, "init");
        Run(sudoBypass: true, "create", "leaked-key");

        var (exit, stdout, stderr) = Run(sudoBypass: true, "burn", "leaked-key", "-h");
        Assert.True(exit == 0, $"exit {exit}: {stdout}{stderr}");
        Assert.DoesNotContain("burn <name> [reason]", stdout);

        var (_, burned, _) = Run(sudoBypass: true, "burned");
        Assert.Contains("leaked-key", burned);
    }

    [Fact]
    public void RunHelp_DirectlyAfterRun_PrintsUsage()
    {
        var (exit, stdout, _) = Run(sudoBypass: true, "run", "--help");

        Assert.Equal(0, exit);
        Assert.Contains("run <cmd> [args...]", stdout);
    }

    [Fact]
    public void RunChildCommandHelp_GoesToTheChild()
    {
        // Exit code 7 can only come from the child: a script that exits 7, given `--help` and a
        // token (run needs one; #105 refuses inline `sh -c` code). Printing run's usage would
        // exit 0, a vault or validation error 1.
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // POSIX sh only (until #181: reported as Passed on Windows)
        Run(sudoBypass: true, "init");
        Run(sudoBypass: true, "create", "child-token");
        var script = Path.Combine(_tempDir, "exit7.sh");
        File.WriteAllText(script, "exit 7\n");
        var (exit, stdout, stderr) = Run(sudoBypass: true, "run", "sh", script, "--help", "{{child-token}}");

        Assert.True(exit == 7, $"exit {exit}: {stdout}{stderr}");
        Assert.DoesNotContain("run <cmd> [args...]", stdout);
    }
}
