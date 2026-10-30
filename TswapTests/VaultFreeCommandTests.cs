using TswapCli;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T7 item 3 (#180): commands that need no vault work without a home folder. They run
/// through <see cref="CliHost"/>, the binary's own composition (Program.cs only hands it the real
/// process environment), with an environment that has no HOME and no TSWAP_CONFIG_DIR, so the
/// config folder cannot be resolved: only a command that needs a vault may try.
/// </summary>
public class VaultFreeCommandTests
{
    private const string TestKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private static (int Exit, string Out, string Err) Run(Dictionary<string, string?> env, params string[] args)
    {
        env["TSWAP_TEST_KEY"] = TestKeyHex; // never real hardware, even for a command that would reach it
        var console = new FakeConsole("");
        var exit = CliHost.Run(args, console, name => env.GetValueOrDefault(name), isPrivileged: false, processPath: "/usr/local/bin/tswap");
        return (exit, console.OutText, console.ErrorText);
    }

    public static TheoryData<string[]> VaultFreeCommandLines =>
    [
        ["--help"],
        ["-h"],
        ["help"],
        ["init", "--help"],
        ["names", "--help"],
        ["get", "--help"],
        ["prompt"],
        ["prompt-hash"],
        ["completion", "bash"],
        ["installscript"],
        ["-v", "--help"],
    ];

    [Theory]
    [MemberData(nameof(VaultFreeCommandLines))]
    public void VaultFreeCommand_WorksWithoutAHomeFolder(string[] args)
    {
        if (OperatingSystem.IsWindows()) return; // HOME/XDG are the Unix inputs (APPDATA on Windows)

        var (exit, stdout, stderr) = Run(new(), args);

        Assert.True(exit == 0, $"'{string.Join(' ', args)}' exit {exit}: {stderr}");
        Assert.NotEqual("", stdout.Trim());
        Assert.DoesNotContain("config folder", stderr);
    }

    // The marker that keeps the list above honest: every command marked as needing no vault is
    // one of these, and every other command needs one.
    [Fact]
    public void NeedsVaultMarker_IsFalseExactlyForTheVaultFreeCommands()
    {
        var vaultFree = CommandRegistry.All.Where(c => !c.NeedsVault).Select(c => c.Name).Order().ToArray();

        Assert.Equal(["completion", "installscript", "prompt", "prompt-hash"], vaultFree);
    }

    [Fact]
    public void EveryVaultFreeCommand_WorksWithoutAHomeFolder()
    {
        if (OperatingSystem.IsWindows()) return;

        foreach (var command in CommandRegistry.All.Where(c => !c.NeedsVault))
        {
            string[] args = command.Name == "completion" ? [command.Name, "bash"] : [command.Name];
            var (exit, _, stderr) = Run(new(), args);
            Assert.True(exit == 0, $"{command.Name}: exit {exit}: {stderr}");
        }
    }

    [Fact]
    public void VaultCommand_WithoutAHomeFolder_SaysItCannotDetermineTheConfigFolder()
    {
        if (OperatingSystem.IsWindows()) return;

        var (exit, _, stderr) = Run(new(), "names");

        Assert.Equal(1, exit);
        Assert.Contains("Cannot determine the config folder", stderr);
        Assert.Contains("TSWAP_CONFIG_DIR", stderr);
    }

    // XDG Base Directory spec (#180's comment): a relative XDG_CONFIG_HOME is ignored.
    [Fact]
    public void RelativeXdgConfigHome_FallsBackToHomeDotConfig()
    {
        if (!OperatingSystem.IsLinux()) return; // macOS and Windows take .NET's folder (not XDG)

        var dir = CliEnvironment.ApplicationDataDir(name => name switch
        {
            "XDG_CONFIG_HOME" => "relative/config",
            "HOME" => "/home/alice",
            _ => null,
        });

        Assert.Equal("/home/alice/.config", dir);
    }

    [Fact]
    public void AbsoluteXdgConfigHome_IsUsed()
    {
        if (!OperatingSystem.IsLinux()) return;

        var dir = CliEnvironment.ApplicationDataDir(name => name switch
        {
            "XDG_CONFIG_HOME" => "/srv/cfg",
            "HOME" => "/home/alice",
            _ => null,
        });

        Assert.Equal("/srv/cfg", dir);
    }

    [Fact]
    public void RelativeXdgConfigHome_WithoutHome_CannotDetermine_NamingXdg()
    {
        if (!OperatingSystem.IsLinux()) return;

        var (exit, _, stderr) = Run(new() { ["XDG_CONFIG_HOME"] = "relative/config" }, "names");

        Assert.Equal(1, exit);
        Assert.Contains("Cannot determine the config folder", stderr);
        Assert.Contains("XDG_CONFIG_HOME", stderr);
    }

    // With the folder resolvable, a vault command reaches the vault through the same host.
    [Fact]
    public void VaultCommand_WithTswapConfigDir_RunsThroughTheHost()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-host-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            var env = new Dictionary<string, string?> { ["TSWAP_CONFIG_DIR"] = dir };
            Assert.Equal(0, Run(env, "init").Exit);
            Assert.Equal(0, Run(env, "create", "host-secret").Exit);

            var (exit, stdout, stderr) = Run(env, "names");

            Assert.True(exit == 0, stderr);
            Assert.Contains("host-secret", stdout);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }
}
