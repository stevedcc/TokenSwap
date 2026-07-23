using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// Unit tests for config-dir resolution and invocation-prefix detection — logic that
/// previously ran inline at the top of Program.cs with no direct coverage. Environment
/// access is injected as delegates, so each branch is testable without touching real
/// env vars or the filesystem.
/// </summary>
public class CliEnvironmentTests
{
    private static string Resolve(
        Dictionary<string, string?> env,
        Func<string, bool>? directoryExists = null,
        Action<string, string>? moveDirectory = null,
        TextWriter? log = null)
        => CliEnvironment.ResolveConfigDir(
            name => env.GetValueOrDefault(name),
            directoryExists ?? (_ => false),
            moveDirectory ?? ((_, _) => { }),
            log ?? TextWriter.Null);

    [Fact]
    public void ConfigDirOverride_WinsOverEverything()
    {
        var dir = Resolve(new() { ["TSWAP_CONFIG_DIR"] = "/custom/dir", ["SUDO_USER"] = "alice" });
        Assert.Equal("/custom/dir", dir);
    }

    [Fact]
    public void SudoUser_ResolvesToInvokingUsersHome()
    {
        if (OperatingSystem.IsWindows()) return; // SUDO_USER handling is Unix-only

        var dir = Resolve(new() { ["SUDO_USER"] = "alice" });

        var expectedHome = OperatingSystem.IsMacOS() ? "/Users/alice" : "/home/alice";
        Assert.Equal(Path.Combine(expectedHome, ".config", "tswap"), dir);
    }

    [Fact]
    public void NoSudoUser_UsesApplicationData()
    {
        var dir = Resolve(new());
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        Assert.Equal(Path.Combine(appData, "tswap"), dir);
    }

    [Fact]
    public void LegacyDir_MigratedOnce_WithLogMessage()
    {
        string? movedFrom = null, movedTo = null;
        var log = new StringWriter();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var legacy = Path.Combine(appData, "tswap-poc");

        var dir = Resolve(new(),
            directoryExists: path => path == legacy, // legacy exists, new dir doesn't
            moveDirectory: (from, to) => { movedFrom = from; movedTo = to; },
            log: log);

        Assert.Equal(legacy, movedFrom);
        Assert.Equal(dir, movedTo);
        Assert.Contains("Migrated config directory", log.ToString());
    }

    [Fact]
    public void LegacyDir_NotMigrated_WhenNewDirExists()
    {
        var moved = false;
        Resolve(new(), directoryExists: _ => true, moveDirectory: (_, _) => moved = true);
        Assert.False(moved);
    }

    [Fact]
    public void LegacyDir_NotMigrated_WhenOverrideSet()
    {
        var moved = false;
        Resolve(new() { ["TSWAP_CONFIG_DIR"] = "/x" },
            directoryExists: _ => true, moveDirectory: (_, _) => moved = true);
        Assert.False(moved);
    }

    [Fact]
    public void DetectInvocationPrefix_NullProcessPath_DefaultsToTswap()
    {
        Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix(null));
    }

    [Fact]
    public void DetectInvocationPrefix_UsesFileNameWithoutExtension()
    {
        Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix("/usr/local/bin/tswap"));
        Assert.Equal("ts", CliEnvironment.DetectInvocationPrefix("/home/u/.local/bin/ts"));
        if (OperatingSystem.IsWindows()) // backslash is a separator only on Windows
            Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix(@"C:\tools\tswap.exe"));
        Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix(
            Path.Combine("some", "dir", OperatingSystem.IsWindows() ? "tswap.exe" : "tswap")));
    }
}
