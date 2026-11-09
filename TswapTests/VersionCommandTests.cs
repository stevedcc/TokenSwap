using System.Text.RegularExpressions;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapTests.Docs;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T18 (#276): <c>tswap --version</c> and <c>tswap version</c>. In process through <see cref="CliHost"/>, the
/// binary's own composition (Program.cs only hands it the real process environment), so the early dispatch is the
/// binary's; <see cref="EndToEndTests"/> checks the same lines on the real binary.
/// </summary>
public sealed class VersionCommandTests
{
    private const string TestKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    /// <summary><c>&lt;Version&gt;</c> in TswapCli/TswapCli.csproj: what <c>--version</c> must print.</summary>
    internal static string CsprojVersion()
    {
        var csproj = File.ReadAllText(Path.Combine(MarkdownLinks.RepoRoot(), "TswapCli", "TswapCli.csproj"));
        var match = Regex.Match(csproj, "<Version>([^<]+)</Version>");
        Assert.True(match.Success, "TswapCli.csproj has no <Version>");
        return match.Groups[1].Value;
    }

    /// <summary>
    /// Runs through <see cref="CliHost"/> with <paramref name="env"/> as the whole process environment, recording every
    /// variable the run asks for in <paramref name="asked"/>.
    /// </summary>
    private static (int Exit, string Out, string Err) Run(Dictionary<string, string?> env, List<string> asked, bool isPrivileged, params string[] args)
    {
        var console = new FakeConsole("");
        var exit = CliHost.Run(args, console, name => { asked.Add(name); return env.GetValueOrDefault(name); },
            isPrivileged, processPath: "/usr/local/bin/tswap");
        return (exit, console.OutText, console.ErrorText);
    }

    /// <summary>The one line, with the platform's line ending trimmed, and nothing after it.</summary>
    private static string SingleLine(string stdout)
    {
        var line = stdout.TrimEnd('\r', '\n');
        Assert.DoesNotContain('\n', line);
        Assert.Equal(line + Environment.NewLine, stdout);
        return line;
    }

    // ------------------------------------------------------------------ contract line 1

    [Theory]
    [InlineData("--version")]
    [InlineData("version")]
    public void Version_PrintsOneLine_TswapAndTheCsprojVersion_AndExitsZero(string form)
    {
        var (exit, stdout, stderr) = Run(new() { ["TSWAP_TEST_KEY"] = TestKeyHex }, [], isPrivileged: false, form);

        Assert.Equal(0, exit);
        Assert.Equal($"tswap {CsprojVersion()}", SingleLine(stdout));
        Assert.Equal("", stderr);
    }

    [Theory]
    [InlineData("0.2.0", "0.2.0")]
    [InlineData("0.2.0+cae3bf0e1d2c", "0.2.0")]
    [InlineData("0.3.0-rc.1", "0.3.0-rc.1")]
    [InlineData("0.3.0-rc.1+cae3bf0e1d2c", "0.3.0-rc.1")]
    public void Display_CutsOnlyBuildMetadata(string informational, string expected)
        => Assert.Equal(expected, VersionCommand.Display(informational));

    // ------------------------------------------------------------------ contract lines 2 and 3

    /// <summary>
    /// Line 2(a): with an empty, unwritable HOME (and no TSWAP_CONFIG_DIR or XDG_CONFIG_HOME) nothing is read or created:
    /// the folder is still empty afterwards and nothing is printed but the version line.
    /// </summary>
    [Theory]
    [InlineData("--version")]
    [InlineData("version")]
    public void Version_WithAnEmptyUnwritableHome_CreatesNothing_AndPrintsOnlyTheLine(string form)
    {
        if (OperatingSystem.IsWindows()) return; // HOME and its mode bits are the Unix inputs

        var home = Path.Combine(Path.GetTempPath(), "tswap-version-home-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(home);
        try
        {
            File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserExecute);

            var (exit, stdout, stderr) = Run(new() { ["HOME"] = home }, [], isPrivileged: false, form);

            Assert.Equal(0, exit);
            Assert.Equal($"tswap {CsprojVersion()}", SingleLine(stdout));
            Assert.Equal("", stderr);
            Assert.Empty(Directory.EnumerateFileSystemEntries(home));
        }
        finally
        {
            File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.Delete(home, true);
        }
    }

    /// <summary>
    /// Lines 2(b) and 3, structurally: the seam is <see cref="CliHost.Run(string[], IConsole, Func{string, string?}, bool, string?)"/>'s
    /// environment function. Every step of startup reads it first: <see cref="CliEnvironment.Create"/> (prefix, config
    /// folder resolver, <c>TSWAP_YUBIKEY_SERIAL</c>, <c>TSWAP_AGENT_SOCK</c>) and <see cref="HardwareServices.ReadTestKey"/>
    /// run before the YubiKey, FIDO2, TPM and Secure Enclave services, the vault store, the agent client and every sudo
    /// check (<see cref="CommandContext"/>, built after them). A version run that never reads the environment has
    /// returned before all of that, privileged or not, whatever SUDO_USER says.
    /// </summary>
    [Theory]
    [InlineData("--version", false)]
    [InlineData("version", false)]
    [InlineData("--version", true)]
    [InlineData("version", true)]
    public void Version_ReturnsBeforeStartupReadsTheEnvironment_SoNoHardwareAgentOrSudoPathIsReached(string form, bool isPrivileged)
    {
        var asked = new List<string>();
        // A sudo environment that would refuse if the config folder were resolved (SUDO_UID doesn't match the user).
        var env = new Dictionary<string, string?>
        {
            ["TSWAP_TEST_KEY"] = TestKeyHex, ["SUDO_USER"] = "nosuchuser-t18", ["SUDO_UID"] = "4294967294",
        };

        var (exit, stdout, stderr) = Run(env, asked, isPrivileged, form);

        Assert.Equal(0, exit);
        Assert.Equal($"tswap {CsprojVersion()}", SingleLine(stdout));
        Assert.Equal("", stderr);
        Assert.Empty(asked);
    }

    /// <summary>The seam's own check: a command that does start up reads the environment through it.</summary>
    [Fact]
    public void TheEnvironmentSeam_RecordsStartup_ForAnyOtherCommand()
    {
        var asked = new List<string>();

        var (exit, _, _) = Run(new() { ["TSWAP_TEST_KEY"] = TestKeyHex }, asked, isPrivileged: false, "prompt-hash");

        Assert.Equal(0, exit);
        Assert.Contains("TSWAP_TEST_KEY", asked);
        Assert.Contains("TSWAP_YUBIKEY_SERIAL", asked);
    }

    // ------------------------------------------------------------------ contract line 5 (pinned before T18)

    /// <summary>
    /// <c>--version</c> after another command is that command's unknown option, as before T18: <c>names</c> ignores an
    /// option it doesn't know, so <c>names --version</c> lists the names exactly as <c>names</c> does.
    /// </summary>
    [Fact]
    public void VersionAfterAnotherCommand_IsThatCommandsUnknownOption_NamesIgnoresIt()
    {
        using var m = new FleetMachine("version-names", SimulatedYubiKeyService.WithKeys(11111111)) { Sudo = false };
        m.Keys.PluggedIn = [11111111];
        m.Ok("", "init", "--yubikey", "--no-password", "--no-recovery");
        m.Ok("", "create", "t18-secret");
        var names = m.Run("", "names");

        var (exit, stdout, stderr) = m.Run("", "names", "--version");

        Assert.Equal(0, exit);
        Assert.Equal(names.Out, stdout);
        Assert.Equal(names.Err, stderr);
        Assert.Contains("t18-secret", stdout);
        Assert.DoesNotContain($"tswap {CsprojVersion()}", stdout);
    }

    // ------------------------------------------------------------------ contract line 6

    [Fact]
    public void Help_ListsTheVersionCommand()
    {
        var (exit, stdout, _) = Run(new() { ["TSWAP_TEST_KEY"] = TestKeyHex }, [], isPrivileged: false, "help");

        Assert.Equal(0, exit);
        Assert.Matches(@"(?m)^  tswap version\s+Print tswap's version", stdout);
    }

    // ------------------------------------------------------------------ contract line 7

    /// <summary>The agent prompt doesn't mention the version command (it is for humans; agents don't need it).</summary>
    [Fact]
    public void AgentPrompt_DoesNotMentionTheVersionCommand()
        => Assert.DoesNotContain("version", Prompt.GetText("tswap"), StringComparison.OrdinalIgnoreCase);
}
