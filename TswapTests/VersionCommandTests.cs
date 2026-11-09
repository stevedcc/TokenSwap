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
    /// What this (development) build's <c>--version</c> reports (owner, 2026-11-09): <c>&lt;Version&gt;-pre-&lt;first 7 of
    /// HEAD&gt;</c>, the commit the SDK embedded when it built the tests' tswap; <c>&lt;Version&gt;-pre</c> where git
    /// can't name one. Only a release build (<c>-p:TswapReleaseBuild=true</c>) reports the plain Version.
    /// </summary>
    internal static string ExpectedVersion()
    {
        var head = GitHead();
        return head is null ? $"{CsprojVersion()}-pre" : $"{CsprojVersion()}-pre-{head[..7]}";
    }

    private static string? GitHead()
    {
        var psi = new System.Diagnostics.ProcessStartInfo("git", ["rev-parse", "HEAD"])
        {
            WorkingDirectory = MarkdownLinks.RepoRoot(), RedirectStandardOutput = true, RedirectStandardError = true,
        };
        try
        {
            using var git = System.Diagnostics.Process.Start(psi)!;
            var sha = git.StandardOutput.ReadToEnd().Trim();
            git.StandardError.ReadToEnd();
            git.WaitForExit();
            return git.ExitCode == 0 && sha.Length == 40 ? sha : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null; // no git on PATH
        }
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
    [InlineData("--VERSION")]
    [InlineData("VERSION")]
    public void Version_PrintsOneLine_TswapAndTheCsprojVersion_AndExitsZero(string form)
    {
        var (exit, stdout, stderr) = Run(new() { ["TSWAP_TEST_KEY"] = TestKeyHex }, [], isPrivileged: false, form);

        Assert.Equal(0, exit);
        Assert.Equal($"tswap {ExpectedVersion()}", SingleLine(stdout));
        Assert.Equal("", stderr);
    }

    /// <summary>
    /// Owner, 2026-11-09: a release build reports the Version (build metadata cut, a prerelease suffix kept); every other
    /// build adds <c>-pre-</c> and the first 7 hex characters of the commit the SDK embeds (<c>+&lt;40-hex sha&gt;</c>),
    /// or only <c>-pre</c> when the metadata is no commit (no git when it was built).
    /// </summary>
    [Theory]
    [InlineData("0.2.0+cae3bf0695b365f5f98d59653fef7c02bcfafb77", true, "0.2.0")]
    [InlineData("0.2.0+cae3bf0695b365f5f98d59653fef7c02bcfafb77", false, "0.2.0-pre-cae3bf0")]
    [InlineData("0.3.0-rc.1+cae3bf0695b365f5f98d59653fef7c02bcfafb77", true, "0.3.0-rc.1")]
    [InlineData("0.3.0-rc.1+cae3bf0695b365f5f98d59653fef7c02bcfafb77", false, "0.3.0-rc.1-pre-cae3bf0")]
    [InlineData("0.2.0", true, "0.2.0")]
    [InlineData("0.2.0", false, "0.2.0-pre")]
    [InlineData("0.3.0-rc.1", false, "0.3.0-rc.1-pre")]
    [InlineData("0.2.0+", false, "0.2.0-pre")]
    [InlineData("0.2.0+cae3bf", false, "0.2.0-pre")]
    [InlineData("0.2.0+local.build", false, "0.2.0-pre")]
    [InlineData("0.2.0+cae3bfz695b365f5f98d59653fef7c02bcfafb77", false, "0.2.0-pre")]
    public void Display_ReleaseBuildIsTheVersion_OtherBuildsArePreWithTheCommit(string informational, bool releaseBuild, string expected)
        => Assert.Equal(expected, VersionCommand.Display(informational, releaseBuild));

    /// <summary>The tests' tswap is built without <c>TswapReleaseBuild</c>, so it is a development build.</summary>
    [Fact]
    public void TheTestsBuild_IsNotAReleaseBuild()
        => Assert.False(VersionCommand.IsReleaseBuild);

    /// <summary>
    /// The flag is compile-time: <c>-p:TswapReleaseBuild=true</c> (release.yml on a tag push) defines the
    /// <c>TSWAP_RELEASE_BUILD</c> compilation symbol that <see cref="VersionCommand.IsReleaseBuild"/> is compiled from;
    /// without it, or with any other value, the symbol is absent. Evaluated with MSBuild, nothing built.
    /// </summary>
    [Theory]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData("false", false)]
    [InlineData(null, false)]
    public void ReleaseBuildProperty_DefinesTheCompileTimeSymbol_OnlyWhenTrue(string? value, bool defined)
    {
        string[] args = ["msbuild", Path.Combine(MarkdownLinks.RepoRoot(), "TswapCli", "TswapCli.csproj"), "-getProperty:DefineConstants", "-p:Configuration=Release"];
        if (value is not null)
            args = [.. args, $"-p:TswapReleaseBuild={value}"];
        var psi = new System.Diagnostics.ProcessStartInfo("dotnet", args) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.Environment.Remove("TswapReleaseBuild"); // MSBuild would read an environment variable of that name as the property
        using var msbuild = System.Diagnostics.Process.Start(psi)!;
        var stdout = msbuild.StandardOutput.ReadToEnd();
        var stderr = msbuild.StandardError.ReadToEnd();
        msbuild.WaitForExit();

        Assert.True(msbuild.ExitCode == 0, stdout + stderr);
        Assert.Equal(defined, stdout.Trim().Split(';').Contains("TSWAP_RELEASE_BUILD"));
        // ... and it is the symbol IsReleaseBuild is compiled from.
        var source = File.ReadAllText(Path.Combine(MarkdownLinks.RepoRoot(), "TswapCli", "Commands", "VersionCommand.cs"));
        Assert.Contains("#if TSWAP_RELEASE_BUILD\n        true;\n#else\n        false;\n#endif", source.Replace("\r\n", "\n"));
    }

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
            Assert.Equal($"tswap {ExpectedVersion()}", SingleLine(stdout));
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
    [InlineData("--VERSION", false)]
    [InlineData("VERSION", true)]
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
        Assert.Equal($"tswap {ExpectedVersion()}", SingleLine(stdout));
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

    /// <summary>
    /// Review F2: <c>version --help</c> and <c>--version --help</c> are the CLI-wide #177 rule (a command's usage, exit 0),
    /// not the extra-argument usage error. Through the registry, so through startup.
    /// </summary>
    [Theory]
    [InlineData("version", "--help")]
    [InlineData("version", "-h")]
    [InlineData("--version", "--help")]
    public void VersionHelp_PrintsItsUsage_AndExitsZero(params string[] args)
    {
        var (exit, stdout, stderr) = Run(new() { ["TSWAP_TEST_KEY"] = TestKeyHex }, [], isPrivileged: false, args);

        Assert.Equal(0, exit);
        Assert.Equal($"Usage: tswap version{Environment.NewLine}{Environment.NewLine}{new VersionCommand().Description}{Environment.NewLine}", stdout);
        Assert.Equal("", stderr);
    }

    /// <summary>
    /// A global flag before it (<c>tswap -v version</c>) goes through startup and the registry, and prints the line last
    /// (in test mode <c>-v</c> first prints its own "[TEST MODE]" line, as for every command).
    /// </summary>
    [Theory]
    [InlineData("-v", "version")]
    [InlineData("--verbose", "--version")]
    public void Version_AfterAGlobalFlag_PrintsTheLine(params string[] args)
    {
        var (exit, stdout, _) = Run(new() { ["TSWAP_TEST_KEY"] = TestKeyHex }, [], isPrivileged: false, args);

        Assert.Equal(0, exit);
        Assert.EndsWith($"{Environment.NewLine}tswap {ExpectedVersion()}{Environment.NewLine}", stdout);
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
        Assert.DoesNotContain($"tswap {CsprojVersion()}", stdout); // the plain Version is a prefix of the -pre form
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
