using TswapCli.Commands;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #240: once the macOS installer package has put tswap into <c>/usr/local/bin</c>, <c>tswap installscript</c>
/// run from that installed copy does only the per-user steps (skill, Claude Code symlink, completions): no binary or
/// dylib install and no <c>sudo</c>. Whether the running binary is the installed copy is decided by device and inode
/// (a symlink to it counts; APFS's case-insensitive names don't matter). Every other run prints today's script.
/// </summary>
public sealed class InstallScriptInstalledCopyTests
{
    private static readonly byte[] Dylib = [1, 2, 3, 4, 5];
    private const string Download = "/tmp/tswap-download/tswap";

    private static string RepoFile(params ReadOnlySpan<string> parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private static string PerUser() => InstallScript.GetMacOSScript(InstalledCopy.MacOSInstallPath, Dylib, binaryInstalled: true);

    [Fact]
    public void GetMacOSScript_Default_Unchanged()
    {
        // The v0.2 script, byte for byte, for the same inputs (generated before the per-user variant existed).
        var expected = File.ReadAllText(RepoFile("TswapTests", "Fixtures", "installscript-macos-default.txt"));

        Assert.Equal(expected, InstallScript.GetMacOSScript(Download, Dylib));
        Assert.Equal(expected, InstallScript.GetMacOSScript(Download, Dylib, binaryInstalled: false));
    }

    [Fact]
    public void GetMacOSScript_BinaryInstalled_HasNoInstallBinaryOrSudo()
    {
        var script = PerUser();

        Assert.DoesNotContain("install_binary", script);
        Assert.DoesNotContain("sudo", script);
        Assert.DoesNotContain("Installing tswap binary", script);
        Assert.DoesNotContain("BINARY=", script);
    }

    [Fact]
    public void GetMacOSScript_BinaryInstalled_HasNoDylibBlob()
    {
        var script = PerUser();

        Assert.DoesNotContain(Convert.ToBase64String(Dylib), script);
        Assert.DoesNotContain("libtswapse.dylib", script);
        Assert.DoesNotContain("base64", script);
    }

    [Fact]
    public void GetMacOSScript_BinaryInstalled_StillWritesSkillSymlinkAndCompletions()
    {
        var full = InstallScript.GetMacOSScript(Download, Dylib);
        var perUser = PerUser();

        // The per-user steps are the same text as in the full script (one template), from the skill on.
        var steps = full[full.IndexOf("echo \"==> Installing tswap skill (SKILL.md)...\"", StringComparison.Ordinal)..];
        Assert.EndsWith(steps, perUser);
        Assert.Contains("/usr/local/bin/tswap prompt > \"$HOME/.agents/skills/tswap/SKILL.md\"", perUser);
        Assert.Contains("ln -sfn \"$HOME/.agents/skills/tswap\" \"$HOME/.claude/skills/tswap\"", perUser);
        Assert.Contains("/usr/local/bin/tswap completion bash", perUser);
        Assert.Contains("tswap agent stop", perUser); // the running-agent reminder
    }

    [Fact]
    public void GetMacOSScript_BinaryInstalled_SaysSo()
    {
        var lines = PerUser().Split('\n');

        Assert.Equal("#!/usr/bin/env bash", lines[0]);
        Assert.Equal("echo \"tswap is already installed at /usr/local/bin/tswap; installing the per-user parts only (skill, Claude Code symlink, shell completions)\"",
            lines.First(line => line.StartsWith("echo ", StringComparison.Ordinal)));
    }

    [Fact]
    public void GetMacOSScript_BinaryInstalled_PassesBashSyntaxCheck()
    {
        if (OperatingSystem.IsWindows())
            return;
        var file = Path.Combine(Directory.CreateTempSubdirectory("tswap-peruser-").FullName, "installTswap.sh");
        File.WriteAllText(file, PerUser());
        try
        {
            using var bash = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("bash", ["-n", file]) { RedirectStandardError = true })!;
            var error = bash.StandardError.ReadToEnd();
            bash.WaitForExit();
            Assert.True(bash.ExitCode == 0, error);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(file)!, recursive: true);
        }
    }

    // ---- the rule: the same file by device and inode ----

    [Fact]
    public void InstalledCopy_SameInode_IsInstalled() =>
        Assert.True(InstalledCopy.IsSame(new FileId(16777232, 4242), new FileId(16777232, 4242)));

    [Fact]
    public void InstalledCopy_OtherFile_IsNot()
    {
        Assert.False(InstalledCopy.IsSame(new FileId(16777232, 4242), new FileId(16777232, 4243)));
        Assert.False(InstalledCopy.IsSame(new FileId(16777232, 4242), new FileId(16777233, 4242)));
    }

    [Fact]
    public void InstalledCopy_NoInstalledFile_IsNot() =>
        Assert.False(InstalledCopy.IsSame(new FileId(16777232, 4242), null));

    /// <summary>The real stat: a symlink is its target's file, a copy is another file, a missing path has no id.</summary>
    [Fact]
    public void UnixFileIds_FollowSymlinks()
    {
        if (OperatingSystem.IsWindows())
            return;
        var dir = Directory.CreateTempSubdirectory("tswap-fileid-").FullName;
        try
        {
            var file = Path.Combine(dir, "tswap");
            File.WriteAllText(file, "binary");
            var link = Path.Combine(dir, "link");
            File.CreateSymbolicLink(link, file);
            var copy = Path.Combine(dir, "copy");
            File.Copy(file, copy);
            var ids = new UnixFileIds();

            var original = ids.Of(file);
            Assert.NotNull(original);
            Assert.Equal(original, ids.Of(link));
            Assert.NotEqual(original, ids.Of(copy));
            Assert.Null(ids.Of(Path.Combine(dir, "missing")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---- the command: which script, and the dylib warning ----

    private sealed class FakeFiles(Dictionary<string, FileId> ids, Dictionary<string, byte[]> contents) : IInstalledFiles
    {
        public FileId? Of(string path) => ids.TryGetValue(path, out var id) ? id : null;
        public byte[]? Read(string path) => contents.TryGetValue(path, out var bytes) ? bytes : null;
    }

    private static readonly FileId Installed = new(1, 100);

    private static (string Script, string Error) Generate(string running, Dictionary<string, FileId> ids, Dictionary<string, byte[]> contents)
    {
        var error = new StringWriter();
        var script = InstallScriptCommand.MacOSScript(running, Dylib, new FakeFiles(ids, contents), error);
        return (script, error.ToString());
    }

    [Fact]
    public void Command_RunFromTheInstalledCopy_PrintsThePerUserScript()
    {
        var (script, error) = Generate("/Users/me/bin/tswap",
            new() { ["/Users/me/bin/tswap"] = Installed, [InstalledCopy.MacOSInstallPath] = Installed },
            new() { [InstalledCopy.MacOSDylibPath] = Dylib });

        Assert.Equal(PerUser(), script);
        Assert.Equal("", error);
    }

    [Fact]
    public void Command_RunFromADownload_PrintsTheFullScript()
    {
        var (script, error) = Generate(Download,
            new() { [Download] = new FileId(1, 7), [InstalledCopy.MacOSInstallPath] = Installed },
            new() { [InstalledCopy.MacOSDylibPath] = Dylib });

        Assert.Equal(InstallScript.GetMacOSScript(Download, Dylib), script);
        Assert.Equal("", error);
    }

    [Fact]
    public void Command_InstalledCopyWithADifferentDylib_WarnsOnStderrAndStaysPerUser()
    {
        var (script, error) = Generate(InstalledCopy.MacOSInstallPath,
            new() { [InstalledCopy.MacOSInstallPath] = Installed },
            new() { [InstalledCopy.MacOSDylibPath] = [9, 9, 9] });

        Assert.Equal(PerUser(), script);
        Assert.Contains("/usr/local/bin/libtswapse.dylib is not the one this tswap was built with", error);
        Assert.Contains("reinstall tswap-osx-arm64.pkg, or run installscript from the unpacked release folder", error);
    }

    [Fact]
    public void Command_InstalledCopyWithoutTheDylib_WarnsOnStderr()
    {
        var (script, error) = Generate(InstalledCopy.MacOSInstallPath,
            new() { [InstalledCopy.MacOSInstallPath] = Installed }, []);

        Assert.DoesNotContain("sudo", script);
        // Read() can't tell a missing file from an unreadable one, so the warning names both.
        Assert.Contains("/usr/local/bin/libtswapse.dylib is missing or unreadable", error);
    }
}
