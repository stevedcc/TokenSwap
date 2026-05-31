using TswapCore;
using Xunit;

namespace TswapTests;

public class InstallScriptTests
{
    // ── Bash script ────────────────────────────────────────────────────────────

    [Fact]
    public void GetBashScript_EmbedsBinaryPath()
    {
        var script = InstallScript.GetBashScript("/home/user/downloads/tswap");
        Assert.Contains("/home/user/downloads/tswap", script);
    }

    [Fact]
    public void GetBashScript_IsShebangBash()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.StartsWith("#!/usr/bin/env bash", script);
    }

    [Fact]
    public void GetBashScript_InstallsToLocalBin()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.Contains("~/.local/bin/tswap", script);
        Assert.Contains("~/.local/bin", script);
    }

    [Fact]
    public void GetBashScript_InstallsToUsrLocalBin()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.Contains("/usr/local/bin/tswap", script);
        Assert.Contains("sudo", script);
    }

    [Fact]
    public void GetBashScript_InstallsSkillMd()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.Contains("~/.agents/skills/tswap", script);
        Assert.Contains("SKILL.md", script);
        // Uses redirect (>) not Out-File; prompt output is UTF-8 on Unix
        Assert.Contains("tswap\" prompt >", script);
    }

    [Fact]
    public void GetBashScript_CreatesClaudeSymlink()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.Contains("~/.claude/skills/tswap", script);
        Assert.Contains("ln -s", script);
    }

    [Fact]
    public void GetBashScript_IsIdempotent_RemovesExistingSymlink()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        // Must remove an existing symlink before creating, so repeated runs don't fail
        Assert.Contains("rm", script);
        Assert.Contains("-L", script); // -L tests for symlink
    }

    [Fact]
    public void GetBashScript_UsesSetEuo()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.Contains("set -euo pipefail", script);
    }

    // ── PowerShell script ──────────────────────────────────────────────────────

    [Fact]
    public void GetPowerShellScript_EmbedsBinaryPath()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\Users\user\Downloads\tswap.exe");
        Assert.Contains(@"C:\Users\user\Downloads\tswap.exe", script);
    }

    [Fact]
    public void GetPowerShellScript_HasNoShebang()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\tmp\tswap.exe");
        Assert.False(script.StartsWith("#!"), "PowerShell script must not start with a shebang");
    }

    [Fact]
    public void GetPowerShellScript_InstallsToWindowsApps()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\tmp\tswap.exe");
        Assert.Contains("WindowsApps", script);
        Assert.Contains("tswap.exe", script);
    }

    [Fact]
    public void GetPowerShellScript_InstallsSkillMdWithUtf8Encoding()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\tmp\tswap.exe");
        Assert.Contains(".agents\\skills\\tswap", script);
        Assert.Contains("SKILL.md", script);
        // Must use Out-File -Encoding utf8, NOT bare > redirection (issue comment requirement)
        Assert.Contains("Out-File -Encoding utf8", script);
        Assert.DoesNotContain("prompt >", script);
    }

    [Fact]
    public void GetPowerShellScript_CreatesClaudeSymlink()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\tmp\tswap.exe");
        Assert.Contains(".claude\\skills", script);
        // Junction or symlink
        Assert.Contains("Junction", script);
    }

    [Fact]
    public void GetPowerShellScript_IsIdempotent_RemovesExistingLink()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\tmp\tswap.exe");
        Assert.Contains("Remove-Item", script);
        Assert.Contains("Test-Path", script);
    }

    [Fact]
    public void GetPowerShellScript_SetsErrorActionPreference()
    {
        var script = InstallScript.GetPowerShellScript(@"C:\tmp\tswap.exe");
        Assert.Contains("ErrorActionPreference", script);
        Assert.Contains("Stop", script);
    }

    // ── GetScript platform dispatch ────────────────────────────────────────────

    [Fact]
    public void GetScript_ReturnsCorrectScriptForCurrentPlatform()
    {
        var script = InstallScript.GetScript("/fake/path/tswap");
        if (OperatingSystem.IsWindows())
        {
            // PowerShell: no shebang, has ErrorActionPreference
            Assert.False(script.StartsWith("#!"));
            Assert.Contains("ErrorActionPreference", script);
        }
        else
        {
            // Bash: has shebang
            Assert.StartsWith("#!/usr/bin/env bash", script);
        }
    }
}
