using System.Diagnostics;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Upgrading over a running tswap (an unlock agent, a broker) and the broker's SELinux pieces (owner, 2026-11-03,
/// after the #224 router test): binaries are replaced by rename, never overwritten in place; on Linux the broker's
/// labelled copy and its module follow the binary; a running agent or broker is named, never restarted.
/// </summary>
public class InstallScriptUpgradeTests
{
    private const string Cil = "(type tswap_broker_t)\n; a comment with 'quotes' and $dollars\n";

    // ── Every generated bash script is valid bash ─────────────────────────────

    [Fact]
    public void TheBashScripts_PassBashSyntaxCheck()
    {
        if (OperatingSystem.IsWindows())
            return; // no bash
        foreach (var script in new[] { InstallScript.GetBashScript("/tmp/tswap", Cil), InstallScript.GetBashScript("/tmp/tswap"),
                     InstallScript.GetMacOSScript("/tmp/tswap", [1, 2, 3]) })
        {
            var (exit, error) = Bash(["-n"], script);
            Assert.True(exit == 0, $"bash -n failed: {error}");
        }
    }

    // ── Replacing a binary that is running ────────────────────────────────────

    [Fact]
    public void InstallBinary_ReplacesARunningBinary_AndTheRunningProcessKeepsGoing()
    {
        // What install_binary must do. On Linux `cp -f` already survives a running target (it unlinks and
        // recreates on ETXTBSY), so this pins the function, not a Linux regression; the hazard it removes is
        // macOS's in-place rewrite of a running binary (and the Secure Enclave library), which CI can't provoke.
        if (!OperatingSystem.IsLinux())
            return;
        var dir = Directory.CreateTempSubdirectory("tswap-install-").FullName;
        try
        {
            var target = Path.Combine(dir, "tswap");
            File.Copy("/usr/bin/sleep", target);
            using var running = Process.Start(new ProcessStartInfo(target, "30") { UseShellExecute = false })!;
            var source = Path.Combine(dir, "new-tswap");
            File.WriteAllText(source, "#!/bin/sh\necho new\n");

            // The function exactly as the Linux script defines it, then one call (no sudo).
            var function = FunctionText(InstallScript.GetBashScript("/tmp/tswap"), "install_binary");
            var (exit, error) = Bash(["-c", function + $"\ninstall_binary '{source}' '{target}'"], "");

            Assert.True(exit == 0, $"install_binary failed: {error}");
            Assert.Equal("#!/bin/sh\necho new\n", File.ReadAllText(target));
            Assert.False(running.HasExited, "the running process was killed");
            Assert.Empty(Directory.GetFiles(dir, "tswap.new.*")); // no temp file left
            running.Kill();
            running.WaitForExit();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void TheScripts_NeverOverwriteAnInstalledBinaryInPlace()
    {
        foreach (var script in new[] { InstallScript.GetBashScript("/tmp/tswap", Cil), InstallScript.GetMacOSScript("/tmp/tswap", [1]) })
        {
            Assert.DoesNotContain("cp -f \"$BINARY\" /usr/local/bin/tswap", script);
            Assert.DoesNotContain("cp -f \"$BINARY\" \"$HOME/.local/bin/tswap\"", script);
            Assert.DoesNotContain("sudo tee /usr/local/bin/libtswapse.dylib", script);
            Assert.Contains("install_binary \"$BINARY\"", script);
        }
    }

    // ── Linux: the broker's labelled copy and module ──────────────────────────

    [Fact]
    public void Linux_RefreshesTheBrokerCopy_OnlyWhenItExists_ThenRestoresItsLabel()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap", Cil);
        var start = script.IndexOf("if [ -e /usr/local/libexec/tswap-broker ]; then\n", StringComparison.Ordinal);
        Assert.True(start >= 0, "no broker-copy step");
        var block = script[start..script.IndexOf("\nfi", start, StringComparison.Ordinal)];
        Assert.Contains("install_binary \"$BINARY\" /usr/local/libexec/tswap-broker sudo", block);
        Assert.Contains("\"$RESTORECON\" -v /usr/local/libexec/tswap-broker", block);
        Assert.Contains("restorecon not found", block); // never a silent unlabelled copy
        Assert.True(block.IndexOf("install_binary", StringComparison.Ordinal) < block.IndexOf("\"$RESTORECON\"", StringComparison.Ordinal),
            "restorecon must label the new copy, so it runs after it");
    }

    [Fact]
    public void Linux_ReinstallsTheEmbeddedModule_OnlyWhenItIsLoaded_UnderItsOwnName()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap", Cil);
        Assert.Contains("\"$SEMODULE\" -l", script);
        Assert.Contains("grep -Ex 'tswap-broker(\\.pp)?'", script);
        // semodule names a module after its file: the file must be tswap-broker.cil (a 2026-11-03 router slip
        // installed tswap-broker-b.cil as a second module).
        Assert.Contains("/tswap-broker.cil\"", script);
        Assert.Contains("\"$SEMODULE\" -i", script);
        Assert.Contains(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Cil)), script);
        // The module first: it carries the file context that restorecon applies to the copy.
        Assert.True(script.IndexOf("\"$SEMODULE\" -i", StringComparison.Ordinal) < script.IndexOf("\"$RESTORECON\" -v", StringComparison.Ordinal));
    }

    [Fact]
    public void Linux_WithoutAnEmbeddedModule_HasNoModuleStep_ButStillRefreshesTheCopy()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.DoesNotContain("-i \"$CIL_DIR", script);
        Assert.DoesNotContain("tswap-broker.cil", script);
        Assert.Contains("/usr/local/libexec/tswap-broker", script);
    }

    [Fact]
    public void Linux_NamesARunningBrokerOrAgent_AndRestartsNothing()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap", Cil);
        Assert.Contains("broker serve", script);
        Assert.Contains("agent serve", script);
        Assert.Contains("systemctl --user restart tswap-broker", script);
        Assert.Contains("tswap agent stop", script);
        Assert.DoesNotMatch(@"\b(?:p?kill|killall)\b", script); // names them, restarts or kills nothing ("skill" is fine)
    }

    [Fact]
    public void TheBrokerEmbeddedModule_IsTheContribFile()
    {
        var resource = InstallScript.BrokerSelinuxModule();
        Assert.NotNull(resource);
        var contrib = File.ReadAllText(Path.Combine(RepoRoot(), "contrib", "selinux", "tswap-broker.cil"));
        Assert.Equal(contrib, resource);
    }

    // ── macOS and Windows: no broker step; the agent is named ─────────────────

    [Fact]
    public void MacOS_HasNoBrokerOrSelinuxStep_ButNamesARunningAgent()
    {
        var script = InstallScript.GetMacOSScript("/tmp/tswap", [1]);
        Assert.DoesNotContain("libexec", script);
        Assert.DoesNotContain("semodule", script);
        Assert.DoesNotContain("restorecon", script);
        Assert.Contains("agent serve", script);
        Assert.Contains("tswap agent stop", script);
    }

    [Fact]
    public void Windows_StopsBeforeCopying_WhenAnAgentRuns()
    {
        var script = InstallScript.GetPowerShellScript("C:\\tswap.exe");
        Assert.DoesNotContain("semodule", script);
        var check = script.IndexOf("agent\\s+serve", StringComparison.Ordinal);
        Assert.True(check >= 0, "no running-agent check");
        Assert.True(check < script.IndexOf("Copy-Item", StringComparison.Ordinal), "the check must come before the copy (a running exe is locked)");
        Assert.Contains("tswap agent stop", script);
        Assert.Contains("throw \"Stop it first", script); // throw, not exit: a dot-sourced script mustn't close the shell
        Assert.DoesNotContain("exit 1", script);
    }

    // ── Behaviour of the generated pieces ─────────────────────────────────────

    [Theory]
    [InlineData("broker", "/usr/local/libexec/tswap-broker broker serve", true)]
    [InlineData("broker", "/usr/local/bin/tswap broker serve", true)]
    [InlineData("broker", "tswap broker socket add lane1", false)]
    [InlineData("broker", "vim notes/broker serve", false)]
    [InlineData("agent", "/usr/local/bin/tswap agent serve --timeout 8h", true)]
    [InlineData("agent", "/home/u/.local/bin/tswap agent serve", true)]
    [InlineData("agent", "tswap agent stop", false)]
    [InlineData("agent", "tswap agent start", false)]
    public void TheRunningProcessPatterns_MatchRealCommandLines(string kind, string commandLine, bool matches)
    {
        Assert.Equal(matches, System.Text.RegularExpressions.Regex.IsMatch(commandLine, PgrepPattern(InstallScript.GetBashScript("/tmp/tswap", Cil), kind)));
    }

    [Fact]
    public void TheBrokerPattern_MatchesTheShippedUnitsExecStart()
    {
        var unit = File.ReadAllLines(Path.Combine(RepoRoot(), "contrib", "systemd", "tswap-broker.service"));
        var execStart = unit.Single(l => l.StartsWith("ExecStart=", StringComparison.Ordinal))["ExecStart=".Length..];
        Assert.Matches(PgrepPattern(InstallScript.GetBashScript("/tmp/tswap", Cil), "broker"), execStart);
    }

    [Fact]
    public void TheModuleInTheGeneratedScript_DecodesToTheContribFile()
    {
        var module = InstallScript.BrokerSelinuxModule()!;
        var script = InstallScript.GetBashScript("/tmp/tswap", module);
        var payload = System.Text.RegularExpressions.Regex.Match(script, "echo \"([A-Za-z0-9+/=]+)\" \\| base64 -d > \"\\$CIL_DIR/tswap-broker.cil\"");
        Assert.True(payload.Success, "no module payload in the script");
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload.Groups[1].Value));
        Assert.Equal(File.ReadAllText(Path.Combine(RepoRoot(), "contrib", "selinux", "tswap-broker.cil")), decoded);
    }

    [Fact]
    public void InstallBinary_WorksUnderTheScriptsOwnShellOptions_AndLeavesNoTemp()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var dir = Directory.CreateTempSubdirectory("tswap-install-").FullName;
        try
        {
            var source = Path.Combine(dir, "src");
            File.WriteAllText(source, "new");
            var target = Path.Combine(dir, "sub", "tswap");
            var (exit, error) = Bash(["-c", "set -euo pipefail\n" + Prelude(InstallScript.GetBashScript("/tmp/tswap")) + $"\ninstall_binary '{source}' '{target}'"], "");

            Assert.True(exit == 0, $"failed: {error}");
            Assert.Equal("new", File.ReadAllText(target));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead |
                         UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute, File.GetUnixFileMode(target));
            Assert.Empty(Directory.GetFiles(Path.Combine(dir, "sub"), "tswap.new.*"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AStopBetweenTheModuleAndTheCopy_SaysToRunAgain_AndTemporaryFilesAreRemoved()
    {
        if (OperatingSystem.IsWindows())
            return;
        var dir = Directory.CreateTempSubdirectory("tswap-install-").FullName;
        try
        {
            var leftover = Path.Combine(dir, "leftover");
            File.WriteAllText(leftover, "x");
            var (exit, error) = Bash(["-c", "set -euo pipefail\n" + Prelude(InstallScript.GetBashScript("/tmp/tswap")) +
                                           $"\nCLEANUP+=('{leftover}')\nBROKER_PENDING=1\nfalse"], "");

            Assert.NotEqual(0, exit);
            Assert.Contains("they must match. Run this script again.", error);
            Assert.False(File.Exists(leftover), "the trap didn't remove the temporary file");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ASuccessfulRun_SaysNothingAboutAMismatch()
    {
        if (OperatingSystem.IsWindows())
            return;
        var (exit, error) = Bash(["-c", "set -euo pipefail\n" + Prelude(InstallScript.GetBashScript("/tmp/tswap")) + "\nBROKER_PENDING=\"\"\ntrue"], "");
        Assert.Equal(0, exit);
        Assert.DoesNotContain("must match", error);
    }

    [Fact]
    public void ThePowerShellScript_Parses()
    {
        if (!OperatingSystem.IsWindows())
            return; // Windows PowerShell ships with every Windows runner
        var path = Path.Combine(Path.GetTempPath(), $"tswap-install-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(path, InstallScript.GetPowerShellScript("C:\\tswap.exe"));
        try
        {
            var psi = new ProcessStartInfo("powershell") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-Command",
                         $"$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$null, [ref]$e); if ($e) {{ $e | ForEach-Object {{ $_.ToString() }}; exit 1 }}" })
                psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, $"PowerShell parse errors: {output}");
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// <summary>The pgrep -f pattern the Linux script uses for a running broker or agent.</summary>
    private static string PgrepPattern(string script, string kind)
    {
        var m = System.Text.RegularExpressions.Regex.Match(script, $"pgrep [^\\n]*-f '([^']*{kind} serve)'");
        Assert.True(m.Success, $"no pgrep for {kind}");
        return m.Groups[1].Value;
    }

    /// <summary>The script's shared prelude: cleanup trap and install_binary, as generated.</summary>
    private static string Prelude(string script)
    {
        var start = script.IndexOf("# Temporary files of this run", StringComparison.Ordinal);
        Assert.True(start >= 0, "no prelude");
        var function = script.IndexOf("install_binary() {", start, StringComparison.Ordinal);
        var end = script.IndexOf("\n}", function, StringComparison.Ordinal);
        return script[start..(end + 2)];
    }

    private static string FunctionText(string script, string name)
    {
        var start = script.IndexOf(name + "() {", StringComparison.Ordinal);
        Assert.True(start >= 0, $"no function {name} in the script");
        var end = script.IndexOf("\n}", start, StringComparison.Ordinal);
        return script[start..(end + 2)];
    }

    private static (int Exit, string Error) Bash(string[] args, string stdin)
    {
        var psi = new ProcessStartInfo("bash") { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardError = true };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.StandardInput.Write(stdin);
        p.StandardInput.Close();
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, error);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "TokenSwap.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }
}
