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
        var start = script.IndexOf("if [ -e /usr/local/libexec/tswap-broker ]", StringComparison.Ordinal);
        Assert.True(start >= 0, "no broker-copy step");
        var block = script[start..script.IndexOf("\nfi", start, StringComparison.Ordinal)];
        Assert.Contains("install_binary \"$BINARY\" /usr/local/libexec/tswap-broker sudo", block);
        Assert.Contains("restorecon -v /usr/local/libexec/tswap-broker", block);
        Assert.True(block.IndexOf("install_binary", StringComparison.Ordinal) < block.IndexOf("restorecon", StringComparison.Ordinal),
            "restorecon must label the new copy, so it runs after it");
    }

    [Fact]
    public void Linux_ReinstallsTheEmbeddedModule_OnlyWhenItIsLoaded_UnderItsOwnName()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap", Cil);
        Assert.Contains("semodule -l", script);
        Assert.Contains("grep -qx tswap-broker", script);
        // semodule names a module after its file: the file must be tswap-broker.cil (a 2026-11-03 router slip
        // installed tswap-broker-b.cil as a second module).
        Assert.Contains("/tswap-broker.cil\"", script);
        Assert.Contains("semodule -i", script);
        Assert.Contains(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Cil)), script);
        // The module first: it carries the file context that restorecon applies to the copy.
        Assert.True(script.IndexOf("semodule -i", StringComparison.Ordinal) < script.IndexOf("restorecon -v", StringComparison.Ordinal));
    }

    [Fact]
    public void Linux_WithoutAnEmbeddedModule_HasNoModuleStep_ButStillRefreshesTheCopy()
    {
        var script = InstallScript.GetBashScript("/tmp/tswap");
        Assert.DoesNotContain("semodule", script);
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
        Assert.Contains("exit 1", script);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

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
