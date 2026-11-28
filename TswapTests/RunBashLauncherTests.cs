using System.Runtime.InteropServices;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T64 Task 3 (#411): <c>run</c> applies <see cref="Validation.BashLauncherRefusal"/> before the vault is unlocked
/// (after the blocklist and file-token checks) and again after substitution, where the refusal names the token, never
/// the word. In process on every OS, with the harness of <see cref="RunMsysTargetTests"/>: the OS from
/// <see cref="CommandContext.Os"/>, the machine from a fake <see cref="MsysTarget.Probe"/>, the child a
/// <see cref="RecordingPty"/>.
/// </summary>
public sealed class RunBashLauncherTests : IDisposable
{
    private const string GitBash = @"C:\Program Files\Git\bin\bash.exe";
    private const string Value = "a\\b\"c";

    private readonly FleetMachine _m = new("run-bash-launcher", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();
    private readonly string _work;

    public RunBashLauncherTests()
    {
        InitRecordVault(_m);
        _work = Path.Combine(_m.Dir, "work");
        Directory.CreateDirectory(_work);
        _m.CurrentDirectory = () => _work;
    }

    public void Dispose() => _m.Dispose();

    private static MsysTarget.Probe WslProbe() => MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"]);

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    /// <summary>The setup's secrets, then the YubiKey's challenge log cleared, so a run's own challenges can be told apart.</summary>
    private void Secrets(params (string Name, string Value)[] secrets)
    {
        foreach (var (name, value) in secrets)
            _m.Ok(value, "ingest", name);
        _m.Keys.Challenges.Clear();
    }

    private (int Exit, string Out, string Err) Run(OSPlatform os, MsysTarget.Probe? probe, params string[] args)
    {
        _m.Os = os;
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty, MsysProbe = () => probe };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    private void AssertRefusedBeforeUnlock(int exit, string stdout, string stderr, string reason, bool windows)
    {
        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Equal(ErrorLine(reason + "\n" + RunCommand.ViewSecretLine(windows)), stderr);
        Assert.DoesNotContain(Value, stdout);
        Assert.DoesNotContain(Value, stderr);
        Assert.Empty(_m.Keys.Challenges); // no key asked
    }

    [Fact]
    public void WslBash_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "bash", "./capture.sh", "{{pw}}");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, BashLauncherRefusalTests.WindowsReason, windows: true);
    }

    [Fact]
    public void WslBash_WithTheTokenOnlyInEnv_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "--env", "PW={{pw}}", "--", "bash", "./capture.sh");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, BashLauncherRefusalTests.WindowsReason, windows: true);
    }

    [Fact]
    public void WslBashBehindARunner_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "uv", "run", "bash.exe", "./capture.sh", "{{pw}}");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, BashLauncherRefusalTests.WindowsReason, windows: true);
    }

    [Fact]
    public void GitBashByItsPath_StartsAsBefore()
    {
        Secrets(("pw", Value));

        var (exit, _, err) = Run(OSPlatform.Windows, WslProbe(), GitBash, "./capture.sh", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal([GitBash], _pty.Argv!);
        Assert.Equal("\"./capture.sh\" \"a\\\\b\\\"c\"", _pty.Options!.WindowsArguments);
    }

    [Fact]
    public void AValueThatSaysBash_AsAnArgument_Starts()
    {
        Secrets(("pw", "bash"));

        var (exit, _, err) = Run(OSPlatform.Windows, WslProbe(), "tool", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["tool", "bash"], _pty.Argv!);
    }

    [Fact]
    public void TheFileTokenRefusal_ComesFirst()
    {
        File.WriteAllText(Path.Combine(_work, "values.yaml"), "db:\n  password: \"\"  # tswap: pw\n  user: app\n");
        Secrets(("pw", Value));

        var (exit, _, stderr) = Run(OSPlatform.Windows, WslProbe(), "bash", "{{@values.yaml}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("'bash' is a shell or interpreter, which can print the filled copy of a {{@file}} token past redaction.", stderr);
        Assert.DoesNotContain("'bash' here is not", stderr);
    }

    [Fact]
    public void ATokenThatBecomesWslBash_IsRefusedAfterSubstitution_NamingTheToken()
    {
        Secrets(("prog", "bash"), ("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "{{prog}}", "./capture.sh", "{{pw}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("After substitution, the value of {{prog}} makes this a command 'run' refuses", stderr);
        Assert.DoesNotContain("bash", stderr);
        Assert.DoesNotContain(Value, stdout + stderr);
    }

    [Fact]
    public void OffWindows_BashExe_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Linux, null, "bash.exe", "./capture.sh", "{{pw}}");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, BashLauncherRefusalTests.OffWindowsReason, windows: false);
    }

    [Fact]
    public void OffWindows_BashExeBehindTasksetWithAnAttachedCpuList_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Linux, null, "taskset", "--cpu-list=0-3", "bash.exe", "./capture.sh", "{{pw}}");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, BashLauncherRefusalTests.OffWindowsReason, windows: false);
    }

    [Fact]
    public void OffWindows_Bash_StartsAsGiven()
    {
        Secrets(("pw", Value));

        var (exit, _, err) = Run(OSPlatform.Linux, null, "bash", "./capture.sh", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["bash", "./capture.sh", Value], _pty.Argv!);
    }

    [Fact]
    public void WslExecBash_Starts()
    {
        Secrets(("pw", Value));

        var (exit, _, err) = Run(OSPlatform.Windows, WslProbe(), "wsl", "-e", "bash", "./capture.sh", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
    }

    [Fact]
    public void ShellModeWslBehindNpx_IsRefusedByTheWslCheck()
    {
        Secrets(("pw", Value));

        var (exit, _, stderr) = Run(OSPlatform.Windows, WslProbe(), "npx", "wsl", "bash.exe", "./capture.sh", "{{pw}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        // Validation.WslShellModeReason (private), up to its way out, which run swaps on Windows.
        Assert.Contains("'npx' runs 'wsl': 'wsl' without -e (or --shell-type none) runs its command line through the Linux shell " +
                        "($SHELL -c), which parses a substituted value again and can transform and print secrets past redaction. " +
                        "Give the command after -e: 'wsl -e ./deploy.sh {{secret}}'. ", stderr);
    }

    [Fact]
    public void QuotedWsl_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "\"wsl.exe\"", "./deploy.sh", "{{pw}}");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, BashLauncherRefusalTests.PaddedWslReason, windows: true);
    }

    [Fact]
    public void WslExecBashExe_IsRefusedBeforeUnlock()
    {
        Secrets(("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "wsl", "-e", "bash.exe", "./capture.sh", "{{pw}}");

        AssertRefusedBeforeUnlock(exit, stdout, stderr, "'wsl' runs 'bash.exe': " + BashLauncherRefusalTests.OffWindowsReason, windows: true);
    }

    [Fact]
    public void ATokenThatBecomesWslsBashExe_IsRefusedAfterSubstitution_NamingTheToken()
    {
        Secrets(("prog", "bash.exe"), ("pw", Value));

        var (exit, stdout, stderr) = Run(OSPlatform.Windows, WslProbe(), "wsl", "-e", "{{prog}}", "./capture.sh", "{{pw}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("After substitution, the value of {{prog}} makes this a command 'run' refuses", stderr);
        Assert.DoesNotContain("bash.exe", stderr);
        Assert.DoesNotContain(Value, stdout + stderr);
    }
}
