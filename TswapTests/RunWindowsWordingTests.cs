using System.Runtime.InteropServices;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T35 Task 2 (#348.3): <c>run</c>'s refusals name a PowerShell script and an elevated prompt on Windows,
/// where there is no <c>./script.sh</c>, <c>$1</c> or <c>sudo</c>, and keep today's Unix wording byte for byte
/// elsewhere. The OS comes from <see cref="CommandContext.Os"/> (<see cref="FleetMachine.Os"/>).
/// </summary>
public sealed class RunWindowsWordingTests : IDisposable
{
    private const string InlinePrefix = "'cmd /c' runs inline code, which can transform and print secrets past redaction. ";

    private readonly FleetMachine _m = new("run-windows-wording", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();

    public void Dispose() => _m.Dispose();

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    private (int Exit, string Out, string Err) Run(OSPlatform os, params string[] args)
    {
        _m.Os = os;
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    public static TheoryData<string> UnixOses => [OSPlatform.Linux.ToString(), OSPlatform.OSX.ToString()];

    // ── the inline-code refusal ──────────────────────────────────────────────────────────

    [Fact]
    public void InlineCode_OnWindows_PowerShellScriptAndElevatedPrompt()
    {
        var (exit, _, stderr) = Run(OSPlatform.Windows, "cmd", "/c", "echo", "{{name}}");

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(InlinePrefix + Validation.WayOutFor(true) + "\n" + RunCommand.ViewSecretLine(true)), stderr);
        Assert.Equal(
            "Put the commands in a script file and run that instead, e.g. 'run powershell -File .\\script.ps1 {{secret}}' " +
            "(the script reads the value as $args[0]; in PowerShell quote the token: '{{secret}}').",
            Validation.WayOutFor(true));
        Assert.Equal("Use '... get <name>' from an elevated command prompt to view a secret.", RunCommand.ViewSecretLine(true));
        Assert.DoesNotContain("sudo", stderr);
        Assert.DoesNotContain("./script.sh", stderr);
        Assert.DoesNotContain("$1", stderr);
        Assert.Equal(0, _pty.Starts);
    }

    [Theory]
    [MemberData(nameof(UnixOses))]
    public void InlineCode_OnUnix_Unchanged(string os)
    {
        var (exit, _, stderr) = Run(OSPlatform.Create(os), "cmd", "/c", "echo", "{{name}}");

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(
            "'cmd /c' runs inline code, which can transform and print secrets past redaction. Put the commands in a " +
            "script file and run that instead, e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1).\n" +
            "Use 'sudo ... get <name>' to view a secret."), stderr);
    }

    [Fact]
    public void Wrapped_OnWindows_TheSentenceIsSwappedInside()
    {
        var (exit, _, stderr) = Run(OSPlatform.Windows, "find", ".", "-exec", "sh", "-c", "x", "{{name}}", ";");

        Assert.Equal(1, exit);
        Assert.Contains("'find -exec' runs", stderr);
        Assert.Contains(Validation.WayOutFor(true), stderr);
        Assert.DoesNotContain(Validation.WayOutFor(false), stderr);
    }

    /// <summary>
    /// One refused argv per place in <c>Validation.cs</c> (at 51b0b37) that appends the way out: <c>InlineReason</c>
    /// and the nine direct uses (su, xargs, sudo -s, docker --entrypoint, machinectl shell, a wrapper with no
    /// command, python3 -, expect -f -, python3 with no script), and brief T49's four reasons (powershell without
    /// -File, an untrusted spelling, a script from stdin, no script or -NoExit), and review fix G2's deno run -: fourteen direct uses in all (G2's bare cmd reuses the
    /// no-command shell reason).
    /// <c>run</c>'s Windows swap relies on each reason ending with the whole sentence.
    /// </summary>
    public static TheoryData<string[]> WayOutReasons =>
    [
        ["sh", "-c", "x"],
        ["cmd", "/c", "x"],
        ["pwsh", "-Command", "x"],
        ["su"],
        ["xargs", "x"],
        ["sudo", "-s"],
        ["docker", "run", "--entrypoint", "python", "img"],
        ["machinectl", "shell"],
        ["nsenter"],
        ["python3", "-"],
        ["expect", "-f", "-"],
        ["python3"],
        ["powershell", "Write-Host", "x"],
        ["powershell", "--File", "x.ps1"],
        ["powershell", "-File", "-"],
        ["powershell", "-NoExit", "-File", "x.ps1"],
        ["deno", "run", "-"],
    ];

    [Theory]
    [MemberData(nameof(WayOutReasons))]
    public void EveryWayOutReason_EndsWithTheWholeSentence(string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.EndsWith(Validation.WayOutFor(false), blocked.Reason, StringComparison.Ordinal);
    }

    // ── the "sudo ... get" lines ─────────────────────────────────────────────────────────

    [Fact]
    public void Blocklisted_And_Pipe_OnWindows_ElevatedPrompt()
    {
        var blocked = Run(OSPlatform.Windows, "echo", "{{name}}");
        var piped = Run(OSPlatform.Windows, "tool", "{{name}}", "|", "more");

        Assert.EndsWith("\n" + RunCommand.ViewSecretLine(true) + Environment.NewLine, blocked.Err, StringComparison.Ordinal);
        Assert.EndsWith("\n" + RunCommand.RetrieveSecretLine(true) + Environment.NewLine, piped.Err, StringComparison.Ordinal);
        Assert.Equal("Use '... get <name>' from an elevated command prompt to retrieve a secret value.", RunCommand.RetrieveSecretLine(true));
        Assert.DoesNotContain("sudo", blocked.Err);
        Assert.DoesNotContain("sudo", piped.Err);

        var unixBlocked = Run(OSPlatform.Linux, "echo", "{{name}}");
        var unixPiped = Run(OSPlatform.Linux, "tool", "{{name}}", "|", "more");

        Assert.EndsWith("\nUse 'sudo ... get <name>' to view a secret." + Environment.NewLine, unixBlocked.Err, StringComparison.Ordinal);
        Assert.EndsWith("\nUse 'sudo ... get <name>' to retrieve a secret value." + Environment.NewLine, unixPiped.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void AfterSubstitution_OnWindows_ElevatedPrompt()
    {
        InitRecordVault(_m);
        _m.Ok("echo\necho\n", "add", "cmd");

        var (exit, _, stderr) = Run(OSPlatform.Windows, "{{cmd}}", "x");

        Assert.Equal(1, exit);
        Assert.Contains("After substitution, the value of {{cmd}} makes this a command 'run' refuses", stderr);
        Assert.EndsWith("\n" + RunCommand.ViewSecretLine(true) + Environment.NewLine, stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("sudo", stderr);
        Assert.Equal(0, _pty.Starts);
    }

    [Fact]
    public void WindowsWayOut_IsRunnable()
    {
        Assert.Null(Validation.GetBlockedInvocation(["powershell", "-File", @".\script.ps1", "{{secret}}"]));
    }
}
