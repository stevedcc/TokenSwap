using System.Runtime.InteropServices;
using TswapCli;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T55 Task 4 (#402): on Windows <c>run</c> starts an MSYS2 program (Git Bash) by its resolved path with the
/// arguments quoted by MSYS2's rules (RedactingPty's <c>WindowsArguments</c>), or refuses before the child starts. In
/// process on every OS: the OS comes from <see cref="CommandContext.Os"/>, the machine from a fake
/// <see cref="MsysTarget.Probe"/> holding Git's files (<see cref="MsysTargetTests.FakeProbe"/>), and the child is a
/// <see cref="RecordingPty"/>. The real Windows child is <c>EndToEndTests.Run_GitBashScript_EvilValues_ArriveExactly_Windows</c>.
/// </summary>
public sealed class RunMsysTargetTests : IDisposable
{
    private const string GitBash = @"C:\Program Files\Git\bin\bash.exe";
    private const string Value = "a\\b\"c";

    private readonly FleetMachine _m = new("run-msys-target", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();

    public RunMsysTargetTests() => InitRecordVault(_m);

    public void Dispose() => _m.Dispose();

    private void Secret(string name, string value) => _m.Ok(value, "ingest", name);

    private (int Exit, string Out, string Err) Run(OSPlatform os, MsysTarget.Probe probe, params string[] args)
    {
        _m.Os = os;
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty, MsysProbe = () => probe };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    private static MsysTarget.Probe Probe(Dictionary<string, string>? variables = null) => MsysTargetTests.FakeProbe([], variables);

    [Fact]
    public void GitBash_StartsByItsResolvedPath_WithTheArgumentsQuotedForMsys2()
    {
        Secret("pw", Value);

        var (exit, _, err) = Run(OSPlatform.Windows, Probe(), "bash", "./capture.sh", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal([GitBash], _pty.Argv!);
        Assert.Equal("\"./capture.sh\" \"a\\\\b\\\"c\"", _pty.Options!.WindowsArguments);
    }

    [Fact]
    public void AProgramNotFound_StartsAsBefore()
    {
        Secret("pw", Value);

        var (exit, _, err) = Run(OSPlatform.Windows, Probe(), "tool", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["tool", Value], _pty.Argv!);
        Assert.Null(_pty.Options!.WindowsArguments);
    }

    [Fact]
    public void OffWindows_GitBashsNameStartsAsBefore()
    {
        Secret("pw", Value);

        var (exit, _, err) = Run(OSPlatform.Linux, Probe(), "bash", "./capture.sh", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["bash", "./capture.sh", Value], _pty.Argv!);
        Assert.Null(_pty.Options!.WindowsArguments);
    }

    private void AssertR1Refused((int Exit, string Out, string Err) run)
    {
        Assert.True(run.Exit == 1, $"exit {run.Exit}: {run.Err}");
        Assert.Equal(0, _pty.Starts);
        Assert.Contains(
            "Refused: MSYS changes the glob option and an argument holds a backslash or double quote; with that option Git Bash " +
            "(MSYS2) reads backslashes and double quotes in its arguments differently, so tswap can't pass the argument(s) from " +
            "'pw' exactly.",
            run.Err);
        Assert.DoesNotContain(Value, run.Err + run.Out);
    }

    [Fact]
    public void MsysNoglobInTswapsEnvironment_Refuses_TheChildNeverStarts()
    {
        Secret("pw", Value);

        AssertR1Refused(Run(OSPlatform.Windows, Probe(new() { ["MSYS"] = "noglob" }), "bash", "./capture.sh", "{{pw}}"));
    }

    [Fact]
    public void MsysNoglobFromAnEnvPair_Refuses_TheChildNeverStarts()
    {
        Secret("pw", Value);
        Secret("g", "noglob");

        AssertR1Refused(Run(OSPlatform.Windows, Probe(), "--env", "MSYS={{g}}", "--", "bash", "./capture.sh", "{{pw}}"));
    }

    [Fact]
    public void AValueLongerThan8000Bytes_Refuses_TheChildNeverStarts()
    {
        var value = string.Concat(Enumerable.Repeat("k7Qz-long-", 820)); // 8,200 bytes
        Secret("pw", value);

        var (exit, output, err) = Run(OSPlatform.Windows, Probe(), "bash", "./capture.sh", "{{pw}}");

        Assert.True(exit == 1, $"exit {exit}: {err}");
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("Refused: the argument(s) from 'pw' is longer than 8,000 bytes", err);
        Assert.DoesNotContain("k7Qz", err + output);
    }

    [Fact]
    public void ALongProgramPath_IsNotAnArgument_AndStarts()
    {
        // Brief T55 amendment 13: R4 measures the arguments only; the program is a path, not a value.
        var folder = @"C:\" + string.Join('\\', Enumerable.Repeat(new string('d', 200), 41)); // over 8,000 characters
        var bash = folder + @"\usr\bin\bash.exe";
        var probe = MsysTargetTests.FakeProbe([bash, folder + @"\usr\bin\msys-2.0.dll"]);
        Secret("pw", Value);

        var (exit, _, err) = Run(OSPlatform.Windows, probe, bash, "./capture.sh", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal([bash], _pty.Argv!);
        Assert.Equal("\"./capture.sh\" \"a\\\\b\\\"c\"", _pty.Options!.WindowsArguments);
    }

    [Fact]
    public void AValueInTheEnvironment_GitBashGetsOnlyTheScript()
    {
        Secret("pw", Value);

        var (exit, _, err) = Run(OSPlatform.Windows, Probe(), "--env", "PW={{pw}}", "--", "bash", "./capture.sh");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal([GitBash], _pty.Argv!);
        Assert.Equal("\"./capture.sh\"", _pty.Options!.WindowsArguments);
        Assert.Equal(Value, _pty.Options.Environment!["PW"]);
    }
}
