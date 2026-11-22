using System.Runtime.InteropServices;
using TswapCli;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T47 Task 2: on Windows <c>run</c> refuses to hand a batch file (or cmd) a substituted value cmd.exe would
/// parse again (batch files re-parse arguments), before the child starts. In process on every OS: the OS comes from
/// <see cref="CommandContext.Os"/> (<see cref="FleetMachine.Os"/>, A8), never the real OS check, and the child is a
/// <see cref="RecordingPty"/>. The real Windows child is <c>EndToEndTests.Run_BatchFile_EvilValues_NeverInject_Windows</c>.
/// </summary>
public sealed class RunBatchRefusalTests : IDisposable
{
    private const string Allowed = "abc def-123_.";

    private readonly FleetMachine _m = new("run-batch-refusal", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();
    private readonly string _temp = Directory.CreateTempSubdirectory("tswap-run-batch-").FullName;

    public RunBatchRefusalTests() => InitRecordVault(_m);

    public void Dispose()
    {
        _m.Dispose();
        Directory.Delete(_temp, recursive: true);
    }

    private static string Amp => EvilValues.Get("ampersand").Value;
    private static string Bang => EvilValues.Get("bang").Value;

    private void Secret(string name, string value) => _m.Ok(value, "ingest", name);

    private (int Exit, string Out, string Err) Run(OSPlatform os, params string[] args) => RunWithTempRoot(os, _temp, args);

    private (int Exit, string Out, string Err) RunWithTempRoot(OSPlatform os, string tempRoot, params string[] args)
    {
        _m.Os = os;
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var env = FilledFilesEnvironment.FromSystem() with
        {
            XdgRuntimeDir = null,
            TempRoot = tempRoot,
            CurrentDirectory = _m.Dir,
            RegisterSignals = _ => new Nothing(),
        };
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty, FilledFilesEnvironment = env };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose() { }
    }

    private void AssertRefused((int Exit, string Out, string Err) run, string value, params string[] names)
    {
        Assert.True(run.Exit == 1, $"exit {run.Exit}: {run.Err}");
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("to a batch file", run.Err);
        foreach (var name in names)
            Assert.Contains($"'{name}'", run.Err);
        Assert.DoesNotContain(value, run.Err + run.Out);
    }

    [Fact]
    public void ABatchFile_WithARefusedValue_IsRefused_TheChildNeverStarts()
    {
        Secret("pw", Amp);

        var run = Run(OSPlatform.Windows, "x.cmd", "{{pw}}");

        AssertRefused(run, Amp, "pw");
        Assert.Contains(
            "Refused: tswap won't pass secret(s) 'pw' to a batch file. cmd.exe parses a batch file's arguments again",
            run.Err);
    }

    [Fact]
    public void ABatchFile_WithAnAllowedValue_StartsWithTheExactArgument()
    {
        Secret("pw", Allowed);

        var (exit, _, err) = Run(OSPlatform.Windows, "x.cmd", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["x.cmd", Allowed], _pty.Argv!);
    }

    [Fact]
    public void AProgram_ThatIsNotABatchFile_StartsWithARefusedClassValue()
    {
        Secret("pw", Amp);

        var (exit, _, err) = Run(OSPlatform.Windows, "x.exe", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["x.exe", Amp], _pty.Argv!);
    }

    public static TheoryData<string> UnixOses => [OSPlatform.Linux.ToString(), OSPlatform.OSX.ToString()];

    [Theory]
    [MemberData(nameof(UnixOses))]
    public void ElsewhereThanWindows_NothingChanges(string os)
    {
        Secret("pw", Amp);

        var (exit, _, err) = Run(OSPlatform.Create(os), "x.cmd", "{{pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["x.cmd", Amp], _pty.Argv!);
    }

    public static TheoryData<string[]> WrappedBatchCommands => new()
    {
        // A1: every program word of the walk, not only argv[0].
        new[] { "timeout", "5", "x.cmd", "{{pw}}" },
        new[] { "find", ".", "-exec", "x.cmd", "{{pw}}", ";" },
        // A5: PowerShell's -File script.
        new[] { "powershell", "-File", "x.cmd", "{{pw}}" },
        // Controller ruling 2.
        new[] { "pwsh", "x.cmd", "{{pw}}" },
        new[] { "powershell", "/File", "x.cmd", "{{pw}}" },
        new[] { "pwsh", "/f", "x.cmd", "{{pw}}" },
        // Review fix F10: any batch target after powershell or pwsh, whatever option or position it is in.
        new[] { "powershell", "x.cmd", "{{pw}}" },
        new[] { "powershell", "--file", "x.cmd", "{{pw}}" },
        new[] { "pwsh", "\u2013File", "x.cmd", "{{pw}}" },
        new[] { "pwsh", " x.cmd", "{{pw}}" },
        // Review fix F11: any word of the command that is a batch target.
        new[] { "pwsh.exe.", "x.cmd", "{{pw}}" },
        new[] { "docker", "run", "img", "x.cmd", "{{pw}}" },
        new[] { "anytool", "--flag", "x.bat", "{{pw}}" },
        // A4: a name Windows normalises to a batch file.
        new[] { "x.cmd.", "{{pw}}" },
        new[] { "CMD.EXE", "{{pw}}" },
    };

    [Theory]
    [MemberData(nameof(WrappedBatchCommands))]
    public void ABatchTargetBehindAWrapper_IsRefused(string[] command)
    {
        Secret("pw", Amp);

        AssertRefused(Run(OSPlatform.Windows, command), Amp, "pw");
    }

    public static TheoryData<string[]> PowerShellSlashCommandBatchCommands => new()
    {
        new[] { "powershell", "/command", "x.cmd", "{{pw}}" },
        new[] { "powershell", "/c", "x.cmd", "{{pw}}" },
        new[] { "pwsh", "/command", "x.cmd", "{{pw}}" },
    };

    /// <summary>
    /// Review fix F1: <c>/command</c> and <c>/c</c> are PowerShell's -Command too, so a batch file run through them is
    /// refused (by whichever check fires first), the child never starts and the value is never printed; on every OS.
    /// </summary>
    [Theory]
    [MemberData(nameof(PowerShellSlashCommandBatchCommands))]
    public void ABatchFileThroughPowerShellsSlashCommand_IsRefused(string[] command)
    {
        Secret("pw", Amp);

        foreach (var os in new[] { OSPlatform.Windows, OSPlatform.Linux })
        {
            var (exit, stdout, stderr) = Run(os, command);

            Assert.True(exit == 1, $"{os}: exit {exit}: {stderr}");
            Assert.Equal(0, _pty.Starts);
            Assert.Contains("❌ Error: ", stderr);
            Assert.DoesNotContain(Amp, stderr + stdout);
        }
    }

    [Fact]
    public void SeveralRefusedSecrets_AreNamedInArgvOrder()
    {
        Secret("zeta", Bang);
        Secret("plain", Allowed);
        Secret("alpha", Amp);

        var run = Run(OSPlatform.Windows, "x.bat", "{{zeta}}", "{{plain}}", "--x={{alpha}}");

        AssertRefused(run, Amp, "zeta", "alpha");
        Assert.DoesNotContain(Bang, run.Err);
        Assert.Contains("secret(s) 'zeta', 'alpha' to a batch file", run.Err);
        Assert.DoesNotContain("'plain'", run.Err);
    }

    [Fact]
    public void AFileToken_WhoseNameHoldsACharacterOfTheSet_IsRefused_AndTheCopyIsGone()
    {
        // A2: the filled copy keeps the source's base name.
        Secret("pw", Allowed);
        File.WriteAllText(_m.PathOf("a&b.yaml"), "password: \"\"  # tswap: pw\n");

        var (exit, _, err) = Run(OSPlatform.Windows, "x.cmd", "{{@a&b.yaml}}");

        Assert.True(exit == 1, err);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("Refused: tswap won't pass the copy of 'a&b.yaml' to a batch file: its name contains characters cmd.exe interprets", err);
        Assert.Contains("Rename the file.", err);
        Assert.DoesNotContain(Allowed, err);
        Assert.Empty(Directory.EnumerateFiles(_temp, "*", SearchOption.AllDirectories));
    }

    /// <summary>
    /// Controller ruling 1: both ways out the refusal names, taken from its own text with the secret's name in, run
    /// on Windows without any refusal, also with a refused-class value.
    /// </summary>
    [Fact]
    public void TheRefusalsOwnExamples_AreNotRefused()
    {
        Secret("pw", Amp);
        var message = Run(OSPlatform.Windows, "x.cmd", "{{pw}}").Err;
        var examples = System.Text.RegularExpressions.Regex.Matches(message, @"'run ([^']+)'")
            .Select(m => m.Groups[1].Value.Split(' '))
            .ToList();
        Assert.Equal(2, examples.Count);
        Assert.Contains(examples, e => e[0] == "--env");

        foreach (var example in examples)
        {
            var before = _pty.Starts;
            var (exit, _, err) = Run(OSPlatform.Windows, example);
            Assert.True(exit == 0, $"'run {string.Join(' ', example)}' was refused: {err}");
            Assert.Equal(before + 1, _pty.Starts);
        }
        Assert.Equal(["deploy.cmd"], _pty.Argv!);
        Assert.Equal(Amp, _pty.Options!.Environment!["PW"]);
    }

    /// <summary>
    /// Controller ruling 3: a temporary folder (the filled-files environment's temp root) whose path holds a character
    /// of the set refuses a {{@file}} for a batch file, naming %TEMP%, never the path.
    /// </summary>
    [Fact]
    public void AFileToken_InATemporaryFolderWithACharacterOfTheSet_IsRefused_NamingTemp()
    {
        Secret("pw", Allowed);
        File.WriteAllText(_m.PathOf("values.yaml"), "password: \"\"  # tswap: pw\n");
        var root = Directory.CreateDirectory(Path.Combine(_temp, "t&mp")).FullName;

        var (exit, _, err) = RunWithTempRoot(OSPlatform.Windows, root, "x.cmd", "{{@values.yaml}}");

        Assert.True(exit == 1, err);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains("Refused: tswap won't pass the copy of 'values.yaml' to a batch file: the temporary folder's path (%TEMP%) contains characters cmd.exe interprets", err);
        Assert.Contains("Set TMP and TEMP to a folder without them, or use a PowerShell script.", err);
        Assert.DoesNotContain("Rename the file.", err);
        Assert.DoesNotContain(_temp, err);
        Assert.DoesNotContain("t&mp", err);
        Assert.Empty(Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void AnEnvValue_NeverCounts()
    {
        // A6: an --env value never reaches the command line. (Not "script.cmd": run refuses "script", a code runner; the refusal's example is deploy.cmd.)
        Secret("pw", Amp);

        var (exit, _, err) = Run(OSPlatform.Windows, "--env", "PW={{pw}}", "--", "capture-env.cmd", "plain-arg");

        Assert.True(exit == 0, err);
        Assert.Equal(["capture-env.cmd", "plain-arg"], _pty.Argv!);
        Assert.Equal(Amp, _pty.Options!.Environment!["PW"]);
    }
}
