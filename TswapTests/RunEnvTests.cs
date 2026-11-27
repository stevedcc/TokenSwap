using System.Text;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T26 (issue #71): <c>run --env NAME={{name}}</c> hands a secret to the child in its environment,
/// never in its argv. In process through <see cref="RecordingPty"/>, whose recorded options carry the
/// environment the child would get; the end-to-end check of a real child's <c>/proc/$$/cmdline</c> is in
/// <see cref="EndToEndTests"/>.
/// </summary>
public sealed class RunEnvTests : IDisposable
{
    private const string DbValue = "db>>pass??word~~1";

    private readonly FleetMachine _m = new("run-env", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly string _temp = Directory.CreateTempSubdirectory("tswap-run-env-").FullName;
    private byte[] _key = [];

    public void Dispose()
    {
        _m.Dispose();
        Directory.Delete(_temp, recursive: true);
    }

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    private void RecordVault() => _key = VaultKey(_m, InitRecordVault(_m));

    private void DbVault()
    {
        RecordVault();
        _m.Ok(DbValue, "ingest", "db-pw");
    }

    private (int Exit, string Out, string Err) Run(params string[] args) => Run(verbose: false, args);

    private (int Exit, string Out, string Err) Run(bool verbose, params string[] args)
    {
        _values.Clear();
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var env = FilledFilesEnvironment.FromSystem() with
        {
            XdgRuntimeDir = null,
            TempRoot = _temp,
            CurrentDirectory = _m.Dir,
            RegisterSignals = _ => new Nothing(),
        };
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty, FilledFilesEnvironment = env };
        if (verbose)
            ctx = ctx with { Env = new CliEnvironment { Prefix = "tswap", ConfigDir = _m.Dir, Verbose = true, CommandArgs = command } };
        var exit = CliRunner.Run(ctx, command);
        _m.StoreOpened = null;
        return (exit, console.OutText, console.ErrorText);
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose() { }
    }

    private IReadOnlyDictionary<string, string> ChildEnvironment => _pty.Options!.Environment!;

    // ── the variable reaches the child, masked in its output ─────────────────────────

    [Fact]
    public void RunEnv_SetsTheVariable_ValueMaskedInOutput()
    {
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(DbValue));
        var unpadded = base64.TrimEnd('=');
        // A form the replacements cover and the fingerprint matcher doesn't: standard base64 without its
        // padding differs from the unpadded base64url form only when it holds '+' or '/'.
        Assert.EndsWith("=", base64);
        Assert.True(unpadded.Contains('+') || unpadded.Contains('/'), unpadded);
        DbVault();
        _pty.Child = _ => $"raw={ChildEnvironment["PGPASSWORD"]}\nb64={unpadded}\n";

        var (exit, _, err) = Run("--env", "PGPASSWORD={{db-pw}}", "--", "psql", "-h", "db");

        Assert.True(exit == 0, err);
        Assert.Equal("raw=[REDACTED: db-pw]\nb64=[REDACTED: db-pw]\n", _pty.Output.ToString());
        Assert.Equal(new Dictionary<string, string> { ["PGPASSWORD"] = DbValue }, ChildEnvironment);
    }

    [Fact]
    public void RunEnv_ValueNotInArgv()
    {
        DbVault();

        var (exit, _, err) = Run("--env", "PGPASSWORD={{db-pw}}", "psql", "-h", "db");

        Assert.True(exit == 0, err);
        Assert.Equal(["psql", "-h", "db"], _pty.Argv!);
        Assert.All(_pty.Argv!, word => Assert.DoesNotContain("pass??word", word));
        Assert.Equal(DbValue, ChildEnvironment["PGPASSWORD"]);
    }

    [Fact]
    public void RunEnv_OnlyEnvTokens_NoArgvTokens_Runs()
    {
        DbVault();

        var (exit, _, err) = Run("--env", "PGPASSWORD={{db-pw}}", "--", "psql");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["psql"], _pty.Argv!);
    }

    [Fact]
    public void RunEnv_EqualsForm_Works()
    {
        DbVault();

        var (exit, _, err) = Run("--env=PGPASSWORD={{db-pw}}", "psql");

        Assert.True(exit == 0, err);
        Assert.Equal(["psql"], _pty.Argv!);
        Assert.Equal(DbValue, ChildEnvironment["PGPASSWORD"]);
    }

    [Fact]
    public void RunEnv_ValueSplitAtTheFirstEquals()
    {
        DbVault();

        var (exit, _, err) = Run("--env", "A={{db-pw}}", "--env=B={{db-pw}}", "psql");

        Assert.True(exit == 0, err);
        Assert.Equal(new Dictionary<string, string> { ["A"] = DbValue, ["B"] = DbValue }, ChildEnvironment);
    }

    [Fact]
    public void RunEnv_PreviousToken_Works()
    {
        RecordVault();
        _m.Ok("old-value-1", "ingest", "tok");
        _m.Ok("new-value-2", "ingest", "--rotate", "tok");
        _pty.Child = _ => $"{ChildEnvironment["OLD"]} {ChildEnvironment["NEW"]}\n";

        var (exit, _, err) = Run("--env", "OLD={{tok:previous}}", "--env", "NEW={{tok}}", "--", "tool");

        Assert.True(exit == 0, err);
        Assert.Equal(new Dictionary<string, string> { ["OLD"] = "old-value-1", ["NEW"] = "new-value-2" }, ChildEnvironment);
        Assert.Equal("[REDACTED: tok:previous] [REDACTED: tok]\n", _pty.Output.ToString());
    }

    [Fact]
    public void RunEnv_WithFileToken_Works()
    {
        DbVault();
        _m.Ok("cfg-value-9", "ingest", "cfg");
        File.WriteAllText(_m.PathOf("cfg.yaml"), "password: \"\"  # tswap: cfg\n");
        string? copy = null;
        _pty.Child = argv =>
        {
            copy = File.ReadAllText(argv[2]);
            return "";
        };

        var (exit, _, err) = Run("--env", "PGPASSWORD={{db-pw}}", "--", "psql", "-f", "{{@cfg.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal(DbValue, ChildEnvironment["PGPASSWORD"]);
        Assert.Equal("psql", _pty.Argv![0]);
        Assert.Contains("cfg-value-9", copy);
        Assert.DoesNotContain("pass??word", string.Join(' ', _pty.Argv!));
    }

    [Fact]
    public void RunEnv_DecryptsOnlyWhatIsUsed()
    {
        RecordVault();
        foreach (var name in new[] { "a", "b", "c" })
            _m.Ok($"{name}-value", "ingest", name);

        var (exit, _, err) = Run("--env", "X={{a}}", "--env", "Y={{a}}", "--", "tool", "{{b}}");

        Assert.True(exit == 0, err);
        HashSet<(string, Stamp)> expected = [(Version("a")), (Version("b"))];
        Assert.Equal(expected, _values.ToHashSet());
        Assert.Equal(2, _values.Count);
        Assert.Equal(["tool", "b-value"], _pty.Argv!);
    }

    private (string, Stamp) Version(string name) =>
        (Path.GetFileName(RecordFile(_m, _key, name)),
            Store(_m).LoadMetadata(_key, TextWriter.Null).Records.Single(r => r.Name == name).Version);

    [Fact]
    public void RunEnv_Verbose_ListsNamesNotValues()
    {
        DbVault();
        _m.Ok("second-value-7", "ingest", "second");

        var (exit, stdout, err) = Run(verbose: true, "--env", "PGPASSWORD={{db-pw}}", "--env", "OTHER={{second}}", "--", "psql");

        Assert.True(exit == 0, err);
        Assert.Contains("Environment: PGPASSWORD, OTHER" + Environment.NewLine, stdout);
        Assert.DoesNotContain(DbValue, stdout + err);
        Assert.DoesNotContain("second-value-7", stdout + err);
    }

    [Fact]
    public void RunEnv_AfterTheCommand_IsTheCommandsArgument()
    {
        DbVault();

        var (exit, _, err) = Run("tool", "--env", "X={{db-pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "--env", $"X={DbValue}"], _pty.Argv!);
        Assert.Null(_pty.Options!.Environment);
    }

    // ── refusals before the unlock: a machine with no vault ─────────────────────────

    private const string Exactly = "must be exactly one {{name}}, {{name:previous}} or {{name:totp}} token";

    public static TheoryData<string, string[]> RefusedBeforeUnlock()
    {
        string[] many = [.. Enumerable.Range(0, 65).SelectMany(i => new[] { "--env", $"V{i}={{{{s}}}}" }), "tool"];
        var longName = "A" + new string('B', 64);
        return new()
        {
            { $"'--env X': the value {Exactly}, not a literal. A literal isn't a secret: set it in your shell, where the child inherits it.",
                ["--env", "X=plain-text", "tool"] },
            { $"'--env X': the value {Exactly}, with nothing around it.", ["--env", "X={{a}}{{b}}", "tool"] },
            { $"'--env X': the value {Exactly}, with nothing around it.", ["--env", "X=pre-{{k}}", "tool"] },
            { "'--env X': a {{@file}} token can't be an --env value (a file path isn't a secret): put it in the command.",
                ["--env", "X={{@cfg.yaml}}", "tool"] },
            { "Unknown token '{{x:bogus}}': the suffixes are ':previous' (the value the last rotation replaced) and ':totp' (the current code of a TOTP seed).",
                ["--env", "X={{x:bogus}}", "tool"] },
            { BadName("1BAD"), ["--env", "1BAD={{s}}", "tool"] },
            { BadName(longName), ["--env", $"{longName}={{{{s}}}}", "tool"] },
            { "'--env' sets X twice (names are compared ignoring case).", ["--env", "X={{s}}", "--env", "X={{t}}", "tool"] },
            { "'--env' sets x twice (names are compared ignoring case).", ["--env", "X={{s}}", "--env=x={{t}}", "tool"] },
            { "At most 64 '--env' variables.", many },
            { Program("PATH"), ["--env", "PATH={{s}}", "tool"] },
            { Program("Path"), ["--env", "Path={{s}}", "tool"] },
            { Program("PATHEXT"), ["--env", "PATHEXT={{s}}", "tool"] },
            { Loader("LD_PRELOAD", "LD_"), ["--env", "LD_PRELOAD={{s}}", "tool"] },
            { Loader("DYLD_INSERT_LIBRARIES", "DYLD_"), ["--env", "DYLD_INSERT_LIBRARIES={{s}}", "tool"] },
            { Code("BASH_ENV"), ["--env", "BASH_ENV={{s}}", "tool"] },
            { Code("GIT_SSH_COMMAND"), ["--env", "GIT_SSH_COMMAND={{s}}", "tool"] },
            { Code("ComSpec"), ["--env", "ComSpec={{s}}", "tool"] },
            { Code("PSModulePath"), ["--env", "PSModulePath={{s}}", "tool"] },
            { Code("node_env"), ["--env", "node_env={{s}}", "tool"] },
            { NoPair, ["--env", "X", "tool"] },
            { NoPair, ["--env=", "tool"] },
            { NoPair, ["--env", "-h", "tool"] },
            { NoPair, ["--env"] },
            // Brief T35 (sanctioned): the trailer follows the OS, identical to the old text on Linux and macOS.
            { "'env' would expose secret values. The 'run' command is for programs that *use* secrets, not display them." +
                "\n" + RunCommand.ViewSecretLine(OperatingSystem.IsWindows()),
                ["--env", "X={{s}}", "--", "env"] },
        };
    }

    private static string BadName(string name) =>
        $"'--env': '{name}' is not a valid environment variable name (a letter or '_', then letters, digits " +
        "and '_', at most 64 characters).";

    private static string Program(string name) =>
        $"'--env' may not set {name}: it decides which program runs, or where and how it runs. Set it in your shell if you need it.";

    private static string Loader(string name, string prefix) =>
        $"'--env' may not set {name}: {prefix}* changes how every program loads.";

    private static string Code(string name) =>
        $"'--env' may not set {name}: it can make a shell, interpreter, library or tool run extra code, or load, trust or " +
        "write files it names. Set it in your shell if it isn't a secret.";

    private const string NoPair = "'--env' needs NAME={{name}} after it: the variable's name, '=' and one {{name}} token.";

    [Theory]
    [MemberData(nameof(RefusedBeforeUnlock))]
    public void RunEnv_RefusedBeforeUnlock(string message, string[] args)
    {
        var (exit, stdout, stderr) = Run(args);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(ErrorLine(message), stderr);
        Assert.Equal(0, _pty.Starts);
        Assert.False(File.Exists(_m.ConfigPath));
    }

    [Theory]
    [InlineData("--env", "X={{s}}")]
    [InlineData("--env", "X={{s}}", "--")]
    [InlineData("--env=X={{s}}", "--env", "Y={{t}}")]
    public void RunEnv_NoCommandAfterTheOptions_GivesTheBareRunUsageError(params string[] args)
    {
        var (bareExit, bareOut, bareErr) = Run();
        Assert.Equal(1, bareExit);
        Assert.StartsWith("\n❌ Error: Usage: tswap run ", bareErr);

        var (exit, stdout, stderr) = Run(args);

        Assert.Equal((bareExit, bareOut, bareErr), (exit, stdout, stderr));
        Assert.Equal(0, _pty.Starts);
    }

    // ── refusals after the unlock: nothing started, no folder written ───────────────

    [Fact]
    public void RunEnv_UnknownSecret_Refused()
    {
        DbVault();

        var (exit, _, err) = Run("--env", "X={{missing}}", "--", "tool", "{{db-pw}}");

        Assert.Equal(1, exit);
        Assert.Contains("Secret 'missing' not found", err);
        AssertNothingStarted();
    }

    [Fact]
    public void RunEnv_MissingPreviousValue_Refused()
    {
        DbVault();

        var (exit, _, err) = Run("--env", "X={{db-pw:previous}}", "--", "tool");

        Assert.Equal(1, exit);
        Assert.Contains("'db-pw:previous': secret 'db-pw' has no previous value (it has not been rotated since it was created).", err);
        AssertNothingStarted();
    }

    [Fact]
    public void RunEnv_NulValue_RefusedWithTheEnvMessage()
    {
        RecordVault();
        _m.Ok("va\0lue\nva\0lue\n", "add", "nul");

        var (exit, _, err) = Run("--env", "X={{nul}}", "--", "tool");

        Assert.Equal(1, exit);
        Assert.EndsWith(ErrorLine(
            "Secret 'nul' has a null or NUL-containing value, which can't be set in a process's environment ('--env X'). " +
            "Re-ingest the secret with a valid value."), err);
        AssertNothingStarted();
    }

    private void AssertNothingStarted()
    {
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(Directory.EnumerateFileSystemEntries(_temp));
    }

    // ── run's help and -v scans skip an --env value and stop at -- ──────────────────

    [Fact]
    public void RunEnv_HelpAfterEnv_PrintsRunsUsage()
    {
        var (_, runHelp, _) = Run("--help");
        Assert.StartsWith("Usage: tswap run ", runHelp);

        var (exit, stdout, stderr) = Run("--env", "X={{s}}", "--help");

        Assert.True(exit == 0, stderr);
        Assert.Equal(runHelp, stdout);
        Assert.Equal(0, _pty.Starts);
        Assert.False(File.Exists(_m.ConfigPath));
    }

    [Fact]
    public void RunEnv_VerboseAfterEnv_GetsTheGlobalFlagRefusal()
    {
        var (exit, _, stderr) = Run("--env", "X={{s}}", "-v", "tool", "{{s}}");

        Assert.Equal(1, exit);
        Assert.Contains("'-v'/'--verbose' is a global flag", stderr);
        Assert.Equal(0, _pty.Starts);
    }

    [Fact]
    public void RunEnv_HelpAfterDoubleDash_IsTheProgram()
    {
        DbVault();

        var (exit, stdout, stderr) = Run("--", "--help", "{{db-pw}}");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("Usage:", stdout);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["--help", DbValue], _pty.Argv!);
    }
}
