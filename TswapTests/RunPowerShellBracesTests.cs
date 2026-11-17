using TswapCli;
using TswapCli.Commands;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T35 Task 1 (#348.1): PowerShell reads an unquoted <c>{...}</c> as a script block and passes
/// <c>{{name}}</c> on as <c>{name}</c>. <c>run</c> recognises an argument that is exactly such a braced name or
/// <c>{@path}</c>: with no token at all the refusal shows the quoted form; next to a real token it warns and
/// passes the argument on unchanged.
/// </summary>
public sealed class RunPowerShellBracesTests : IDisposable
{
    private const string DbValue = "braces-db-value-7f3a";

    private readonly FleetMachine _m = new("run-braces", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();

    public void Dispose() => _m.Dispose();

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    private (int Exit, string Out, string Err) Run(params string[] args)
    {
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    private void DbVault()
    {
        InitRecordVault(_m);
        _m.Ok(DbValue, "ingest", "db-pw");
    }

    // ── no token at all: the refusal, then one hint per braced argument ─────────────────

    [Fact]
    public void NoToken_BracedName_HintsTheQuotedForm()
    {
        var (exit, stdout, stderr) = Run("tool", "{db-pw}");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.BracesHint("{db-pw}")), stderr);
        Assert.Equal(ErrorLine(
            "No {{tokens}} or {{@file}} tokens found in command\nThe argument {db-pw} looks like the token " +
            "{{db-pw}} with one pair of braces removed, as PowerShell does to an unquoted token. Quote it: '{{db-pw}}'."),
            stderr);
        Assert.Equal(0, _pty.Starts);
        Assert.False(File.Exists(_m.ConfigPath));
    }

    [Fact]
    public void NoToken_BracedPrevious_And_FileToken()
    {
        var (exit, _, stderr) = Run("helm", "upgrade", "app", "./chart", "-f", "{@values.yaml}", "--set", "{db-pw:previous}");

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.BracesHint("{@values.yaml}") + "\n" +
            RunCommand.BracesHint("{db-pw:previous}")), stderr);
        Assert.Contains("'{{@values.yaml}}'", stderr);
        Assert.Contains("'{{db-pw:previous}}'", stderr);
    }

    [Fact]
    public void NoToken_SameBracedArgumentTwice_OneLine()
    {
        var (exit, _, stderr) = Run("tool", "{a}", "{a}");

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.BracesHint("{a}")), stderr);
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("--x={a}")]
    [InlineData("{a}{b}")]
    [InlineData("{}")]
    [InlineData("{a b}")]
    [InlineData("{a.b}")]
    [InlineData("HEAD@{1}")]
    [InlineData("{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}")] // 65 characters
    public void NoToken_NothingBraced_PlainErrorUnchanged(string argument)
    {
        var (exit, _, stderr) = Run("tool", argument);

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText), stderr);
    }

    [Fact]
    public void NoToken_ControlCharactersInAFileToken_ShownAsQuestionMarks()
    {
        var (exit, _, stderr) = Run("tool", "{@x\u001b[31my}");

        Assert.Equal(1, exit);
        Assert.Contains("{@x?[31my}", stderr);
        Assert.Contains("'{{@x?[31my}}'", stderr);
        // Ordinal: a culture-aware search ignores ESC and "finds" it at position 0.
        Assert.DoesNotContain("\u001b", stderr, StringComparison.Ordinal);
    }

    // ── tokens found: a warning, and the argument goes to the child as it is ─────────────

    [Fact]
    public void Token_PlusBracedArgument_WarnsAndPassesItOn()
    {
        DbVault();

        var (exit, stdout, stderr) = Run("tool", "{{db-pw}}", "{other}");

        Assert.True(exit == 0, stderr);
        Assert.Equal(["tool", DbValue, "{other}"], _pty.Argv!);
        var warning = RunCommand.BracesWarning("{other}");
        Assert.Equal(
            "Warning: the argument {other} looks like the token {{other}} with one pair of braces removed, as PowerShell " +
            "does to an unquoted token; it is passed on as it is. Quote it: '{{other}}'.", warning);
        Assert.Equal(1, Occurrences(stderr, warning));
        Assert.DoesNotContain(DbValue, stdout);
        Assert.DoesNotContain(DbValue, stderr);
    }

    [Fact]
    public void Token_PlusBracedArgument_RefusedCommand_NoWarning()
    {
        DbVault();

        var (exit, _, stderr) = Run("echo", "{{db-pw}}", "{other}");

        Assert.Equal(1, exit);
        Assert.Contains("'echo' would expose secret values", stderr);
        Assert.DoesNotContain("looks like the token", stderr);
        Assert.Equal(0, _pty.Starts);
    }

    [Fact]
    public void BracedTokens_DistinctInArgumentOrder()
    {
        Assert.Equal(["{b}", "{@f.yaml}", "{a:previous}"],
            RunCommand.BracedTokens(["x", "{b}", "{@f.yaml}", "{b}", "{a:previous}", "{a:other}", "{@}", "{@a{b}"]));
    }

    // ── the agent prompt ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Prompt_TellsPowerShellToQuote()
    {
        var text = Prompt.GetText("tswap");

        Assert.Contains("in PowerShell quote each argument holding a token", text);
        Assert.Contains(@".\deploy.ps1 '{{secret-name}}'", text);
    }

    private static int Occurrences(string text, string part)
    {
        var count = 0;
        for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
}
