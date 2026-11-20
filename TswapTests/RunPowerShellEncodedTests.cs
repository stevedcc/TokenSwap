using System.Text;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T43 Task 1 (#348): Windows PowerShell 5.1 and PowerShell 7 pass an unquoted <c>{{name}}</c> to a native
/// program as a script block: <c>-encodedCommand &lt;Base64 of the UTF-16LE text {name}&gt;</c> in its place, and
/// <c>-inputFormat xml -outputFormat text</c> as the last four arguments. <c>run</c> recognises that form (shape only):
/// with no token at all the refusal shows the quoted form; next to a real token it warns and passes it on unchanged.
/// </summary>
public sealed class RunPowerShellEncodedTests : IDisposable
{
    private const string DbValue = "encoded-db-value-41c9";

    private static readonly string[] Tail = ["-inputFormat", "xml", "-outputFormat", "text"];

    private readonly FleetMachine _m = new("run-encoded", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();

    public void Dispose() => _m.Dispose();

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    private static string Enc(string body) => Convert.ToBase64String(Encoding.Unicode.GetBytes(body));

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

    // ── no token at all: the refusal, then one hint per encoded token ────────────────────

    [Fact]
    public void Laptop_EchoName_HintsTheQuotedForm()
    {
        var (exit, stdout, stderr) = Run("cmd", "/c", "echo", "-encodedCommand", "ewBuAGEAbQBlAH0A", "-inputFormat", "xml",
            "-outputFormat", "text");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(ErrorLine(
            "No {{tokens}} or {{@file}} tokens found in command\nPowerShell passed an unquoted token {{name}} on as a " +
            "script block (-encodedCommand ...). Quote it: '{{name}}'."), stderr);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.EncodedHint(new("{name}", null))), stderr);
        Assert.Equal(0, _pty.Starts);
        Assert.False(File.Exists(_m.ConfigPath));
    }

    [Fact]
    public void Laptop_WordAfterToken_StillHinted()
    {
        var (exit, _, stderr) = Run(["cmd", "/c", "echo", "-encodedCommand", "ewBuAGEAbQBlAH0A", "END", .. Tail]);

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.EncodedHint(new("{name}", null))), stderr);
    }

    [Fact]
    public void Laptop_PasswordPrefix_QuotesTheWholeArgument()
    {
        var (exit, _, stderr) = Run(["cmd", "/c", "echo", "--password=", "-encodedCommand", "ewBkAGIALQBwAHcAfQA=", .. Tail]);

        Assert.Equal(1, exit);
        Assert.Contains("Quote it: '--password={{db-pw}}'.", stderr);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.EncodedHint(new("{db-pw}", "--password="))),
            stderr);
    }

    [Fact]
    public void Previous_And_File()
    {
        var (exit, _, stderr) = Run(["helm", "upgrade", "app", "./chart", "-f", "-encodedCommand", Enc("{@values.yaml}"),
            "--set", "-encodedCommand", Enc("{db-pw:previous}"), .. Tail]);

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.EncodedHint(new("{@values.yaml}", null)) +
            "\n" + RunCommand.EncodedHint(new("{db-pw:previous}", null))), stderr);
        Assert.Contains("Quote it: '{{@values.yaml}}'.", stderr);
        Assert.Contains("Quote it: '{{db-pw:previous}}'.", stderr);
    }

    [Fact]
    public void SamePairTwice_OneLine()
    {
        var (exit, _, stderr) = Run(["tool", "-encodedCommand", Enc("{name}"), "-encodedCommand", Enc("{name}"), .. Tail]);

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.EncodedHint(new("{name}", null))), stderr);

        var (exit2, _, stderr2) = Run(["tool", "--password=", "-encodedCommand", Enc("{name}"), "-encodedCommand",
            Enc("{name}"), .. Tail]);

        Assert.Equal(1, exit2);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" +
            RunCommand.EncodedHint(new("{name}", "--password=")) + "\n" + RunCommand.EncodedHint(new("{name}", null))),
            stderr2);
    }

    public static TheoryData<string> NotOursCases =>
    [
        "no tail", "tail incomplete", "switch last before the tail", "invalid Base64", "odd byte count",
        "lone high surrogate", "Get-Date", "space in the name", "text after the brace", "final newline",
    ];

    private static string[] NotOursArgs(string name) => name switch
    {
        // The pair stays before the last four arguments, so only the tail check can reject these two.
        "no tail" => ["cmd", "/c", "echo", "-encodedCommand", "ewBuAGEAbQBlAH0A", "a", "b", "c", "d"],
        "tail incomplete" => ["cmd", "/c", "echo", "-encodedCommand", "ewBuAGEAbQBlAH0A", "END", "-inputFormat", "xml",
            "-outputFormat"],
        "switch last before the tail" => ["cmd", "/c", "echo", "-encodedCommand", .. Tail],
        "invalid Base64" => ["tool", "-encodedCommand", "!!!", .. Tail],
        "odd byte count" => ["tool", "-encodedCommand", Convert.ToBase64String("{\0a"u8), .. Tail],
        // A2: "{@a", a lone high surrogate (0x00 0xD8), "b}": a lax decoder makes it {@a�b}, a file token's shape.
        "lone high surrogate" => ["tool", "-encodedCommand", "ewBAAGEAANhiAH0A", .. Tail],
        "Get-Date" => ["tool", "-encodedCommand", Enc("Get-Date"), .. Tail],
        "space in the name" => ["tool", "-encodedCommand", Enc("{a b}"), .. Tail],
        "text after the brace" => ["tool", "-encodedCommand", Enc("{name}x"), .. Tail],
        "final newline" => ["tool", "-encodedCommand", Enc("{name}\n"), .. Tail],
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };

    [Theory]
    [MemberData(nameof(NotOursCases))]
    public void NotOurs_NoHint(string name)
    {
        var (exit, _, stderr) = Run(NotOursArgs(name));

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText), stderr);
    }

    [Fact]
    public void CaseInsensitiveSwitches()
    {
        var (exit, _, stderr) = Run("tool", "-EncodedCommand", Enc("{name}"), "-INPUTFORMAT", "XML", "-OUTPUTFORMAT", "TEXT");

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.EncodedHint(new("{name}", null))), stderr);
    }

    [Fact]
    public void ControlCharacters_ArePrintedSafely()
    {
        var (exit, _, stderr) = Run(["tool", "-encodedCommand", Enc("{@a\u001bb}"), .. Tail]);

        Assert.Equal(1, exit);
        Assert.Contains("{@a?b}", stderr);
        Assert.Contains("Quote it: '{{@a?b}}'.", stderr);
        // Ordinal: a culture-aware search ignores ESC and "finds" it at position 0.
        Assert.DoesNotContain("\u001b", stderr, StringComparison.Ordinal);
    }

    // ── tokens found: a warning, and the pair goes to the child as it is ─────────────────

    [Fact]
    public void WithRealToken_WarnsAndRuns()
    {
        DbVault();
        var other = Enc("{other}");

        var (exit, stdout, stderr) = Run(["tool", "{{db-pw}}", "{a}", "-encodedCommand", other, .. Tail]);

        Assert.True(exit == 0, stderr);
        var warning = RunCommand.EncodedWarning(new("{other}", null));
        Assert.Equal(
            "Warning: PowerShell passed an unquoted token {{other}} on as a script block (-encodedCommand ...); it is " +
            "passed on as it is. Quote it: '{{other}}'.", warning);
        Assert.Equal(1, Occurrences(stderr, warning));
        var bracesWarning = RunCommand.BracesWarning("{a}");
        var bracesAt = stderr.IndexOf(bracesWarning, StringComparison.Ordinal);
        Assert.True(bracesAt >= 0 && bracesAt < stderr.IndexOf(warning, StringComparison.Ordinal), stderr);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(["tool", DbValue, "{a}", "-encodedCommand", other, .. Tail], _pty.Argv!);
        Assert.DoesNotContain(DbValue, stdout);
        Assert.DoesNotContain(DbValue, stderr);
    }

    [Fact]
    public void BothForms_TogetherInOrder()
    {
        var (exit, _, stderr) = Run(["tool", "{a}", "-encodedCommand", Enc("{b}"), .. Tail]);

        Assert.Equal(1, exit);
        Assert.Equal(ErrorLine(RunCommand.NoTokensText + "\n" + RunCommand.BracesHint("{a}") + "\n" +
            RunCommand.EncodedHint(new("{b}", null))), stderr);
    }

    private static int Occurrences(string text, string part)
    {
        var count = 0;
        for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
}
