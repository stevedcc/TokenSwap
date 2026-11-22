using TswapCore;
using Xunit;
using SubstitutedToken = TswapCore.Validation.SubstitutedToken;

namespace TswapTests;

/// <summary>
/// Brief T47 Task 1: <see cref="Validation.BatchArgumentRefusal"/>, the pure check behind <c>run</c>'s refusal to pass
/// a value cmd.exe would parse again to a batch file (batch files re-parse arguments). Platform-independent, so it
/// runs on every OS; <c>run</c> calls it only when <c>ctx.Os</c> is Windows (RunBatchRefusalTests).
/// </summary>
public sealed class BatchArgumentTests
{
    private const string Name = "db-pw";

    /// <summary>A7, A15, A22: one value per character of the set, from the corpus where it has one.</summary>
    public static readonly IReadOnlyList<(string Case, string Value)> PerCharacter =
    [
        ("double-quote", EvilValues.Get("double-quote").Value),
        ("ampersand", EvilValues.Get("ampersand").Value),
        ("pipe", EvilValues.Get("pipe").Value),
        ("less-than", EvilValues.Get("less-than").Value),
        ("greater-than", EvilValues.Get("greater-than").Value),
        ("caret", Inside('^')),
        ("percent", EvilValues.Get("percent").Value),
        ("bang", EvilValues.Get("bang").Value),
        ("open-parenthesis", Inside('(')),
        ("close-parenthesis", Inside(')')),
        ("cr-inside", EvilValues.Get("cr-inside").Value),
        ("lf-inside", EvilValues.Get("lf-inside").Value),
    ];

    private static string Inside(char c) => "abcdefg" + c + "hijklmno";

    /// <summary>Every value the check must refuse: T46's batch cases and the per-character rows.</summary>
    private static IEnumerable<(string Case, string Value)> RefusedValues() =>
        EvilValues.BatchCases.Select(c => (c.Name, c.Value)).Concat(PerCharacter);

    private static string? Check(string value, params string[] argv)
    {
        var at = Array.IndexOf(argv, "{{" + Name + "}}");
        Assert.True(at >= 0, "the test's argv holds the token");
        var substituted = argv.ToArray();
        substituted[at] = value;
        return Validation.BatchArgumentRefusal(substituted, [new SubstitutedToken(Name, at, value)]);
    }

    public static TheoryData<string> BatchPrograms => ["x.cmd", "X.BAT", @"C:\dir\x.cmd", "cmd", "cmd.exe"];

    public static TheoryData<string> OtherPrograms => ["x.exe", "x.ps1", "powershell"];

    public static TheoryData<string> PerCharacterCases
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (var (name, _) in PerCharacter)
                data.Add(name);
            return data;
        }
    }

    [Theory]
    [MemberData(nameof(BatchPrograms))]
    public void EveryBatchCase_IsRefused_ForABatchTarget(string program)
    {
        List<string> allowed = [];
        foreach (var (caseName, value) in RefusedValues())
            if (Check(value, program, "{{" + Name + "}}") is null)
                allowed.Add(caseName);
        Assert.True(allowed.Count == 0, $"{program}: allowed {string.Join(", ", allowed)}");
    }

    [Theory]
    [MemberData(nameof(PerCharacterCases))]
    public void EachCharacterOfTheSet_IsRefused(string caseName)
    {
        var value = PerCharacter.Single(p => p.Case == caseName).Value;
        Assert.NotNull(Check(value, "x.cmd", "{{" + Name + "}}"));
    }

    [Fact]
    public void AValueWithoutThoseCharacters_IsAllowed() =>
        Assert.Null(Check("abc def-123_.", "x.cmd", "{{" + Name + "}}"));

    [Theory]
    [MemberData(nameof(OtherPrograms))]
    public void AnyValue_IsAllowed_ForOtherPrograms(string program)
    {
        List<string> refused = [];
        foreach (var (caseName, value) in RefusedValues())
            if (Check(value, program, "{{" + Name + "}}") is not null)
                refused.Add(caseName);
        Assert.True(refused.Count == 0, $"{program}: refused {string.Join(", ", refused)}");
    }

    [Fact]
    public void TheMessage_NamesTheSecret_NeverTheValue()
    {
        foreach (var (caseName, value) in RefusedValues())
        {
            var message = Check(value, "x.cmd", "{{" + Name + "}}");
            Assert.NotNull(message);
            Assert.True(message.Contains($"'{Name}'", StringComparison.Ordinal), $"{caseName}: {message}");
            Assert.True(message.Contains("batch file", StringComparison.Ordinal), $"{caseName}: {message}");
            Assert.False(message.Contains(value, StringComparison.Ordinal), $"{caseName}: the value is in the message");
            Assert.False(message.Contains("INJECTED", StringComparison.Ordinal), $"{caseName}: {message}");
        }
    }

    [Fact]
    public void TheMessage_IsTheBriefsText()
    {
        var message = Check(EvilValues.Get("ampersand").Value, "x.cmd", "{{" + Name + "}}");

        Assert.Equal(
            "Refused: tswap won't pass secret(s) 'db-pw' to a batch file. cmd.exe parses a batch file's arguments again, " +
            "and their values contain characters it interprets (one of \" & | < > ^ % ! ( ) or a line break; tswap's " +
            "generated values often do). Use a PowerShell script ('run powershell -File .\\script.ps1 {{db-pw}}', read as " +
            "$args[0]), or the environment ('run --env PW={{db-pw}} script.cmd', read with setlocal EnableDelayedExpansion " +
            "as !PW!).",
            message);
    }

    // ── A4: the program name, normalised as Windows does ──────────────────────────────────

    [Theory]
    [InlineData("x.cmd")]
    [InlineData("x.cmd.")]
    [InlineData("x.cmd ")]
    [InlineData("x.cmd...")]
    [InlineData("x.cmd::$DATA")]
    [InlineData("CMD.EXE")]
    [InlineData("X.BAT")]
    [InlineData(@"C:\dir\x.cmd")]
    [InlineData("C:x.cmd")]
    [InlineData("./x.bat")]
    [InlineData("cmd")]
    public void IsBatchTarget_True(string program) => Assert.True(Validation.IsBatchTarget(program));

    [Theory]
    [InlineData("x.exe")]
    [InlineData("x.ps1")]
    [InlineData("powershell")]
    [InlineData("x.cmdx")]
    [InlineData("xcmd")]
    [InlineData(@"C:\cmd.d\tool.exe")]
    [InlineData("cmdlet")]
    public void IsBatchTarget_False(string program) => Assert.False(Validation.IsBatchTarget(program));

    // ── A1, A5, A13, A20, A21: every program word of the walk, and PowerShell's -File script ─────────

    public static TheoryData<string[]> RefusedCommands => new()
    {
        new[] { "x.cmd", "{{" + Name + "}}" },
        new[] { @"C:\dir\x.cmd", "{{" + Name + "}}" },
        new[] { "timeout", "5", "x.cmd", "{{" + Name + "}}" },
        new[] { "nohup", "x.bat", "{{" + Name + "}}" },
        new[] { "find", ".", "-exec", "x.cmd", "{{" + Name + "}}", ";" },
        new[] { "powershell", "-File", "x.cmd", "{{" + Name + "}}" },
        new[] { "pwsh", "-NoProfile", "-File", "x.cmd", "{{" + Name + "}}" },
        new[] { "powershell", "-f", "x.cmd", "{{" + Name + "}}" },
        new[] { "powershell", "-fi", "x.cmd", "{{" + Name + "}}" },
        new[] { "powershell", "-fil", "x.cmd", "{{" + Name + "}}" },
        new[] { "powershell", "-FILE", "x.bat", "{{" + Name + "}}" },
        new[] { "timeout", "5", "powershell", "-File", "x.cmd", "{{" + Name + "}}" },
    };

    [Theory]
    [MemberData(nameof(RefusedCommands))]
    public void ABatchTargetAnywhereInTheWalk_IsRefused(string[] argv) =>
        Assert.NotNull(Check(EvilValues.Get("ampersand").Value, argv));

    public static TheoryData<string[]> AllowedCommands => new()
    {
        new[] { "powershell", "-File", "x.ps1", "{{" + Name + "}}" },
        new[] { "pwsh", "-f", "x.ps1", "{{" + Name + "}}" },
        new[] { "timeout", "5", "x.exe", "{{" + Name + "}}" },
        // A1: an unknown wrapper is out of reach, as for every other check.
        new[] { "wrapper.exe", "x.cmd", "{{" + Name + "}}" },
        // A batch file named as data to a program that isn't a wrapper.
        new[] { "tool.exe", "--script", "x.cmd", "{{" + Name + "}}" },
    };

    [Theory]
    [MemberData(nameof(AllowedCommands))]
    public void NoBatchTargetInTheWalk_IsAllowed(string[] argv) =>
        Assert.Null(Check(EvilValues.Get("ampersand").Value, argv));

    [Fact]
    public void ProgramPositions_KeepTheRawWord()
    {
        // A20: the walk yields positions, so the .cmd is intact where ProgramWords strips it.
        string[] wrapped = ["timeout", "5", "x.cmd", "a"];
        string[] found = ["find", ".", "-exec", @"C:\dir\x.cmd", "{}", ";"];

        Assert.Equal(new[] { 0, 2 }, Validation.ProgramPositions(wrapped));
        Assert.Equal(new[] { 0, 3 }, Validation.ProgramPositions(found));
        Assert.Equal(new[] { "timeout", "x" }, Validation.ProgramWords(wrapped));
        Assert.Equal(@"C:\dir\x.cmd", found[Validation.ProgramPositions(found).Last()]);
    }

    // ── A2, A8, A14, A26: file tokens, several tokens, argv order ─────────────────────────

    [Fact]
    public void AFileTokenPath_WithACharacterOfTheSet_IsRefused_NamingTheFile()
    {
        var copy = Path.Combine("tmp", "tswap-files", "a&b.yaml");
        var message = Validation.BatchArgumentRefusal(["x.cmd", copy], [new SubstitutedToken("a&b.yaml", 1, copy, IsFile: true)]);

        Assert.Equal(
            "Refused: tswap won't pass the copy of 'a&b.yaml' to a batch file: its name contains characters cmd.exe " +
            "interprets (one of \" & | < > ^ % ! ( ) or a line break). Rename the file.",
            message);
    }

    [Fact]
    public void AFileTokenPath_WithoutThoseCharacters_IsAllowed()
    {
        var copy = Path.Combine("tmp", "tswap-files", "values.yaml");
        Assert.Null(Validation.BatchArgumentRefusal(["x.cmd", copy], [new SubstitutedToken("values.yaml", 1, copy, IsFile: true)]));
    }

    [Fact]
    public void SeveralSecrets_AreNamedInArgvOrder_OnlyTheRefusedOnes()
    {
        var amp = EvilValues.Get("ampersand").Value;
        var bang = EvilValues.Get("bang").Value;
        string[] argv = ["x.cmd", bang, "plain-value", amp];
        var message = Validation.BatchArgumentRefusal(argv,
        [
            new SubstitutedToken("zeta", 1, bang),
            new SubstitutedToken("plain", 2, "plain-value"),
            new SubstitutedToken("alpha", 3, amp),
        ]);

        Assert.NotNull(message);
        Assert.StartsWith("Refused: tswap won't pass secret(s) 'zeta', 'alpha' to a batch file.", message);
        Assert.Contains("'run powershell -File .\\script.ps1 {{zeta}}'", message);
        Assert.Contains("'run --env PW={{zeta}} script.cmd'", message);
        Assert.DoesNotContain("plain", message);
    }

    [Fact]
    public void ASecretUsedTwice_IsNamedOnce()
    {
        var amp = EvilValues.Get("ampersand").Value;
        var message = Validation.BatchArgumentRefusal(["x.cmd", amp, amp],
            [new SubstitutedToken(Name, 1, amp), new SubstitutedToken(Name, 2, amp)]);

        Assert.StartsWith($"Refused: tswap won't pass secret(s) '{Name}' to a batch file.", message);
    }

    [Fact]
    public void AMixedRefusal_UsesTheSecretsClause_AndAppendsRenameTheFile()
    {
        var amp = EvilValues.Get("ampersand").Value;
        var copy = Path.Combine("tmp", "c%d.yaml");
        var message = Validation.BatchArgumentRefusal(["x.cmd", copy, amp],
            [new SubstitutedToken("c%d.yaml", 1, copy, IsFile: true), new SubstitutedToken(Name, 2, amp)]);

        Assert.NotNull(message);
        Assert.StartsWith($"Refused: tswap won't pass secret(s) '{{{{@c%d.yaml}}}}', '{Name}' to a batch file.", message);
        Assert.Contains($"{{{{{Name}}}}}", message);
        Assert.EndsWith(" Rename the file.", message);
        Assert.DoesNotContain(amp, message);
    }

    [Fact]
    public void SubstitutedTokens_ListsEachTokenWithItsArgvIndex_InOrder()
    {
        string[] args = ["x.cmd", "--a={{a}}", "{{@f.yaml}}", "{{b}}{{a:previous}}"];
        var tokens = Validation.SubstitutedTokens(args,
            new Dictionary<string, string> { ["a"] = "va", ["b"] = "vb", ["a:previous"] = "vp" },
            new Dictionary<string, string> { ["f.yaml"] = "/tmp/f.yaml" });

        Assert.Equal(
        [
            new SubstitutedToken("a", 1, "va"),
            new SubstitutedToken("f.yaml", 2, "/tmp/f.yaml", IsFile: true),
            new SubstitutedToken("b", 3, "vb"),
            new SubstitutedToken("a:previous", 3, "vp"),
        ], tokens);
    }
}
