using System.Text;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T55 Task 3 (#402): <see cref="MsysTarget.QuoteArguments"/> (each argument one word of MSYS2's command-line
/// parser, never split, never an @file, never expanded) and <see cref="MsysTarget.Refusal"/> (R1 the glob option (and an
/// unclosed quote in <c>MSYS</c>), R2 a locale that isn't UTF-8, R3 U+F000-U+F0FF, R4 an argument over 8,000 bytes).
/// </summary>
public class MsysQuotingTests
{
    public static TheoryData<string[], string> QuoteRows => new()
    {
        { ["abc"], "\"abc\"" },
        { [""], "\"\"" },
        { ["a b"], "\"a b\"" },
        { ["a\\b"], "\"a\\\\b\"" },
        { ["a\\\\b"], "\"a\\\\\\\\b\"" },
        { ["a\\"], "\"a\\\\\"" },
        { ["a\"b"], "\"a\\\"b\"" },
        { ["a\\\"b"], "\"a\\\\\\\"b\"" },
        { ["'"], "\"'\"" },
        { ["{{x}}"], "\"{{x}}\"" },
        { ["@f"], "\"@f\"" },
        { ["*"], "\"*\"" },
        { ["a\nb"], "\"a\nb\"" },
        { ["./capture.sh", "a\"b"], "\"./capture.sh\" \"a\\\"b\"" },
    };

    [Theory]
    [MemberData(nameof(QuoteRows))]
    public void QuoteArguments_QuotesEachArgument_EscapingBackslashAndQuote(string[] arguments, string expected) =>
        Assert.Equal(expected, MsysTarget.QuoteArguments(arguments));

    /// <summary>Brief T55 Task 1's values (spike round 2), beside the corpus.</summary>
    private static readonly string[] SpikeValues =
    [
        "a\\b", "a\\\\b", "a\\\\\\b", "a\\", "a\\\\", "\\", "\\\"", "a\\\"b", "a\\\\\"b", "\"", "\"\"",
        "a\"\"b", "C:\\x\\y", "C:\\x\"y\\", "c:\"x", "\\\\srv\\share\\x", "@at-file.txt", "@missing-file", "~",
        "~/x", "*", "abc*def-value-2", "[ab]-value", "{a,b}-value", "a b", "a\tb", "a\nb", "a\rb",
        "a\r\nb", "a\vb", "a\fb", "caf\u00E9", "\u8868x", "\u30BDx", "x\uF022 \uF020y", "x\uF02Ay",
        "x\uF080y", "",
    ];

    /// <summary>
    /// MSYS2's word rules (brief T55, "MSYS2's parser", rules 2 and 4) for a command line made only of double-quoted runs:
    /// a word ends at an unquoted space, tab, CR or LF; inside <c>"</c>, <c>\\</c> is <c>\</c>, <c>\"</c> is <c>"</c> and
    /// any other <c>\</c> stays. Anything outside quotes other than a separator is kept as is.
    /// </summary>
    private static List<string> DecodeMsys(string commandLine)
    {
        List<string> words = [];
        StringBuilder? word = null;
        var quoted = false;
        for (var i = 0; i < commandLine.Length; i++)
        {
            var c = commandLine[i];
            if (quoted)
            {
                if (c == '\\' && i + 1 < commandLine.Length && commandLine[i + 1] is '\\' or '"')
                    word!.Append(commandLine[++i]);
                else if (c == '"')
                    quoted = false;
                else
                    word!.Append(c);
            }
            else if (c is ' ' or '\t' or '\r' or '\n')
            {
                if (word is not null)
                    words.Add(word.ToString());
                word = null;
            }
            else
            {
                word ??= new StringBuilder();
                if (c == '"')
                    quoted = true;
                else
                    word.Append(c);
            }
        }
        if (word is not null)
            words.Add(word.ToString());
        return words;
    }

    [Fact]
    public void QuoteArguments_DecodesBackToTheValue_ForEveryCorpusAndSpikeValue()
    {
        var values = EvilValues.Cases.Concat(EvilValues.BatchCases).Select(c => c.Value).Concat(SpikeValues).ToList();
        List<string> failures = [];
        foreach (var value in values)
        {
            var decoded = DecodeMsys(MsysTarget.QuoteArguments(["./capture.sh", value]));
            if (decoded is not ["./capture.sh", var only] || only != value)
                failures.Add($"[{value}] decoded as {decoded.Count} word(s): [{string.Join("] [", decoded)}]");
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private static string? Refuse(string[] arguments, Dictionary<string, string>? variables = null,
        IReadOnlyList<Validation.SubstitutedToken>? tokens = null)
    {
        Dictionary<string, string> vars = new(variables ?? [], StringComparer.OrdinalIgnoreCase);
        return MsysTarget.Refusal(arguments, tokens ?? [], name => vars.GetValueOrDefault(name));
    }

    private const string R1Start = "Refused: MSYS changes the glob option and an argument holds a backslash or double quote";
    private const string R2Start = "Refused: the locale (LC_ALL, LC_CTYPE or LANG) is not UTF-8";
    private const string R3Middle = "holds a character from U+F000 to U+F0FF";

    [Theory]
    [InlineData("MSYS", "noglob", "a\\b", true)]
    [InlineData("MSYS", "noglob", "abc", false)]
    [InlineData("MSYS", "winsymlinks:nativestrict", "a\\b", false)]
    // Brief T55 amendment 14 (spike round 3): a non-empty value with no prefix leaves globbing on; no longer refused.
    [InlineData("msys", "GLOB:ignorecase", "a\"b", false)]
    [InlineData("MSYS", "glob", "a\\b", false)]
    [InlineData("MSYS", "winsymlinks:native  NoGlob", "a\\b", true)]
    public void Refusal_R1_TheGlobOptionChanged_AndABackslashOrQuote(string name, string value, string argument, bool refused)
    {
        var text = Refuse([argument], new() { [name] = value });

        if (refused)
            Assert.StartsWith(R1Start, text);
        else
            Assert.Null(text);
    }

    /// <summary>
    /// Brief T55 amendment 14: every MSYS spelling spike round 3 measured with <c>a\b</c> and <c>a"b</c>, and amendment
    /// 16's rows (a word cut at a quote), and whether R1 refuses it: globbing off (both arrived altered) refuses; globbing on (both arrived exactly) does not, except
    /// the accepted over-refusals (<c>nonoglob</c>, <c>--glob</c>, <c>no-glob</c>, <c>"no"glob</c>: fail closed). Null
    /// is <c>MSYS</c> unset.
    /// </summary>
    public static TheoryData<string?, bool> MsysSpellings => new()
    {
        // Globbing off (measured): refused.
        { "noglob", true },
        { "-glob", true },
        { "glob=", true },
        { "glob:", true },
        { "noglob:", true },
        { "noglob=", true },
        { "\"noglob\"", true },
        { "\"glob:\"", true },
        { "NOGLOB", true },
        { "Glob:", true },
        { "glob:\"\"", true },
        { "  noglob", true },
        { "noglob  ", true },
        { "winsymlinks:nativestrict noglob", true },
        { "winsymlinks:nativestrict\tnoglob", true }, // the rule splits at tabs too
        // Globbing on (measured), refused anyway: the accepted over-refusals.
        { "nonoglob", true },
        { "--glob", true },
        { "no-glob", true },
        { "\"no\"glob", true },
        // Globbing on (measured): allowed.
        { null, false },
        { "glob", false },
        { "glob:normal", false },
        { "glob=normal", false },
        { "glob:ignorecase", false },
        { "glob=ignorecase", false },
        { "glob:off", false },
        { "glob:no", false },
        { "glob:false", false },
        { "winsymlinks:nativestrict", false },
        // Amendment 16 (MiMo round 2 I1): MSYS2's strbrk also ends a token at a closing quote mid-word, so every
        // contiguous run of quote-split pieces is judged. Globbing off through such a cut: refused.
        { "glob:\"\":x", true },
        { "glob:\"\"x", true },
        { "glob=\"\":x", true },
        { "\"glob:\"\":x", true },
        { "noglob\"\"x", true },
        // Accepted over-refusal: its run glob: has an empty value.
        { "glob:\"x\"", true },
        // No run changes the option: allowed.
        { "\"glob:ignorecase\"", false },
    };

    [Theory]
    [MemberData(nameof(MsysSpellings))]
    public void Refusal_R1_FollowsMsys2sSpellingsOfTheGlobOption(string? msys, bool refused)
    {
        Dictionary<string, string> variables = msys is null ? [] : new() { ["MSYS"] = msys };

        foreach (var argument in new[] { "a\\b", "a\"b" })
        {
            var text = Refuse([argument], variables);
            if (refused)
                Assert.StartsWith(R1Start, text);
            else
                Assert.Null(text);
        }
        Assert.Null(Refuse(["abc*def"], variables));
    }

    // ── Brief T62 Task 2 (#427): the linear R1 scan and an unclosed quote in MSYS ─────────────────────────────

    /// <summary>
    /// The oracle: the run model as T55 wrote it (dcc4c04 <c>MsysTarget.cs:183-215</c>, copied verbatim), quadratic in
    /// the pieces and cubic in characters. <see cref="MsysTarget.ChangesGlobOption"/> must give its verdict for every word.
    /// </summary>
    private static bool WordChangesGlobOption(string word)
    {
        var pieces = word.Split('"');
        for (var first = 0; first < pieces.Length; first++)
        for (var last = first; last < pieces.Length; last++)
            if (RunChangesGlobOption(string.Concat(pieces[first..(last + 1)])))
                return true;
        return false;
    }

    private static bool RunChangesGlobOption(string run)
    {
        var rest = run.AsSpan();
        var prefixed = false;
        while (true)
        {
            if (rest.StartsWith("no", StringComparison.OrdinalIgnoreCase))
                rest = rest[2..];
            else if (rest.StartsWith('-'))
                rest = rest[1..];
            else
                break;
            prefixed = true;
        }
        if (!rest.StartsWith("glob", StringComparison.OrdinalIgnoreCase))
            return false;
        rest = rest[4..];
        if (rest.IsEmpty)
            return prefixed;
        if (rest[0] is not (':' or '='))
            return false;
        return prefixed || rest.Length == 1;
    }

    private static readonly string[] ModelTokens = ["no", "NO", "-", "glob", "GLOB", "gl", "ob", ":", "=", "\"", "x", "n", "o"];

    /// <summary>
    /// Every word of one to five of <see cref="ModelTokens"/> (402,233 words): the linear scan gives the run model's
    /// verdict. A mismatch names the word.
    /// </summary>
    [Fact]
    public void ChangesGlobOption_AgreesWithTheRunModel()
    {
        var words = new List<string>(402_233);
        void Build(string prefix, int depth)
        {
            if (depth == 0)
                return;
            foreach (var token in ModelTokens)
            {
                words.Add(prefix + token);
                Build(prefix + token, depth - 1);
            }
        }
        Build("", 5);

        var mismatches = words.Where(w => MsysTarget.ChangesGlobOption(w, null) != WordChangesGlobOption(w)).Take(20).ToList();

        Assert.Equal(402_233, words.Count);
        Assert.True(mismatches.Count == 0,
            "The linear scan disagrees with the run model on: " + string.Join(", ", mismatches.Select(w => $"'{w}' (model: {WordChangesGlobOption(w)})")));
    }

    public static TheoryData<string> LinearRows => ["quote x 10000", "-quote x 5000", "no-quote x 3333", "glob:quote x 2000", "random 10000"];

    private static (string Msys, bool? Verdict) LinearInput(string row) => row switch
    {
        "quote x 10000" => (string.Concat(Enumerable.Repeat("\"", 10_000)), false),
        "-quote x 5000" => (string.Concat(Enumerable.Repeat("-\"", 5_000)), false),
        "no-quote x 3333" => (string.Concat(Enumerable.Repeat("no\"", 3_333)), false),
        "glob:quote x 2000" => (string.Concat(Enumerable.Repeat("glob:\"", 2_000)), true), // glob: is a run ending at a quote
        "random 10000" => (RandomMsys(), null),
        _ => throw new ArgumentOutOfRangeException(nameof(row), row, null),
    };

    private static string RandomMsys()
    {
        const string alphabet = "no-glob:=\"x ";
        var random = new Random(62);
        return new string([.. Enumerable.Range(0, 10_000).Select(_ => alphabet[random.Next(alphabet.Length)])]);
    }

    [Theory]
    [MemberData(nameof(LinearRows))]
    public void ChangesGlobOption_IsLinear(string row)
    {
        var (msys, verdict) = LinearInput(row);
        long steps = 0;

        var changes = MsysTarget.ChangesGlobOption(msys, () => steps++);

        Assert.True(steps <= 4L * (msys.Length + 1), $"{steps} steps for {msys.Length} characters (bound {4L * (msys.Length + 1)}).");
        if (verdict is { } expected)
            Assert.Equal(expected, changes);
    }

    private const string UnclosedStart = "Refused: MSYS holds a double quote that is never closed";

    [Theory]
    [InlineData("\"winsymlinks:native", true)]
    [InlineData("winsymlinks:native \"x", true)]
    [InlineData("x\"", true)]
    [InlineData("\\\"", true)]
    [InlineData("\"a b", true)]
    [InlineData("a \"b", true)]
    [InlineData("\"a\\\"", true)]
    [InlineData("\"\\\\\"", true)]
    [InlineData("\"a\\\"b\"", false)]
    [InlineData("\"a\"", false)]
    [InlineData("\"\"", false)]
    [InlineData("a\"b\"c", false)]
    [InlineData("\"a b\"", false)]
    [InlineData(null, false)]
    [InlineData("winsymlinks:native", false)]
    public void Refusal_R1_AnUnclosedQuoteInMsys(string? msys, bool refused)
    {
        Dictionary<string, string> variables = msys is null ? [] : new() { ["MSYS"] = msys };

        var text = Refuse(["a\\b"], variables);

        if (refused)
            Assert.StartsWith(UnclosedStart, text);
        else
            Assert.Null(text);
        Assert.Null(Refuse(["abc"], variables));
    }

    [Fact]
    public void Refusal_R1_GlobBeforeUnclosedQuote()
    {
        Dictionary<string, string> variables = new() { ["MSYS"] = "\"noglob" };

        Assert.StartsWith(R1Start, Refuse(["a\\b"], variables));
        Assert.Null(Refuse(["abc"], variables));
    }

    public static TheoryData<Dictionary<string, string>, string, bool> LocaleRows => new()
    {
        { new() { ["LANG"] = "ja_JP.SJIS" }, "caf\u00E9", true },
        { new() { ["LANG"] = "ja_JP.SJIS" }, "abc", false },
        { new() { ["LC_ALL"] = "", ["LANG"] = "de_DE" }, "\u00E9", true },
        { new() { ["LC_ALL"] = "C.UTF-8" }, "\u00E9", false },
        { new() { ["LC_ALL"] = "C.UTF-8", ["LANG"] = "ja_JP.SJIS" }, "\u00E9", false },
        { new() { ["LANG"] = "en_US.utf8" }, "\u00E9", false },
        { new() { ["LANG"] = "C" }, "\u00E9", false },
        { new() { ["LANG"] = "POSIX" }, "\u00E9", false },
        { new(), "\u00E9", false },
        { new() { ["LC_CTYPE"] = "en_GB.UTF-8@euro" }, "\u00E9", false },
        { new() { ["LC_CTYPE"] = "en_GB.ISO-8859-1", ["LANG"] = "en_GB.UTF-8" }, "\u00E9", true },
    };

    [Theory]
    [MemberData(nameof(LocaleRows))]
    public void Refusal_R2_ALocaleThatIsNotUtf8_AndANonAsciiArgument(Dictionary<string, string> variables, string argument, bool refused)
    {
        var text = Refuse([argument], variables);

        if (refused)
            Assert.StartsWith(R2Start, text);
        else
            Assert.Null(text);
    }

    [Theory]
    [InlineData("x\uF022y", true)]
    [InlineData("x\uF0FFy", true)]
    [InlineData("x\uF000y", true)]
    [InlineData("x\uEFFFy", false)]
    [InlineData("x\uF100y", false)]
    public void Refusal_R3_APrivateUseCharacterOlderRuntimesTurnIntoAscii(string argument, bool refused)
    {
        var text = Refuse([argument]);

        if (refused)
            Assert.Equal(
                "Refused: an argument holds a character from U+F000 to U+F0FF, which older MSYS2 runtimes turn into ASCII such as a " +
                "quote or a space before reading the command line. Pass the secret in the environment " +
                "('run --env PW={{name}} -- <bash.exe> ./script.sh', read as \"$PW\").",
                text);
        else
            Assert.Null(text);
    }

    [Fact]
    public void Refusal_RulesInOrder_R1BeforeR2BeforeR3()
    {
        Dictionary<string, string> all = new() { ["MSYS"] = "noglob", ["LANG"] = "de_DE" };

        Assert.StartsWith(R1Start, Refuse(["a\\\u00E9\uF022"], all));
        Assert.StartsWith(R2Start, Refuse(["\u00E9\uF022"], all));
        Assert.Contains(R3Middle, Refuse(["\uF022"], new() { ["MSYS"] = "noglob" }));
    }

    private const string R4Middle = "is longer than 8,000 bytes";

    public static TheoryData<string, bool> LengthRows => new()
    {
        // Brief T55 amendment 13: R4 counts UTF-8 bytes (spike round 3: a longer quoted word is cut without an error).
        { new string('a', 8000), false },
        { new string('\u00E9', 4000), false }, // 8,000 bytes
        { new string('a', 8001), true },
        { new string('\u00E9', 4001), true }, // 8,002 bytes
    };

    [Theory]
    [MemberData(nameof(LengthRows))]
    public void Refusal_R4_AnArgumentLongerThan8000BytesInUtf8(string argument, bool refused)
    {
        var text = Refuse([argument]);

        if (refused)
            Assert.Equal(
                "Refused: an argument is longer than 8,000 bytes, and Git Bash (MSYS2) cuts a longer argument without an error, so " +
                "tswap can't pass it exactly. Pass the secret in the environment " +
                "('run --env PW={{name}} -- <bash.exe> ./script.sh', read as \"$PW\").",
                text);
        else
            Assert.Null(text);
    }

    [Fact]
    public void Refusal_RulesInOrder_R4AfterR1R2AndR3()
    {
        Dictionary<string, string> all = new() { ["MSYS"] = "noglob", ["LANG"] = "de_DE" };
        var tooLong = new string('a', 8001);

        Assert.StartsWith(R1Start, Refuse(["a\\\u00E9\uF022" + tooLong], all));
        Assert.StartsWith(R2Start, Refuse(["\u00E9\uF022" + tooLong], all));
        Assert.Contains(R3Middle, Refuse(["\uF022" + tooLong], new() { ["MSYS"] = "noglob" }));
        Assert.Contains(R4Middle, Refuse([tooLong], all));
    }

    [Fact]
    public void Refusal_R4_NamesTheTokensInTheLongArgument_AndNeverHoldsTheValue()
    {
        var value = string.Concat(Enumerable.Repeat("k7Qz-long-", 801)); // 8,010 bytes
        Validation.SubstitutedToken[] tokens = [new("short", 1, "abc"), new("pw", 2, value)];

        var text = Refuse(["abc", value], tokens: tokens);

        Assert.NotNull(text);
        Assert.StartsWith("Refused: the argument(s) from 'pw' " + R4Middle, text);
        Assert.DoesNotContain("k7Qz", text);
    }

    [Fact]
    public void Refusal_R4_TheProgramIsNotAnArgument()
    {
        // Amendment 6: the arguments exclude the program, so a long program (a token at ArgIndex 0) is never measured.
        Validation.SubstitutedToken[] tokens = [new("prog", 0, new string('p', 9000))];

        Assert.Null(Refuse(["abc"], tokens: tokens));
    }

    [Fact]
    public void Refusal_TheProgramIsNotAnArgument_NorAProgramToken()
    {
        // Brief T55 amendment 6: the arguments exclude the program; a token in it (ArgIndex 0) is never named.
        Validation.SubstitutedToken[] tokens = [new("prog", 0, "C:\\x\\b\u00E9sh.exe"), new("pw", 2, "\u00E9")];

        var text = Refuse(["./s.sh", "\u00E9"], new() { ["LANG"] = "de_DE" }, tokens);

        Assert.Equal(
            "Refused: the locale (LC_ALL, LC_CTYPE or LANG) is not UTF-8, and in it Git Bash (MSYS2) can read part of a non-ASCII " +
            "character as a backslash, so tswap can't pass the argument(s) from 'pw' exactly. Use a UTF-8 locale for this command, " +
            "or pass the secret in the environment ('run --env PW={{name}} -- <bash.exe> ./script.sh', read as \"$PW\").",
            text);
    }

    [Fact]
    public void Refusal_NamesEveryTokenWhoseTextHoldsTheTrigger_InArgvOrder_EachOnce_FilesAsTokens()
    {
        Validation.SubstitutedToken[] tokens =
        [
            new("plain", 1, "abc"),
            new("pw", 2, "a\\b"),
            new("f.yaml", 3, "C:\\Temp\\tswap-x\\f.yaml", IsFile: true),
            new("pw", 4, "a\\b"),
            new("other", 4, "c\"d"),
        ];

        var text = Refuse(["abc", "a\\b", "C:\\Temp\\tswap-x\\f.yaml", "a\\bc\"d"], new() { ["MSYS"] = "noglob" }, tokens);

        Assert.Equal(
            R1Start + "; with that option Git Bash (MSYS2) reads backslashes and double quotes in its arguments differently, so " +
            "tswap can't pass the argument(s) from 'pw', '{{@f.yaml}}', 'other' exactly. Remove the glob option from MSYS for " +
            "this command, or pass the secret in the environment ('run --env PW={{name}} -- <bash.exe> ./script.sh', read as \"$PW\").",
            text);
    }

    [Fact]
    public void Refusal_SaysAnArgument_WhenNoTokensTextHoldsTheTrigger()
    {
        var text = Refuse(["./s.sh", "lit\u00E9ral", "abc"], new() { ["LANG"] = "ja_JP.SJIS" }, [new("pw", 2, "abc")]);

        Assert.Contains("so tswap can't pass an argument exactly.", text);
        Assert.DoesNotContain("'pw'", text);
    }

    [Fact]
    public void Refusal_NeverHoldsTheValue_AVariablesValue_OrTheCharacter()
    {
        const string value = "a\"b$c&d'e\u00E9\uF022";
        Validation.SubstitutedToken[] tokens = [new("pw", 2, value)];
        (Dictionary<string, string> Vars, string Start)[] cases =
        [
            (new() { ["MSYS"] = "noglob" }, R1Start),
            (new() { ["MSYS"] = "\"winsymlinks:native" }, UnclosedStart),
            (new() { ["LANG"] = "ja_JP.SJIS" }, R2Start),
            (new(), "Refused: the argument(s) from 'pw' " + R3Middle),
        ];

        foreach (var (vars, start) in cases)
        {
            var text = Refuse(["./s.sh", value], vars, tokens);
            Assert.NotNull(text);
            Assert.StartsWith(start, text);
            Assert.DoesNotContain(value, text);
            Assert.DoesNotContain("\u00E9", text);
            Assert.DoesNotContain("\uF022", text);
            Assert.DoesNotContain("noglob", text);
            Assert.DoesNotContain("SJIS", text);
            Assert.DoesNotContain("winsymlinks", text);
        }
    }
}
