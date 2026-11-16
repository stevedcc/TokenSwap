using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T21 (#314): the commands that store a new value (<c>add</c>, <c>ingest</c>, <c>ingest --rotate</c>,
/// <c>create</c>, <c>rotate</c>) warn on stderr, after their success line, when that value is shorter than
/// 8 characters: redaction hides a value that short only where it stands as a whole word or number (brief T30), so
/// a secret that short can show inside a longer one. The warning names the secret and the reason only, never the
/// value or its length, and never refuses: exit 0, value stored.
/// </summary>
public sealed class ShortValueWarningTests : IDisposable
{
    private readonly FleetMachine _m = new("short-value", SimulatedYubiKeyService.WithKeys(SerialA));

    public ShortValueWarningTests() => InitRecordVault(_m);

    public void Dispose() => _m.Dispose();

    /// <summary>The exact line, written out here so the test pins the text (and its number) itself.</summary>
    private static string Warning(string name) =>
        $"Warning: the value of '{name}' is shorter than 8 characters. 'run', 'redact' and 'tocomment' hide a value this " +
        "short only where it stands as a whole word or number, not inside a longer one, so a secret this short can show " +
        "unmasked there. If it isn't a secret (a username, a port, a setting), store it as a field of the secret it belongs to.";

    private static string WarningLine(string name) => Warning(name) + Environment.NewLine;

    private static string WhitespaceWarningLine(string name) =>
        $"Warning: the value of '{name}' ends in whitespace (or is only whitespace). That is usually a paste mistake, and 'run' " +
        $"can't always mask such a value in a command's output. If it wasn't meant, run {TswapCli.ElevatedCommand.For("tswap", $"add {name}")} again." +
        Environment.NewLine;

    private (int Exit, string Out, string Err) Add(string name, string value) => _m.Run($"{value}\n{value}\n", "add", name);

    /// <summary>An existing secret (8 characters, so its own ingest warns about nothing) for the rotations.</summary>
    private void Existing(string name) => Assert.Equal("", _m.Run("old-value", "ingest", name).Err);

    // --- add ---

    [Fact]
    public void Add_SevenCharacters_Warns_StoresTheValue()
    {
        var (exit, _, err) = Add("s", "abcdefg");

        Assert.Equal(0, exit);
        Assert.Equal(WarningLine("s"), err);
        Assert.Equal("abcdefg", _m.Get("s"));
    }

    [Fact]
    public void Add_EightCharacters_NoWarning()
    {
        var (exit, _, err) = Add("s", "abcdefgh");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal("abcdefgh", _m.Get("s"));
    }

    /// <summary>Like the whitespace warning: the same short value again writes nothing, and still warns.</summary>
    [Fact]
    public void Add_SameShortValueAgain_StillWarns()
    {
        Add("s", "abcdefg");

        var (exit, _, err) = Add("s", "abcdefg");

        Assert.Equal(0, exit);
        Assert.Equal(WarningLine("s"), err);
    }

    [Fact]
    public void Add_ShortValueEndingInASpace_WhitespaceLineThenShortLine()
    {
        var (exit, _, err) = Add("s", "abc ");

        Assert.Equal(0, exit);
        Assert.Equal(WhitespaceWarningLine("s") + WarningLine("s"), err);
    }

    [Fact]
    public void Add_ShortValue_LeaksNoValue()
    {
        var (_, stdout, err) = Add("s", "qz7Wk2p");

        Assert.DoesNotContain("qz7Wk2p", stdout);
        Assert.DoesNotContain("qz7Wk2p", err);
        Assert.Equal(WarningLine("s"), err);
    }

    // --- ingest ---

    [Fact]
    public void Ingest_SevenCharacters_Warns_StoresTheValue()
    {
        var (exit, stdout, err) = _m.Run("abcdefg", "ingest", "s");

        Assert.Equal(0, exit);
        Assert.Contains("ingested from stdin", stdout);
        Assert.Equal(WarningLine("s"), err);
        Assert.Equal("abcdefg", _m.Get("s"));
    }

    [Fact]
    public void Ingest_EightCharacters_NoWarning()
    {
        var (exit, _, err) = _m.Run("abcdefgh", "ingest", "s");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal("abcdefgh", _m.Get("s"));
    }

    /// <summary>The value checked is the stored one, after ingest trims the trailing whitespace.</summary>
    [Fact]
    public void Ingest_EightCharactersWithTheTrailingNewlineTrimmedToSeven_Warns()
    {
        var (exit, _, err) = _m.Run("abcdefg \n", "ingest", "s");

        Assert.Equal(0, exit);
        Assert.Equal(WarningLine("s"), err);
        Assert.Equal("abcdefg", _m.Get("s"));
    }

    [Fact]
    public void Ingest_ShortValue_LeaksNoValue()
    {
        var (_, stdout, err) = _m.Run("qz7Wk2p", "ingest", "s");

        Assert.DoesNotContain("qz7Wk2p", stdout);
        Assert.DoesNotContain("qz7Wk2p", err);
        Assert.Equal(WarningLine("s"), err);
    }

    // --- ingest --rotate ---

    [Fact]
    public void IngestRotate_SevenCharacters_Warns_StoresTheValue()
    {
        Existing("s");

        var (exit, stdout, err) = _m.Run("abcdefg", "ingest", "--rotate", "s");

        Assert.Equal(0, exit);
        Assert.Contains("rotated", stdout);
        Assert.Equal(WarningLine("s"), err);
        Assert.Equal("abcdefg", _m.Get("s"));
    }

    [Fact]
    public void IngestRotate_EightCharacters_NoWarning()
    {
        Existing("s");

        var (exit, _, err) = _m.Run("abcdefgh", "ingest", "--rotate", "s");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal("abcdefgh", _m.Get("s"));
    }

    [Fact]
    public void IngestRotate_ShortValue_LeaksNoValue()
    {
        Existing("s");

        var (_, stdout, err) = _m.Run("qz7Wk2p", "ingest", "--rotate", "s");

        Assert.DoesNotContain("qz7Wk2p", stdout);
        Assert.DoesNotContain("qz7Wk2p", err);
        Assert.Equal(WarningLine("s"), err);
    }

    // --- create ---

    [Fact]
    public void Create_LengthSeven_Warns_StoresTheValue()
    {
        var (exit, stdout, err) = _m.Run("", "create", "s", "7");

        Assert.Equal(0, exit);
        Assert.Contains("created", stdout);
        Assert.Equal(WarningLine("s"), err);
        Assert.Equal(7, _m.Get("s").Length);
    }

    [Fact]
    public void Create_LengthEight_NoWarning()
    {
        var (exit, _, err) = _m.Run("", "create", "s", "8");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal(8, _m.Get("s").Length);
    }

    [Fact]
    public void Create_DefaultLength_NoWarning()
    {
        var (exit, _, err) = _m.Run("", "create", "s");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal(32, _m.Get("s").Length);
    }

    [Fact]
    public void Create_ShortValue_LeaksNoValue()
    {
        var (_, stdout, err) = _m.Run("", "create", "s", "7");

        var value = _m.Get("s");
        Assert.Equal(7, value.Length);
        Assert.DoesNotContain(value, stdout);
        Assert.DoesNotContain(value, err);
        Assert.Equal(WarningLine("s"), err);
    }

    // --- rotate ---

    [Fact]
    public void Rotate_LengthSeven_Warns_StoresTheValue()
    {
        Existing("s");

        var (exit, stdout, err) = _m.Run("", "rotate", "s", "7");

        Assert.Equal(0, exit);
        Assert.Contains("rotated", stdout);
        Assert.Equal(WarningLine("s"), err);
        Assert.Equal(7, _m.Get("s").Length);
    }

    [Fact]
    public void Rotate_LengthEight_NoWarning()
    {
        Existing("s");

        var (exit, _, err) = _m.Run("", "rotate", "s", "8");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal(8, _m.Get("s").Length);
    }

    [Fact]
    public void Rotate_DefaultLength_NoWarning()
    {
        Existing("s");

        var (exit, _, err) = _m.Run("", "rotate", "s");

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal(32, _m.Get("s").Length);
    }

    [Fact]
    public void Rotate_ShortValue_LeaksNoValue()
    {
        Existing("s");

        var (_, stdout, err) = _m.Run("", "rotate", "s", "7");

        var value = _m.Get("s");
        Assert.Equal(7, value.Length);
        Assert.DoesNotContain(value, stdout);
        Assert.DoesNotContain(value, err);
        Assert.Equal(WarningLine("s"), err);
    }

    // --- the agent prompt ---

    /// <summary>The new rule is appended as the last key rule (rules 1 to 11 keep their numbers).</summary>
    [Fact]
    public void Prompt_LastKeyRule_NeverStoreNonSecretSettings()
    {
        var text = TswapCore.Prompt.GetText("tswap");
        var start = text.IndexOf("## Key rules", StringComparison.Ordinal);
        var rules = text[start..text.IndexOf("## Keeping secrets out of config files", start, StringComparison.Ordinal)].ReplaceLineEndings("\n");
        var numbered = System.Text.RegularExpressions.Regex.Matches(rules, @"^(\d+)\. ", System.Text.RegularExpressions.RegexOptions.Multiline);

        Assert.Equal(Enumerable.Range(1, 12).Select(n => n.ToString()), numbered.Select(m => m.Groups[1].Value));
        var last = rules[numbered[^1].Index..].Trim();
        Assert.StartsWith("12. NEVER store usernames, ports, hostnames or other non-secret settings as secrets", last);
        Assert.EndsWith("get burned for no reason", last);
    }

    /// <summary>Brief T30: rule 12 says what redaction now does with a short value (whole words only).</summary>
    [Fact]
    public void Prompt_Rule12_SaysWholeWord()
    {
        var text = TswapCore.Prompt.GetText("tswap");
        var start = text.IndexOf("\n12. ", text.IndexOf("## Key rules", StringComparison.Ordinal), StringComparison.Ordinal);
        var end = text.IndexOf("\n## ", start, StringComparison.Ordinal);
        var rule = System.Text.RegularExpressions.Regex.Replace(text[start..end], @"\s+", " ");

        Assert.Contains("wherever it stands as a whole word or number", rule);
        Assert.DoesNotContain("also inside longer words", rule);
    }
}
