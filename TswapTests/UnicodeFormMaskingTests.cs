using System.Text;
using TswapCli;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T54 Task 3 (#400): a stored value is recognised in its stored, NFC and NFD spellings, base64 included, by
/// <c>redact</c>, <c>run</c> (its scanner and its token replacements) and the field guard rail. Every test string is
/// built from escapes, with characters from Unicode 3.2 or earlier, so every supported ICU normalises it alike.
/// </summary>
public sealed class UnicodeFormMaskingTests : IDisposable
{
    private const string Nfc = "caf\u00e9-secret-value";
    private const string Nfd = "cafe\u0301-secret-value";
    private const string BothLines = "nfc " + Nfc + " end\nnfd " + Nfd + " end\n";
    private const string Masked = "nfc [REDACTED: s] end\nnfd [REDACTED: s] end\n";

    private readonly FleetMachine _m = new("unicode-forms", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();
    private readonly string _work;

    public UnicodeFormMaskingTests()
    {
        VaultKey(_m, InitRecordVault(_m));
        _work = _m.PathOf("work");
        Directory.CreateDirectory(_work);
    }

    public void Dispose() => _m.Dispose();

    private string Redact(string input)
    {
        var path = Path.Combine(_work, "input.txt");
        // As Encoding.UTF8 writes it (a lone surrogate becomes U+FFFD, as the stored value's bytes do).
        File.WriteAllBytes(path, Encoding.UTF8.GetBytes(input));
        var (exit, stdout, err) = _m.Run("", "redact", path);
        Assert.True(exit == 0, err);
        return stdout;
    }

    /// <summary><c>run</c> through the recording PTY; returns what the child's output became.</summary>
    private string Run(string childOutput, params string[] args)
    {
        _pty.Child = _ => childOutput;
        var console = new FakeConsole("") { Interleaved = true };
        string[] command = ["run", .. args];
        var exit = CliRunner.Run(_m.Context(console, command) with { PtyRunner = () => _pty }, command);
        Assert.True(exit == 0, "run failed");
        return _pty.Output.ToString();
    }

    [Theory]
    [InlineData(Nfc)]
    [InlineData(Nfd)]
    public void Redact_BothSpellings_Masked(string stored)
    {
        _m.Ok(stored, "ingest", "s");

        Assert.Equal(Masked, Redact(BothLines));
    }

    [Fact]
    public void Redact_ACompositionExclusion_MaskedInItsNormalForm()
    {
        _m.Ok("\u0958-secret-value", "ingest", "s");

        Assert.Equal("[REDACTED: s]", Redact("\u0915\u093c-secret-value"));
    }

    [Fact]
    public void Redact_Base64OfTheOtherSpelling_MaskedWithTheBase64Label()
    {
        _m.Ok(Nfc, "ingest", "s");

        Assert.Equal("[REDACTED: s (base64)]", Redact(Convert.ToBase64String(Encoding.UTF8.GetBytes(Nfd))));
    }

    [Fact]
    public void Run_TokenPath_BothSpellings_Masked()
    {
        _m.Ok(Nfc, "ingest", "s");

        Assert.Equal(Masked, Run(BothLines, "tool", "{{s}}"));
    }

    [Fact]
    public void Run_ScannerPath_BothSpellings_Masked()
    {
        _m.Ok(Nfc, "ingest", "s");
        _m.Ok("other-ascii-value", "ingest", "other");

        Assert.Equal(Masked, Run(BothLines, "tool", "{{other}}"));
    }

    /// <summary>A value with whitespace: its NFD plain entry pairs with its own NFD stripped entry for the whitespace count.</summary>
    [Fact]
    public void Run_ScannerPath_NfdSpellingOfAValueWithASpace_Masked()
    {
        _m.Ok("p\u00e4ss w\u00f6rd-secret", "ingest", "s");
        _m.Ok("other-ascii-value", "ingest", "other");

        Assert.Equal("x [REDACTED: s] y\n", Run("x pa\u0308ss wo\u0308rd-secret y\n", "tool", "{{other}}"));
    }

    [Fact]
    public void FieldSet_TheOtherSpellingOfAStoredValue_Refused()
    {
        _m.Ok(Nfd, "ingest", "s");
        _m.Ok("db-value-123", "ingest", "db");

        var (exit, _, err) = _m.Run("", "field", "set", "db", "username=" + Nfc);

        Assert.NotEqual(0, exit);
        Assert.Contains("contains a stored secret value", err);
        Assert.DoesNotContain("username", _m.Ok("", "field", "show", "db"));
    }

    [Fact]
    public void Redact_ALoneSurrogateValue_MaskedWithoutAnException()
    {
        const string value = "x\uD800y-secret-value";
        _m.Ok(value + "\n" + value + "\n", "add", "s");

        Assert.Equal("[REDACTED: s]", Redact(value));
    }

    [Fact]
    public void Variants_HoldTheOtherSpelling_AndAsciiIsUnchanged()
    {
        var variants = Redaction.Variants("caf\u00e9");

        Assert.Contains("cafe\u0301", variants);
        Assert.Contains("Y2FmZcyB", variants);
        Assert.Equal(["abc", "YWJj"], Redaction.Variants("abc"));
    }
}
