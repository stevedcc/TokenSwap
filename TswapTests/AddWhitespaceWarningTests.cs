using TswapCli;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 11 (owner decision 5): <c>sudo tswap add</c> stores a value exactly as typed,
/// and warns on stderr when it ends in whitespace (or is only whitespace): usually a paste mistake,
/// and <c>run</c> can't always mask such a value. The warning names the secret and the reason only,
/// never the value, its length or which whitespace; it never refuses.
/// </summary>
public sealed class AddWhitespaceWarningTests : IDisposable
{
    private readonly FleetMachine _m = new("add-whitespace", SimulatedYubiKeyService.WithKeys(SerialA));

    public AddWhitespaceWarningTests() => InitRecordVault(_m);

    public void Dispose() => _m.Dispose();

    private static string Warning(string name) =>
        $"Warning: the value of '{name}' ends in whitespace (or is only whitespace). That is usually a paste mistake, and 'run' " +
        $"can't always mask such a value in a command's output. If it wasn't meant, run {ElevatedCommand.For("tswap", $"add {name}")} again.";

    private (int Exit, string Out, string Err) Add(string name, string value) => _m.Run($"{value}\n{value}\n", "add", name);

    private string StoredValue(string name)
    {
        var (exit, stdout, err) = _m.Run("", "get", name);
        Assert.True(exit == 0, err);
        return stdout.ReplaceLineEndings("\n").TrimEnd('\n');
    }

    [Fact]
    public void Add_TrailingSpace_Warns_StoresAsTyped()
    {
        var (exit, _, err) = Add("s", "value ");

        Assert.Equal(0, exit);
        Assert.Equal(Warning("s") + Environment.NewLine, err);
        Assert.Equal("value ", StoredValue("s"));
    }

    [Fact]
    public void Add_WhitespaceOnly_Warns()
    {
        var (exit, _, err) = Add("s", "   ");

        Assert.Equal(0, exit);
        Assert.Equal(Warning("s") + Environment.NewLine, err);
    }

    [Fact]
    public void Add_TrailingTab_Warns()
    {
        var (exit, _, err) = Add("s", "v\t");

        Assert.Equal(0, exit);
        Assert.Equal(Warning("s") + Environment.NewLine, err);
        Assert.Equal("v\t", StoredValue("s"));
    }

    /// <summary>The same value again writes nothing, and still warns.</summary>
    [Fact]
    public void Add_SameValueAgain_StillWarns()
    {
        Add("s", "value ");

        var (exit, _, err) = Add("s", "value ");

        Assert.Equal(0, exit);
        Assert.Equal(Warning("s") + Environment.NewLine, err);
    }

    [Theory]
    [InlineData("value")]
    [InlineData(" leading")]
    [InlineData("in ner")]
    public void Add_NoTrailingWhitespace_NoWarning(string value)
    {
        var (exit, _, err) = Add("s", value);

        Assert.Equal(0, exit);
        Assert.Equal("", err);
        Assert.Equal(value, StoredValue("s"));
    }

    [Fact]
    public void Add_Warning_LeaksNoValueOrLength()
    {
        const string Value = "Zq7-distinctive-value-xY9 ";

        var (_, stdout, err) = Add("s", Value);

        foreach (var leak in new[] { Value, Value.Trim(), "Zq7", Value.Length.ToString(), (Value.Length - 1).ToString() })
        {
            Assert.DoesNotContain(leak, err);
            Assert.DoesNotContain(leak, stdout);
        }
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("a", false)]
    [InlineData(" a", false)]
    [InlineData("a ", true)]
    [InlineData("a\t", true)]
    [InlineData("a\u00A0", true)] // a no-break space, escaped so it stays visible and can't be normalised away
    [InlineData(" ", true)]
    [InlineData("\u00A0", true)]
    public void EndsInWhitespace(string value, bool expected) => Assert.Equal(expected, Validation.EndsInWhitespace(value));
}
