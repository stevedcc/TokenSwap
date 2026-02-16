using TswapCore;
using Xunit;

namespace TswapTests;

public class PromptTests
{
    [Fact]
    public void GetText_SubstitutesPrefix()
    {
        var text = Prompt.GetText("tswap");
        Assert.Contains("`tswap create <name>", text);
        Assert.DoesNotContain("%CMD%", text);
    }

    [Fact]
    public void GetText_DifferentPrefixes()
    {
        var compiled = Prompt.GetText("tswap");
        var script = Prompt.GetText("./tswap.cs");

        Assert.Contains("tswap create", compiled);
        Assert.Contains("./tswap.cs create", script);
    }

    [Fact]
    public void GetHash_Deterministic()
    {
        var hash1 = Prompt.GetHash("tswap");
        var hash2 = Prompt.GetHash("tswap");
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void GetHash_DiffersForDifferentPrefix()
    {
        var hash1 = Prompt.GetHash("tswap");
        var hash2 = Prompt.GetHash("./tswap.cs");
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void GetHash_IsLowercaseHex()
    {
        var hash = Prompt.GetHash("tswap");
        Assert.Matches("^[0-9a-f]{64}$", hash);
    }

    [Fact]
    public void Template_ContainsKeyRules()
    {
        var text = Prompt.GetText("tswap");
        Assert.Contains("NEVER use sudo commands", text);
        Assert.Contains("burn", text);
        Assert.Contains("{{secret-name}}", text);
    }
}
