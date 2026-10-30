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
        var defaultPrefix = Prompt.GetText("tswap");
        var renamed = Prompt.GetText("mytswap");

        Assert.Contains("tswap create", defaultPrefix);
        Assert.Contains("mytswap create", renamed);
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
        var hash2 = Prompt.GetHash("mytswap");
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

    [Fact]
    public void Template_ListsTheKeyringSudoCommandsUnderNever()
    {
        // T5 review: slot add, slot merge and recover each add a way to decrypt the vault.
        var text = Prompt.GetText("tswap");
        var never = text[text.IndexOf("## Commands you must NEVER use", StringComparison.Ordinal)..text.IndexOf("## Key rules", StringComparison.Ordinal)];
        Assert.Contains("- `sudo tswap slot add --yubikey`", never);
        Assert.Contains("- `sudo tswap slot merge <file>`", never);
        Assert.Contains("- `sudo tswap recover --yubikey|--tpm|--secure-enclave`", never);
    }

    [Fact]
    public void Template_TellsTheAgentToReplaceABurnedSecretWithRotate()
    {
        // Brief T6 decision 7: replacing a burned secret is the agent's job, and needs no sudo.
        var text = Prompt.GetText("tswap");
        var should = text[text.IndexOf("## Commands you SHOULD use", StringComparison.Ordinal)..text.IndexOf("## Commands you must NEVER use", StringComparison.Ordinal)];
        Assert.Contains("- `tswap rotate <name> [length]`", should);
        Assert.Contains("tswap ingest --rotate <name>", should);
        Assert.Contains("tswap rotate", text[text.IndexOf("## Key rules", StringComparison.Ordinal)..]);
        Assert.DoesNotContain("delete", should);
    }

    [Fact]
    public void Template_ListsTheRecordStoreSudoCommandsUnderNever()
    {
        var text = Prompt.GetText("tswap");
        var never = text[text.IndexOf("## Commands you must NEVER use", StringComparison.Ordinal)..text.IndexOf("## Key rules", StringComparison.Ordinal)];
        Assert.Contains("- `sudo tswap migrate --to-records", never);
        Assert.Contains("- `sudo tswap vault merge <folder>`", never);
    }
}
