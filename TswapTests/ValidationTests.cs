using TswapCore;
using Xunit;

namespace TswapTests;

public class ValidationTests
{
    // --- Token extraction ---

    [Fact]
    public void ExtractTokens_SingleToken()
    {
        var tokens = Validation.ExtractTokens("curl --password {{db-pass}} http://example.com");
        Assert.Single(tokens);
        Assert.Equal("db-pass", tokens[0]);
    }

    [Fact]
    public void ExtractTokens_MultipleTokens()
    {
        var tokens = Validation.ExtractTokens("cmd --user {{user}} --pass {{pass}}");
        Assert.Equal(2, tokens.Count);
        Assert.Contains("user", tokens);
        Assert.Contains("pass", tokens);
    }

    [Fact]
    public void ExtractTokens_DuplicatesDeduped()
    {
        var tokens = Validation.ExtractTokens("{{key}} and {{key}} again");
        Assert.Single(tokens);
        Assert.Equal("key", tokens[0]);
    }

    [Fact]
    public void ExtractTokens_NoTokens()
    {
        var tokens = Validation.ExtractTokens("just a normal command");
        Assert.Empty(tokens);
    }

    [Fact]
    public void ExtractTokens_AlphanumericAndHyphen()
    {
        var tokens = Validation.ExtractTokens("{{my-secret-123}}");
        Assert.Single(tokens);
        Assert.Equal("my-secret-123", tokens[0]);
    }

    [Fact]
    public void ExtractTokens_RejectsUnderscoreInToken()
    {
        // Token regex only allows [a-zA-Z0-9-], not underscores
        var tokens = Validation.ExtractTokens("{{my_secret}}");
        Assert.Empty(tokens);
    }

    // --- Blocked commands ---

    [Fact]
    public void GetBlockedCommand_BlocksEcho()
    {
        Assert.Equal("echo", Validation.GetBlockedCommand("echo"));
    }

    [Fact]
    public void GetBlockedCommand_BlocksCat()
    {
        Assert.Equal("cat", Validation.GetBlockedCommand("cat"));
    }

    [Fact]
    public void GetBlockedCommand_BlocksTee()
    {
        Assert.Equal("tee", Validation.GetBlockedCommand("tee"));
    }

    [Fact]
    public void GetBlockedCommand_AllowsCurl()
    {
        Assert.Null(Validation.GetBlockedCommand("curl"));
    }

    [Fact]
    public void GetBlockedCommand_AllowsRclone()
    {
        Assert.Null(Validation.GetBlockedCommand("rclone"));
    }

    [Fact]
    public void GetBlockedCommand_CaseInsensitive()
    {
        Assert.Equal("echo", Validation.GetBlockedCommand("ECHO"));
        Assert.Equal("printf", Validation.GetBlockedCommand("Printf"));
    }

    // --- Pipe/redirect detection ---

    [Fact]
    public void HasPipeOrRedirect_DetectsPipe()
    {
        Assert.True(Validation.HasPipeOrRedirect("cmd | other"));
    }

    [Fact]
    public void HasPipeOrRedirect_DetectsRedirect()
    {
        Assert.True(Validation.HasPipeOrRedirect("cmd > file.txt"));
    }

    [Fact]
    public void HasPipeOrRedirect_DetectsAppend()
    {
        Assert.True(Validation.HasPipeOrRedirect("cmd >> file.txt"));
    }

    [Fact]
    public void HasPipeOrRedirect_NormalCommandAllowed()
    {
        Assert.False(Validation.HasPipeOrRedirect("curl --password secret http://example.com"));
    }

    // --- Token substitution ---

    [Fact]
    public void SubstituteTokens_ReplacesTokens()
    {
        var secrets = new Dictionary<string, string> { { "pass", "s3cret" } };
        var result = Validation.SubstituteTokens("cmd --password {{pass}}", secrets);
        Assert.Equal("cmd --password 's3cret'", result);
    }

    [Fact]
    public void SubstituteTokens_EscapesSingleQuotes()
    {
        var secrets = new Dictionary<string, string> { { "pass", "it's" } };
        var result = Validation.SubstituteTokens("cmd {{pass}}", secrets);
        Assert.Equal("cmd 'it'\\''s'", result);
    }

    [Fact]
    public void SubstituteTokens_MultipleTokens()
    {
        var secrets = new Dictionary<string, string>
        {
            { "user", "admin" },
            { "pass", "pw123" }
        };
        var result = Validation.SubstituteTokens("cmd --user {{user}} --pass {{pass}}", secrets);
        Assert.Equal("cmd --user 'admin' --pass 'pw123'", result);
    }

    // --- Sanitize ---

    [Fact]
    public void SanitizeCommand_MasksTokens()
    {
        var result = Validation.SanitizeCommand("cmd --pass {{db-pass}} --user {{user}}");
        Assert.Equal("cmd --pass ******** --user ********", result);
    }

    [Fact]
    public void SanitizeCommand_NoTokensUnchanged()
    {
        var input = "just a command";
        Assert.Equal(input, Validation.SanitizeCommand(input));
    }
}
