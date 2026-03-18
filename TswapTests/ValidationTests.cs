using TswapCore;
using Xunit;

namespace TswapTests;

public class ValidationTests
{
    // --- ValidateName ---

    [Fact]
    public void ValidateName_ValidNamesPass()
    {
        // Should not throw
        Validation.ValidateName("my-secret");
        Validation.ValidateName("MY_SECRET_123");
        Validation.ValidateName(new string('a', 64)); // exactly at limit
    }

    [Fact]
    public void ValidateName_EmptyThrows()
    {
        var ex = Assert.Throws<Exception>(() => Validation.ValidateName(""));
        Assert.Contains("empty", ex.Message);
    }

    [Fact]
    public void ValidateName_TooLongThrows()
    {
        var ex = Assert.Throws<Exception>(() => Validation.ValidateName(new string('a', 65)));
        Assert.Contains("too long", ex.Message);
    }

    [Fact]
    public void ValidateName_InvalidCharsThrows()
    {
        var ex = Assert.Throws<Exception>(() => Validation.ValidateName("bad name"));
        Assert.Contains("Invalid secret name", ex.Message);
    }

    [Fact]
    public void ValidateName_ControlCharEscapedInMessage()
    {
        // A name containing a control character (ESC = 0x1B) should have it replaced with
        // '?' in the error message, not echoed raw, to prevent terminal injection.
        var ex = Assert.Throws<Exception>(() => Validation.ValidateName("bad\u001bname"));
        // The sanitized form must appear (ESC replaced with '?')
        Assert.Contains("bad?name", ex.Message);
        // Every character in the message must be in the printable ASCII range or whitespace
        Assert.All(ex.Message, c => Assert.True(c >= 0x20 || c == '\n' || c == '\r' || c == '\t',
            $"Message contains non-printable character U+{(int)c:X4}"));
    }

    // --- ReadBoundedStdin ---

    [Fact]
    public void ReadBoundedStdin_ReadsAndTrims()
    {
        using var reader = new StringReader("hello world\n");
        Assert.Equal("hello world", Validation.ReadBoundedStdin(reader));
    }

    [Fact]
    public void ReadBoundedStdin_ExactLimitAllowed()
    {
        var value = new string('x', 65536);
        using var reader = new StringReader(value);
        Assert.Equal(value, Validation.ReadBoundedStdin(reader));
    }

    [Fact]
    public void ReadBoundedStdin_OverLimitThrows()
    {
        var value = new string('x', 65537);
        using var reader = new StringReader(value);
        var ex = Assert.Throws<Exception>(() => Validation.ReadBoundedStdin(reader));
        Assert.Contains("too long", ex.Message);
    }

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
    public void ExtractTokens_AcceptsUnderscoreInToken()
    {
        // Token regex allows [a-zA-Z0-9_-] so ingest-style names like my_secret work
        var tokens = Validation.ExtractTokens("{{my_secret}}");
        Assert.Single(tokens);
        Assert.Equal("my_secret", tokens[0]);
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
    public void SubstituteTokensInArgs_ReplacesTokenInSingleArg()
    {
        var secrets = new Dictionary<string, string> { { "pass", "s3cret" } };
        var result = Validation.SubstituteTokensInArgs(["--password", "{{pass}}"], secrets);
        Assert.Equal(new[] { "--password", "s3cret" }, result);
    }

    [Fact]
    public void SubstituteTokensInArgs_RawValue_NoShellQuoting()
    {
        // Single quotes in the value are passed through verbatim — no shell escaping.
        var secrets = new Dictionary<string, string> { { "pass", "it's" } };
        var result = Validation.SubstituteTokensInArgs(["cmd", "{{pass}}"], secrets);
        Assert.Equal(new[] { "cmd", "it's" }, result);
    }

    [Fact]
    public void SubstituteTokensInArgs_MultipleTokensAcrossArgs()
    {
        var secrets = new Dictionary<string, string>
        {
            { "user", "admin" },
            { "pass", "pw123" }
        };
        var result = Validation.SubstituteTokensInArgs(
            ["cmd", "--user", "{{user}}", "--pass", "{{pass}}"], secrets);
        Assert.Equal(new[] { "cmd", "--user", "admin", "--pass", "pw123" }, result);
    }

    [Fact]
    public void SubstituteTokensInArgs_TokenInsideCompoundArg()
    {
        // Token embedded in a larger string (e.g. a -c script passed to sh).
        var secrets = new Dictionary<string, string> { { "tok", "val" } };
        var result = Validation.SubstituteTokensInArgs(
            ["sh", "-c", "echo before; echo {{tok}}; echo after"], secrets);
        Assert.Equal(new[] { "sh", "-c", "echo before; echo val; echo after" }, result);
    }

    [Fact]
    public void SubstituteTokensInArgs_PreservesArgCount()
    {
        var secrets = new Dictionary<string, string> { { "x", "y" } };
        var input = new[] { "a", "{{x}}", "c" };
        var result = Validation.SubstituteTokensInArgs(input, secrets);
        Assert.Equal(3, result.Length);
    }

    [Fact]
    public void SubstituteTokensInArgs_NulInValueThrows()
    {
        var secrets = new Dictionary<string, string> { { "tok", "val\0ue" } };
        var ex = Assert.Throws<Exception>(() =>
            Validation.SubstituteTokensInArgs(["cmd", "{{tok}}"], secrets));
        Assert.Contains("NUL", ex.Message);
        Assert.Contains("tok", ex.Message);
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
