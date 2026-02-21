using TswapCore;
using Xunit;

namespace TswapTests;

public class RedactTests
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static SecretsDb MakeDb(params (string name, string value, bool burned)[] secrets)
    {
        var dict = new Dictionary<string, Secret>();
        foreach (var (name, value, burned) in secrets)
        {
            dict[name] = new Secret(
                value,
                DateTime.UtcNow,
                DateTime.UtcNow,
                burned ? DateTime.UtcNow : null,
                burned ? "test" : null
            );
        }
        return new SecretsDb(dict);
    }

    private static SecretsDb MakeDb(params (string name, string value)[] secrets)
    {
        var items = secrets.Select(s => (s.name, s.value, false)).ToArray();
        return MakeDb(items);
    }

    // -------------------------------------------------------------------------
    // Redact.RedactContent — plaintext
    // -------------------------------------------------------------------------

    [Fact]
    public void Redact_PlaintextValue_IsRedacted()
    {
        var db = MakeDb(("db-pass", "s3cr3t"));
        var result = Redact.RedactContent("password: s3cr3t", db);
        Assert.Equal("password: [REDACTED: db-pass]", result);
    }

    [Fact]
    public void Redact_MultipleOccurrencesOnOneLine_AllRedacted()
    {
        var db = MakeDb(("tok", "abc123"));
        var result = Redact.RedactContent("tok=abc123 backup=abc123", db);
        Assert.Equal("tok=[REDACTED: tok] backup=[REDACTED: tok]", result);
    }

    [Fact]
    public void Redact_MultipleSecrets_BothRedacted()
    {
        var db = MakeDb(("a", "alpha"), ("b", "beta"));
        var result = Redact.RedactContent("x=alpha y=beta", db);
        Assert.Equal("x=[REDACTED: a] y=[REDACTED: b]", result);
    }

    [Fact]
    public void Redact_MultiLineContent_EachLineProcessed()
    {
        var db = MakeDb(("pw", "secret"));
        var result = Redact.RedactContent("line1: secret\nline2: ok\nline3: secret", db);
        Assert.Equal("line1: [REDACTED: pw]\nline2: ok\nline3: [REDACTED: pw]", result);
    }

    [Fact]
    public void Redact_BurnedSecret_NotRedacted()
    {
        var db = MakeDb(("pw", "secret", true));
        var result = Redact.RedactContent("password: secret", db);
        Assert.Equal("password: secret", result);
    }

    [Fact]
    public void Redact_NoMatch_ContentUnchanged()
    {
        var db = MakeDb(("pw", "mysecret"));
        var result = Redact.RedactContent("nothing to see here", db);
        Assert.Equal("nothing to see here", result);
    }

    [Fact]
    public void Redact_EmptyDb_ContentUnchanged()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>());
        var result = Redact.RedactContent("password: abc", db);
        Assert.Equal("password: abc", result);
    }

    // -------------------------------------------------------------------------
    // Redact.RedactContent — base64 variant
    // -------------------------------------------------------------------------

    [Fact]
    public void Redact_Base64EncodedValue_IsRedactedWithLabel()
    {
        var db = MakeDb(("db-pass", "hunter2"));
        // base64("hunter2") = "aHVudGVyMg=="
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("hunter2"));
        var result = Redact.RedactContent($"data: {b64}", db);
        Assert.Equal("data: [REDACTED: db-pass (base64)]", result);
    }

    [Fact]
    public void Redact_Base64UrlEncodedValue_IsRedactedWithLabel()
    {
        // ">>?>>" encodes to base64 "Pj4/Pz4+" which contains both + and /,
        // guaranteeing a distinct base64url form "Pj4_Pz4-" for every run.
        var db = MakeDb(("my-key", ">>??>>"));
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(">>??>>"));
        var b64url = b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var result = Redact.RedactContent($"data: {b64url}", db);
        Assert.Equal("data: [REDACTED: my-key (base64url)]", result);
    }

    // -------------------------------------------------------------------------
    // Redact.RedactContent — longest-match ordering
    // -------------------------------------------------------------------------

    [Fact]
    public void Redact_LongerValueTakesPrecedenceOverShorter()
    {
        // "superSecret" contains "secret" — the longer one must win
        var db = MakeDb(("long", "superSecret"), ("short", "secret"));
        var result = Redact.RedactContent("val=superSecret", db);
        Assert.Equal("val=[REDACTED: long]", result);
    }

    // -------------------------------------------------------------------------
    // Redact.ToComment
    // -------------------------------------------------------------------------

    [Fact]
    public void ToComment_UnquotedValue_ReplacedWithMarker()
    {
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, changes) = Redact.ToComment("password: s3cr3t", db);
        Assert.Equal("password: \"\"  # tswap: db-pass", content);
        Assert.Single(changes);
        Assert.Equal(1, changes[0].LineNumber);
    }

    [Fact]
    public void ToComment_QuotedValue_QuotesConsumed()
    {
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, _) = Redact.ToComment("password: \"s3cr3t\"", db);
        Assert.Equal("password: \"\"  # tswap: db-pass", content);
    }

    [Fact]
    public void ToComment_SingleQuotedValue_QuotesConsumed()
    {
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, _) = Redact.ToComment("password: 's3cr3t'", db);
        Assert.Equal("password: \"\"  # tswap: db-pass", content);
    }

    [Fact]
    public void ToComment_NoMatch_EmptyChanges()
    {
        var db = MakeDb(("pw", "mysecret"));
        var (content, changes) = Redact.ToComment("nothing here", db);
        Assert.Equal("nothing here", content);
        Assert.Empty(changes);
    }

    [Fact]
    public void ToComment_MultipleLines_OnlyChangedLinesReported()
    {
        var db = MakeDb(("pw", "s3cr3t"));
        var (content, changes) = Redact.ToComment("a: ok\nb: s3cr3t\nc: ok", db);
        Assert.Equal("a: ok\nb: \"\"  # tswap: pw\nc: ok", content);
        Assert.Single(changes);
        Assert.Equal(2, changes[0].LineNumber);
    }

    [Fact]
    public void ToComment_AlreadyConverted_Idempotent()
    {
        var db = MakeDb(("pw", "s3cr3t"));
        var converted = "password: \"\"  # tswap: pw";
        // Running tocomment again should produce no changes (value not present any more)
        var (_, changes) = Redact.ToComment(converted, db);
        Assert.Empty(changes);
    }

    [Fact]
    public void ToComment_BurnedSecret_NotReplaced()
    {
        var db = MakeDb(("pw", "s3cr3t", true));
        var (content, changes) = Redact.ToComment("password: s3cr3t", db);
        Assert.Equal("password: s3cr3t", content);
        Assert.Empty(changes);
    }

    [Fact]
    public void ToComment_DiffRecordsBeforeAndAfter()
    {
        var db = MakeDb(("pw", "s3cr3t"));
        var (_, changes) = Redact.ToComment("p: s3cr3t", db);
        Assert.Single(changes);
        Assert.Equal("p: s3cr3t", changes[0].Before);
        Assert.Equal("p: \"\"  # tswap: pw", changes[0].After);
    }

    // -------------------------------------------------------------------------
    // Redact.ToComment — YAML punctuation adjacency
    // -------------------------------------------------------------------------

    [Fact]
    public void ToComment_YamlFlowMapping_UnquotedValueAdjacentToComma()
    {
        // value sits between ": " and "," — comma must survive unchanged
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, _) = Redact.ToComment("{password: s3cr3t, host: local}", db);
        Assert.Equal("{password: \"\"  # tswap: db-pass, host: local}", content);
    }

    [Fact]
    public void ToComment_YamlFlowMapping_DoubleQuotedValueAdjacentToComma()
    {
        // double-quoted value inside a flow mapping — quotes consumed, comma survives
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, _) = Redact.ToComment("{password: \"s3cr3t\", host: local}", db);
        Assert.Equal("{password: \"\"  # tswap: db-pass, host: local}", content);
    }

    [Fact]
    public void ToComment_YamlFlowSequence_ValueAdjacentToBracket()
    {
        // value is the sole element of a flow sequence — bracket must survive
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, _) = Redact.ToComment("passwords: [s3cr3t]", db);
        Assert.Equal("passwords: [\"\"  # tswap: db-pass]", content);
    }

    [Fact]
    public void ToComment_YamlNoSpaceAfterColon_Replaced()
    {
        // compact "key:value" (no space) — value still matched and replaced
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, changes) = Redact.ToComment("password:s3cr3t", db);
        Assert.Equal("password:\"\"  # tswap: db-pass", content);
        Assert.Single(changes);
    }

    [Fact]
    public void ToComment_ValueWithExistingTrailingComment_CommentPreserved()
    {
        // existing inline comment is preserved (appended after the tswap marker)
        var db = MakeDb(("db-pass", "s3cr3t"));
        var (content, _) = Redact.ToComment("password: s3cr3t  # legacy value", db);
        Assert.Equal("password: \"\"  # tswap: db-pass  # legacy value", content);
    }

    [Fact]
    public void ToComment_CrlfLineEndings_NormalizedToLf()
    {
        // CRLF input must not leave stray \r in the output or miscount line numbers
        var db = MakeDb(("pw", "s3cr3t"));
        var (content, changes) = Redact.ToComment("a: ok\r\nb: s3cr3t\r\nc: ok", db);
        Assert.DoesNotContain("\r", content);
        Assert.Single(changes);
        Assert.Equal(2, changes[0].LineNumber);
    }

    [Fact]
    public void ToComment_SecretContainsRegexSpecialChars_LiteralMatchOnly()
    {
        // "p+ss" as an unescaped regex matches "pss"/"ppss"/… but NOT the literal "p+ss".
        // Regex.Escape must be applied so only the exact value is replaced.
        var db = MakeDb(("api-key", "p+ss"));
        var (content, changes) = Redact.ToComment("apikey: p+ss", db);
        Assert.Equal("apikey: \"\"  # tswap: api-key", content);
        Assert.Single(changes);
    }

    [Fact]
    public void ToComment_SecretContainsRegexSpecialChars_DoesNotMatchRelatedString()
    {
        // "pss" satisfies the unescaped regex "p+ss" but must NOT be replaced when
        // the actual stored secret is "p+ss".
        var db = MakeDb(("api-key", "p+ss"));
        var (content, changes) = Redact.ToComment("apikey: pss", db);
        Assert.Equal("apikey: pss", content);
        Assert.Empty(changes);
    }

    // -------------------------------------------------------------------------
    // Redact.FindUnknownSecrets
    // -------------------------------------------------------------------------

    [Fact]
    public void FindUnknownSecrets_MatchesCredentialKeyword()
    {
        var hits = Redact.FindUnknownSecrets("password: abcdefghijklmno");
        Assert.Single(hits);
        Assert.Equal(1, hits[0].Line);
    }

    [Fact]
    public void FindUnknownSecrets_ShortValue_NotMatched()
    {
        // Value shorter than 12 chars should not trigger the heuristic
        var hits = Redact.FindUnknownSecrets("password: short");
        Assert.Empty(hits);
    }

    [Fact]
    public void FindUnknownSecrets_NoKeyword_NotMatched()
    {
        var hits = Redact.FindUnknownSecrets("hostname: abcdefghijklmno");
        Assert.Empty(hits);
    }

    [Fact]
    public void FindUnknownSecrets_MultipleLines_ReturnsCorrectLineNumbers()
    {
        var content = "ok: nothing\ntoken: abcdefghijklmnop\nfine: nope";
        var hits = Redact.FindUnknownSecrets(content);
        Assert.Single(hits);
        Assert.Equal(2, hits[0].Line);
    }
}
