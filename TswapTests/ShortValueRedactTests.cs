using System.Text.Json;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T30 (#314): <c>redact</c> masks a value shorter than 8 characters only where it stands as a whole
/// word or number (<see cref="TswapCore.Fingerprints.TokenBoundary"/>), in every form of it; values of 8
/// characters or more are still masked anywhere. Through <see cref="Redact.RedactContent(string, SecretsDb)"/>,
/// which goes through the same <see cref="SecretMatcher"/> as the command.
/// </summary>
public class ShortValueRedactTests
{
    private static Secret S(string value, string? previous = null) =>
        new(value, TestTime.Fixed, TestTime.Fixed, null, null) { PreviousValue = previous };

    private static SecretsDb Db(params (string Name, Secret Secret)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => s.Secret)) { KeepsPreviousValues = true };

    private static readonly SecretsDb Port = Db(("p", S("465")));

    private static string R(string content, SecretsDb? db = null) => Redact.RedactContent(content, db ?? Port);

    [Fact]
    public void Redact_IssueExamples()
    {
        Assert.Equal("65465", R("65465"));
        Assert.Equal("1465", R("1465"));
        Assert.Equal("port=[REDACTED: p]", R("port=465"));
        Assert.Equal("\"[REDACTED: p]\"", R("\"465\""));
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\"")]
    [InlineData("'")]
    [InlineData("=")]
    [InlineData(":")]
    [InlineData("@")]
    [InlineData("/")]
    [InlineData(".")]
    [InlineData(",")]
    [InlineData("(")]
    [InlineData(")")]
    [InlineData("[")]
    [InlineData("]")]
    [InlineData("{")]
    [InlineData("}")]
    [InlineData(";")]
    [InlineData("+")]
    [InlineData("\n")]
    [InlineData("\t")]
    [InlineData("😀")]
    public void Redact_ShortValue_EveryDelimiter(string d)
    {
        Assert.Equal($"a{d}[REDACTED: p]{d}b", R($"a{d}465{d}b"));
        Assert.Equal("[REDACTED: p]", R("465"));
        Assert.Equal("[REDACTED: p] x", R("465 x"));
        Assert.Equal("x [REDACTED: p]", R("x 465"));
    }

    [Theory]
    [InlineData("x")]
    [InlineData("Z")]
    [InlineData("5")]
    [InlineData("_")]
    [InlineData("-")]
    [InlineData("é")]
    public void Redact_ShortValue_WordNeighbours_Unchanged(string w)
    {
        Assert.Equal($"{w}465", R($"{w}465"));
        Assert.Equal($"465{w}", R($"465{w}"));
        Assert.Equal($"{w}465{w}", R($"{w}465{w}"));
    }

    [Fact]
    public void Redact_JsonWithShortNumericValue_StillParses()
    {
        const string numbers = "{\"in\":65465,\"out\":1465,\"sum\":4650,\"id\":\"x465\"}";
        var redacted = R(numbers);
        Assert.Equal(numbers, redacted);
        using (JsonDocument.Parse(redacted)) { }

        var quoted = R("{\"port\":\"465\"}");
        Assert.Equal("{\"port\":\"[REDACTED: p]\"}", quoted);
        using var doc = JsonDocument.Parse(quoted);
        Assert.Equal("[REDACTED: p]", doc.RootElement.GetProperty("port").GetString());
    }

    [Fact]
    public void Redact_ShortWord_InsideLongerWords()
    {
        var db = Db(("u", S("post")), ("w", S("web")));
        Assert.Equal("postgresql", R("postgresql", db));
        Assert.Equal("repost", R("repost", db));
        Assert.Equal("namespace: web-ngx", R("namespace: web-ngx", db));
        Assert.Equal("/home/webster", R("/home/webster", db));
        Assert.Equal("user=[REDACTED: u]", R("user=post", db));
        Assert.Equal("host: [REDACTED: w].example", R("host: web.example", db));
    }

    [Fact]
    public void Redact_PasswordInUrl_StillMasked() =>
        Assert.Equal("https://user:[REDACTED: pw]@host/", R("https://user:pw1@host/", Db(("pw", S("pw1")))));

    [Fact]
    public void Redact_LongValueInsideWord_StillMasked() =>
        Assert.Equal("abc[REDACTED: long]xyz", R("abcs3cr3t-long-valuexyz", Db(("long", S("s3cr3t-long-value")))));

    [Fact]
    public void Redact_Threshold_SevenAndEight()
    {
        Assert.Equal("xabcdefgx", R("xabcdefgx", Db(("s", S("abcdefg")))));
        Assert.Equal("x[REDACTED: s]x", R("xabcdefghx", Db(("s", S("abcdefgh")))));
    }

    [Fact]
    public void Redact_ShortValueEncodedForms_WholeTokenOnly() =>
        Assert.Equal("b64=[REDACTED: p (base64)] xNDY1", R("b64=NDY1 xNDY1"));

    [Fact]
    public void Redact_ShortPrevious_LongCurrent_EachByItsOwnLength() =>
        Assert.Equal("x465x [REDACTED: p:previous] x[REDACTED: p]x",
            R("x465x 465 xlong-value-12x", Db(("p", S("long-value-12", previous: "465")))));

    [Fact]
    public void Redact_ShortTwinOfALongValue_LongStillMasked() =>
        // "1234567" is short and its base64 is exactly b-long's value: the short twin (first in tie order) is
        // rejected inside the word, and that doesn't block the long value.
        Assert.Equal("x[REDACTED: b-long]", R("xMTIzNDU2Nw==", Db(("a-short", S("1234567")), ("b-long", S("MTIzNDU2Nw==")))));

    [Fact]
    public void Redact_SymbolEdges_Unconstrained()
    {
        Assert.Equal("x[REDACTED: s]", R("x#42", Db(("s", S("#42")))));
        var bang = Db(("s", S("42!")));
        Assert.Equal("142!", R("142!", bang));
        Assert.Equal("a [REDACTED: s]b", R("a 42!b", bang));
    }

    /// <summary>A pin: tocomment's own <c>[-\w]</c> boundary already holds for every value, before T30 and after.</summary>
    [Fact]
    public void ToComment_ShortValue_Unchanged()
    {
        Assert.Equal("port: \"\"  # tswap: p", Redact.ToComment("port: 465", Port).Content);
        Assert.Equal("n: 65465", Redact.ToComment("n: 65465", Port).Content);
    }
}

/// <summary>Brief T30: the <c>redact</c> command on a record vault, with the issue's JSON case.</summary>
public sealed class ShortValueRedactCommandTests : IDisposable
{
    private readonly FleetMachine _m = new("short-redact", SimulatedYubiKeyService.WithKeys(SerialA));

    public ShortValueRedactCommandTests() => InitRecordVault(_m);

    public void Dispose() => _m.Dispose();

    [Fact]
    public void Redact_Command_JsonFile()
    {
        _m.Ok("465", "ingest", "k8s-mail-email-port");
        _m.Ok("long-db-password-1", "ingest", "db-pw");
        var file = _m.PathOf("sessions.json");
        File.WriteAllText(file, "{\"in\":65465,\"pw\":\"long-db-password-1\",\"port\":\"465\"}");

        var (exit, stdout, stderr) = _m.Run("", "redact", file);

        Assert.True(exit == 0, stderr);
        Assert.Equal("{\"in\":65465,\"pw\":\"[REDACTED: db-pw]\",\"port\":\"[REDACTED: k8s-mail-email-port]\"}", stdout);
        using (JsonDocument.Parse(stdout)) { }
    }
}
