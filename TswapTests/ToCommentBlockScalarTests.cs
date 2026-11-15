using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T20 (#315), task 4: <c>tocomment</c> adopts a YAML literal block scalar (<c>|</c>, <c>|-</c>,
/// <c>|+</c>) whose content is exactly one stored value: the key line becomes <c>key: ""  # tswap: NAME</c>
/// and the block's lines go. One walk decides the block (content indentation from its first non-blank
/// line, blank lines belong, a line between the key's and the content's indentation leaves it alone),
/// chomping decides the candidate, and only a stored value's plain variant matching the whole candidate
/// (or the candidate minus its single trailing LF) counts.
/// </summary>
public sealed class ToCommentBlockScalarTests
{
    private const string Pem =
        "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEw\nggE9AgEAAkEAq7BFUpkGp3+Gz8XxKE0VYg9N\n-----END PRIVATE KEY-----";

    private static readonly string[] PemLines = Pem.Split('\n');

    /// <summary>The PEM as a block's lines, each indented by <paramref name="indent"/>, each ending in LF.</summary>
    private static string Block(string indent = "    ") => string.Concat(PemLines.Select(l => indent + l + "\n"));

    private static SecretsDb Db(params (string Name, string Value)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => new Secret(s.Value, TestTime.Fixed, TestTime.Fixed, null, null)));

    private static void AssertUnchanged(string content, SecretsDb db)
    {
        var (result, changes) = Redact.ToComment(content, db);
        Assert.Empty(changes);
        Assert.Equal(content.Replace("\r\n", "\n"), result);
    }

    // ------------------------------------------------------------------ chomping

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Clip_PemBlockFollowedByABlankLine_Adopted(bool storedWithTrailingLf)
    {
        // '|' keeps exactly one trailing LF: the blank line before 'other:' belongs to the block, and
        // chomping drops the LF it adds.
        var db = Db(("pem", storedWithTrailingLf ? Pem + "\n" : Pem));
        var content = "tls:\n  key: |\n" + Block() + "\nother: x\n";

        var (result, changes) = Redact.ToComment(content, db);

        Assert.Equal("tls:\n  key: \"\"  # tswap: pem\nother: x\n", result);
        LineDiff[] expected =
        [
            new(2, "  key: |", "  key: \"\"  # tswap: pem"),
            new BlockLineDiff(3, "    " + PemLines[0]),
            new BlockLineDiff(4, "    " + PemLines[1]),
            new BlockLineDiff(5, "    " + PemLines[2]),
            new BlockLineDiff(6, "    " + PemLines[3]),
            new BlockLineDiff(7, ""),
        ];
        Assert.Equal(expected, changes);
    }

    [Fact]
    public void Strip_PemBlock_AdoptedForAValueWithoutTrailingLf()
    {
        var content = "key: |-\n" + Block() + "next: 1\n";

        var (result, _) = Redact.ToComment(content, Db(("pem", Pem)));

        Assert.Equal("key: \"\"  # tswap: pem\nnext: 1\n", result);
    }

    [Fact]
    public void Strip_PemBlock_NotAValueWithTrailingLf()
    {
        // '|-' holds no trailing LF, so a value ending in one is not what the block holds.
        AssertUnchanged("key: |-\n" + Block() + "next: 1\n", Db(("pem", Pem + "\n")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Keep_PemBlock_Adopted(bool storedWithTrailingLf)
    {
        var content = "key: |+\n" + Block() + "next: 1\n";

        var (result, _) = Redact.ToComment(content, Db(("pem", storedWithTrailingLf ? Pem + "\n" : Pem)));

        Assert.Equal("key: \"\"  # tswap: pem\nnext: 1\n", result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("      ")]
    public void Keep_TwoTrailingBlankLines_KeptInTheValue(string blank)
    {
        // '|+' keeps every trailing LF; a blank line's spaces are dropped, so both files give one result.
        var content = "key: |+\n" + Block() + blank + "\n" + blank + "\nnext: 1\n";

        var (result, changes) = Redact.ToComment(content, Db(("pem", Pem + "\n\n\n")));

        Assert.Equal("key: \"\"  # tswap: pem\nnext: 1\n", result);
        Assert.Equal(1 + PemLines.Length + 2, changes.Count);
        AssertUnchanged(content, Db(("pem", Pem + "\n"))); // fewer LFs than the block holds: no match
    }

    // ------------------------------------------------------------------ what is not a block, or not adopted

    [Theory]
    [InlineData("key: |\n")]
    [InlineData("key: |")]
    [InlineData("key: |\n\n   \n")]
    [InlineData("key: |\nnext: 1\n")]
    public void NoNonBlankLineDeeperThanTheKey_NoMatch(string content)
    {
        AssertUnchanged(content, Db(("pem", Pem)));
    }

    [Fact]
    public void LineBetweenKeyAndContentIndentation_LeftUnchanged()
    {
        // YAML would end the block at the 2-space line; tswap leaves the key alone.
        var content = "key: |\n    " + PemLines[0] + "\n    " + PemLines[1] + "\n  " + PemLines[2] + "\n    " + PemLines[3] + "\n";

        AssertUnchanged(content, Db(("pem", Pem)));
    }

    [Fact]
    public void BlockHoldingTheValuePlusOneLine_NoMatch()
    {
        var content = "key: |\n" + Block() + "    extra line\nnext: 1\n";

        AssertUnchanged(content, Db(("pem", Pem)));
    }

    [Theory]
    [InlineData("key: >\n")]
    [InlineData("key: >-\n")]
    [InlineData("key: |2\n")]
    [InlineData("key: |-2\n")]
    public void FoldedOrIndentationIndicator_LeftUnchanged(string keyLine)
    {
        AssertUnchanged(keyLine + Block() + "next: 1\n", Db(("pem", Pem)));
    }

    [Fact]
    public void BaseSixtyFourOfTheValue_NotAdopted()
    {
        // Only the plain variant counts: a block holding the value's base64 is not adopted.
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Pem));
        var content = "key: |\n    " + b64 + "\nnext: 1\n";

        var (result, _) = Redact.ToComment(content, Db(("pem", Pem)));

        Assert.DoesNotContain("key: \"\"", result);
        Assert.StartsWith("key: |\n", result);
    }

    // ------------------------------------------------------------------ versions, layout

    [Fact]
    public void PreviousVersion_WritesNamePrevious()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["pem"] = new Secret("a-new-value-after-rotation", TestTime.Fixed, TestTime.Fixed, null, null) { PreviousValue = Pem },
        });
        var content = "key: |\n" + Block();

        var (result, _) = Redact.ToComment(content, db);

        Assert.Equal("key: \"\"  # tswap: pem:previous\n", result);
    }

    [Fact]
    public void BlockAtEndOfFileWithoutFinalNewline_Adopted()
    {
        var content = "a: 1\nkey: |\n" + Block().TrimEnd('\n');

        var (result, changes) = Redact.ToComment(content, Db(("pem", Pem)));

        Assert.Equal("a: 1\nkey: \"\"  # tswap: pem", result);
        Assert.Equal(1 + PemLines.Length, changes.Count);
    }

    [Fact]
    public void TwoBlocks_BothAdopted()
    {
        const string cert = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG\n-----END CERTIFICATE-----";
        var content = "tls:\n  key: |\n" + Block("    ") + "  crt: |\n" + string.Concat(cert.Split('\n').Select(l => "    " + l + "\n")) + "name: app\n";

        var (result, _) = Redact.ToComment(content, Db(("pem", Pem), ("crt", cert)));

        Assert.Equal("tls:\n  key: \"\"  # tswap: pem\n  crt: \"\"  # tswap: crt\nname: app\n", result);
    }

    [Fact]
    public void CrLfFile_NormalisedAndAdopted()
    {
        var content = ("tls:\n  key: |\n" + Block() + "other: x\n").Replace("\n", "\r\n");

        var (result, _) = Redact.ToComment(content, Db(("pem", Pem)));

        Assert.Equal("tls:\n  key: \"\"  # tswap: pem\nother: x\n", result);
    }

    [Fact]
    public void RoundTrip_ToCommentThenApply_GivesTheStoredValue()
    {
        var db = Db(("pem", Pem));
        var content = "tls:\n  key: |\n" + Block() + "other: x\n";

        var (commented, _) = Redact.ToComment(content, db);
        var filled = Apply.ApplySecrets(commented, db);

        var line = filled.Split('\n')[1];
        Assert.Equal(Pem, DoubleQuotedTestDecoder.Decode(ApplyMultiLineTests.QuotedPart(line, "  key: \"")));
    }
}

/// <summary>Brief T20, task 4: <c>tocomment --dry-run</c> over a block scalar prints no line of the value.</summary>
public sealed class ToCommentBlockScalarCommandTests : IDisposable
{
    private const string Pem =
        "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEw\nggE9AgEAAkEAq7BFUpkGp3+Gz8XxKE0VYg9N\n-----END PRIVATE KEY-----";

    private readonly FleetMachine _m = new("tocomment-block", SimulatedYubiKeyService.WithKeys(SerialA));

    public ToCommentBlockScalarCommandTests()
    {
        InitRecordVault(_m);
        _m.Ok(Pem, "ingest", "pem");
    }

    public void Dispose() => _m.Dispose();

    private string WriteFile()
    {
        var file = _m.PathOf("values.yaml");
        File.WriteAllText(file, "tls:\n  key: |\n" + string.Concat(Pem.Split('\n').Select(l => "    " + l + "\n")) + "other: x\n");
        return file;
    }

    [Fact]
    public void DryRun_PrintsNoLineOfTheValue()
    {
        var file = WriteFile();
        var before = File.ReadAllText(file);

        var (exit, stdout, stderr) = _m.Run("", "tocomment", file, "--dry-run");

        Assert.Equal(0, exit);
        foreach (var line in Pem.Split('\n'))
        {
            Assert.DoesNotContain(line, stdout);
            Assert.DoesNotContain(line, stderr);
        }
        Assert.Contains("  line 2:\n  -   key: |\n  +   key: \"\"  # tswap: pem\n", stderr.Replace("\r\n", "\n"));
        Assert.Equal(4, stderr.Replace("\r\n", "\n").Split('\n').Count(l => l == "  - [removed block line]"));
        Assert.DoesNotContain("[removed continuation line]", stderr);
        Assert.Equal(before, File.ReadAllText(file)); // a dry run writes nothing
    }

    [Fact]
    public void Write_ReplacesTheBlock()
    {
        var file = WriteFile();

        var (exit, _, stderr) = _m.Run("", "tocomment", file);

        Assert.True(exit == 0, stderr);
        Assert.Equal("tls:\n  key: \"\"  # tswap: pem\nother: x\n", File.ReadAllText(file));
    }
}
