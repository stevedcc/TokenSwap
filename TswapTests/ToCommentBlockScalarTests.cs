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
/// <para>
/// Brief T22 (#319): on a line of block-scalar content (any block start: <c>|</c>, <c>&gt;</c>, indicators,
/// node properties, sequence entries), an encoded form of a value is never replaced; the line stays whole
/// and is reported as an <see cref="UnreplacedLine"/>. Plain values there are replaced as before.
/// </para>
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

    // ------------------------------------------------------------------ T22 (#319): encoded values inside block content

    private static string B64(string value) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value));

    private const string Tok = "s3cr3t-T0ken-value-42";

    /// <summary>Brief T22: <paramref name="content"/> comes back as it was, with no change and exactly <paramref name="unreplaced"/>.</summary>
    private static void AssertLeft(string content, SecretsDb db, params UnreplacedLine[] unreplaced)
    {
        var (result, changes, left) = Redact.ToCommentReporting(content, db);
        Assert.Equal(content, result);
        Assert.Empty(changes);
        Assert.Equal(unreplaced, left);
    }

    [Fact]
    public void BaseSixtyFourInABlock_LeftUnchanged_Reported()
    {
        // #319: the line path used to rewrite the content line to '""  # tswap: pem', which run then
        // filled with the plain value where the file held its base64.
        AssertLeft("key: |\n    " + B64(Pem) + "\nnext: 1\n", Db(("pem", Pem)), new UnreplacedLine(2, "pem"));
    }

    [Fact]
    public void PlainValueInAScriptBlock_StillReplaced()
    {
        // A plain value: the marker's '#' is a shell comment and run fills the plain value back.
        var (result, changes, unreplaced) = Redact.ToCommentReporting("script: |\n  export TOKEN=" + Tok + "\nnext: 1\n", Db(("tok", Tok)));

        Assert.Equal("script: |\n  export TOKEN=\"\"  # tswap: tok\nnext: 1\n", result);
        LineDiff[] expected = [new(2, "  export TOKEN=" + Tok, "  export TOKEN=\"\"  # tswap: tok")];
        Assert.Equal(expected, changes);
        Assert.Empty(unreplaced);
    }

    [Fact]
    public void Base64InAScriptBlock_LineLeftUnchanged()
    {
        var scriptLine = "  echo " + B64(Tok) + " | base64 -d";
        var content = "script: |\n" + scriptLine + "\ntoken: " + Tok + "\n";

        var (result, changes, unreplaced) = Redact.ToCommentReporting(content, Db(("tok", Tok)));

        Assert.Equal("script: |\n" + scriptLine + "\ntoken: \"\"  # tswap: tok\n", result);
        LineDiff[] expected = [new(3, "token: " + Tok, "token: \"\"  # tswap: tok")];
        Assert.Equal(expected, changes);
        UnreplacedLine[] left = [new(2, "tok")];
        Assert.Equal(left, unreplaced);
    }

    private const string Other = "an0ther-Secret-V4lue";

    [Fact]
    public void MixedLine_PlainAndEncoded_LeftWhole()
    {
        // No partial rewrite: the plain value stays too, and only the encoded hit is recorded.
        AssertLeft("cmd: |\n  run --user " + Tok + " --key " + B64(Other) + "\nnext: 1\n", Db(("tok", Tok), ("other", Other)),
            new UnreplacedLine(2, "other"));
    }

    [Theory]
    [InlineData("key: >")]
    [InlineData("key: >-")]
    public void FoldedBlock_Encoded_LeftUnchanged(string keyLine)
    {
        AssertLeft(keyLine + "\n  " + B64(Tok) + "\nnext: 1\n", Db(("tok", Tok)), new UnreplacedLine(2, "tok"));
    }

    [Fact]
    public void SequenceEntryBlock_Encoded_LeftUnchanged()
    {
        AssertLeft("items:\n  - |\n    " + B64(Tok) + "\n  - plain\n", Db(("tok", Tok)), new UnreplacedLine(3, "tok"));
    }

    [Theory]
    [InlineData("key: |2")]
    [InlineData("key: |2-")]
    [InlineData("key: >-1")]
    public void IndentationIndicator_Encoded_LeftUnchanged(string keyLine)
    {
        AssertLeft(keyLine + "\n    " + B64(Tok) + "\nnext: 1\n", Db(("tok", Tok)), new UnreplacedLine(2, "tok"));
    }

    [Fact]
    public void BlockStartWithComment_Encoded_LeftUnchanged()
    {
        AssertLeft("key: | # note\n  " + B64(Tok) + "\nnext: 1\n", Db(("tok", Tok)), new UnreplacedLine(2, "tok"));
    }

    [Theory]
    [InlineData("key: !!binary |")]
    [InlineData("key: &a >-")]
    [InlineData("key: !!binary &a |")]
    public void TaggedBlock_Encoded_LeftUnchanged(string keyLine)
    {
        AssertLeft(keyLine + "\n  " + B64(Pem) + "\nnext: 1\n", Db(("pem", Pem)), new UnreplacedLine(2, "pem"));
    }

    [Fact]
    public void CompactSequenceEntry_SiblingKeyNotContent()
    {
        // The block's node is 'command' (column 10), not the line (indent 8): 'token:' at column 10 is a
        // sibling key, outside the block, so its encoded value is replaced as today.
        var contentLine = "            echo " + B64(Tok);
        var content = "steps:\n        - command: |\n" + contentLine + "\n          token: " + B64(Tok) + "\n";

        var (result, changes, unreplaced) = Redact.ToCommentReporting(content, Db(("tok", Tok)));

        Assert.Equal("steps:\n        - command: |\n" + contentLine + "\n          token: \"\"  # tswap: tok\n", result);
        LineDiff[] expected = [new(4, "          token: " + B64(Tok), "          token: \"\"  # tswap: tok")];
        Assert.Equal(expected, changes);
        UnreplacedLine[] left = [new(3, "tok")];
        Assert.Equal(left, unreplaced);
    }

    [Fact]
    public void QuotedPipe_NotABlock()
    {
        // A quoted "|" is a string, not a block indicator: today's output exactly.
        var (result, changes, unreplaced) = Redact.ToCommentReporting("key: \"|\"\n    " + B64(Pem) + "\n", Db(("pem", Pem)));

        Assert.Equal("key: \"|\"\n    \"\"  # tswap: pem\n", result);
        LineDiff[] expected = [new(2, "    " + B64(Pem), "    \"\"  # tswap: pem")];
        Assert.Equal(expected, changes);
        Assert.Empty(unreplaced);
    }

    [Fact]
    public void BlockEndsAtNodeColumn()
    {
        var (result, changes, unreplaced) = Redact.ToCommentReporting(
            "parent:\n  key: |\n    text\n  other: " + B64(Tok) + "\n", Db(("tok", Tok)));

        Assert.Equal("parent:\n  key: |\n    text\n  other: \"\"  # tswap: tok\n", result);
        Assert.Single(changes);
        Assert.Empty(unreplaced);
    }

    [Fact]
    public void TwoValuesOnOneContentLine_TwoRecords()
    {
        // Ordered by line, then token ordinally ('other' before 'tok', whatever the order on the line).
        AssertLeft("k: |\n  " + B64(Tok) + " " + B64(Other) + "\n", Db(("tok", Tok), ("other", Other)),
            new UnreplacedLine(2, "other"), new UnreplacedLine(2, "tok"));
    }

    [Fact]
    public void ContinuationLineHoldingAnEncodedValue_KeptAndReported()
    {
        // The plain value on line 2 is replaced; line 3 looks like a base64 continuation of it, but it is
        // block content holding another value's base64, so it is not removed.
        var content = "script: |\n  export A=" + Tok + "\n    " + B64(Other) + "\n";

        var (result, changes, unreplaced) = Redact.ToCommentReporting(content, Db(("tok", Tok), ("other", Other)));

        Assert.Equal("script: |\n  export A=\"\"  # tswap: tok\n    " + B64(Other) + "\n", result);
        LineDiff[] expected = [new(2, "  export A=" + Tok, "  export A=\"\"  # tswap: tok")];
        Assert.Equal(expected, changes);
        UnreplacedLine[] left = [new(3, "other")];
        Assert.Equal(left, unreplaced);
    }

    [Fact]
    public void SameValueTwiceOnALine_OneRecord()
    {
        AssertLeft("k: |\n  " + B64(Tok) + " " + B64(Tok) + "\n", Db(("tok", Tok)), new UnreplacedLine(2, "tok"));
    }

    /// <summary>
    /// Brief T22: which lines are block-scalar content, one character per element of the file split on LF
    /// ('1' content, '0' not).
    /// </summary>
    [Theory]
    [InlineData("k: |\n  a\n\n  b\nx: 1\n", "011100")]          // blank lines inside count
    [InlineData("  k: |\n   a\n  x\n   y\n", "01000")]          // ends at the first non-blank line at the node column
    [InlineData("  k: |\n    a\n \n    b\nz\n", "011100")]      // a blank line indented less does not end it
    [InlineData("a: |\n  b: |\n    c\n  d\ne\n", "011100")]     // a nested block start is content
    [InlineData("k: |\n  a\n", "010")]                          // the trailing empty element is not content
    [InlineData("k: |\n  a\n\n", "0110")]                       // ... but a blank line before it is
    [InlineData("- |\n  a\n- b\n", "0100")]                     // bare sequence entry: the dash's column
    [InlineData("  - key: |\n      a\n    sib: x\n", "0100")]   // compact entry: the key's column
    [InlineData("k: >-\n a\n", "010")]
    [InlineData("k: |+\n a\n", "010")]
    [InlineData("k: |2-\n a\n", "010")]
    [InlineData("k: >-1\n a\n", "010")]
    [InlineData("k: !!binary |\n a\n", "010")]
    [InlineData("k: &a >2\n a\n", "010")]
    [InlineData("k: | # note\n a\n", "010")]
    [InlineData("k: \"|\"\n a\n", "000")]                       // quoted
    [InlineData("k: &a|\n a\n", "000")]                         // 'a|' is the anchor's name
    [InlineData("k: !!binary|\n a\n", "000")]                   // '!!binary|' is the tag
    [InlineData("k: |++\n a\n", "000")]                         // one chomping indicator only
    [InlineData("k: | x\n a\n", "000")]                         // text after the indicator
    [InlineData("k: v\n a\n", "000")]
    public void BlockScalarContent_MarksContentLines(string content, string expected)
    {
        var marks = ToCommentProcessor.BlockScalarContent(content.Split('\n'));

        Assert.Equal(expected, string.Concat(marks.Select(m => m ? '1' : '0')));
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

    // ------------------------------------------------------------------ T22 (#319): the warning

    private static string B64(string value) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value));

    private static string Warning(int line, string token) =>
        $"Warning: line {line} holds an encoded form (base64 or similar) of the value of '{token}' inside a YAML block scalar. " +
        "A '# tswap:' marker is filled with the plain value, so it was not replaced: move the value out of the block by hand, or keep the block as a whole secret.";

    private static readonly string IssueLine = "    " + B64(Pem);

    /// <summary>The #319 file: a block whose content line is the base64 of pem's value.</summary>
    private string WriteIssueFile(string extra = "", bool crlf = false)
    {
        var file = _m.PathOf("issue.yaml");
        var text = "key: |\n" + IssueLine + "\nnext: 1\n" + extra;
        File.WriteAllBytes(file, System.Text.Encoding.UTF8.GetBytes(crlf ? text.Replace("\n", "\r\n") : text));
        return file;
    }

    private static string[] Mode(bool dryRun) => dryRun ? ["--dry-run"] : [];

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void OnlyAnUnreplacedLine_WarnsAndLeavesTheFile(bool dryRun, bool crlf)
    {
        var file = WriteIssueFile(crlf: crlf);
        var before = File.ReadAllBytes(file);

        var (exit, _, stderr) = _m.Run("", ["tocomment", file, .. Mode(dryRun)]);

        Assert.True(exit == 0, stderr);
        Assert.Equal(Warning(2, "pem") + "\nFile unchanged.\n", stderr.Replace("\r\n", "\n"));
        Assert.DoesNotContain("No secrets found", stderr);
        Assert.Equal(before, File.ReadAllBytes(file)); // not written at all: CRLF line ends stay too
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnreplacedLine_NothingOfItIsPrinted(bool dryRun)
    {
        _m.Ok("plain-Secret-value-9", "ingest", "tok");
        var file = WriteIssueFile("token: plain-Secret-value-9\n");

        var (exit, stdout, stderr) = _m.Run("", ["tocomment", file, .. Mode(dryRun)]);

        Assert.True(exit == 0, stderr);
        Assert.Contains(Warning(2, "pem"), stderr);
        foreach (var text in (string[])[B64(Pem), IssueLine.Trim(), .. Pem.Split('\n'), "plain-Secret-value-9"])
        {
            Assert.DoesNotContain(text, stdout);
            Assert.DoesNotContain(text, stderr);
        }
    }

    [Fact]
    public void ReplacedAndUnreplacedLines_WritesTheReplacedOne_Warns_CountsOne()
    {
        _m.Ok("plain-Secret-value-9", "ingest", "tok");
        var file = WriteIssueFile("token: plain-Secret-value-9\n");

        var (exit, _, stderr) = _m.Run("", "tocomment", file);

        Assert.True(exit == 0, stderr);
        Assert.Equal("key: |\n" + IssueLine + "\nnext: 1\ntoken: \"\"  # tswap: tok\n", File.ReadAllText(file));
        // The listing, then the warning, then the summary counting only the changed line.
        Assert.EndsWith(
            "  line 4:\n  - token: [REDACTED: tok]\n  + token: \"\"  # tswap: tok\n" + Warning(2, "pem") + "\n\n✓ 1 line(s) updated in " + file + "\n",
            stderr.Replace("\r\n", "\n"));
    }

    [Fact]
    public void ReplacedAndUnreplacedLines_DryRun_SameWarning()
    {
        _m.Ok("plain-Secret-value-9", "ingest", "tok");
        var file = WriteIssueFile("token: plain-Secret-value-9\n");
        var before = File.ReadAllBytes(file);

        var (exit, _, stderr) = _m.Run("", "tocomment", file, "--dry-run");

        Assert.True(exit == 0, stderr);
        Assert.EndsWith(Warning(2, "pem") + "\n\n(dry run) 1 line(s) would be modified.\n", stderr.Replace("\r\n", "\n"));
        Assert.Equal(before, File.ReadAllBytes(file));
    }

    [Fact]
    public void PreviousVersion_WarningNamesNamePrevious()
    {
        const string old = "old-Rotated-value-77";
        _m.Ok(old, "ingest", "svc");
        _m.Ok("", "burn", "svc", "test");
        _m.Ok("", "rotate", "svc");
        var file = _m.PathOf("prev.yaml");
        File.WriteAllText(file, "script: |\n  echo " + B64(old) + " | base64 -d\n");

        var (exit, _, stderr) = _m.Run("", "tocomment", file);

        Assert.True(exit == 0, stderr);
        Assert.Equal(Warning(2, "svc:previous") + "\nFile unchanged.\n", stderr.Replace("\r\n", "\n"));
    }

    [Fact]
    public void NoSecrets_SaysSoExactly()
    {
        var file = _m.PathOf("none.yaml");
        File.WriteAllText(file, "key: |\n  nothing here\n");

        var (exit, _, stderr) = _m.Run("", "tocomment", file);

        Assert.True(exit == 0, stderr);
        Assert.Equal("No secrets found. File unchanged.\n", stderr.Replace("\r\n", "\n"));
    }
}
