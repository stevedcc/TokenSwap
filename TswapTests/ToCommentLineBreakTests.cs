using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T50b Task 3 (#399): <c>tocomment</c> finds a value with a line break on the raw content (and its line-ending
/// views). It is replaced as one change (<see cref="MultiLineDiff"/>) only when it is a whole value after <c>key:</c>
/// and outside block-scalar content. Otherwise it is left and reported as a <see cref="SkippedValue"/> over its lines.
/// Every row runs the round-trip guard; the rows the oracle handles also compare its content and changes.
/// </summary>
public sealed class ToCommentLineBreakTests
{
    private static SecretsDb Db(params (string Name, string Value)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => new Secret(s.Value, TestTime.Fixed, TestTime.Fixed, null, null))) { KeepsPreviousValues = true };

    private const string Two = "line-one\nline-two";

    private static ToCommentReport Report(string content, SecretsDb db, bool oracle = true)
    {
        var report = Redact.ToCommentReport(content, db);
        if (oracle)
        {
            var (oracleContent, oracleChanges) = PlaintextRedactOracle.ToComment(content, db);
            Assert.Equal(report.Content, oracleContent);
            Assert.Equal(report.Changes, oracleChanges);
        }
        ToCommentRoundTrip.Check(report.Changes, db);
        return report;
    }

    private static (int, int, string, SkippedReason)[] Skipped(ToCommentReport report) =>
        [.. report.Skipped.Select(s => (s.FirstLine, s.LastLine, s.Token, s.Reason))];

    private static void AssertUnchanged(ToCommentReport report, string content, params (int, int, string, SkippedReason)[] skipped)
    {
        Assert.Equal(content.Replace("\r\n", "\n"), report.Content);
        Assert.Empty(report.Changes);
        Assert.Equal(skipped, Skipped(report));
    }

    private static readonly LineDiff Row1Change = new MultiLineDiff(1, 2, "token: line-one\nline-two", "token: \"\"  # tswap: s");

    [Theory]
    [InlineData(1, Two, "token: line-one\nline-two\nnext: 1\n")]
    [InlineData(2, "line-one\r\nline-two", "token: line-one\r\nline-two\r\nnext: 1\r\n")]
    [InlineData(3, "line-one\r\nline-two", "token: line-one\nline-two\nnext: 1\n")]
    [InlineData(4, Two, "token: line-one\r\nline-two\r\nnext: 1\r\n")]
    public void Rows1To4_ReplacedWhateverTheLineEndings(int row, string stored, string content)
    {
        var report = Report(content, Db(("s", stored)));

        Assert.True(report.Content == "token: \"\"  # tswap: s\nnext: 1\n", $"row {row}");
        Assert.Equal(new[] { Row1Change }, report.Changes);
        Assert.Empty(report.Skipped);
    }

    [Fact]
    public void Row5_InTheMiddleOfAFile()
    {
        var report = Report("a: 1\ntoken: line-one\nline-two\nb: 2\n", Db(("s", Two)));

        Assert.Equal("a: 1\ntoken: \"\"  # tswap: s\nb: 2\n", report.Content);
        Assert.Equal(new LineDiff[] { new MultiLineDiff(2, 3, "token: line-one\nline-two", "token: \"\"  # tswap: s") }, report.Changes);
        Assert.Empty(report.Skipped);
    }

    [Fact]
    public void Row6_ThreeLines()
    {
        var report = Report("token: line-one\nline-two\nline-three\n", Db(("s", "line-one\nline-two\nline-three")));

        Assert.Equal("token: \"\"  # tswap: s\n", report.Content);
        Assert.Equal(new LineDiff[] { new MultiLineDiff(1, 3, "token: line-one\nline-two\nline-three", "token: \"\"  # tswap: s") }, report.Changes);
        Assert.Empty(report.Skipped);
    }

    [Fact]
    public void Row7_QuotedWithAComment()
    {
        var report = Report("token: \"line-one\nline-two\"  # note\n", Db(("s", Two)));

        Assert.Equal("token: \"\"  # tswap: s  # note\n", report.Content);
        Assert.Equal(new LineDiff[] { new MultiLineDiff(1, 2, "token: \"line-one\nline-two\"  # note", "token: \"\"  # tswap: s  # note") }, report.Changes);
        Assert.Empty(report.Skipped);
    }

    [Theory]
    [InlineData(8, "cmd: echo line-one\nline-two | tee x\n")]
    [InlineData(9, "TOKEN=line-one\nline-two\n")]
    [InlineData(10, "token: line-one\nline-two more\n")]
    public void Rows8To10_NotAWholeValue_Left(int row, string content)
    {
        var report = Report(content, Db(("s", Two)));

        Assert.True(report.Changes.Count == 0, $"row {row}");
        AssertUnchanged(report, content, (1, 2, "s", SkippedReason.NotWholeValue));
    }

    [Fact]
    public void Row11_AnotherValueBeforeIt_Reported()
    {
        var report = Report("password: xyz-12345 token: line-one\nline-two\n", Db(("s", Two), ("p", "xyz-12345")));

        Assert.Equal("password: xyz-12345 token: \"\"  # tswap: s\n", report.Content);
        Assert.Equal(new LineDiff[] { new MultiLineDiff(1, 2, "password: xyz-12345 token: line-one\nline-two", "password: xyz-12345 token: \"\"  # tswap: s") },
            report.Changes);
        Assert.Equal(new[] { (1, 1, "p", SkippedReason.NotWholeValue) }, Skipped(report));
    }

    [Fact]
    public void Row12_LeftAndAnotherValueAfterIt()
    {
        const string content = "cmd: echo line-one\nline-two | tee-cmd-x\n";

        var report = Report(content, Db(("s", Two), ("t", "tee-cmd-x")));

        AssertUnchanged(report, content, (1, 2, "s", SkippedReason.NotWholeValue), (2, 2, "t", SkippedReason.NotWholeValue));
    }

    [Fact]
    public void Row13_AnotherValueInTheComment_Reported()
    {
        var report = Report("token: line-one\nline-two  # key: y-value-123\n", Db(("s", Two), ("y", "y-value-123")));

        Assert.Equal("token: \"\"  # tswap: s  # key: y-value-123\n", report.Content);
        Assert.Equal(new LineDiff[] { new MultiLineDiff(1, 2, "token: line-one\nline-two  # key: y-value-123", "token: \"\"  # tswap: s  # key: y-value-123") },
            report.Changes);
        Assert.Equal(new[] { (2, 2, "y", SkippedReason.NotWholeValue) }, Skipped(report));
    }

    [Fact]
    public void Row14_InsideBlockContent_LeftAsInBlockScalar()
    {
        const string content = "script: |\n  echo line-one\n  line-two\n";

        var report = Report(content, Db(("s", "line-one\n  line-two")), oracle: false);

        AssertUnchanged(report, content, (2, 3, "s", SkippedReason.InBlockScalar));
    }

    [Fact]
    public void Row15_AdoptedBlock_DropsTheOccurrenceInsideIt()
    {
        var report = Report("key: |\n  line-one\n  line-two\n", Db(("pem", Two), ("frag", "line-one\n  line-two")), oracle: false);

        Assert.Equal("key: \"\"  # tswap: pem\n", report.Content);
        LineDiff[] expected = [new(1, "key: |", "key: \"\"  # tswap: pem"), new BlockLineDiff(2, "  line-one"), new BlockLineDiff(3, "  line-two")];
        Assert.Equal(expected, report.Changes);
        Assert.Empty(report.Skipped);
    }

    [Fact]
    public void Row16_StartsWithALineBreak_Left()
    {
        const string content = "x: a\nline-two-x\n";

        var report = Report(content, Db(("s", "\nline-two-x")));

        AssertUnchanged(report, content, (1, 2, "s", SkippedReason.NotWholeValue));
    }

    /// <summary>
    /// Code review (MiMo I-1): a value ending in a CR that is the CR of the file's CRLF, or a CR at the end of the file,
    /// ends at a line break: it is left and reported (it used to throw, or consume the file's last line break).
    /// </summary>
    [Theory]
    [InlineData("token: line-one\nline-two\r\nnext: 1\r\n")]
    [InlineData("token: line-one\nline-two\r")]
    public void EndsWithTheCrOfALineBreak_Left(string content)
    {
        var report = Report(content, Db(("s", "line-one\nline-two\r")));

        AssertUnchanged(report, content, (1, 2, "s", SkippedReason.NotWholeValue));
    }

    /// <summary>Code review (MiMo M-2): a value in the marker a multi-line replacement consumes is gone, so it is not reported.</summary>
    [Fact]
    public void ValueInsideTheConsumedMarker_NotReported()
    {
        var report = Report("token: line-one\nline-two  # tswap: old-name\n", Db(("s", Two), ("o", "old-name")));

        Assert.Equal("token: \"\"  # tswap: s\n", report.Content);
        Assert.Empty(report.Skipped);
    }

    /// <summary>Code review (MiMo M-4): two multi-line values competing for overlapping text; the longer one is taken first.</summary>
    [Fact]
    public void CompetingMultiLineValues_TheLongerFirst()
    {
        const string content = "k: one-x\ntwo-x\nthree-x\n";

        var report = Report(content, Db(("s1", "one-x\ntwo-x"), ("s2", "two-x\nthree-x")));

        AssertUnchanged(report, content, (2, 3, "s2", SkippedReason.NotWholeValue));
    }

    /// <summary>Code review (MiMo M-4): a multi-line value shorter than 8 characters, as a whole value and inside a word.</summary>
    [Fact]
    public void ShortMultiLineValue()
    {
        var db = Db(("s", "a1\nb2"));

        var whole = Report("k: a1\nb2\n", db);
        Assert.Equal("k: \"\"  # tswap: s\n", whole.Content);
        Assert.Equal(new LineDiff[] { new MultiLineDiff(1, 2, "k: a1\nb2", "k: \"\"  # tswap: s") }, whole.Changes);

        var inWord = Report("k: xa1\nb2\n", db);
        Assert.Equal("k: xa1\nb2\n", inWord.Content);
        Assert.Empty(inWord.Changes);
    }

    [Fact]
    public void Row17_EndsWithALineBreak_TheLinePathReplacesTheStrippedForm()
    {
        var report = Report("token: line-one-x\nnext: 1\n", Db(("s", "line-one-x\n")));

        Assert.Equal("token: \"\"  # tswap: s\nnext: 1\n", report.Content);
        Assert.Equal(new[] { new LineDiff(1, "token: line-one-x", "token: \"\"  # tswap: s") }, report.Changes);
        Assert.Empty(report.Skipped);
    }
}
