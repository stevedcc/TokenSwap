using System.Text;
using System.Text.RegularExpressions;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T63 (#419): after <c>tocomment</c> replaces a value, a continuation line (indented deeper, base64-like) that
/// holds a stored value (any variant, current or previous, inside a longer run too) is commented out (<c># </c> after
/// its indentation) and reported as <see cref="SkippedReason.ContinuationLine"/>, never removed; in block-scalar content
/// it stays as it is (<see cref="SkippedReason.InBlockScalar"/>). A continuation line holding no value is removed as
/// before.
/// </summary>
public sealed class ToCommentContinuationTests
{
    private const string A = "Aaaaaaaaaaaaaaaaaaaa1";
    private const string B = "Bbbbbbbbbbbbbbbbbbbb2";
    private const string C = "Cccccccccccccccccccc3";

    /// <summary>Filler: base64-like, no stored value.</summary>
    private const string F = "QUJDREVGR0hJSktMTU5PUA==";

    private static string B64(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static readonly LineDiff L1 = new(1, "key: " + A, "key: \"\"  # tswap: a");

    private static CommentedLineDiff Cm(int n, string text) => new(n, "    " + text, "    # " + text);

    private static LineDiff Removed(int n, string text) => new(n, "    " + text, "");

    private static Secret S(string value, string? previous = null) =>
        new(value, TestTime.Fixed, TestTime.Fixed, null, null) { PreviousValue = previous };

    private static SecretsDb Db(params (string Name, Secret Secret)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => s.Secret)) { KeepsPreviousValues = true };

    private static SecretsDb AB(bool withC = false) => withC
        ? Db(("a", S(A)), ("b", S(B)), ("c", S(C)))
        : Db(("a", S(A)), ("b", S(B)));

    /// <summary><c>Redact.ToCommentReport</c>, its markers checked to fill back (<see cref="ToCommentRoundTrip"/>).</summary>
    private static ToCommentReport ToCommentReport(string content, SecretsDb db)
    {
        var report = Redact.ToCommentReport(content, db);
        ToCommentRoundTrip.Check(report.Changes, db);
        return report;
    }

    private sealed record Row(string Content, SecretsDb Db, string After, LineDiff[] Changes, SkippedValue[] Skipped);

    private static SkippedValue Cont(int line, string token) => new(line, line, token, SkippedReason.ContinuationLine);

    private static readonly int[] CommentedRows = [1, 2, 3, 4, 5, 6, 7, 8, 81];

    private static Row RowOf(int row) => row switch
    {
        1 => new($"key: {A}\n    {B}\nnext: x\n", AB(), $"key: \"\"  # tswap: a\n    # {B}\nnext: x\n",
            [L1, Cm(2, B)], [Cont(2, "b")]),
        2 => new($"key: {A}\n    {B64(B)}\n", AB(), $"key: \"\"  # tswap: a\n    # {B64(B)}\n",
            [L1, Cm(2, B64(B))], [Cont(2, "b")]),
        3 => new($"key: {A}\n    {F}\n    {B}\n", AB(), $"key: \"\"  # tswap: a\n    # {B}\n",
            [L1, Removed(2, F), Cm(3, B)], [Cont(3, "b")]),
        4 => new($"key: {A}\n    XXXX{B}YYYY\n", AB(), $"key: \"\"  # tswap: a\n    # XXXX{B}YYYY\n",
            [L1, Cm(2, "XXXX" + B + "YYYY")], [Cont(2, "b")]),
        5 => new($"key: {A}\n    {B64(A)}\n", AB(), $"key: \"\"  # tswap: a\n    # {B64(A)}\n",
            [L1, Cm(2, B64(A))], [Cont(2, "a")]),
        6 => new($"key: {A}\n    {B}\nnext: x\n", Db(("a", S(A)), ("b", S("Bnewnewnewnewnewnew99", previous: B)))
            , $"key: \"\"  # tswap: a\n    # {B}\nnext: x\n", [L1, Cm(2, B)], [Cont(2, "b:previous")]),
        7 => new($"key: {A}\n    {B}\n    {F}\n", AB(), $"key: \"\"  # tswap: a\n    # {B}\n",
            [L1, Cm(2, B), Removed(3, F)], [Cont(2, "b")]),
        8 => new($"key: {A}\n    {B}{B64(C)}\n", AB(withC: true), $"key: \"\"  # tswap: a\n    # {B}{B64(C)}\n",
            [L1, Cm(2, B + B64(C))], [Cont(2, "b"), Cont(2, "c")]),
        81 => new($"key: {A}\n    {B}\n    {C}\n", AB(withC: true), $"key: \"\"  # tswap: a\n    # {B}\n    # {C}\n",
            [L1, Cm(2, B), Cm(3, C)], [Cont(2, "b"), Cont(3, "c")]),
        _ => throw new ArgumentOutOfRangeException(nameof(row)),
    };

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(81)] // row 8a
    public void ContinuationLine_HoldingAValue_IsCommentedOut_AndReported(int row)
    {
        var r = RowOf(row);

        var report = ToCommentReport(r.Content, r.Db);

        Assert.Equal(r.After, report.Content);
        Assert.Equal(r.Changes, report.Changes);
        Assert.Equal(r.Skipped, report.Skipped);
        Assert.Empty(report.Unreplaced);
    }

    [Fact]
    public void ContinuationLine_WithNoValue_IsRemovedAsBefore()
    {
        var report = ToCommentReport($"key: {A}\n    {F}\n", AB());

        Assert.Equal("key: \"\"  # tswap: a\n", report.Content);
        Assert.Equal([L1, Removed(2, F)], report.Changes);
        Assert.Empty(report.Skipped);
    }

    [Fact]
    public void ContinuationLine_InBlockContent_HoldingAPlainValue_KeptAsItIs()
    {
        var content = $"script: |\n  export A={A}\n    {B}\n";

        var report = ToCommentReport(content, AB());

        Assert.Equal($"script: |\n  export A=\"\"  # tswap: a\n    {B}\n", report.Content);
        Assert.Equal([new LineDiff(2, "  export A=" + A, "  export A=\"\"  # tswap: a")], report.Changes);
        Assert.Equal([new SkippedValue(3, 3, "b", SkippedReason.InBlockScalar)], report.Skipped);
    }

    private static readonly Regex KeyLine = new(@"^[A-Za-z]\w*: ");

    [Fact]
    public void ContinuationLine_CommentedOut_EveryLineIsAKeyOrAComment()
    {
        foreach (var row in CommentedRows)
        {
            var r = RowOf(row);
            var lines = ToCommentReport(r.Content, r.Db).Content.Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                Assert.True(line.Length == 0 || KeyLine.IsMatch(line) || line.TrimStart().StartsWith('#'),
                    $"row {row}, line {i + 1}: neither empty, a key at column 0, nor a comment");
            }
        }
    }

    [Fact]
    public void ToComment_SecondRun_OverACommentedLine_ReportsItAsNotAWholeValue()
    {
        var first = RowOf(1).After;

        var report = ToCommentReport(first, AB());

        Assert.Equal(first, report.Content);
        Assert.Empty(report.Changes);
        Assert.Equal([new SkippedValue(2, 2, "b", SkippedReason.NotWholeValue)], report.Skipped);
    }
}
