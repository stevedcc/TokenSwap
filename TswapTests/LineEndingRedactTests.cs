using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T50a Task 1 (#398): <c>redact</c> finds a stored value whatever the line endings of the value and of the file
/// (<c>\r\n</c> or <c>\n</c>), by matching on the raw text, its folded view (each <c>\r\n</c> as <c>\n</c>) and its
/// unfolded view (each bare <c>\n</c> as <c>\r\n</c>), and replacing the raw span. The output is LF as before.
/// </summary>
public class LineEndingRedactTests
{
    private static Secret S(string value) => new(value, TestTime.Fixed, TestTime.Fixed, null, null);

    private static SecretsDb Db(params (string Name, Secret Secret)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => s.Secret)) { KeepsPreviousValues = true };

    public static TheoryData<int, string, string, string> MaskedRows => new()
    {
        { 1, "line-one\r\nline-two", "token: line-one\r\nline-two\r\nnext: 1\r\n", "token: [REDACTED: s]\nnext: 1\n" },
        { 2, "line-one\r\nline-two", "token: line-one\nline-two\nnext: 1\n", "token: [REDACTED: s]\nnext: 1\n" },
        { 3, "line-one\nline-two", "token: line-one\r\nline-two\r\nnext: 1\r\n", "token: [REDACTED: s]\nnext: 1\n" },
        { 4, "line-one\nline-two", "token: line-one\nline-two\nnext: 1\n", "token: [REDACTED: s]\nnext: 1\n" },
        { 5, "line-one\r\nline-two", "a: line-one\r\nline-two\nb: line-one\nline-two\n", "a: [REDACTED: s]\nb: [REDACTED: s]\n" },
        { 6, "single-line-value", "k: single-line-value\r\n", "k: [REDACTED: s]\n" },
        // A value starting at an inserted '\r' (only the unfolded view holds it).
        { 7, "\r\nline-one\r\nline-two", "x:\nline-one\nline-two\n", "x:[REDACTED: s]\n" },
        // A value ending in an inserted '\r': the line break stays.
        { 8, "abc def-gh\r", "x: abc def-gh\n", "x: [REDACTED: s]\n" },
        // Found raw (at the '\n') and folded (at the '\r'): the folded start is leftmost and wins, no stray '\r'.
        { 9, "\nline-two-x", "x: a\r\nline-two-x\r\n", "x: a[REDACTED: s]\n" },
    };

    [Theory, MemberData(nameof(MaskedRows))]
    public void Redact_ValueWithAnyLineEndings_Masked(int row, string value, string content, string expected)
    {
        var output = Redact.RedactContent(content, Db(("s", S(value))));

        Assert.Equal(expected, output);
        var window = EvilValues.FirstWindowOf(value, output);
        Assert.True(window < 0, $"row {row}: an 8-character window of the value appears at index {window} of the output");
    }

    /// <summary>Row 10: only the value's first line is in the text, so nothing is masked (the output is LF).</summary>
    [Fact]
    public void Redact_OnlyPartOfAMultiLineValue_LeftInPlace()
    {
        var output = Redact.RedactContent("x line-one\r\ny\r\n", Db(("s", S("line-one\r\nline-two"))));

        Assert.Equal("x line-one\ny\n", output);
    }
}
