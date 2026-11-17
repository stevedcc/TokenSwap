using RedactingPty;
using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T35 Task 4 (#349): <see cref="TerminalTitleMatcher"/> through RedactingPty's real
/// <see cref="StreamRedactor"/>: window-title sequences (OSC 0, 1, 2) are dropped from a child's output, everything
/// else passes byte for byte, and a prompt is never held back.
/// </summary>
public sealed class TerminalTitleMatcherTests
{
    private const string Title = "\u001b]0;C:\\WINDOWS\\system32\\choice.exe\u0007";

    // The owner's capture of `tswap run choice /m '{{name}}' /t 1 /d y` (#349), ESC written out.
    private const string OwnersCapture =
        "\u001b[?9001h\u001b[?1004h\u001b[?25l\u001b[2J\u001b[m\u001b[H[REDACTED: name] [Y,N]?" + Title + "\u001b[?25h\r\n\u001b[?9001l\u001b[?1004l";

    private static string Redact(string input, int chunkSize, params StreamReplacement[] replacements)
    {
        var redactor = new StreamRedactor(replacements, [new TerminalTitleMatcher()]);
        var output = new System.Text.StringBuilder();
        for (var i = 0; i < input.Length; i += chunkSize)
            output.Append(redactor.ProcessChunk(input.Substring(i, Math.Min(chunkSize, input.Length - i))));
        output.Append(redactor.Flush());
        return output.ToString();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(int.MaxValue)]
    public void OwnersCapture_TitleGone_RestByteForByte(int chunkSize)
    {
        Assert.Equal(OwnersCapture.Replace(Title, ""), Redact(OwnersCapture, chunkSize));
    }

    [Theory]
    [InlineData("\u001b]0;t\u0007")]
    [InlineData("\u001b]2;t\u001b\\")]
    [InlineData("\u001b]1;t\u0007")]
    public void BothTerminators_AndOsc1And2(string title)
    {
        Assert.Equal("ab", Redact("a" + title + "b", int.MaxValue));
        Assert.Equal("ab", Redact("a" + title + "b", 1));
    }

    [Theory]
    [InlineData("\u001b]8;;https://x\u001b\\")] // a hyperlink
    [InlineData("\u001b]4;1;rgb:ff/00/00\u0007")] // a colour
    [InlineData("\u001b[2J\u001b[H")] // CSI
    public void OtherSequences_Stay(string sequence)
    {
        var input = "a" + sequence + "b";

        Assert.Equal(input, Redact(input, int.MaxValue));
        Assert.Equal(input, Redact(input, 1));
    }

    [Fact]
    public void UnterminatedOrOverlong_PassesThrough()
    {
        var overlong = "a\u001b]0;" + new string('t', TerminalTitleMatcher.MaxTitleLength + 1) + "\u0007b";
        var longest = "a\u001b]0;" + new string('t', TerminalTitleMatcher.MaxTitleLength) + "\u0007b";
        const string unterminated = "a\u001b]0;never ended";

        Assert.Equal(overlong, Redact(overlong, 5));
        Assert.Equal("ab", Redact(longest, 5));
        Assert.Equal(unterminated, Redact(unterminated, int.MaxValue));
        Assert.Equal(unterminated, Redact(unterminated, 1));
    }

    [Fact]
    public void Prompt_IsNotHeld()
    {
        Assert.Equal("Overwrite? [Y,N]?", new StreamRedactor([], [new TerminalTitleMatcher()]).ProcessChunk("Overwrite? [Y,N]?"));

        var titleStarted = new StreamRedactor([], [new TerminalTitleMatcher()]);
        Assert.Equal("abc", titleStarted.ProcessChunk("abc\u001b]0;par"));
        Assert.True(titleStarted.HasHeld);

        Assert.Equal("abc\u001b[2J", new StreamRedactor([], [new TerminalTitleMatcher()]).ProcessChunk("abc\u001b[2J"));
    }

    [Theory]
    [InlineData("abc\u001b", 3)]
    [InlineData("abc\u001b]", 3)]
    [InlineData("abc\u001b]2", 3)]
    [InlineData("abc\u001b]2;", 3)]
    [InlineData("abc\u001b]2;title\u001b", 3)]
    [InlineData("abc\u001b]9", 6)] // not a title number
    [InlineData("abc\u001b]2;ti\u001btle", 13)] // ESC inside the text, not a terminator
    public void PendingFrom_TheIncompleteTitleOnly(string window, int expected)
    {
        Assert.Equal(expected, ((IStreamMatcher)new TerminalTitleMatcher()).PendingFrom(window));
    }

    [Fact]
    public void TitleHoldingASecret_NeitherSurvives()
    {
        var replacement = new StreamReplacement("s3cret-title", "[REDACTED: t]");

        Assert.Equal("ab", Redact("a\u001b]0;s3cret-title\u0007b", int.MaxValue, replacement));
        Assert.Equal("ab", Redact("a\u001b]0;s3cret-title\u0007b", 2, replacement));
    }
}
