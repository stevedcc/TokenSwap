using TswapCore.Fingerprints;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T65 (#434): <see cref="LineEndingViews.WriteBreaks"/> builds the views with every line break written as
/// <c>\n</c>, <c>\r\n</c> or <c>\r</c>, with span maps; <see cref="LineEndingViews.HasLoneCr"/> says when the first two
/// can differ from the folded and unfolded views.
/// </summary>
public class LineEndingViewsTests
{
    private static (string View, int[] Starts, int[] Ends) Write(string text, string lineBreak)
    {
        var view = new char[2 * text.Length];
        var starts = new int[2 * text.Length];
        var ends = new int[2 * text.Length];
        var m = LineEndingViews.WriteBreaks(text, lineBreak, view, starts, ends);
        return (new string(view, 0, m), starts[..m], ends[..m]);
    }

    public static TheoryData<string, string, string, int[], int[]> MapRows => new()
    {
        { "a\r\nb", "\n", "a\nb", [0, 1, 3], [1, 3, 4] },
        { "a\rb", "\r\n", "a\r\nb", [0, 1, 2, 2], [1, 2, 2, 3] },
        { "a\nb", "\r", "a\rb", [0, 1, 2], [1, 2, 3] },
        { "a\nb", "\r\n", "a\r\nb", [0, 1, 1, 2], [1, 1, 2, 3] },
        { "\r", "\n", "\n", [0], [1] },
    };

    [Theory, MemberData(nameof(MapRows))]
    public void WriteBreaks_MapsEachBreak(string text, string lineBreak, string view, int[] starts, int[] ends)
    {
        var written = Write(text, lineBreak);

        Assert.Equal(view, written.View);
        Assert.Equal(starts, written.Starts);
        Assert.Equal(ends, written.Ends);
    }

    [Fact]
    public void WriteBreaks_ViewIsWithLineBreaks()
    {
        char[] alphabet = ['a', '\r', '\n'];
        var checkedStrings = 0;
        for (var length = 0; length <= 6; length++)
        {
            var count = (int)Math.Pow(alphabet.Length, length);
            for (var code = 0; code < count; code++)
            {
                var chars = new char[length];
                for (int i = 0, c = code; i < length; i++, c /= alphabet.Length)
                    chars[i] = alphabet[c % alphabet.Length];
                var text = new string(chars);
                foreach (var lineBreak in new[] { "\n", "\r\n", "\r" })
                {
                    var (view, starts, ends) = Write(text, lineBreak);
                    Assert.Equal(LineEndingViews.WithLineBreaks(text, lineBreak), view);
                    for (var i = 0; i < view.Length; i++)
                    {
                        Assert.True(starts[i] <= ends[i], $"{Escape(text)} as {Escape(lineBreak)}: index {i} maps to [{starts[i]}, {ends[i]})");
                        if (i > 0)
                            Assert.True(starts[i - 1] <= starts[i] && ends[i - 1] <= ends[i],
                                $"{Escape(text)} as {Escape(lineBreak)}: the maps decrease at index {i}");
                    }
                }
                checkedStrings++;
            }
        }
        Assert.Equal(1 + 3 + 9 + 27 + 81 + 243 + 729, checkedStrings);
    }

    [Fact]
    public void WriteBreaks_AnyOtherLineBreak_Throws() =>
        Assert.Throws<ArgumentException>(() => Write("a\nb", "\n\n"));

    [Theory]
    [InlineData("a\rb", true)]
    [InlineData("a\r", true)]
    [InlineData("\r\r\n", true)]
    [InlineData("a\r\nb", false)]
    [InlineData("a\nb", false)]
    [InlineData("", false)]
    public void HasLoneCr(string text, bool expected) => Assert.Equal(expected, LineEndingViews.HasLoneCr(text));

    private static string Escape(string s) => s.Replace("\r", "\\r").Replace("\n", "\\n");
}
