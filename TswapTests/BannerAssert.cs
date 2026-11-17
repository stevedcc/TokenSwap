using Xunit;

namespace TswapTests;

/// <summary>Brief T34 (#337.6): a printed banner's lines are as wide as its box.</summary>
internal static class BannerAssert
{
    /// <summary>
    /// At least one line of <paramref name="output"/> starts with <c>║</c>, and every such line, and every bottom row (a line
    /// starting with <c>╚</c>, review round 1 M6), has the same length as the nearest line above it that starts with <c>╔</c>.
    /// </summary>
    public static void LinesUp(string output)
    {
        var lines = output.ReplaceLineEndings("\n").Split('\n');
        string? top = null;
        var sides = 0;
        foreach (var line in lines)
        {
            if (line.StartsWith('╔'))
                top = line;
            else if (line.StartsWith('║') || line.StartsWith('╚'))
            {
                if (line.StartsWith('║'))
                    sides++;
                Assert.True(top is not null, $"a banner line with no top above it: {line}");
                Assert.True(line.Length == top.Length, $"'{line}' is {line.Length} characters, its box {top.Length}");
            }
        }
        Assert.True(sides > 0, "no banner line in the output");
    }
}
