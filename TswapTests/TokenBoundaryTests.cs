using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore.Fingerprints;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T30 (#314): <see cref="TokenBoundary"/>, the rule that a value shorter than 8 characters is
/// matched only where it stands as a whole word or number. A word character is what tocomment's
/// <c>[-\w]</c> matches; an occurrence is delimited when each of its ends that is a word character has
/// no word character beyond it (the text's start and end count as non-word neighbours).
/// </summary>
public class TokenBoundaryTests
{
    [Fact]
    public void IsWordChar_EqualsToCommentsClass()
    {
        var wordClass = new Regex(@"^[-\w]$");
        for (var c = 0; c <= 0xFFFF; c++)
        {
            var ch = (char)c;
            Assert.True(wordClass.IsMatch(ch.ToString()) == TokenBoundary.IsWordChar(ch), $"U+{c:X4}");
        }
    }

    [Theory]
    [InlineData("65465", 2, 3, false)]
    [InlineData("1465", 1, 3, false)]
    [InlineData("4650", 1, 3, false)]
    [InlineData("port=465", 5, 3, true)]
    [InlineData("\"465\"", 1, 3, true)]
    [InlineData(":465/", 1, 3, true)]
    [InlineData("465", 0, 3, true)]
    [InlineData("web-ngx", 0, 3, false)]
    [InlineData("webster", 0, 3, false)]
    [InlineData("user_web", 5, 3, false)]
    [InlineData("éweb", 1, 3, false)]
    [InlineData("web.example", 0, 3, true)]
    [InlineData("host: web", 6, 3, true)]
    [InlineData("x#42", 1, 3, true)]
    [InlineData("142!", 1, 3, false)]
    [InlineData("a 42!b", 2, 3, true)]
    [InlineData("😀465😀", 2, 3, true)]
    public void IsDelimited(string text, int start, int length, bool expected) =>
        Assert.Equal(expected, TokenBoundary.IsDelimited(text, start, length));

    public static TheoryData<string, int, int> HoldCases => new()
    {
        { "ab 65465", 5, 3 },
        { "ab 65465", 8, 3 },
        { "ab 65465", 2, 2 },
        { "ab cd", 3, 3 },
        { " " + new string('x', 256), 257, 1 },
        { " " + new string('x', 257), 258, 258 },
        { "", 0, 0 },
    };

    [Theory]
    [MemberData(nameof(HoldCases))]
    public void HoldOutsideWord(string text, int pending, int expected) =>
        Assert.Equal(expected, TokenBoundary.HoldOutsideWord(text, pending));

    [Fact]
    public void IsShort_SevenShort_EightNot()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        Assert.True(TokenBoundary.IsShort(Fingerprinter.Compute(Encoding.UTF8.GetBytes("abcdefg"), keys)));
        Assert.False(TokenBoundary.IsShort(Fingerprinter.Compute(Encoding.UTF8.GetBytes("abcdefgh"), keys)));
    }

    /// <summary>
    /// Amendment A4 (ruling): a set without a plain entry (an empty value's set, or one from a later
    /// build's variant set) is not short, so its entries keep matching anywhere: the masking side.
    /// </summary>
    [Fact]
    public void IsShort_NoPlainEntry_NotShort()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var shortSet = Fingerprinter.Compute(Encoding.UTF8.GetBytes("abc"), keys);
        var withoutPlain = shortSet with { Entries = [.. shortSet.Entries.Where(e => e.Kind != VariantKind.Plain)] };

        Assert.NotEmpty(withoutPlain.Entries);
        Assert.False(TokenBoundary.IsShort(withoutPlain));
        Assert.False(TokenBoundary.IsShort(Fingerprinter.Compute([], keys)));
    }
}
