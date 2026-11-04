using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>Guided init, task 2: answers that tolerate a stray YubiKey one-time code.</summary>
public class GuidedPromptsTests
{
    [Theory]
    [InlineData("cccccbvjiflgrtrrkvuvdvnhlfrngkbckfbtveuftrgt", true)]
    [InlineData("1 3", false)]
    [InlineData("yes", false)]
    [InlineData("", false)]
    public void LooksLikeYubicoOtp(string line, bool expected) =>
        Assert.Equal(expected, GuidedPrompts.LooksLikeYubicoOtp(line));

    [Fact]
    public void ReadAnswer_SkipsAnOtpLine_AndSaysSo()
    {
        var c = new FakeConsole("cccccbvjiflgrtrrkvuvdvnhlfrngkbckfbtveuftrgt\n1 3\n") { IsInputRedirected = false };
        Assert.Equal("1 3", GuidedPrompts.ReadAnswer(c));
        Assert.Contains("That was a YubiKey's one-time code; it was ignored.", c.OutText);
        Assert.DoesNotContain("flashing", c.OutText);
    }

    [Fact]
    public void ReadAnswer_Eof_IsNull() =>
        Assert.Null(GuidedPrompts.ReadAnswer(new FakeConsole("") { IsInputRedirected = false }));
}
