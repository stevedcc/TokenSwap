using TswapCore;
using TswapCore.Agent;
using Xunit;

namespace TswapTests;

/// <summary>Brief T17 ruling 11: <c>--timeout</c>, seconds or <c>&lt;n&gt;d|h|m|s</c> in that order, 60 s to 30 d.</summary>
public class AgentDurationTests
{
    [Theory]
    [InlineData("90", 90)]
    [InlineData("60", 60)]
    [InlineData("90m", 90 * 60)]
    [InlineData("8h", 8 * 3600)]
    [InlineData("1d12h", 36 * 3600)]
    [InlineData("1d12h30m", 36 * 3600 + 30 * 60)]
    [InlineData("1m30s", 90)]
    [InlineData("30d", 30 * 86400)]
    [InlineData("2592000", 30 * 86400)]
    public void Parses(string text, long seconds) =>
        Assert.Equal(TimeSpan.FromSeconds(seconds), AgentDuration.Parse(text));

    [Theory]
    [InlineData("59")]
    [InlineData("59s")]
    [InlineData("0")]
    [InlineData("31d")]
    [InlineData("30d1s")]
    [InlineData("2592001")]
    [InlineData("1x")]
    [InlineData("")]
    [InlineData("-5m")]
    [InlineData("+5m")]
    [InlineData(" 5m")]
    [InlineData("5m ")]
    [InlineData("5m5m")]
    [InlineData("5s1m")]
    [InlineData("1h1d")]
    [InlineData("m")]
    [InlineData("5M")]
    [InlineData("1.5h")]
    [InlineData("99999999999999d")]
    [InlineData("99999999999999999999999")]
    [InlineData("٩٠")] // Arabic-Indic digits: char.IsDigit says yes, the parser must say no
    public void Refuses_AsAUsageError(string text)
    {
        var ex = Assert.Throws<UsageException>(() => AgentDuration.Parse(text));
        Assert.Contains("--timeout", ex.Message);
    }
}
