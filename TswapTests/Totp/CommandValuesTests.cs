using TswapCore;
using TswapCore.Totp;
using Xunit;
using static TswapTests.Totp.OtpNetContractTests;

namespace TswapTests.Totp;

/// <summary>
/// Code review round 1 (MiMo M4): <see cref="CommandValues"/> asks its inner lookup for a value once per token, also
/// when the value is passed on as stored, so an uncached lookup never decrypts a value twice.
/// </summary>
public sealed class CommandValuesTests
{
    private sealed class CountingLookup(Dictionary<string, string> values) : ISecretLookup
    {
        public List<string> Resolved { get; } = [];
        public bool Contains(string name) => values.ContainsKey(name);
        public bool HasPreviousValue(string name) => false;
        public bool IsBurnedToken(string token) => false;
        public void ThrowIfUnreadable(string name) { }

        public string ResolveToken(string token, string? where = null)
        {
            Resolved.Add(token);
            return values[token];
        }
    }

    [Theory]
    [InlineData("plain-password-1", "t", "plain-password-1")]
    [InlineData(Sha1Uri, "t", "050471")]
    [InlineData(Sha1Seed, "t:totp", "050471")]
    public void ResolveToken_AsksTheInnerLookupExactlyOnce(string stored, string token, string expected)
    {
        var inner = new CountingLookup(new() { ["t"] = stored });
        var values = new CommandValues(inner, At(1111111111), "tswap", windows: false);

        Assert.Equal(expected, values.ResolveToken(token));
        Assert.Equal(["t"], inner.Resolved);
    }
}
