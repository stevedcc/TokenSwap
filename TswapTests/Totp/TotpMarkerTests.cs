using TswapCli.Commands;
using TswapCore;
using Xunit;

namespace TswapTests.Totp;

/// <summary>
/// Brief T65 (#435.6): the <c>:totp</c> alternative of the marker and token patterns. <c>tocomment</c> consumes an
/// existing <c># tswap: name:totp</c> marker (<c>ToCommentProcessor.ExistingMarker</c>, and
/// <c>SecretMatcher.ConsumedMarker</c> for a multi-line value), <c>run</c> takes <c>{a:totp}</c> as a token PowerShell
/// passed on (<c>RunCommand.BracedNameRegex</c>), and <c>apply</c> resolves a <c>:totp</c> marker once, without the
/// <c>:previous</c> pre-check.
/// </summary>
public sealed class TotpMarkerTests
{
    private static Secret S(string value) => new(value, TestTime.Fixed, TestTime.Fixed, null, null);

    private static SecretsDb Db(params (string Name, Secret Secret)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => s.Secret)) { KeepsPreviousValues = true };

    [Fact]
    public void ToComment_AnExistingTotpMarker_IsConsumed()
    {
        var db = Db(("pw", S("s3cr3t-value1")));

        var (content, changes) = Redact.ToComment("password: \"s3cr3t-value1\"  # tswap: other:totp", db);

        Assert.Equal("password: \"\"  # tswap: pw", content);
        Assert.Single(changes);
    }

    [Fact]
    public void ToComment_AMultiLineValue_ConsumesATotpMarker()
    {
        var db = Db(("s", S("line-one\nline-two")));

        var report = Redact.ToCommentReport("token: line-one\nline-two  # tswap: old-name:totp\n", db);

        Assert.Equal("token: \"\"  # tswap: s\n", report.Content);
        Assert.Empty(report.Skipped);
    }

    [Fact]
    public void BracedTokens_TakeATotpToken() =>
        Assert.Equal(["{a:totp}"], RunCommand.BracedTokens(["x", "{a:totp}", "{a:other}"]));

    [Fact]
    public void Apply_ATotpMarker_ResolvesOnce_WithoutThePreviousPreCheck()
    {
        var lookup = new RecordingLookup();

        var (content, _) = Apply.ApplySecretsReporting("c: \"\"  # tswap: t:totp\n", lookup, null);

        Assert.Equal("c: \"123456\"  # tswap: t:totp\n", content);
        Assert.Equal(["t:totp"], lookup.Resolved);
    }

    /// <summary>A secret <c>t</c> without a previous value whose every token resolves to <c>123456</c>.</summary>
    private sealed class RecordingLookup : ISecretLookup
    {
        public List<string> Resolved { get; } = [];

        public bool Contains(string name) => true;

        public bool HasPreviousValue(string name) => false;

        public bool IsBurnedToken(string token) => false;

        public string ResolveToken(string token, string? where = null)
        {
            Resolved.Add(token);
            return "123456";
        }

        public void ThrowIfUnreadable(string name)
        {
        }
    }
}
