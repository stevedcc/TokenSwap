using System.Text;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T54 Task 4 (owner decision 2): <c>tocomment</c> replaces a value found in its other Unicode spelling, as it
/// replaces the stored one; <c>apply</c> then fills in the stored spelling (the round trip below checks the filled
/// value is the vault's). The NFC and NFD plain kinds count as plain for T20, T22 and rule (a′); their stripped and
/// encoded kinds count as encoded.
/// </summary>
public sealed class ToCommentUnicodeFormTests
{
    private const string Stored = "caf\u00e9-db-pass-1";
    private const string Nfd = "cafe\u0301-db-pass-1";

    private static readonly SecretsDb Vault =
        new(new Dictionary<string, Secret> { ["s"] = new(Stored, TestTime.Fixed, TestTime.Fixed, null, null) }) { KeepsPreviousValues = true };

    [Theory]
    [InlineData("password: " + Nfd + "\n", "password: \"\"  # tswap: s\n")]
    [InlineData("DB_PASS=" + Nfd + "\n", "DB_PASS=\"\"  # tswap: s\n")]
    public void TheOtherSpelling_ReplacedAsAWholeValue(string file, string expected)
    {
        var report = ToCommentWholeValueTests.Report(file, Vault);

        Assert.Equal(expected, report.Content);
        Assert.Empty(report.Skipped);
        Assert.Equal(["s"], report.ReplacedNames);
    }

    [Fact]
    public void Base64OfTheOtherSpelling_OnAnEnvLine_LeftAndReported()
    {
        const string base64 = "Y2FmZcyBLWRiLXBhc3MtMQ==";
        Assert.Equal(Convert.ToBase64String(Encoding.UTF8.GetBytes(Nfd)), base64);
        const string file = "DB_PASS=" + base64 + "\n";

        var report = ToCommentWholeValueTests.Report(file, Vault);

        Assert.Equal(file, report.Content);
        Assert.Empty(report.Changes);
        Assert.Equal(new SkippedValue(1, 1, "s", SkippedReason.NotWholeValue), Assert.Single(report.Skipped));
    }

    [Fact]
    public void LiteralBlockHoldingTheOtherSpelling_AdoptedWhole()
    {
        const string file = "key: |\n  " + Nfd + "\n";

        var report = Redact.ToCommentReport(file, Vault);
        ToCommentRoundTrip.Check(report.Changes, Vault);

        Assert.Equal("key: \"\"  # tswap: s\n", report.Content);
        Assert.Empty(report.Skipped);
        Assert.Empty(report.Unreplaced);
    }
}
