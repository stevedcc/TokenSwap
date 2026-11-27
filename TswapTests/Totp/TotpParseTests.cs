using System.Text.RegularExpressions;
using TswapCore.Totp;
using TswapTests.Docs;
using Xunit;
using static TswapTests.Totp.OtpNetContractTests;

namespace TswapTests.Totp;

/// <summary>
/// Brief T58 (#374), Task 1: tswap's parse of otpauth URIs and bare Base32 seeds (<see cref="TotpSeed"/>), the
/// recognition of otpauth records (<see cref="TotpCodes.Classify"/>) and the refusal reasons, each exactly as the brief
/// states it. Fixed times only.
/// </summary>
public partial class TotpParseTests
{
    private const double T = 1111111111;

    private static string CodeOf(string uri, double at = T)
    {
        using var seed = TotpSeed.FromUri(uri);
        return TotpCodes.Compute(seed, At(at)).Code;
    }

    [Fact]
    public void Sha256Uri_UsesSha256_NotSha1()
    {
        var code = CodeOf($"otpauth://totp/X:y?secret={Sha1Seed}&algorithm=SHA256");
        Assert.Equal("584430", code);
        Assert.NotEqual("050471", code);
    }

    [Fact]
    public void Period60Digits8_UsesStepOfSixty()
    {
        using var seed = TotpSeed.FromUri($"otpauth://totp/X:y?secret={Sha1Seed}&period=60&digits=8");
        var code = TotpCodes.Compute(seed, At(T));
        Assert.Equal("19360094", code.Code); // step 1111111111 / 60 (Python hmac)
        Assert.Equal(60 - (int)(1111111111 % 60), code.RemainingSeconds);
        Assert.Equal(60, code.Period);
    }

    public static TheoryData<string, string> Spellings() => new()
    {
        { $"OTPAUTH://TOTP/X:y?secret={Sha1Seed}&algorithm=sha512", $"otpauth://totp/X:y?secret={Sha1Seed}&algorithm=SHA512" },
        { $"otpauth://totp/X:y?secret={Sha1Seed}&algorithm=sha-256", $"otpauth://totp/X:y?secret={Sha1Seed}&algorithm=SHA256" },
        { $"otpauth://totp/X:y?secret={Sha1Seed.ToLowerInvariant()}", $"otpauth://totp/X:y?secret={Sha1Seed}" },
        { $"otpauth://totp/X?secret={Sha256Seed}%3D%3D%3D%3D&algorithm=SHA256", $"otpauth://totp/X?secret={Sha256Seed}&algorithm=SHA256" },
        { $"otpauth://totp?secret={Sha1Seed}", $"otpauth://totp/X:y?secret={Sha1Seed}" },
        { $"otpauth://totp/X:y?issuer=A&secret={Sha1Seed}&issuer=B", $"otpauth://totp/X:y?secret={Sha1Seed}" },
        { $"otpauth://totp/X:y?secret={Sha1Seed}&image=https%3A%2F%2Fexample.com%2Fx.png", $"otpauth://totp/X:y?secret={Sha1Seed}" },
        { $" \t\notpauth://totp/X:y?secret={Sha1Seed}\r\n ", $"otpauth://totp/X:y?secret={Sha1Seed}" },
    };

    [Theory]
    [MemberData(nameof(Spellings))]
    public void AcceptedSpellings_GiveTheSameCodeAsThePlainForm(string spelling, string plain)
    {
        Assert.Equal(ValueKind.Totp, TotpCodes.Classify(spelling));
        Assert.Equal(CodeOf(plain), CodeOf(spelling));
    }

    private const string Sha1 = "otpauth://totp/Example:alice?secret=" + Sha1Seed;

    public static TheoryData<string, string, string> Refusals() => new()
    {
        { "R0 BOM", "﻿" + Sha1, "the value holds an otpauth URI among other text; store the URI alone" },
        { "R0 label", "certum-totp: " + Sha1, "the value holds an otpauth URI among other text; store the URI alone" },
        { "R0 second line", "user: alice\n" + Sha1, "the value holds an otpauth URI among other text; store the URI alone" },
        { "R1", "otpauth:totp/X?secret=" + Sha1Seed, "the URI doesn't start with otpauth://" },
        { "R2", "otpauth://hotp/X?secret=" + Sha1Seed + "&counter=1", "HOTP (counter-based) URIs aren't supported" },
        { "R3", "otpauth://u@totp/X?secret=" + Sha1Seed, "the URI's type isn't totp" },
        { "R4", Sha1 + "#x", "a '#' fragment isn't allowed" },
        { "R5", "otpauth://totp/X?issuer=X", "the secret parameter is missing" },
        { "R6", "otpauth://totp/X?Secret=" + Sha1Seed, "parameter names are lower case: 'secret'" },
        { "R7", Sha1 + "&digits=6&digits=6", "the parameter 'digits' appears more than once" },
        { "R8", Sha1 + "&period&", "the parameter 'period' has no value" },
        { "R9", "otpauth://totp/X?secret=%G1" + Sha1Seed, "a parameter has a malformed percent-encoding" },
        { "R10", Sha1 + "&algorithm=MD5", "algorithm must be SHA1, SHA256 or SHA512 (or SHA-1, SHA-256, SHA-512)" },
        { "R11", Sha1 + "&digits=7", "digits must be 6 or 8" },
        { "R12 zero", Sha1 + "&period=0", "period must be a whole number of seconds from 1 to 300" },
        { "R12 301", Sha1 + "&period=301", "period must be a whole number of seconds from 1 to 300" },
        { "R14 word", "otpauth://totp/X?secret=" + Sha1Seed + " note", "the secret parameter contains a space (a URI's secret is Base32 without spaces)" },
        { "R14 %20", "otpauth://totp/X?secret=GEZD%20GNBV%20GY3T%20QOJQ%20GEZD%20GNBV%20GY3T%20QOJQ", "the secret parameter contains a space (a URI's secret is Base32 without spaces)" },
        { "B1", "otpauth://totp/X?secret=GEZ1GNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "the seed isn't Base32 (letters A-Z, digits 2-7, '=' padding)" },
        { "B2", "otpauth://totp/X?secret=GEZDGNBVGY3TQOJQG", "the seed's length isn't a Base32 length" },
        { "B3 inner", "otpauth://totp/X?secret=GEZD=GNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "the seed's '=' padding is wrong" },
        { "B3 none needed", "otpauth://totp/X?secret=GEZDGNBVGY3TQOJQ=", "the seed's '=' padding is wrong" },
        { "B3 short run", "otpauth://totp/X?secret=GEZDGNBVGY3TQ==", "the seed's '=' padding is wrong" },
        { "B4", "otpauth://totp/X?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZB&algorithm=SHA256", "the seed isn't canonical Base32 (its last character has unused bits set)" },
        { "B5", "otpauth://totp/X?secret=GEZDGNBVGY3TQ", "the seed is shorter than 16 Base32 characters (80 bits)" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public void Refusals_GiveExactlyTheReason_WithoutTheValue(string row, string value, string reason)
    {
        var ex = Assert.Throws<TotpSeedException>(() => TotpSeed.FromUri(value));
        Assert.True(reason == ex.Message, $"{row}: expected '{reason}', got '{ex.Message}'");
        Assert.DoesNotContain(value.Trim(), ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("GEZDGNBV", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Refusals_CoverTwentyFiveRows() => Assert.Equal(25, Refusals().Count);

    [Theory]
    [InlineData("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "050471")]
    [InlineData("GeZd GnBv Gy3T QoJq GeZd GnBv Gy3T QoJq", "050471")]
    [InlineData(Sha256Seed, "201283")]
    [InlineData(Sha256Seed + "====", "201283")]
    public void BareForms_UseTheDefaults(string bare, string expected)
    {
        using var seed = TotpSeed.FromBase32(bare);
        Assert.Equal(expected, TotpCodes.Compute(seed, At(T)).Code);
    }

    [Theory]
    [InlineData("hunter2-password", ValueKind.None)]
    [InlineData(Sha1Seed, ValueKind.None)]
    [InlineData("otpauth-backup-codes", ValueKind.None)]
    [InlineData(Sha1, ValueKind.Totp)]
    [InlineData("otpauth://hotp/X?secret=" + Sha1Seed + "&counter=1", ValueKind.OtpAuthUnusable)]
    [InlineData(" otpauth:x", ValueKind.OtpAuthUnusable)]
    [InlineData("﻿" + Sha1, ValueKind.OtpAuthUnusable)]
    [InlineData("certum-totp: " + Sha1, ValueKind.OtpAuthUnusable)]
    [InlineData("user: alice\n" + Sha1, ValueKind.OtpAuthUnusable)]
    public void Classify(string value, ValueKind expected) => Assert.Equal(expected, TotpCodes.Classify(value));

    [GeneratedRegex(@"\b(ComputeTotp|RemainingSeconds|WindowStart)\s*\(\s*\)")]
    private static partial Regex ClockReadingCall();

    [Fact]
    public void NoSource_CallsOtpNetsClockReadingOverloads()
    {
        var sources = MarkdownLinks.AllTracked()
            .Where(f => (f.StartsWith("TswapCore/", StringComparison.Ordinal) || f.StartsWith("TswapCli/", StringComparison.Ordinal))
                        && f.EndsWith(".cs", StringComparison.Ordinal))
            .ToList();
        Assert.Contains("TswapCore/Totp/TotpCodes.cs", sources);
        var offenders = sources
            .Where(f => File.Exists(Path.Combine(MarkdownLinks.RepoRoot(), f)))
            .Where(f => ClockReadingCall().IsMatch(MarkdownLinks.ReadText(Path.Combine(MarkdownLinks.RepoRoot(), f))))
            .ToList();
        Assert.True(offenders.Count == 0,
            $"These sources call an Otp.NET overload that reads the system clock: {string.Join(", ", offenders)}. Pass the command's time.");
    }

    [Theory]
    [InlineData("totp.ComputeTotp()")]
    [InlineData("x.RemainingSeconds( )")]
    [InlineData("WindowStart()")]
    public void ClockScan_FindsAParameterlessCall(string sample) => Assert.Matches(ClockReadingCall(), sample);
}
