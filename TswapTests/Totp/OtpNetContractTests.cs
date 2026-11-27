using System.Text;
using TswapCore.Totp;
using Xunit;

namespace TswapTests.Totp;

/// <summary>
/// Brief T58 (#374): the upgrade guard for Otp.NET. Each test pins one thing tswap relies on (the RFC 6238 vectors,
/// leading zeros, step edges and remaining seconds, the digit count, the Base32 forms tswap hands the library) and fails
/// by name when a bump of the package changes it. Every row goes through tswap's own path
/// (<see cref="TotpSeed.FromUri"/> / <see cref="TotpSeed.FromBase32"/> and <see cref="TotpCodes.Compute"/>), not the raw
/// library alone. The expected values are RFC 6238 Appendix B's, the rest computed independently with Python's
/// <c>hmac</c>. Every time is fixed; nothing reads the clock.
/// </summary>
public class OtpNetContractTests
{
    internal const string Sha1Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"
    internal const string Sha256Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"; // 32 bytes, unpadded
    internal const string Sha512Seed =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"; // 64 bytes

    internal const string Sha1Uri = "otpauth://totp/Example:alice?secret=" + Sha1Seed + "&issuer=Example";

    internal static DateTimeOffset At(double unixSeconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds((long)Math.Round(unixSeconds * 1000));

    private static TotpCode Code(string uri, double at)
    {
        using var seed = TotpSeed.FromUri(uri);
        return TotpCodes.Compute(seed, At(at));
    }

    public static TheoryData<string, string, long, string> Rfc6238Vectors()
    {
        var data = new TheoryData<string, string, long, string>();
        var seeds = new (string Algorithm, string Seed, string Padding)[]
        {
            ("SHA1", Sha1Seed, ""), ("SHA256", Sha256Seed, "===="), ("SHA512", Sha512Seed, "="),
        };
        var codes = new (long Time, string Sha1, string Sha256, string Sha512)[]
        {
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        };
        foreach (var (algorithm, seed, padding) in seeds)
            foreach (var row in codes)
            {
                var expected = algorithm switch { "SHA1" => row.Sha1, "SHA256" => row.Sha256, _ => row.Sha512 };
                data.Add(algorithm, seed, row.Time, expected);
                if (padding.Length > 0) data.Add(algorithm, seed + padding, row.Time, expected);
            }
        return data;
    }

    [Theory]
    [MemberData(nameof(Rfc6238Vectors))]
    public void Rfc6238_AppendixB_Vectors(string algorithm, string seed, long time, string expected)
    {
        var code = Code($"otpauth://totp/RFC?secret={seed.Replace("=", "%3D")}&algorithm={algorithm}&digits=8", time);
        Assert.Equal(expected, code.Code);
    }

    [Fact]
    public void LeadingZeros_AreKept()
    {
        Assert.Equal("07081804", Code(Sha1Uri + "&digits=8", 1111111109).Code);
        Assert.Equal("050471", Code(Sha1Uri, 1111111111).Code);
    }

    [Theory]
    [InlineData(1111111109.999, "081804", 1)]
    [InlineData(1111111110.000, "050471", 30)]
    [InlineData(1111111139.999, "050471", 1)]
    [InlineData(1111111140.000, "266759", 30)]
    public void StepEdges_Period30(double at, string expected, int remaining)
    {
        var code = Code(Sha1Uri, at);
        Assert.Equal(expected, code.Code);
        Assert.Equal(remaining, code.RemainingSeconds);
        Assert.Equal(30, code.Period);
    }

    [Theory]
    [InlineData(1111111139.999, 6, "360094", 1)]
    [InlineData(1111111139.999, 8, "19360094", 1)]
    [InlineData(1111111140.000, 6, "593113", 60)]
    [InlineData(1111111140.000, 8, "68593113", 60)]
    public void StepEdges_Period60(double at, int digits, string expected, int remaining)
    {
        var code = Code($"{Sha1Uri}&period=60&digits={digits}", at);
        Assert.Equal(expected, code.Code);
        Assert.Equal(remaining, code.RemainingSeconds);
        Assert.Equal(60, code.Period);
    }

    [Theory]
    [InlineData(59)]
    [InlineData(1111111109)]
    [InlineData(1111111111)]
    [InlineData(2000000000)]
    public void Digits6_AreTheLastSixOfDigits8(long at)
    {
        var six = Code(Sha1Uri, at).Code;
        var eight = Code(Sha1Uri + "&digits=8", at).Code;
        Assert.Equal(6, six.Length);
        Assert.Equal(8, eight.Length);
        Assert.Equal(eight[2..], six);
    }

    public static TheoryData<string, string> AcceptedSpellings() => new()
    {
        { "upper", "otpauth://totp/X?secret=" + Sha1Seed },
        { "lower", "otpauth://totp/X?secret=" + Sha1Seed.ToLowerInvariant() },
        { "mixed", "otpauth://totp/X?secret=GeZdGnBvGy3tQoJqGeZdGnBvGy3tQoJq" },
        { "padded =", "otpauth://totp/X?secret=" + Sha256Seed + "====" },
        { "padded %3D", "otpauth://totp/X?secret=" + Sha256Seed + "%3D%3D%3D%3D" },
        { "padded %3d", "otpauth://totp/X?secret=" + Sha256Seed + "%3d%3d%3d%3d" },
        { "unpadded", "otpauth://totp/X?secret=" + Sha256Seed },
        { "lower padded", "otpauth://totp/X?secret=" + Sha256Seed.ToLowerInvariant() + "====" },
    };

    [Theory]
    [MemberData(nameof(AcceptedSpellings))]
    public void Base32_EachAcceptedSpelling_DecodesToTheSeedBytes(string spelling, string uri)
    {
        var expected = uri.Contains(Sha256Seed, StringComparison.OrdinalIgnoreCase)
            ? "12345678901234567890123456789012"
            : "12345678901234567890";
        using var seed = TotpSeed.FromUri(uri);
        Assert.True(expected == Encoding.ASCII.GetString(seed.KeyBytes), $"spelling '{spelling}' decoded to other bytes");
    }

    [Theory]
    [InlineData("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", "12345678901234567890")]
    [InlineData("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "12345678901234567890")]
    [InlineData("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ GEZA ====", "12345678901234567890123456789012")]
    public void Base32_BareFormWithSpaces_DecodesToTheSeedBytes(string bare, string expected)
    {
        using var seed = TotpSeed.FromBase32(bare);
        Assert.Equal(expected, Encoding.ASCII.GetString(seed.KeyBytes));
    }

    [Fact]
    public void Dispose_ZeroesTheKeyBytes()
    {
        var seed = TotpSeed.FromUri(Sha1Uri);
        var key = seed.KeyBytes;
        seed.Dispose();
        Assert.All(key, b => Assert.Equal(0, b));
    }
}
