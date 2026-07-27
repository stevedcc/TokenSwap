using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Golden-value tests for the deterministic filename scheme (issue #114):
/// <c>HMAC(K_names, secretName)</c>, hex-encoded. The expected hex below was independently
/// computed with OpenSSL (<c>printf '%s' "github-token" | openssl dgst -sha256 -mac HMAC
/// -macopt hexkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f</c>), not
/// merely captured from this code's own output, so this pins the wire format against an
/// independent HMAC-SHA256 implementation rather than just locking in whatever .NET happens to
/// produce.
/// </summary>
public class FilenameHasherTests
{
    private static readonly byte[] KNames = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    [Fact]
    public void ComputeRecordId_MatchesIndependentlyComputedHmac()
    {
        var recordId = FilenameHasher.ComputeRecordId(KNames, "github-token");

        Assert.Equal("1b82240342ab424d628060349762c02e4332cda59b361036c7e5f0c80f47cfde", Convert.ToHexStringLower(recordId));
    }

    [Fact]
    public void ComputeFilename_IsLowercaseHexOfRecordId()
    {
        var filename = FilenameHasher.ComputeFilename(KNames, "github-token");

        Assert.Equal("1b82240342ab424d628060349762c02e4332cda59b361036c7e5f0c80f47cfde", filename);
        Assert.DoesNotContain(filename, c => char.IsUpper(c));
    }

    [Fact]
    public void ComputeRecordId_Returns32Bytes()
    {
        var recordId = FilenameHasher.ComputeRecordId(KNames, "anything");

        Assert.Equal(32, recordId.Length);
    }

    [Fact]
    public void ComputeRecordId_Deterministic()
    {
        var a = FilenameHasher.ComputeRecordId(KNames, "aws-secret");
        var b = FilenameHasher.ComputeRecordId(KNames, "aws-secret");

        Assert.Equal(a, b);
    }

    [Fact]
    public void ComputeRecordId_DifferentNamesDifferentIds()
    {
        var a = FilenameHasher.ComputeRecordId(KNames, "aws-secret");
        var b = FilenameHasher.ComputeRecordId(KNames, "gcp-secret");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeRecordId_DifferentKeysDifferentIds()
    {
        var otherKey = Convert.FromHexString("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

        var a = FilenameHasher.ComputeRecordId(KNames, "aws-secret");
        var b = FilenameHasher.ComputeRecordId(otherKey, "aws-secret");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeRecordId_WrongKeyLengthThrows()
    {
        Assert.Throws<ArgumentException>(() => FilenameHasher.ComputeRecordId(new byte[16], "name"));
    }
}
