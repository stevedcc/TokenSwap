using System.Security.Cryptography;
using YkSpike;
using Xunit;

namespace YkSpike.Tests;

public class PrfTests
{
    [Fact]
    public void Salt_IsSha256OfLabelZeroInput()
    {
        byte[] expected = SHA256.HashData([.. "WebAuthn PRF"u8, 0, .. "tswap-yk-spike-salt-v1"u8]);
        Assert.Equal(expected, Prf.Salt("tswap-yk-spike-salt-v1"u8));
    }

    [Fact]
    public void Salt_IsThirtyTwoBytes() => Assert.Equal(32, Prf.Salt("x"u8).Length);
}
