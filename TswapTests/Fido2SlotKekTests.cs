using TswapCore;
using TswapCore.Keyring;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 1: a FIDO2 slot's <c>KEK_slot</c>, <c>HKDF-SHA256(ikm: hmac-secret output (|| stretched
/// vault password), salt: the slot's PRF input, info: "tswap/fido2-slot/v1|v2" || slotId)</c>.
/// </summary>
public class Fido2SlotKekTests
{
    private static readonly byte[] Output = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Salt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] SlotId = Enumerable.Range(200, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] Stretched = Enumerable.Range(0x80, 32).Select(i => (byte)i).ToArray();

    // Worked out by hand (Python's hmac and hashlib, RFC 5869), not by the code under test.
    private const string ExpectedV1 = "058A46BE620779CB5DCD38F8411D3BF8A7BCB7697CDEF2D356BFAA2A628AD34E";
    private const string ExpectedV2 = "5C546121C33623476EC1B7B9D7164D7C34361F1D40B2D33AB83B6C1ED22DE82F";

    [Fact]
    public void Fido2Kek_V1AndV2_Pinned()
    {
        using var stretched = StretchedPassword.FromBytes(Stretched);

        var v1 = Fido2SlotKek.Derive(Output, Salt, SlotId);
        var v2 = Fido2SlotKek.DeriveV2(Output, stretched, Salt, SlotId);

        Assert.Equal(ExpectedV1, Convert.ToHexString(v1));
        Assert.Equal(ExpectedV2, Convert.ToHexString(v2));
        Assert.NotEqual(v1, v2);
    }

    [Fact]
    public void Fido2Kek_ADifferentSlotIdGivesADifferentKek()
    {
        using var stretched = StretchedPassword.FromBytes(Stretched);
        var otherSlotId = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

        Assert.NotEqual(Fido2SlotKek.Derive(Output, Salt, SlotId), Fido2SlotKek.Derive(Output, Salt, otherSlotId));
        Assert.NotEqual(
            Fido2SlotKek.DeriveV2(Output, stretched, Salt, SlotId),
            Fido2SlotKek.DeriveV2(Output, stretched, Salt, otherSlotId));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void Fido2Kek_RefusesAnOutputThatIsNotThirtyTwoBytes(int length)
    {
        using var stretched = StretchedPassword.FromBytes(Stretched);
        var output = new byte[length];

        var v1 = Assert.Throws<TswapException>(() => Fido2SlotKek.Derive(output, Salt, SlotId));
        var v2 = Assert.Throws<TswapException>(() => Fido2SlotKek.DeriveV2(output, stretched, Salt, SlotId));
        Assert.Contains($"{length}-byte", v1.Message);
        Assert.Contains($"{length}-byte", v2.Message);
    }

    [Fact]
    public void Fido2Kek_OutputSizeIsThirtyTwo() => Assert.Equal(32, Fido2SlotKek.OutputSize);
}
