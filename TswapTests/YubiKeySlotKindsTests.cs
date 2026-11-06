using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 1: <see cref="YubiKeySlotKinds.Classify"/> routes a <c>TSYK</c> blob by its version byte
/// (1–2 OTP, 3 FIDO2, greater than 3 needs a newer tswap, 0 corrupt) and never throws.
/// </summary>
public class YubiKeySlotKindsTests
{
    private static readonly byte[] Challenge = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Salt = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] CredentialId = Enumerable.Range(0xA0, 16).Select(i => (byte)i).ToArray();
    private static readonly Guid Aaguid = Guid.Parse("d7781e5d-e353-46aa-afe2-3ca49f13332a");

    private static byte[] OtpV1() => new YubiKeySlotBlob(11111111, Challenge, Salt, YubiKeyTouchPolicy.Required).Encode();

    private static byte[] OtpV2() =>
        new YubiKeySlotBlob(11111111, Challenge, Salt, YubiKeyTouchPolicy.Required, requiresPassword: true).Encode();

    private static Fido2SlotBlob Fido2Blob() =>
        Fido2SlotBlob.Create(33060005, Aaguid, CredentialId, requiresPassword: false);

    private static byte[] WithByte(byte[] bytes, int index, byte value)
    {
        var copy = (byte[])bytes.Clone();
        copy[index] = value;
        return copy;
    }

    [Fact]
    public void Classify_OtpVersionOne()
    {
        var kind = Assert.IsType<YubiKeySlotKind.Otp>(YubiKeySlotKinds.Classify(OtpV1()));
        Assert.Equal(11111111, kind.Blob.Serial);
        Assert.False(kind.Blob.RequiresPassword);
    }

    [Fact]
    public void Classify_OtpVersionTwo()
    {
        var kind = Assert.IsType<YubiKeySlotKind.Otp>(YubiKeySlotKinds.Classify(OtpV2()));
        Assert.True(kind.Blob.RequiresPassword);
    }

    [Fact]
    public void Classify_Fido2VersionThree()
    {
        var original = Fido2Blob();

        var kind = Assert.IsType<YubiKeySlotKind.Fido2>(YubiKeySlotKinds.Classify(original.Encode()));

        Assert.Equal(original.CredentialId, kind.Blob.CredentialId);
        Assert.Equal(original.PrfInput, kind.Blob.PrfInput);
        Assert.Equal(33060005, kind.Blob.Serial);
    }

    [Fact]
    public void Classify_VersionZeroIsCorrupt()
    {
        var kind = Assert.IsType<YubiKeySlotKind.Corrupt>(YubiKeySlotKinds.Classify(WithByte(OtpV1(), 4, 0)));
        Assert.StartsWith("Malformed YubiKey slot blob: ", kind.Error);
    }

    [Fact]
    public void Classify_MagicWithoutAVersionIsCorrupt()
    {
        Assert.IsType<YubiKeySlotKind.Corrupt>(YubiKeySlotKinds.Classify("TSYK"u8.ToArray()));
    }

    [Fact]
    public void Classify_VersionFourNeedsANewerTswap()
    {
        var kind = Assert.IsType<YubiKeySlotKind.NeedsNewerTswap>(
            YubiKeySlotKinds.Classify(WithByte(Fido2Blob().Encode(), 4, 4)));
        Assert.Equal(SlotPassword.NeedsNewerTswapText(4), kind.Error);
    }

    [Fact]
    public void Classify_Fido2WithAnotherRpIdIsCorrupt()
    {
        // Same length as "tswap.crawford.dev" (18 bytes), so only the rp id differs.
        var bytes = Fido2Blob().Encode();
        "evil.crawford.dev!"u8.CopyTo(bytes.AsSpan(60));

        var kind = Assert.IsType<YubiKeySlotKind.Corrupt>(YubiKeySlotKinds.Classify(bytes));
        Assert.StartsWith("Malformed FIDO2 slot blob: ", kind.Error);
    }

    [Fact]
    public void Classify_Fido2PrfVersionZeroIsCorrupt()
    {
        var kind = Assert.IsType<YubiKeySlotKind.Corrupt>(YubiKeySlotKinds.Classify(WithByte(Fido2Blob().Encode(), 6, 0)));
        Assert.StartsWith("Malformed FIDO2 slot blob: ", kind.Error);
    }

    [Fact]
    public void Classify_Fido2PrfVersionTwoNeedsANewerTswap()
    {
        var kind = Assert.IsType<YubiKeySlotKind.NeedsNewerTswap>(
            YubiKeySlotKinds.Classify(WithByte(Fido2Blob().Encode(), 6, 2)));
        Assert.Equal("needs a newer tswap (FIDO2 slot PRF version 2); upgrade tswap.", kind.Error);
    }

    [Fact]
    public void Classify_Fido2TruncatedIsCorruptWithTheFido2Text()
    {
        var kind = Assert.IsType<YubiKeySlotKind.Corrupt>(YubiKeySlotKinds.Classify(Fido2Blob().Encode()[..40]));
        Assert.StartsWith("Malformed FIDO2 slot blob: ", kind.Error);
    }

    [Fact]
    public void Classify_ATpmPasswordBlobIsNone()
    {
        byte[] tpm = [.. "TSTP"u8.ToArray(), 0x01, 0x01, 0xAA, 0xBB];
        Assert.IsType<YubiKeySlotKind.None>(YubiKeySlotKinds.Classify(tpm));
    }

    [Fact]
    public void Classify_NullIsNone() => Assert.IsType<YubiKeySlotKind.None>(YubiKeySlotKinds.Classify(null));

    [Fact]
    public void IsYubiKey_IsTheTsykMagicAtAnyVersion()
    {
        Assert.True(YubiKeySlotKinds.IsYubiKey(OtpV1()));
        Assert.True(YubiKeySlotKinds.IsYubiKey(Fido2Blob().Encode()));
        Assert.True(YubiKeySlotKinds.IsYubiKey(WithByte(OtpV1(), 4, 9)));
        Assert.False(YubiKeySlotKinds.IsYubiKey("TSTP"u8.ToArray()));
        Assert.False(YubiKeySlotKinds.IsYubiKey("TSY"u8.ToArray()));
        Assert.False(YubiKeySlotKinds.IsYubiKey(null));
    }
}
