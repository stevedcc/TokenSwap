using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the (K_v, slot private key) payload <see cref="SlotPayloadWrap"/> wraps inside a
/// slot (issue #119). Golden-byte test pins the exact concatenation order, since
/// <see cref="SlotSecretPayload"/> relies on both fields being a fixed, pinned width rather than
/// length-prefixed — see its doc comment for why that's safe here specifically.
/// </summary>
public class SlotSecretPayloadTests
{
    private static readonly byte[] VaultKey = Convert.FromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] SlotPrivateKey = Convert.FromHexString(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

    [Fact]
    public void Encode_MatchesGoldenBytesExactly()
    {
        var encoded = SlotSecretPayload.Encode(VaultKey, SlotPrivateKey);

        const string expectedHex =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

        Assert.Equal(64, encoded.Length);
        Assert.Equal(expectedHex, Convert.ToHexStringLower(encoded));
    }

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var encoded = SlotSecretPayload.Encode(VaultKey, SlotPrivateKey);

        var (vaultKey, slotPrivateKey) = SlotSecretPayload.Decode(encoded);

        Assert.Equal(VaultKey, vaultKey);
        Assert.Equal(SlotPrivateKey, slotPrivateKey);
    }

    [Fact]
    public void Encode_WrongVaultKeyLengthThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => SlotSecretPayload.Encode(new byte[16], SlotPrivateKey));
    }

    [Fact]
    public void Encode_WrongSlotPrivateKeyLengthThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => SlotSecretPayload.Encode(VaultKey, new byte[16]));
    }

    [Fact]
    public void Decode_WrongLengthThrowsTswapException()
    {
        var ex = Assert.Throws<TswapException>(() => SlotSecretPayload.Decode(new byte[10]));
        Assert.Contains("Malformed slot payload", ex.Message);
    }

    [Fact]
    public void Decode_EmptyInputThrowsTswapException()
    {
        Assert.Throws<TswapException>(() => SlotSecretPayload.Decode([]));
    }
}
