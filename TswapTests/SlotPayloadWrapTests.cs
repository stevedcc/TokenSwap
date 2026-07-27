using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the Phase 6 two-layer slot AEAD wrap (issues #116/#117). Golden-byte tests pin the
/// exact AAD encoding (<see cref="SlotPayloadWrap.BuildAad"/>) for known inputs, not just
/// round-tripping. Tamper tests flip one AAD-bound field at a time after wrapping to prove each
/// field is actually mixed into the AEAD call, not just present in a parameter list that isn't
/// wired up — this is the primary defense against the threshold-downgrade attack described in
/// <c>MULTI_MACHINE_KEYING.md</c> §The landmine.
/// </summary>
public class SlotPayloadWrapTests
{
    private static readonly byte[] KekSlot = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] VaultId = Convert.FromHexString("101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] SlotId = Convert.FromHexString("202122232425262728292a2b2c2d2e2f");
    private const byte FormatVersion = 1;
    private const byte K = 1;

    [Fact]
    public void BuildAad_MatchesGoldenBytesExactly()
    {
        var aad = SlotPayloadWrap.BuildAad(FormatVersion, VaultId, K, SlotId);

        // formatVersion(1)=01 || vaultId(16) || k(1)=01 || slotId(16), explicit field order.
        const string expectedHex =
            "01" +
            "101112131415161718191a1b1c1d1e1f" +
            "01" +
            "202122232425262728292a2b2c2d2e2f";

        Assert.Equal(34, aad.Length);
        Assert.Equal(expectedHex, Convert.ToHexStringLower(aad));
    }

    [Fact]
    public void BuildAad_DifferentFormatVersionProducesDifferentAad()
    {
        var aad1 = SlotPayloadWrap.BuildAad(1, VaultId, K, SlotId);
        var aad2 = SlotPayloadWrap.BuildAad(2, VaultId, K, SlotId);

        Assert.NotEqual(aad1, aad2);
    }

    [Fact]
    public void WrapUnwrap_RoundTripsPayload()
    {
        var payload = "the quick brown fox"u8.ToArray();

        var wrapped = SlotPayloadWrap.Wrap(payload, KekSlot, FormatVersion, VaultId, K, SlotId);
        var unwrapped = SlotPayloadWrap.Unwrap(wrapped, KekSlot, FormatVersion, VaultId, K, SlotId);

        Assert.Equal(payload, unwrapped);
    }

    [Fact]
    public void WrapUnwrap_RoundTripsEmptyPayload()
    {
        var wrapped = SlotPayloadWrap.Wrap([], KekSlot, FormatVersion, VaultId, K, SlotId);
        var unwrapped = SlotPayloadWrap.Unwrap(wrapped, KekSlot, FormatVersion, VaultId, K, SlotId);

        Assert.Empty(unwrapped);
    }

    [Fact]
    public void Wrap_OutputLayoutIsNoncePlusTagPlusCiphertext()
    {
        var payload = new byte[32];

        var wrapped = SlotPayloadWrap.Wrap(payload, KekSlot, FormatVersion, VaultId, K, SlotId);

        Assert.Equal(12 + 16 + 32, wrapped.Length);
    }

    [Fact]
    public void Wrap_ProducesFreshNoncePerCall()
    {
        var payload = "same payload"u8.ToArray();

        var wrapped1 = SlotPayloadWrap.Wrap(payload, KekSlot, FormatVersion, VaultId, K, SlotId);
        var wrapped2 = SlotPayloadWrap.Wrap(payload, KekSlot, FormatVersion, VaultId, K, SlotId);

        Assert.NotEqual(wrapped1[..12], wrapped2[..12]);
    }

    [Fact]
    public void Unwrap_TamperedFormatVersionFailsAuthentication()
    {
        var wrapped = SlotPayloadWrap.Wrap("payload"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, SlotId);

        var ex = Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(wrapped, KekSlot, formatVersion: 2, VaultId, K, SlotId));
        Assert.Contains("authentication", ex.Message);
    }

    [Fact]
    public void Unwrap_TamperedVaultIdFailsAuthentication()
    {
        var wrapped = SlotPayloadWrap.Wrap("payload"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, SlotId);
        var tamperedVaultId = (byte[])VaultId.Clone();
        tamperedVaultId[0] ^= 0xFF;

        Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(wrapped, KekSlot, FormatVersion, tamperedVaultId, K, SlotId));
    }

    [Fact]
    public void Unwrap_TamperedKFailsAuthentication()
    {
        // The threshold-downgrade attack itself: rewriting k after wrapping must not unwrap.
        var wrapped = SlotPayloadWrap.Wrap("payload"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, SlotId);

        Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(wrapped, KekSlot, FormatVersion, VaultId, k: 2, SlotId));
    }

    [Fact]
    public void Unwrap_TamperedSlotIdFailsAuthentication()
    {
        var wrapped = SlotPayloadWrap.Wrap("payload"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, SlotId);
        var tamperedSlotId = (byte[])SlotId.Clone();
        tamperedSlotId[0] ^= 0xFF;

        Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(wrapped, KekSlot, FormatVersion, VaultId, K, tamperedSlotId));
    }

    [Fact]
    public void Unwrap_TamperedCiphertextFailsAuthentication()
    {
        var wrapped = SlotPayloadWrap.Wrap("payload"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, SlotId);
        wrapped[^1] ^= 0xFF;

        Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(wrapped, KekSlot, FormatVersion, VaultId, K, SlotId));
    }

    [Fact]
    public void Unwrap_WrongKekSlotFailsCleanly()
    {
        var wrapped = SlotPayloadWrap.Wrap("payload"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, SlotId);
        var wrongKek = new byte[32];

        var ex = Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(wrapped, wrongKek, FormatVersion, VaultId, K, SlotId));
        Assert.Contains("authentication", ex.Message);
    }

    [Fact]
    public void Unwrap_TruncatedInputThrowsTswapException()
    {
        var ex = Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap(new byte[10], KekSlot, FormatVersion, VaultId, K, SlotId));
        Assert.Contains("nonce+tag", ex.Message);
    }

    [Fact]
    public void Unwrap_EmptyInputThrowsTswapException()
    {
        Assert.Throws<TswapException>(() =>
            SlotPayloadWrap.Unwrap([], KekSlot, FormatVersion, VaultId, K, SlotId));
    }

    [Fact]
    public void Wrap_WrongKekSlotLengthThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            SlotPayloadWrap.Wrap("x"u8.ToArray(), new byte[16], FormatVersion, VaultId, K, SlotId));
    }

    [Fact]
    public void Wrap_WrongVaultIdLengthThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            SlotPayloadWrap.Wrap("x"u8.ToArray(), KekSlot, FormatVersion, new byte[4], K, SlotId));
    }

    [Fact]
    public void Wrap_WrongSlotIdLengthThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            SlotPayloadWrap.Wrap("x"u8.ToArray(), KekSlot, FormatVersion, VaultId, K, new byte[4]));
    }
}
