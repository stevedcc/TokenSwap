using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the Phase 6 keyring/slot fixed-binary encoding (issue #119, see
/// <see cref="KeyringCodec"/>'s layout doc). Golden-byte tests pin the exact on-disk layout for
/// known inputs, not just round-tripping — the same rigor <c>SlotPayloadWrapTests</c> and
/// <c>SecretRecordCodecTests</c> already apply to their own formats, and for the same reason:
/// this structure's bytes (vaultId, k, slotId) directly feed <see cref="SlotPayloadWrap"/>'s
/// AAD, so an accidental layout change here would silently brick every keyring vault.
/// </summary>
public class KeyringCodecTests
{
    private static readonly byte[] VaultId = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
    private static readonly byte[] SlotId = Convert.FromHexString("101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] PublicKey =
        Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] Wrapped = Convert.FromHexString("aabbccdd");

    private static Keyring OneSlotKeyring() =>
        new(FormatVersion: 1, VaultId, K: 1, Slots: [new Slot(SlotId, PublicKey, Wrapped)]);

    [Fact]
    public void Encode_MatchesGoldenBytesExactly()
    {
        var bytes = KeyringCodec.Encode(OneSlotKeyring());

        const string expectedHex =
            "01" +                                                                 // formatVersion
            "000102030405060708090a0b0c0d0e0f" +                                   // vaultId (16)
            "01" +                                                                 // k
            "01000000" +                                                           // slotCount = 1 (LE)
            "101112131415161718191a1b1c1d1e1f" +                                   // slotId (16)
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +   // publicKey (32)
            "04000000" +                                                           // wrappedLength = 4 (LE)
            "aabbccdd";                                                            // wrapped

        Assert.Equal(78, bytes.Length);
        Assert.Equal(expectedHex, Convert.ToHexStringLower(bytes));
    }

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var keyring = OneSlotKeyring();

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Equal(keyring.FormatVersion, decoded.FormatVersion);
        Assert.Equal(keyring.VaultId, decoded.VaultId);
        Assert.Equal(keyring.K, decoded.K);
        Assert.Single(decoded.Slots);
        Assert.Equal(SlotId, decoded.Slots[0].SlotId);
        Assert.Equal(PublicKey, decoded.Slots[0].PublicKey);
        Assert.Equal(Wrapped, decoded.Slots[0].Wrapped);
    }

    [Fact]
    public void EncodeDecode_RoundTripsEmptyWrapped()
    {
        var keyring = new Keyring(1, VaultId, 1, [new Slot(SlotId, PublicKey, [])]);

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Empty(decoded.Slots[0].Wrapped);
    }

    [Fact]
    public void EncodeDecode_RoundTripsMultipleSlots()
    {
        // v0 always writes exactly one slot, but the format supports more from day one
        // (#121 appends slots without a format bump) — prove the loop actually handles it.
        var slotId2 = Convert.FromHexString("303132333435363738393a3b3c3d3e3f");
        var publicKey2 = Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        var keyring = new Keyring(1, VaultId, 1,
            [new Slot(SlotId, PublicKey, Wrapped), new Slot(slotId2, publicKey2, [1, 2, 3])]);

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Equal(2, decoded.Slots.Count);
        Assert.Equal(slotId2, decoded.Slots[1].SlotId);
        Assert.Equal(publicKey2, decoded.Slots[1].PublicKey);
        Assert.Equal(new byte[] { 1, 2, 3 }, decoded.Slots[1].Wrapped);
    }

    [Fact]
    public void Encode_WrongVaultIdLengthThrowsArgumentException()
    {
        var keyring = new Keyring(1, new byte[4], 1, [new Slot(SlotId, PublicKey, Wrapped)]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Encode_WrongSlotIdLengthThrowsArgumentException()
    {
        var keyring = new Keyring(1, VaultId, 1, [new Slot(new byte[4], PublicKey, Wrapped)]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Encode_WrongPublicKeyLengthThrowsArgumentException()
    {
        var keyring = new Keyring(1, VaultId, 1, [new Slot(SlotId, new byte[4], Wrapped)]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Decode_TooShortForHeaderThrowsTswapException()
    {
        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(new byte[10]));
        Assert.Contains("shorter than the header", ex.Message);
    }

    [Fact]
    public void Decode_EmptyInputThrowsTswapException()
    {
        Assert.Throws<TswapException>(() => KeyringCodec.Decode([]));
    }

    [Fact]
    public void Decode_TruncatedSlotHeaderThrowsTswapException()
    {
        // A valid header claiming one slot, but far fewer bytes than a slot header needs.
        var bytes = KeyringCodec.Encode(OneSlotKeyring());
        var truncated = bytes[..25]; // header(22) + 3 bytes of the first slot, nowhere near enough

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(truncated));
        Assert.Contains("truncated slot header", ex.Message);
    }

    [Fact]
    public void Decode_WrappedLengthPrefixExceedsAvailableDataThrowsTswapException()
    {
        var bytes = KeyringCodec.Encode(OneSlotKeyring());
        // Overwrite wrappedLength (right after slotId+publicKey, i.e. offset 22+16+32=70) with
        // an enormous value while leaving the actual trailing bytes unchanged (still just 4).
        var tampered = (byte[])bytes.Clone();
        var lengthOffset = 22 + 16 + 32;
        tampered[lengthOffset] = 0xFF;
        tampered[lengthOffset + 1] = 0xFF;
        tampered[lengthOffset + 2] = 0xFF;
        tampered[lengthOffset + 3] = 0x7F;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(tampered));
        Assert.Contains("wrapped-slot length prefix exceeds available data", ex.Message);
    }

    [Fact]
    public void Decode_SlotCountLargerThanDataDoesNotHangOrOverflow()
    {
        // A corrupted/hostile slotCount (near uint.MaxValue) must fail fast on the first
        // iteration's bounds check, not loop for a very long time or overflow an
        // addition-based bounds check into a false pass (see KeyringCodec.Decode's own comment
        // on subtraction- vs addition-based bounds checks).
        var bytes = KeyringCodec.Encode(OneSlotKeyring());
        var tampered = (byte[])bytes.Clone();
        var slotCountOffset = 1 + KeyringFormat.VaultIdSize + 1;
        tampered[slotCountOffset] = 0xFE;
        tampered[slotCountOffset + 1] = 0xFF;
        tampered[slotCountOffset + 2] = 0xFF;
        tampered[slotCountOffset + 3] = 0xFF;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(tampered));
        Assert.Contains("Malformed keyring", ex.Message);
    }
}
