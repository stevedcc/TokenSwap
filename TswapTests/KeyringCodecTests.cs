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
        new(FormatVersion: KeyringFormat.KeyringFormatVersion, VaultId, K: 1, Slots: [new Slot(SlotId, PublicKey, Wrapped)]);

    [Fact]
    public void Encode_MatchesGoldenBytesExactly()
    {
        // Issue #120: this golden-byte assertion was deliberately updated from #119's original
        // 78-byte/no-trailing-kind-byte shape to include the new per-slot `kind` byte appended
        // after `wrapped` (see KeyringCodec's "kind (issue #120)" doc-comment section) — a
        // called-out, intentional change to what #119 originally pinned, not a silent drift; see
        // this issue's PR body. OneSlotKeyring()'s 3-argument Slot(...) call defaults to
        // SlotKind.Machine (0x00), which is what the trailing byte below encodes.
        //
        // formatVersion is "02", not "01": #120's own follow-up fix bumped
        // KeyringFormat.KeyringFormatVersion 1 -> 2, because the trailing `kind` byte is a
        // breaking wire-format change (every existing slot's serialized shape changed), not a
        // merely-additive one — see KeyringFormat.KeyringFormatVersion's doc comment.
        var bytes = KeyringCodec.Encode(OneSlotKeyring());

        const string expectedHex =
            "02" +                                                                 // formatVersion
            "000102030405060708090a0b0c0d0e0f" +                                   // vaultId (16)
            "01" +                                                                 // k
            "01000000" +                                                           // slotCount = 1 (LE)
            "101112131415161718191a1b1c1d1e1f" +                                   // slotId (16)
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +   // publicKey (32)
            "04000000" +                                                           // wrappedLength = 4 (LE)
            "aabbccdd" +                                                           // wrapped
            "00";                                                                  // kind = Machine (0)

        Assert.Equal(79, bytes.Length);
        Assert.Equal(expectedHex, Convert.ToHexStringLower(bytes));
    }

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        // This is also the "pre-#120 shape still round-trips" proof the #120 test bar asks for:
        // OneSlotKeyring() is exactly #119's original single-machine-slot, no-recovery shape
        // (Slot's 3-argument constructor defaults Kind to SlotKind.Machine), and it round-trips
        // unchanged through the codec #120 extended.
        var keyring = OneSlotKeyring();

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Equal(keyring.FormatVersion, decoded.FormatVersion);
        Assert.Equal(keyring.VaultId, decoded.VaultId);
        Assert.Equal(keyring.K, decoded.K);
        Assert.Single(decoded.Slots);
        Assert.Equal(SlotId, decoded.Slots[0].SlotId);
        Assert.Equal(PublicKey, decoded.Slots[0].PublicKey);
        Assert.Equal(Wrapped, decoded.Slots[0].Wrapped);
        Assert.Equal(SlotKind.Machine, decoded.Slots[0].Kind);
    }

    [Fact]
    public void EncodeDecode_RoundTripsEmptyWrapped()
    {
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1, [new Slot(SlotId, PublicKey, [])]);

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Empty(decoded.Slots[0].Wrapped);
    }

    [Fact]
    public void EncodeDecode_RoundTripsMultipleSlots()
    {
        // v0 always writes exactly one slot, but the format supports more from day one
        // (#121 appends slots without a format bump) — prove the loop actually handles it.
        // Also mixes slot kinds (#120): a machine slot plus a recovery slot, proving Kind
        // round-trips independently per slot, not just as a keyring-wide value.
        var slotId2 = Convert.FromHexString("303132333435363738393a3b3c3d3e3f");
        var publicKey2 = Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1,
            [new Slot(SlotId, PublicKey, Wrapped), new Slot(slotId2, publicKey2, [1, 2, 3], SlotKind.Recovery)]);

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Equal(2, decoded.Slots.Count);
        Assert.Equal(SlotKind.Machine, decoded.Slots[0].Kind);
        Assert.Equal(slotId2, decoded.Slots[1].SlotId);
        Assert.Equal(publicKey2, decoded.Slots[1].PublicKey);
        Assert.Equal(new byte[] { 1, 2, 3 }, decoded.Slots[1].Wrapped);
        Assert.Equal(SlotKind.Recovery, decoded.Slots[1].Kind);
    }

    [Fact]
    public void Encode_WrongVaultIdLengthThrowsArgumentException()
    {
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, new byte[4], 1, [new Slot(SlotId, PublicKey, Wrapped)]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Encode_WrongSlotIdLengthThrowsArgumentException()
    {
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1, [new Slot(new byte[4], PublicKey, Wrapped)]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Encode_WrongPublicKeyLengthThrowsArgumentException()
    {
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1, [new Slot(SlotId, new byte[4], Wrapped)]);

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
    public void Decode_TruncatedKindByteThrowsTswapException()
    {
        // A slot whose wrapped bytes decoded fine but has nothing left for the trailing kind
        // byte #120 added — must fail loudly, not read past the end of the array.
        var bytes = KeyringCodec.Encode(OneSlotKeyring());
        var truncated = bytes[..^1]; // drop just the final kind byte

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(truncated));
        Assert.Contains("truncated slot kind", ex.Message);
    }

    [Fact]
    public void Decode_UnknownSlotKindThrowsTswapException()
    {
        // A kind byte that is neither Machine (0) nor Recovery (1) — e.g. corruption, or a
        // future slot kind this build predates — must fail loudly rather than silently cast an
        // undefined enum value.
        var bytes = KeyringCodec.Encode(OneSlotKeyring());
        var tampered = (byte[])bytes.Clone();
        tampered[^1] = 0xFF;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(tampered));
        Assert.Contains("unknown slot kind", ex.Message);
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

    [Fact]
    public void Decode_MismatchedFormatVersionThrowsClearErrorNotTruncatedSlotKind()
    {
        // Regression test for the bug this commit fixes: byte-exact reproduction of what issue
        // #119's original (pre-#120, already-merged in PR #147) KeyringCodec.Encode would have
        // written for a real vault — same header/slot layout as OneSlotKeyring(), but
        // formatVersion=1 (the pre-#120 value) and NO trailing per-slot `kind` byte (the #120
        // addition). This is exactly what's already on disk for any vault created via the #119
        // code.
        //
        // Before this fix, KeyringCodec.Decode never checked formatVersion at all, so feeding it
        // this pre-#120 blob fell through to the subtraction-based bounds check for the missing
        // trailing byte and threw "Malformed keyring: truncated slot kind" instead — a safe
        // failure, but a misleading diagnostic: the real cause is a format-version mismatch, not
        // truncation/corruption, and the fix is "re-run tswap init --keyring", not "restore
        // config.json from backup" (which would not help, since the backup is in the same old,
        // now-unreadable format). This test proves Decode now names the real cause instead.
        var preIssue120Bytes = BuildPreIssue120Bytes(formatVersion: 1);

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(preIssue120Bytes));

        Assert.Contains("Unsupported keyring format version: 1", ex.Message);
        Assert.DoesNotContain("truncated slot kind", ex.Message);
    }

    [Fact]
    public void Decode_UnsupportedFormatVersionThrowsBeforeParsingAnySlot()
    {
        // Even a well-formed, fully current #120-shaped keyring (kind byte present, everything
        // else valid) must still be rejected purely on formatVersion — proving the check runs
        // unconditionally right after the header is read, not only as a side effect of slot
        // parsing happening to fail later.
        var bytes = KeyringCodec.Encode(OneSlotKeyring());
        var tampered = (byte[])bytes.Clone();
        tampered[0] = 99;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(tampered));

        Assert.Contains("Unsupported keyring format version: 99", ex.Message);
    }

    /// <summary>
    /// Builds bytes matching issue #119's original, pre-#120 <c>KeyringCodec.Encode</c> output
    /// shape for a single machine slot: same header/slot fields as <see cref="OneSlotKeyring"/>,
    /// but with the given <paramref name="formatVersion"/> and, deliberately, no trailing
    /// per-slot <c>kind</c> byte — #120 added that byte, so bytes built this way pre-date it.
    /// </summary>
    private static byte[] BuildPreIssue120Bytes(byte formatVersion)
    {
        var bytes = new List<byte> { formatVersion };
        bytes.AddRange(VaultId);
        bytes.Add(1); // k
        bytes.AddRange(LittleEndianUInt32(1)); // slotCount = 1
        bytes.AddRange(SlotId);
        bytes.AddRange(PublicKey);
        bytes.AddRange(LittleEndianUInt32((uint)Wrapped.Length));
        bytes.AddRange(Wrapped);
        return bytes.ToArray();
    }

    private static byte[] LittleEndianUInt32(uint value)
    {
        var buffer = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        return buffer;
    }
}
