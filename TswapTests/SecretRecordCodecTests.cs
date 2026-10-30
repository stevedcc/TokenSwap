using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Golden-byte tests for the per-secret record wire format (issues #111-#113), as brief T6
/// decision 3 changed it (HLC write stamp and origin id in the authenticated cleartext header,
/// version stamp, name, value and burns inside). The header is deterministic and asserted
/// byte-exact; the decrypted inner payload of one record of each type is asserted byte-exact
/// against bytes computed independently (Python, <c>struct.pack</c> + <c>hmac</c>/HKDF by hand).
/// Only the AES-GCM nonce and tag are random, so they are not pinned.
/// </summary>
public class SecretRecordCodecTests
{
    private static readonly byte[] VaultKey = Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] OriginA = Enumerable.Repeat((byte)0xAA, 16).ToArray();
    private static readonly byte[] OriginB = Enumerable.Repeat((byte)0xBB, 16).ToArray();

    // Python: hkdf(VaultKey, salt=None, info=b'tswap-record-names-v1') then hmac-sha256(kNames, b'db-pass').
    private const string ExpectedNamesKeyHex = "2ed49fe10795ccdcf52d9b4de13f2065ef1703bb1cf94ccf3f275a6a26fa9ada";
    private const string ExpectedRecordIdHex = "40d7af34f39ce53c81e9bec0685ebfa139a081fabc3c613f7991722137dc09be";

    // Python: hkdf(VaultKey, salt=recordId || pack('<qI', 1700000000500, 2) || 0xAA*16, info=b'tswap-record-key-v1').
    private const string ExpectedRecordKeyHex = "2ec1d76fb77f532b668d75a5bb135815389a5ffa65c985e445420383ff7f0a21";

    private static readonly byte[] RecordId = Convert.FromHexString(ExpectedRecordIdHex);
    private static readonly Stamp Write = new(new Hlc(1_700_000_000_500, 2), OriginA);
    private static readonly Stamp Version = new(new Hlc(1_700_000_000_000, 0), OriginA);
    private const long CreatedMs = 1_699_000_000_000;

    private const string ExpectedHeaderHex =
        "54535231" + "01" + ExpectedRecordIdHex +
        "f469e5cf8b010000" + "02000000" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "1c010000";

    private const string ExpectedValueInnerHex = "000068e5cf8b01000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa009e4a948b010000070064622d706173730500000068656c6c6f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    private const string ExpectedTombstoneInnerHex = "012c69e5cf8b01000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa009e4a948b010000070064622d70617373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    private const string ExpectedBurnedInnerHex = "020068e5cf8b01000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa009e4a948b010000070064622d706173730500000068656c6c6f00010068e5cf8b01000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9069e5cf8b01000001000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06006c65616b6564000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    private const string ExpectedPreviousInnerHex = "000068e5cf8b01000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa009e4a948b010000070064622d706173730500000068656c6c6f010084d97b8901000003000000cccccccccccccccccccccccccccccccc060000006f6c642d7077000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    private static SecretRecord ValueRecord(byte[]? value = null) =>
        new(RecordId, Write, RecordType.Value, Version, "db-pass", CreatedMs, value ?? "hello"u8.ToArray(), []);

    private static SecretRecord TombstoneRecord() =>
        new(RecordId, Write, RecordType.Tombstone, new Stamp(new Hlc(1_700_000_000_300, 0), OriginA), "db-pass", CreatedMs, [], []);

    private static SecretRecord BurnedRecord() =>
        new(RecordId, Write, RecordType.Burned, Version, "db-pass", CreatedMs, "hello"u8.ToArray(),
            [new BurnEntry(Version, new Stamp(new Hlc(1_700_000_000_400, 1), OriginB), "leaked")]);

    private static byte[] DecryptInner(byte[] encoded)
    {
        var key = RecordKeyDerivation.Derive(VaultKey, RecordId, Write);
        return Crypto.Decrypt(encoded[SecretRecordCodec.HeaderSize..], key, encoded.AsSpan(0, SecretRecordCodec.HeaderSize));
    }

    [Fact]
    public void NamesKeyAndRecordId_MatchIndependentlyComputedBytes()
    {
        var namesKey = RecordKeyDerivation.DeriveNamesKey(VaultKey);

        Assert.Equal(ExpectedNamesKeyHex, Convert.ToHexStringLower(namesKey));
        Assert.Equal(ExpectedRecordIdHex, FilenameHasher.ComputeFilename(namesKey, "db-pass"));
    }

    [Fact]
    public void PerRecordKey_FromTheWriteStamp_MatchesIndependentlyComputedHkdf()
    {
        Assert.Equal(ExpectedRecordKeyHex, Convert.ToHexStringLower(RecordKeyDerivation.Derive(VaultKey, RecordId, Write)));
    }

    [Fact]
    public void PerRecordKey_DiffersByOriginAtTheSameHlc()
    {
        var other = new Stamp(Write.Hlc, OriginB);

        Assert.NotEqual(RecordKeyDerivation.Derive(VaultKey, RecordId, Write), RecordKeyDerivation.Derive(VaultKey, RecordId, other));
    }

    [Fact]
    public void Encode_HeaderIsExactAndDeterministic()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);

        Assert.Equal(69, SecretRecordCodec.HeaderSize);
        Assert.Equal(ExpectedHeaderHex, Convert.ToHexStringLower(encoded[..69]));
        Assert.Equal(69 + 12 + 16 + 256, encoded.Length);
    }

    [Fact]
    public void Encode_ValueRecord_InnerPayloadMatchesGoldenBytes()
    {
        Assert.Equal(ExpectedValueInnerHex, Convert.ToHexStringLower(DecryptInner(SecretRecordCodec.Encode(ValueRecord(), VaultKey))));
    }

    [Fact]
    public void Encode_TombstoneRecord_InnerPayloadMatchesGoldenBytes()
    {
        Assert.Equal(ExpectedTombstoneInnerHex, Convert.ToHexStringLower(DecryptInner(SecretRecordCodec.Encode(TombstoneRecord(), VaultKey))));
    }

    [Fact]
    public void Encode_BurnedRecord_InnerPayloadMatchesGoldenBytes()
    {
        Assert.Equal(ExpectedBurnedInnerHex, Convert.ToHexStringLower(DecryptInner(SecretRecordCodec.Encode(BurnedRecord(), VaultKey))));
    }

    [Fact]
    public void Encode_ValueRecordWithAPreviousValue_InnerPayloadMatchesGoldenBytes()
    {
        // Fix round 1 (B): one level of previous value, with that value's version stamp.
        var previous = new PreviousValue(new Stamp(new Hlc(1_690_000_000_000, 3), Enumerable.Repeat((byte)0xCC, 16).ToArray()), "old-pw"u8.ToArray());
        var record = ValueRecord() with { Previous = previous };

        var encoded = SecretRecordCodec.Encode(record, VaultKey);

        Assert.Equal(ExpectedPreviousInnerHex, Convert.ToHexStringLower(DecryptInner(encoded)));
        var decoded = SecretRecordCodec.Decode(encoded, VaultKey);
        Assert.True(record.SameState(decoded));
        Assert.Equal("old-pw"u8.ToArray(), decoded.Previous!.Value);
    }

    [Fact]
    public void Header_IsAuthenticated_AnyFlippedHeaderByteFailsToOpen()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);

        // Every header byte past the magic and version (checked first with their own messages),
        // the payload length included (also checked first): the write stamp and origin feed the
        // key and the associated data, the record id both.
        foreach (var index in new[] { 5, 36, 37, 44, 45, 48, 49, 64 })
        {
            var tampered = (byte[])encoded.Clone();
            tampered[index] ^= 0x01;
            Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(tampered, VaultKey));
        }
    }

    [Theory]
    [InlineData(RecordType.Value)]
    [InlineData(RecordType.Tombstone)]
    [InlineData(RecordType.Burned)]
    public void EncodeDecode_RoundTripsEveryRecordType(RecordType type)
    {
        var record = type switch
        {
            RecordType.Value => ValueRecord(),
            RecordType.Tombstone => TombstoneRecord(),
            _ => BurnedRecord(),
        };

        var decoded = SecretRecordCodec.Decode(SecretRecordCodec.Encode(record, VaultKey), VaultKey);

        Assert.True(record.SameState(decoded));
        Assert.Equal(record.Write, decoded.Write);
        Assert.Equal(type, decoded.Type);
    }

    [Fact]
    public void Encode_TombstoneAndSmallValueRecordProduceTheSameFileSize()
    {
        Assert.Equal(SecretRecordCodec.Encode(ValueRecord(), VaultKey).Length, SecretRecordCodec.Encode(TombstoneRecord(), VaultKey).Length);
    }

    [Fact]
    public void Encode_RecordTypeIsNotVisibleInCleartext()
    {
        var value = SecretRecordCodec.Encode(ValueRecord(), VaultKey);
        var burned = SecretRecordCodec.Encode(BurnedRecord(), VaultKey);

        Assert.Equal(value[..69], burned[..69]);
        Assert.Equal(value.Length, burned.Length);
    }

    [Theory]
    [InlineData(0, 256)]
    [InlineData(1, 256)]
    [InlineData(255, 256)]
    [InlineData(256, 256)]
    [InlineData(257, 512)]
    [InlineData(512, 512)]
    [InlineData(513, 768)]
    public void BucketSize_RoundsUpToNextMultipleWithOneBucketFloor(int rawLength, int expectedBucket)
    {
        Assert.Equal(expectedBucket, SecretRecordCodec.BucketSize(rawLength));
    }

    [Fact]
    public void Encode_ValueOneBytePastTheBucket_TakesTheNextBucket()
    {
        // Inner payload: 39 fixed + 7 (name) + 4 + value + 1 (previous flag) + 1 (burn count) = 52 + value bytes.
        var fits = SecretRecordCodec.Encode(ValueRecord(new byte[256 - 52]), VaultKey);
        var past = SecretRecordCodec.Encode(ValueRecord(new byte[256 - 52 + 1]), VaultKey);

        Assert.Equal(69 + 28 + 256, fits.Length);
        Assert.Equal(69 + 28 + 512, past.Length);
    }

    [Fact]
    public void Decode_TooShortThrowsDistinctError()
    {
        var ex = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(new byte[10], VaultKey));
        Assert.Contains("header", ex.Message);
    }

    [Fact]
    public void Decode_BadMagicThrowsDistinctError()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);
        encoded[0] ^= 0xFF;

        Assert.Contains("magic", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey)).Message);
    }

    [Fact]
    public void Decode_UnsupportedFormatVersionThrowsDistinctError()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);
        encoded[4] = 99;

        Assert.Contains("format version", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey)).Message);
    }

    [Fact]
    public void Decode_HugePayloadLengthPrefixThrowsInsteadOfOverflowing()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);
        BinaryPrimitives.WriteUInt32LittleEndian(encoded.AsSpan(65, 4), uint.MaxValue - 1);

        Assert.Contains("length prefix", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey)).Message);
    }

    [Fact]
    public void Decode_PayloadShorterThanAesGcmOverheadThrowsDistinctError()
    {
        var forged = SecretRecordCodec.Encode(ValueRecord(), VaultKey)[..74];
        BinaryPrimitives.WriteUInt32LittleEndian(forged.AsSpan(65, 4), 5);

        Assert.Contains("payload", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(forged, VaultKey)).Message);
    }

    [Fact]
    public void Decode_TruncatedRecordThrowsTswapException()
    {
        // A record cut short mid-sync: the length prefix no longer fits the data.
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);

        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded[..^1], VaultKey));
    }

    [Fact]
    public void Decode_TrailingBytesThrow()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);

        Assert.Contains("trailing", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode([.. encoded, 0], VaultKey)).Message);
    }

    [Fact]
    public void Decode_TamperedCiphertextFailsAuthentication()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);
        encoded[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(encoded, VaultKey));
    }

    [Fact]
    public void Decode_WrongVaultKeyFailsAuthentication()
    {
        var encoded = SecretRecordCodec.Encode(ValueRecord(), VaultKey);

        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(encoded, new byte[32]));
    }

    [Fact]
    public void Decode_RecordIdThatDoesNotBelongToTheName_IsRefused()
    {
        // A record re-encrypted under another secret's id (as a K_v holder could) is not accepted
        // in that secret's place: the id must be HMAC(K_names, name of the record).
        var otherId = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(VaultKey), "other");
        var encoded = SecretRecordCodec.Encode(ValueRecord() with { RecordId = otherId }, VaultKey);

        Assert.Contains("record id", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey)).Message);
    }

    [Fact]
    public void Encode_WrongRecordIdLengthThrows()
    {
        Assert.Throws<ArgumentException>(() => SecretRecordCodec.Encode(ValueRecord() with { RecordId = new byte[10] }, VaultKey));
    }

    [Fact]
    public void Stamp_WrongOriginLengthThrows()
    {
        Assert.Throws<ArgumentException>(() => new Stamp(Hlc.Zero, new byte[4]));
    }

    [Fact]
    public void Encode_MoreThanMaxBurnsThrows()
    {
        var burns = Enumerable.Range(0, RecordMerge.MaxBurns + 1)
            .Select(i => new BurnEntry(new Stamp(new Hlc(i, 0), OriginA), new Stamp(new Hlc(i, 1), OriginA), null))
            .ToList();

        Assert.Throws<ArgumentException>(() => SecretRecordCodec.Encode(ValueRecord() with { Burns = burns }, VaultKey));
    }

    [Fact]
    public void Burns_ReasonNullAndEmpty_RoundTripDistinctly()
    {
        var record = ValueRecord() with
        {
            Type = RecordType.Burned,
            Burns =
            [
                new BurnEntry(new Stamp(new Hlc(1, 0), OriginA), new Stamp(new Hlc(2, 0), OriginA), null),
                new BurnEntry(Version, new Stamp(new Hlc(1_700_000_000_100, 0), OriginB), ""),
            ],
        };

        var decoded = SecretRecordCodec.Decode(SecretRecordCodec.Encode(record, VaultKey), VaultKey);

        Assert.Null(decoded.Burns[0].Reason);
        Assert.Equal("", decoded.Burns[1].Reason);
    }
}
