using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Golden-byte tests for the per-secret record wire format (issues #111-#113) — pinning the
/// exact envelope and inner-payload layout <see cref="SecretRecordCodec"/> documents, not just
/// round-tripping encode/decode. The envelope's cleartext fields (magic, format version,
/// recordId, writeCounter, payload length) are fully deterministic and asserted byte-exact.
/// The encrypted payload's plaintext (the "inner payload": type, originId, timestamp,
/// generation counter, value, then zero padding to the bucket boundary) is also deterministic
/// given fixed inputs, so it is independently decrypted here (bypassing
/// <see cref="SecretRecordCodec.Decode"/>) and asserted byte-exact too. Only the AES-GCM
/// nonce/tag are necessarily random and therefore not pinned — pinning them would be wrong for
/// an AEAD scheme, not merely untested.
/// </summary>
public class SecretRecordCodecTests
{
    private static readonly byte[] VaultKey = Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] RecordId = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] OriginId = new byte[16];
    private static readonly DateTimeOffset Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_000);

    static SecretRecordCodecTests()
    {
        Array.Fill(OriginId, (byte)0xAA);
    }

    // Independently computed (Python, struct.pack) plaintext for: type=Value(0), the fixed
    // OriginId/Timestamp/GenerationCounter=0 above, value=UTF8("hello"), padded with zeros to
    // the 256-byte bucket. See SecretRecordCodec's layout doc comment for the field ordering.
    private const string ExpectedValueInnerHex = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0068e5cf8b010000000000000500000068656c6c6f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    [Fact]
    public void Encode_EnvelopeHeaderIsExactAndDeterministic()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 5, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray());

        var encoded = SecretRecordCodec.Encode(record, VaultKey);

        // magic "TSR1" + formatVersion(1) + recordId(32) + writeCounter=5 LE(8) + payloadLength
        // = nonce(12)+tag(16)+ciphertext(256) = 284 = 0x011C LE(4).
        var expectedHeader = Convert.FromHexString(
            "54535231" + "01" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "0500000000000000" +
            "1c010000");

        Assert.Equal(expectedHeader, encoded[..49]);
        Assert.Equal(49 + 284, encoded.Length);
    }

    [Fact]
    public void Encode_DecryptedInnerPayloadMatchesGoldenBytesExactly()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 5, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);

        var perRecordKey = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 5);
        var encryptedPayload = encoded[49..];
        var inner = Crypto.Decrypt(encryptedPayload, perRecordKey);

        Assert.Equal(256, inner.Length);
        Assert.Equal(ExpectedValueInnerHex, Convert.ToHexStringLower(inner));
    }

    [Fact]
    public void EncodeDecode_RoundTripsAllFields()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 5, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray(), GenerationCounter: 0);

        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        var decoded = SecretRecordCodec.Decode(encoded, VaultKey);

        Assert.Equal(record.RecordId, decoded.RecordId);
        Assert.Equal(record.WriteCounter, decoded.WriteCounter);
        Assert.Equal(record.OriginId, decoded.OriginId);
        Assert.Equal(record.Timestamp, decoded.Timestamp);
        Assert.Equal(record.Type, decoded.Type);
        Assert.Equal(record.Value, decoded.Value);
        Assert.Equal(record.GenerationCounter, decoded.GenerationCounter);
    }

    [Fact]
    public void EncodeDecode_RoundTripsNonZeroGenerationCounter()
    {
        // The field is reserved/unused today (issue #118 is a later wave), but the codec must
        // still carry an arbitrary value through correctly so that feature is additive later.
        var record = new SecretRecord(RecordId, WriteCounter: 3, OriginId, Timestamp, RecordType.Value, "v"u8.ToArray(), GenerationCounter: 42);

        var decoded = SecretRecordCodec.Decode(SecretRecordCodec.Encode(record, VaultKey), VaultKey);

        Assert.Equal(42u, decoded.GenerationCounter);
    }

    [Theory]
    [InlineData(RecordType.Value)]
    [InlineData(RecordType.Tombstone)]
    [InlineData(RecordType.Burned)]
    public void EncodeDecode_RoundTripsEveryRecordType(RecordType type)
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, type, "payload"u8.ToArray());

        var decoded = SecretRecordCodec.Decode(SecretRecordCodec.Encode(record, VaultKey), VaultKey);

        Assert.Equal(type, decoded.Type);
    }

    [Fact]
    public void Encode_TombstoneAndSmallValueRecordProduceTheSameFileSize()
    {
        // Issue #112: a tombstone must not be distinguishable from a live record by file size.
        var value = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray());
        var tombstone = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Tombstone, []);

        var valueEncoded = SecretRecordCodec.Encode(value, VaultKey);
        var tombstoneEncoded = SecretRecordCodec.Encode(tombstone, VaultKey);

        Assert.Equal(valueEncoded.Length, tombstoneEncoded.Length);
    }

    [Fact]
    public void Encode_RecordTypeIsNotVisibleInCleartext()
    {
        // Issue #112: record type lives inside the encrypted payload, not a cleartext field —
        // a transport observer must not be able to tell a tombstone from a value write.
        var value = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "x"u8.ToArray());
        var burned = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Burned, "x"u8.ToArray());

        var valueEncoded = SecretRecordCodec.Encode(value, VaultKey);
        var burnedEncoded = SecretRecordCodec.Encode(burned, VaultKey);

        // Cleartext envelope (everything but the AEAD payload) is byte-identical.
        Assert.Equal(valueEncoded[..49], burnedEncoded[..49]);
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
    public void Decode_TooShortThrowsDistinctError()
    {
        var ex = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(new byte[10], VaultKey));
        Assert.Contains("header", ex.Message);
    }

    [Fact]
    public void Decode_BadMagicThrowsDistinctError()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "x"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        encoded[0] ^= 0xFF;

        var ex = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey));
        Assert.Contains("magic", ex.Message);
    }

    [Fact]
    public void Decode_UnsupportedFormatVersionThrowsDistinctError()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "x"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        encoded[4] = 99;

        var ex = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey));
        Assert.Contains("format version", ex.Message);
    }

    [Fact]
    public void Decode_HugePayloadLengthPrefixThrowsInsteadOfOverflowing()
    {
        // Mirrors SecureEnclaveHardwareServiceTests' overflow guard: a payloadLength near
        // uint.MaxValue must not pass an addition-based bounds check via integer overflow.
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "x"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(encoded.AsSpan(45, 4), uint.MaxValue - 1);

        var ex = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey));
        Assert.Contains("length prefix", ex.Message);
    }

    [Fact]
    public void Decode_PayloadShorterThanAesGcmOverheadThrowsDistinctError()
    {
        // A payloadLength that is internally consistent with the array's actual remaining bytes
        // (so it passes the existing bounds check) but smaller than AES-GCM's fixed 12-byte
        // nonce + 16-byte tag overhead must not reach Crypto.Decrypt, which would throw a raw
        // ArgumentOutOfRangeException while slicing out the nonce instead of a catchable
        // TswapException.
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "x"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);

        // Forge a record whose payload is only 5 bytes — well under the 28-byte AES-GCM minimum
        // — and whose total length (49 header + 5) matches that payloadLength exactly.
        var forged = encoded[..54];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(forged.AsSpan(45, 4), 5);

        var ex = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(forged, VaultKey));
        Assert.Contains("payload", ex.Message);
    }

    [Fact]
    public void Decode_TruncatedPayloadThrows()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "x"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        var truncated = encoded[..^1];

        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(truncated, VaultKey));
    }

    [Fact]
    public void Decode_TamperedCiphertextThrows()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        encoded[^1] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => SecretRecordCodec.Decode(encoded, VaultKey));
    }

    [Fact]
    public void Decode_TamperedCleartextWriteCounterFailsAuthentication()
    {
        // Demonstrates the free integrity property from the codec's doc comment: writeCounter
        // feeds the per-record key derivation, so an on-path attacker flipping the cleartext
        // writeCounter (without also re-deriving and re-encrypting) makes the reader derive a
        // different key, which fails the AEAD tag check — no separate AAD binding needed for
        // this specific field's integrity.
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        // writeCounter occupies bytes [37, 45) of the envelope header.
        encoded[37] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => SecretRecordCodec.Decode(encoded, VaultKey));
    }

    [Fact]
    public void Decode_WrongVaultKeyThrows()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, "hello"u8.ToArray());
        var encoded = SecretRecordCodec.Encode(record, VaultKey);
        var wrongKey = new byte[32];

        Assert.ThrowsAny<Exception>(() => SecretRecordCodec.Decode(encoded, wrongKey));
    }

    [Fact]
    public void Encode_WrongRecordIdLengthThrows()
    {
        var record = new SecretRecord(new byte[10], WriteCounter: 1, OriginId, Timestamp, RecordType.Value, []);
        Assert.Throws<ArgumentException>(() => SecretRecordCodec.Encode(record, VaultKey));
    }

    [Fact]
    public void Encode_WrongOriginIdLengthThrows()
    {
        var record = new SecretRecord(RecordId, WriteCounter: 1, new byte[4], Timestamp, RecordType.Value, []);
        Assert.Throws<ArgumentException>(() => SecretRecordCodec.Encode(record, VaultKey));
    }

    [Fact]
    public void Encode_LargeValueCrossesIntoNextBucket()
    {
        var smallValue = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, new byte[1]);
        var largeValue = new SecretRecord(RecordId, WriteCounter: 1, OriginId, Timestamp, RecordType.Value, new byte[300]);

        var smallEncoded = SecretRecordCodec.Encode(smallValue, VaultKey);
        var largeEncoded = SecretRecordCodec.Encode(largeValue, VaultKey);

        Assert.Equal(49 + 12 + 16 + 256, smallEncoded.Length);
        Assert.Equal(49 + 12 + 16 + 512, largeEncoded.Length);
    }
}
