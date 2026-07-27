using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// Encodes/decodes one <see cref="SecretRecord"/> to/from the Phase 6 per-secret record wire
/// format (issues #111-#113). Fixed-binary, explicitly ordered — see
/// <see cref="KeyringFormat"/> for why this is not JSON.
///
/// <para><b>On-disk layout</b> (all multi-byte integers little-endian):</para>
/// <code>
/// Cleartext envelope:
///   magic            4 bytes   "TSR1" (KeyringFormat.RecordMagic)
///   formatVersion    1 byte    KeyringFormat.RecordFormatVersion
///   recordId         32 bytes  HMAC(K_names, secretName) — see FilenameHasher
///   writeCounter     8 bytes   ordering authority; MUST be cleartext, see below
///   payloadLength    4 bytes   length in bytes of the section that follows
///   payload          payloadLength bytes  AES-256-GCM: nonce(12) | tag(16) | ciphertext
///
/// Encrypted payload (ciphertext, once decrypted), padded to the next multiple of
/// KeyringFormat.PaddingBucketSize before encryption (issue #113a):
///   recordType         1 byte    RecordType
///   originId           16 bytes  ordering tiebreak / last-writer id
///   timestampUnixMs    8 bytes   display-only, see SecretRecord.Timestamp
///   generationCounter  4 bytes   reserved (issue #118), always 0 today
///   valueLength        4 bytes   real length of the value that follows (pre-padding)
///   value              valueLength bytes
///   [zero padding to the bucket boundary]
/// </code>
///
/// <para><b>Why <c>recordType</c> lives inside the encrypted payload, not the cleartext
/// envelope:</b> per <c>REFACTORING_PLAN.md</c> §Phase 6, "record type is part of the payload" —
/// keeping it encrypted means a transport observer sees the same shape (magic, version,
/// recordId, writeCounter, a ciphertext of some bucketed length) for a value write, a delete,
/// and a burn. Only the padding bucket is visible, per issue #113a; the record kind is not.</para>
///
/// <para><b>Why <c>writeCounter</c> must be cleartext despite that:</b> the per-record key is
/// <c>HKDF(K_v, salt = recordId || writeCounter)</c> (issue #113b), so a reader needs
/// <c>writeCounter</c> to derive the key before it can decrypt anything — it cannot itself be
/// inside the thing it helps decrypt. This is a deliberate, spec-driven exception, not an
/// oversight: it also means an on-path attacker cannot tamper with the cleartext
/// <c>writeCounter</c> without the derived key changing and authentication failing, which is a
/// free integrity property of this construction, not something bolted on separately (formal AAD
/// binding is out of scope here — see issue #117, which is about the keyring's slot AEAD, not
/// per-record envelopes).</para>
/// </summary>
public static class SecretRecordCodec
{
    // magic(4) + formatVersion(1) + recordId(32) + writeCounter(8) + payloadLength(4)
    private const int EnvelopeHeaderSize = 4 + 1 + KeyringFormat.RecordIdSize + 8 + 4;

    // recordType(1) + originId(16) + timestamp(8) + generationCounter(4) + valueLength(4)
    private const int InnerHeaderSize = 1 + KeyringFormat.OriginIdSize + 8 + 4 + 4;

    /// <summary>
    /// Encrypts and encodes <paramref name="record"/> under the per-record key derived from
    /// <paramref name="vaultKey"/> (<c>K_v</c>) via <see cref="RecordKeyDerivation"/>.
    /// </summary>
    public static byte[] Encode(SecretRecord record, byte[] vaultKey)
    {
        if (record.RecordId.Length != KeyringFormat.RecordIdSize)
            throw new ArgumentException($"RecordId must be {KeyringFormat.RecordIdSize} bytes", nameof(record));
        if (record.OriginId.Length != KeyringFormat.OriginIdSize)
            throw new ArgumentException($"OriginId must be {KeyringFormat.OriginIdSize} bytes", nameof(record));

        var rawInner = InnerHeaderSize + record.Value.Length;
        var bucketed = BucketSize(rawInner);
        var inner = new byte[bucketed]; // zero-initialized: the padding tail is all zero bytes

        inner[0] = (byte)record.Type;
        record.OriginId.CopyTo(inner, 1);
        BinaryPrimitives.WriteInt64LittleEndian(inner.AsSpan(17, 8), record.Timestamp.ToUnixTimeMilliseconds());
        BinaryPrimitives.WriteUInt32LittleEndian(inner.AsSpan(25, 4), record.GenerationCounter);
        BinaryPrimitives.WriteUInt32LittleEndian(inner.AsSpan(29, 4), (uint)record.Value.Length);
        record.Value.CopyTo(inner, InnerHeaderSize);

        var perRecordKey = RecordKeyDerivation.Derive(vaultKey, record.RecordId, record.WriteCounter);
        var encryptedPayload = Crypto.Encrypt(inner, perRecordKey);

        var result = new byte[EnvelopeHeaderSize + encryptedPayload.Length];
        var span = result.AsSpan();
        KeyringFormat.RecordMagic.CopyTo(span);
        span[4] = KeyringFormat.RecordFormatVersion;
        record.RecordId.CopyTo(span.Slice(5, KeyringFormat.RecordIdSize));
        BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(5 + KeyringFormat.RecordIdSize, 8), record.WriteCounter);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(13 + KeyringFormat.RecordIdSize, 4), (uint)encryptedPayload.Length);
        encryptedPayload.CopyTo(span.Slice(EnvelopeHeaderSize));
        return result;
    }

    /// <summary>
    /// Decodes and decrypts a record previously produced by <see cref="Encode"/>. Throws
    /// <see cref="TswapException"/> with a distinct message for each of: too-short input, bad
    /// magic, unsupported format version, a corrupt/overflowing length prefix, a payload too
    /// short to hold AES-GCM's fixed nonce+tag overhead, and truncated payload — deliberately
    /// separate from whatever <see cref="Crypto.Decrypt"/> throws for a wrong key or tampered
    /// ciphertext, so the two classes of failure aren't conflated.
    /// </summary>
    public static SecretRecord Decode(byte[] bytes, byte[] vaultKey)
    {
        if (bytes.Length < EnvelopeHeaderSize)
            throw new TswapException("Malformed record: shorter than the envelope header");

        if (!bytes.AsSpan(0, 4).SequenceEqual(KeyringFormat.RecordMagic))
            throw new TswapException("Malformed record: bad magic bytes");

        var formatVersion = bytes[4];
        if (formatVersion != KeyringFormat.RecordFormatVersion)
            throw new TswapException($"Unsupported record format version: {formatVersion}");

        var recordId = bytes.AsSpan(5, KeyringFormat.RecordIdSize).ToArray();
        var writeCounter = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(5 + KeyringFormat.RecordIdSize, 8));
        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(13 + KeyringFormat.RecordIdSize, 4));

        // Subtraction-based bounds check (not "EnvelopeHeaderSize + payloadLength > bytes.Length"):
        // a payloadLength near uint.MaxValue would overflow an addition-based check and pass when
        // it shouldn't, reaching an allocation sized by attacker-controlled length.
        if (payloadLength > bytes.Length - EnvelopeHeaderSize)
            throw new TswapException("Malformed record: payload length prefix exceeds available data");

        // A payloadLength can be internally consistent with the file's remaining bytes (passing
        // the check above) yet still be too small to hold AES-GCM's fixed nonce+tag overhead —
        // without this check, Crypto.Decrypt would throw a raw ArgumentOutOfRangeException while
        // slicing out the nonce instead of a catchable TswapException.
        var minPayloadSize = AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize;
        if (payloadLength < minPayloadSize)
            throw new TswapException("Malformed record: payload too short to contain a valid encrypted payload");

        var encryptedPayload = bytes.AsSpan(EnvelopeHeaderSize, (int)payloadLength).ToArray();
        var perRecordKey = RecordKeyDerivation.Derive(vaultKey, recordId, writeCounter);
        var inner = Crypto.Decrypt(encryptedPayload, perRecordKey);

        if (inner.Length < InnerHeaderSize)
            throw new TswapException("Malformed record: decrypted payload shorter than the inner header");

        var type = (RecordType)inner[0];
        var originId = inner.AsSpan(1, KeyringFormat.OriginIdSize).ToArray();
        var timestampMs = BinaryPrimitives.ReadInt64LittleEndian(inner.AsSpan(17, 8));
        var generationCounter = BinaryPrimitives.ReadUInt32LittleEndian(inner.AsSpan(25, 4));
        var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(inner.AsSpan(29, 4));

        if (valueLength > inner.Length - InnerHeaderSize)
            throw new TswapException("Malformed record: value length prefix exceeds decrypted payload");

        var value = inner.AsSpan(InnerHeaderSize, (int)valueLength).ToArray();

        return new SecretRecord(recordId, writeCounter, originId, DateTimeOffset.FromUnixTimeMilliseconds(timestampMs), type, value, generationCounter);
    }

    /// <summary>
    /// Rounds <paramref name="rawLength"/> up to the next multiple of
    /// <see cref="KeyringFormat.PaddingBucketSize"/>, with a floor of one full bucket (an empty
    /// tombstone still occupies a whole bucket, not a zero-length one, per issue #113a).
    /// </summary>
    internal static int BucketSize(int rawLength)
    {
        if (rawLength <= 0)
            return KeyringFormat.PaddingBucketSize;

        var bucket = KeyringFormat.PaddingBucketSize;
        return ((rawLength + bucket - 1) / bucket) * bucket;
    }
}
