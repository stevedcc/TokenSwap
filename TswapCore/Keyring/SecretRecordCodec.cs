using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TswapCore.Keyring;

/// <summary>
/// Encodes/decodes one <see cref="SecretRecord"/> to/from the per-secret record wire format
/// (issues #111-#113, brief T6 decision 3). Fixed-binary, explicitly ordered — see
/// <see cref="KeyringFormat"/> for why this is not JSON. Record format version 1 never shipped
/// before brief T6, which replaced the plain write counter with a hybrid logical clock.
///
/// <para><b>On-disk layout</b> (all multi-byte integers little-endian):</para>
/// <code>
/// Cleartext header (all of it is the AES-GCM associated data):
///   magic            4 bytes   "TSR1" (KeyringFormat.RecordMagic)
///   formatVersion    1 byte    KeyringFormat.RecordFormatVersion
///   recordId         32 bytes  HMAC(K_names, secretName) — see FilenameHasher
///   writeHlcMs       8 bytes   this write's HLC, physical part (signed)
///   writeHlcLogical  4 bytes   this write's HLC, logical counter
///   writeOrigin      16 bytes  origin id of the machine that wrote the file
///   payloadLength    4 bytes   length of the section that follows
///   payload          AES-256-GCM under HKDF(K_v, recordId || write stamp): nonce(12) | tag(16) | ciphertext
///
/// Encrypted payload, padded with zero bytes to the next multiple of
/// KeyringFormat.PaddingBucketSize (256) before encryption (issue #113a):
///   recordType         1 byte    RecordType
///   versionHlcMs       8 bytes   } the stamp of the value or delete that decides
///   versionHlcLogical  4 bytes   } existence (decision 4)
///   versionOrigin      16 bytes  }
///   createdMs          8 bytes   display only
///   nameLength         2 bytes   then the UTF-8 name
///   valueLength        4 bytes   then the value bytes (empty for a tombstone)
///   hasPrevious        1 byte    0, or 1 then (fix round 1, B: the value a rotation replaced):
///     versionHlcMs 8, versionHlcLogical 4, versionOrigin 16, valueLength 4, value bytes
///   burnCount          1 byte    at most RecordMerge.MaxBurns, then per burn:
///     versionHlcMs 8, versionHlcLogical 4, versionOrigin 16   the version it marks
///     burnHlcMs 8, burnHlcLogical 4, burnOrigin 16            the burn's own stamp
///     reasonLength 2 (0xFFFF = no reason), then the UTF-8 reason
///   [zero padding to the bucket boundary]
/// </code>
///
/// <para><b>Why the write stamp is cleartext:</b> the per-record key is derived from it (decision
/// 3), so a reader needs it before decrypting. It is authenticated as associated data together with
/// the rest of the header, so it can't be altered without the record failing to open. The origin
/// id is per machine config, i.e. per vault, so it does not link a machine across vaults; per-record
/// edit timing is visible to the transport (the documented metadata leak of deterministic
/// filenames).</para>
///
/// <para><b>Why the record type is inside the payload:</b> a transport observer sees the same
/// shape for a value write, a delete and a burn; only the padding bucket is visible.</para>
///
/// <para>Decoding is strict: the record id must be <c>HMAC(K_names, name)</c> of the name inside
/// (so a record can't be moved under another secret's file name), lengths must fit, burns must be
/// at most <see cref="RecordMerge.MaxBurns"/>, and the padding must be all zero.</para>
/// </summary>
public static class SecretRecordCodec
{
    /// <summary>magic(4) + formatVersion(1) + recordId(32) + hlc(8+4) + origin(16) + payloadLength(4).</summary>
    public const int HeaderSize = 4 + 1 + KeyringFormat.RecordIdSize + 12 + KeyringFormat.OriginIdSize + 4;

    private const int StampSize = 12 + KeyringFormat.OriginIdSize;

    // recordType(1) + version stamp + createdMs(8) + nameLength(2)
    private const int InnerFixedSize = 1 + StampSize + 8 + 2;

    private const ushort NoReason = 0xFFFF;

    /// <summary>Encrypts and encodes <paramref name="record"/> under a per-record key from <paramref name="vaultKey"/> (<c>K_v</c>).</summary>
    public static byte[] Encode(SecretRecord record, byte[] vaultKey)
    {
        if (record.RecordId.Length != KeyringFormat.RecordIdSize)
            throw new ArgumentException($"RecordId must be {KeyringFormat.RecordIdSize} bytes", nameof(record));
        if (record.Burns.Count > RecordMerge.MaxBurns)
            throw new ArgumentException($"A record holds at most {RecordMerge.MaxBurns} burns", nameof(record));

        var name = Encoding.UTF8.GetBytes(record.Name);
        if (name.Length > ushort.MaxValue)
            throw new ArgumentException("Name too long for a record", nameof(record));
        var reasons = record.Burns.Select(b => b.Reason == null ? null : Encoding.UTF8.GetBytes(b.Reason)).ToList();
        if (reasons.Any(r => r != null && r.Length >= NoReason))
            throw new TswapException("A burn reason is too long to store (64 KiB at most).");

        if (record.Previous != null && record.Type == RecordType.Tombstone)
            throw new ArgumentException("A tombstone carries no previous value", nameof(record));
        var raw = InnerFixedSize + name.Length + 4 + record.Value.Length
            + 1 + (record.Previous == null ? 0 : StampSize + 4 + record.Previous.Value.Length) + 1
            + record.Burns.Count * (2 * StampSize + 2) + reasons.Sum(r => r?.Length ?? 0);
        var inner = new byte[BucketSize(raw)]; // zero-initialized: the padding tail is all zero bytes
        var span = inner.AsSpan();
        var offset = 0;
        span[offset++] = (byte)record.Type;
        offset = WriteStamp(span, offset, record.Version);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(offset, 8), record.CreatedMs);
        offset += 8;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)name.Length);
        offset += 2;
        name.CopyTo(span.Slice(offset));
        offset += name.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)record.Value.Length);
        offset += 4;
        record.Value.CopyTo(span.Slice(offset));
        offset += record.Value.Length;
        if (record.Previous is { } previous)
        {
            span[offset++] = 1;
            offset = WriteStamp(span, offset, previous.Version);
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)previous.Value.Length);
            offset += 4;
            previous.Value.CopyTo(span.Slice(offset));
            offset += previous.Value.Length;
        }
        else
        {
            span[offset++] = 0;
        }
        span[offset++] = (byte)record.Burns.Count;
        for (var i = 0; i < record.Burns.Count; i++)
        {
            offset = WriteStamp(span, offset, record.Burns[i].Version);
            offset = WriteStamp(span, offset, record.Burns[i].Burn);
            var reason = reasons[i];
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), reason == null ? NoReason : (ushort)reason.Length);
            offset += 2;
            if (reason != null)
            {
                reason.CopyTo(span.Slice(offset));
                offset += reason.Length;
            }
        }

        var header = new byte[HeaderSize];
        var h = header.AsSpan();
        KeyringFormat.RecordMagic.CopyTo(h);
        h[4] = KeyringFormat.RecordFormatVersion;
        record.RecordId.CopyTo(h.Slice(5, KeyringFormat.RecordIdSize));
        WriteStamp(h, 5 + KeyringFormat.RecordIdSize, record.Write);
        var payloadLength = AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize + inner.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(h.Slice(HeaderSize - 4, 4), (uint)payloadLength);

        var perRecordKey = RecordKeyDerivation.Derive(vaultKey, record.RecordId, record.Write);
        try
        {
            var encrypted = Crypto.Encrypt(inner, perRecordKey, header);
            return [.. header, .. encrypted];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(perRecordKey);
            CryptographicOperations.ZeroMemory(inner);
        }
    }

    /// <summary>
    /// Reads the cleartext write stamp and record id without the key (for messages and for the
    /// highest-HLC-seen bookkeeping of records that can't be decrypted). Null when the header is
    /// malformed.
    /// </summary>
    public static (byte[] RecordId, Stamp Write)? PeekHeader(byte[] bytes)
    {
        if (bytes.Length < HeaderSize || !bytes.AsSpan(0, 4).SequenceEqual(KeyringFormat.RecordMagic)
            || bytes[4] != KeyringFormat.RecordFormatVersion)
            return null;
        return (bytes.AsSpan(5, KeyringFormat.RecordIdSize).ToArray(), ReadStamp(bytes, 5 + KeyringFormat.RecordIdSize));
    }

    /// <summary>
    /// Decodes and decrypts a record produced by <see cref="Encode"/>. Every malformed input is a
    /// <see cref="TswapException"/> with its own message; a wrong key or tampered bytes are a
    /// <see cref="CryptographicException"/> from the AEAD (deliberately separate classes).
    /// </summary>
    public static SecretRecord Decode(byte[] bytes, byte[] vaultKey)
    {
        if (bytes.Length < HeaderSize)
            throw new TswapException("Malformed record: shorter than the envelope header");
        if (!bytes.AsSpan(0, 4).SequenceEqual(KeyringFormat.RecordMagic))
            throw new TswapException("Malformed record: bad magic bytes");
        var formatVersion = bytes[4];
        if (formatVersion != KeyringFormat.RecordFormatVersion)
            throw new TswapException($"Unsupported record format version: {formatVersion}");

        var recordId = bytes.AsSpan(5, KeyringFormat.RecordIdSize).ToArray();
        var write = ReadStamp(bytes, 5 + KeyringFormat.RecordIdSize);
        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(HeaderSize - 4, 4));

        // Subtraction-based: a length near uint.MaxValue can't overflow an addition into passing.
        if (payloadLength > bytes.Length - HeaderSize)
            throw new TswapException("Malformed record: payload length prefix exceeds available data");
        if (payloadLength != bytes.Length - HeaderSize)
            throw new TswapException("Malformed record: trailing bytes after the payload");
        var minPayloadSize = AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize;
        if (payloadLength < minPayloadSize)
            throw new TswapException("Malformed record: payload too short to contain a valid encrypted payload");

        var perRecordKey = RecordKeyDerivation.Derive(vaultKey, recordId, write);
        byte[] inner;
        try
        {
            inner = Crypto.Decrypt(bytes[HeaderSize..], perRecordKey, bytes.AsSpan(0, HeaderSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(perRecordKey);
        }

        try
        {
            return DecodeInner(inner, recordId, write, vaultKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
        }
    }

    private static SecretRecord DecodeInner(byte[] inner, byte[] recordId, Stamp write, byte[] vaultKey)
    {
        if (inner.Length < InnerFixedSize)
            throw new TswapException("Malformed record: decrypted payload shorter than the inner header");
        var offset = 0;
        var typeByte = inner[offset++];
        if (typeByte > (byte)RecordType.Burned)
            throw new TswapException($"Malformed record: unknown record type {typeByte}");
        var version = ReadStamp(inner, offset);
        offset += StampSize;
        var createdMs = BinaryPrimitives.ReadInt64LittleEndian(inner.AsSpan(offset, 8));
        offset += 8;
        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(inner.AsSpan(offset, 2));
        offset += 2;
        Need(inner, offset, nameLength + 4, "name");
        var name = DecodeUtf8(inner.AsSpan(offset, nameLength), "name");
        offset += nameLength;
        var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(inner.AsSpan(offset, 4));
        offset += 4;
        if (valueLength > inner.Length - offset - 1)
            throw new TswapException("Malformed record: value length prefix exceeds decrypted payload");
        var value = inner.AsSpan(offset, (int)valueLength).ToArray();
        offset += (int)valueLength;
        Need(inner, offset, 2, "previous value");
        PreviousValue? previous = null;
        var hasPrevious = inner[offset++];
        if (hasPrevious > 1)
            throw new TswapException("Malformed record: bad previous-value flag");
        if (hasPrevious == 1)
        {
            if (typeByte == (byte)RecordType.Tombstone)
                throw new TswapException("Malformed record: a tombstone carries a previous value");
            Need(inner, offset, StampSize + 4, "previous value");
            var previousVersion = ReadStamp(inner, offset);
            offset += StampSize;
            var previousLength = BinaryPrimitives.ReadUInt32LittleEndian(inner.AsSpan(offset, 4));
            offset += 4;
            if (previousLength > inner.Length - offset - 1)
                throw new TswapException("Malformed record: previous value length prefix exceeds decrypted payload");
            previous = new PreviousValue(previousVersion, inner.AsSpan(offset, (int)previousLength).ToArray());
            offset += (int)previousLength;
        }
        var burnCount = inner[offset++];
        if (burnCount > RecordMerge.MaxBurns)
            throw new TswapException($"Malformed record: {burnCount} burns (at most {RecordMerge.MaxBurns})");
        var burns = new List<BurnEntry>(burnCount);
        for (var i = 0; i < burnCount; i++)
        {
            Need(inner, offset, 2 * StampSize + 2, "burn");
            var burnVersion = ReadStamp(inner, offset);
            offset += StampSize;
            var burnStamp = ReadStamp(inner, offset);
            offset += StampSize;
            var reasonLength = BinaryPrimitives.ReadUInt16LittleEndian(inner.AsSpan(offset, 2));
            offset += 2;
            string? reason = null;
            if (reasonLength != NoReason)
            {
                Need(inner, offset, reasonLength, "burn reason");
                reason = DecodeUtf8(inner.AsSpan(offset, reasonLength), "burn reason");
                offset += reasonLength;
            }
            burns.Add(new BurnEntry(burnVersion, burnStamp, reason));
        }
        if (inner.AsSpan(offset).ContainsAnyExcept((byte)0))
            throw new TswapException("Malformed record: non-zero bytes in the padding");

        var namesKey = RecordKeyDerivation.DeriveNamesKey(vaultKey);
        var expectedId = FilenameHasher.ComputeRecordId(namesKey, name);
        CryptographicOperations.ZeroMemory(namesKey);
        if (!CryptographicOperations.FixedTimeEquals(expectedId, recordId))
            throw new TswapException("Malformed record: its record id does not belong to the name inside it");

        return new SecretRecord(recordId, write, (RecordType)typeByte, version, name, createdMs, value, burns, previous);
    }

    private static void Need(byte[] inner, int offset, int count, string what)
    {
        if (count > inner.Length - offset)
            throw new TswapException($"Malformed record: truncated {what}");
    }

    private static string DecodeUtf8(ReadOnlySpan<byte> bytes, string what)
    {
        try
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new TswapException($"Malformed record: the {what} is not valid UTF-8");
        }
    }

    private static int WriteStamp(Span<byte> span, int offset, Stamp stamp)
    {
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(offset, 8), stamp.Hlc.PhysicalMs);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset + 8, 4), stamp.Hlc.Logical);
        stamp.Origin.CopyTo(span.Slice(offset + 12, KeyringFormat.OriginIdSize));
        return offset + StampSize;
    }

    private static Stamp ReadStamp(byte[] bytes, int offset) => new(
        new Hlc(BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(offset, 8)),
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 8, 4))),
        bytes.AsSpan(offset + 12, KeyringFormat.OriginIdSize).ToArray());

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
