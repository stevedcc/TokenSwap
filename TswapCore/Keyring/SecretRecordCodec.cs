using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Fingerprints;

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
///
/// <para><b>Format 3</b> (brief T16-S1, v0.2.0): split envelopes. The layout above is format 2, still
/// read, and written when asked (<see cref="Encode(SecretRecord, byte[], byte)"/>). Format 3:</para>
/// <code>
/// magic "TSR1" 4 | formatVersion 3 | recordId 32 | writeStamp 28 | valueSectionCount 1
/// metadataLength 4 | metadata section: nonce 12 | tag 16 | ciphertext (padded to 256)
/// per value section, in the metadata's version order: length 4 | nonce 12 | tag 16 | ciphertext (padded to 256)
///
/// metadata plaintext: recordType 1 | versionStamp 28 | createdMs 8 | nameLength 2 + name
///   | versionCount 1 (0 tombstone, 1 current, 2 current + previous), per version (current first):
///       stamp 28 | role 1 (0 current, 1 previous)
///       | hasFingerprints 1, then variantSetVersion 1 | entryCount 1
///         | per entry: kind 1 | length 4 | rollingHash 8 | hmac 16
///   | burns (as format 2: burnCount 1, per burn version stamp, burn stamp, reasonLength 2 + reason)
///   | extensionCount 2, per extension: type 2 | length 4 | data
///   | zero padding
/// value plaintext: valueLength 4 | value | zero padding
///
/// metadata key = HKDF(K_v, salt = recordId || writeStamp,   info = "tswap-record-meta-v3")
/// value key    = HKDF(K_v, salt = recordId || versionStamp, info = "tswap-record-value-v3")
/// AAD (metadata) = magic | 3 | recordId | 0x01 | writeStamp | valueSectionCount
/// AAD (value)    = magic | 3 | recordId | 0x02 | versionStamp
/// </code>
/// <para><b>Why a value section binds only its own stamp:</b> its associated data holds only fields
/// that never change for that section, so a later write (a burn, a merge, a reindex) can copy it byte
/// for byte under a new write stamp. Each section is AES-256-GCM with a fresh random nonce (ruling 1);
/// a value section is encrypted once, by the machine that creates or converts its version, and then
/// copied. Version stamps are not in the clear (ruling 2): the sections follow the metadata's version
/// list in order, and each one authenticates only under its own version's key and stamp, so a
/// section moved to another version, another record or the metadata slot fails its tag.</para>
/// <para><b>Why the length prefixes are not authenticated, and why decoding must still check
/// them:</b> a wrong slice fails its section's tag, so they need no AAD; but decoding must consume
/// the file exactly (every prefix checked against what remains, no trailing bytes) and require
/// <c>valueSectionCount</c> to equal the metadata's version count, or a file could carry a section
/// no version lists (or list a version without one). Do not "optimise" these checks away.</para>
/// </summary>
public static class SecretRecordCodec
{
    /// <summary>magic(4) + formatVersion(1) + recordId(32) + hlc(8+4) + origin(16) + payloadLength(4).</summary>
    public const int HeaderSize = 4 + 1 + KeyringFormat.RecordIdSize + 12 + KeyringFormat.OriginIdSize + 4;

    private const int StampSize = 12 + KeyringFormat.OriginIdSize;

    // recordType(1) + version stamp + createdMs(8) + nameLength(2)
    private const int InnerFixedSize = 1 + StampSize + 8 + 2;

    private const ushort NoReason = 0xFFFF;

    /// <summary>Encrypts and encodes <paramref name="record"/> in <see cref="KeyringFormat.RecordFormatVersion"/>.</summary>
    public static byte[] Encode(SecretRecord record, byte[] vaultKey) => Encode(record, vaultKey, KeyringFormat.RecordFormatVersion);

    /// <summary>
    /// Brief T16-S1: encodes <paramref name="record"/> in <paramref name="formatVersion"/>. Format 2
    /// is the single-payload layout (fingerprints, extensions and <see cref="SecretRecord.Sealed"/>
    /// are dropped); format 3 writes the metadata section and one value section per retained version,
    /// copying <see cref="SecretRecord.Sealed"/>'s section of a version byte for byte when present and
    /// encrypting the plaintext with a fresh random nonce otherwise.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <see cref="SecretRecord.Sealed"/> holds a stamp that is not a retained version, a fingerprint
    /// set has more than 255 entries, or the record is otherwise not encodable.
    /// </exception>
    public static byte[] Encode(SecretRecord record, byte[] vaultKey, byte formatVersion) => formatVersion switch
    {
        KeyringFormat.RecordFormatVersionV2 => EncodeV2(record, vaultKey),
        KeyringFormat.RecordFormatVersion => EncodeV3(record, vaultKey),
        _ => throw new ArgumentOutOfRangeException(nameof(formatVersion), $"This build writes record formats 2 and 3, not {formatVersion}."),
    };

    private static byte[] EncodeV2(SecretRecord record, byte[] vaultKey)
    {
        if (record.RecordId.Length != KeyringFormat.RecordIdSize)
            throw new ArgumentException($"RecordId must be {KeyringFormat.RecordIdSize} bytes", nameof(record));
        if (record.Burns.Count > RecordMerge.MaxBurns)
            throw new ArgumentException($"A record holds at most {RecordMerge.MaxBurns} burns", nameof(record));

        var name = Encoding.UTF8.GetBytes(record.Name);
        if (name.Length > ushort.MaxValue)
            throw new ArgumentException("Name too long for a record", nameof(record));
        var reasons = record.Burns.Select(b => b.Reason is null ? null : Encoding.UTF8.GetBytes(b.Reason)).ToList();
        if (reasons.Any(r => r is not null && r.Length >= NoReason))
            throw new TswapException("A burn reason is too long to store (64 KiB at most).");

        if (record.Previous is not null && record.Type == RecordType.Tombstone)
            throw new ArgumentException("A tombstone carries no previous value", nameof(record));
        var raw = InnerFixedSize + name.Length + 4 + record.Value.Length
            + 1 + (record.Previous is null ? 0 : StampSize + 4 + record.Previous.Value.Length) + 1
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
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), reason is null ? NoReason : (ushort)reason.Length);
            offset += 2;
            if (reason is not null)
            {
                reason.CopyTo(span.Slice(offset));
                offset += reason.Length;
            }
        }

        var header = new byte[HeaderSize];
        var h = header.AsSpan();
        KeyringFormat.RecordMagic.CopyTo(h);
        h[4] = KeyringFormat.RecordFormatVersionV2;
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
    /// malformed. Works for formats 2 and 3 (both start magic | version | recordId | write stamp).
    /// </summary>
    public static (byte[] RecordId, Stamp Write)? PeekHeader(byte[] bytes)
    {
        var headerSize = FormatVersionOf(bytes) switch
        {
            KeyringFormat.RecordFormatVersionV2 => HeaderSize,
            KeyringFormat.RecordFormatVersion => V3HeaderSize,
            _ => 0,
        };
        if (headerSize == 0 || bytes.Length < headerSize)
            return null;
        return (bytes.AsSpan(5, KeyringFormat.RecordIdSize).ToArray(), ReadStamp(bytes, 5 + KeyringFormat.RecordIdSize));
    }

    /// <summary>
    /// Brief T16-S1: the format byte of a record file (any value, read or not), or null when the
    /// bytes don't start with the record magic and a version byte.
    /// </summary>
    public static byte? FormatVersionOf(byte[] bytes) =>
        bytes.Length >= 5 && bytes.AsSpan(0, 4).SequenceEqual(KeyringFormat.RecordMagic) ? bytes[4] : null;

    /// <summary>
    /// Decodes and decrypts a record produced by <see cref="Encode(SecretRecord, byte[], byte)"/>,
    /// format 2 or 3 (format 3 fills <see cref="SecretRecord.Sealed"/> with the value sections as
    /// read). Every malformed input is a <see cref="TswapException"/> with its own message; a wrong
    /// key or tampered bytes are a <see cref="CryptographicException"/> from the AEAD (deliberately
    /// separate classes).
    /// </summary>
    public static SecretRecord Decode(byte[] bytes, byte[] vaultKey)
    {
        if (bytes.Length < HeaderSize)
            throw new TswapException("Malformed record: shorter than the envelope header");
        return CheckFormat(bytes) == KeyringFormat.RecordFormatVersionV2 ? DecodeV2(bytes, vaultKey) : DecodeV3(bytes, vaultKey);
    }

    /// <summary>Magic and a readable format version, or a <see cref="TswapException"/> naming what is wrong.</summary>
    private static byte CheckFormat(byte[] bytes)
    {
        if (bytes.Length < 5 || !bytes.AsSpan(0, 4).SequenceEqual(KeyringFormat.RecordMagic))
            throw new TswapException("Malformed record: bad magic bytes");
        var formatVersion = bytes[4];
        if (formatVersion is KeyringFormat.RecordFormatVersionV2 or KeyringFormat.RecordFormatVersion)
            return formatVersion;
        throw new TswapException(formatVersion < KeyringFormat.RecordFormatVersionV2
            ? $"Unsupported record format version {formatVersion}: written by a pre-release tswap build, which this " +
              $"build (record format versions {KeyringFormat.RecordFormatVersionV2} and {KeyringFormat.RecordFormatVersion}) " +
              "does not read. Re-create the vault folder from a classic vault or an export."
            : $"Unsupported record format version {formatVersion}: written by a newer tswap (this build reads versions " +
              $"{KeyringFormat.RecordFormatVersionV2} and {KeyringFormat.RecordFormatVersion}); upgrade tswap to open it.");
    }

    private static SecretRecord DecodeV2(byte[] bytes, byte[] vaultKey)
    {
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

    // ------------------------------------------------------------------ format 3 (brief T16-S1)

    /// <summary>Format 3 header: magic(4) + formatVersion(1) + recordId(32) + writeStamp(28) + valueSectionCount(1).</summary>
    public const int V3HeaderSize = 4 + 1 + KeyringFormat.RecordIdSize + StampSize + 1;

    private const byte MetadataRole = 0x01;
    private const byte ValueRole = 0x02;
    private const byte CurrentRole = 0;
    private const byte PreviousRole = 1;
    private const int FingerprintEntrySize = 1 + 4 + 8 + FingerprintEntry.HmacLength;
    private const int SectionOverhead = 12 + 16; // AES-GCM nonce + tag

    // recordType(1) + version stamp + createdMs(8) + nameLength(2)
    private const int MetadataFixedSize = 1 + StampSize + 8 + 2;

    /// <summary>One retained value version as format 3 lists it.</summary>
    private readonly record struct VersionEntry(Stamp Version, byte Role, FingerprintSet? Fingerprints);

    private static byte[] EncodeV3(SecretRecord record, byte[] vaultKey)
    {
        if (record.RecordId.Length != KeyringFormat.RecordIdSize)
            throw new ArgumentException($"RecordId must be {KeyringFormat.RecordIdSize} bytes", nameof(record));
        if (record.Burns.Count > RecordMerge.MaxBurns)
            throw new ArgumentException($"A record holds at most {RecordMerge.MaxBurns} burns", nameof(record));
        var isTombstone = record.Type == RecordType.Tombstone;
        if (isTombstone && record.Previous is not null)
            throw new ArgumentException("A tombstone carries no previous value", nameof(record));
        if (isTombstone && record.Fingerprints is not null)
            throw new ArgumentException("A tombstone carries no fingerprints", nameof(record));

        List<(VersionEntry Entry, byte[] Value)> versions = [];
        if (!isTombstone)
        {
            versions.Add((new VersionEntry(record.Version, CurrentRole, record.Fingerprints), record.Value));
            if (record.Previous is { } previous)
            {
                if (previous.Version.Equals(record.Version))
                    throw new ArgumentException("The previous value's version stamp equals the current one", nameof(record));
                versions.Add((new VersionEntry(previous.Version, PreviousRole, previous.Fingerprints), previous.Value));
            }
        }
        if (record.Sealed is { } sealedSections)
        {
            foreach (var (stamp, section) in sealedSections)
            {
                if (!versions.Any(v => v.Entry.Version.Equals(stamp)))
                    throw new ArgumentException($"Sealed holds a value section for {stamp}, which is not a retained version", nameof(record));
                if (section.Length < SectionOverhead)
                    throw new ArgumentException("A sealed value section is shorter than its nonce and tag", nameof(record));
            }
        }
        foreach (var (entry, _) in versions)
        {
            if (entry.Fingerprints is { Entries.Count: > byte.MaxValue })
                throw new ArgumentException($"A fingerprint set holds at most {byte.MaxValue} entries", nameof(record));
            if (entry.Fingerprints?.Entries.Any(e => e.Hmac.Length != FingerprintEntry.HmacLength || e.Length < 0) == true)
                throw new ArgumentException("A fingerprint entry is malformed", nameof(record));
        }
        if (record.Extensions.Count > ushort.MaxValue)
            throw new ArgumentException($"A record holds at most {ushort.MaxValue} extensions", nameof(record));

        var name = Encoding.UTF8.GetBytes(record.Name);
        if (name.Length > ushort.MaxValue)
            throw new ArgumentException("Name too long for a record", nameof(record));
        var reasons = record.Burns.Select(b => b.Reason is null ? null : Encoding.UTF8.GetBytes(b.Reason)).ToList();
        if (reasons.Any(r => r is not null && r.Length >= NoReason))
            throw new TswapException("A burn reason is too long to store (64 KiB at most).");

        long raw = MetadataFixedSize + name.Length + 1;
        foreach (var (entry, _) in versions)
            raw += StampSize + 1 + 1 + (entry.Fingerprints is null ? 0 : 2 + entry.Fingerprints.Entries.Count * FingerprintEntrySize);
        raw += 1 + record.Burns.Count * (2 * StampSize + 2) + reasons.Sum(r => r?.Length ?? 0);
        raw += 2 + record.Extensions.Sum(e => 2L + 4 + e.Data.Length);
        if (raw > int.MaxValue / 2)
            throw new ArgumentException("Record metadata too large", nameof(record));

        var metadata = new byte[BucketSize((int)raw)]; // zero-initialized: the padding tail is all zero bytes
        var span = metadata.AsSpan();
        var offset = 0;
        span[offset++] = (byte)record.Type;
        offset = WriteStamp(span, offset, record.Version);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(offset, 8), record.CreatedMs);
        offset += 8;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)name.Length);
        offset += 2;
        name.CopyTo(span.Slice(offset));
        offset += name.Length;
        span[offset++] = (byte)versions.Count;
        foreach (var (entry, _) in versions)
        {
            offset = WriteStamp(span, offset, entry.Version);
            span[offset++] = entry.Role;
            if (entry.Fingerprints is not { } set)
            {
                span[offset++] = 0;
                continue;
            }
            span[offset++] = 1;
            span[offset++] = set.VariantSetVersion;
            span[offset++] = (byte)set.Entries.Count;
            foreach (var fp in set.Entries)
            {
                span[offset++] = (byte)fp.Kind;
                BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)fp.Length);
                offset += 4;
                BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(offset, 8), fp.RollingHash);
                offset += 8;
                fp.Hmac.CopyTo(span.Slice(offset));
                offset += FingerprintEntry.HmacLength;
            }
        }
        offset = WriteBurns(span, offset, record.Burns, reasons);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)record.Extensions.Count);
        offset += 2;
        foreach (var extension in record.Extensions)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), extension.Type);
            offset += 2;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)extension.Data.Length);
            offset += 4;
            extension.Data.CopyTo(span.Slice(offset));
            offset += extension.Data.Length;
        }

        var count = (byte)versions.Count;
        var header = new byte[V3HeaderSize];
        KeyringFormat.RecordMagic.CopyTo(header, 0);
        header[4] = KeyringFormat.RecordFormatVersion;
        record.RecordId.CopyTo(header, 5);
        WriteStamp(header, 5 + KeyringFormat.RecordIdSize, record.Write);
        header[V3HeaderSize - 1] = count;

        byte[] metadataSection;
        var metadataKey = RecordKeyDerivation.DeriveMetadataKey(vaultKey, record.RecordId, record.Write);
        try
        {
            metadataSection = Crypto.Encrypt(metadata, metadataKey, MetadataAad(record.RecordId, record.Write, count));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(metadataKey);
            CryptographicOperations.ZeroMemory(metadata);
        }

        // Ruling 1: a retained version's section is copied when this record already carries it;
        // only a version without one (new, or converted from format 2) is encrypted here.
        var sections = versions
            .Select(v => record.Sealed is not null && record.Sealed.TryGetValue(v.Entry.Version, out var copied)
                ? copied
                : SealValue(record.RecordId, v.Entry.Version, v.Value, vaultKey))
            .ToList();

        var total = V3HeaderSize + 4 + metadataSection.Length + sections.Sum(x => 4 + x.Length);
        var bytes = new byte[total];
        header.CopyTo(bytes, 0);
        var at = V3HeaderSize;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at, 4), (uint)metadataSection.Length);
        at += 4;
        metadataSection.CopyTo(bytes, at);
        at += metadataSection.Length;
        foreach (var section in sections)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at, 4), (uint)section.Length);
            at += 4;
            section.CopyTo(bytes, at);
            at += section.Length;
        }
        return bytes;
    }

    /// <summary>
    /// Encrypts one value version as a format 3 value section (<c>nonce | tag | ciphertext</c>)
    /// under its own key, with a fresh random nonce and only its own stamp in the associated data.
    /// </summary>
    internal static byte[] SealValue(byte[] recordId, Stamp version, byte[] value, byte[] vaultKey)
    {
        var plain = new byte[BucketSize(4 + value.Length)];
        BinaryPrimitives.WriteUInt32LittleEndian(plain.AsSpan(0, 4), (uint)value.Length);
        value.CopyTo(plain, 4);
        var key = RecordKeyDerivation.DeriveValueKey(vaultKey, recordId, version);
        try
        {
            return Crypto.Encrypt(plain, key, ValueAad(recordId, version));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>
    /// Decrypts one format 3 value section of <paramref name="recordId"/>'s version
    /// <paramref name="version"/> and returns its value bytes (the caller zeroes them). A section of
    /// another version, another record or the metadata slot fails authentication.
    /// </summary>
    internal static byte[] OpenSealed(byte[] recordId, Stamp version, byte[] section, byte[] vaultKey)
    {
        if (section.Length < SectionOverhead)
            throw new TswapException("Malformed record: a value section is shorter than its nonce and tag");
        var key = RecordKeyDerivation.DeriveValueKey(vaultKey, recordId, version);
        byte[] plain;
        try
        {
            plain = Crypto.Decrypt(section, key, ValueAad(recordId, version));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        try
        {
            if (plain.Length < 4)
                throw new TswapException("Malformed record: a value section is too short for its length prefix");
            var length = BinaryPrimitives.ReadUInt32LittleEndian(plain.AsSpan(0, 4));
            if (length > plain.Length - 4)
                throw new TswapException("Malformed record: value length prefix exceeds its section");
            if (plain.AsSpan(4 + (int)length).ContainsAnyExcept((byte)0))
                throw new TswapException("Malformed record: non-zero bytes in a value section's padding");
            return plain.AsSpan(4, (int)length).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>
    /// Brief T16-S1: decrypts <b>only</b> the metadata section of a format 3 record and returns
    /// what it holds; the value sections are framed (lengths checked, the file consumed exactly) but
    /// never decrypted. A format 2 record gives null <b>without decrypting anything</b> (its version
    /// stamp is inside its single payload). Other formats and malformed files throw as
    /// <see cref="Decode"/> does.
    /// </summary>
    public static RecordMetadata? DecodeMetadata(byte[] bytes, byte[] vaultKey) =>
        DecodeMetadataAndSections(bytes, vaultKey)?.Metadata;

    /// <summary>
    /// <see cref="DecodeMetadata"/> plus the value sections as read, by version stamp (still
    /// encrypted): the store's metadata path compares them across conflicted copies without
    /// decrypting a value.
    /// </summary>
    internal static (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sealed)? DecodeMetadataAndSections(byte[] bytes, byte[] vaultKey)
    {
        if (bytes.Length < 5)
            throw new TswapException("Malformed record: shorter than the envelope header");
        if (CheckFormat(bytes) == KeyringFormat.RecordFormatVersionV2)
            return null;
        var (metadata, sections) = ReadV3Metadata(bytes, vaultKey);
        Dictionary<Stamp, byte[]> sealedSections = [];
        var i = 0;
        foreach (var (version, _, _) in metadata.RetainedVersions())
            sealedSections[version] = sections[i++];
        return (metadata, sealedSections);
    }

    /// <summary>
    /// Brief T16-S1: decrypts the metadata section (to learn the version order, ruling 2) and the
    /// one value section of <paramref name="version"/>; no other value section is decrypted.
    /// </summary>
    public static byte[] OpenValue(byte[] bytes, byte[] vaultKey, Stamp version)
    {
        var decoded = DecodeMetadataAndSections(bytes, vaultKey)
            ?? throw new TswapException("A format 2 record has no separate value sections; decode it whole.");
        if (!decoded.Sealed.TryGetValue(version, out var section))
            throw new TswapException($"The record holds no value version {version}.");
        return OpenSealed(decoded.Metadata.RecordId, version, section, vaultKey);
    }

    private static SecretRecord DecodeV3(byte[] bytes, byte[] vaultKey)
    {
        var (metadata, sections) = ReadV3Metadata(bytes, vaultKey);
        Dictionary<Stamp, byte[]> sealedSections = [];
        byte[] value = [];
        PreviousValue? previous = null;
        var i = 0;
        foreach (var (version, fingerprints, isPrevious) in metadata.RetainedVersions())
        {
            var section = sections[i++];
            var opened = OpenSealed(metadata.RecordId, version, section, vaultKey);
            sealedSections[version] = section;
            if (isPrevious)
                previous = new PreviousValue(version, opened, fingerprints);
            else
                value = opened;
        }
        return new SecretRecord(metadata.RecordId, metadata.Write, metadata.Type, metadata.Version, metadata.Name,
            metadata.CreatedMs, value, metadata.Burns, previous)
        {
            Fingerprints = metadata.Fingerprints,
            Extensions = metadata.Extensions,
            Sealed = sealedSections,
        };
    }

    /// <summary>
    /// Format 3 framing only, nothing decrypted: every length prefix checked against what remains and
    /// the file consumed exactly (a section no version could list is trailing bytes).
    /// </summary>
    private static (byte[] RecordId, Stamp Write, byte Count, byte[] MetadataSection, List<byte[]> Sections) FrameV3(byte[] bytes)
    {
        if (bytes.Length < V3HeaderSize + 4)
            throw new TswapException("Malformed record: shorter than the envelope header");
        var recordId = bytes.AsSpan(5, KeyringFormat.RecordIdSize).ToArray();
        var write = ReadStamp(bytes, 5 + KeyringFormat.RecordIdSize);
        var count = bytes[V3HeaderSize - 1];

        var offset = V3HeaderSize;
        var metadataLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        if (metadataLength > bytes.Length - offset)
            throw new TswapException("Malformed record: metadata length prefix exceeds available data");
        if (metadataLength < SectionOverhead)
            throw new TswapException("Malformed record: metadata section too short to contain a valid encrypted payload");
        var metadataSection = bytes.AsSpan(offset, (int)metadataLength).ToArray();
        offset += (int)metadataLength;
        List<byte[]> sections = [];
        for (var i = 0; i < count; i++)
        {
            if (4 > bytes.Length - offset)
                throw new TswapException("Malformed record: a value section is missing (the file ends before it)");
            var length = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
            offset += 4;
            if (length > bytes.Length - offset)
                throw new TswapException("Malformed record: value section length prefix exceeds available data");
            if (length < SectionOverhead)
                throw new TswapException("Malformed record: a value section is shorter than its nonce and tag");
            sections.Add(bytes.AsSpan(offset, (int)length).ToArray());
            offset += (int)length;
        }
        if (offset != bytes.Length)
            throw new TswapException("Malformed record: trailing bytes after the last value section (a section no version lists)");
        return (recordId, write, count, metadataSection, sections);
    }

    /// <summary>
    /// The value sections of a format 3 file this process just encoded from <paramref name="written"/>,
    /// by version stamp, read from the framing alone (nothing is decrypted): the store keeps them so a
    /// second write in the same command copies them instead of encrypting again.
    /// </summary>
    internal static IReadOnlyDictionary<Stamp, byte[]> SectionsOf(byte[] bytes, SecretRecord written)
    {
        var sections = FrameV3(bytes).Sections;
        Dictionary<Stamp, byte[]> byVersion = [];
        if (written.Type != RecordType.Tombstone)
        {
            byVersion[written.Version] = sections[0];
            if (written.Previous is { } previous)
                byVersion[previous.Version] = sections[1];
        }
        return byVersion;
    }

    /// <summary>
    /// Frames a format 3 file (<see cref="FrameV3"/>), decrypts and parses its metadata section, and
    /// checks the framing against it:
    /// <c>valueSectionCount</c> must equal the metadata's version count. Returns the metadata and
    /// the still-encrypted value sections in version order.
    /// </summary>
    private static (RecordMetadata Metadata, List<byte[]> Sections) ReadV3Metadata(byte[] bytes, byte[] vaultKey)
    {
        var (recordId, write, count, metadataSection, sections) = FrameV3(bytes);

        var key = RecordKeyDerivation.DeriveMetadataKey(vaultKey, recordId, write);
        byte[] plain;
        try
        {
            plain = Crypto.Decrypt(metadataSection, key, MetadataAad(recordId, write, count));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        try
        {
            var metadata = ParseMetadata(plain, recordId, write, vaultKey);
            var listed = metadata.RetainedVersions().Count();
            if (listed != count)
                throw new TswapException(
                    $"Malformed record: the metadata lists {listed} value version(s) but the file carries {count} value section(s)");
            return (metadata, sections);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static RecordMetadata ParseMetadata(byte[] plain, byte[] recordId, Stamp write, byte[] vaultKey)
    {
        if (plain.Length < MetadataFixedSize)
            throw new TswapException("Malformed record: decrypted metadata shorter than its fixed fields");
        var offset = 0;
        var typeByte = plain[offset++];
        if (typeByte > (byte)RecordType.Burned)
            throw new TswapException($"Malformed record: unknown record type {typeByte}");
        var type = (RecordType)typeByte;
        var version = ReadStamp(plain, offset);
        offset += StampSize;
        var createdMs = BinaryPrimitives.ReadInt64LittleEndian(plain.AsSpan(offset, 8));
        offset += 8;
        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(plain.AsSpan(offset, 2));
        offset += 2;
        Need(plain, offset, nameLength + 1, "name");
        var name = DecodeUtf8(plain.AsSpan(offset, nameLength), "name");
        offset += nameLength;

        var versionCount = plain[offset++];
        if (versionCount > 2)
            throw new TswapException($"Malformed record: {versionCount} value versions (at most 2)");
        if (type == RecordType.Tombstone && versionCount != 0)
            throw new TswapException("Malformed record: a tombstone lists value versions");
        if (type != RecordType.Tombstone && versionCount == 0)
            throw new TswapException("Malformed record: a value record lists no value version");
        List<VersionEntry> versions = [];
        for (var i = 0; i < versionCount; i++)
        {
            Need(plain, offset, StampSize + 2, "version list");
            var stamp = ReadStamp(plain, offset);
            offset += StampSize;
            var role = plain[offset++];
            if (role != (i == 0 ? CurrentRole : PreviousRole))
                throw new TswapException($"Malformed record: unexpected version role {role} at position {i}");
            if (versions.Any(v => v.Version.Equals(stamp)))
                throw new TswapException("Malformed record: a version stamp is listed twice");
            if (i == 0 && !stamp.Equals(version))
                throw new TswapException("Malformed record: the current value's stamp differs from the record's version");
            var hasFingerprints = plain[offset++];
            if (hasFingerprints > 1)
                throw new TswapException("Malformed record: bad fingerprint flag");
            FingerprintSet? set = null;
            if (hasFingerprints == 1)
            {
                Need(plain, offset, 2, "fingerprint set");
                var setVersion = plain[offset++];
                var entryCount = plain[offset++];
                Need(plain, offset, entryCount * FingerprintEntrySize, "fingerprint set");
                var entries = new FingerprintEntry[entryCount];
                for (var e = 0; e < entryCount; e++)
                {
                    var kind = (VariantKind)plain[offset++];
                    // Strict for the variant sets this build defines; a newer set version may define
                    // kinds this build doesn't know, and its records must stay readable (fix round 1).
                    if (setVersion <= SecretVariants.CurrentSetVersion && !Enum.IsDefined(kind))
                        throw new TswapException($"Malformed record: unknown variant kind {(byte)kind} in a fingerprint set of version {setVersion}");
                    var length = BinaryPrimitives.ReadUInt32LittleEndian(plain.AsSpan(offset, 4));
                    offset += 4;
                    if (length > int.MaxValue)
                        throw new TswapException("Malformed record: a fingerprint length is out of range");
                    var rolling = BinaryPrimitives.ReadUInt64LittleEndian(plain.AsSpan(offset, 8));
                    offset += 8;
                    var hmac = plain.AsSpan(offset, FingerprintEntry.HmacLength).ToArray();
                    offset += FingerprintEntry.HmacLength;
                    entries[e] = new FingerprintEntry(kind, (int)length, rolling, hmac);
                }
                set = new FingerprintSet(setVersion, entries);
            }
            versions.Add(new VersionEntry(stamp, role, set));
        }

        Need(plain, offset, 1, "burns");
        var (burns, afterBurns) = ReadBurns(plain, offset);
        offset = afterBurns;

        Need(plain, offset, 2, "extensions");
        var extensionCount = BinaryPrimitives.ReadUInt16LittleEndian(plain.AsSpan(offset, 2));
        offset += 2;
        var extensions = new List<RecordExtension>(extensionCount);
        for (var i = 0; i < extensionCount; i++)
        {
            Need(plain, offset, 6, "extension");
            var extensionType = BinaryPrimitives.ReadUInt16LittleEndian(plain.AsSpan(offset, 2));
            offset += 2;
            var length = BinaryPrimitives.ReadUInt32LittleEndian(plain.AsSpan(offset, 4));
            offset += 4;
            if (length > plain.Length - offset)
                throw new TswapException("Malformed record: extension length prefix exceeds the metadata");
            extensions.Add(new RecordExtension(extensionType, plain.AsSpan(offset, (int)length).ToArray()));
            offset += (int)length;
        }
        if (plain.AsSpan(offset).ContainsAnyExcept((byte)0))
            throw new TswapException("Malformed record: non-zero bytes in the metadata padding");

        CheckRecordId(recordId, name, vaultKey);
        var current = versions.Count > 0 ? versions[0] : (VersionEntry?)null;
        var previous = versions.Count > 1 ? versions[1] : (VersionEntry?)null;
        return new RecordMetadata(recordId, write, type, version, name, createdMs, burns,
            current?.Fingerprints, previous?.Version, previous?.Fingerprints, extensions);
    }

    private static void CheckRecordId(byte[] recordId, string name, byte[] vaultKey)
    {
        var namesKey = RecordKeyDerivation.DeriveNamesKey(vaultKey);
        var expectedId = FilenameHasher.ComputeRecordId(namesKey, name);
        CryptographicOperations.ZeroMemory(namesKey);
        if (!CryptographicOperations.FixedTimeEquals(expectedId, recordId))
            throw new TswapException("Malformed record: its record id does not belong to the name inside it");
    }

    private static byte[] MetadataAad(byte[] recordId, Stamp write, byte valueSectionCount)
    {
        var aad = new byte[4 + 1 + KeyringFormat.RecordIdSize + 1 + StampSize + 1];
        KeyringFormat.RecordMagic.CopyTo(aad, 0);
        aad[4] = KeyringFormat.RecordFormatVersion;
        recordId.CopyTo(aad, 5);
        aad[5 + KeyringFormat.RecordIdSize] = MetadataRole;
        WriteStamp(aad, 6 + KeyringFormat.RecordIdSize, write);
        aad[^1] = valueSectionCount;
        return aad;
    }

    private static byte[] ValueAad(byte[] recordId, Stamp version)
    {
        var aad = new byte[4 + 1 + KeyringFormat.RecordIdSize + 1 + StampSize];
        KeyringFormat.RecordMagic.CopyTo(aad, 0);
        aad[4] = KeyringFormat.RecordFormatVersion;
        recordId.CopyTo(aad, 5);
        aad[5 + KeyringFormat.RecordIdSize] = ValueRole;
        WriteStamp(aad, 6 + KeyringFormat.RecordIdSize, version);
        return aad;
    }

    /// <summary>The burn list as formats 2 and 3 store it: count, then per burn version, burn, reason.</summary>
    private static int WriteBurns(Span<byte> span, int offset, IReadOnlyList<BurnEntry> burns, List<byte[]?> reasons)
    {
        span[offset++] = (byte)burns.Count;
        for (var i = 0; i < burns.Count; i++)
        {
            offset = WriteStamp(span, offset, burns[i].Version);
            offset = WriteStamp(span, offset, burns[i].Burn);
            var reason = reasons[i];
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), reason is null ? NoReason : (ushort)reason.Length);
            offset += 2;
            if (reason is not null)
            {
                reason.CopyTo(span.Slice(offset));
                offset += reason.Length;
            }
        }
        return offset;
    }

    private static (List<BurnEntry> Burns, int Offset) ReadBurns(byte[] inner, int offset)
    {
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
        return (burns, offset);
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
