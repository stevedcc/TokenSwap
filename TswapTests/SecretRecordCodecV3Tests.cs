using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 4: record format 3 (split envelopes). The hand-built files below are written
/// from the brief's pinned layout by test code (<see cref="Layout"/>), not by the codec, so they pin
/// the byte layout, the key labels and the associated data independently of the implementation.
/// </summary>
public class SecretRecordCodecV3Tests
{
    private static readonly byte[] VaultKey = Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] OriginA = Enumerable.Repeat((byte)0xAA, 16).ToArray();
    private static readonly byte[] OriginB = Enumerable.Repeat((byte)0xBB, 16).ToArray();
    private static readonly byte[] OriginC = Enumerable.Repeat((byte)0xCC, 16).ToArray();

    private static readonly Stamp Write = new(new Hlc(1_700_000_000_500, 2), OriginA);
    private static readonly Stamp Version = new(new Hlc(1_700_000_000_000, 0), OriginA);
    private static readonly Stamp PreviousStamp = new(new Hlc(1_690_000_000_000, 3), OriginC);
    private const long CreatedMs = 1_699_000_000_000;

    private static byte[] IdOf(string name) => FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(VaultKey), name);

    private static FingerprintSet Fp(string value)
    {
        using var keys = FingerprintKeys.Derive(VaultKey);
        return Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys);
    }

    private static SecretRecord ValueRecord(string name = "db-pass", byte[]? value = null, bool withPrevious = false) =>
        new(IdOf(name), Write, RecordType.Value, Version, name, CreatedMs, value ?? "hello"u8.ToArray(), [],
            withPrevious ? new PreviousValue(PreviousStamp, "old-pw"u8.ToArray(), Fp("old-pw")) : null)
        {
            Fingerprints = value is null ? Fp("hello") : null,
        };

    private static SecretRecord BurnedRecord(bool withPrevious) =>
        ValueRecord(withPrevious: withPrevious) with
        {
            Type = RecordType.Burned,
            Burns = [new BurnEntry(Version, new Stamp(new Hlc(1_700_000_000_400, 1), OriginB), "leaked")],
        };

    private static SecretRecord TombstoneRecord() =>
        new(IdOf("db-pass"), Write, RecordType.Tombstone, new Stamp(new Hlc(1_700_000_000_300, 0), OriginA), "db-pass", CreatedMs, [],
            [new BurnEntry(Version, new Stamp(new Hlc(1_700_000_000_100, 0), OriginB), null)]);

    private static byte[] Encode(SecretRecord record) => SecretRecordCodec.Encode(record, VaultKey, 3);

    // ------------------------------------------------------------------ the layout, written by hand

    /// <summary>The brief's v3 layout, built by test code (independent of the codec).</summary>
    private static class Layout
    {
        public static byte[] Stamp(Stamp s)
        {
            var b = new byte[28];
            BinaryPrimitives.WriteInt64LittleEndian(b, s.Hlc.PhysicalMs);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), s.Hlc.Logical);
            s.Origin.CopyTo(b, 12);
            return b;
        }

        public static byte[] Pad(List<byte> raw, int extraPadding = 0)
        {
            var size = Math.Max(256, (raw.Count + 255) / 256 * 256);
            var padded = new byte[size];
            raw.CopyTo(padded);
            if (extraPadding != 0)
                padded[^1] = (byte)extraPadding;
            return padded;
        }

        public static byte[] MetadataPlain(
            RecordType type, Stamp version, string name, IEnumerable<(Stamp Stamp, byte Role, FingerprintSet? Set)> versions,
            IEnumerable<BurnEntry>? burns = null, IEnumerable<RecordExtension>? extensions = null, int nonZeroPadding = 0)
        {
            List<byte> raw = [(byte)type, .. Stamp(version)];
            var created = new byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(created, CreatedMs);
            raw.AddRange(created);
            var nameBytes = Encoding.UTF8.GetBytes(name);
            raw.AddRange(BitConverter.GetBytes((ushort)nameBytes.Length));
            raw.AddRange(nameBytes);
            var list = versions.ToList();
            raw.Add((byte)list.Count);
            foreach (var (stamp, role, set) in list)
            {
                raw.AddRange(Stamp(stamp));
                raw.Add(role);
                if (set is null)
                {
                    raw.Add(0);
                    continue;
                }
                raw.Add(1);
                raw.Add(set.VariantSetVersion);
                raw.Add((byte)set.Entries.Count);
                foreach (var e in set.Entries)
                {
                    raw.Add((byte)e.Kind);
                    raw.AddRange(BitConverter.GetBytes((uint)e.Length));
                    raw.AddRange(BitConverter.GetBytes(e.RollingHash));
                    raw.AddRange(e.Hmac);
                }
            }
            var burnList = (burns ?? []).ToList();
            raw.Add((byte)burnList.Count);
            foreach (var burn in burnList)
            {
                raw.AddRange(Stamp(burn.Version));
                raw.AddRange(Stamp(burn.Burn));
                if (burn.Reason is null)
                {
                    raw.AddRange(BitConverter.GetBytes((ushort)0xFFFF));
                }
                else
                {
                    var reason = Encoding.UTF8.GetBytes(burn.Reason);
                    raw.AddRange(BitConverter.GetBytes((ushort)reason.Length));
                    raw.AddRange(reason);
                }
            }
            var extensionList = (extensions ?? []).ToList();
            raw.AddRange(BitConverter.GetBytes((ushort)extensionList.Count));
            foreach (var extension in extensionList)
            {
                raw.AddRange(BitConverter.GetBytes(extension.Type));
                raw.AddRange(BitConverter.GetBytes((uint)extension.Data.Length));
                raw.AddRange(extension.Data);
            }
            return Pad(raw, nonZeroPadding);
        }

        public static byte[] ValuePlain(byte[] value, int nonZeroPadding = 0) =>
            Pad([.. BitConverter.GetBytes((uint)value.Length), .. value], nonZeroPadding);

        public static byte[] MetadataAad(byte[] recordId, Stamp write, byte count) =>
            [.. "TSR1"u8, 3, .. recordId, 0x01, .. Stamp(write), count];

        public static byte[] ValueAad(byte[] recordId, Stamp version) =>
            [.. "TSR1"u8, 3, .. recordId, 0x02, .. Stamp(version)];

        public static byte[] MetadataSection(byte[] recordId, Stamp write, byte count, byte[] plain)
        {
            var key = Hkdf(recordId, write, "tswap-record-meta-v3");
            return Crypto.Encrypt(plain, key, MetadataAad(recordId, write, count));
        }

        public static byte[] ValueSection(byte[] recordId, Stamp version, byte[] plain)
        {
            var key = Hkdf(recordId, version, "tswap-record-value-v3");
            return Crypto.Encrypt(plain, key, ValueAad(recordId, version));
        }

        /// <summary>HKDF with the brief's salt and labels, spelled out here rather than calling RecordKeyDerivation.</summary>
        private static byte[] Hkdf(byte[] recordId, Stamp stamp, string label) =>
            HKDF.DeriveKey(HashAlgorithmName.SHA256, VaultKey, 32, salt: [.. recordId, .. Stamp(stamp)], info: Encoding.UTF8.GetBytes(label));

        public static byte[] File(byte[] recordId, Stamp write, byte count, byte[] metadataSection, params byte[][] sections)
        {
            List<byte> file = [.. "TSR1"u8, 3, .. recordId, .. Stamp(write), count];
            file.AddRange(BitConverter.GetBytes((uint)metadataSection.Length));
            file.AddRange(metadataSection);
            foreach (var section in sections)
            {
                file.AddRange(BitConverter.GetBytes((uint)section.Length));
                file.AddRange(section);
            }
            return [.. file];
        }
    }

    /// <summary>Offsets of a v3 file's sections: (start of section bytes, length), metadata first.</summary>
    private static List<(int Start, int Length)> Sections(byte[] file)
    {
        List<(int, int)> result = [];
        var offset = SecretRecordCodec.V3HeaderSize;
        while (offset < file.Length)
        {
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(offset, 4));
            result.Add((offset + 4, length));
            offset += 4 + length;
        }
        return result;
    }

    /// <summary>A file with the section list replaced (header, metadata and count kept).</summary>
    private static byte[] WithSections(byte[] file, params byte[][] sections)
    {
        var meta = Sections(file)[0];
        List<byte> rebuilt = [.. file.AsSpan(0, meta.Start + meta.Length)];
        foreach (var section in sections)
        {
            rebuilt.AddRange(BitConverter.GetBytes((uint)section.Length));
            rebuilt.AddRange(section);
        }
        return [.. rebuilt];
    }

    private static byte[] SectionBytes(byte[] file, int index)
    {
        var (start, length) = Sections(file)[index];
        return file.AsSpan(start, length).ToArray();
    }

    // ------------------------------------------------------------------ tests

    [Fact]
    public void TheRecordFormatVersion_IsPinnedAt3_AndV2At2()
    {
        Assert.Equal(3, KeyringFormat.RecordFormatVersion);
        Assert.Equal(2, KeyringFormat.RecordFormatVersionV2);
        Assert.Equal(3, SecretRecordCodec.Encode(ValueRecord(), VaultKey)[4]);
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Encode(ValueRecord())));
        Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(SecretRecordCodec.Encode(ValueRecord(), VaultKey, 2)));
        Assert.Null(SecretRecordCodec.FormatVersionOf([1, 2, 3]));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecretRecordCodec.Encode(ValueRecord(), VaultKey, 4));
    }

    [Fact]
    public void HandBuiltLayout_DecodesToTheExpectedRecord()
    {
        var record = BurnedRecord(withPrevious: true) with { Extensions = [new RecordExtension(0x7777, [1, 2, 3])] };
        var id = record.RecordId;
        var metadata = Layout.MetadataPlain(RecordType.Burned, Version, "db-pass",
            [(Version, 0, record.Fingerprints), (PreviousStamp, 1, record.Previous!.Fingerprints)], record.Burns, record.Extensions);
        var file = Layout.File(id, Write, 2, Layout.MetadataSection(id, Write, 2, metadata),
            Layout.ValueSection(id, Version, Layout.ValuePlain("hello"u8.ToArray())),
            Layout.ValueSection(id, PreviousStamp, Layout.ValuePlain("old-pw"u8.ToArray())));

        var decoded = SecretRecordCodec.Decode(file, VaultKey);

        Assert.True(record.SameState(decoded));
        Assert.Equal(Write, decoded.Write);
        // And the codec's own output has the same framing and decodes the same way.
        var encoded = Encode(record);
        Assert.Equal(file.AsSpan(0, SecretRecordCodec.V3HeaderSize).ToArray(), encoded.AsSpan(0, SecretRecordCodec.V3HeaderSize).ToArray());
        Assert.Equal(Sections(file).Select(s => s.Length), Sections(encoded).Select(s => s.Length));
        Assert.True(record.SameState(SecretRecordCodec.Decode(encoded, VaultKey)));
    }

    [Theory]
    [InlineData(RecordType.Value, false)]
    [InlineData(RecordType.Value, true)]
    [InlineData(RecordType.Burned, false)]
    [InlineData(RecordType.Burned, true)]
    [InlineData(RecordType.Tombstone, false)]
    public void RoundTrip_ValueBurnedTombstone_WithAndWithoutPrevious(RecordType type, bool withPrevious)
    {
        var record = (type switch
        {
            RecordType.Value => ValueRecord(withPrevious: withPrevious),
            RecordType.Burned => BurnedRecord(withPrevious),
            _ => TombstoneRecord(),
        }) with { Extensions = [new RecordExtension(0x0102, [9, 8, 7]), new RecordExtension(0xFFFF, [])] };

        var encoded = Encode(record);
        var decoded = SecretRecordCodec.Decode(encoded, VaultKey);
        var metadata = SecretRecordCodec.DecodeMetadata(encoded, VaultKey)!;

        Assert.True(record.SameState(decoded));
        Assert.Equal(record.Write, decoded.Write);
        Assert.Equal(type, decoded.Type);
        Assert.Equal(record.Fingerprints, decoded.Fingerprints);
        Assert.Equal(record.Previous?.Fingerprints, decoded.Previous?.Fingerprints);
        Assert.Equal(record.Extensions, decoded.Extensions);
        Assert.Equal(type == RecordType.Tombstone ? 0 : withPrevious ? 2 : 1, decoded.Sealed!.Count);
        Assert.Equal(decoded.Sealed.Count, encoded[SecretRecordCodec.V3HeaderSize - 1]);

        Assert.Equal(record.Name, metadata.Name);
        Assert.Equal(record.Type, metadata.Type);
        Assert.Equal(record.Version, metadata.Version);
        Assert.Equal(record.Write, metadata.Write);
        Assert.Equal(record.CreatedMs, metadata.CreatedMs);
        Assert.Equal(record.Burns, metadata.Burns);
        Assert.Equal(record.Fingerprints, metadata.Fingerprints);
        Assert.Equal(record.Previous?.Version, metadata.PreviousVersion);
        Assert.Equal(record.Previous?.Fingerprints, metadata.PreviousFingerprints);
        Assert.Equal(record.Extensions, metadata.Extensions);
    }

    [Fact]
    public void RoundTrip_VersionWithoutFingerprints_KeepsThemNull()
    {
        var record = ValueRecord(withPrevious: true) with { Fingerprints = null };
        record = record with { Previous = record.Previous! with { Fingerprints = null } };

        var decoded = SecretRecordCodec.Decode(Encode(record), VaultKey);

        Assert.Null(decoded.Fingerprints);
        Assert.Null(decoded.Previous!.Fingerprints);
        Assert.True(record.SameState(decoded));
    }

    [Fact]
    public void DecodeMetadata_DecryptsNoValueSection()
    {
        var encoded = Encode(ValueRecord(withPrevious: true));
        var corrupted = (byte[])encoded.Clone();
        foreach (var (start, length) in Sections(encoded).Skip(1))
            corrupted[start + length - 1] ^= 0x01; // inside each value section's ciphertext

        var metadata = SecretRecordCodec.DecodeMetadata(corrupted, VaultKey);

        Assert.NotNull(metadata);
        Assert.Equal("db-pass", metadata.Name);
        Assert.Equal(PreviousStamp, metadata.PreviousVersion);
        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(corrupted, VaultKey));
    }

    [Fact]
    public void DecodeMetadata_V2Record_ReturnsNullWithoutDecrypting()
    {
        var v2 = SecretRecordCodec.Encode(ValueRecord(), VaultKey, 2);
        v2[^1] ^= 0xFF; // the single payload now fails its tag: decrypting would throw

        Assert.Null(SecretRecordCodec.DecodeMetadata(v2, VaultKey));
        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(v2, VaultKey));
    }

    [Fact]
    public void OpenValue_DecryptsOneVersion()
    {
        var encoded = Encode(ValueRecord(withPrevious: true));
        var corrupted = (byte[])encoded.Clone();
        var (start, length) = Sections(encoded)[1]; // the current value's section
        corrupted[start + length - 1] ^= 0x01;

        Assert.Equal("old-pw"u8.ToArray(), SecretRecordCodec.OpenValue(corrupted, VaultKey, PreviousStamp));
        Assert.Equal("hello"u8.ToArray(), SecretRecordCodec.OpenValue(encoded, VaultKey, Version));
        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.OpenValue(corrupted, VaultKey, Version));
        Assert.Throws<TswapException>(() => SecretRecordCodec.OpenValue(encoded, VaultKey, Write));
    }

    [Fact]
    public void ValueSection_CopiedBytes_AuthenticateUnderANewWriteStamp()
    {
        var first = SecretRecordCodec.Decode(Encode(ValueRecord(withPrevious: true)), VaultKey);
        var later = first with { Write = new Stamp(new Hlc(1_800_000_000_000, 0), OriginB), Type = RecordType.Burned,
            Burns = [new BurnEntry(Version, new Stamp(new Hlc(1_800_000_000_000, 0), OriginB), "r")] };

        var rewritten = Encode(later);

        Assert.Equal(SectionBytes(Encode(first), 1).Length, SectionBytes(rewritten, 1).Length);
        Assert.Equal(first.Sealed![Version], SectionBytes(rewritten, 1));
        Assert.Equal(first.Sealed[PreviousStamp], SectionBytes(rewritten, 2));
        var decoded = SecretRecordCodec.Decode(rewritten, VaultKey);
        Assert.True(later.SameState(decoded));
        Assert.Equal(later.Write, decoded.Write);
    }

    [Fact]
    public void ValueSection_FreshEncodes_UseDifferentNonces()
    {
        var a = Encode(ValueRecord());
        var b = Encode(ValueRecord());

        Assert.NotEqual(SectionBytes(a, 1), SectionBytes(b, 1));
        Assert.NotEqual(SectionBytes(a, 1)[..12], SectionBytes(b, 1)[..12]);
        Assert.Equal("hello"u8.ToArray(), SecretRecordCodec.Decode(a, VaultKey).Value);
        Assert.Equal("hello"u8.ToArray(), SecretRecordCodec.Decode(b, VaultKey).Value);
    }

    [Fact]
    public void ValueSection_SwappedBetweenVersions_FailsAuthentication()
    {
        var encoded = Encode(ValueRecord(withPrevious: true));

        var swapped = WithSections(encoded, SectionBytes(encoded, 2), SectionBytes(encoded, 1));

        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(swapped, VaultKey));
    }

    [Fact]
    public void ValueSection_FromAnotherRecord_FailsAuthentication()
    {
        var mine = Encode(ValueRecord());
        // Another record with the same version stamp: only the record id in key and AAD differs.
        var theirs = Encode(ValueRecord("other"));

        var spliced = WithSections(mine, SectionBytes(theirs, 1));

        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(spliced, VaultKey));
    }

    [Fact]
    public void MetadataListsVersionWithoutSection_FailsClosed()
    {
        var id = IdOf("db-pass");
        var plain = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", [(Version, 0, null), (PreviousStamp, 1, null)]);
        var current = Layout.ValueSection(id, Version, Layout.ValuePlain("hello"u8.ToArray()));

        // The header says two sections (as the metadata does), the file carries one.
        var missing = Layout.File(id, Write, 2, Layout.MetadataSection(id, Write, 2, plain), current);
        // The header says one section (authenticated as such), the metadata lists two versions.
        var miscounted = Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, plain), current);

        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(missing, VaultKey));
        Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(missing, VaultKey));
        Assert.Contains("lists 2", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(miscounted, VaultKey)).Message);
        Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(miscounted, VaultKey));
    }

    [Fact]
    public void SectionWithoutVersion_FailsClosed()
    {
        var id = IdOf("db-pass");
        var plain = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", [(Version, 0, null)]);
        var current = Layout.ValueSection(id, Version, Layout.ValuePlain("hello"u8.ToArray()));
        var extra = Layout.ValueSection(id, PreviousStamp, Layout.ValuePlain("old"u8.ToArray()));

        // One section listed and counted, two carried: trailing bytes.
        var trailing = Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, plain), current, extra);
        // Two sections counted (and authenticated so), one version listed.
        var miscounted = Layout.File(id, Write, 2, Layout.MetadataSection(id, Write, 2, plain), current, extra);
        // Control: the well-formed file decodes.
        Assert.Equal("hello"u8.ToArray(), SecretRecordCodec.Decode(Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, plain), current), VaultKey).Value);

        Assert.Contains("trailing", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(trailing, VaultKey)).Message);
        Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(trailing, VaultKey));
        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(miscounted, VaultKey));
        Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(miscounted, VaultKey));
    }

    [Fact]
    public void Tombstone_ListingAVersion_OrValueListingNone_FailsClosed()
    {
        var id = IdOf("db-pass");
        var tombstoneWithVersion = Layout.MetadataPlain(RecordType.Tombstone, Version, "db-pass", [(Version, 0, null)]);
        var valueWithout = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", []);
        var section = Layout.ValueSection(id, Version, Layout.ValuePlain("x"u8.ToArray()));

        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(
            Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, tombstoneWithVersion), section), VaultKey));
        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(
            Layout.File(id, Write, 0, Layout.MetadataSection(id, Write, 0, valueWithout)), VaultKey));
    }

    [Fact]
    public void UnknownExtension_SurvivesDecodeEncode()
    {
        var data = RandomNumberGenerator.GetBytes(300);
        var record = ValueRecord() with { Extensions = [new RecordExtension(0x7777, data)] };

        var once = SecretRecordCodec.Decode(Encode(record), VaultKey);
        var twice = SecretRecordCodec.Decode(Encode(once with { Write = new Stamp(new Hlc(1_800_000_000_000, 0), OriginB) }), VaultKey);

        var extension = Assert.Single(twice.Extensions);
        Assert.Equal(0x7777, extension.Type);
        Assert.Equal(data, extension.Data);
    }

    [Fact]
    public void V2Records_StillDecode_AndEncodeAsV2WhenAsked()
    {
        // The v2 golden inner payload of SecretRecordCodecTests (computed independently in Python),
        // sealed under the v2 per-record key: a format 2 file this build did not write.
        const string goldenInnerHex = "000068e5cf8b01000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa009e4a948b010000070064622d706173730500000068656c6c6f0000";
        var inner = new byte[256];
        Convert.FromHexString(goldenInnerHex).CopyTo(inner, 0);
        var id = IdOf("db-pass");
        byte[] header = [.. "TSR1"u8, 2, .. id, .. Layout.Stamp(Write), .. BitConverter.GetBytes((uint)(12 + 16 + 256))];
        var v2 = (byte[])[.. header, .. Crypto.Encrypt(inner, RecordKeyDerivation.Derive(VaultKey, id, Write), header)];

        var decoded = SecretRecordCodec.Decode(v2, VaultKey);

        Assert.Equal("db-pass", decoded.Name);
        Assert.Equal("hello"u8.ToArray(), decoded.Value);
        Assert.Null(decoded.Fingerprints);
        Assert.Null(decoded.Sealed);
        Assert.Empty(decoded.Extensions);
        Assert.Equal((id, Write), SecretRecordCodec.PeekHeader(v2)!.Value, new PeekComparer());

        var reencoded = SecretRecordCodec.Encode(decoded with { Fingerprints = Fp("hello"), Extensions = [new RecordExtension(1, [1])] }, VaultKey, 2);
        Assert.Equal(2, reencoded[4]);
        Assert.Equal(v2.Length, reencoded.Length);
        var again = SecretRecordCodec.Decode(reencoded, VaultKey);
        Assert.True(decoded.SameState(again));
        Assert.Null(again.Fingerprints); // dropped by format 2
        Assert.Empty(again.Extensions);
    }

    [Fact]
    public void PeekHeader_ReadsV3()
    {
        var encoded = Encode(ValueRecord());

        var peek = SecretRecordCodec.PeekHeader(encoded);

        Assert.Equal((IdOf("db-pass"), Write), peek!.Value, new PeekComparer());
        Assert.Null(SecretRecordCodec.PeekHeader(encoded[..10]));
    }

    private sealed class PeekComparer : IEqualityComparer<(byte[] RecordId, Stamp Write)>
    {
        public bool Equals((byte[] RecordId, Stamp Write) x, (byte[] RecordId, Stamp Write) y) =>
            x.RecordId.AsSpan().SequenceEqual(y.RecordId) && x.Write.Equals(y.Write);

        public int GetHashCode((byte[] RecordId, Stamp Write) obj) => obj.Write.GetHashCode();
    }

    [Fact]
    public void NewerFormatVersion_IsRefusedWithUpgradeMessage()
    {
        var encoded = Encode(ValueRecord());
        encoded[4] = 4;

        var decode = Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey));
        var metadata = Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(encoded, VaultKey));

        foreach (var message in new[] { decode.Message, metadata.Message })
        {
            Assert.Contains("format version 4", message);
            Assert.Contains("newer tswap", message);
            Assert.Contains("upgrade", message);
        }
    }

    [Theory]
    [InlineData(1, 256)]
    [InlineData(300, 512)]
    [InlineData(4200, 4352)]
    public void PadsEachSectionTo256(int valueLength, int expectedCiphertext)
    {
        var encoded = Encode(ValueRecord(value: RandomNumberGenerator.GetBytes(valueLength)));
        var sections = Sections(encoded);

        Assert.Equal(2, sections.Count);
        Assert.Equal(0, (sections[0].Length - 28) % 256);
        Assert.Equal(256, sections[0].Length - 28);
        Assert.Equal(expectedCiphertext, sections[1].Length - 28);
    }

    [Fact]
    public void TruncatedFile_FailsClosed()
    {
        var encoded = Encode(ValueRecord(withPrevious: true));

        foreach (var cut in new[] { 1, 28, 300, encoded.Length - SecretRecordCodec.V3HeaderSize - 1 })
        {
            Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded[..^cut], VaultKey));
            Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(encoded[..^cut], VaultKey));
        }
    }

    [Fact]
    public void AppendedBytes_FailClosed()
    {
        var encoded = Encode(ValueRecord());

        Assert.Contains("trailing", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode([.. encoded, 0], VaultKey)).Message);
        Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata([.. encoded, 0, 0, 0, 0, 0], VaultKey));
    }

    [Fact]
    public void TamperedValueSectionCount_FailsClosed()
    {
        var encoded = Encode(ValueRecord(withPrevious: true));
        foreach (var count in new byte[] { 0, 1, 3 })
        {
            var tampered = (byte[])encoded.Clone();
            tampered[SecretRecordCodec.V3HeaderSize - 1] = count;

            var ex = Record.Exception(() => SecretRecordCodec.Decode(tampered, VaultKey));
            Assert.True(ex is TswapException or CryptographicException, $"count {count}: {ex?.GetType().Name ?? "no exception"}");
            ex = Record.Exception(() => SecretRecordCodec.DecodeMetadata(tampered, VaultKey));
            Assert.True(ex is TswapException or CryptographicException, $"count {count} (metadata): {ex?.GetType().Name ?? "no exception"}");
        }
    }

    [Fact]
    public void Header_IsAuthenticatedByTheMetadataSection()
    {
        var encoded = Encode(ValueRecord());
        foreach (var index in new[] { 5, 36, 37, 44, 45, 48, 49, 64 })
        {
            var tampered = (byte[])encoded.Clone();
            tampered[index] ^= 0x01;
            Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.DecodeMetadata(tampered, VaultKey));
        }
    }

    [Fact]
    public void MetadataSectionInAValueSlot_FailsAuthentication()
    {
        var encoded = Encode(ValueRecord());

        var spliced = WithSections(encoded, SectionBytes(encoded, 0));

        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(spliced, VaultKey));
    }

    [Fact]
    public void NonZeroPaddingInASection_FailsClosed()
    {
        var id = IdOf("db-pass");
        var goodMetadata = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", [(Version, 0, null)]);
        var badMetadata = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", [(Version, 0, null)], nonZeroPadding: 1);
        var goodValue = Layout.ValueSection(id, Version, Layout.ValuePlain("hello"u8.ToArray()));
        var badValue = Layout.ValueSection(id, Version, Layout.ValuePlain("hello"u8.ToArray(), nonZeroPadding: 1));

        var badValueFile = Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, goodMetadata), badValue);
        var badMetadataFile = Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, badMetadata), goodValue);

        Assert.Contains("padding", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(badValueFile, VaultKey)).Message);
        Assert.Contains("padding", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(badMetadataFile, VaultKey)).Message);
        Assert.Contains("padding", Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(badMetadataFile, VaultKey)).Message);
    }

    [Fact]
    public void DuplicateVersionStamps_AreRefused()
    {
        var id = IdOf("db-pass");
        var plain = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", [(Version, 0, null), (Version, 1, null)]);
        var section = Layout.ValueSection(id, Version, Layout.ValuePlain("hello"u8.ToArray()));
        var file = Layout.File(id, Write, 2, Layout.MetadataSection(id, Write, 2, plain), section, section);

        Assert.Contains("twice", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(file, VaultKey)).Message);
        Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(file, VaultKey));
        Assert.Throws<ArgumentException>(() => Encode(ValueRecord() with { Previous = new PreviousValue(Version, [1]) }));
    }

    [Fact]
    public void CurrentStampDifferentFromTheRecordVersion_IsRefused()
    {
        var id = IdOf("db-pass");
        var plain = Layout.MetadataPlain(RecordType.Value, Version, "db-pass", [(PreviousStamp, 0, null)]);
        var file = Layout.File(id, Write, 1, Layout.MetadataSection(id, Write, 1, plain),
            Layout.ValueSection(id, PreviousStamp, Layout.ValuePlain("hello"u8.ToArray())));

        Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(file, VaultKey));
    }

    [Fact]
    public void Encode_SealedForAnUnretainedVersion_Throws()
    {
        var sealedFor = new Dictionary<Stamp, byte[]> { [PreviousStamp] = new byte[300] };

        Assert.Throws<ArgumentException>(() => Encode(ValueRecord() with { Sealed = sealedFor }));
        Assert.Throws<ArgumentException>(() => Encode(TombstoneRecord() with { Sealed = new Dictionary<Stamp, byte[]> { [Version] = new byte[300] } }));
    }

    [Fact]
    public void Encode_MoreThan255FingerprintEntries_Throws()
    {
        var entry = new FingerprintEntry(VariantKind.Plain, 1, 1, new byte[16]);
        var huge = new FingerprintSet(1, Enumerable.Repeat(entry, 256).ToList());

        Assert.Throws<ArgumentException>(() => Encode(ValueRecord() with { Fingerprints = huge }));
        // 255 is the most a set can hold.
        var most = new FingerprintSet(1, Enumerable.Repeat(entry, 255).ToList());
        Assert.Equal(255, SecretRecordCodec.Decode(Encode(ValueRecord() with { Fingerprints = most }), VaultKey).Fingerprints!.Entries.Count);
    }

    [Fact]
    public void BinaryValue_RoundTripsByteForByte()
    {
        byte[] value = [0x00, 0xFF, 0xFE, 0x80];

        var decoded = SecretRecordCodec.Decode(Encode(ValueRecord(value: value)), VaultKey);

        Assert.Equal(value, decoded.Value);
    }

    [Fact]
    public void DerivedKeys_AreDistinct()
    {
        var id = IdOf("db-pass");
        var metadata = RecordKeyDerivation.DeriveMetadataKey(VaultKey, id, Version);
        var value = RecordKeyDerivation.DeriveValueKey(VaultKey, id, Version);
        var v2 = RecordKeyDerivation.Derive(VaultKey, id, Version);

        Assert.NotEqual(metadata, value);
        Assert.NotEqual(metadata, v2);
        Assert.NotEqual(value, v2);
        Assert.NotEqual(value, RecordKeyDerivation.DeriveValueKey(VaultKey, id, Write));
        Assert.NotEqual(value, RecordKeyDerivation.DeriveValueKey(VaultKey, IdOf("other"), Version));
    }

    [Fact]
    public void RecordIdThatDoesNotBelongToTheName_IsRefused()
    {
        var encoded = Encode(ValueRecord() with { RecordId = IdOf("other") });

        Assert.Contains("record id", Assert.Throws<TswapException>(() => SecretRecordCodec.Decode(encoded, VaultKey)).Message);
        Assert.Contains("record id", Assert.Throws<TswapException>(() => SecretRecordCodec.DecodeMetadata(encoded, VaultKey)).Message);
    }

    [Fact]
    public void WrongVaultKey_FailsAuthentication()
    {
        var encoded = Encode(ValueRecord());

        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.Decode(encoded, new byte[32]));
        Assert.ThrowsAny<CryptographicException>(() => SecretRecordCodec.DecodeMetadata(encoded, new byte[32]));
    }
}
