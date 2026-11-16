using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using TswapCore.Keyring;

namespace TswapCore.Fields;

/// <summary>
/// The deterministic binary encoding of a <see cref="FieldSet"/>, the data of the
/// <see cref="FieldsExtension"/> record extension (issue #311). Two machines that hold the same
/// fields write the same bytes: entries are sorted by name (ordinal), each history newest first.
///
/// <para><b>Layout</b> (multi-byte integers little-endian; stamps as <see cref="SecretRecordCodec"/>
/// writes them: HLC physical 8, logical 4, origin 16):</para>
/// <code>
/// version 1 (= 1) | since stamp 28 | entryCount u16 | entries
/// entry:  name str | flags 1 (bit 0: deleted) | value str (absent when deleted) | changed stamp 28 | who
///         | historyCount 1 (at most 5) | changes
/// change: oldValue str? | changed stamp 28 | who
/// who:    origin str | user str? | flags 1 (bit 0: elevated, bit 1: terminal) | by str?
/// str:    length u16 + UTF-8; str?: length 0xFFFF means null
/// </code>
/// </summary>
public static class FieldsCodec
{
    /// <summary>The most replaced states a field keeps.</summary>
    public const int MaxHistory = 5;

    private const byte Version = 1;
    private const ushort NoString = 0xFFFF;
    private const byte DeletedFlag = 0x01;
    private const byte ElevatedFlag = 0x01;
    private const byte TerminalFlag = 0x02;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Encodes <paramref name="set"/> in canonical order. Throws <see cref="ArgumentException"/> for a
    /// set no rule allows (two entries of one name, more than <see cref="MaxHistory"/> changes, a
    /// string over the length prefix, a value that doesn't match its deleted flag).
    /// </summary>
    public static byte[] Encode(FieldSet set)
    {
        var entries = set.Entries.OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
        for (var i = 1; i < entries.Count; i++)
            if (entries[i].Name == entries[i - 1].Name)
                throw new ArgumentException($"The fields hold two entries named '{entries[i].Name}'.", nameof(set));
        if (entries.Count > ushort.MaxValue)
            throw new ArgumentException($"{entries.Count} field entries (at most {ushort.MaxValue}).", nameof(set));

        var writer = new ArrayBufferWriter<byte>();
        WriteByte(writer, Version);
        WriteStamp(writer, set.Since);
        WriteUInt16(writer, (ushort)entries.Count);
        foreach (var entry in entries)
            WriteEntry(writer, entry);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>Decodes <see cref="Encode"/>'s bytes; anything else throws a "Malformed record" <see cref="TswapException"/>.</summary>
    public static FieldSet Decode(ReadOnlySpan<byte> data)
    {
        var reader = new Reader(data);
        var version = reader.Byte("version");
        if (version != Version)
            throw Malformed($"version {version} (this tswap reads version {Version})");
        var since = reader.Stamp("lineage stamp");
        var count = reader.UInt16("entry count");
        List<FieldEntry> entries = [with(capacity: count)];
        for (var i = 0; i < count; i++)
        {
            var entry = ReadEntry(ref reader);
            if (entries.Count > 0 && string.CompareOrdinal(entries[^1].Name, entry.Name) >= 0)
                throw Malformed($"entries out of order or repeated at '{entry.Name}'");
            entries.Add(entry);
        }
        if (!reader.AtEnd)
            throw Malformed("trailing bytes");
        return new FieldSet(since, entries);
    }

    /// <summary>
    /// The fields in <paramref name="extensions"/>, or null when there is no <see cref="FieldsExtension"/>
    /// entry (a record written before fields existed). Two such entries are malformed.
    /// </summary>
    public static FieldSet? TryGet(IReadOnlyList<RecordExtension> extensions)
    {
        RecordExtension? found = null;
        foreach (var extension in extensions)
        {
            if (extension.Type != FieldsExtension.Type)
                continue;
            if (found is not null)
                throw Malformed("appears twice");
            found = extension;
        }
        return found is null ? null : Decode(found.Data);
    }

    /// <summary>
    /// <paramref name="extensions"/> with its <see cref="FieldsExtension"/> entry replaced by
    /// <paramref name="set"/> (in place; added at the end when there was none) or removed (null).
    /// Every other extension keeps its position and bytes.
    /// </summary>
    public static IReadOnlyList<RecordExtension> With(IReadOnlyList<RecordExtension> extensions, FieldSet? set)
    {
        var replacement = set is null ? null : new RecordExtension(FieldsExtension.Type, Encode(set));
        List<RecordExtension> result = [with(capacity: extensions.Count + 1)];
        var placed = false;
        foreach (var extension in extensions)
        {
            if (extension.Type != FieldsExtension.Type)
                result.Add(extension);
            else if (!placed)
            {
                placed = true;
                if (replacement is not null)
                    result.Add(replacement);
            }
        }
        if (!placed && replacement is not null)
            result.Add(replacement);
        return result;
    }

    private static void WriteEntry(ArrayBufferWriter<byte> writer, FieldEntry entry)
    {
        if (entry.Deleted != (entry.Value is null))
            throw new ArgumentException($"Field '{entry.Name}': a value must be null exactly when the field is deleted.", nameof(entry));
        if (entry.History.Count > MaxHistory)
            throw new ArgumentException($"Field '{entry.Name}' has {entry.History.Count} history entries (at most {MaxHistory}).", nameof(entry));

        WriteString(writer, entry.Name);
        WriteByte(writer, entry.Deleted ? DeletedFlag : (byte)0);
        if (entry.Value is not null)
            WriteString(writer, entry.Value);
        WriteStamp(writer, entry.Changed);
        WriteWho(writer, entry.Who);
        WriteByte(writer, (byte)entry.History.Count);

        // Newest first by (stamp, origin); two changes of one identity (damage only) by their bytes.
        var changes = entry.History.Select(change => (change, bytes: EncodeChange(change))).ToList();
        changes.Sort((a, b) =>
        {
            var stamp = b.change.Changed.CompareTo(a.change.Changed);
            if (stamp != 0)
                return stamp;
            var origin = string.CompareOrdinal(b.change.Who.Origin, a.change.Who.Origin);
            return origin != 0 ? origin : a.bytes.AsSpan().SequenceCompareTo(b.bytes);
        });
        foreach (var (_, bytes) in changes)
            writer.Write(bytes);
    }

    /// <summary>One history entry as <see cref="Encode"/> writes it (the order of equal-identity changes).</summary>
    internal static byte[] EncodeChange(FieldChange change)
    {
        var writer = new ArrayBufferWriter<byte>();
        WriteNullableString(writer, change.OldValue);
        WriteStamp(writer, change.Changed);
        WriteWho(writer, change.Who);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>A <see cref="FieldWho"/> as <see cref="Encode"/> writes it.</summary>
    internal static byte[] EncodeWho(FieldWho who)
    {
        var writer = new ArrayBufferWriter<byte>();
        WriteWho(writer, who);
        return writer.WrittenSpan.ToArray();
    }

    private static void WriteWho(ArrayBufferWriter<byte> writer, FieldWho who)
    {
        WriteString(writer, who.Origin);
        WriteNullableString(writer, who.User);
        WriteByte(writer, (byte)((who.Elevated ? ElevatedFlag : 0) | (who.Terminal ? TerminalFlag : 0)));
        WriteNullableString(writer, who.By);
    }

    private static FieldEntry ReadEntry(ref Reader reader)
    {
        var name = reader.String("field name");
        var flags = reader.Byte("entry flags");
        if ((flags & ~DeletedFlag) != 0)
            throw Malformed($"unknown entry flags 0x{flags:x2} on '{name}'");
        var deleted = (flags & DeletedFlag) != 0;
        var value = deleted ? null : reader.String("field value");
        var changed = reader.Stamp("change stamp");
        var who = ReadWho(ref reader);
        var historyCount = reader.Byte("history count");
        if (historyCount > MaxHistory)
            throw Malformed($"'{name}' has {historyCount} history entries (at most {MaxHistory})");
        List<FieldChange> history = [with(capacity: historyCount)];
        for (var i = 0; i < historyCount; i++)
            history.Add(new FieldChange(reader.NullableString("old value"), reader.Stamp("history stamp"), ReadWho(ref reader)));
        return new FieldEntry(name, value, deleted, changed, who, history);
    }

    private static FieldWho ReadWho(ref Reader reader)
    {
        var origin = reader.String("origin");
        var user = reader.NullableString("user");
        var flags = reader.Byte("who flags");
        if ((flags & ~(ElevatedFlag | TerminalFlag)) != 0)
            throw Malformed($"unknown who flags 0x{flags:x2}");
        var by = reader.NullableString("--by label");
        return new FieldWho(origin, user, (flags & ElevatedFlag) != 0, (flags & TerminalFlag) != 0, by);
    }

    private static void WriteByte(ArrayBufferWriter<byte> writer, byte value)
    {
        writer.GetSpan(1)[0] = value;
        writer.Advance(1);
    }

    private static void WriteUInt16(ArrayBufferWriter<byte> writer, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(writer.GetSpan(2), value);
        writer.Advance(2);
    }

    private static void WriteStamp(ArrayBufferWriter<byte> writer, Stamp stamp)
    {
        SecretRecordCodec.WriteStamp(writer.GetSpan(SecretRecordCodec.StampSize), 0, stamp);
        writer.Advance(SecretRecordCodec.StampSize);
    }

    private static void WriteString(ArrayBufferWriter<byte> writer, string value)
    {
        var bytes = StrictUtf8.GetBytes(value);
        if (bytes.Length >= NoString)
            throw new ArgumentException($"A field string of {bytes.Length} bytes (at most {NoString - 1}).", nameof(value));
        WriteUInt16(writer, (ushort)bytes.Length);
        writer.Write(bytes);
    }

    private static void WriteNullableString(ArrayBufferWriter<byte> writer, string? value)
    {
        if (value is null)
            WriteUInt16(writer, NoString);
        else
            WriteString(writer, value);
    }

    private static TswapException Malformed(string what) => new($"Malformed record: fields extension {what}");

    private ref struct Reader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _offset;

        public readonly bool AtEnd => _offset == _data.Length;

        private ReadOnlySpan<byte> Take(int count, string what)
        {
            if (count > _data.Length - _offset)
                throw Malformed($"truncated ({what})");
            var slice = _data.Slice(_offset, count);
            _offset += count;
            return slice;
        }

        public byte Byte(string what) => Take(1, what)[0];

        public ushort UInt16(string what) => BinaryPrimitives.ReadUInt16LittleEndian(Take(2, what));

        public Stamp Stamp(string what) => SecretRecordCodec.ReadStamp(Take(SecretRecordCodec.StampSize, what), 0);

        public string String(string what) =>
            NullableString(what) ?? throw Malformed($"{what} missing");

        public string? NullableString(string what)
        {
            var length = UInt16(what);
            if (length == NoString)
                return null;
            var bytes = Take(length, what);
            try
            {
                return StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                throw Malformed($"{what} is not valid UTF-8");
            }
        }
    }
}
