using System.Text;
using TswapCore.Keyring;

namespace TswapCore.Totp;

/// <summary>
/// Brief T58 (#374), Task 4: the <c>ValueKinds</c> record extension (type <c>0x0101</c>, <see cref="Fields.FieldsExtension"/>'s
/// registry), so <c>names</c> can mark otpauth records from metadata alone. An older build keeps the extension when it
/// writes a new value, so each kind is bound to a version stamp.
/// <code>
/// format 1 | count 1 (0-2) | per entry: version stamp 28 (SecretRecordCodec's stamp encoding) | kind 1 (1 Totp, 2 OtpAuthUnusable)
/// </code>
/// Entries are ordered current, then previous, as <see cref="RecordMetadata.RetainedVersions"/> orders them; only
/// otpauth versions get one, and with none there is no extension. Display only: nothing here ever makes a record
/// unreadable, and <c>run</c>, <c>totp</c> and <c>rotate</c> decide from the value, not from this mark.
/// </summary>
public static class ValueKinds
{
    /// <summary>The extension type.</summary>
    public const ushort Type = 0x0101;

    // A new format byte needs a `KeyringFormat.RecordFormatVersion` bump, so that builds that can't read it refuse the
    // folder: `Decode` gives null for an unknown format, and a write or a reindex would then replace the extension with
    // this build's entries.
    private const byte Format = 1;
    private const int EntrySize = SecretRecordCodec.StampSize + 1;

    /// <summary>One entry: a version stamp and its kind byte (as stored; an unknown byte is carried, never read as a kind).</summary>
    public readonly record struct Entry(Stamp Version, byte Kind);

    /// <summary>
    /// The current version's kind: the entry whose stamp equals <see cref="RecordMetadata.Version"/>. <see cref="ValueKind.None"/>
    /// for a tombstone, no entry, an unknown kind byte, and an extension that is missing, doesn't decode or appears twice.
    /// </summary>
    public static ValueKind Of(RecordMetadata metadata)
    {
        if (metadata.Type == RecordType.Tombstone || Entries(metadata.Extensions) is not { } entries)
            return ValueKind.None;
        foreach (var entry in entries)
            if (entry.Version.Equals(metadata.Version))
                return entry.Kind is (byte)ValueKind.Totp or (byte)ValueKind.OtpAuthUnusable ? (ValueKind)entry.Kind : ValueKind.None;
        return ValueKind.None;
    }

    /// <summary>The kind of a value's UTF-8 bytes, decoded as <c>Fingerprinter.Compute</c> decodes them.</summary>
    public static ValueKind Classify(byte[] value) => TotpCodes.Classify(Encoding.UTF8.GetString(value));

    /// <summary>
    /// The entries of the one <c>0x0101</c> extension in <paramref name="extensions"/>, or null when there is none, there
    /// are two or more, or it doesn't decode (a truncated list, an unknown format byte, a count of 0 or above 2).
    /// </summary>
    public static IReadOnlyList<Entry>? Entries(IReadOnlyList<RecordExtension> extensions)
    {
        var found = extensions.Where(e => e.Type == Type).ToList();
        return found.Count == 1 ? Decode(found[0].Data) : null;
    }

    /// <summary>Decodes an extension's data, or null when it isn't this build's format 1 layout.</summary>
    public static IReadOnlyList<Entry>? Decode(byte[] data)
    {
        if (data.Length < 2 || data[0] != Format || data[1] is 0 or > 2 || data.Length != 2 + data[1] * EntrySize)
            return null;
        List<Entry> entries = [];
        for (var i = 0; i < data[1]; i++)
        {
            var offset = 2 + i * EntrySize;
            entries.Add(new Entry(SecretRecordCodec.ReadStamp(data, offset), data[offset + SecretRecordCodec.StampSize]));
        }
        return entries;
    }

    /// <summary>Encodes 1 or 2 entries in the format 1 layout.</summary>
    public static byte[] Encode(IReadOnlyList<Entry> entries)
    {
        if (entries.Count is 0 or > 2)
            throw new ArgumentOutOfRangeException(nameof(entries), "A ValueKinds extension holds one or two entries.");
        var data = new byte[2 + entries.Count * EntrySize];
        data[0] = Format;
        data[1] = (byte)entries.Count;
        for (var i = 0; i < entries.Count; i++)
        {
            var offset = SecretRecordCodec.WriteStamp(data, 2 + i * EntrySize, entries[i].Version);
            data[offset] = entries[i].Kind;
        }
        return data;
    }

    /// <summary>
    /// <paramref name="extensions"/> with the <c>0x0101</c> extension holding exactly <paramref name="entries"/>: in the
    /// place of the first one there was (at the end when there was none), every other <c>0x0101</c> dropped; no
    /// <c>0x0101</c> at all for no entries. Every other extension keeps its place and bytes. Returns
    /// <paramref name="extensions"/> itself when nothing changes.
    /// </summary>
    public static IReadOnlyList<RecordExtension> With(IReadOnlyList<RecordExtension> extensions, IReadOnlyList<Entry> entries)
    {
        var replacement = entries.Count == 0 ? null : new RecordExtension(Type, Encode(entries));
        List<RecordExtension> result = [];
        var placed = false;
        foreach (var extension in extensions)
        {
            if (extension.Type != Type)
            {
                result.Add(extension);
                continue;
            }
            if (!placed && replacement is not null)
                result.Add(replacement);
            placed = true;
        }
        if (!placed && replacement is not null)
            result.Add(replacement);
        return result.SequenceEqual(extensions) ? extensions : result;
    }

    /// <summary>
    /// A new value version's extensions (brief T58, "Write"): an entry for <paramref name="version"/> from
    /// <paramref name="kind"/>, then the entry the replaced current version (<paramref name="replaced"/>, now previous)
    /// had, if any; every other entry dropped.
    /// </summary>
    public static IReadOnlyList<RecordExtension> ForNewVersion(IReadOnlyList<RecordExtension> extensions, Stamp version, ValueKind kind,
        Stamp? replaced)
    {
        List<Entry> entries = [];
        if (kind != ValueKind.None)
            entries.Add(new Entry(version, (byte)kind));
        if (replaced is not null && Entries(extensions)?.FirstOrDefault(e => e.Version.Equals(replaced)) is { Version: not null } kept)
            entries.Add(kept);
        return With(extensions, entries);
    }

    /// <summary>
    /// The extensions with an entry for every retained version from its value (<c>vault reindex</c>, which holds every
    /// value): <paramref name="current"/>, then <paramref name="previous"/>.
    /// </summary>
    public static IReadOnlyList<RecordExtension> FromValues(IReadOnlyList<RecordExtension> extensions, (Stamp Version, byte[] Value) current,
        (Stamp Version, byte[] Value)? previous)
    {
        List<Entry> entries = [];
        foreach (var (version, value) in previous is { } p ? [current, p] : new[] { current })
            if (Classify(value) is var kind and not ValueKind.None)
                entries.Add(new Entry(version, (byte)kind));
        return With(extensions, entries);
    }
}
