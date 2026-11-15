using System.Text;
using TswapCore.Keyring;

namespace TswapCore.Fields;

/// <summary>One change a field write asks for: set <see cref="Name"/> to <see cref="Value"/>, or remove it (null).</summary>
public sealed record FieldEdit(string Name, string? Value);

/// <summary>
/// The one applier of field edits (issue #311, spec "Writes"), shared by both store paths: the
/// metadata-only write (<see cref="RecordWrites"/>) and the plaintext one
/// (<see cref="RecordVaultStore.NextRecord"/>, <see cref="RecordVaultStore.SetFieldsRecord"/>).
/// </summary>
public static class FieldEdits
{
    /// <summary>
    /// <paramref name="current"/> with <paramref name="edits"/> applied in order. An edit that changes
    /// nothing (the same value, or a removal of an absent or deleted field) is skipped: no stamp, no
    /// history. Every other edit mints one change stamp from <paramref name="nextStamp"/>, pushes the
    /// replaced state (its value, or null for a delete marker, with its stamp and who; nothing for a
    /// field that never existed) onto the field's history, keeps the newest
    /// <see cref="FieldsCodec.MaxHistory"/>, and stamps the entry with the new stamp and
    /// <paramref name="who"/>; a removal leaves a delete marker. Values are stored NFC-normalised
    /// (<see cref="FieldRules.NormaliseValue"/>). Returns <paramref name="current"/> itself when no
    /// edit changed anything.
    /// </summary>
    /// <exception cref="TswapException">
    /// A field name or value the rules refuse (<see cref="FieldRules.Validate"/>); or the result is over a
    /// cap (<see cref="FieldRules.CheckCaps"/>) and the write doesn't shrink it (spec Merge rule 7: it
    /// adds a live field or sets a value at least as long as the one it replaces). The message names
    /// <paramref name="secretName"/>.
    /// </exception>
    public static FieldSet Apply(FieldSet current, IReadOnlyList<FieldEdit> edits, FieldWho who, Func<Stamp> nextStamp, string secretName)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(edits);
        ArgumentNullException.ThrowIfNull(who);
        ArgumentNullException.ThrowIfNull(nextStamp);

        var byName = current.Entries.ToDictionary(e => e.Name, StringComparer.Ordinal);
        var changed = false;
        var grows = false;
        foreach (var edit in edits)
        {
            string? value = null;
            if (edit.Value is not null)
            {
                if (FieldRules.Validate(edit.Name, edit.Value) is { } refusal)
                    throw new TswapException($"Secret '{secretName}': {refusal}");
                value = FieldRules.NormaliseValue(edit.Value);
            }
            var old = byName.GetValueOrDefault(edit.Name);
            var oldValue = old is { Deleted: false } ? old.Value : null;
            if (oldValue == value)
                continue;

            grows |= value is not null && (oldValue is null || Encoding.UTF8.GetByteCount(value) >= Encoding.UTF8.GetByteCount(oldValue));
            var stamp = nextStamp();
            IEnumerable<FieldChange> history = old is null
                ? []
                : [new FieldChange(old.Value, old.Changed, old.Who), .. old.History];
            byName[edit.Name] = new FieldEntry(edit.Name, value, value is null, stamp, who, [.. history
                // A write never keeps a change of an earlier life of the name (the merge would drop it).
                .Where(c => c.Changed.CompareTo(current.Since) >= 0)
                .OrderByDescending(c => c.Changed)
                .ThenByDescending(c => c.Who.Origin, StringComparer.Ordinal)
                .Take(FieldsCodec.MaxHistory)]);
            changed = true;
        }
        if (!changed)
            return current;

        var next = new FieldSet(current.Since, [.. byName.Values.OrderBy(e => e.Name, StringComparer.Ordinal)]);
        if (grows && FieldRules.CheckCaps(next) is { } cap)
            throw new TswapException($"Refused: the fields of '{secretName}' are over a cap. {cap}");
        return next;
    }

    /// <summary>
    /// The extension list a value write leaves (spec "Writes", lineage). A new life of the name
    /// (<paramref name="createdAt"/>: from nothing or over a tombstone) gets a fresh <c>Fields</c>
    /// extension with <see cref="FieldSet.Since"/> = the new version, whatever <c>Fields</c> the old
    /// record carried; a live record keeps its own (one written before fields existed gets one, with
    /// <see cref="FieldSet.Since"/> = <see cref="Stamp.Zero"/>, only when edits change it). Then
    /// <paramref name="edits"/> are applied (<see cref="Apply"/>, stamped after the version). Every
    /// other extension keeps its place and bytes.
    /// </summary>
    internal static IReadOnlyList<RecordExtension> ForWrite(IReadOnlyList<RecordExtension> extensions, Stamp? createdAt,
        IReadOnlyList<FieldEdit>? edits, FieldWho? who, Func<Stamp>? nextStamp, string secretName)
    {
        if (edits is { Count: > 0 } && (who is null || nextStamp is null))
            throw new ArgumentException("A field write needs who made it and a stamp source.", nameof(edits));
        if (createdAt is { } since)
        {
            var fresh = new FieldSet(since, []);
            return FieldsCodec.With(extensions, edits is { Count: > 0 } ? Apply(fresh, edits, who!, nextStamp!, secretName) : fresh);
        }
        if (edits is not { Count: > 0 })
            return extensions;
        var before = FieldsCodec.TryGet(extensions) ?? new FieldSet(Stamp.Zero, []);
        var after = Apply(before, edits, who!, nextStamp!, secretName);
        return ReferenceEquals(after, before) ? extensions : FieldsCodec.With(extensions, after);
    }

    /// <summary>The extension list a tombstone keeps: every type but <c>Fields</c> (spec "Writes", delete).</summary>
    internal static IReadOnlyList<RecordExtension> ForTombstone(IReadOnlyList<RecordExtension> extensions) =>
        FieldsCodec.With(extensions, null);
}
