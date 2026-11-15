using System.Text;
using TswapCore.Keyring;

namespace TswapCore.Fields;

/// <summary>
/// The per-field merge of the <see cref="FieldsExtension"/> (issue #311, spec "Merge" rules 2-5 and 7),
/// which <see cref="RecordMerge"/> applies in both its merge paths. Every rule is a total order or a set
/// union, so the result doesn't depend on the order of the inputs, and merging it again with any of
/// them changes nothing.
/// <list type="bullet">
/// <item><b>Lineage:</b> <see cref="FieldSet.Since"/> is the largest input's; entries (values and
/// delete markers) changed before it belong to an earlier life of the name and are dropped.</item>
/// <item><b>Per field:</b> the entry with the newest change stamp wins, a marker over a value and a
/// value over a marker alike. Equal stamps with different content (damage only) are decided by the
/// ordinally smallest (deleted flag, value bytes), then the smallest encoded who.</item>
/// <item><b>History:</b> the union of the inputs' histories, plus every input entry whose content
/// differs from the winner's as a replaced state (so a concurrent change is never lost silently); an
/// input entry identical to the winner adds nothing. One change per identity (stamp, origin), the
/// smallest encoding when two differ; newest first; at most <see cref="FieldsCodec.MaxHistory"/>.</item>
/// <item><b>Caps</b> (<see cref="FieldRules"/>) are never applied: a merge may exceed them.</item>
/// </list>
/// </summary>
public static class FieldMerge
{
    /// <summary>
    /// Merges the <c>Fields</c> data of every copy of one secret that has it (copies without the
    /// extension are not passed).
    /// </summary>
    /// <exception cref="ArgumentException">No inputs.</exception>
    public static FieldSet Merge(IReadOnlyList<FieldSet> inputs)
    {
        if (inputs.Count == 0)
            throw new ArgumentException("FieldMerge needs at least one input", nameof(inputs));

        var since = inputs.Select(s => s.Since).Aggregate(Stamp.Max);
        List<FieldEntry> entries = [];
        var byName = inputs
            .SelectMany(s => s.Entries)
            .Where(e => e.Changed.CompareTo(since) >= 0)
            .GroupBy(e => e.Name, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal);
        foreach (var group in byName)
        {
            var candidates = group.ToList();
            var winner = candidates.Aggregate((x, y) => Beats(y, x) ? y : x);
            var replaced = candidates
                .Where(e => !SameState(e, winner))
                .Select(e => new FieldChange(e.Value, e.Changed, e.Who));
            entries.Add(winner with { History = CanonicalHistory(candidates.SelectMany(e => e.History).Concat(replaced)) });
        }
        return new FieldSet(since, entries);
    }

    /// <summary>Whether <paramref name="a"/> wins over <paramref name="b"/> (two entries of one name).</summary>
    private static bool Beats(FieldEntry a, FieldEntry b)
    {
        var stamp = a.Changed.CompareTo(b.Changed);
        if (stamp != 0)
            return stamp > 0;
        // Rule 4: name and stamp are equal, so the smallest projection (deleted flag, value bytes) wins,
        // then the smallest encoded who, so the winner is one input entry whatever the order.
        if (a.Deleted != b.Deleted)
            return !a.Deleted;
        var value = Encoding.UTF8.GetBytes(a.Value ?? "").AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b.Value ?? ""));
        if (value != 0)
            return value < 0;
        return FieldsCodec.EncodeWho(a.Who).AsSpan().SequenceCompareTo(FieldsCodec.EncodeWho(b.Who)) < 0;
    }

    /// <summary>The same state of a field, its history aside: the same entry, held by two copies.</summary>
    private static bool SameState(FieldEntry a, FieldEntry b) =>
        a.Deleted == b.Deleted && a.Value == b.Value && a.Changed.Equals(b.Changed) && a.Who.Equals(b.Who);

    /// <summary>One change per identity (the smallest encoding), newest first, trimmed.</summary>
    private static List<FieldChange> CanonicalHistory(IEnumerable<FieldChange> changes) =>
        changes
            .GroupBy(c => (c.Changed, c.Who.Origin))
            .Select(g => g.Select(c => (Change: c, Bytes: FieldsCodec.EncodeChange(c)))
                .Aggregate((x, y) => y.Bytes.AsSpan().SequenceCompareTo(x.Bytes) < 0 ? y : x).Change)
            .OrderByDescending(c => c.Changed)
            .ThenByDescending(c => c.Who.Origin, StringComparer.Ordinal)
            .Take(FieldsCodec.MaxHistory)
            .ToList();
}
