namespace TswapCore.Keyring;

/// <summary>
/// The merge rules of the record store (brief T6 decision 4, owner decisions on #132 and #8),
/// applied when one secret has several versions: the record, its sync-conflict copies, or another
/// vault folder.
/// <list type="bullet">
/// <item><b>Existence:</b> the last action wins by (HLC, origin) (<see cref="Stamp"/>), for values
/// and tombstones alike. A burn never decides existence.</item>
/// <item><b>Burns:</b> a burn marks the value version it was issued against. If that version is the
/// winner (and a value), the secret is burned; otherwise the burn is history. Two burns of the same
/// version keep the earliest (#35: an incident record is never overwritten).</item>
/// <item><b>History</b> is bounded to <see cref="MaxBurns"/> entries: the outstanding burn, then the
/// most recent others by (burn HLC, origin).</item>
/// </list>
/// </summary>
public static class RecordMerge
{
    /// <summary>The most burns one record keeps (the outstanding one included).</summary>
    public const int MaxBurns = 16;

    /// <summary>
    /// Puts <paramref name="burns"/> in canonical form for a record whose winning version is
    /// <paramref name="version"/> (a tombstone when <paramref name="isTombstone"/>): one burn per
    /// version (the earliest), bounded to <see cref="MaxBurns"/> (the outstanding burn always kept,
    /// then the most recent), ordered by (version, burn) so equal states encode equally.
    /// </summary>
    public static IReadOnlyList<BurnEntry> CanonicalBurns(IEnumerable<BurnEntry> burns, Stamp version, bool isTombstone)
    {
        var earliestPerVersion = burns
            .GroupBy(b => b.Version)
            .Select(g => g.OrderBy(b => b.Burn).ThenBy(b => b.Reason, StringComparer.Ordinal).First())
            .ToList();
        var outstanding = isTombstone ? null : earliestPerVersion.FirstOrDefault(b => b.Version.Equals(version));
        var kept = earliestPerVersion
            .Where(b => !ReferenceEquals(b, outstanding))
            .OrderByDescending(b => b.Burn)
            .ThenByDescending(b => b.Version) // fix round 1 (C): equal burn stamps happen (restore)
            .Take(outstanding is null ? MaxBurns : MaxBurns - 1)
            .ToList();
        if (outstanding is not null)
            kept.Add(outstanding);
        return kept.OrderBy(b => b.Version).ThenBy(b => b.Burn).ToList();
    }

    /// <summary>The record type that follows from a winning version and its burns.</summary>
    public static RecordType TypeOf(bool isTombstone, Stamp version, IEnumerable<BurnEntry> burns) =>
        isTombstone ? RecordType.Tombstone
        : burns.Any(b => b.Version.Equals(version)) ? RecordType.Burned
        : RecordType.Value;

    /// <summary>
    /// <paramref name="record"/> with its burns canonical and its type recomputed from them
    /// (<see cref="CanonicalBurns"/>, <see cref="TypeOf"/>).
    /// </summary>
    public static SecretRecord Normalize(SecretRecord record)
    {
        var isTombstone = record.Type == RecordType.Tombstone;
        var burns = CanonicalBurns(record.Burns, record.Version, isTombstone);
        return record with { Burns = burns, Type = TypeOf(isTombstone, record.Version, burns) };
    }

    /// <summary>
    /// Merges two versions of one secret (same record id). Commutative, associative and
    /// idempotent: the winning version is the larger <see cref="SecretRecord.Version"/> stamp
    /// (ties between identical stamps, which only damage could produce, are decided by content so
    /// the result still doesn't depend on order: a tombstone wins over a value, then the larger value
    /// bytewise, then the later created time, then the name, then the previous value: present over
    /// absent, then its version, then its bytes); burns are the union, then
    /// <see cref="CanonicalBurns"/>; the write stamp is the larger of the two.
    /// </summary>
    public static SecretRecord Merge(SecretRecord a, SecretRecord b)
    {
        if (!a.RecordId.AsSpan().SequenceEqual(b.RecordId))
            throw new ArgumentException("Only versions of one record can be merged", nameof(b));
        var order = a.Version.CompareTo(b.Version);
        if (order == 0)
            order = CompareContent(a, b);
        var winner = order >= 0 ? a : b;
        var isTombstone = winner.Type == RecordType.Tombstone;
        var burns = CanonicalBurns(a.Burns.Concat(b.Burns), winner.Version, isTombstone);
        return winner with
        {
            Write = Stamp.Max(a.Write, b.Write),
            Burns = burns,
            Type = TypeOf(isTombstone, winner.Version, burns),
        };
    }

    private static int CompareContent(SecretRecord a, SecretRecord b)
    {
        var tombstone = (a.Type == RecordType.Tombstone).CompareTo(b.Type == RecordType.Tombstone);
        if (tombstone != 0)
            return tombstone;
        var value = a.Value.AsSpan().SequenceCompareTo(b.Value);
        if (value != 0)
            return value;
        var created = a.CreatedMs.CompareTo(b.CreatedMs);
        if (created != 0)
            return created;
        var name = string.CompareOrdinal(a.Name, b.Name);
        if (name != 0)
            return name;
        // Fix round 3: the previous value last (absent < present, then its version, then its bytes).
        var hasPrevious = (a.Previous is not null).CompareTo(b.Previous is not null);
        if (hasPrevious != 0 || a.Previous is null)
            return hasPrevious;
        var previousVersion = a.Previous.Version.CompareTo(b.Previous!.Version);
        return previousVersion != 0 ? previousVersion : a.Previous.Value.AsSpan().SequenceCompareTo(b.Previous.Value);
    }
}
