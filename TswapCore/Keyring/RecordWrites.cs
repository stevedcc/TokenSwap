using TswapCore.Fingerprints;

namespace TswapCore.Keyring;

/// <summary>
/// Brief T16-S2b: the write rules of <see cref="RecordVaultStore.NextRecord"/> and
/// <see cref="RecordVaultStore.Tombstone"/> for a record held as metadata and still-encrypted
/// value sections, so a write of a format 3 record decrypts no value it doesn't use. A retained
/// version's section and fingerprint set are carried forward byte for byte; a new version's
/// section is sealed by the caller from the value in its hands. Every result is normalised
/// (<see cref="RecordMerge.Normalize(RecordMetadata)"/>); its write stamp is the commit's to
/// assign, as for <see cref="RecordVaultStore.NextRecord"/>'s. <c>RecordWritesTests.RecordWrites_MatchNextRecord_OnRandomStates</c> holds
/// the two rule sets equal.
/// </summary>
internal static class RecordWrites
{
    /// <summary>
    /// <see cref="RecordVaultStore.NextRecord"/>'s dispatch for a record held as metadata: a new
    /// version (<see cref="NewVersion"/>, sealed by <paramref name="seal"/>) when there is no live
    /// record, when <paramref name="rotated"/>, or when <paramref name="sameValue"/> says the value
    /// differs; otherwise, with <paramref name="burnedAt"/> set, a burn of the current version
    /// (<see cref="Burn"/>, stamped by <paramref name="nextStamp"/>, not at <paramref name="burnedAt"/>);
    /// otherwise null (nothing to write). Stamps are taken only for what is written.
    /// </summary>
    public static (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sections)? Next(
        RecordMetadata? state, IReadOnlyDictionary<Stamp, byte[]> heldSections, byte[] recordId, string name, Func<bool> sameValue,
        bool rotated, bool restored, DateTime created, DateTime? burnedAt, string? burnReason, byte[] origin, Func<Stamp> nextStamp,
        Func<Stamp, (byte[] Section, FingerprintSet Fingerprints)> seal)
    {
        // NextRecord's order: a new version when there is no live record, when rotated, or when the
        // value differs (asked last, so add's comparison runs only when it decides something).
        if (state is not { Type: not RecordType.Tombstone } live || rotated || !sameValue())
        {
            var version = nextStamp();
            var (section, fingerprints) = seal(version);
            return NewVersion(state, heldSections, recordId, name, version, section, fingerprints, restored, created, burnedAt, burnReason, origin);
        }
        // The same value with a burn: a burn of the current version, stamped now, when it has none.
        if (burnedAt is not null && live.Burns.All(b => !b.Version.Equals(live.Version)))
            return (Burn(live, nextStamp(), burnReason)!, heldSections);
        return null;
    }

    /// <summary>
    /// A new value version <paramref name="version"/> (create, add, rotate, import, restore) over
    /// <paramref name="state"/> (null: no record). The replaced current version becomes the previous
    /// one with its section and set; an older previous is dropped with its section; an outstanding
    /// burn of the replaced version becomes history.
    /// </summary>
    /// <param name="heldSections">The sections of <paramref name="state"/>'s retained versions.</param>
    /// <param name="newSection">The new version's sealed value section.</param>
    /// <param name="newFingerprints">The new value's fingerprints.</param>
    /// <param name="restored"><c>restore</c>: the burns of the version being restored are issued again on the new one.</param>
    /// <param name="created">The creation time when there is no live record (a live record keeps its own).</param>
    /// <param name="importedBurnAt">An imported burn's time, on the new version.</param>
    /// <param name="origin">This machine's origin id (an imported burn's stamp).</param>
    public static (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sections) NewVersion(
        RecordMetadata? state, IReadOnlyDictionary<Stamp, byte[]> heldSections, byte[] recordId, string name, Stamp version,
        byte[] newSection, FingerprintSet newFingerprints, bool restored, DateTime created, DateTime? importedBurnAt,
        string? importedBurnReason, byte[] origin)
    {
        var live = state is { Type: not RecordType.Tombstone };
        List<BurnEntry> burns = [.. state?.Burns ?? []];
        Dictionary<Stamp, byte[]> sections = new() { [version] = newSection };
        if (live)
        {
            if (!heldSections.TryGetValue(state!.Version, out var current))
                throw new InvalidOperationException("The record's current version has no held value section.");
            sections[state.Version] = current;
            if (restored && state.PreviousVersion is { } restoredFrom)
                burns.AddRange([.. state.Burns.Where(b => b.Version.Equals(restoredFrom)).Select(b => new BurnEntry(version, b.Burn, b.Reason))]);
        }
        if (importedBurnAt is { } at)
            burns.Add(new BurnEntry(version, new Stamp(new Hlc(new DateTimeOffset(UtcOf(at)).ToUnixTimeMilliseconds(), 0), origin), importedBurnReason));
        var createdMs = live ? state!.CreatedMs : new DateTimeOffset(DateTime.SpecifyKind(created, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
        var metadata = new RecordMetadata(recordId, Stamp.Zero, RecordType.Value, version, name, createdMs, burns, newFingerprints,
            live ? state!.Version : null, live ? state!.Fingerprints : null, state?.Extensions ?? []);
        return (RecordMerge.Normalize(metadata), sections);
    }

    /// <summary>
    /// A burn of <paramref name="state"/>'s current version, or null when it is a tombstone or that
    /// version is burned already (nothing to write). Sections and sets are untouched.
    /// </summary>
    public static RecordMetadata? Burn(RecordMetadata state, Stamp burn, string? reason)
    {
        if (state.Type == RecordType.Tombstone || state.Burns.Any(b => b.Version.Equals(state.Version)))
            return null;
        return RecordMerge.Normalize(state with { Burns = [.. state.Burns, new BurnEntry(state.Version, burn, reason)] });
    }

    /// <summary>The tombstone a delete writes: no value versions, sections or sets; the burns kept as history.</summary>
    public static RecordMetadata Tombstone(RecordMetadata state, Stamp version) => RecordMerge.Normalize(state with
    {
        Type = RecordType.Tombstone, Version = version, Fingerprints = null, PreviousVersion = null, PreviousFingerprints = null,
    });

    // RecordVaultStore.UnixMs's rule: an unspecified time is UTC, a local one is converted.
    private static DateTime UtcOf(DateTime time) =>
        time.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(time, DateTimeKind.Utc) : time.ToUniversalTime();
}
