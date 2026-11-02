using System.Buffers.Binary;
using TswapCore.Fingerprints;

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

    /// <summary>Merges two versions of one secret: <c>MergeAll([a, b])</c>.</summary>
    public static SecretRecord Merge(SecretRecord a, SecretRecord b) => MergeAll([a, b]);

    /// <summary>
    /// Brief T16-S1 ruling 11: merges every copy of one secret (the main file, its conflicted
    /// copies and, for <c>vault merge</c>, the other folder's state) in one step. The result doesn't
    /// depend on the order of <paramref name="inputs"/>, because every rule is a total order or an
    /// all-inputs-must-agree check:
    /// <list type="bullet">
    /// <item><b>Winner:</b> the input with the largest version stamp. Inputs sharing that stamp must
    /// agree on tombstone-ness, value, created time, name and previous value (presence, stamp, value).
    /// Today's content tie-break is gone: two different values under one stamp (only damage or a clock
    /// rollback makes them) fail closed instead of one being picked silently.</item>
    /// <item><b>Retained versions</b> (current and previous): every input holding one of their stamps,
    /// as its current or its previous value, must hold the same plaintext. Versions the winner doesn't
    /// retain are ignored: a superseded version's damage no longer matters.</item>
    /// <item><b>Sections</b> (<see cref="SecretRecord.Sealed"/>): per retained version, the ordinally
    /// smallest section bytes among the inputs holding one. Two machines that each converted a version
    /// hold different ciphertexts of one plaintext (random nonces, ruling 1); the minimum is a fixed
    /// point, so every folder converges on one section and a second merge changes nothing.</item>
    /// <item><b>Fingerprints:</b> per retained version, the set with the highest variant-set version
    /// (null is bottom); two different sets at one variant-set version conflict.</item>
    /// <item><b>Extensions:</b> the whole list of the input with the largest write stamp; ties by the
    /// ordinal order of the encoded list.</item>
    /// <item><b>Burns:</b> the union, then <see cref="CanonicalBurns"/>. <b>Write stamp:</b> the largest.</item>
    /// </list>
    /// A conflict is a <see cref="RecordConflictException"/>: the caller marks that record unreadable
    /// (warned, never merged or overwritten) and carries on with the others.
    /// </summary>
    /// <exception cref="ArgumentException">No inputs, or inputs of different records.</exception>
    public static SecretRecord MergeAll(IReadOnlyList<SecretRecord> inputs)
    {
        if (inputs.Count == 0)
            throw new ArgumentException("MergeAll needs at least one input", nameof(inputs));
        var recordId = inputs[0].RecordId;
        if (inputs.Any(r => !r.RecordId.AsSpan().SequenceEqual(recordId)))
            throw new ArgumentException("Only versions of one record can be merged", nameof(inputs));

        var version = inputs.Select(r => r.Version).Aggregate(Stamp.Max);
        var tied = inputs.Where(r => r.Version.Equals(version)).ToList();
        var winner = tied[0];
        foreach (var other in tied.Skip(1))
            RequireSameVersion(winner, other);

        var isTombstone = winner.Type == RecordType.Tombstone;
        List<(Stamp Version, bool IsPrevious)> retained = [];
        if (!isTombstone)
        {
            retained.Add((version, false));
            if (winner.Previous is { } previous)
                retained.Add((previous.Version, true));
        }

        var sealedSections = new Dictionary<Stamp, byte[]>();
        FingerprintSet? currentFingerprints = null, previousFingerprints = null;
        foreach (var (stamp, isPrevious) in retained)
        {
            var plaintext = isPrevious ? winner.Previous!.Value : winner.Value;
            byte[]? section = null;
            FingerprintSet? best = null;
            List<FingerprintSet> sets = [];
            foreach (var input in inputs)
            {
                if (input.Type == RecordType.Tombstone && input.Version.Equals(stamp))
                    throw new RecordConflictException($"the version {stamp} is a value in one copy and a delete in another");
                foreach (var (value, fingerprints) in Holdings(input, stamp))
                {
                    if (!value.AsSpan().SequenceEqual(plaintext))
                        throw new RecordConflictException($"two copies hold different values under the version {stamp}");
                    if (fingerprints is not null)
                        sets.Add(fingerprints);
                    if (input.Sealed is not null && input.Sealed.TryGetValue(stamp, out var candidate)
                        && (section is null || candidate.AsSpan().SequenceCompareTo(section) < 0))
                        section = candidate;
                }
            }
            foreach (var group in sets.GroupBy(f => f.VariantSetVersion))
            {
                var first = group.First();
                if (group.Any(f => !f.Equals(first)))
                    throw new RecordConflictException($"two copies hold different fingerprints of the version {stamp}");
                if (best is null || first.VariantSetVersion > best.VariantSetVersion)
                    best = first;
            }
            if (section is not null)
                sealedSections[stamp] = section;
            if (isPrevious)
                previousFingerprints = best;
            else
                currentFingerprints = best;
        }

        var write = inputs.Select(r => r.Write).Aggregate(Stamp.Max);
        var extensions = inputs
            .Where(r => r.Write.Equals(write))
            .Select(r => (r.Extensions, Encoded: EncodeExtensions(r.Extensions)))
            .Aggregate((x, y) => y.Encoded.AsSpan().SequenceCompareTo(x.Encoded) < 0 ? y : x)
            .Extensions;
        var burns = CanonicalBurns(inputs.SelectMany(r => r.Burns), version, isTombstone);
        return winner with
        {
            Write = write,
            Burns = burns,
            Type = TypeOf(isTombstone, version, burns),
            Previous = winner.Previous is null ? null : winner.Previous with { Fingerprints = previousFingerprints },
            Fingerprints = currentFingerprints,
            Extensions = extensions,
            Sealed = sealedSections.Count == 0 ? null : sealedSections,
        };
    }

    /// <summary>
    /// Brief T16-S1 ruling 11, the metadata-only path: <see cref="MergeAll"/>'s rules over metadata
    /// sections and still-encrypted value sections, with no plaintext. Fingerprints stand in for
    /// plaintext: two copies hold the same plaintext for a version when their sections are
    /// byte-identical, or when they share a variant-set version with equal sets (and no shared
    /// variant-set version with different sets). Where that can't be shown (no sets to compare, or
    /// sets that disagree), differing sections or any other disagreement are a
    /// <see cref="RecordConflictException"/>: the record is unreadable on this path (fail closed)
    /// until a full-load write converges its copies. Returns the merged metadata and the chosen
    /// section of each retained version (the ordinally smallest, as the full load picks).
    /// </summary>
    public static (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sealed) MergeAllMetadata(
        IReadOnlyList<(RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sealed)> inputs)
    {
        if (inputs.Count == 0)
            throw new ArgumentException("MergeAllMetadata needs at least one input", nameof(inputs));
        var recordId = inputs[0].Metadata.RecordId;
        if (inputs.Any(r => !r.Metadata.RecordId.AsSpan().SequenceEqual(recordId)))
            throw new ArgumentException("Only versions of one record can be merged", nameof(inputs));

        var version = inputs.Select(r => r.Metadata.Version).Aggregate(Stamp.Max);
        var tied = inputs.Where(r => r.Metadata.Version.Equals(version)).ToList();
        var winner = tied[0].Metadata;
        foreach (var (other, _) in tied.Skip(1))
        {
            if ((winner.Type == RecordType.Tombstone) != (other.Type == RecordType.Tombstone)
                || winner.CreatedMs != other.CreatedMs
                || winner.Name != other.Name
                || !Equals(winner.PreviousVersion, other.PreviousVersion))
                throw new RecordConflictException($"two copies share the version {version} but differ in content");
        }

        var isTombstone = winner.Type == RecordType.Tombstone;
        var sealedSections = new Dictionary<Stamp, byte[]>();
        FingerprintSet? currentFingerprints = null, previousFingerprints = null;
        foreach (var (stamp, _, isPrevious) in winner.RetainedVersions())
        {
            List<(FingerprintSet? Set, byte[] Section)> holders = [];
            foreach (var (metadata, sections) in inputs)
            {
                if (metadata.Type == RecordType.Tombstone && metadata.Version.Equals(stamp))
                    throw new RecordConflictException($"the version {stamp} is a value in one copy and a delete in another");
                foreach (var (held, set, _) in metadata.RetainedVersions())
                {
                    if (!held.Equals(stamp))
                        continue;
                    if (!sections.TryGetValue(stamp, out var section))
                        throw new RecordConflictException($"a copy lists the version {stamp} without its value section");
                    holders.Add((set, section));
                }
            }
            FingerprintSet? best = null;
            foreach (var group in holders.Where(h => h.Set is not null).Select(h => h.Set!).GroupBy(f => f.VariantSetVersion))
            {
                var first = group.First();
                if (group.Any(f => !f.Equals(first)))
                    throw new RecordConflictException($"two copies hold different fingerprints of the version {stamp}");
                if (best is null || first.VariantSetVersion > best.VariantSetVersion)
                    best = first;
            }
            for (var i = 0; i < holders.Count; i++)
            {
                for (var j = i + 1; j < holders.Count; j++)
                {
                    var (a, b) = (holders[i], holders[j]);
                    if (a.Section.AsSpan().SequenceEqual(b.Section))
                        continue;
                    // Different ciphertexts: equal only if fingerprints prove it (sets at one variant-set
                    // version were checked equal above).
                    if (a.Set is null || b.Set is null || a.Set.VariantSetVersion != b.Set.VariantSetVersion)
                        throw new RecordConflictException(
                            $"two copies hold different value sections of the version {stamp} and no fingerprints show them equal");
                }
            }
            sealedSections[stamp] = holders.Select(h => h.Section).Aggregate((x, y) => y.AsSpan().SequenceCompareTo(x) < 0 ? y : x);
            if (isPrevious)
                previousFingerprints = best;
            else
                currentFingerprints = best;
        }

        var write = inputs.Select(r => r.Metadata.Write).Aggregate(Stamp.Max);
        var extensions = inputs
            .Where(r => r.Metadata.Write.Equals(write))
            .Select(r => (r.Metadata.Extensions, Encoded: EncodeExtensions(r.Metadata.Extensions)))
            .Aggregate((x, y) => y.Encoded.AsSpan().SequenceCompareTo(x.Encoded) < 0 ? y : x)
            .Extensions;
        var burns = CanonicalBurns(inputs.SelectMany(r => r.Metadata.Burns), version, isTombstone);
        return (winner with
        {
            Write = write,
            Burns = burns,
            Type = TypeOf(isTombstone, version, burns),
            Fingerprints = currentFingerprints,
            PreviousFingerprints = previousFingerprints,
            Extensions = extensions,
        }, sealedSections);
    }

    /// <summary>The plaintexts (and their fingerprints) <paramref name="record"/> holds under <paramref name="stamp"/>.</summary>
    private static IEnumerable<(byte[] Value, FingerprintSet? Fingerprints)> Holdings(SecretRecord record, Stamp stamp)
    {
        if (record.Type != RecordType.Tombstone && record.Version.Equals(stamp))
            yield return (record.Value, record.Fingerprints);
        if (record.Previous is { } previous && previous.Version.Equals(stamp))
            yield return (previous.Value, previous.Fingerprints);
    }

    /// <summary>Two copies sharing the winning version stamp must be the same version.</summary>
    private static void RequireSameVersion(SecretRecord a, SecretRecord b)
    {
        var aTombstone = a.Type == RecordType.Tombstone;
        if (aTombstone != (b.Type == RecordType.Tombstone)
            || !a.Value.AsSpan().SequenceEqual(b.Value)
            || a.CreatedMs != b.CreatedMs
            || a.Name != b.Name
            || (a.Previous is null) != (b.Previous is null)
            || (a.Previous is { } pa && (!pa.Version.Equals(b.Previous!.Version) || !pa.Value.AsSpan().SequenceEqual(b.Previous.Value))))
            throw new RecordConflictException($"two copies share the version {a.Version} but differ in content");
    }

    /// <summary>The extension list as format 3 stores it (count, then type, length, data), for the tie order.</summary>
    private static byte[] EncodeExtensions(IReadOnlyList<RecordExtension> extensions)
    {
        var bytes = new byte[2 + extensions.Sum(e => 6 + e.Data.Length)];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, (ushort)extensions.Count);
        var offset = 2;
        foreach (var extension in extensions)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), extension.Type);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 2, 4), (uint)extension.Data.Length);
            extension.Data.CopyTo(bytes, offset + 6);
            offset += 6 + extension.Data.Length;
        }
        return bytes;
    }

    /// <summary>
    /// Brief T16-S1 ruling 11, validation per input: recomputes the fingerprint sets of
    /// <paramref name="record"/>'s retained values from their plaintext, for the variant-set version
    /// this build computes (<see cref="SecretVariants.CurrentSetVersion"/>), and refuses a set that
    /// doesn't match. Full loads call it on every decoded copy before merging, so a stored set can't
    /// claim fingerprints of a different value (which would hide it from redaction). A set of another
    /// variant-set version can't be recomputed here and is taken as it is.
    /// </summary>
    /// <exception cref="RecordConflictException">A stored set doesn't match its value.</exception>
    public static void ValidateFingerprints(SecretRecord record, FingerprintKeys keys)
    {
        if (record.Type != RecordType.Tombstone)
            Validate(record.Value, record.Fingerprints, keys);
        if (record.Previous is { } previous)
            Validate(previous.Value, previous.Fingerprints, keys);

        static void Validate(byte[] value, FingerprintSet? stored, FingerprintKeys keys)
        {
            if (stored is null || stored.VariantSetVersion != SecretVariants.CurrentSetVersion)
                return;
            if (!Fingerprinter.Compute(value, keys).Equals(stored))
                throw new RecordConflictException("a copy's fingerprints don't match its value");
        }
    }
}

/// <summary>
/// Brief T16-S1 ruling 11: the copies of one record can't be merged (two different values under one
/// version stamp, different fingerprint sets at one variant-set version, or fingerprints that don't
/// match their value). The store marks that record unreadable (warned, never merged, never
/// overwritten) and carries on with the others; the user removes the damaged copy.
/// </summary>
public sealed class RecordConflictException(string message) : TswapException(message);
