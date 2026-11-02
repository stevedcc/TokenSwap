using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 5 (ruling 11): <see cref="RecordMerge.MergeAll"/> merges every copy of a
/// record in one step, its result doesn't depend on the order of the copies, and two different
/// values under one version stamp fail closed (<see cref="RecordConflictException"/>) instead of
/// being picked silently.
/// </summary>
public class RecordMergeV3Tests
{
    private static readonly byte[] VaultKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] OriginA = Enumerable.Repeat((byte)0x0A, 16).ToArray();
    private static readonly byte[] OriginB = Enumerable.Repeat((byte)0x0B, 16).ToArray();
    private static readonly byte[] Id = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(VaultKey), "s");

    private static Stamp S(long ms, byte[]? origin = null) => new(new Hlc(ms, 0), origin ?? OriginA);

    private static FingerprintSet Fp(string value)
    {
        using var keys = FingerprintKeys.Derive(VaultKey);
        return Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys);
    }

    private static SecretRecord Rec(Stamp version, string value, Stamp? write = null, (Stamp Version, string Value)? previous = null,
        bool fingerprints = true, IReadOnlyDictionary<Stamp, byte[]>? sealedSections = null, params BurnEntry[] burns) =>
        RecordMerge.Normalize(new SecretRecord(Id, write ?? version, RecordType.Value, version, "s", 1, Encoding.UTF8.GetBytes(value), burns,
            previous is { } p ? new PreviousValue(p.Version, Encoding.UTF8.GetBytes(p.Value), fingerprints ? Fp(p.Value) : null) : null)
        {
            Fingerprints = fingerprints ? Fp(value) : null,
            Sealed = sealedSections,
        });

    private static Dictionary<Stamp, byte[]> Sections(params (Stamp Stamp, byte[] Bytes)[] sections) =>
        sections.ToDictionary(s => s.Stamp, s => s.Bytes);

    private static bool SealedEqual(IReadOnlyDictionary<Stamp, byte[]>? a, IReadOnlyDictionary<Stamp, byte[]>? b)
    {
        if ((a?.Count ?? 0) != (b?.Count ?? 0)) return false;
        if (a is null || b is null) return true;
        return a.All(kv => b.TryGetValue(kv.Key, out var other) && other.AsSpan().SequenceEqual(kv.Value));
    }

    /// <summary>The same merged record: state, write stamp and sealed sections.</summary>
    private static bool Same(SecretRecord a, SecretRecord b) => a.SameState(b) && a.Write.Equals(b.Write) && SealedEqual(a.Sealed, b.Sealed);

    private static IEnumerable<List<T>> Permutations<T>(IReadOnlyList<T> items)
    {
        if (items.Count <= 1)
        {
            yield return [.. items];
            yield break;
        }
        for (var i = 0; i < items.Count; i++)
        {
            var rest = items.Where((_, j) => j != i).ToList();
            foreach (var tail in Permutations(rest))
                yield return [items[i], .. tail];
        }
    }

    /// <summary>MergeAll in every order: all agree (returned) or all conflict (null).</summary>
    private static SecretRecord? MergeEveryOrder(IReadOnlyList<SecretRecord> inputs)
    {
        SecretRecord? first = null;
        bool? conflicted = null;
        foreach (var order in Permutations(inputs))
        {
            SecretRecord? result = null;
            try
            {
                result = RecordMerge.MergeAll(order);
            }
            catch (RecordConflictException)
            {
            }
            var isConflict = result is null;
            conflicted ??= isConflict;
            Assert.True(conflicted == isConflict, "a conflict in one order but not in another");
            if (result is null) continue;
            first ??= result;
            Assert.True(Same(first, result), "MergeAll depends on the order of its inputs");
        }
        return first;
    }

    [Fact]
    public void MergeAll_Empty_Throws()
    {
        Assert.Throws<ArgumentException>(() => RecordMerge.MergeAll([]));
    }

    [Fact]
    public void Merge_IsMergeAllOfTwo()
    {
        var a = Rec(S(1000), "a");
        var b = Rec(S(2000), "b", previous: (S(1000), "a"));

        Assert.True(Same(RecordMerge.MergeAll([a, b]), RecordMerge.Merge(a, b)));
        Assert.True(Same(RecordMerge.MergeAll([b, a]), RecordMerge.Merge(a, b)));
    }

    [Fact]
    public void MergeAll_KeepsFingerprintsOfTheRetainedVersions()
    {
        var older = Rec(S(1000), "v1", previous: (S(500), "v0"));
        var newer = Rec(S(2000), "v2", previous: (S(1000), "v1"));

        var merged = MergeEveryOrder([older, newer])!;

        Assert.Equal(Fp("v2"), merged.Fingerprints);
        Assert.Equal(S(1000), merged.Previous!.Version);
        Assert.Equal(Fp("v1"), merged.Previous.Fingerprints);
    }

    [Fact]
    public void MergeAll_FingerprintsOfAVersion_ComeFromAnyInputHoldingIt()
    {
        // The newer copy lost its previous value's fingerprints (it was converted from format 2);
        // the older copy holds that version as its current value, with fingerprints.
        var older = Rec(S(1000), "v1");
        var newer = Rec(S(2000), "v2", previous: (S(1000), "v1")) is var n
            ? n with { Previous = n.Previous! with { Fingerprints = null } }
            : null!;

        var merged = MergeEveryOrder([older, newer])!;

        Assert.Equal(Fp("v1"), merged.Previous!.Fingerprints);
    }

    [Fact]
    public void MergeAll_PrefersTheNewerVariantSet()
    {
        var known = Rec(S(1000), "v");
        var newer = known with { Fingerprints = new FingerprintSet(9, [new FingerprintEntry(VariantKind.Plain, 1, 7, new byte[16])]) };
        var none = known with { Fingerprints = null };

        Assert.Equal(9, MergeEveryOrder([known, newer, none])!.Fingerprints!.VariantSetVersion);
        Assert.Equal(Fp("v"), MergeEveryOrder([known, none])!.Fingerprints);
        Assert.Null(MergeEveryOrder([none, none])!.Fingerprints);
    }

    [Fact]
    public void MergeAll_PicksOneSectionPerVersion_DropsUnretained()
    {
        byte[] sectionV0 = [5, 5, 5], sectionV1 = [1, 1, 1], sectionV2 = [2, 2, 2];
        var older = Rec(S(1000), "v1", previous: (S(500), "v0"), sealedSections: Sections((S(1000), sectionV1), (S(500), sectionV0)));
        var newer = Rec(S(2000), "v2", previous: (S(1000), "v1"), sealedSections: Sections((S(2000), sectionV2)));

        var merged = MergeEveryOrder([older, newer])!;

        Assert.Equal(2, merged.Sealed!.Count);
        Assert.Equal(sectionV2, merged.Sealed[S(2000)]);
        Assert.Equal(sectionV1, merged.Sealed[S(1000)]); // the previous version's section, from the copy holding it as current
        Assert.False(merged.Sealed.ContainsKey(S(500)));
    }

    [Fact]
    public void MergeAll_EqualPlaintextDifferentSections_KeepsTheOrdinallySmaller()
    {
        byte[] small = [0x01, 0xFF, 0xFF], large = [0x02, 0x00], mid = [0x01, 0xFF, 0xFF, 0x00];
        var a = Rec(S(1000), "v", write: S(3000), sealedSections: Sections((S(1000), large)));
        var b = Rec(S(1000), "v", write: S(4000, OriginB), sealedSections: Sections((S(1000), small)));
        var c = Rec(S(1000), "v", write: S(2000), sealedSections: Sections((S(1000), mid)));

        var merged = MergeEveryOrder([a, b, c])!;

        Assert.Equal(small, merged.Sealed![S(1000)]);
        Assert.Equal(S(4000, OriginB), merged.Write);
    }

    [Fact]
    public void MergeAll_SameStampDifferentValues_Conflicts()
    {
        // Current version.
        Assert.Null(MergeEveryOrder([Rec(S(1000), "x"), Rec(S(1000), "y")]));
        Assert.Throws<RecordConflictException>(() => RecordMerge.Merge(Rec(S(1000), "x"), Rec(S(1000), "y")));
        // Previous version (retained by the winner): same current, previous values differ under one stamp.
        Assert.Null(MergeEveryOrder([Rec(S(2000), "v", previous: (S(1000), "p1")), Rec(S(2000), "v", previous: (S(1000), "p2"))]));
        // A retained previous version held as another copy's current value, with a different plaintext.
        Assert.Null(MergeEveryOrder([Rec(S(2000), "v", previous: (S(1000), "p1")), Rec(S(1000), "p2")]));
        // Tied winners disagreeing on previous presence, created time, name, or tombstone-ness.
        Assert.Null(MergeEveryOrder([Rec(S(2000), "v", previous: (S(1000), "p")), Rec(S(2000), "v")]));
        Assert.Null(MergeEveryOrder([Rec(S(2000), "v"), Rec(S(2000), "v") with { CreatedMs = 2 }]));
        Assert.Null(MergeEveryOrder([Rec(S(2000), "v"), Rec(S(2000), "v") with { Name = "t" }]));
        Assert.Null(MergeEveryOrder([Rec(S(2000), "v"), Tombstone(S(2000))]));
    }

    private static SecretRecord Tombstone(Stamp version, Stamp? write = null) =>
        RecordMerge.Normalize(new SecretRecord(Id, write ?? version, RecordType.Tombstone, version, "s", 1, [], []));

    [Fact]
    public void MergeAll_DamageInASupersededVersion_IsIgnored()
    {
        var a = Rec(S(1000), "x");
        var b = Rec(S(1000), "y");
        var winner = Rec(S(3000), "z", previous: (S(2000), "w"));

        var merged = MergeEveryOrder([a, b, winner])!;

        Assert.Equal("z"u8.ToArray(), merged.Value);
        Assert.Equal("w"u8.ToArray(), merged.Previous!.Value);
        // And a tombstone superseding damage.
        Assert.Equal(RecordType.Tombstone, MergeEveryOrder([a, b, Tombstone(S(3000))])!.Type);
    }

    [Fact]
    public void MergeAll_SameUnknownVariantSetVersionDifferentEntries_Conflicts()
    {
        var baseRecord = Rec(S(1000), "v");
        var a = baseRecord with { Fingerprints = new FingerprintSet(9, [new FingerprintEntry(VariantKind.Plain, 1, 7, new byte[16])]) };
        var b = baseRecord with { Fingerprints = new FingerprintSet(9, [new FingerprintEntry(VariantKind.Plain, 1, 8, new byte[16])]) };

        Assert.Null(MergeEveryOrder([a, b]));
        Assert.Null(MergeEveryOrder([a, b, baseRecord]));
        Assert.NotNull(MergeEveryOrder([a, a, baseRecord]));
    }

    [Fact]
    public void MergeAll_ExtensionsFollowTheLargestWriteStamp()
    {
        var older = Rec(S(1000), "v", write: S(5000)) with { Extensions = [new RecordExtension(0x7777, [1])] };
        var newerWrite = Rec(S(1000), "v", write: S(6000)) with { Extensions = [new RecordExtension(0x7777, [2]), new RecordExtension(1, [])] };
        var newerVersionOlderWrite = Rec(S(2000), "w", write: S(5500), previous: (S(1000), "v")) with { Extensions = [] };

        Assert.Equal(newerWrite.Extensions, MergeEveryOrder([older, newerWrite])!.Extensions);
        // The write stamp decides, not the version: the winning version's copy has an older write.
        var merged = MergeEveryOrder([older, newerWrite, newerVersionOlderWrite])!;
        Assert.Equal("w"u8.ToArray(), merged.Value);
        Assert.Equal(newerWrite.Extensions, merged.Extensions);
        // Equal write stamps: the ordinally smaller encoded list (count 2 LE | type 2 LE | length 4 LE | data):
        // 01 00 | 01 00 ... sorts before 01 00 | 02 00 ..., although tieB's data is longer.
        var tieA = Rec(S(1000), "v", write: S(7000)) with { Extensions = [new RecordExtension(0x0002, [9])] };
        var tieB = Rec(S(1000), "v", write: S(7000)) with { Extensions = [new RecordExtension(0x0001, [9, 9])] };
        Assert.Equal(tieB.Extensions, MergeEveryOrder([tieA, tieB])!.Extensions);
    }

    [Fact]
    public void MergeAll_BurnsAreTheUnion()
    {
        var a = Rec(S(1000), "v", burns: new BurnEntry(S(1000), S(1500), "one"));
        var b = Rec(S(1000), "v", write: S(1200), burns: new BurnEntry(S(1000), S(1400, OriginB), "two"));

        var merged = MergeEveryOrder([a, b])!;

        Assert.Equal(RecordType.Burned, merged.Type);
        Assert.Equal("two", Assert.Single(merged.Burns).Reason); // the earliest burn of a version wins (#35)
    }

    [Fact]
    public void Validate_TamperedFingerprintSet_IsRejected()
    {
        using var keys = FingerprintKeys.Derive(VaultKey);
        var good = Rec(S(2000), "v", previous: (S(1000), "p"));
        var tamperedCurrent = good with { Fingerprints = Fp("other") };
        var tamperedPrevious = good with { Previous = good.Previous! with { Fingerprints = Fp("other") } };
        var unknownVersion = good with { Fingerprints = new FingerprintSet(9, []) };

        RecordMerge.ValidateFingerprints(good, keys);
        RecordMerge.ValidateFingerprints(good with { Fingerprints = null }, keys);
        RecordMerge.ValidateFingerprints(unknownVersion, keys); // a set this build can't recompute is taken as is
        Assert.Throws<RecordConflictException>(() => RecordMerge.ValidateFingerprints(tamperedCurrent, keys));
        Assert.Throws<RecordConflictException>(() => RecordMerge.ValidateFingerprints(tamperedPrevious, keys));
    }

    [Fact]
    public void MergeAll_ConcurrentConversion_ConvergesOnOneSection()
    {
        // One v2 record converted to v3 by two machines: different write stamps, different sections.
        var v2 = SecretRecordCodec.Decode(
            SecretRecordCodec.Encode(Rec(S(1000), "the-value", fingerprints: false), VaultKey, KeyringFormat.RecordFormatVersionV2), VaultKey);
        var onA = SecretRecordCodec.Decode(SecretRecordCodec.Encode(v2 with { Write = S(5000), Fingerprints = Fp("the-value") }, VaultKey, 3), VaultKey);
        var onB = SecretRecordCodec.Decode(SecretRecordCodec.Encode(v2 with { Write = S(5000, OriginB), Fingerprints = Fp("the-value") }, VaultKey, 3), VaultKey);
        Assert.NotEqual(onA.Sealed![S(1000)], onB.Sealed![S(1000)]);

        var merged = MergeEveryOrder([onA, onB])!;

        var expected = onA.Sealed[S(1000)].AsSpan().SequenceCompareTo(onB.Sealed[S(1000)]) < 0 ? onA.Sealed[S(1000)] : onB.Sealed[S(1000)];
        Assert.Equal(expected, merged.Sealed![S(1000)]);
        Assert.Equal(S(5000, OriginB), merged.Write);
        // The merged record encodes and decodes with that very section.
        var written = SecretRecordCodec.Decode(SecretRecordCodec.Encode(merged with { Write = S(6000) }, VaultKey, 3), VaultKey);
        Assert.Equal(expected, written.Sealed![S(1000)]);
        Assert.Equal("the-value"u8.ToArray(), written.Value);
        // A fixed point: merging the result with either input changes nothing.
        Assert.True(Same(merged, RecordMerge.MergeAll([merged, onA, onB])));
    }

    [Fact]
    public void MergeAll_IsIdempotent()
    {
        var x = Rec(S(2000), "v", previous: (S(1000), "p"), sealedSections: Sections((S(2000), [3]), (S(1000), [4])))
            with { Extensions = [new RecordExtension(5, [5])] };

        Assert.True(Same(x, RecordMerge.MergeAll([x, x])));
        Assert.True(Same(x, RecordMerge.MergeAll([x])));
    }

    /// <summary>
    /// The property: for random lists of 1-4 copies, every permutation gives the same result or the
    /// same conflict, and the merge is idempotent. The generator deliberately draws same-stamp
    /// different values (current and previous), damage in superseded versions, equal plaintexts
    /// with different sections, null, known and unknown fingerprint set versions, and colliding
    /// extension types with different data under different write stamps.
    /// </summary>
    [Fact]
    public void MergeAll_RandomCopies_OrderIndependentAndIdempotent()
    {
        var random = new Random(5_11);
        Stamp[] versions = [S(1000), S(1000, OriginB), S(2000), S(3000)];
        Stamp[] writes = [S(5000), S(5000, OriginB), S(6000), S(7000)];
        string[] values = ["a", "b", "a"]; // "a" twice: equal plaintexts are common
        byte[][] sectionPool = [[1], [1, 0], [0, 9], [2], [1]];
        var conflicts = 0;
        var merges = 0;

        for (var round = 0; round < 400; round++)
        {
            var count = random.Next(1, 5);
            List<SecretRecord> inputs = [];
            for (var i = 0; i < count; i++)
            {
                var vi = random.Next(versions.Length);
                var version = versions[vi];
                SecretRecord record;
                if (random.Next(8) == 0)
                {
                    record = Tombstone(version, writes[random.Next(writes.Length)]);
                }
                else
                {
                    var value = values[random.Next(values.Length)];
                    (Stamp, string)? previous = vi > 0 && random.Next(2) == 0 ? (versions[random.Next(vi)], values[random.Next(values.Length)]) : null;
                    if (previous is { } p && p.Item1.Equals(version)) previous = null;
                    var sections = new Dictionary<Stamp, byte[]>();
                    if (random.Next(2) == 0) sections[version] = sectionPool[random.Next(sectionPool.Length)];
                    if (previous is { } pp && random.Next(2) == 0) sections[pp.Item1] = sectionPool[random.Next(sectionPool.Length)];
                    record = Rec(version, value, writes[random.Next(writes.Length)], previous, fingerprints: random.Next(3) != 0,
                        sealedSections: sections.Count == 0 ? null : sections);
                    switch (random.Next(6))
                    {
                        case 0:
                            record = record with { Fingerprints = new FingerprintSet(9, [new FingerprintEntry(VariantKind.Plain, 1, (ulong)random.Next(2), new byte[16])]) };
                            break;
                        case 1 when record.Previous is not null:
                            record = record with { Previous = record.Previous with { Fingerprints = null } };
                            break;
                    }
                    if (random.Next(3) == 0)
                        record = record with { Burns = RecordMerge.CanonicalBurns([new BurnEntry(version, writes[random.Next(writes.Length)], "r")], version, false), Type = RecordType.Burned };
                }
                if (random.Next(2) == 0)
                    record = record with { Extensions = [new RecordExtension(0x7777, [(byte)random.Next(3)])] };
                inputs.Add(record);
            }

            var merged = MergeEveryOrder(inputs);
            if (merged is null)
            {
                conflicts++;
                continue;
            }
            merges++;
            Assert.True(Same(merged, RecordMerge.MergeAll([.. inputs, merged])), $"round {round}: MergeAll([.. xs, MergeAll(xs)]) != MergeAll(xs)");
            Assert.True(Same(merged, RecordMerge.MergeAll([merged, merged])), $"round {round}: MergeAll([x, x]) != x");
            foreach (var input in inputs)
                if (RecordMerge.MergeAll([input]) is var single)
                    Assert.True(Same(single, RecordMerge.MergeAll([input, input])), $"round {round}: not idempotent on an input");
        }

        // The generator must exercise both outcomes.
        Assert.True(conflicts > 20, $"only {conflicts} conflicts");
        Assert.True(merges > 100, $"only {merges} merges");
    }
}
