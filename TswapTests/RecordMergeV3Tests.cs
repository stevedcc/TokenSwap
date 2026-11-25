using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Fields;
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

    // Issue #311, task 2: the Fields extension merges per field; every other extension type keeps the whole-list rule.

    private static readonly FieldWho WhoA = new("0a0a0a0a", "u", Elevated: false, Terminal: false, By: null);

    private static RecordExtension FieldsExt(Stamp since, params FieldEntry[] entries) =>
        new(FieldsExtension.Type, FieldsCodec.Encode(new FieldSet(since, entries)));

    private static FieldEntry Field(string name, string value, Stamp changed, params FieldChange[] history) =>
        new(name, value, Deleted: false, changed, WhoA, history);

    [Fact]
    public void MergeAll_Tombstone_DropsFields_KeepsOtherExtensions()
    {
        var live = Rec(S(1000), "v", write: S(5000)) with
        {
            Extensions = [new RecordExtension(0x7777, [1]), FieldsExt(S(1000), Field("host", "db", S(4900)))],
        };
        // An older-format tombstone that kept a Fields extension: it doesn't survive either.
        var deleted = Tombstone(S(3000), write: S(3000)) with { Extensions = [FieldsExt(S(1000), Field("host", "db", S(1500)))] };

        var merged = MergeEveryOrder([live, deleted])!;

        Assert.Equal(RecordType.Tombstone, merged.Type);
        Assert.Equal([new RecordExtension(0x7777, [1])], merged.Extensions);
        Assert.Null(FieldsCodec.TryGet(merged.Extensions));
    }

    [Fact]
    public void MergeAll_LiveWithEmptyFields_KeepsSince()
    {
        // The copy with the newer write predates fields (no extension); the other has no fields left.
        var withFields = Rec(S(1000), "v", write: S(5000)) with { Extensions = [FieldsExt(S(1000))] };
        var withoutFields = Rec(S(1000), "v", write: S(6000)) with { Extensions = [new RecordExtension(0x7777, [2])] };

        var merged = MergeEveryOrder([withFields, withoutFields])!;

        var fields = FieldsCodec.TryGet(merged.Extensions);
        Assert.NotNull(fields); // rule 6: the empty extension stays, with its lineage stamp
        Assert.Equal(S(1000), fields.Since);
        Assert.Empty(fields.Entries);
        Assert.Equal([new RecordExtension(0x7777, [2]), FieldsExt(S(1000))], merged.Extensions);
    }

    /// <summary>
    /// MiMo r2 N1: the secret had a field, was deleted and re-created without fields (an empty
    /// extension anchoring the new life). Two stale copies of the first life, one with a newer write
    /// stamp than the re-creation (a burn on a machine that hadn't synced), must not bring the field back.
    /// </summary>
    [Fact]
    public void MergeAll_RecreatedWithoutFields_ThenTwoStaleCopies_NoOldFields()
    {
        var recreated = Rec(S(3000), "new", write: S(3000)) with { Extensions = [FieldsExt(S(3000))] };
        var stale = Rec(S(1000), "old", write: S(1200)) with { Extensions = [FieldsExt(S(1000), Field("host", "old-db", S(1100)))] };
        var staleBurned = RecordMerge.Normalize(Rec(S(1000), "old", write: S(3500)) with
        {
            Burns = [new BurnEntry(S(1000), S(3500), "seen")],
            Extensions = [FieldsExt(S(1000), Field("host", "old-db", S(1100)), Field("port", "5432", S(2000)))],
        });

        var merged = MergeEveryOrder([recreated, stale, staleBurned])!;

        Assert.Equal("new"u8.ToArray(), merged.Value);
        var fields = FieldsCodec.TryGet(merged.Extensions);
        Assert.NotNull(fields); // rule 6: the empty extension stays, with its lineage stamp
        Assert.Equal(S(3000), fields.Since);
        Assert.Empty(fields.Entries);
        Assert.Equal([FieldsExt(S(3000))], merged.Extensions);
    }

    [Fact]
    public void MergeAll_TwoIdenticalCopies_WritesNothing()
    {
        var x = Rec(S(2000), "v", write: S(2500)) with
        {
            Extensions =
            [
                new RecordExtension(0x7777, [7]),
                FieldsExt(S(2000), Field("host", "db", S(2400), new FieldChange("db0", S(2100), WhoA)),
                    new FieldEntry("port", null, Deleted: true, S(2300), WhoA, [])),
            ],
        };
        var copy = SecretRecordCodec.Decode(SecretRecordCodec.Encode(x, VaultKey, 3), VaultKey);

        var merged = RecordMerge.MergeAll([x, copy]);

        Assert.True(merged.SameState(x));
        Assert.True(merged.SameState(copy));
    }

    [Fact]
    public void MergeAll_OverCap_StaysReadable()
    {
        // Two legal copies, each with 40 fields of other names: 80 after the merge, over the 64-field cap.
        var onA = Rec(S(1000), "v", write: S(5000)) with
        {
            Extensions = [FieldsExt(S(1000), [.. Enumerable.Range(0, 40).Select(i => Field($"a{i:d2}", "x", S(4000)))])],
        };
        var onB = Rec(S(1000), "v", write: S(5000, OriginB)) with
        {
            Extensions = [FieldsExt(S(1000), [.. Enumerable.Range(0, 40).Select(i => Field($"b{i:d2}", "y", S(4000, OriginB)))])],
        };

        var merged = MergeEveryOrder([onA, onB])!;

        Assert.Equal(80, FieldsCodec.TryGet(merged.Extensions)!.Live.Count());
        Assert.True(80 > FieldRules.MaxLiveFields);
        var written = SecretRecordCodec.Decode(SecretRecordCodec.Encode(merged with { Write = S(6000) }, VaultKey, 3), VaultKey);
        Assert.Equal(80, FieldsCodec.TryGet(written.Extensions)!.Live.Count());
        Assert.True(RecordMerge.MergeAll([written, onA, onB]).SameState(merged));
    }

    private static (RecordMetadata, IReadOnlyDictionary<Stamp, byte[]>) MetaOf(SecretRecord r) => MetaOf(r, [1, 2, 3]);

    private static (RecordMetadata, IReadOnlyDictionary<Stamp, byte[]>) MetaOf(SecretRecord r, byte[] section) =>
        (new RecordMetadata(r.RecordId, r.Write, r.Type, r.Version, r.Name, r.CreatedMs, r.Burns, r.Fingerprints,
            r.Previous?.Version, r.Previous?.Fingerprints, r.Extensions),
         new Dictionary<Stamp, byte[]> { [r.Version] = section });

    // ------------------------------------------------------------------ brief T54 Task 2: base entries decide

    private const string NonAscii = "caf\u00e9-db-pass";

    private static FingerprintSet WithEntry(FingerprintSet set, VariantKind kind, Func<FingerprintEntry, FingerprintEntry> change) =>
        set with { Entries = [.. set.Entries.Select(e => e.Kind == kind ? change(e) : e)] };

    /// <summary>The entry as another machine's library might have computed it: same kind and length, another HMAC.</summary>
    private static FingerprintEntry OtherHmac(FingerprintEntry entry) => entry with { Hmac = new byte[FingerprintEntry.HmacLength] };

    /// <summary>The set an older tswap (variant set 1) computes for the same value: the base entries only.</summary>
    private static FingerprintSet VersionOne(FingerprintSet set) => new(1, [.. set.Entries.Where(e => e.Kind.BaseKind() == e.Kind)]);

    [Fact]
    public void MergeAll_CopiesWhoseFormEntriesDiffer_MergeToTheSortedUnion_OnBothPaths()
    {
        var mine = Rec(S(1000), NonAscii);
        var otherSet = WithEntry(mine.Fingerprints!, VariantKind.NfdPlain, OtherHmac);
        var other = mine with { Write = S(1500), Fingerprints = otherSet };
        var real = mine.Fingerprints!.Entries;
        var fake = otherSet.Entries.Single(e => e.Kind == VariantKind.NfdPlain);
        Assert.NotEqual(real.Single(e => e.Kind == VariantKind.NfdPlain), fake);
        // The zero HMAC sorts before the real one of the same kind and length.
        List<FingerprintEntry> expected =
        [
            .. real.Where(e => e.Kind.BaseKind() == e.Kind),
            .. real.Where(e => e.Kind.BaseKind() != e.Kind).SelectMany(e => e.Kind == VariantKind.NfdPlain ? new[] { fake, e } : [e]),
        ];

        var merged = MergeEveryOrder([mine, other])!;

        Assert.Equal(new FingerprintSet(SecretVariants.CurrentSetVersion, expected), merged.Fingerprints);
        Assert.Equal(merged.Fingerprints, RecordMerge.MergeAllMetadata([MetaOf(mine), MetaOf(other)]).Metadata.Fingerprints);
        Assert.Equal(merged.Fingerprints, RecordMerge.MergeAllMetadata([MetaOf(other), MetaOf(mine)]).Metadata.Fingerprints);
    }

    [Fact]
    public void MergeAll_CopiesWhosePlainEntriesDiffer_StillConflict_OnBothPaths()
    {
        var mine = Rec(S(1000), NonAscii);
        var lying = mine with { Write = S(1500), Fingerprints = WithEntry(mine.Fingerprints!, VariantKind.Plain, OtherHmac) };

        Assert.Null(MergeEveryOrder([mine, lying]));
        Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAllMetadata([MetaOf(mine), MetaOf(lying)]));
        Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAllMetadata([MetaOf(lying), MetaOf(mine)]));
    }

    /// <summary>
    /// An older tswap's copy (variant set 1) and this build's (2) of one value, with different value sections: the
    /// base entries prove the sections hold one value, so both paths merge and pick the same (version 2) set.
    /// </summary>
    [Fact]
    public void MergeAll_VersionOneAndVersionTwoCopies_WithDifferentSections_Merge_AndPickTheSameSet()
    {
        var v2 = Rec(S(1000), NonAscii) with { Sealed = Sections((S(1000), [1, 2, 3])) };
        var v1 = v2 with { Write = S(1200), Fingerprints = VersionOne(v2.Fingerprints!), Sealed = Sections((S(1000), [4, 5, 6])) };

        var full = MergeEveryOrder([v1, v2])!;
        var meta = RecordMerge.MergeAllMetadata([MetaOf(v1, [4, 5, 6]), MetaOf(v2, [1, 2, 3])]).Metadata;
        var metaReversed = RecordMerge.MergeAllMetadata([MetaOf(v2, [1, 2, 3]), MetaOf(v1, [4, 5, 6])]).Metadata;

        Assert.Equal(v2.Fingerprints, full.Fingerprints);
        Assert.Equal(v2.Fingerprints, meta.Fingerprints);
        Assert.Equal(v2.Fingerprints, metaReversed.Fingerprints);
    }

    [Fact]
    public void MergeAllMetadata_VersionOneAndVersionTwoCopies_WithDifferentPlainEntries_Conflict()
    {
        var v2 = Rec(S(1000), NonAscii);
        var v1 = v2 with { Write = S(1200), Fingerprints = WithEntry(VersionOne(v2.Fingerprints!), VariantKind.Plain, OtherHmac) };

        Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAllMetadata([MetaOf(v1, [4, 5, 6]), MetaOf(v2, [1, 2, 3])]));
        Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAllMetadata([MetaOf(v2, [1, 2, 3]), MetaOf(v1, [4, 5, 6])]));
    }

    [Fact]
    public void Validate_AFormEntryThatDiffersFromTheRecomputation_IsAccepted_ABaseEntryIsNot()
    {
        using var keys = FingerprintKeys.Derive(VaultKey);
        var good = Rec(S(1000), NonAscii);
        var otherLibrary = good with { Fingerprints = WithEntry(good.Fingerprints!, VariantKind.NfdPlain, OtherHmac) };
        var lyingBase64 = good with { Fingerprints = WithEntry(good.Fingerprints!, VariantKind.Base64, OtherHmac) };
        var ascii = Rec(S(1000), "ascii-value");
        var lyingAsciiVersionOne = ascii with { Fingerprints = WithEntry(ascii.Fingerprints! with { VariantSetVersion = 1 }, VariantKind.Plain, OtherHmac) };

        RecordMerge.ValidateFingerprints(otherLibrary, keys);
        Assert.Throws<RecordConflictException>(() => RecordMerge.ValidateFingerprints(lyingBase64, keys));
        // A version 1 set that proves its value ASCII is current, so it is checked too.
        Assert.Throws<RecordConflictException>(() => RecordMerge.ValidateFingerprints(lyingAsciiVersionOne, keys));
    }

    /// <summary>
    /// T54 fix round 1 (MiMo M1, owner decision, controller ruling (b)): a set of every version this build knows (1 to
    /// CurrentSetVersion) has its base entries checked, so a version 1 set of a non-ASCII value that lies about its
    /// value is refused; a true one passes. Versions it doesn't know stay "taken as is" (T16-S1).
    /// </summary>
    [Fact]
    public void Validate_AVersionOneSetOfANonAsciiValue_HasItsBaseEntriesChecked()
    {
        using var keys = FingerprintKeys.Derive(VaultKey);
        var good = Rec(S(1000), NonAscii);
        var versionOne = good with { Fingerprints = VersionOne(good.Fingerprints!) };
        var lying = good with { Fingerprints = WithEntry(VersionOne(good.Fingerprints!), VariantKind.Plain, OtherHmac) };

        RecordMerge.ValidateFingerprints(versionOne, keys);
        Assert.Throws<RecordConflictException>(() => RecordMerge.ValidateFingerprints(lying, keys));
    }

    [Fact]
    public void Union_IsOrderIndependent_IdempotentAndRefusesOtherBaseEntriesOrVersions()
    {
        var set = Fp(NonAscii);
        var other = WithEntry(set, VariantKind.NfdPlain, OtherHmac);

        Assert.Equal(set, FingerprintSet.Union(set, set));
        Assert.Equal(FingerprintSet.Union(set, other), FingerprintSet.Union(other, set));
        Assert.True(set.SameBaseEntries(other));
        Assert.True(set.SameBaseEntries(VersionOne(set)));
        Assert.False(set.SameBaseEntries(WithEntry(set, VariantKind.Base64Url, OtherHmac)));
        Assert.Throws<ArgumentException>(() => FingerprintSet.Union(set, WithEntry(set, VariantKind.Plain, OtherHmac)));
        Assert.Throws<ArgumentException>(() => FingerprintSet.Union(set, VersionOne(set)));
    }

    /// <summary>Review I1: a Fields extension that can't be decoded is a conflict (that record unreadable), on both paths.</summary>
    [Theory]
    [InlineData(new byte[] { 1 })] // version 1, truncated
    [InlineData(new byte[] { 2, 0, 0 })]
    public void MergeAll_MalformedFields_IsAConflict_OnBothPaths(byte[] data)
    {
        var damaged = Rec(S(1000), "v", write: S(5000)) with { Extensions = [new RecordExtension(FieldsExtension.Type, data)] };
        var good = Rec(S(1000), "v", write: S(4000)) with { Extensions = [FieldsExt(S(1000), Field("host", "db", S(1500)))] };

        foreach (var inputs in new[] { new[] { damaged }, [damaged, good], [good, damaged] })
        {
            var full = Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAll(inputs));
            Assert.Contains("fields extension", full.Message);
            var meta = Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAllMetadata([.. inputs.Select(MetaOf)]));
            Assert.Equal(full.Message, meta.Message);
        }
    }

    /// <summary>Review M1 ruling: the merged Fields extension keeps its place in the list.</summary>
    [Fact]
    public void MergeAll_FieldsFirst_KeepsItsPosition()
    {
        var x = Rec(S(2000), "v", write: S(2500)) with
        {
            Extensions = [FieldsExt(S(2000), Field("host", "db", S(2400))), new RecordExtension(0x7777, [7])],
        };
        var copy = SecretRecordCodec.Decode(SecretRecordCodec.Encode(x, VaultKey, 3), VaultKey);

        var merged = MergeEveryOrder([x, copy])!;

        Assert.True(merged.SameState(x));
        Assert.Equal(x.Extensions, merged.Extensions);
        Assert.Equal([FieldsExtension.Type, (ushort)0x7777], merged.Extensions.Select(e => e.Type));
        var (metaMerged, _) = RecordMerge.MergeAllMetadata([MetaOf(x), MetaOf(copy)]);
        Assert.Equal(x.Extensions, metaMerged.Extensions);
        // Merged with a copy whose Fields differ, the place stays too.
        var edited = x with { Write = S(2600), Extensions = [FieldsExt(S(2000), Field("host", "db2", S(2550))), new RecordExtension(0x7777, [7])] };
        Assert.Equal([FieldsExtension.Type, (ushort)0x7777], MergeEveryOrder([x, edited])!.Extensions.Select(e => e.Type));
    }
}
