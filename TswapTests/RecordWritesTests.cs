using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 2: the write rules on metadata and held sections (<see cref="RecordWrites"/>),
/// which decrypt nothing, against <see cref="RecordVaultStore.NextRecord"/>, the rules
/// <see cref="RecordVaultStore.SaveSecrets"/> applies to plaintext; and the metadata merge against
/// the plaintext merge on random copy sets.
/// </summary>
public sealed class RecordWritesTests
{
    private static readonly byte[] Key = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];
    private static readonly byte[] OriginA = [.. Enumerable.Repeat((byte)0xA1, 16)];
    private static readonly byte[] OriginB = [.. Enumerable.Repeat((byte)0xB2, 16)];
    private static readonly DateTime Created = new(2025, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    private static byte[] IdOf(string name) => FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(Key), name);

    private static Stamp At(long ms, uint logical = 0, byte[]? origin = null) => new(new Hlc(ms, logical), origin ?? OriginA);

    private static FingerprintSet Fp(byte[] value) => RecordVaultTestSupport.Fingerprints(Key, value);

    private static byte[] Section() => RandomNumberGenerator.GetBytes(12 + 16 + 256);

    /// <summary>A record's metadata as format 3 stores it.</summary>
    private static RecordMetadata Meta(SecretRecord r) =>
        new(r.RecordId, r.Write, r.Type, r.Version, r.Name, r.CreatedMs, r.Burns, r.Fingerprints, r.Previous?.Version, r.Previous?.Fingerprints, r.Extensions);

    private static void AssertSame(RecordMetadata expected, RecordMetadata actual, string because = "")
    {
        Assert.True(expected.RecordId.AsSpan().SequenceEqual(actual.RecordId), because + ": record id");
        Assert.True(expected.Write.Equals(actual.Write), because + ": write stamp");
        Assert.True(expected.Type == actual.Type, $"{because}: type {expected.Type} vs {actual.Type}");
        Assert.True(expected.Version.Equals(actual.Version), because + ": version");
        Assert.True(expected.Name == actual.Name, because + ": name");
        Assert.True(expected.CreatedMs == actual.CreatedMs, because + ": created");
        Assert.True(expected.Burns.SequenceEqual(actual.Burns), because + ": burns");
        Assert.True(Equals(expected.Fingerprints, actual.Fingerprints), because + ": fingerprints");
        Assert.True(Equals(expected.PreviousVersion, actual.PreviousVersion), because + ": previous version");
        Assert.True(Equals(expected.PreviousFingerprints, actual.PreviousFingerprints), because + ": previous fingerprints");
        Assert.True(expected.Extensions.SequenceEqual(actual.Extensions), because + ": extensions");
    }

    private static SecretRecord Live(string value = "v1", PreviousValue? previous = null, IReadOnlyList<BurnEntry>? burns = null)
    {
        var version = At(2_000);
        var bytes = Encoding.UTF8.GetBytes(value);
        var sealedSections = new Dictionary<Stamp, byte[]> { [version] = Section() };
        if (previous is not null)
            sealedSections[previous.Version] = Section();
        return RecordMerge.Normalize(new SecretRecord(IdOf("s"), At(2_001), RecordType.Value, version, "s", 1_000, bytes, burns ?? [], previous)
        {
            Fingerprints = Fp(bytes),
            Sealed = sealedSections,
        });
    }

    private static (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sections) NewVersionOf(SecretRecord state, string value,
        bool restored = false, DateTime? importedBurnAt = null, string? reason = null) =>
        RecordWrites.NewVersion(Meta(state), state.Sealed ?? new Dictionary<Stamp, byte[]>(), state.RecordId, state.Name, At(5_000),
            Section(), Fp(Encoding.UTF8.GetBytes(value)), restored, Created, importedBurnAt, reason, OriginA);

    [Fact]
    public void NewVersion_OverALiveRecord_KeepsThePreviousSectionAndSet_DropsTheOlderPrevious()
    {
        var old = new PreviousValue(At(1_500), "v0"u8.ToArray(), Fp("v0"u8.ToArray()));
        var state = Live(previous: old, burns: [new BurnEntry(At(2_000), At(2_500), "seen")]);

        var (metadata, sections) = NewVersionOf(state, "v2");

        Assert.Equal(At(5_000), metadata.Version);
        Assert.Equal(RecordType.Value, metadata.Type);
        Assert.Equal(At(2_000), metadata.PreviousVersion);
        Assert.Equal(state.Fingerprints, metadata.PreviousFingerprints);
        Assert.Equal(Fp("v2"u8.ToArray()), metadata.Fingerprints);
        Assert.Equal(state.Sealed![At(2_000)], sections[At(2_000)]);
        Assert.False(sections.ContainsKey(At(1_500)));
        Assert.Equal(2, sections.Count);
        Assert.Equal(1_000, metadata.CreatedMs);
        // The outstanding burn of the replaced version is history now.
        var burn = Assert.Single(metadata.Burns);
        Assert.Equal(At(2_000), burn.Version);
        Assert.Null(SecretInfo.From(metadata)!.BurnedAt);
        Assert.Single(SecretInfo.From(metadata)!.History);
    }

    [Fact]
    public void NewVersion_OverATombstone_TakesTheCreatedTimeFromTheInput_KeepsBurns_NoPrevious()
    {
        var tombstone = RecordVaultStore.Tombstone(Live(burns: [new BurnEntry(At(2_000), At(2_500), "seen")]), At(3_000));

        var (metadata, sections) = NewVersionOf(tombstone, "v2");

        Assert.Equal(new DateTimeOffset(Created).ToUnixTimeMilliseconds(), metadata.CreatedMs);
        Assert.Null(metadata.PreviousVersion);
        Assert.Single(sections);
        Assert.Equal(new BurnEntry(At(2_000), At(2_500), "seen"), Assert.Single(metadata.Burns));
        Assert.Equal(RecordType.Value, metadata.Type);
    }

    [Fact]
    public void Burn_OfTheCurrentVersion_LeavesTheSectionsAndSetsAlone()
    {
        var state = Live(previous: new PreviousValue(At(1_500), "v0"u8.ToArray(), Fp("v0"u8.ToArray())));

        var burned = RecordWrites.Burn(Meta(state), At(4_000), "leaked")!;

        Assert.Equal(RecordType.Burned, burned.Type);
        Assert.Equal(new BurnEntry(At(2_000), At(4_000), "leaked"), Assert.Single(burned.Burns));
        Assert.Equal(state.Fingerprints, burned.Fingerprints);
        Assert.Equal(At(1_500), burned.PreviousVersion);
        Assert.Equal(state.Version, burned.Version);
        Assert.Null(RecordWrites.Burn(burned, At(4_500), "again"));
    }

    [Fact]
    public void Tombstone_HasNoVersionsOrSets_KeepsBurnsAsHistory()
    {
        var state = Live(previous: new PreviousValue(At(1_500), "v0"u8.ToArray(), Fp("v0"u8.ToArray())),
            burns: [new BurnEntry(At(2_000), At(2_500), "seen")]);

        var tombstone = RecordWrites.Tombstone(Meta(state), At(6_000));

        Assert.Equal(RecordType.Tombstone, tombstone.Type);
        Assert.Equal(At(6_000), tombstone.Version);
        Assert.Null(tombstone.Fingerprints);
        Assert.Null(tombstone.PreviousVersion);
        Assert.Null(tombstone.PreviousFingerprints);
        Assert.Empty(tombstone.RetainedVersions());
        Assert.Single(tombstone.Burns);
    }

    [Fact]
    public void Restore_ReissuesTheRestoredVersionsBurns_WithTheirOriginalStampAndReason()
    {
        var previous = new PreviousValue(At(1_500), "v0"u8.ToArray(), Fp("v0"u8.ToArray()));
        var state = Live(previous: previous, burns: [new BurnEntry(At(1_500), At(1_700, 2, OriginB), "old leak")]);

        var (metadata, _) = NewVersionOf(state, "v0", restored: true);

        Assert.Equal(RecordType.Burned, metadata.Type);
        Assert.Contains(new BurnEntry(At(5_000), At(1_700, 2, OriginB), "old leak"), metadata.Burns);
        Assert.Contains(new BurnEntry(At(1_500), At(1_700, 2, OriginB), "old leak"), metadata.Burns);
        Assert.Equal(At(2_000), metadata.PreviousVersion);
    }

    /// <summary>Restore copies a burn's stamp onto a new version, so equal burn stamps happen; the order can't matter.</summary>
    [Fact]
    public void Normalize_EqualBurnStamps_DoesNotDependOnOrder()
    {
        var burn = At(5_000, 0, OriginB);
        var burns = Enumerable.Range(0, RecordMerge.MaxBurns + 4).Select(i => new BurnEntry(At(100 + i), burn, $"b{i}")).ToList();
        var metadata = Meta(Live() with { Burns = burns });

        var forward = RecordMerge.Normalize(metadata);
        var backward = RecordMerge.Normalize(metadata with { Burns = [.. Enumerable.Reverse(burns)] });

        AssertSame(forward, backward);
        Assert.Equal(RecordMerge.MaxBurns, forward.Burns.Count);
        Assert.Equal(RecordMerge.Normalize(Live() with { Burns = burns }).Burns, forward.Burns);
    }

    [Fact]
    public void ImportedBurn_KeepsItsTime_OnTheNewVersion()
    {
        var at = new DateTime(2024, 3, 4, 5, 6, 7, DateTimeKind.Utc);

        var (metadata, _) = RecordWrites.NewVersion(null, new Dictionary<Stamp, byte[]>(), IdOf("s"), "s", At(5_000), Section(),
            Fp("v"u8.ToArray()), restored: false, Created, at, "imported", OriginA);

        var burn = Assert.Single(metadata.Burns);
        Assert.Equal(new BurnEntry(At(5_000), At(new DateTimeOffset(at).ToUnixTimeMilliseconds()), "imported"), burn);
        Assert.Equal(RecordType.Burned, metadata.Type);
    }

    [Fact]
    public void Extensions_SurviveEveryWrite()
    {
        var extension = new RecordExtension(0x7777, [1, 2, 3]);
        var state = Live() with { Extensions = [extension] };

        Assert.Equal([extension], NewVersionOf(state, "v2").Metadata.Extensions);
        Assert.Equal([extension], RecordWrites.Burn(Meta(state), At(4_000), null)!.Extensions);
        Assert.Equal([extension], RecordWrites.Tombstone(Meta(state), At(4_000)).Extensions);
    }

    private static readonly FieldWho Claude = new("a1a1a1a1", "steve", Elevated: false, Terminal: false, By: "claude");

    private static RecordExtension FieldsExtensionOf(FieldSet set) => new(FieldsExtension.Type, FieldsCodec.Encode(set));

    private static FieldSet FieldsIn(IReadOnlyList<RecordExtension> extensions) => Assert.IsType<FieldSet>(FieldsCodec.TryGet(extensions));

    /// <summary>Issue #311: a field-less create anchors the lineage (spec "Writes": always a <c>Fields</c> extension).</summary>
    [Fact]
    public void Create_WithoutFields_WritesEmptyExtension()
    {
        var (metadata, _) = RecordWrites.NewVersion(null, new Dictionary<Stamp, byte[]>(), IdOf("s"), "s", At(5_000), Section(),
            Fp("v"u8.ToArray()), restored: false, Created, null, null, OriginA);
        var plain = RecordVaultStore.NextRecord(null, IdOf("s"), "s", "v"u8.ToArray(), rotated: false, restored: false, Created, null, null,
            OriginA, () => At(5_000))!;

        foreach (var extensions in new[] { metadata.Extensions, plain.Extensions })
        {
            var extension = Assert.Single(extensions);
            Assert.Equal(FieldsExtension.Type, extension.Type);
            Assert.Equal(new FieldSet(At(5_000), []), FieldsCodec.Decode(extension.Data));
        }
    }

    /// <summary>
    /// Issue #311: a re-creation over a tombstone that still carries an earlier life's fields (a 0.3.x
    /// tombstone keeps every extension) starts a new lineage: <c>Since</c> = the new version, no old
    /// field, the other extension types kept in place.
    /// </summary>
    [Fact]
    public void Create_AfterDelete_NewSinceNoOldFields()
    {
        var oldLife = new FieldSet(At(2_000), [new FieldEntry("owner", "old-team", false, At(2_100), Claude, [])]);
        var other = new RecordExtension(0x7777, [1, 2, 3]);
        var tombstone = RecordVaultStore.Tombstone(Live(), At(3_000)) with { Extensions = [FieldsExtensionOf(oldLife), other] };

        var (metadata, _) = NewVersionOf(tombstone, "v2");
        var plain = RecordVaultStore.NextRecord(tombstone, tombstone.RecordId, "s", "v2"u8.ToArray(), rotated: false, restored: false, Created,
            null, null, OriginA, () => At(5_000))!;
        var withEdits = RecordWrites.NewVersion(Meta(tombstone), new Dictionary<Stamp, byte[]>(), tombstone.RecordId, "s", At(5_000), Section(),
            Fp("v2"u8.ToArray()), restored: false, Created, null, null, OriginA, [new FieldEdit("kind", "token")], Claude, () => At(5_001)).Metadata;

        foreach (var extensions in new[] { metadata.Extensions, plain.Extensions })
        {
            Assert.Equal([FieldsExtensionOf(new FieldSet(At(5_000), [])), other], extensions);
        }
        var fields = FieldsIn(withEdits.Extensions);
        Assert.Equal(At(5_000), fields.Since);
        Assert.Null(fields.Get("owner"));
        var kind = Assert.Single(fields.Entries);
        Assert.Equal(("kind", "token", At(5_001)), (kind.Name, kind.Value, kind.Changed));
        Assert.Empty(kind.History);
    }

    /// <summary>
    /// Issue #311, spec "Writes": a tombstone drops <c>Fields</c> (a deliberate change from 0.3.0) and
    /// keeps every other extension type, in its order (<see cref="Extensions_SurviveEveryWrite"/> pins
    /// the unknown type alone).
    /// </summary>
    [Fact]
    public void Tombstone_DropsFields_KeepsOtherExtensions()
    {
        var a = new RecordExtension(0x7000, [1]);
        var b = new RecordExtension(0x7777, [2, 3]);
        var fields = FieldsExtensionOf(new FieldSet(At(2_000), [new FieldEntry("owner", "x", false, At(2_100), Claude, [])]));
        var state = Live() with { Extensions = [a, fields, b] };

        Assert.Equal([a, b], RecordWrites.Tombstone(Meta(state), At(4_000)).Extensions);
        Assert.Equal([a, b], RecordVaultStore.Tombstone(state, At(4_000)).Extensions);
    }

    // ------------------------------------------------------------------ against the plaintext rules

    private static readonly string[] FieldNames = ["a", "b", "c"];

    private static string RandomValue(Random random) => $"value-{random.Next(1_000_000)}";

    private static FingerprintSet? RandomSet(Random random, byte[] value) => random.Next(8) switch
    {
        0 => null,
        1 => Fp(value) with { VariantSetVersion = SecretVariants.CurrentSetVersion + 1 }, // a later build's
        _ => Fp(value),
    };

    /// <summary>A random merged record of one secret, as a full load gives it (every retained version with a section).</summary>
    private static SecretRecord? RandomState(Random random, Random fields, string name)
    {
        if (random.Next(6) == 0)
            return null;
        var stamps = Enumerable.Range(0, 6).Select(_ => At(random.Next(1_000, 9_000), (uint)random.Next(3), random.Next(2) == 0 ? OriginA : OriginB))
            .Distinct().Order().ToList();
        var version = stamps[^1];
        var burns = Enumerable.Range(0, random.Next(5))
            .Select(_ => new BurnEntry(stamps[random.Next(stamps.Count)], At(random.Next(1_000, 9_000), 0, OriginB), random.Next(3) == 0 ? null : "r"))
            .ToList();
        List<RecordExtension> extensions = random.Next(3) == 0 ? [new RecordExtension(0x7000, [(byte)random.Next(256)])] : [];
        // Issue #311: a random valid Fields extension on most states, before or after the other type
        // (drawn from its own generator, so the draws above stay those this test always made).
        if (fields.Next(4) != 0)
            extensions.Insert(fields.Next(extensions.Count + 1), FieldsExtensionOf(FieldMergeTests.RandomSet(fields)));
        if (random.Next(5) == 0)
            return RecordMerge.Normalize(new SecretRecord(IdOf(name), At(9_500), RecordType.Tombstone, version, name, 500, [], burns)
            {
                Extensions = extensions,
            });
        var value = Encoding.UTF8.GetBytes(RandomValue(random));
        PreviousValue? previous = null;
        if (stamps.Count > 1 && random.Next(3) != 0)
        {
            var old = Encoding.UTF8.GetBytes(RandomValue(random));
            previous = new PreviousValue(stamps[^2], old, RandomSet(random, old));
        }
        var sealedSections = new Dictionary<Stamp, byte[]> { [version] = Section() };
        if (previous is not null)
            sealedSections[previous.Version] = Section();
        return RecordMerge.Normalize(new SecretRecord(IdOf(name), At(9_500), RecordType.Value, version, name, 500, value, burns, previous)
        {
            Fingerprints = RandomSet(random, value),
            Extensions = extensions,
            Sealed = sealedSections,
        });
    }

    /// <summary>
    /// Seeded: random merged states (absent, tombstone, live with and without a previous value,
    /// burns of any version, sets of this build's, a later build's or none, extensions) and every
    /// operation (new version, restore, imported burn, burn, delete; issue #311: valid <c>Fields</c>
    /// extensions, value writes with field edits and metadata-only field writes). The metadata rules give
    /// <see cref="RecordVaultStore.NextRecord"/>'s record converted to metadata (after
    /// <see cref="RecordVaultStore.PrepareV3"/>, which fingerprints a copied version that has no
    /// set; the writer does that by decrypting the section, the test from the plaintext it knows),
    /// and copy each retained section byte for byte.
    /// </summary>
    [Fact]
    public void RecordWrites_MatchNextRecord_OnRandomStates()
    {
        var random = new Random(2_016);
        var fields = new Random(3_11);
        using var keys = FingerprintKeys.Derive(Key);
        int compared = 0, burns = 0, restores = 0, tombstones = 0, imports = 0, sameValueBurns = 0, unchanged = 0;
        int fieldWrites = 0, fieldsUnchanged = 0, valueWritesWithEdits = 0, fieldsOnlyValueWrites = 0, nothingWritten = 0;
        for (var round = 0; round < 600; round++)
        {
            var name = $"s{round % 7}";
            var state = RandomState(random, fields, name);
            var live = state is { Type: not RecordType.Tombstone };
            var meta = state is null ? null : Meta(state);
            var held = state?.Sealed ?? new Dictionary<Stamp, byte[]>();
            var stamp = At(10_000 + round, (uint)random.Next(2));
            var plaintexts = new Dictionary<Stamp, byte[]>();
            if (live)
            {
                plaintexts[state!.Version] = state.Value;
                if (state.Previous is { } p)
                    plaintexts[p.Version] = p.Value;
            }

            // One stamp source per path, the same sequence: the version (or burn) first, then the change stamps.
            Func<Stamp> Stamps()
            {
                var k = 0;
                return () => k++ == 0 ? stamp : At(10_000 + round, (uint)(100 + k));
            }
            IReadOnlyList<FieldEdit> RandomEdits() =>
                [.. Enumerable.Range(0, fields.Next(1, 4)).Select(_ => new FieldEdit(FieldNames[fields.Next(FieldNames.Length)],
                    fields.Next(4) == 0 ? null : $"x{fields.Next(3)}"))];

            // Issue #311: a metadata-only field write on every live state, besides the operation below.
            if (live)
            {
                var edits = RandomEdits();
                var expected = RecordVaultStore.SetFieldsRecord(state!, edits, Claude, Stamps());
                var actual = RecordWrites.SetFields(meta!, edits, Claude, Stamps());
                AssertSame(Meta(expected), actual, $"round {round}: field write");
                Assert.Equal(state!.Version, actual.Version);
                if (actual.Extensions.SequenceEqual(meta!.Extensions))
                    fieldsUnchanged++;
                fieldWrites++;
            }

            switch (live ? random.Next(4) : 0)
            {
                case 0: // a value: create, add (same or new value), rotate, import (with or without a burn), restore
                {
                    var restored = live && state!.Previous is not null && random.Next(3) == 0;
                    // Code review (MiMo A-2): add's "same value" and import's burn over a live record of the
                    // same value go through the same dispatch as everything else (CommitWrites calls Next).
                    var sameValue = live && !restored && random.Next(2) == 0;
                    var rotated = restored || random.Next(sameValue ? 6 : 2) == 0;
                    var value = restored ? state!.Previous!.Value : sameValue ? state!.Value : Encoding.UTF8.GetBytes(RandomValue(random));
                    DateTime? importedAt = random.Next(sameValue ? 2 : 3) == 0 ? new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMinutes(round) : null;
                    var edits = fields.Next(3) == 0 ? RandomEdits() : null;
                    var expected = RecordVaultStore.NextRecord(state, IdOf(name), name, value, rotated, restored, Created, importedAt, "imp",
                        OriginA, Stamps(), edits, edits is null ? null : Claude);
                    byte[]? section = null;
                    var actual = RecordWrites.Next(meta, held, IdOf(name), name, () => value.AsSpan().SequenceEqual(state!.Value), rotated, restored,
                        Created, importedAt, "imp", OriginA, Stamps(), version =>
                        {
                            section = Section();
                            return (section, Fp(value));
                        }, edits, edits is null ? null : Claude);
                    valueWritesWithEdits += edits is null ? 0 : 1;
                    Assert.Equal(expected is null, actual is null);
                    if (expected is not null)
                    {
                        if (section is not null)
                            plaintexts[stamp] = value;
                        Compare(expected, actual!.Value.Metadata, actual.Value.Sections, state, section);
                    }
                    // The value part: a burn of the same value, or nothing (field edits may still be written).
                    var burnAdded = expected is not null && section is null && expected.OutstandingBurn is not null && state!.OutstandingBurn is null;
                    if (burnAdded)
                        sameValueBurns++;
                    if (expected is null || (section is null && !burnAdded))
                        unchanged++;
                    if (expected is null)
                        nothingWritten++; // both paths write nothing (task 3 review, Minor 1)
                    // A same-value write that wrote its fields and nothing else (task 3 review, Minor 2).
                    if (expected is not null && section is null && !burnAdded && expected.Version.Equals(state!.Version)
                        && !expected.Extensions.SequenceEqual(state.Extensions))
                        fieldsOnlyValueWrites++;
                    restores += restored ? 1 : 0;
                    imports += importedAt is null ? 0 : 1;
                    break;
                }
                case 1 or 2: // burn
                {
                    var expected = RecordVaultStore.NextRecord(state, IdOf(name), name, state!.Value, rotated: false, restored: false, Created,
                        Created, "burned", OriginA, () => stamp);
                    var actual = RecordWrites.Burn(meta!, stamp, "burned");
                    Assert.Equal(expected is null, actual is null);
                    if (expected is not null)
                        Compare(expected, actual!, held, state, null);
                    burns++;
                    break;
                }
                default: // delete
                {
                    var expected = RecordVaultStore.Tombstone(state!, stamp);
                    var actual = RecordWrites.Tombstone(meta!, stamp);
                    AssertSame(Meta(expected), actual, $"round {round}: tombstone");
                    tombstones++;
                    break;
                }
            }
            compared++;

            void Compare(SecretRecord expected, RecordMetadata actual, IReadOnlyDictionary<Stamp, byte[]> sections, SecretRecord? before, byte[]? newSection)
            {
                var prepared = RecordVaultStore.PrepareV3(expected, keys, recomputeOlderSets: false);
                // The writer fingerprints a copied version without a set from its section; here from its known plaintext.
                var filled = actual with
                {
                    Fingerprints = actual.Fingerprints ?? (actual.Type == RecordType.Tombstone ? null : Fp(plaintexts[actual.Version])),
                    PreviousFingerprints = actual.PreviousFingerprints ?? (actual.PreviousVersion is { } pv ? Fp(plaintexts[pv]) : null),
                };
                AssertSame(Meta(prepared), filled, $"round {round}");
                var retained = filled.RetainedVersions().Select(v => v.Version).ToList();
                Assert.Equal(retained.Count, sections.Count);
                foreach (var version in retained)
                {
                    var expectedSection = version.Equals(filled.Version) && newSection is not null ? newSection : before!.Sealed![version];
                    Assert.Equal(expectedSection, sections[version]);
                    if (prepared.Sealed?.TryGetValue(version, out var copied) == true)
                        Assert.Equal(copied, sections[version]);
                }
            }
        }
        Assert.True(compared == 600 && burns > 50 && restores > 10 && tombstones > 50 && imports > 20 && sameValueBurns > 10 && unchanged > 10,
            $"compared {compared}, burns {burns}, restores {restores}, tombstones {tombstones}, imports {imports}, " +
            $"same-value burns {sameValueBurns}, unchanged {unchanged}");
        Assert.True(fieldWrites > 50 && fieldsUnchanged > 3 && valueWritesWithEdits > 30 && fieldsOnlyValueWrites > 5,
            $"field writes {fieldWrites} (unchanged {fieldsUnchanged}), value writes with edits {valueWritesWithEdits} " +
            $"(fields only {fieldsOnlyValueWrites})");
        Assert.True(nothingWritten > 10, $"only {nothingWritten} rounds where both paths wrote nothing");
    }

    /// <summary>
    /// MiMo M-1, seeded: random sets of copies of one record (diverging versions, burns, previous
    /// values, re-encrypted sections, sets present or stripped, damage). The metadata merge either
    /// equals the plaintext merge (winner, burns, write stamp, extensions, fingerprints, chosen
    /// sections) or refuses with <see cref="RecordConflictException"/>, the case that takes the
    /// whole-record fallback; it never picks a different winner, and it refuses whenever the
    /// plaintext merge does.
    /// </summary>
    [Fact]
    public void MergeAllMetadata_MatchesMergeAll_OrRefuses_OnRandomCopySets()
    {
        var random = new Random(2_017);
        int merged = 0, refused = 0, bothRefused = 0, fieldMerges = 0;
        for (var round = 0; round < 400; round++)
        {
            var name = "s";
            var baseValue = Encoding.UTF8.GetBytes(RandomValue(random));
            var basePrevious = new PreviousValue(At(1_000), Encoding.UTF8.GetBytes(RandomValue(random)), null);
            var baseRecord = new SecretRecord(IdOf(name), At(2_100), RecordType.Value, At(2_000), name, 500, baseValue, [],
                random.Next(2) == 0 ? basePrevious : null);
            var baseFile = Encode(baseRecord, withSets: true, At(2_100));
            List<byte[]> files = [baseFile];
            for (var c = 0; c < random.Next(1, 4); c++)
            {
                var write = At(3_000 + c, 0, random.Next(2) == 0 ? OriginA : OriginB);
                var withSets = random.Next(3) != 0;
                files.Add(random.Next(7) switch
                {
                    0 => baseFile, // the same bytes (a sync tool's duplicate)
                    1 => Encode(baseRecord, withSets, write), // re-encrypted, same plaintext
                    2 => Encode(RecordMerge.Normalize(baseRecord with
                    {
                        Burns = [new BurnEntry(At(2_000), At(2_500 + c, 0, OriginB), "seen")],
                    }), withSets, write),
                    3 => Encode(baseRecord with // rotated on another machine: the base version is its previous
                    {
                        Version = At(4_000 + c), Value = Encoding.UTF8.GetBytes(RandomValue(random)),
                        Previous = new PreviousValue(At(2_000), baseValue, null),
                    }, withSets, write),
                    4 => Encode(baseRecord with { Type = RecordType.Tombstone, Version = At(4_500 + c), Value = [], Previous = null }, false, write),
                    5 => Encode(baseRecord with { Value = Encoding.UTF8.GetBytes("damaged") }, withSets, write), // one version, two values
                    _ => Encode(baseRecord with { Version = At(1_500 + c) }, withSets, write), // an older version
                });
            }

            var full = files.Select(f => SecretRecordCodec.Decode(f, Key)).ToList();
            var meta = files.Select(f => SecretRecordCodec.DecodeMetadataAndSections(f, Key)!.Value).ToList();
            SecretRecord? fullMerged = null;
            var fullConflict = Record.Exception(() => fullMerged = RecordMerge.MergeAll(full));
            (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sealed)? metaMerged = null;
            var metaConflict = Record.Exception(() => metaMerged = RecordMerge.MergeAllMetadata(meta));
            if (metaConflict is not null)
            {
                Assert.IsType<RecordConflictException>(metaConflict);
                refused++;
                bothRefused += fullConflict is null ? 0 : 1;
                continue;
            }
            Assert.True(fullConflict is null, $"round {round}: the plaintext merge refused ({fullConflict?.Message}) but the metadata merge merged");
            AssertSame(Meta(fullMerged!), metaMerged!.Value.Metadata, $"round {round}");
            // Issue #311: copies with diverging fields, merged per field on both paths.
            if (fullMerged!.Type != RecordType.Tombstone && full.Count(r => FieldsCodec.TryGet(r.Extensions) is { Entries.Count: > 0 }) >= 2)
                fieldMerges++;
            Assert.Equal(fullMerged!.Sealed?.Count ?? 0, metaMerged.Value.Sealed.Count);
            foreach (var (stamp, section) in metaMerged.Value.Sealed)
                Assert.Equal(fullMerged.Sealed![stamp], section);
            merged++;
        }
        Assert.True(merged > 100 && refused > 50 && bothRefused > 10, $"merged {merged}, refused {refused} (both {bothRefused})");
        Assert.True(fieldMerges > 20, $"only {fieldMerges} merges of diverging fields");

        byte[] Encode(SecretRecord record, bool withSets, Stamp write)
        {
            var prepared = record with
            {
                Write = write,
                Fingerprints = withSets && record.Type != RecordType.Tombstone ? Fp(record.Value) : null,
                Previous = record.Previous is { } p ? p with { Fingerprints = withSets ? Fp(p.Value) : null } : null,
                Sealed = null,
                // Issue #311: random valid Fields extensions (some beside another type), on a third of
                // the copies the record's own list.
                Extensions = random.Next(3) == 0 ? record.Extensions : RandomExtensions(),
            };
            return SecretRecordCodec.Encode(prepared, Key, 3);
        }

        IReadOnlyList<RecordExtension> RandomExtensions() => random.Next(5) switch
        {
            0 => [],
            1 => [new RecordExtension(0x7777, [(byte)random.Next(3)])],
            2 => [new RecordExtension(0x7777, [(byte)random.Next(3)]), new RecordExtension(FieldsExtension.Type, FieldsCodec.Encode(FieldMergeTests.RandomSet(random)))],
            _ => [new RecordExtension(FieldsExtension.Type, FieldsCodec.Encode(FieldMergeTests.RandomSet(random)))],
        };
    }
}
