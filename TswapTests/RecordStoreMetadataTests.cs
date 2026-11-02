using System.Text;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 6: <see cref="RecordVaultStore.LoadMetadata"/> reads names, burns and
/// fingerprints from metadata sections only. It never decrypts a value section, never decrypts a
/// format 2 file (such a record counts as not fingerprinted, ruling 12), and folds conflicted copies
/// by the same rules as the full load, failing closed where fingerprints can't prove two sections equal.
/// </summary>
public sealed class RecordStoreMetadataTests : IDisposable
{
    private static readonly byte[] OriginA = Enumerable.Repeat((byte)0x0A, 16).ToArray();
    private static readonly byte[] OriginB = Enumerable.Repeat((byte)0x0B, 16).ToArray();

    private readonly FleetMachine _m = new("store-meta", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _key;

    public RecordStoreMetadataTests()
    {
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    /// <summary>The record file of <paramref name="name"/> (its folder created, for tests that plant files first).</summary>
    private string FileOf(string name)
    {
        Directory.CreateDirectory(_m.RecordsDir);
        return RecordFile(_m, _key, name);
    }

    private byte[] IdOf(string name) => FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), name);

    private static Stamp S(long ms, byte[]? origin = null) => new(new Hlc(ms, 0), origin ?? OriginA);

    private SecretRecord NewRecord(string name, Stamp version, string value, Stamp? write = null, long createdMs = 1) =>
        new(IdOf(name), write ?? version, RecordType.Value, version, name, createdMs, Encoding.UTF8.GetBytes(value), [])
        {
            Fingerprints = Fingerprints(_key, Encoding.UTF8.GetBytes(value)),
        };

    [Fact]
    public void LoadMetadata_DecryptsNoValueSection()
    {
        WriteMarker(_m);
        for (var i = 0; i < 20; i++)
        {
            _m.Ok($"value-{i}-a", "ingest", $"s{i}");
            _m.Ok($"value-{i}-b", "ingest", "--rotate", $"s{i}");
        }
        _m.Ok("", "burn", "s3", "seen");
        _m.Ok("", "delete", "s4");
        var store = Store(_m);
        var values = new List<(string, Stamp)>();
        store.ValueDecrypted = (file, version) => values.Add((file, version));

        var metadata = store.LoadMetadata(_key, TextWriter.Null);

        Assert.Empty(values);
        Assert.Equal(0, metadata.NotFingerprinted);
        Assert.Equal(0, metadata.OlderVariantSet);
        Assert.Empty(metadata.Unreadable);
        Assert.True(metadata.IsFullyFingerprinted);
        var full = Store(_m).LoadRecordStates(_key, TextWriter.Null).States.Values.ToDictionary(r => r.Name);
        Assert.Equal(full.Keys.Order(), metadata.Records.Select(r => r.Name).Order());
        foreach (var record in metadata.Records)
        {
            var expected = full[record.Name];
            Assert.Equal(expected.Type, record.Type);
            Assert.Equal(expected.Version, record.Version);
            Assert.Equal(expected.Burns, record.Burns);
            Assert.Equal(expected.Fingerprints, record.Fingerprints);
            Assert.Equal(expected.Previous?.Version, record.PreviousVersion);
            Assert.Equal(expected.Previous?.Fingerprints, record.PreviousFingerprints);
        }
        Assert.Equal(RecordType.Burned, metadata.Records.Single(r => r.Name == "s3").Type);
        Assert.Equal(RecordType.Tombstone, metadata.Records.Single(r => r.Name == "s4").Type);
    }

    [Fact]
    public void LoadMetadata_CountsV2AndMissingFingerprints_WithoutDecryptingV2()
    {
        _m.Ok("a-value", "ingest", "a"); // no marker yet: format 2
        WriteMarker(_m);
        _m.Ok("b-value", "ingest", "b"); // format 3
        System.IO.File.WriteAllBytes(FileOf("c"),
            SecretRecordCodec.Encode(NewRecord("c", S(1000), "c-value") with { Fingerprints = null }, _key, 3));
        _m.Ok("", "delete", "b"); // a tombstone is never "missing fingerprints"
        _m.Ok("d-value", "ingest", "d");
        var store = Store(_m);
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;

        var metadata = store.LoadMetadata(_key, TextWriter.Null);

        Assert.Equal(2, metadata.NotFingerprinted); // a (format 2) and c (no set)
        Assert.False(metadata.IsFullyFingerprinted);
        Assert.DoesNotContain(Path.GetFileName(FileOf("a")), decrypted);
        Assert.Contains(Path.GetFileName(FileOf("c")), decrypted);
        Assert.Equal(["b", "c", "d"], metadata.Records.Select(r => r.Name).Order());
    }

    [Fact]
    public void LoadMetadata_CountsOlderVariantSets()
    {
        WriteMarker(_m);
        var older = NewRecord("o", S(1000), "o-value");
        older = older with { Fingerprints = older.Fingerprints! with { VariantSetVersion = 0 } };
        System.IO.File.WriteAllBytes(FileOf("o"), SecretRecordCodec.Encode(older, _key, 3));
        _m.Ok("n-value", "ingest", "n");

        var metadata = Store(_m).LoadMetadata(_key, TextWriter.Null);

        Assert.Equal(1, metadata.OlderVariantSet);
        Assert.Equal(0, metadata.NotFingerprinted);
        Assert.True(metadata.IsFullyFingerprinted); // an older set still matches; only a missing one is "not fingerprinted"
    }

    [Fact]
    public void LoadMetadata_V2ConflictCopyOfAV3Record_IsNotFingerprinted_WithoutDecryptingIt()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        var copy = FileOf("s") + " (1)";
        System.IO.File.WriteAllBytes(copy, SecretRecordCodec.Encode(ReadRecord(_m, _key, "s"), _key, KeyringFormat.RecordFormatVersionV2));
        var store = Store(_m);
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;

        var metadata = store.LoadMetadata(_key, TextWriter.Null);

        Assert.Equal(1, metadata.NotFingerprinted);
        Assert.DoesNotContain(Path.GetFileName(copy), decrypted);
        Assert.Empty(metadata.Unreadable);
    }

    [Fact]
    public void LoadMetadata_TiedCopiesThatDisagree_AreUnreadable_InEveryOrder()
    {
        // A copy can't carry another name at the store level (the record id must be the HMAC of the
        // name inside, so the codec refuses it before any merge); the metadata merge itself refuses
        // the disagreement in every order of its inputs.
        var id = IdOf("s");
        var version = S(2000);
        RecordMetadata Meta(string name, long writeMs) => new(id, S(writeMs), RecordType.Value, version, name, 1, [],
            Fingerprints(_key, "v"u8.ToArray()), null, null, []);
        var section = new Dictionary<Stamp, byte[]> { [version] = [1, 2, 3] };
        (RecordMetadata, IReadOnlyDictionary<Stamp, byte[]>)[] inputs = [(Meta("s", 3000), section), (Meta("s", 4000), section), (Meta("t", 5000), section)];
        foreach (var order in Permutations(inputs))
            Assert.Throws<RecordConflictException>(() => RecordMerge.MergeAllMetadata(order));

        // At the store level, the same rule over three files that disagree on another tied field
        // (created time), in all six assignments of contents to the main file and two copies.
        WriteMarker(_m);
        var main = FileOf("s");
        string[] files = [main, main + " (1)", main + ".sync-conflict-20261102-120000-ABCDEF"];
        byte[][] contents =
        [
            SecretRecordCodec.Encode(NewRecord("s", version, "v", S(3000)), _key, 3),
            SecretRecordCodec.Encode(NewRecord("s", version, "v", S(4000)), _key, 3),
            SecretRecordCodec.Encode(NewRecord("s", version, "v", S(5000), createdMs: 2), _key, 3),
        ];
        foreach (var order in Permutations(contents))
        {
            for (var i = 0; i < files.Length; i++)
                System.IO.File.WriteAllBytes(files[i], order[i]);

            var metadata = Store(_m).LoadMetadata(_key, TextWriter.Null);
            var (_, unreadable) = Store(_m).LoadRecordStates(_key, TextWriter.Null);

            Assert.Equal([Path.GetFileName(main)], metadata.Unreadable);
            Assert.Empty(metadata.Records);
            Assert.Equal([Path.GetFileName(main)], unreadable);
        }
    }

    /// <summary>
    /// The real route of a copy that carries another name (fix round 1): its record id must be
    /// HMAC(K_names, name), so the codec refuses it at decode, before any merge. On both load paths the
    /// copy is skipped with a warning and kept on disk, and the record stays readable from the others.
    /// </summary>
    [Fact]
    public void ACopyCarryingAnotherName_IsSkippedWithAWarning_TheRecordStaysReadable()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        var main = FileOf("s");
        var copy = main + " (1)";
        var renamed = ReadRecord(_m, _key, "s") with { Name = "t", Write = S(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 1000) };
        System.IO.File.WriteAllBytes(copy, SecretRecordCodec.Encode(renamed, _key, 3)); // record id of "s", name "t"

        var metadataWarnings = new StringWriter();
        var metadata = Store(_m).LoadMetadata(_key, metadataWarnings);
        var fullWarnings = new StringWriter();
        var db = Store(_m).LoadSecrets(_key, fullWarnings);

        Assert.Empty(metadata.Unreadable);
        Assert.Equal("s", Assert.Single(metadata.Records).Name);
        Assert.Contains(Path.GetFileName(copy), metadataWarnings.ToString());
        Assert.Contains("can't be used", metadataWarnings.ToString());
        Assert.Null(db.UnreadableFiles);
        Assert.Equal("s-value", db.Secrets["s"].Value);
        Assert.Contains(Path.GetFileName(copy), fullWarnings.ToString());
        Assert.Contains("can't be used", fullWarnings.ToString());
        Assert.True(System.IO.File.Exists(copy));
    }

    [Fact]
    public void LoadMetadata_ConcurrentConversionCopies_PickTheSameSectionAsTheFullLoad()
    {
        _m.Ok("the-value", "ingest", "s"); // format 2
        var v2 = ReadRecord(_m, _key, "s");
        var fingerprints = Fingerprints(_key, v2.Value);
        var onA = SecretRecordCodec.Encode(v2 with { Write = S(v2.Write.Hlc.PhysicalMs + 10), Fingerprints = fingerprints }, _key, 3);
        var onB = SecretRecordCodec.Encode(v2 with { Write = S(v2.Write.Hlc.PhysicalMs + 10, OriginB), Fingerprints = fingerprints }, _key, 3);
        System.IO.File.WriteAllBytes(FileOf("s"), onA);
        System.IO.File.WriteAllBytes(FileOf("s") + " (1)", onB);
        var (a, b) = (ValueSections(onA)[0], ValueSections(onB)[0]);
        Assert.NotEqual(a, b);
        var smaller = a.AsSpan().SequenceCompareTo(b) < 0 ? a : b;

        var store = Store(_m);
        var metadata = store.LoadMetadata(_key, TextWriter.Null);
        var full = Store(_m).LoadRecordStates(_key, TextWriter.Null).States[Path.GetFileName(FileOf("s"))];

        Assert.Empty(metadata.Unreadable);
        Assert.Equal(v2.Version, Assert.Single(metadata.Records).Version);
        Assert.Equal(smaller, full.Sealed![v2.Version]);
        Assert.Equal(smaller, store.MetadataSections![Path.GetFileName(FileOf("s"))][v2.Version]);
    }

    [Fact]
    public void LoadMetadata_DifferentSectionsWithoutFingerprints_FailClosed()
    {
        var v = S(1000);
        var record = NewRecord("s", v, "same") with { Fingerprints = null };
        System.IO.File.WriteAllBytes(FileOf("s"), SecretRecordCodec.Encode(record with { Write = S(2000) }, _key, 3));
        System.IO.File.WriteAllBytes(FileOf("s") + " (1)", SecretRecordCodec.Encode(record with { Write = S(3000) }, _key, 3));

        var metadata = Store(_m).LoadMetadata(_key, TextWriter.Null);
        var (states, unreadable) = Store(_m).LoadRecordStates(_key, TextWriter.Null);

        Assert.Equal([Path.GetFileName(FileOf("s"))], metadata.Unreadable); // can't prove the two sections equal
        Assert.Empty(unreadable); // the full load can: it has the plaintexts
        Assert.Single(states);
    }

    /// <summary>
    /// The property the brief names: over random histories (several copies per record, some in
    /// format 2, some with same-stamp damage, some superseded damage), the metadata load agrees with
    /// the full load: equal names, types, burns and fingerprints for records without a format 2 copy;
    /// a record with a format 2 copy is not fingerprinted; a conflict is unreadable on both paths.
    /// </summary>
    [Fact]
    public void LoadMetadata_FoldsConflictCopies_LikeTheFullLoad()
    {
        var random = new Random(6_12);
        var config = _m.Config;
        var counts = new Dictionary<string, int> { ["v2"] = 0, ["conflict"] = 0, ["merged"] = 0, ["multi"] = 0 };
        Stamp[] versions = [S(1000), S(2000), S(2000, OriginB), S(3000)];
        string ValueOf(Stamp v) => $"value-{v.Hlc.PhysicalMs}-{v.Origin[0]}";

        for (var round = 0; round < 6; round++)
        {
            var folder = Path.Combine(_m.Dir, $"history-{round}");
            var records = Path.Combine(folder, "records");
            Directory.CreateDirectory(records);
            var expectations = new Dictionary<string, (bool HasV2, string Name)>();
            for (var r = 0; r < 12; r++)
            {
                var name = $"r{r}";
                var file = FilenameHasher.ToFilename(IdOf(name));
                var copies = random.Next(1, 4);
                var hasV2 = false;
                string[] suffixes = ["", " (1)", ".sync-conflict-20261102-120000-ABCDEF"];
                var start = random.Next(2); // 1: no main file, only conflicted copies
                for (var c = 0; c < copies; c++)
                {
                    var vi = random.Next(versions.Length);
                    var version = versions[vi];
                    SecretRecord record;
                    if (random.Next(7) == 0)
                    {
                        record = new SecretRecord(IdOf(name), version, RecordType.Tombstone, version, name, 1, [], []);
                    }
                    else
                    {
                        var damaged = random.Next(6) == 0;
                        record = NewRecord(name, version, damaged ? $"damaged-{random.Next(3)}" : ValueOf(version));
                        if (vi > 0 && random.Next(2) == 0)
                        {
                            var pv = versions[random.Next(vi)];
                            if (!pv.Equals(version))
                            {
                                var pValue = random.Next(6) == 0 ? "damaged-p" : ValueOf(pv);
                                record = record with { Previous = new PreviousValue(pv, Encoding.UTF8.GetBytes(pValue), Fingerprints(_key, Encoding.UTF8.GetBytes(pValue))) };
                            }
                        }
                        if (random.Next(3) == 0)
                            record = RecordMerge.Normalize(record with { Burns = [new BurnEntry(version, S(4000 + random.Next(3)), "r")] });
                    }
                    record = record with { Write = S(5000 + random.Next(4), random.Next(2) == 0 ? OriginA : OriginB) };
                    var v2 = random.Next(6) == 0;
                    hasV2 |= v2;
                    var bytes = SecretRecordCodec.Encode(record, _key, v2 ? KeyringFormat.RecordFormatVersionV2 : KeyringFormat.RecordFormatVersion);
                    System.IO.File.WriteAllBytes(Path.Combine(records, file + suffixes[Math.Min(c + start, 2)]), bytes);
                    if (c + start >= 2) break;
                }
                if (copies > 1) counts["multi"]++;
                expectations[file] = (hasV2, name);
            }

            var metadata = RecordVaultStore.ForFolder(folder, config).LoadMetadata(_key, TextWriter.Null);
            var (states, unreadable) = RecordVaultStore.ForFolder(folder, config).LoadRecordStates(_key, TextWriter.Null);
            var byName = metadata.Records.ToDictionary(m => m.Name);
            Assert.Equal(expectations.Values.Count(e => e.HasV2), metadata.NotFingerprinted);

            foreach (var (file, (hasV2, name)) in expectations)
            {
                if (hasV2)
                {
                    counts["v2"]++;
                    Assert.False(byName.ContainsKey(name), $"round {round}: {name} has a format 2 copy but was listed");
                    Assert.DoesNotContain(file, metadata.Unreadable);
                    continue;
                }
                if (unreadable.Contains(file))
                {
                    counts["conflict"]++;
                    Assert.Contains(file, metadata.Unreadable);
                    continue;
                }
                counts["merged"]++;
                Assert.True(byName.TryGetValue(name, out var meta), $"round {round}: {name} is readable in the full load but not listed");
                var full = states[file];
                Assert.Equal(full.Name, meta.Name);
                Assert.Equal(full.Type, meta.Type);
                Assert.Equal(full.Version, meta.Version);
                Assert.Equal(full.Burns, meta.Burns);
                Assert.Equal(full.Fingerprints, meta.Fingerprints);
                Assert.Equal(full.Previous?.Version, meta.PreviousVersion);
                Assert.Equal(full.Previous?.Fingerprints, meta.PreviousFingerprints);
                Assert.Equal(full.Write, meta.Write);
            }
        }

        Assert.True(counts["v2"] > 3, $"generator: {counts["v2"]} records with a format 2 copy");
        Assert.True(counts["conflict"] > 3, $"generator: {counts["conflict"]} conflicts");
        Assert.True(counts["merged"] > 20, $"generator: {counts["merged"]} merged records");
        Assert.True(counts["multi"] > 20, $"generator: {counts["multi"]} records with copies");
    }

    private static IEnumerable<T[]> Permutations<T>(IReadOnlyList<T> items)
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
}
