using System.Text;
using TswapCli;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 4: <see cref="VaultWriter"/> answers what <see cref="SecretsDb"/> answers,
/// with the same texts, writes what <see cref="RecordVaultStore.SaveSecrets"/> writes (the oracle,
/// over random histories), and decrypts only the values a write needs.
/// </summary>
public sealed class VaultWriterTests : IDisposable
{
    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m;
    private readonly byte[] _key;
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly StringWriter _warnings = new();

    public VaultWriterTests()
    {
        _m = new FleetMachine("vault-writer", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private string FileOf(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private VaultWriter Writer(FleetMachine? machine = null, byte[]? key = null)
    {
        var store = new RecordVaultStore((machine ?? _m).Dir, time: new FuncTimeProvider(() => _now), warnings: TextWriter.Null)
        {
            ValueDecrypted = (file, version) => _values.Add((file, version)),
        };
        return new VaultWriter(store, key ?? _key, _warnings);
    }

    private Dictionary<string, string> Snapshot()
    {
        var files = Directory.GetFiles(_m.RecordsDir).ToDictionary(f => Path.GetFileName(f), f => Convert.ToHexString(File.ReadAllBytes(f)));
        files["config.json"] = Convert.ToHexString(File.ReadAllBytes(_m.ConfigPath));
        return files;
    }

    private static string? Error(Action action) => Record.Exception(action) switch
    {
        null => null,
        var ex => $"{ex.GetType().Name}: {ex.Message}",
    };

    private void Plant(string name, Func<SecretRecord, SecretRecord> change)
    {
        var path = RecordFile(_m, _key, name);
        var state = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(change(state), _key, KeyringFormat.RecordFormatVersion));
    }

    // ------------------------------------------------------------------ lookups

    /// <summary>
    /// Random vaults, each asserted to hold a name in every state (live with and without a previous
    /// value, tombstone, absent, unreadable): <see cref="VaultWriter.Find"/> is null exactly where
    /// <see cref="SecretsDb.Secrets"/> lacks the name, <see cref="VaultWriter.ThrowIfUnreadable"/>
    /// throws exactly the text <see cref="SecretsDb.ThrowIfUnreadable"/> throws, and
    /// <see cref="VaultWriter.Restore"/> throws exactly what <c>ResolveToken(name:previous)</c> throws
    /// (neither throws for a live name with a previous value). No write is made.
    /// </summary>
    [Fact]
    public void Lookups_MatchSecretsDb()
    {
        var random = new Random(16_25);
        var compared = 0;
        for (var round = 0; round < 4; round++)
        {
            using var m = new FleetMachine($"writer-lookup-{round}", SimulatedYubiKeyService.WithKeys(SerialA));
            var key = VaultKey(m, InitRecordVault(m));
            Dictionary<string, string> states = [];
            for (var i = 0; i < 8; i++)
            {
                var name = $"s{round}-{i}";
                m.Ok($"value-{i}", "ingest", name);
                var kind = i < 4 ? i : random.Next(4);
                if (kind == 1)
                    m.Ok($"rotated-{i}", "ingest", "--rotate", name);
                if (random.Next(3) == 0)
                    m.Ok("", "burn", name, "seen");
                if (kind == 2)
                    m.Ok("", "delete", name);
                if (kind == 3)
                {
                    var path = RecordFile(m, key, name);
                    File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
                }
                states[name] = kind switch { 0 => "live", 1 => "live+previous", 2 => "tombstone", _ => "unreadable" };
            }
            states[$"absent-{round}"] = "absent";

            var db = Store(m).LoadSecrets(key, TextWriter.Null);
            Assert.All(new[] { "live", "live+previous", "tombstone", "absent", "unreadable" }, state => Assert.Contains(state, states.Values));
            Assert.Contains(states, kv => kv.Value == "live+previous" && db.Secrets[kv.Key].PreviousValue is not null);
            using var writer = Writer(m, key);
            foreach (var (name, state) in states)
            {
                Assert.True((writer.Find(name) is null) == !db.Secrets.ContainsKey(name), $"{name} ({state}): Find");
                Assert.Equal(Error(() => db.ThrowIfUnreadable(name)), Error(() => writer.ThrowIfUnreadable(name)));
                Assert.Equal(Error(() => db.ResolveToken(name + SecretsDb.PreviousSuffix)), Error(() => writer.Restore(name)));
                compared++;
            }
            Assert.Contains(states, kv => kv.Value == "unreadable" && Error(() => writer.ThrowIfUnreadable(kv.Key)) is not null);
        }
        Assert.Equal(4 * 9, compared);
    }

    // ------------------------------------------------------------------ what is decrypted

    [Fact]
    public void Add_SameValue_ByFingerprints_DecryptsNothing_WritesNothing()
    {
        _m.Ok("the-value", "ingest", "s");
        var before = Snapshot();

        using (var writer = Writer())
        {
            writer.SetValue("s", "the-value", _now.UtcDateTime);
            Assert.Empty(writer.Commit());
        }

        Assert.Empty(_values);
        Assert.Equal(before, Snapshot());
    }

    /// <summary>Owner decision 6: a set of another variant-set version can't tell, so that one current value is compared.</summary>
    [Fact]
    public void Add_SetOfAnotherVariantVersion_DecryptsOnlyThatCurrentValue()
    {
        _m.Ok("same-value", "ingest", "same");
        _m.Ok("old-value", "ingest", "changed");
        _m.Ok("other-value", "ingest", "other");
        foreach (var name in new[] { "same", "changed" })
            Plant(name, s => s with { Fingerprints = s.Fingerprints! with { VariantSetVersion = SecretVariants.CurrentSetVersion + 1 } });
        var same = ReadRecord(_m, _key, "same");
        var changed = ReadRecord(_m, _key, "changed");
        var sameBytes = File.ReadAllBytes(RecordFile(_m, _key, "same"));

        using (var writer = Writer())
        {
            writer.SetValue("same", "same-value", _now.UtcDateTime);
            writer.SetValue("changed", "new-value", _now.UtcDateTime);
            Assert.Equal(["changed"], writer.Commit().Keys);
        }

        Assert.Equal(new[] { (FileOf("changed"), changed.Version), (FileOf("same"), same.Version) }.OrderBy(v => v.Item1, StringComparer.Ordinal),
            _values.OrderBy(v => v.File, StringComparer.Ordinal));
        Assert.Equal(sameBytes, File.ReadAllBytes(RecordFile(_m, _key, "same")));
        Assert.Equal("new-value", _m.Get("changed"));
        Assert.Equal("old-value", Store(_m).LoadSecrets(_key, TextWriter.Null).Secrets["changed"].PreviousValue);
    }

    [Fact]
    public void Restore_DecryptsOnlyThePreviousSection()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("v2", "ingest", "--rotate", "s");
        _m.Ok("other", "ingest", "t");
        var previous = ReadRecord(_m, _key, "s").Previous!.Version;

        using (var writer = Writer())
        {
            writer.Restore("s");
            writer.Commit();
        }

        Assert.Equal([(FileOf("s"), previous)], _values);
        Assert.Equal("v1", _m.Get("s"));
    }

    [Fact]
    public void CopiedVersionWithoutASet_IsFingerprintedFromItsSection()
    {
        _m.Ok("the-value", "ingest", "s");
        Plant("s", s => s with { Fingerprints = null });
        var version = ReadRecord(_m, _key, "s").Version;

        using (var writer = Writer())
        {
            writer.Burn("s", "seen");
            writer.Commit();
        }

        Assert.Equal([(FileOf("s"), version)], _values);
        var written = ReadRecord(_m, _key, "s");
        Assert.Equal(Fingerprints(_key, "the-value"u8.ToArray()), written.Fingerprints);
        Assert.Equal(RecordType.Burned, written.Type);
        Assert.Equal("", _warnings.ToString());
    }

    /// <summary>Owner decision 9: a section without a set that can't be decrypted is carried forward without one, with one warning.</summary>
    [Fact]
    public void CopiedVersionWithoutASet_Damaged_CarriedForwardWithoutASet_Warns()
    {
        _m.Ok("the-value", "ingest", "s");
        Plant("s", s => s with { Fingerprints = null });
        var path = RecordFile(_m, _key, "s");
        var bytes = File.ReadAllBytes(path);
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(path, bytes);
        var section = Assert.Single(ValueSections(bytes));

        using (var writer = Writer())
        {
            writer.Burn("s", "seen");
            writer.Commit();
        }

        var after = File.ReadAllBytes(path);
        Assert.Equal(section, Assert.Single(ValueSections(after)));
        var metadata = SecretRecordCodec.DecodeMetadata(after, _key)!;
        Assert.Null(metadata.Fingerprints);
        Assert.Equal(RecordType.Burned, metadata.Type);
        Assert.Equal(1, Store(_m).LoadMetadata(_key, TextWriter.Null).NotFingerprinted);
        Assert.Equal(
            $"Warning: record {FileOf("s")} holds a value version that can't be decrypted, so it was kept as it is without fingerprints; " +
            "restore the file from a backup or another copy." + Environment.NewLine,
            _warnings.ToString());
    }

    /// <summary>Version stamps are issued in ordinal name order whatever order the names were staged in (import stages in culture order).</summary>
    [Fact]
    public void Import_StampsInOrdinalOrder()
    {
        string[] cultureOrder = [.. new[] { "B-x", "a-x" }.OrderBy(n => n, StringComparer.CurrentCulture)];
        Assert.Equal(["a-x", "B-x"], cultureOrder);

        using (var writer = Writer())
        {
            foreach (var name in cultureOrder)
                writer.SetValue(name, $"{name}-value", _now.UtcDateTime);
            writer.Commit();
        }

        var b = ReadRecord(_m, _key, "B-x");
        var a = ReadRecord(_m, _key, "a-x");
        Assert.True(b.Version.CompareTo(a.Version) < 0, $"B-x {b.Version} vs a-x {a.Version}");
        Assert.True(b.Write.CompareTo(a.Write) < 0);
        Assert.True(a.Version.CompareTo(b.Write) < 0, "every version stamp before the first write stamp");
    }

    [Fact]
    public void UnreadableTarget_StagesNothing_CommitThrowsFirstInOrdinalOrder_BeforeAnyWrite()
    {
        foreach (var name in new[] { "u1", "u2", "ok" })
            _m.Ok($"{name}-value", "ingest", name);
        foreach (var name in new[] { "u1", "u2" })
        {
            var path = RecordFile(_m, _key, name);
            File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
        }
        var before = Snapshot();

        string message;
        using (var writer = Writer())
        {
            writer.SetValue("u2", "x", _now.UtcDateTime, always: true);
            writer.SetValue("ok", "x", _now.UtcDateTime, always: true);
            writer.Burn("u1", null);
            message = Assert.Throws<TswapException>(writer.Commit).Message;
        }

        Assert.Equal(SecretsDb.UnreadableRecordText("u1", FileOf("u1")), message);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void FormatTwoWriteWarning_CountOnly()
    {
        using var m = new FleetMachine("writer-v2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(m, InitFormatTwoVault(m));
        m.Ok("distinctive-live-value", "ingest", "distinctive-live-name");
        m.Ok("distinctive-gone-value", "ingest", "distinctive-gone-name");
        m.Ok("", "delete", "distinctive-gone-name");

        var error = new StringWriter();
        using (var writer = Writer(m, key))
        {
            Assert.NotNull(writer.Find("distinctive-live-name"));
            Assert.Null(writer.Find("distinctive-gone-name"));
            Assert.Null(writer.Find("never-there"));
            FingerprintTexts.WarnFormatTwo(error, "tswap", writer.FormatTwoDecoded, FormatTwoUse.Write);
        }

        var text = error.ToString();
        Assert.Equal(
            "Warning: 2 of the records read here were stored in the old record format 2, which tswap can only decrypt whole; the value " +
            $"versions not needed were wiped. Ask the user to run {ElevatedCommand.For("tswap", "vault reindex")} once to convert the vault." +
            Environment.NewLine,
            text);
        foreach (var leak in new[] { "distinctive", Path.GetFileName(RecordFile(m, key, "distinctive-live-name")),
                     Path.GetFileName(RecordFile(m, key, "distinctive-gone-name")) })
            Assert.DoesNotContain(leak, text);
    }

    // ------------------------------------------------------------------ the oracle

    /// <summary>What one write command does through <see cref="VaultWriter"/>, as the commands will (false: refused).</summary>
    private static class Through
    {
        private static bool Commit(VaultWriter writer)
        {
            writer.Commit();
            return true;
        }

        private static VaultWriter Open(BareRecordVault vault) => new(vault.Store(), BareRecordVault.Key, TextWriter.Null);

        public static bool Create(BareRecordVault vault, string name, string value)
        {
            using var writer = Open(vault);
            writer.ThrowIfUnreadable(name);
            if (writer.Find(name) is not null)
                return false;
            writer.SetValue(name, value, vault.Now);
            return Commit(writer);
        }

        public static bool Add(BareRecordVault vault, string name, string value)
        {
            using var writer = Open(vault);
            writer.SetValue(name, value, vault.Now);
            return Commit(writer);
        }

        public static bool Burn(BareRecordVault vault, string name, string? reason)
        {
            using var writer = Open(vault);
            if (writer.Find(name) is not { BurnedAt: null })
                return false;
            writer.Burn(name, reason);
            return Commit(writer);
        }

        public static bool Rotate(BareRecordVault vault, string name, string value)
        {
            using var writer = Open(vault);
            if (writer.Find(name) is null)
                return false;
            writer.SetValue(name, value, vault.Now, always: true);
            return Commit(writer);
        }

        public static bool Restore(BareRecordVault vault, string name)
        {
            using var writer = Open(vault);
            if (writer.Find(name) is not { HasPrevious: true })
                return false;
            writer.Restore(name);
            return Commit(writer);
        }

        public static bool Delete(BareRecordVault vault, string name)
        {
            using var writer = Open(vault);
            if (writer.Find(name) is null)
                return false;
            writer.Delete(name);
            return Commit(writer);
        }

        public static bool Import(BareRecordVault vault, IReadOnlyDictionary<string, Secret> exported)
        {
            using var writer = Open(vault);
            foreach (var (name, secret) in exported.OrderBy(kv => kv.Key))
            {
                if (writer.Find(name) is null)
                    writer.SetValue(name, secret.Value, secret.Created, importedBurnAt: secret.BurnedAt, importedBurnReason: secret.BurnReason);
            }
            return Commit(writer);
        }
    }

    /// <summary>
    /// The oracle. Seeded random histories on one machine with a fixed clock: create/ingest, add of
    /// a same and of a new value, burn, rotate, restore, delete and import (with burns), each run on
    /// two copies of one folder: through <see cref="RecordVaultStore.LoadSecrets"/> +
    /// <see cref="RecordVaultStore.SaveSecrets"/> exactly as the commands mutated the database, and
    /// through <see cref="VaultWriter"/>. After every step both refuse alike and every record is
    /// equal (<see cref="SecretRecord.SameState"/> and the write stamp; format; <c>LastHlc</c>), every
    /// file decodes with v0.2's reader, and on the writer's copy every section of a version that was
    /// retained before is byte-identical. On a marked folder and on an unmarked format 2 one.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PerRecordWrites_MatchSaveSecrets_OnRandomHistories(bool marked)
    {
        int steps = 0, writes = 0, copiedSections = 0;
        HashSet<string> kinds = [];
        for (var seed = 0; seed < 3; seed++)
        {
            var random = new Random(16_200 + seed + (marked ? 100 : 0));
            using var legacy = BareRecordVault.Create($"oracle-legacy-{seed}", marked, startMs: 1_760_000_000_000);
            using var writer = legacy.Copy($"oracle-writer-{seed}");
            string[] names = ["alpha", "Beta", "gamma", "d-1", "e"];
            for (var step = 0; step < 70; step++)
            {
                var advance = random.Next(3) == 0 ? 0 : random.Next(1, 5_000);
                legacy.NowMs += advance;
                writer.NowMs += advance;
                var name = names[random.Next(names.Length)];
                var value = random.Next(4) == 0 ? "shared-value" : $"value-{random.Next(1_000_000)}";
                var sectionsBefore = Sections(writer);
                var kind = random.Next(9);
                // Every random input of the step is drawn once, so both runs get the same.
                var reason = random.Next(2) == 0 ? null : "seen";
                var export = kind >= 7 ? ExportOf(random, names, step) : null;
                var same = CurrentValueOf(legacy, name) ?? value;
                Func<BareRecordVault, bool> run = kind switch
                {
                    0 => v => BareRecordVault.Legacy.Create(v, name, value),
                    1 => v => BareRecordVault.Legacy.Add(v, name, value),
                    2 => v => BareRecordVault.Legacy.Add(v, name, same), // add of the same value
                    3 => v => BareRecordVault.Legacy.Burn(v, name, reason),
                    4 => v => BareRecordVault.Legacy.Rotate(v, name, value),
                    5 => v => BareRecordVault.Legacy.Restore(v, name),
                    6 => v => BareRecordVault.Legacy.Delete(v, name),
                    _ => v => BareRecordVault.Legacy.Import(v, export!),
                };
                Func<BareRecordVault, bool> through = kind switch
                {
                    0 => v => Through.Create(v, name, value),
                    1 => v => Through.Add(v, name, value),
                    2 => v => Through.Add(v, name, same),
                    3 => v => Through.Burn(v, name, reason),
                    4 => v => Through.Rotate(v, name, value),
                    5 => v => Through.Restore(v, name),
                    6 => v => Through.Delete(v, name),
                    _ => v => Through.Import(v, export!),
                };
                var legacyWrote = run(legacy);
                var writerWrote = through(writer);
                Assert.True(legacyWrote == writerWrote, $"seed {seed} step {step} ({kind} {name}): refused differently");
                kinds.Add($"{kind}:{legacyWrote}");

                var expected = legacy.Records();
                var actual = writer.Records();
                Assert.Equal(expected.Select(r => r.File), actual.Select(r => r.File));
                foreach (var ((file, format, e), (_, actualFormat, a)) in expected.Zip(actual))
                {
                    Assert.True(format == actualFormat, $"seed {seed} step {step}: {file} format {format} vs {actualFormat}");
                    Assert.True(e.SameState(a), $"seed {seed} step {step} ({kind} {name}): {e.Name} differs");
                    Assert.True(e.Write.Equals(a.Write), $"seed {seed} step {step}: {e.Name} write {e.Write} vs {a.Write}");
                }
                Assert.Equal(legacy.LastHlc, writer.LastHlc);
                foreach (var (key, section) in Sections(writer))
                {
                    if (sectionsBefore.TryGetValue(key, out var before))
                    {
                        Assert.True(before.SequenceEqual(section), $"seed {seed} step {step}: section {key} was re-encrypted");
                        copiedSections++;
                    }
                }
                steps++;
                writes += legacyWrote ? 1 : 0;
            }
        }
        Assert.Equal(3 * 70, steps);
        Assert.True(writes > 100, $"only {writes} writes");
        for (var kind = 0; kind < 9; kind++)
            Assert.Contains($"{kind}:True", kinds);
        if (marked)
            Assert.True(copiedSections > 100, $"only {copiedSections} copied sections compared");

    }

    private static IReadOnlyDictionary<string, Secret> ExportOf(Random random, string[] names, int step)
    {
        Dictionary<string, Secret> export = [];
        foreach (var name in names.Where(_ => random.Next(2) == 0))
        {
            var created = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddHours(step);
            export[name] = random.Next(3) == 0
                ? new Secret($"imported-{name}-{step}", created, created.AddHours(1), created.AddHours(2), random.Next(2) == 0 ? null : "leaked")
                : new Secret($"imported-{name}-{step}", created, created.AddHours(1));
        }
        return export;
    }

    private static string? CurrentValueOf(BareRecordVault vault, string name) =>
        vault.Store().LoadSecrets(BareRecordVault.Key, TextWriter.Null).Secrets.GetValueOrDefault(name)?.Value;

    /// <summary>Every format 3 value section in the folder, by (file, version).</summary>
    private static Dictionary<string, byte[]> Sections(BareRecordVault vault)
    {
        Dictionary<string, byte[]> sections = [];
        foreach (var file in Directory.GetFiles(vault.RecordsDir).Where(f => Path.GetFileName(f).Length == 64))
        {
            var bytes = File.ReadAllBytes(file);
            if (SecretRecordCodec.DecodeMetadataAndSections(bytes, BareRecordVault.Key) is not { } decoded)
                continue;
            foreach (var (version, section) in decoded.Sealed)
                sections[$"{Path.GetFileName(file)[..8]}/{version}"] = section;
        }
        return sections;
    }
}
