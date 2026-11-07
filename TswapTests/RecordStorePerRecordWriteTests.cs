using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 3: the store's per-record write session (<see cref="RecordVaultStore.BeginWrite"/>,
/// <see cref="RecordVaultStore.OpenForWrite"/>, <see cref="RecordVaultStore.CommitWrites"/>) reads
/// only the record it writes, decrypts no value of a format 3 record it doesn't need, and keeps the
/// stale-write guard, the copy folding, the HLC rules and ruling 3.
/// </summary>
public sealed class RecordStorePerRecordWriteTests : IDisposable
{
    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m;
    private readonly byte[] _key;
    private readonly List<string> _records = [];
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly StringWriter _warnings = new();

    public RecordStorePerRecordWriteTests() : this(formatTwo: false)
    {
    }

    private RecordStorePerRecordWriteTests(bool formatTwo)
    {
        _m = new FleetMachine("per-record-write", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, formatTwo ? InitFormatTwoVault(_m) : InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private string FileOf(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private RecordVaultStore WatchedStore()
    {
        var store = new RecordVaultStore(_m.Dir, time: new FuncTimeProvider(() => _now), warnings: _warnings)
        {
            RecordDecrypted = file => _records.Add(file),
            ValueDecrypted = (file, version) => _values.Add((file, version)),
        };
        return store;
    }

    private IReadOnlyList<RecordMetadata> WriteOne(string name, Func<SecretEntry?, PendingWrite> write)
    {
        var store = WatchedStore();
        var session = store.BeginWrite(_key);
        using var entry = store.OpenForWrite(session, name);
        return store.CommitWrites(session, [write(entry)]);
    }

    private ValueWrite NewValue(string name, SecretEntry? entry, string value, bool always = false) =>
        new(name, entry, System.Text.Encoding.UTF8.GetBytes(value), always, Restored: false, _now.UtcDateTime);

    /// <summary>Every file of the records folder and config.json, as bytes.</summary>
    private Dictionary<string, string> Snapshot()
    {
        var files = Directory.GetFiles(_m.RecordsDir).ToDictionary(f => Path.GetFileName(f), f => Convert.ToHexString(File.ReadAllBytes(f)));
        files["config.json"] = Convert.ToHexString(File.ReadAllBytes(_m.ConfigPath));
        return files;
    }

    private static string Copy(string path) => path + ".sync-conflict-20261107-120000-ABCDEFG";

    [Fact]
    public void Burn_FormatThree_ReadsOnlyItsRecord_DecryptsNoValue()
    {
        _m.Ok("a-value", "ingest", "a");
        _m.Ok("b-value", "ingest", "b");
        _m.Ok("b-value-2", "ingest", "--rotate", "b");
        _m.Ok("c-value", "ingest", "c");
        var before = Snapshot();
        var sections = ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "b")));

        WriteOne("b", entry => new BurnWrite("b", entry!, "seen"));

        Assert.Empty(_values);
        Assert.Equal([FileOf("b")], _records);
        var after = Snapshot();
        foreach (var name in new[] { "a", "c" })
            Assert.Equal(before[FileOf(name)], after[FileOf(name)]);
        Assert.Equal(sections, ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "b"))));
        var db = Store(_m).LoadSecrets(_key, TextWriter.Null);
        Assert.Equal("seen", db.Secrets["b"].BurnReason);
        Assert.Equal("b-value-2", db.Secrets["b"].Value);
        Assert.Equal("b-value", db.Secrets["b"].PreviousValue);
    }

    [Fact]
    public void Guard_TargetChangedSinceOpen_RefusesWritingNothing()
    {
        _m.Ok("b-value", "ingest", "b");
        var store = WatchedStore();
        var session = store.BeginWrite(_key);
        using var entry = store.OpenForWrite(session, "b");
        _m.Ok("", "burn", "b", "elsewhere"); // another process writes it in between
        var between = Snapshot();

        var ex = Assert.Throws<TswapException>(() => store.CommitWrites(session, [new BurnWrite("b", entry!, "here")]));

        Assert.Contains("changed on disk", ex.Message);
        Assert.Equal(between, Snapshot());
    }

    [Fact]
    public void Guard_RecordCreatedElsewhereSinceOpen_IsNotOverwritten()
    {
        var store = WatchedStore();
        var session = store.BeginWrite(_key);
        var entry = store.OpenForWrite(session, "new");
        Assert.Null(entry);
        _m.Ok("theirs", "ingest", "new");
        var between = Snapshot();

        var ex = Assert.Throws<TswapException>(() => store.CommitWrites(session, [NewValue("new", null, "mine")]));

        Assert.Contains("changed on disk", ex.Message);
        Assert.Equal(between, Snapshot());
        Assert.Equal("theirs", _m.Get("new"));
    }

    [Fact]
    public void Guard_Batch_OneChanged_NoneWritten()
    {
        _m.Ok("a-value", "ingest", "a");
        var store = WatchedStore();
        var session = store.BeginWrite(_key);
        List<PendingWrite> writes = [.. new[] { "x", "y", "z" }.Select(n => NewValue(n, store.OpenForWrite(session, n), $"{n}-value"))];
        _m.Ok("theirs", "ingest", "y");
        var between = Snapshot();

        Assert.Throws<TswapException>(() => store.CommitWrites(session, writes));

        Assert.Equal(between, Snapshot());
        Assert.False(File.Exists(RecordFile(_m, _key, "x")));
        Assert.False(File.Exists(RecordFile(_m, _key, "z")));
    }

    [Fact]
    public void Copies_FoldedAndRemoved_OnlyForTheWrittenRecord()
    {
        foreach (var name in new[] { "a", "b" })
        {
            _m.Ok($"{name}-1", "ingest", name);
            var older = File.ReadAllBytes(RecordFile(_m, _key, name));
            _m.Ok($"{name}-2", "ingest", "--rotate", name);
            File.WriteAllBytes(Copy(RecordFile(_m, _key, name)), older);
        }

        WriteOne("a", entry => new BurnWrite("a", entry!, null));

        Assert.False(File.Exists(Copy(RecordFile(_m, _key, "a"))));
        Assert.True(File.Exists(Copy(RecordFile(_m, _key, "b"))));
        Assert.DoesNotContain(_records, f => f.StartsWith(FileOf("b"), StringComparison.Ordinal));
        Assert.Empty(_values);
        var a = ReadRecord(_m, _key, "a");
        Assert.Equal(RecordType.Burned, a.Type);
        Assert.Equal("a-2"u8.ToArray(), a.Value);
    }

    /// <summary>
    /// Stage 2 difference 10's setup: two copies of one version of "split" with different
    /// ciphertexts, the copy without a fingerprint set. The metadata merge refuses, so the write
    /// decodes that record whole, as the full load did, and converges the copies; no other record is
    /// read and the record is not counted as format 2.
    /// </summary>
    [Fact]
    public void CopiesOnlyPlaintextCanMerge_FallBackToThatRecord_AndConverge()
    {
        _m.Ok("alpha-value", "ingest", "alpha");
        var origin = Convert.FromBase64String(_m.Config.OriginId!);
        var id = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), "split");
        var version = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds(), 0), origin);
        var record = new SecretRecord(id, version, RecordType.Value, version, "split", 1, "split-value"u8.ToArray(), [])
        {
            Fingerprints = Fingerprints(_key, "split-value"u8.ToArray()),
        };
        var path = RecordFile(_m, _key, "split");
        File.WriteAllBytes(path, SecretRecordCodec.Encode(record, _key, KeyringFormat.RecordFormatVersion));
        var later = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds() + 1000, 0), origin);
        File.WriteAllBytes(path + " (1)", SecretRecordCodec.Encode(record with { Write = later, Fingerprints = null }, _key, KeyringFormat.RecordFormatVersion));
        var alpha = File.ReadAllBytes(RecordFile(_m, _key, "alpha"));

        var store = WatchedStore();
        var session = store.BeginWrite(_key);
        using (var entry = store.OpenForWrite(session, "split"))
        {
            Assert.False(entry!.IsFormatTwo);
            store.CommitWrites(session, [new BurnWrite("split", entry, "seen")]);
        }

        Assert.False(File.Exists(path + " (1)"));
        // Both files of that record (the main file and its copy) were decoded whole; nothing else.
        Assert.Equal([FileOf("split"), FileOf("split") + " (1)"], _values.Select(v => v.File).Order(StringComparer.Ordinal));
        Assert.Equal(alpha, File.ReadAllBytes(RecordFile(_m, _key, "alpha")));
        var written = ReadRecord(_m, _key, "split");
        Assert.Equal(RecordType.Burned, written.Type);
        Assert.Equal("split-value"u8.ToArray(), written.Value);
        Assert.NotNull(written.Fingerprints);
    }

    /// <summary>A file with a valid magic/version header, a far-future write stamp and junk after it.</summary>
    private static byte[] JunkWithFutureHeader()
    {
        var bytes = new byte[SecretRecordCodec.HeaderSize + 300];
        RandomNumberGenerator.Fill(bytes);
        "TSR1"u8.CopyTo(bytes);
        bytes[4] = KeyringFormat.RecordFormatVersion;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(37, 8), 9_000_000_000_000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(65, 4), 300);
        return bytes;
    }

    [Fact]
    public void Hlc_ObservesTheTargetsAuthenticatedStampsOnly()
    {
        _m.Ok("a-value", "ingest", "a");
        var path = RecordFile(_m, _key, "a");
        var ahead = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds() + 3 * 86_400_000L, 5), new byte[16]);
        var state = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        File.WriteAllBytes(Copy(path), SecretRecordCodec.Encode(state with { Write = ahead }, _key, KeyringFormat.RecordFormatVersion));
        File.WriteAllBytes(path + " (1)", JunkWithFutureHeader());

        var written = Assert.Single(WriteOne("a", entry => new BurnWrite("a", entry!, null)));

        var burn = Assert.Single(written.Burns);
        Assert.True(burn.Burn.CompareTo(ahead) > 0, $"burn {burn.Burn} vs the copy's {ahead}");
        Assert.True(written.Write.CompareTo(burn.Burn) > 0);
        var lastHlc = Hlc.TryParse(_m.Config.LastHlc)!.Value;
        Assert.True(lastHlc > ahead.Hlc);
        Assert.True(lastHlc.PhysicalMs < 9_000_000_000_000, $"LastHlc {lastHlc} followed the junk copy");
    }

    /// <summary>Difference 3 (owner decision 4): a far-ahead stamp in another record no longer moves this write's stamps.</summary>
    [Fact]
    public void Hlc_UnrelatedFutureRecord_DoesNotRaiseTheStamp()
    {
        _m.Ok("a-value", "ingest", "a");
        _m.Ok("far-value", "ingest", "far");
        var path = RecordFile(_m, _key, "far");
        var ahead = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds() + 3 * 86_400_000L, 0), new byte[16]);
        var state = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(state with { Write = ahead }, _key, KeyringFormat.RecordFormatVersion));
        _now += TimeSpan.FromSeconds(1);

        var written = Assert.Single(WriteOne("a", entry => new BurnWrite("a", entry!, null)));

        Assert.Equal(_now.ToUnixTimeMilliseconds(), Assert.Single(written.Burns).Burn.Hlc.PhysicalMs);
        Assert.Equal(_now.ToUnixTimeMilliseconds(), Hlc.TryParse(_m.Config.LastHlc)!.Value.PhysicalMs);
        Assert.DoesNotContain(FileOf("far"), _records);
    }

    [Fact]
    public void NewerMarker_RefusesBeforeWriting()
    {
        _m.Ok("a-value", "ingest", "a");
        WriteMarker(_m, "4");
        var before = Snapshot();

        var ex = Assert.Throws<TswapException>(() => WriteOne("a", entry => new BurnWrite("a", entry!, null)));

        Assert.Contains("newer tswap", ex.Message);
        Assert.Equal(before, Snapshot());
    }

    /// <summary>The unmarked-folder cases (ruling 3 per record): a vault as tswap 0.1 made it.</summary>
    public sealed class Unmarked : IDisposable
    {
        private readonly RecordStorePerRecordWriteTests _t = new(formatTwo: true);

        public void Dispose() => _t.Dispose();

        private byte FormatOf(string name) => File.ReadAllBytes(RecordFile(_t._m, _t._key, name))[4];

        [Fact]
        public void Unmarked_AuthenticatedFormatThreeRecord_SelectsFormatThree_DecryptingNoValue()
        {
            _t._m.Ok("a-value", "ingest", "a");
            _t._m.Ok("b-value", "ingest", "b");
            var probed = _t.PlantFormatThree("b");

            _t.WriteOne("new", entry => _t.NewValue("new", entry, "new-value"));

            Assert.Equal(KeyringFormat.RecordFormatVersion, FormatOf("new"));
            Assert.Empty(_t._values);
            Assert.Equal([probed], _t._records);
            Assert.Equal(KeyringFormat.RecordFormatVersionV2, FormatOf("a"));
        }

        [Fact]
        public void Unmarked_DamagedFormatThreeFile_SelectsNothing()
        {
            _t._m.Ok("a-value", "ingest", "a");
            _t._m.Ok("b-value", "ingest", "b");
            _t.PlantFormatThree("b");
            var path = RecordFile(_t._m, _t._key, "b");
            var bytes = File.ReadAllBytes(path);
            bytes[SecretRecordCodec.V3HeaderSize + 4 + 20] ^= 0x01; // inside the metadata section
            File.WriteAllBytes(path, bytes);

            _t.WriteOne("new", entry => _t.NewValue("new", entry, "new-value"));

            Assert.Equal(KeyringFormat.RecordFormatVersionV2, FormatOf("new"));
            Assert.DoesNotContain(Path.GetFileName(path), _t._warnings.ToString());
        }

        /// <summary>Difference 4: an intact metadata section selects format 3 even when a value section is damaged.</summary>
        [Fact]
        public void Unmarked_FormatThreeWithDamagedValueSection_SelectsFormatThree()
        {
            _t._m.Ok("b-value", "ingest", "b");
            _t.PlantFormatThree("b");
            var path = RecordFile(_t._m, _t._key, "b");
            var bytes = File.ReadAllBytes(path);
            bytes[^1] ^= 0x01; // the last value section's ciphertext
            File.WriteAllBytes(path, bytes);

            _t.WriteOne("new", entry => _t.NewValue("new", entry, "new-value"));

            Assert.Equal(KeyringFormat.RecordFormatVersion, FormatOf("new"));
            Assert.Empty(_t._values);
        }
    }

    /// <summary>Re-encodes <paramref name="name"/>'s format 2 record in format 3 (as a v0.2 machine would have written it).</summary>
    private string PlantFormatThree(string name)
    {
        var path = RecordFile(_m, _key, name);
        var state = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(state with { Fingerprints = Fingerprints(_key, state.Value) }, _key,
            KeyringFormat.RecordFormatVersion));
        return Path.GetFileName(path);
    }
}
