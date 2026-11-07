using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b: the write commands decrypt no value they don't use (format 3), read only the
/// record they write, and still write what they wrote before (each test reads the write back).
/// Tasks 5 (<c>create</c>, <c>ingest</c>, <c>add</c>), 6 (<c>burn</c>, <c>delete</c>,
/// <c>rotate</c>, <c>ingest --rotate</c>), 7 (<c>restore</c>) and 8 (<c>import</c>).
/// </summary>
public sealed class WriteCommandDecryptionTests : IDisposable
{
    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m;
    private readonly byte[] _key;
    private readonly List<string> _records = [];
    private readonly List<(string File, Stamp Version)> _values = [];

    public WriteCommandDecryptionTests()
    {
        _m = new FleetMachine("write-decryption", SimulatedYubiKeyService.WithKeys(SerialA));
        _m.Time = new FuncTimeProvider(() => _now);
        _key = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("a-value", "ingest", "a");
        _m.Ok("b-value", "ingest", "b");
        _m.Ok("b-value-2", "ingest", "--rotate", "b");
    }

    public void Dispose() => _m.Dispose();

    private string FileOf(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    /// <summary>From here on, every command's decryptions are recorded.</summary>
    private void Watch()
    {
        _now += TimeSpan.FromSeconds(10);
        _m.StoreOpened = store =>
        {
            store.RecordDecrypted = file => _records.Add(file);
            store.ValueDecrypted = (file, version) => _values.Add((file, version));
        };
    }

    private void StopWatching() => _m.StoreOpened = null;

    /// <summary>Every file of the records folder and config.json, as bytes.</summary>
    private Dictionary<string, string> Snapshot()
    {
        var files = Directory.GetFiles(_m.RecordsDir).ToDictionary(f => Path.GetFileName(f), f => Convert.ToHexString(File.ReadAllBytes(f)));
        files["config.json"] = Convert.ToHexString(File.ReadAllBytes(_m.ConfigPath));
        return files;
    }

    /// <summary>Every record file except <paramref name="except"/>'s is byte-identical to <paramref name="before"/>.</summary>
    private void AssertOthersUnchanged(Dictionary<string, string> before, params string[] except)
    {
        var after = Snapshot();
        var skip = except.Select(FileOf).Append("config.json").ToHashSet();
        foreach (var (file, bytes) in before.Where(kv => !skip.Contains(kv.Key)))
            Assert.True(after.TryGetValue(file, out var now) && now == bytes, $"{file} changed");
    }

    private SecretsDb Db() => Store(_m).LoadSecrets(_key, TextWriter.Null);

    private void AssertModified(string name)
    {
        StopWatching();
        var line = _m.Ok("", "names").Split('\n').Single(l => l.StartsWith(name + " ", StringComparison.Ordinal));
        Assert.Contains(Hlc.Display(_now.UtcDateTime), line);
    }

    private void Plant(string name, Func<SecretRecord, SecretRecord> change)
    {
        var path = RecordFile(_m, _key, name);
        var state = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(change(state), _key, KeyringFormat.RecordFormatVersion));
    }

    /// <summary>Flips a bit in the last value section's ciphertext: the metadata stays intact.</summary>
    private void DamageLastValueSection(string name)
    {
        var path = RecordFile(_m, _key, name);
        var bytes = File.ReadAllBytes(path);
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(path, bytes);
    }

    private static string Copy(string path) => path + ".sync-conflict-20261107-120000-ABCDEFG";

    private const string PermissionsNotice = "Notice: tightened permissions";

    // ------------------------------------------------------------------ task 5: create, ingest, add

    [Fact]
    public void Create_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("", "create", "c");

        Assert.Empty(_values);
        Assert.All(_records, r => Assert.Equal(FileOf("c"), r));
        AssertOthersUnchanged(before, "c");
        Assert.Equal(32, _m.Get("c").Length);
        AssertModified("c");
    }

    [Fact]
    public void Ingest_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("c-value", "ingest", "c");

        Assert.Empty(_values);
        Assert.All(_records, r => Assert.Equal(FileOf("c"), r));
        AssertOthersUnchanged(before, "c");
        Assert.Equal("c-value", _m.Get("c"));
        AssertModified("c");
    }

    [Fact]
    public void Add_NewName_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("c-value\nc-value\n", "add", "c");

        Assert.Empty(_values);
        Assert.All(_records, r => Assert.Equal(FileOf("c"), r));
        AssertOthersUnchanged(before, "c");
        Assert.Equal("c-value", _m.Get("c"));
        AssertModified("c");
    }

    [Fact]
    public void Add_ChangedValue_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("a-new\na-new\n", "add", "a");

        Assert.Empty(_values);
        Assert.Equal([FileOf("a")], _records);
        AssertOthersUnchanged(before, "a");
        Assert.Equal("a-new", _m.Get("a"));
        Assert.Equal("a-value", Db().Secrets["a"].PreviousValue);
        AssertModified("a");
    }

    [Fact]
    public void Add_UnreadableTarget_RefusesNamingTheFile_WritesNothing()
    {
        var path = RecordFile(_m, _key, "a");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
        var before = Snapshot();
        Watch();

        var (exit, _, err) = _m.Run("x\nx\n", "add", "a");

        Assert.Equal(1, exit);
        Assert.Contains(SecretsDb.UnreadableRecordText("a", FileOf("a")), err);
        Assert.Equal(before, Snapshot());
        Assert.Empty(_values);
    }

    /// <summary>
    /// MiMo r3 M-8, decision 1's rule: a record whose current set is of value A while its section holds
    /// B. The fingerprints decide, so <c>add</c> of A writes nothing without the stored value having been
    /// checked; whoever uses the value still fails closed, naming the file.
    /// </summary>
    [Fact]
    public void Add_FingerprintMismatch_SameValue_WritesNothing()
    {
        Plant("a", s => s with { Value = "B-value"u8.ToArray(), Fingerprints = Fingerprints(_key, "A-value"u8.ToArray()), Sealed = null });
        var before = Snapshot();
        Watch();

        _m.Ok("A-value\nA-value\n", "add", "a");

        Assert.Equal(before, Snapshot());
        Assert.Empty(_values);
        StopWatching();
        var (exit, _, err) = _m.Run("", "get", "a");
        Assert.Equal(1, exit);
        Assert.Contains(FileOf("a"), err);
    }

    /// <summary>Difference 2: existence comes from metadata, so a damaged value section is an existing name.</summary>
    [Fact]
    public void Create_ExistingNameWithDamagedValueSection_RefusesAsExisting()
    {
        DamageLastValueSection("a");
        var before = Snapshot();
        Watch();

        var (exit, _, err) = _m.Run("", "create", "a");

        Assert.Equal(1, exit);
        Assert.Contains("Secret 'a' already exists", err);
        Assert.Equal(before, Snapshot());
        Assert.Empty(_values);
    }

    /// <summary>Difference 2: a changed value over a damaged section; the fingerprints decide, the damage is carried forward as the previous version.</summary>
    [Fact]
    public void Add_DamagedValueSection_NewVersion_KeepsItAsPrevious()
    {
        DamageLastValueSection("a");
        var damaged = Assert.Single(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a"))));
        Watch();

        _m.Ok("a-new\na-new\n", "add", "a");

        Assert.Empty(_values);
        var sections = ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a")));
        Assert.Equal(2, sections.Count);
        Assert.Equal(damaged, sections[1]);
        Assert.Equal("a-new", _m.Get("a"));
        using var view = new VaultView(Store(_m), _key, TextWriter.Null);
        Assert.Contains(FileOf("a"), Assert.Throws<TswapException>(() => view.ResolveToken("a:previous")).Message);
    }

    /// <summary>A file with a valid magic/version header and junk after it (an unusable copy).</summary>
    private static byte[] Junk()
    {
        var bytes = new byte[SecretRecordCodec.HeaderSize + 300];
        RandomNumberGenerator.Fill(bytes);
        "TSR1"u8.CopyTo(bytes);
        bytes[4] = KeyringFormat.RecordFormatVersion;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(65, 4), 300);
        return bytes;
    }

    /// <summary>Plants on <paramref name="name"/> a conflicted copy (an older version), an unusable copy and a stamp a year ahead.</summary>
    private void PlantWarnings(string name)
    {
        var path = RecordFile(_m, _key, name);
        var older = File.ReadAllBytes(path);
        _m.Ok($"{name}-rotated", "ingest", "--rotate", name);
        File.WriteAllBytes(Copy(path), older);
        File.WriteAllBytes(path + " (1)", Junk());
        var yearAhead = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds() + 400L * 86_400_000, 0), new byte[16]);
        Plant(name, s => s with { Write = yearAhead });
    }

    /// <summary>Difference 1: warnings about records a write doesn't touch are not printed.</summary>
    [Fact]
    public void Write_UntouchedRecordsWarnings_NotReported()
    {
        _m.Ok("u-value", "ingest", "unreadable");
        var path = RecordFile(_m, _key, "unreadable");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
        PlantWarnings("b");
        var fullLoad = new StringWriter();
        Store(_m).LoadSecrets(_key, fullLoad);
        foreach (var name in new[] { "unreadable", "b" })
            Assert.Contains(FileOf(name), fullLoad.ToString()); // the full load reports them
        Watch();

        var (exit, _, err) = _m.Run("c-value", "ingest", "c");

        Assert.Equal(0, exit);
        // The permissions notice names every file it narrowed (unchanged: it is about the folder, not a record).
        var findings = string.Join("\n", err.Split('\n').Where(l => !l.StartsWith(PermissionsNotice, StringComparison.Ordinal)));
        foreach (var name in new[] { "unreadable", "b" })
            Assert.DoesNotContain(FileOf(name), findings);
        Assert.DoesNotContain("unreadable record", err);
    }

    /// <summary>
    /// The written record's own findings keep the full load's warning texts: a conflicted copy (its
    /// note), an unusable copy and a stamp a year ahead. The write succeeds.
    /// </summary>
    [Fact]
    public void Write_TargetsOwnWarnings_SameTexts()
    {
        PlantWarnings("b");
        var fullLoad = new StringWriter();
        Store(_m).LoadSecrets(_key, fullLoad);
        var expected = Lines(fullLoad.ToString()).Where(l => l.Contains(FileOf("b"), StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(3, expected.Count);
        Watch();

        var (exit, _, err) = _m.Run("b-new\nb-new\n", "add", "b");

        Assert.True(exit == 0, err);
        Assert.Equal(expected, Lines(err).Where(l => l.Contains(FileOf("b"), StringComparison.Ordinal)).Order(StringComparer.Ordinal));
        Assert.Equal("b-new", _m.Get("b"));
        Assert.False(File.Exists(Copy(RecordFile(_m, _key, "b"))));

        static IEnumerable<string> Lines(string text) =>
            text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && !l.StartsWith(PermissionsNotice, StringComparison.Ordinal));
    }

    /// <summary>Difference 5: a planted record whose bytes aren't UTF-8 is no longer re-versioned by an unrelated write.</summary>
    [Fact]
    public void Write_UnrelatedNonUtf8Record_NotRewritten()
    {
        Plant("a", s => s with { Value = [0xFF, 0xFE, 0x41], Fingerprints = Fingerprints(_key, [0xFF, 0xFE, 0x41]), Sealed = null });
        var planted = File.ReadAllBytes(RecordFile(_m, _key, "a"));
        Watch();

        _m.Ok("c-value", "ingest", "c");

        Assert.Equal(planted, File.ReadAllBytes(RecordFile(_m, _key, "a")));
    }

    // ------------------------------------------------------------------ task 6: burn, delete, rotate, ingest --rotate

    [Fact]
    public void Burn_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("", "burn", "b", "seen");

        Assert.Empty(_values);
        Assert.Equal([FileOf("b")], _records);
        AssertOthersUnchanged(before, "b");
        StopWatching();
        var burned = System.Text.Json.JsonDocument.Parse(_m.Ok("", "burned", "--json")).RootElement;
        var entry = Assert.Single(burned.EnumerateArray(), e => e.GetProperty("status").GetString() == "outstanding");
        Assert.Equal("b", entry.GetProperty("name").GetString());
        Assert.Equal("seen", entry.GetProperty("reason").GetString());
        Assert.Equal(_now.UtcDateTime, entry.GetProperty("burnedAt").GetDateTime().ToUniversalTime());
        Assert.Equal("b-value-2", _m.Get("b"));
    }

    [Fact]
    public void Delete_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("", "delete", "b");

        Assert.Empty(_values);
        Assert.Equal([FileOf("b")], _records);
        AssertOthersUnchanged(before, "b");
        var record = ReadRecord(_m, _key, "b");
        Assert.Equal(RecordType.Tombstone, record.Type);
        Assert.Empty(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "b"))));
        Assert.False(Db().Secrets.ContainsKey("b"));
    }

    [Fact]
    public void Rotate_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("", "rotate", "a", "20");

        Assert.Empty(_values);
        Assert.Equal([FileOf("a")], _records);
        AssertOthersUnchanged(before, "a");
        Assert.Equal(20, _m.Get("a").Length);
        Assert.Equal("a-value", Db().Secrets["a"].PreviousValue);
        AssertModified("a");
    }

    [Fact]
    public void IngestRotate_DecryptsNoValue()
    {
        var before = Snapshot();
        Watch();

        _m.Ok("a-new", "ingest", "--rotate", "a");

        Assert.Empty(_values);
        Assert.Equal([FileOf("a")], _records);
        AssertOthersUnchanged(before, "a");
        Assert.Equal("a-new", _m.Get("a"));
        Assert.Equal("a-value", Db().Secrets["a"].PreviousValue);
    }

    [Fact]
    public void Burn_UnreadableTarget_NamesTheFile()
    {
        var path = RecordFile(_m, _key, "a");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
        var before = Snapshot();
        Watch();

        var (exit, _, err) = _m.Run("", "burn", "a");

        Assert.Equal(1, exit);
        Assert.Contains(SecretsDb.UnreadableRecordText("a", FileOf("a")), err);
        Assert.Equal(before, Snapshot());
        Assert.Empty(_values);
    }

    /// <summary>Difference 2: a burn copies a damaged section forward; whoever uses the value still fails closed, naming the file.</summary>
    [Fact]
    public void Burn_DamagedValueSection_Succeeds_GetStillFailsNamingTheFile()
    {
        DamageLastValueSection("a");
        var damaged = Assert.Single(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a"))));
        Watch();

        _m.Ok("", "burn", "a", "seen");

        Assert.Empty(_values);
        Assert.Equal(damaged, Assert.Single(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a")))));
        Assert.Equal(RecordType.Burned, SecretRecordCodec.DecodeMetadata(File.ReadAllBytes(RecordFile(_m, _key, "a")), _key)!.Type);
        StopWatching();
        var (exit, _, err) = _m.Run("", "get", "a");
        Assert.Equal(1, exit);
        Assert.Contains(SecretsDb.UnreadableRecordText("a", FileOf("a")), err);
    }

    /// <summary>Difference 2: fingerprints that don't match the value are carried forward with it; a restore of it fails closed.</summary>
    [Fact]
    public void Rotate_FingerprintMismatch_KeepsItAsPrevious_RestoreFailsClosed()
    {
        Plant("a", s => s with { Fingerprints = Fingerprints(_key, "something-else"u8.ToArray()) });
        var mismatched = File.ReadAllBytes(RecordFile(_m, _key, "a"));
        Watch();

        _m.Ok("a-new", "ingest", "--rotate", "a");

        Assert.Empty(_values);
        var sections = ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a")));
        Assert.Equal(Assert.Single(ValueSections(mismatched)), sections[1]);
        Assert.Equal("a-new", _m.Get("a"));
        var before = Snapshot();
        var (exit, _, err) = _m.Run("", "restore", "a");
        Assert.Equal(1, exit);
        Assert.Contains(SecretsDb.UnreadableRecordText("a", FileOf("a")), err);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void Delete_DamagedValueSection_WritesATombstone()
    {
        DamageLastValueSection("a");
        Watch();

        _m.Ok("", "delete", "a");

        Assert.Empty(_values);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "a").Type);
        Assert.Empty(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a"))));
    }

    [Fact]
    public void IngestRotate_DamagedValueSection_Succeeds()
    {
        DamageLastValueSection("a");
        var damaged = Assert.Single(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a"))));
        Watch();

        _m.Ok("a-new", "ingest", "--rotate", "a");

        Assert.Empty(_values);
        Assert.Equal(damaged, ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a")))[1]);
        Assert.Equal("a-new", _m.Get("a"));
    }

    /// <summary>Owner decision 8: the one value the comparison needs can't be decrypted, so <c>add</c> refuses; <c>rotate</c> still works.</summary>
    [Fact]
    public void Add_OtherVariantSet_DamagedCurrent_RefusesNamingTheFile_WritesNothing()
    {
        Plant("a", s => s with { Fingerprints = s.Fingerprints! with { VariantSetVersion = TswapCore.Fingerprints.SecretVariants.CurrentSetVersion + 1 } });
        DamageLastValueSection("a");
        var before = Snapshot();
        Watch();

        var (exit, _, err) = _m.Run("a-new\na-new\n", "add", "a");

        Assert.Equal(1, exit);
        Assert.Contains(SecretsDb.UnreadableRecordText("a", FileOf("a")), err);
        Assert.Equal(before, Snapshot());
        Assert.Equal([FileOf("a")], _values.Select(v => v.File));
        _m.Ok("", "rotate", "a");
        Assert.NotEqual(before[FileOf("a")], Snapshot()[FileOf("a")]);
    }

    /// <summary>Difference 5: a burn of a record whose bytes aren't UTF-8 writes a burn, not a new version with mangled bytes.</summary>
    [Fact]
    public void Burn_NonUtf8Record_WritesABurn_NotANewVersion()
    {
        Plant("a", s => s with { Value = [0xFF, 0xFE, 0x41], Fingerprints = Fingerprints(_key, [0xFF, 0xFE, 0x41]), Sealed = null });
        var planted = ReadRecord(_m, _key, "a");
        var section = Assert.Single(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a"))));
        Watch();

        _m.Ok("", "burn", "a");

        var burned = ReadRecord(_m, _key, "a");
        Assert.Equal(RecordType.Burned, burned.Type);
        Assert.Equal(planted.Version, burned.Version);
        Assert.Equal(new byte[] { 0xFF, 0xFE, 0x41 }, burned.Value);
        Assert.Null(burned.Previous);
        Assert.Equal(section, Assert.Single(ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "a")))));
    }
}
