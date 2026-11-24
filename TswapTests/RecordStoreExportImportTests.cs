using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 decision 9: export and import keep their single-file encrypted format and serialise
/// whatever store is active. An export is a snapshot of the current values and burn state (no
/// tombstones, no history) and, since format 3 (issue #311), each secret's live fields; importing into a
/// record store writes each secret as a new version, so importing an old export can bring back a deleted
/// secret (the user's explicit act).
/// </summary>
public sealed class RecordStoreExportImportTests : IDisposable
{
    private DateTimeOffset _now = new(2026, 11, 15, 16, 42, 7, TimeSpan.Zero);
    private readonly FleetMachine _m;
    private readonly byte[] _vaultKey;

    public RecordStoreExportImportTests()
    {
        _m = new FleetMachine("export-records", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = Tick };
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    /// <summary>A fixed clock that moves on by a millisecond each time a store reads it.</summary>
    private DateTimeOffset Tick() => _now = _now.AddMilliseconds(1);

    /// <summary>The decrypted payload (the exported <see cref="SecretsDb"/> as JSON) of the export at <paramref name="path"/>.</summary>
    private static string Payload(string path, string passphrase)
    {
        var file = JsonSerializer.Deserialize(File.ReadAllText(path), TswapJsonContext.Default.ExportFile)!;
        var key = ExportCrypto.DeriveKey(passphrase, Convert.FromBase64String(file.Salt), file);
        return Encoding.UTF8.GetString(Crypto.Decrypt(Convert.FromBase64String(file.Ciphertext), key));
    }

    /// <summary>Writes a v3 export at <paramref name="path"/> whose decrypted payload is <paramref name="payloadJson"/> (a crafted file).</summary>
    private static void WriteExport(string path, string passphrase, string payloadJson)
    {
        var salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var kdf = ExportCrypto.DefaultArgon2idParams;
        var ciphertext = Crypto.Encrypt(Encoding.UTF8.GetBytes(payloadJson), ExportCrypto.DeriveArgon2id(passphrase, salt, kdf));
        var file = new ExportFile(ExportFile.V3, TestTime.Fixed, Convert.ToBase64String(salt), Convert.ToBase64String(ciphertext), kdf);
        File.WriteAllText(path, JsonSerializer.Serialize(file, TswapJsonContext.Default.ExportFile));
    }

    /// <summary>A v3 payload of one secret per entry: name to its <c>Fields</c> member as raw JSON (null: no member).</summary>
    private static string PayloadOf(params (string Name, string? FieldsJson)[] secrets) =>
        "{ \"Secrets\": { " + string.Join(", ", secrets.Select(s =>
            $"\"{s.Name}\": {{ \"Value\": \"{s.Name}-value-0042\", \"Created\": \"2026-01-02T03:04:05Z\", " +
            $"\"Modified\": \"2026-01-02T03:04:05Z\"{(s.FieldsJson is null ? "" : ", \"Fields\": " + s.FieldsJson)} }}")) + " } }";

    /// <summary>Replaces <paramref name="name"/>'s Fields extension on disk with bytes no build decodes (a damaged record).</summary>
    private static void PlantMalformedFields(FleetMachine m, byte[] key, string name)
    {
        var path = RecordFile(m, key, name);
        var record = SecretRecordCodec.Decode(File.ReadAllBytes(path), key);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(record with
        {
            Extensions = [.. record.Extensions.Where(e => e.Type != FieldsExtension.Type), new RecordExtension(FieldsExtension.Type, [0xFF, 0xFF, 0xFF])],
        }, key));
    }

    private static FieldSet FieldsOf(FleetMachine m, byte[] key, string name) =>
        Assert.IsType<FieldSet>(FieldsCodec.TryGet(ReadRecord(m, key, name).Extensions));

    private static Dictionary<string, string> Live(FleetMachine m, byte[] key, string name) =>
        FieldsOf(m, key, name).Live.ToDictionary(e => e.Name, e => e.Value!, StringComparer.Ordinal);

    [Fact]
    public void AnExport_IsASnapshot_AndImportingItBringsBackADeletedSecret()
    {
        _m.Ok("v1", "ingest", "kept");
        _m.Ok("v2", "ingest", "deleted-later");
        _m.Ok("v3", "ingest", "rotated");
        _m.Ok("", "burn", "rotated", "seen");
        _m.Ok("", "rotate", "rotated");
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);
        var exportText = File.ReadAllText(export);
        Assert.Contains("tswap-export-v3", exportText);

        _m.Ok("", "delete", "deleted-later");
        var tombstone = ReadRecord(_m, _vaultKey, "deleted-later");
        _m.Ok("pass\n", "import", export);

        Assert.Equal("v2", _m.Get("deleted-later"));
        Assert.True(ReadRecord(_m, _vaultKey, "deleted-later").Version.CompareTo(tombstone.Version) > 0);
        Assert.Equal("v1", _m.Get("kept"));
        // The rotated secret's history stays in the vault; the export carried no history.
        Assert.Single(ReadRecord(_m, _vaultKey, "rotated").Burns);
    }

    // ------------------------------------------------------------------ issue #311: fields (export format v3)

    [Fact]
    public void Export_V3_CarriesFields()
    {
        _m.Ok("db-value-0042", "ingest", "db", "--field", "url=https://old.example", "--field", "host=db1");
        _m.Ok("", "field", "set", "db", "url=https://new.example");
        _m.Ok("", "field", "unset", "db", "host");
        var export = _m.PathOf("backup.json");

        _m.Ok("pass\npass\n", "export", export);

        Assert.Contains("\"Version\": \"tswap-export-v3\"", File.ReadAllText(export));
        var payload = Payload(export, "pass");
        var db = JsonSerializer.Deserialize(payload, TswapJsonContext.Default.SecretsDb)!;
        // Live fields only: the replaced url is history and host a delete marker, neither is exported.
        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://new.example" }, db.Secrets["db"].Fields);
        Assert.DoesNotContain("old.example", payload);
        Assert.DoesNotContain("host", payload);
    }

    [Fact]
    public void Export_FieldlessSecret_NoFieldsProperty()
    {
        _m.Ok("plain-value-0042", "ingest", "plain");
        var export = _m.PathOf("backup.json");

        _m.Ok("pass\npass\n", "export", export);

        var payload = Payload(export, "pass");
        Assert.Contains("\"plain\"", payload);
        Assert.DoesNotContain("\"Fields\"", payload);
    }

    [Fact]
    public void Import_V3_RestoresFields()
    {
        _m.Ok("db-value-0042", "ingest", "db", "--field", "url=https://db.example", "--field", "username=app");
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);
        using var other = new FleetMachine("export-records-other", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = Tick };
        var otherKey = VaultKey(other, InitRecordVault(other));

        other.Ok("pass\n", "import", export);

        Assert.Equal("db-value-0042", other.Get("db"));
        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://db.example", ["username"] = "app" }, Live(other, otherKey, "db"));
        // The import is a change made on the importing machine: fresh stamps after the new version, its origin.
        var record = ReadRecord(other, otherKey, "db");
        var fields = FieldsOf(other, otherKey, "db");
        Assert.Equal(record.Version, fields.Since);
        var origin = Store(other).ShortOriginId();
        Assert.NotEqual(Store(_m).ShortOriginId(), origin);
        Assert.All(fields.Entries, e =>
        {
            Assert.Equal(origin, e.Who.Origin);
            Assert.True(e.Changed.CompareTo(fields.Since) > 0, $"{e.Name} changed at {e.Changed}, not after {fields.Since}");
            Assert.Empty(e.History);
        });
    }

    /// <summary>
    /// Spec "Export and import" (MiMo r3 N7): an export is a snapshot; a field removed after it comes back on
    /// import and stays back when the imported copy is merged with a copy that holds the earlier removal.
    /// </summary>
    [Fact]
    public void Import_OldExport_ThenMergeWithEarlierRemoval_FieldStays()
    {
        _m.Ok("db-value-0042", "ingest", "db", "--field", "url=https://db.example", "--field", "host=db1");
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);
        _m.Ok("", "field", "unset", "db", "host");
        using var laptop = new FleetMachine("export-records-laptop", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = Tick };
        _m.CopyVaultTo(laptop);
        Assert.True(FieldsCodec.TryGet(ReadRecord(laptop, _vaultKey, "db").Extensions)!.Get("host")!.Deleted);
        _m.Ok("", "delete", "db");
        _m.Ok("pass\n", "import", export);

        _m.Ok("", "vault", "merge", laptop.VaultDir!);

        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://db.example", ["host"] = "db1" }, Live(_m, _vaultKey, "db"));
        Assert.Equal("db-value-0042", _m.Get("db"));
    }

    // ------------------------------------------------------------------ review fixes: damaged records, crafted files

    /// <summary>Review I1: a record whose Fields extension can't be decoded is unreadable on its own; export names its file.</summary>
    [Fact]
    public void Export_MalformedFieldsExtension_RefusedNamingTheRecord()
    {
        _m.Ok("db-value-0042", "ingest", "db", "--field", "url=https://db.example");
        _m.Ok("other-value-0042", "ingest", "other");
        PlantMalformedFields(_m, _vaultKey, "db");
        var file = Path.GetFileName(RecordFile(_m, _vaultKey, "db"));
        var export = _m.PathOf("backup.json");

        var (exit, _, stderr) = _m.Run("pass\npass\n", "export", export);

        Assert.Equal(1, exit);
        Assert.Contains($"'export' covers every secret, but 1 record(s) can't be read: {file}.", stderr);
        Assert.False(File.Exists(export));
    }

    /// <summary>Review I1: <c>vault merge</c> reports the damaged record and merges every other one.</summary>
    [Fact]
    public void VaultMerge_MalformedFieldsExtension_ThatRecordReported_OthersMerged()
    {
        _m.Ok("db-value-0042", "ingest", "db", "--field", "url=https://db.example");
        using var laptop = new FleetMachine("export-records-merge", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = Tick };
        _m.CopyVaultTo(laptop);
        laptop.Ok("new-value-0042", "ingest", "from-laptop");
        laptop.Ok("", "field", "set", "db", "host=db1");
        PlantMalformedFields(_m, _vaultKey, "db");
        var file = Path.GetFileName(RecordFile(_m, _vaultKey, "db"));

        var (exit, _, stderr) = _m.Run("", "vault", "merge", laptop.VaultDir!, "--yes");

        Assert.True(exit == 0, stderr);
        Assert.Contains($"Warning: record {file} can't be read", stderr);
        Assert.Equal("new-value-0042", _m.Get("from-laptop"));
        // The damaged record is left as it is: still the planted extension, not the laptop's fields.
        var kept = ReadRecord(_m, _vaultKey, "db").Extensions.Single(e => e.Type == FieldsExtension.Type);
        Assert.Equal([0xFF, 0xFF, 0xFF], kept.Data);
    }

    /// <summary>Review m1: a crafted <c>"Fields": {"x": null}</c> is treated as a null <c>Value</c> is: that secret is skipped, nothing written for it.</summary>
    [Fact]
    public void Import_NullFieldValue_SecretSkipped()
    {
        var export = _m.PathOf("crafted.json");
        WriteExport(export, "pass", PayloadOf(("crafted", """{ "url": null }"""), ("good", """{ "url": "https://good.example" }""")));

        var stdout = _m.Ok("pass\n", "import", export);

        Assert.Contains("Skipped 'crafted' (field 'url' is null", stdout);
        Assert.False(File.Exists(RecordFile(_m, _vaultKey, "crafted")));
        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://good.example" }, Live(_m, _vaultKey, "good"));
    }

    /// <summary>Review m1: a non-string field value makes the payload unreadable: the import is refused, nothing written.</summary>
    [Fact]
    public void Import_NonStringFieldValue_Refused()
    {
        var export = _m.PathOf("crafted.json");
        WriteExport(export, "pass", PayloadOf(("good", null), ("crafted", """{ "port": 5432 }""")));

        var (exit, _, stderr) = _m.Run("pass\n", "import", export);

        Assert.Equal(1, exit);
        Assert.Contains("Export data is corrupted", stderr);
        Assert.False(File.Exists(RecordFile(_m, _vaultKey, "good")));
        Assert.False(File.Exists(RecordFile(_m, _vaultKey, "crafted")));
    }

    /// <summary>Review m3: a field the rules refuse (a bad name, a control character) refuses the whole import; nothing is written.</summary>
    [Theory]
    [InlineData("""{ "Bad Name": "x" }""", "Refused field name 'Bad Name'")]
    [InlineData("""{ "note": "a\u0007b" }""", "Refused field 'note': The value contains U+0007")]
    public void Import_FieldRefusedByRules_WholeImportRefused(string fieldsJson, string refusal)
    {
        var export = _m.PathOf("crafted.json");
        WriteExport(export, "pass", PayloadOf(("good", """{ "url": "https://good.example" }"""), ("crafted", fieldsJson)));
        var before = _m.RecordFiles;

        var (exit, _, stderr) = _m.Run("pass\n", "import", export);

        Assert.Equal(1, exit);
        Assert.Contains("Secret 'crafted': " + refusal, stderr);
        Assert.Equal(before, _m.RecordFiles);
    }

    /// <summary>
    /// Final review I2 (ruling): import applies no caps, as a merge doesn't (spec Merge rule 7: two legal copies
    /// can leave a secret over them, and an export is the backup of that). An export over the 64-field cap or the
    /// 64 KiB cap imports whole; the secret stays readable, and only a growing write is refused afterwards.
    /// </summary>
    [Theory]
    [InlineData(65, 8)]
    [InlineData(17, FieldRules.MaxValueLength)]
    public void Import_OverACap_ImportsEveryField(int count, int length)
    {
        var fields = Enumerable.Range(0, count).ToDictionary(i => $"f{i:D2}", i => new string((char)('a' + i % 26), length));
        var export = _m.PathOf("over-cap.json");
        WriteExport(export, "pass", PayloadOf(("big", JsonSerializer.Serialize(fields)), ("small", """{ "url": "https://x.example" }""")));
        Assert.NotNull(FieldRules.CheckCaps(new FieldSet(Stamp.Zero,
            [.. fields.Select(f => new FieldEntry(f.Key, f.Value, false, Stamp.Zero, new FieldWho("00000000", null, false, false, null), []))])));

        var stdout = _m.Ok("pass\n", "import", export);

        Assert.Contains("Imported 2 secret(s)", stdout);
        Assert.Equal(fields, Live(_m, _vaultKey, "big"));
        Assert.Equal("big-value-0042", _m.Get("big"));
        var (exit, _, stderr) = _m.Run("", "field", "set", "big", "extra=x");
        Assert.Equal(1, exit);
        Assert.Contains("Refused: the fields of 'big' are over a cap.", stderr);
    }

    // ------------------------------------------------------------------ brief T54 Task 6: passphrases in NFC

    private const string PassNfc = "p\u00e4ss-export-1";
    private const string PassNfd = "pa\u0308ss-export-1";
    private const string LoneSurrogatePass = "x\uD800y";

    /// <summary>Imports <paramref name="path"/> into a fresh vault with <paramref name="typed"/>; returns the run and that vault's value of s.</summary>
    private static (int Exit, string Err, string? Value) ImportFresh(string path, string typed)
    {
        using var fresh = new FleetMachine("import-fresh", SimulatedYubiKeyService.WithKeys(SerialA));
        InitRecordVault(fresh);
        var (exit, _, err) = fresh.Run(typed + "\n", "import", path);
        return (exit, err, exit == 0 ? fresh.Get("s") : null);
    }

    /// <summary>An export "made by an older tswap": the key derived over the raw passphrase, a fixed salt.</summary>
    private string OlderExport(string version, string passphrase)
    {
        var salt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var kdf = version == ExportFile.V1 ? null : ExportCrypto.DefaultArgon2idParams;
        var file = new ExportFile(version, TestTime.Fixed, Convert.ToBase64String(salt), "", kdf);
        var key = ExportCrypto.DeriveKey(passphrase, salt, file);
        var ciphertext = Crypto.Encrypt(Encoding.UTF8.GetBytes(PayloadOf(("s", null))), key);
        var path = _m.PathOf($"older-{version}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(file with { Ciphertext = Convert.ToBase64String(ciphertext) }, TswapJsonContext.Default.ExportFile));
        return path;
    }

    private string Export(string passphrase, string confirmation)
    {
        _m.Ok("s-value-0042", "ingest", "s");
        var path = _m.PathOf("unicode-export.json");
        var (exit, _, err) = _m.Run(passphrase + "\n" + confirmation + "\n", "export", path);
        Assert.True(exit == 0, err);
        return path;
    }

    [Theory]
    [InlineData(PassNfc, PassNfd)]
    [InlineData(PassNfd, PassNfc)]
    public void Export_ImportsWhicheverSpellingIsTyped(string exportedWith, string importedWith)
    {
        var path = Export(exportedWith, exportedWith);

        var (exit, err, value) = ImportFresh(path, importedWith);

        Assert.True(exit == 0, err);
        Assert.Equal("s-value-0042", value);
    }

    [Theory]
    [InlineData("tswap-export-v3", PassNfd, PassNfc)] // the NFD candidate (typed NFC is its own NFC: the second of two)
    [InlineData("tswap-export-v3", PassNfc, PassNfd)] // the first candidate
    [InlineData("tswap-export-v1", PassNfd, PassNfc)] // PBKDF2
    [InlineData("tswap-export-v3", LoneSurrogatePass, LoneSurrogatePass)] // [typed]
    public void OlderExport_MadeOverTheRawPassphrase_Imports(string version, string madeWith, string typed)
    {
        var path = OlderExport(version, madeWith);

        var (exit, err, value) = ImportFresh(path, typed);

        Assert.True(exit == 0, err);
        Assert.Equal("s-value-0042", value);
    }

    [Fact]
    public void Export_ConfirmationInTheOtherSpelling_IsAccepted()
    {
        var path = Export(PassNfc, PassNfd);

        Assert.Equal(0, ImportFresh(path, PassNfc).Exit);
    }

    [Fact]
    public void Export_ALoneSurrogatePassphrase_IsRefused_NothingWritten()
    {
        _m.Ok("s-value-0042", "ingest", "s");
        var path = _m.PathOf("refused-export.json");

        var (exit, _, err) = _m.Run(LoneSurrogatePass + "\n" + LoneSurrogatePass + "\n", "export", path);

        Assert.NotEqual(0, exit);
        Assert.Contains("The passphrase holds half of a character (a lone UTF-16 surrogate); type it again.", err);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Import_AWrongPassphrase_IsTodaysDecryptionFailure()
    {
        var path = Export(PassNfc, PassNfc);

        var (exit, err, _) = ImportFresh(path, "pa\u0308ss-export-2");

        Assert.NotEqual(0, exit);
        Assert.Contains("Decryption failed — wrong passphrase or file tampered", err);
    }

    [Fact]
    public void PassphraseCandidates_AreNfcTypedNfd_WithoutDuplicates()
    {
        Assert.Equal([PassNfc, PassNfd], ExportCrypto.PassphraseCandidates(PassNfd));
        Assert.Equal([PassNfc, PassNfd], ExportCrypto.PassphraseCandidates(PassNfc));
        Assert.Equal(["abc"], ExportCrypto.PassphraseCandidates("abc"));
        Assert.Equal([LoneSurrogatePass], ExportCrypto.PassphraseCandidates(LoneSurrogatePass));
        Assert.Equal(PassNfc, ExportCrypto.NormalisePassphrase(PassNfd));
    }
}
