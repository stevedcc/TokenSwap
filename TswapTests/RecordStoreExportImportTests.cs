using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Fields;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 decision 9: export and import keep their single-file encrypted format and serialize
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
}
