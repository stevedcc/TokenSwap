using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 decision 9: export and import keep their single-file encrypted format and serialize
/// whatever store is active. An export is a snapshot of the current values and burn state (no
/// tombstones, no history); importing into a record store writes each secret as a new version, so
/// importing an old export can bring back a deleted secret (the user's explicit act).
/// </summary>
public sealed class RecordStoreExportImportTests : IDisposable
{
    private readonly FleetMachine _m = new("export-records", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _vaultKey;

    public RecordStoreExportImportTests() => _vaultKey = VaultKey(_m, InitRecordVault(_m));

    public void Dispose() => _m.Dispose();

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
        Assert.Contains("tswap-export-v2", exportText);

        _m.Ok("", "delete", "deleted-later");
        var tombstone = ReadRecord(_m, _vaultKey, "deleted-later");
        _m.Ok("pass\n", "import", export);

        Assert.Equal("v2", _m.Get("deleted-later"));
        Assert.True(ReadRecord(_m, _vaultKey, "deleted-later").Version.CompareTo(tombstone.Version) > 0);
        Assert.Equal("v1", _m.Get("kept"));
        // The rotated secret's history stays in the vault; the export carried no history.
        Assert.Single(ReadRecord(_m, _vaultKey, "rotated").Burns);
    }
}
