using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 5 (decision 6): before writing a record the store re-reads it, and refuses when it
/// changed in any way since this command loaded it (another process, another machine on the shared
/// folder, a sync tool). Nothing is written then, not even the other records of the same save.
/// </summary>
public sealed class StaleWriteGuardTests : IDisposable
{
    private readonly FleetMachine _m = new("stale", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _vaultKey;

    public StaleWriteGuardTests()
    {
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("v1", "ingest", "s");
    }

    public void Dispose() => _m.Dispose();

    private (RecordVaultStore Store, SecretsDb Db) Load()
    {
        var store = new RecordVaultStore(_m.Dir);
        store.LoadConfig();
        return (store, store.LoadSecrets(_vaultKey));
    }

    private Dictionary<string, byte[]> Snapshot() =>
        Directory.GetFiles(_m.RecordsDir).ToDictionary(f => f, File.ReadAllBytes);

    [Fact]
    public void AnotherProcessWritesANewerVersion_TheSaveIsRefused_AndNothingIsWritten()
    {
        var (store, db) = Load();

        // Another "process" (its own store instance) writes a newer version in between.
        var (other, otherDb) = Load();
        otherDb.Secrets["s"] = otherDb.Secrets["s"] with { Value = "v2-from-the-other-process" };
        other.SaveSecrets(otherDb, _vaultKey);
        var afterOther = Snapshot();
        var configAfterOther = File.ReadAllText(_m.ConfigPath);

        db.Secrets["s"] = db.Secrets["s"] with { Value = "v2-stale" };
        db.Secrets["t"] = new Secret("new", DateTime.UtcNow, DateTime.UtcNow);
        var ex = Assert.Throws<TswapException>(() => store.SaveSecrets(db, _vaultKey));

        Assert.Contains("changed on disk", ex.Message);
        Assert.Equal(afterOther.Keys.Order(), Snapshot().Keys.Order());
        Assert.All(afterOther, kv => Assert.Equal(kv.Value, File.ReadAllBytes(kv.Key)));
        Assert.Equal(configAfterOther, File.ReadAllText(_m.ConfigPath));
        Assert.Equal("v2-from-the-other-process", _m.Get("s"));
        Assert.Equal(1, _m.Run("", "get", "t").Exit);
    }

    [Fact]
    public void AnyDifference_NotOnlyANewerStamp_IsRefused()
    {
        var oldBytes = File.ReadAllBytes(RecordFile(_m, _vaultKey, "s"));
        _m.Ok("", "burn", "s", "seen");
        var (store, db) = Load();

        // A sync tool puts the older version back.
        File.WriteAllBytes(RecordFile(_m, _vaultKey, "s"), oldBytes);
        db.Secrets.Remove("s");

        Assert.Throws<TswapException>(() => store.SaveSecrets(db, _vaultKey));
        Assert.Equal(oldBytes, File.ReadAllBytes(RecordFile(_m, _vaultKey, "s")));
    }

    [Fact]
    public void ARecordCreatedElsewhereSinceTheLoad_IsNotOverwritten()
    {
        var (store, db) = Load();
        var (other, otherDb) = Load();
        otherDb.Secrets["fresh"] = new Secret("from-the-other-process", DateTime.UtcNow, DateTime.UtcNow);
        other.SaveSecrets(otherDb, _vaultKey);

        db.Secrets["fresh"] = new Secret("stale-create", DateTime.UtcNow, DateTime.UtcNow);

        Assert.Throws<TswapException>(() => store.SaveSecrets(db, _vaultKey));
        Assert.Equal("from-the-other-process", _m.Get("fresh"));
    }
}
