using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Fix round 2: <see cref="RecordVaultStore.SaveSecrets"/> compares the database it is given with
/// what it loaded, so a secret missing from that database becomes a tombstone. An empty or partial
/// database saved by mistake would delete the shared vault; a save that would tombstone two or more
/// records therefore refuses and writes nothing. Deleting one secret per save keeps working.
/// </summary>
public sealed class EmptySaveGuardTests : IDisposable
{
    private readonly FleetMachine _m = new("empty-save", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _vaultKey;

    public EmptySaveGuardTests()
    {
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("v1", "ingest", "a");
        _m.Ok("v2", "ingest", "b");
        _m.Ok("v3", "ingest", "c");
    }

    public void Dispose() => _m.Dispose();

    private Dictionary<string, byte[]> Snapshot() =>
        Directory.GetFiles(_m.RecordsDir).ToDictionary(f => f, File.ReadAllBytes);

    private (RecordVaultStore Store, SecretsDb Db) Load()
    {
        var store = new RecordVaultStore(_m.Dir);
        store.LoadConfig();
        return (store, store.LoadSecrets(_vaultKey));
    }

    [Fact]
    public void SavingAnEmptyDatabase_Refuses_AndLeavesEveryRecordUntouched()
    {
        var before = Snapshot();
        var (store, _) = Load();

        var ex = Assert.Throws<TswapException>(() => store.SaveSecrets(new SecretsDb([]), _vaultKey));

        Assert.Contains("3 secrets", ex.Message);
        Assert.Contains("empty or partial", ex.Message);
        Assert.Equal(before.Keys.Order(), Snapshot().Keys.Order());
        Assert.All(before, kv => Assert.Equal(kv.Value, File.ReadAllBytes(kv.Key)));
        Assert.Equal("v1", _m.Get("a"));
    }

    [Fact]
    public void SavingWithTwoOfThreeMissing_Refuses_AndWritesNothing()
    {
        var before = Snapshot();
        var (store, db) = Load();
        db.Secrets.Remove("a");
        db.Secrets.Remove("b");
        db.Secrets["new"] = new Secret("x", DateTime.UtcNow, DateTime.UtcNow);

        var ex = Assert.Throws<TswapException>(() => store.SaveSecrets(db, _vaultKey));

        Assert.Contains("2 secrets", ex.Message);
        Assert.Equal(before.Keys.Order(), Snapshot().Keys.Order());
        Assert.All(before, kv => Assert.Equal(kv.Value, File.ReadAllBytes(kv.Key)));
    }

    [Fact]
    public void DeletingOneSecret_StillWritesItsTombstone()
    {
        _m.Ok("", "delete", "b");

        Assert.Equal(TswapCore.Keyring.RecordType.Tombstone, ReadRecord(_m, _vaultKey, "b").Type);
        Assert.Equal("v1", _m.Get("a"));
        Assert.Equal("v3", _m.Get("c"));
    }
}
