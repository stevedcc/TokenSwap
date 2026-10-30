using System.Text;
using System.Text.Json;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T8 fix round 2, item 4: <see cref="RecordVaultStore.ReadSecretValue"/> folds a record's
/// sync-conflict copies by T6's merge rules, and decrypts exactly those files, no other record.
/// </summary>
public sealed class BrokerVaultConflictTests : IDisposable
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly FleetMachine _other;
    private readonly byte[] _vaultKey;
    private DateTimeOffset _now = T0;
    private DateTimeOffset _otherNow = T0;

    public BrokerVaultConflictTests()
    {
        _m = new FleetMachine("bk-conflict-a", _keys) { Clock = () => _now };
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
        _other = new FleetMachine("bk-conflict-b", _keys) { Clock = () => _otherNow };
    }

    public void Dispose()
    {
        _m.Dispose();
        _other.Dispose();
    }

    /// <summary>Another replica of the vault folder, with an older and a newer value of "s" on the two sides.</summary>
    private (string Older, string Newer) TwoVersionsOfS()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("a", "ingest", "unrelated-a");
        _m.Ok("b", "ingest", "unrelated-b");
        var copy = Path.Combine(_other.Dir, "vault");
        foreach (var dir in Directory.GetDirectories(_m.VaultDir!, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(dir.Replace(_m.VaultDir!, copy));
        foreach (var file in Directory.GetFiles(_m.VaultDir!, "*", SearchOption.AllDirectories))
            File.Copy(file, file.Replace(_m.VaultDir!, copy));
        File.WriteAllText(_other.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { VaultDir = copy, OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));
        _otherNow = T0.AddMinutes(5);
        _other.Ok("v2\nv2\n", "add", "s"); // newer on the other replica
        return (RecordFile(_m, _vaultKey, "s"), RecordFile(_other, _vaultKey, "s"));
    }

    private (string? Value, List<string> Decrypted) Read(string name)
    {
        var store = Assert.IsType<RecordVaultStore>(VaultStores.Open(_m.Dir));
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;
        var value = store.ReadSecretValue(name, _vaultKey);
        return (value is null ? null : Encoding.UTF8.GetString(value), decrypted);
    }

    [Fact]
    public void MainRecordDeleted_OneConflictCopy_IsTheValue_AndOnlyItIsDecrypted()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var (older, newer) = TwoVersionsOfS();
        var copy = older + " (1)";
        File.Copy(newer, copy);
        File.Delete(older);

        var (value, decrypted) = Read("s");

        Assert.Equal("v2", value);
        Assert.Equal([Path.GetFileName(copy)], decrypted);
    }

    [Fact]
    public void MainRecordDeleted_TwoConflictCopies_TheMergedWinner_AndExactlyThoseTwoDecrypted()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var (older, newer) = TwoVersionsOfS();
        var oldCopy = older + " (conflicted copy 2026-10-30)";
        var newCopy = older + ".sync-conflict-20261030-120000-ABCDEF";
        File.Copy(older, oldCopy);
        File.Copy(newer, newCopy);
        File.Delete(older);

        var (value, decrypted) = Read("s");

        Assert.Equal("v2", value);
        Assert.Equal([Path.GetFileName(oldCopy), Path.GetFileName(newCopy)], decrypted.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void MainRecordAndANewerConflictCopy_TheNewerWins_AndOnlyTheseTwoAreDecrypted()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var (older, newer) = TwoVersionsOfS();
        var copy = older + " (1)";
        File.Copy(newer, copy);

        var (value, decrypted) = Read("s");

        Assert.Equal("v2", value);
        Assert.Equal([Path.GetFileName(older), Path.GetFileName(copy)], decrypted.Order(StringComparer.Ordinal));
    }
}
