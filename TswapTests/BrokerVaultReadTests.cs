using System.Text;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 fix round 1, item 5 (owner decision: "keep as little data unlocked for as short a time
/// as possible"): the broker reads one record of a record-store vault per request, never the
/// whole database, and serve refuses a classic vault.
/// </summary>
public class BrokerVaultReadTests : IDisposable
{
    private readonly FleetMachine _m = new("brokerrec") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };

    public void Dispose() => _m.Dispose();

    private VaultUnlocker Unlocker(byte[]? tpm = null) =>
        new(_m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, tpm ?? _m.Tpm!)]);

    /// <summary>A TPM vault with <paramref name="count"/> secrets s0..sN, migrated to a record store.</summary>
    private RecordVaultStore RecordVault(int count)
    {
        _m.Ok("", "init", "--tpm", "--no-recovery");
        for (var i = 0; i < count; i++)
            _m.Ok($"value-{i}\n", "ingest", "s" + i);
        _m.Ok("", "migrate", "--to-records");
        return Assert.IsType<RecordVaultStore>(VaultStores.Open(_m.Dir));
    }

    [Fact]
    public void ARequest_DecryptsExactlyOneRecord_OfFifty()
    {
        if (OperatingSystem.IsWindows())
            return;
        var store = RecordVault(50);
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;
        var source = new VaultBrokerSecretSource(store, Unlocker());

        using (var secret = source.Read("s17"))
            Assert.Equal("value-17", Encoding.UTF8.GetString(secret.Value));
        Assert.Single(decrypted);
        using (var secret = source.Read("s42"))
            Assert.Equal("value-42", Encoding.UTF8.GetString(secret.Value));
        Assert.Equal(2, decrypted.Count);
        Assert.NotEqual(decrypted[0], decrypted[1]);
    }

    [Fact]
    public void AMissingSecret_DecryptsNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        var store = RecordVault(3);
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;

        Assert.Throws<BrokerSecretException>(() => new VaultBrokerSecretSource(store, Unlocker()).Read("missing"));
        Assert.Empty(decrypted);
    }

    [Fact]
    public void AnUnreadableTargetRecord_FailsClosed_AndNoOtherRecordIsRead()
    {
        if (OperatingSystem.IsWindows())
            return;
        var store = RecordVault(5);
        var key = Unlocker().Unlock(store.LoadConfig(), _ => 0);
        var target = Path.Combine(store.RecordsDir, TswapCore.Keyring.FilenameHasher.ComputeFilename(
            TswapCore.Keyring.RecordKeyDerivation.DeriveNamesKey(key), "s2"));
        var bytes = File.ReadAllBytes(target);
        bytes[^1] ^= 0xFF; // tampered: fails authentication
        File.WriteAllBytes(target, bytes);
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;

        var ex = Assert.Throws<BrokerSecretException>(() => new VaultBrokerSecretSource(store, Unlocker()).Read("s2"));

        Assert.Contains("can't be read", ex.Message);
        Assert.Equal([Path.GetFileName(target)], decrypted);
    }

    [Fact]
    public void AnUnlockThatFails_IsAnUnlockFailure()
    {
        if (OperatingSystem.IsWindows())
            return;
        var store = RecordVault(1);
        Assert.Throws<BrokerUnlockException>(() => new VaultBrokerSecretSource(store, Unlocker(new byte[32])).Read("s0"));
    }

    [Fact]
    public void Serve_OnAClassicVault_RefusesToStart_NamingTheMigration()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", "init", "--tpm", "--no-recovery");
        _m.Ok("", "broker", "route", "add", "api", "--upstream", "https://a.example", "--auth", "bearer", "--secret", "k", "--path", "");

        var (exit, _, err) = _m.Run("", "broker", "serve");

        Assert.NotEqual(0, exit);
        Assert.Contains("sudo tswap migrate --to-records", err);
    }
}
