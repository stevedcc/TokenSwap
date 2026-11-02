using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Owner decision 2026-11-02 (brief T16-S1 fix round 2, item 10): a plain <c>slot accept</c> (no
/// <c>--vault-dir</c>) on a machine without a vault creates a record vault at
/// <c>&lt;config dir&gt;/vault</c> with the <c>record-format</c> marker, as plain <c>init</c> does; it never
/// writes a classic vault (which every command would then refuse) again.
/// </summary>
public sealed class SlotAcceptRecordVaultTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _router;
    private readonly FleetMachine _desktop;

    public SlotAcceptRecordVaultTests()
    {
        _router = new FleetMachine("accept-rec-router", _keys) { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };
        _desktop = new FleetMachine("accept-rec-desktop", _keys);
        _keys.PluggedIn = [];
        _router.Ok("", "init", "--tpm");
    }

    public void Dispose()
    {
        _router.Dispose();
        _desktop.Dispose();
    }

    /// <summary>request on the desktop (key A), approve on the router, accept on the desktop.</summary>
    private (int Exit, string Out, string Err) JoinWithKeyA()
    {
        var request = _desktop.PathOf("request.json");
        var approve = _desktop.PathOf("approve.json");
        _keys.PluggedIn = [SerialA];
        _desktop.Ok("", "slot", "request", request);
        _router.Ok("", "slot", "approve", request, approve);
        return _desktop.Run("", "slot", "accept", approve);
    }

    [Fact]
    public void PlainAccept_CreatesARecordVault_WithTheMarker_ThatTheJoinedKeyOpens()
    {
        var (exit, _, err) = JoinWithKeyA();

        Assert.True(exit == 0, err);
        var config = _desktop.Config;
        var vaultDir = Path.Combine(_desktop.Dir, "vault");
        Assert.Equal(RecordVaultStore.StoreName, config.Store);
        Assert.Equal(vaultDir, config.VaultDir);
        Assert.Null(config.Keyring);
        Assert.Null(config.PendingSlotId);
        Assert.NotNull(config.OriginId);
        Assert.False(File.Exists(_desktop.SecretsPath));
        Assert.Equal("3", File.ReadAllText(Path.Combine(vaultDir, RecordVaultStore.RecordFormatMarkerFileName)).Trim());
        var keyring = KeyringCodec.Decode(File.ReadAllBytes(Path.Combine(vaultDir, "keyring")));
        Assert.Equal(_router.Keyring.VaultId, keyring.VaultId);
        Assert.Equal(3, keyring.Slots.Count);
        Assert.Equal(config.KeyringSlotId, Convert.ToBase64String(keyring.Slots[2].SlotId));

        // Key A alone opens it (no TPM on the desktop): a write and a read back, in format 3.
        _keys.PluggedIn = [SerialA];
        _desktop.Ok("desk-value", "ingest", "desk");
        Assert.Equal("desk-value", _desktop.Get("desk"));
        var record = Directory.GetFiles(Path.Combine(vaultDir, "records")).Single();
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(record)));
        _keys.PluggedIn = [SerialB];
        Assert.NotEqual(0, _desktop.Run("", "get", "desk").Exit);
    }

    [Fact]
    public void PlainAccept_IntoANonEmptyDefaultFolder_IsRefused_AndChangesNothing()
    {
        var vaultDir = Path.Combine(_desktop.Dir, "vault");
        Directory.CreateDirectory(vaultDir);
        File.WriteAllText(Path.Combine(vaultDir, "something"), "x");
        var request = _desktop.PathOf("request.json");
        var approve = _desktop.PathOf("approve.json");
        _keys.PluggedIn = [SerialA];
        _desktop.Ok("", "slot", "request", request);
        _router.Ok("", "slot", "approve", request, approve);
        var config = File.ReadAllText(_desktop.ConfigPath);

        var (exit, _, err) = _desktop.Run("", "slot", "accept", approve);

        Assert.NotEqual(0, exit);
        Assert.Contains("not empty", err);
        Assert.Equal(config, File.ReadAllText(_desktop.ConfigPath));
        Assert.Equal(["something"], Directory.GetFileSystemEntries(vaultDir).Select(Path.GetFileName));
        Assert.False(File.Exists(_desktop.SecretsPath));
    }
}
