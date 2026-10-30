using System.Security.Cryptography;
using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 2 (decision 2): the vault folder's <c>keyring</c> file. A save reads what is on
/// disk and writes the union (by slot id), so it never drops a slot it didn't know about; a load
/// folds in sync tools' conflicted copies of <c>keyring</c>; another vault's keyring, or one slot id
/// with different bytes, is refused loudly, never resolved by picking one.
/// </summary>
public sealed class KeyringFileTests : IDisposable
{
    private const int SerialC = 33333333;
    private const int SerialD = 34444444;
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB, SerialC, SerialD);
    private readonly FleetMachine _m;
    private readonly string _recoveryKey;

    public KeyringFileTests()
    {
        _m = new FleetMachine("keyring-a", _keys);
        _keys.PluggedIn = [SerialA];
        _recoveryKey = InitRecordVault(_m);
        _keys.PluggedIn = [SerialA, SerialB, SerialC];
    }

    public void Dispose() => _m.Dispose();

    private string KeyringPath => Path.Combine(_m.VaultDir!, "keyring");

    private static Slot FakeSlot(SlotKind kind = SlotKind.Machine) => new(
        RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize),
        RandomNumberGenerator.GetBytes(SlotKeyPair.KeySize),
        RandomNumberGenerator.GetBytes(80),
        kind,
        kind == SlotKind.Machine ? RandomNumberGenerator.GetBytes(40) : null);

    private static Config WithKeyring(Config config, Keyring keyring) =>
        config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(keyring)) };

    private static Keyring KeyringOf(Config config) => KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

    private static bool Has(Keyring keyring, Slot slot) => keyring.Slots.Any(s => s.SlotId.AsSpan().SequenceEqual(slot.SlotId));

    /// <summary>A second machine whose config points at the same vault folder.</summary>
    private FleetMachine SecondMachineOnTheSameFolder()
    {
        var other = new FleetMachine("keyring-b", _keys);
        File.WriteAllText(other.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { OriginId = RecordVaultStore.NewOriginId() }, TswapJsonContext.Default.Config));
        return other;
    }

    [Fact]
    public void TwoMachinesOnOneFolder_EachAddASlot_TheKeyringFileHasBoth()
    {
        using var other = SecondMachineOnTheSameFolder();
        var storeA = new RecordVaultStore(_m.Dir);
        var storeB = new RecordVaultStore(other.Dir);
        var configA = storeA.LoadConfig();
        var configB = storeB.LoadConfig();
        var slotB = FakeSlot();
        var slotA = FakeSlot();

        // B saves first; A, still holding the keyring it loaded before B's save, saves after.
        storeB.SaveConfig(WithKeyring(configB, KeyringOf(configB) with { Slots = [.. KeyringOf(configB).Slots, slotB] }));
        storeA.SaveConfig(WithKeyring(configA, KeyringOf(configA) with { Slots = [.. KeyringOf(configA).Slots, slotA] }));

        var onDisk = KeyringCodec.Decode(File.ReadAllBytes(KeyringPath));
        Assert.True(Has(onDisk, slotA));
        Assert.True(Has(onDisk, slotB));
        Assert.Equal(KeyringOf(configA).Slots.Count + 2, onDisk.Slots.Count);
    }

    [Fact]
    public void TwoCopiesOfTheFolder_EachSlotAddAKey_TheSyncedConflictCopyIsFoldedIn_AndBothKeysOpenTheVault()
    {
        // Copy 2: the same vault folder copied elsewhere, used by a second machine config.
        using var copy = new FleetMachine("keyring-copy", _keys);
        var copyFolder = Path.Combine(copy.Dir, "vault");
        CopyFolder(_m.VaultDir!, copyFolder);
        File.WriteAllText(copy.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { VaultDir = copyFolder, OriginId = RecordVaultStore.NewOriginId() }, TswapJsonContext.Default.Config));

        _keys.PluggedIn = [SerialA, SerialB];
        _m.Ok("", "slot", "add", "--yubikey");
        _keys.PluggedIn = [SerialA, SerialC];
        copy.Ok("", "slot", "add", "--yubikey");

        // A sync tool brings copy 2's keyring back as a conflicted copy.
        var conflicted = Path.Combine(_m.VaultDir!, "keyring (conflicted copy 2026-10-30)");
        File.Copy(Path.Combine(copyFolder, "keyring"), conflicted);

        var loaded = KeyringOf(new RecordVaultStore(_m.Dir).LoadConfig());
        Assert.Equal(4, loaded.Slots.Count); // key A, recovery, key B, key C

        // Key C (only in the conflicted copy) opens the vault on this machine.
        _m.Ok("v", "ingest", "s");
        _keys.PluggedIn = [SerialC];
        Assert.Equal("v", _m.Get("s"));

        // The next keyring write stores the union and removes the copy it made redundant.
        _keys.PluggedIn = [SerialD];
        _m.Ok(_recoveryKey, "slot", "add", "--yubikey", "--recovery-key-stdin");
        Assert.False(File.Exists(conflicted));
        Assert.Equal(5, KeyringCodec.Decode(File.ReadAllBytes(KeyringPath)).Slots.Count);
    }

    [Fact]
    public void AnUndecodableKeyringConflictCopy_IsWarnedAboutAndKept()
    {
        var conflicted = Path.Combine(_m.VaultDir!, "keyring.sync-conflict-20261030-120000-ABCDEF");
        File.WriteAllBytes(conflicted, [1, 2, 3]);

        var (exit, _, err) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.Contains("keyring.sync-conflict-20261030-120000-ABCDEF", err);
        Assert.True(File.Exists(conflicted));
    }

    [Fact]
    public void AConflictCopyFromAnotherVault_IsRefused()
    {
        using var stranger = new FleetMachine("stranger", _keys);
        InitRecordVault(stranger);
        File.Copy(Path.Combine(stranger.VaultDir!, "keyring"), Path.Combine(_m.VaultDir!, "keyring-LAPTOP-42"));

        var (exit, _, err) = _m.Run("", "names");

        Assert.NotEqual(0, exit);
        Assert.Contains("another vault", err);
    }

    [Fact]
    public void SavingAKeyringOfAnotherVault_IsRefused_AndTheFileIsUnchanged()
    {
        var before = File.ReadAllBytes(KeyringPath);
        var store = new RecordVaultStore(_m.Dir);
        var config = store.LoadConfig();
        var foreign = KeyringOf(config) with { VaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize) };

        var ex = Assert.Throws<TswapException>(() => store.SaveConfig(WithKeyring(config, foreign)));

        Assert.Contains("another vault", ex.Message);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath));
    }

    [Fact]
    public void TheSameSlotIdWithDifferentBytes_IsRefusedLoudly_OnLoadAndOnSave()
    {
        var store = new RecordVaultStore(_m.Dir);
        var config = store.LoadConfig();
        var keyring = KeyringOf(config);
        var altered = keyring with
        {
            Slots = [keyring.Slots[0] with { Wrapped = RandomNumberGenerator.GetBytes(keyring.Slots[0].Wrapped.Length) }, .. keyring.Slots.Skip(1)],
        };

        Assert.Contains("differs", Assert.Throws<TswapException>(() => store.SaveConfig(WithKeyring(config, altered))).Message);

        File.WriteAllBytes(Path.Combine(_m.VaultDir!, "keyring (1)"), KeyringCodec.Encode(altered));
        var (exit, _, err) = _m.Run("", "names");
        Assert.NotEqual(0, exit);
        Assert.Contains("differs", err);
    }

    private static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var file in Directory.GetFiles(from))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (var dir in Directory.GetDirectories(from))
            CopyFolder(dir, Path.Combine(to, Path.GetFileName(dir)));
    }
}
