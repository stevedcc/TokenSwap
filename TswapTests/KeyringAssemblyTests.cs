using System.Security.Cryptography;
using System.Text.Json;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Backend-neutral keyring assembly (issue #151 work item 2, brief T2 item 3):
/// <c>InitCommand.AssembleKeyring</c> takes only <c>KEK_slot</c> and a <see cref="Config"/> the
/// backend has already filled, and adds the keyring to it. The YubiKey-shaped
/// <c>BuildKeyringConfig</c> stays as a thin wrapper that fills the YubiKey fields; its output
/// is pinned here field by field so the split cannot change what a YubiKey keyring vault
/// writes, apart from the random values.
/// </summary>
public class KeyringAssemblyTests
{
    [Fact]
    public void YubiKeyKeyringConfig_IsUnchangedFieldByField()
    {
        var before = DateTime.UtcNow;
        var kekSlot = RandomNumberGenerator.GetBytes(32);
        var serials = new List<int> { 11111111, 22222222 };
        var xor = Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
        var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var salt = RandomNumberGenerator.GetBytes(32);

        var (config, vaultKey, recoveryPrivateKey) = InitCommand.BuildKeyringConfig(
            kekSlot, serials, xor, requiresTouch: true, RngMode.YubiKey, challenge, salt, includeRecovery: true);

        // Every Config field, in declaration order.
        Assert.Equal(serials, config.YubiKeySerials);
        Assert.Equal(xor, config.RedundancyXor);
        Assert.InRange(config.Created, before, DateTime.UtcNow);
        Assert.Equal(DateTimeKind.Utc, config.Created.Kind);
        Assert.True(config.RequiresTouch);
        Assert.Equal(RngMode.YubiKey, config.RngMode);
        Assert.Equal(challenge, config.UnlockChallenge);
        Assert.Null(config.Backend);
        Assert.Null(config.SecureEnclaveWrappedKey);
        Assert.Null(config.TpmSealedKey);
        Assert.Equal(Convert.ToBase64String(salt), config.MasterKeySalt);
        Assert.NotNull(config.Keyring);
        Assert.Null(config.PendingSlotId);
        Assert.Null(config.PendingSlotPublicKey);
        Assert.Null(config.PendingSlotPrivateKey);
        Assert.NotNull(config.KeyringSlotId);

        // The keyring structure.
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        Assert.Equal(KeyringFormat.KeyringFormatVersion, keyring.FormatVersion);
        Assert.Equal(KeyringFormat.VaultIdSize, keyring.VaultId.Length);
        Assert.Equal(1, keyring.K);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));

        var machine = keyring.Slots[0];
        Assert.Equal(config.KeyringSlotId, Convert.ToBase64String(machine.SlotId));
        Assert.Equal(SlotKeyPair.KeySize, machine.PublicKey.Length);
        Assert.Equal(12 + 16 + 64, machine.Wrapped.Length); // nonce + tag + (K_v || slot private key)
        var (machineVaultKey, slotPrivateKey) = SlotSecretPayload.Decode(SlotPayloadWrap.Unwrap(
            machine.Wrapped, kekSlot, keyring.FormatVersion, keyring.VaultId, keyring.K, machine.SlotId));
        Assert.Equal(vaultKey, machineVaultKey);
        Assert.Equal(SlotKeyPair.KeySize, slotPrivateKey.Length);

        var recovery = keyring.Slots[1];
        Assert.NotEqual(machine.SlotId, recovery.SlotId);
        Assert.Equal(SlotKeyPair.KeySize, recovery.PublicKey.Length);
        Assert.Equal(vaultKey, RecoverySlotWrap.Unwrap(
            recovery.Wrapped, recovery.PublicKey, recoveryPrivateKey!,
            keyring.FormatVersion, keyring.VaultId, keyring.K, recovery.SlotId));

        // And the on-disk JSON has exactly the same properties, in the same order.
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(config, TswapJsonContext.Default.Config));
        Assert.Equal(
            ["YubiKeySerials", "RedundancyXor", "Created", "RequiresTouch", "RngMode", "UnlockChallenge", "MasterKeySalt", "Keyring", "KeyringSlotId"],
            json.RootElement.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public void AssembleKeyring_KeepsTheBackendsConfigAndAddsOnlyTheKeyring()
    {
        // A non-YubiKey backend's config: YubiKeySerials = [] and RedundancyXor = "" (issue
        // #151's note: keep the convention, no on-disk change).
        var backendConfig = new Config(
            YubiKeySerials: [],
            RedundancyXor: "",
            Created: new DateTime(2026, 10, 29, 12, 0, 0, DateTimeKind.Utc),
            RequiresTouch: false,
            RngMode: RngMode.System,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: "c2VhbGVk");
        var kekSlot = RandomNumberGenerator.GetBytes(32);

        var (config, vaultKey, recoveryPrivateKey) = InitCommand.AssembleKeyring(kekSlot, backendConfig, includeRecovery: true);

        Assert.Equal(backendConfig with { Keyring = config.Keyring, KeyringSlotId = config.KeyringSlotId }, config);
        Assert.Empty(config.YubiKeySerials);
        Assert.Equal("", config.RedundancyXor);

        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var machine = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Machine);
        Assert.Equal(config.KeyringSlotId, Convert.ToBase64String(machine.SlotId));
        var (machineVaultKey, _) = SlotSecretPayload.Decode(SlotPayloadWrap.Unwrap(
            machine.Wrapped, kekSlot, keyring.FormatVersion, keyring.VaultId, keyring.K, machine.SlotId));
        Assert.Equal(vaultKey, machineVaultKey);

        var recovery = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        Assert.Equal(vaultKey, RecoverySlotWrap.Unwrap(
            recovery.Wrapped, recovery.PublicKey, recoveryPrivateKey!,
            keyring.FormatVersion, keyring.VaultId, keyring.K, recovery.SlotId));
    }

    [Fact]
    public void AssembleKeyring_NoRecovery_HasOnlyTheMachineSlot()
    {
        var backendConfig = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave, SecureEnclaveWrappedKey: "d3JhcHBlZA==");

        var (config, _, recoveryPrivateKey) = InitCommand.AssembleKeyring(RandomNumberGenerator.GetBytes(32), backendConfig, includeRecovery: false);

        Assert.Null(recoveryPrivateKey);
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        Assert.Equal(SlotKind.Machine, Assert.Single(keyring.Slots).Kind);
    }

    [Fact]
    public void AssembleKeyring_RejectsAConfigThatAlreadyHasAKeyring()
    {
        var existing = InitCommand.AssembleKeyring(RandomNumberGenerator.GetBytes(32),
            new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm, TpmSealedKey: "eA=="), includeRecovery: false).Config;

        Assert.Throws<ArgumentException>(() => InitCommand.AssembleKeyring(RandomNumberGenerator.GetBytes(32), existing, includeRecovery: false));
    }
}
