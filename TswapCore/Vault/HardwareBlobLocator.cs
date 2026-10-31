using TswapCore.Keyring;

namespace TswapCore.Vault;

/// <summary>
/// Finds a wrap/seal backend's blob (TPM sealed key, Secure Enclave wrapped key, or the
/// simulated backend's) in a <see cref="Config"/>. Shared by every such backend's
/// <see cref="IHardwareKeyService.Unlock"/>, so they all look in the same place:
/// <list type="bullet">
/// <item><b>Keyring vault</b> (<see cref="Config.Keyring"/> set, issue #154): this machine's own
/// machine slot's <see cref="Slot.HwBlob"/>, found by <see cref="Config.KeyringSlotId"/> (or the
/// only machine slot when that is null), the same lookup <see cref="VaultUnlocker"/> uses to pick
/// the slot it unwraps.</item>
/// <item><b>Pending slot request</b> (brief T5): <see cref="Config.PendingSlotHwBlob"/>, for
/// <c>slot accept</c>.</item>
/// <item><b>Single-slot vault</b> made before keyring vaults: <see cref="Config.TpmSealedKey"/>
/// (TPM) or <see cref="Config.SecureEnclaveWrappedKey"/> (Secure Enclave), base64.</item>
/// </list>
/// Throws <see cref="TswapException"/> with "Config is corrupted" messages (the single-slot ones
/// unchanged from what the real backends have always said).
/// </summary>
public static class HardwareBlobLocator
{
    public static byte[] Read(Config config, HardwareBackend backend)
    {
        var (field, missing, notBase64) = backend switch
        {
            HardwareBackend.Tpm => (config.TpmSealedKey,
                "vault uses the 'tpm' backend but has no sealed key",
                "the TPM sealed key is not valid base64"),
            HardwareBackend.SecureEnclave => (config.SecureEnclaveWrappedKey,
                "vault uses the 'secure-enclave' backend but has no wrapped key",
                "the Secure Enclave wrapped key is not valid base64"),
            _ => throw new ArgumentOutOfRangeException(nameof(backend), backend, "Only wrap/seal backends store a blob"),
        };

        if (config.Keyring is not null)
            return ReadFromOwnMachineSlot(config, backend);

        // Brief T5 decision 2: a machine between 'slot request --tpm|--secure-enclave' and 'slot
        // accept' keeps its freshly sealed blob in PendingSlotHwBlob; accept recovers KEK_slot from
        // it through VaultUnlocker.UnlockHardware. (VaultUnlocker.Unlock refuses a pending config
        // before it gets here, so this never opens a vault.) Only together with PendingSlotId,
        // which is what that guard keys on: a half-cleared config must not make the pending
        // KEK_slot a classic vault's master key.
        if (config.PendingSlotId is not null && config.PendingSlotHwBlob is null)
            throw new TswapException(
                $"Config is corrupted: this machine's pending '{backend.DisplayName()}' slot request has no hardware blob. " +
                "Run 'tswap slot request' again on this machine.");
        if (config.PendingSlotHwBlob is not null && config.PendingSlotId is not null)
        {
            try
            {
                return Convert.FromBase64String(config.PendingSlotHwBlob);
            }
            catch (FormatException)
            {
                throw new TswapException(
                    "Config is corrupted: the pending slot request's hardware blob is not valid base64. Run 'tswap slot request' again.");
            }
        }

        if (field is not { Length: > 0 })
            throw new TswapException($"Config is corrupted: {missing}. Restore config.json from backup or re-run 'tswap init'.");

        try
        {
            return Convert.FromBase64String(field);
        }
        catch (FormatException)
        {
            throw new TswapException($"Config is corrupted: {notBase64}. Restore config.json from backup or re-run 'tswap init'.");
        }
    }

    private static byte[] ReadFromOwnMachineSlot(Config config, HardwareBackend backend)
    {
        Keyring.Keyring keyring;
        byte[]? ownSlotId = null;
        try
        {
            keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
            if (config.KeyringSlotId is not null)
                ownSlotId = Convert.FromBase64String(config.KeyringSlotId);
        }
        catch (FormatException)
        {
            throw new TswapException(
                "Config is corrupted: Keyring or KeyringSlotId is not valid base64. Restore config.json from backup or re-run 'tswap init'.");
        }

        var slot = ownSlotId is not null
            ? keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine && s.SlotId.AsSpan().SequenceEqual(ownSlotId))
            : keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine);

        if (slot is null)
            throw new TswapException(
                "Config is corrupted: keyring has no machine slot matching this machine. Restore config.json from backup or re-run 'tswap init'.");

        if (slot.HwBlob is not { Length: > 0 } hwBlob)
            throw new TswapException(
                $"Config is corrupted: this machine's keyring slot has no '{backend.DisplayName()}' hardware blob. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        return hwBlob;
    }
}
