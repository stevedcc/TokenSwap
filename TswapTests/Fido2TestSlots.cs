using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 2: keyrings that hold an OTP slot and a FIDO2 slot side by side, for the tests of every place
/// that reads YubiKey slot blobs. A FIDO2 slot here wraps the vault key under a random KEK: nothing in task 2 opens
/// one, so its blob is what matters.
/// </summary>
internal sealed class Fido2TestSlots
{
    public const int Fido2Serial = 33060005;

    /// <summary>YubiKey 5 NFC or 5C NFC (<see cref="YubicoAaguids"/>).</summary>
    public static readonly Guid Aaguid = Guid.Parse("d7781e5d-e353-46aa-afe2-3ca49f13332a");

    public const string ModelName = "YubiKey 5 NFC or 5C NFC";

    public byte[] VaultKey { get; } = RandomNumberGenerator.GetBytes(32);
    public byte[] VaultId { get; } = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
    public List<Slot> Slots { get; } = [];
    public byte[]? RecoveryPrivateKey { get; private set; }

    public static Fido2SlotBlob Blob(int? serial = Fido2Serial, bool requiresPassword = false) =>
        Fido2SlotBlob.Create(serial, Aaguid, RandomNumberGenerator.GetBytes(64), requiresPassword);

    /// <summary>An OTP slot whose KEK comes from <paramref name="keys"/>, so it really opens the vault with that key.</summary>
    public Slot AddOtp(IYubiKeyService keys, int serial, bool requiresPassword = false, bool? requiresTouch = true)
    {
        var blob = YubiKeySlotBlob.Create(serial, requiresTouch);
        if (requiresPassword)
            blob = blob.WithPassword();
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var kek = requiresPassword ? RandomNumberGenerator.GetBytes(32) : YubiKeySlotKek.Recover(keys, blob, slotId);
        return Add(kek, blob.Encode(), slotId);
    }

    public Slot AddFido2(Fido2SlotBlob blob) => Add(RandomNumberGenerator.GetBytes(32), blob.Encode());

    public Slot AddRecovery()
    {
        var recovery = SlotKeyPair.Generate();
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            VaultKey, recovery.PublicKey, KeyringFormat.KeyringFormatVersion, VaultId, 1, slotId);
        RecoveryPrivateKey = recovery.PrivateKey;
        var slot = new Slot(slotId, ephemeralPublicKey, wrapped, SlotKind.Recovery);
        Slots.Add(slot);
        return slot;
    }

    private Slot Add(byte[] kek, byte[] hwBlob, byte[]? slotId = null)
    {
        slotId ??= RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var pair = SlotKeyPair.Generate();
        var slot = MachineSlotWrap.Wrap(VaultKey, pair.PrivateKey, pair.PublicKey, slotId, kek,
            KeyringFormat.KeyringFormatVersion, VaultId, 1) with { HwBlob = hwBlob };
        Slots.Add(slot);
        return slot;
    }

    public Keyring Keyring => new(KeyringFormat.KeyringFormatVersion, VaultId, 1, [.. Slots]);

    /// <summary>A keyring config of <paramref name="backend"/> whose own slot is <paramref name="own"/>.</summary>
    public Config Config(HardwareBackend? backend = HardwareBackend.YubiKey, Slot? own = null) => new(
        [], "", TestTime.Fixed, RngMode: RngMode.System, Backend: backend,
        Keyring: Convert.ToBase64String(KeyringCodec.Encode(Keyring)),
        KeyringSlotId: own is null ? null : Convert.ToBase64String(own.SlotId));

    /// <summary><paramref name="keyring"/> with a FIDO2 slot added (wrapping random bytes: only its blob is read).</summary>
    public static Keyring WithFido2Slot(Keyring keyring, Fido2SlotBlob blob)
    {
        var pair = SlotKeyPair.Generate();
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var slot = MachineSlotWrap.Wrap(RandomNumberGenerator.GetBytes(32), pair.PrivateKey, pair.PublicKey, slotId,
            RandomNumberGenerator.GetBytes(32), keyring.FormatVersion, keyring.VaultId, keyring.K) with { HwBlob = blob.Encode() };
        return keyring with { Slots = [.. keyring.Slots, slot] };
    }

    public static string Id8(Slot slot) => Convert.ToHexStringLower(slot.SlotId)[..8];
}
