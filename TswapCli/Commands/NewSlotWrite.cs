using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCli.Commands;

/// <summary>
/// Brief T24: the steps <c>recover</c> and <c>slot add</c> share when a new slot goes into this machine's keyring: the
/// slot's wrap (a fresh X25519 keypair, <c>KEK_slot</c> and the private key zeroed), a TPM or Secure Enclave slot made
/// this machine's own (<see cref="EnrolOwnSlot"/>, <see cref="AsOwnSlot"/>), and the one write (<see cref="Save"/>).
/// </summary>
internal static class NewSlotWrite
{
    /// <summary>
    /// Wraps <paramref name="vaultKey"/> into a new machine slot <paramref name="slotId"/> under
    /// <paramref name="kekSlot"/>, carrying <paramref name="hwBlob"/>. Zeroes <paramref name="kekSlot"/> and the slot's
    /// private key, which then lives only inside the wrap.
    /// </summary>
    public static Slot Wrap(byte[] vaultKey, TswapCore.Keyring.Keyring keyring, byte[] slotId, byte[] kekSlot, byte[] hwBlob)
    {
        try
        {
            var slotKeyPair = SlotKeyPair.Generate();
            try
            {
                return MachineSlotWrap.Wrap(
                    vaultKey, slotKeyPair.PrivateKey, slotKeyPair.PublicKey, slotId, kekSlot,
                    keyring.FormatVersion, keyring.VaultId, keyring.K) with { HwBlob = hwBlob };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(slotKeyPair.PrivateKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekSlot);
        }
    }

    /// <summary>Enrols this machine's TPM or Secure Enclave (with the stretched vault password, or none) and wraps the new slot.</summary>
    public static Slot EnrolOwnSlot(IHardwareEnrolmentService enrolment, byte[] vaultKey, TswapCore.Keyring.Keyring keyring,
        byte[] slotId, StretchedPassword? password)
    {
        var (kekSlot, hwBlob) = enrolment.Enrol(password);
        return Wrap(vaultKey, keyring, slotId, kekSlot, hwBlob);
    }

    /// <summary>
    /// The three machine-local fields that make slot <paramref name="slotId"/> this machine's own
    /// <paramref name="hardware"/> slot: <see cref="Config.Backend"/> (else the unlock routes the own slot to the YubiKey
    /// backend), <see cref="Config.KeyringSlotId"/> (what <see cref="HardwareBlobLocator"/> reads) and
    /// <see cref="Config.RequiresTouch"/> (brief T11 decision 6: true only for a Secure Enclave slot with presence).
    /// </summary>
    public static Config AsOwnSlot(Config config, HardwareBackend hardware, byte[] slotId, bool requirePresence) => config with
    {
        Backend = hardware,
        KeyringSlotId = Convert.ToBase64String(slotId),
        RequiresTouch = hardware == HardwareBackend.SecureEnclave && requirePresence,
    };

    /// <summary>
    /// The one write of a new slot, in this order: <c>config.json</c> backed up (the path printed), then a first password's
    /// <c>vault-password</c> file (before the keyring that needs it), then <see cref="IVaultStore.SaveConfig"/> (on a record
    /// vault the shared <c>keyring</c>, then this machine's <c>config.json</c>). Each is the store's atomic,
    /// owner-preserving write (<see cref="DirectoryOwnerMatcher"/>), so under sudo every file keeps the vault folder
    /// owner's ownership and mode.
    /// <para>What a failure leaves: before <c>SaveConfig</c>, the keyring as it was (a first password's file may already
    /// be there, and a rerun asks once against it). Between the shared <c>keyring</c> and <c>config.json</c>, an extra
    /// slot this config doesn't point at: the vault opens as before, and a rerun adds another slot (the orphan stays;
    /// keyrings merge as a union). No file is half written.</para>
    /// </summary>
    public static void Save(CommandContext ctx, Config newConfig, VaultPasswordFile? newPasswordFile)
    {
        if (ctx.Storage is IFileVaultStore fileStore && fileStore.Owner.FileExists(fileStore.ConfigFile))
            ctx.Console.Out.WriteLine($"\nPrevious config backed up to: {fileStore.BackupConfig()}");
        if (newPasswordFile is not null && ctx.Storage is RecordVaultStore recordStore)
            recordStore.WriteVaultPassword(newPasswordFile);
        ctx.Storage.SaveConfig(newConfig);
    }

    /// <summary>
    /// The last lines after a new slot of this machine's (<c>recover</c>, <c>slot add --tpm|--secure-enclave</c>): its
    /// fingerprint, the slot count, and how other machines get it (#247: a record vault keeps its keyring in the vault
    /// folder, so sharers read it there and own copies take it by <c>vault merge</c>).
    /// </summary>
    public static void PrintSharingFooter(CommandContext ctx, Slot newSlot, TswapCore.Keyring.Keyring extended)
    {
        var c = ctx.Console;
        SlotCommand.PrintFingerprint(c, "New slot", newSlot.PublicKey);
        c.Out.WriteLine($"Slots in this machine's keyring: {extended.Slots.Count}");
        var folder = (ctx.Storage as RecordVaultStore)?.VaultDir ?? "this vault's folder";
        c.Out.WriteLine("Machines that share this vault folder get the new slot with it.");
        c.Out.WriteLine($"A machine with its own copy of the vault gets it once you copy {folder} there and run, on that machine:");
        c.Out.WriteLine($"  sudo {ctx.Prefix} vault merge <the copied folder>   (it asks you to confirm the new slot, or pass --yes)");
    }
}
