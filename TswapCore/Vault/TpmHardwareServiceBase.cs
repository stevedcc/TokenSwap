using TswapCore.Keyring;
using TswapCore.VaultPassword;

namespace TswapCore.Vault;

/// <summary>
/// Shared <see cref="IHardwareKeyService.Unlock"/> plumbing for <see cref="LinuxTpmHardwareService"/>
/// and <see cref="WindowsTpmHardwareService"/>: both platforms store an opaque, platform-specific
/// blob in the same <see cref="Config.TpmSealedKey"/> field (see either subclass's header comment
/// for what that blob actually contains), and both need identical base64-decode and 32-byte
/// length validation around whatever platform-specific "recover the key" primitive their own
/// interop class implements (<c>Tpm2ToolsInterop</c> on Linux, <c>PlatformCryptoProviderInterop</c>
/// on Windows). Only that primitive differs — hence <see cref="RecoverKey"/> — which is why this
/// exists as a shared base rather than duplicating this validation (and its exact error message
/// text) in both subclasses.
///
/// Deliberately public (not internal): <see cref="LinuxTpmHardwareService"/>/
/// <see cref="WindowsTpmHardwareService"/> are themselves public, and a base class can't be less
/// accessible than its derived class.
/// </summary>
public abstract class TpmHardwareServiceBase : IHardwareKeyService
{
    public HardwareBackend Backend => HardwareBackend.Tpm;

    /// <summary>Real hardware (or a simulator/virtual TPM pointed to by the environment), not a test double. (Tests substitute a fake at the seam.)</summary>
    public bool IsSimulated => false;

    /// <summary>
    /// Recovers the 32 bytes this machine's TPM protects by unsealing/unwrapping its blob: the
    /// machine slot's <see cref="Keyring.Slot.HwBlob"/> in a keyring vault (<c>KEK_slot</c>), or
    /// <see cref="Config.TpmSealedKey"/> in a single-slot vault (the vault key itself); see
    /// <see cref="HardwareBlobLocator"/>.
    /// <paramref name="chooseSerial"/> is unused — a TPM is a single, non-removable device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial, VaultPasswordProvider? password)
    {
        _ = chooseSerial; // intentionally unused — a TPM is a single, non-removable device

        // A keyring vault's blob is in this machine's slot (issue #154); a single-slot vault's
        // in TpmSealedKey. Same "Config is corrupted" errors as before for the latter.
        var sealedBlob = HardwareBlobLocator.Read(config, HardwareBackend.Tpm);

        // Brief T17: a password slot's blob carries the TSTP header; the provider is called only then.
        var (needsPassword, _, package) = TpmSlotBlob.Split(sealedBlob);
        byte[] key;
        if (needsPassword)
        {
            if (password is null)
                throw new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal);
            using var stretched = password();
            key = RecoverKey(package, stretched);
        }
        else
        {
            key = RecoverKey(package, null);
        }
        // RecoverKey is a generic primitive (Phase 6 will use it for Shamir shares of varying
        // size too — see docs/design/multi-machine-keying.md), so it doesn't itself enforce a length. This
        // call site specifically claims "the vault master key," so it does: a corrupted or
        // truncated sealed blob that still happens to unseal/decrypt should fail here with a
        // clear message, not surface as an opaque downstream error.
        if (key.Length != 32)
            throw new TswapException(
                $"Config is corrupted: expected a 32-byte vault key from the TPM, got {key.Length}. " +
                "Restore config.json from backup or re-run 'tswap init'.");
        return key;
    }

    /// <summary>
    /// The platform-specific unseal (Linux)/unwrap (Windows) primitive — the same operation as
    /// this backend's own public <c>Unseal</c>/<c>Unwrap</c> method, just named neutrally here
    /// since the two platforms don't share a verb for it (see each subclass's header comment for
    /// why: TPM2 sealed-object seal/unseal on Linux vs. RSA-OAEP wrap/unwrap on Windows).
    /// </summary>
    /// <remarks>Brief T17: <paramref name="password"/> is the stretched vault password of a password slot
    /// (the <c>TSTP</c> header already removed from <paramref name="wrapped"/>), null for a password-free one.</remarks>
    protected abstract byte[] RecoverKey(byte[] wrapped, StretchedPassword? password);
}
