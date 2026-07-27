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
    /// Recovers the vault master key by unsealing/unwrapping <see cref="Config.TpmSealedKey"/>.
    /// <paramref name="chooseSerial"/> is unused — a TPM is a single, non-removable device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        _ = chooseSerial; // intentionally unused — a TPM is a single, non-removable device

        if (config.TpmSealedKey is not { Length: > 0 } sealedBase64)
            throw new TswapException(
                "Config is corrupted: vault uses the 'tpm' backend but has no sealed key. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        byte[] sealedBlob;
        try
        {
            sealedBlob = Convert.FromBase64String(sealedBase64);
        }
        catch (FormatException)
        {
            throw new TswapException(
                "Config is corrupted: the TPM sealed key is not valid base64. " +
                "Restore config.json from backup or re-run 'tswap init'.");
        }

        var key = RecoverKey(sealedBlob);
        // RecoverKey is a generic primitive (Phase 6 will use it for Shamir shares of varying
        // size too — see MULTI_MACHINE_KEYING.md), so it doesn't itself enforce a length. This
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
    protected abstract byte[] RecoverKey(byte[] wrapped);
}
