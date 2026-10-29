using System.Runtime.Versioning;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault;

/// <summary>
/// Windows TPM 2.0 <see cref="IHardwareKeyService"/>. Needs a TPM 2.0 device exposed through
/// Windows' CNG "Microsoft Platform Crypto Provider", so it only builds/runs on Windows — see
/// <c>HARDWARE_BACKENDS.md</c> and <c>MULTI_MACHINE_KEYING.md</c> for the design this
/// implements. The <see cref="Unlock"/> validation logic (base64 decode, 32-byte length check)
/// lives in <see cref="TpmHardwareServiceBase"/>, shared with <see cref="LinuxTpmHardwareService"/>.
///
/// <para><b>Primitive:</b> RSA-OAEP wrap/unwrap against a named, non-exportable, TPM-backed
/// key, via <see cref="PlatformCryptoProviderInterop"/> — see its header comment for why this is
/// wrap/unwrap rather than the TPM2 sealed-object seal/unseal the Linux backend uses (a real,
/// verified platform difference: PCP keys cannot be exported in any blob format, so there is no
/// self-contained key blob to hand back on its own — instead a fresh, randomly-named key is
/// created on every <see cref="Wrap"/> call and its name bundled into the returned blob, so the
/// blob as a whole is still self-contained and every vault gets its own isolated TPM key).</para>
///
/// <para><b>Where the blob lives (issue #154).</b> In a keyring vault (what <c>tswap init</c>
/// makes since brief T2) the self-contained wrapped blob is this machine's machine slot's
/// <see cref="Keyring.Slot.HwBlob"/> and protects that slot's <c>KEK_slot</c>; it is versioned by
/// the keyring's AEAD-bound format version. In a single-slot vault made before keyring vaults it
/// is the legacy, unversioned <see cref="Config.TpmSealedKey"/> and protects the vault key itself.
/// <see cref="HardwareBlobLocator"/> picks the right one; <see cref="Enroll"/> produces it.</para>
///
/// <para><b>Status: developed and tested only against this machine's (virtual) TPM in a
/// Parallels VM, not yet verified against physical TPM hardware</b> — see
/// <c>HARDWARE_BACKENDS.md</c>'s Windows TPM section before trusting this as a primary vault
/// backend.</para>
///
/// <para>Registered at the composition root only on Windows — see <c>TswapCli/Program.cs</c>. On
/// other builds <see cref="VaultUnlocker"/> returns a clear "backend not supported" error for a
/// tpm vault.</para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsTpmHardwareService : TpmHardwareServiceBase, IHardwareEnrollmentService
{
    /// <summary>
    /// Enrollment seam (issue #151): generates a random <c>KEK_slot</c> and wraps it to a fresh
    /// TPM-backed key via <see cref="Wrap"/>. The returned blob is useless off this machine.
    /// </summary>
    public HardwareEnrollment Enroll()
    {
        var kekSlot = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return new HardwareEnrollment(kekSlot, Wrap(kekSlot));
    }

    /// <summary>
    /// Enrollment side: wraps <paramref name="plaintextKey"/> (the vault key) to a fresh
    /// TPM-backed key. The returned blob is useless off this machine.
    /// </summary>
    public byte[] Wrap(byte[] plaintextKey) => PlatformCryptoProviderInterop.Wrap(plaintextKey);

    /// <summary>Unlock side: unwraps a payload produced by <see cref="Wrap"/> using this machine's named TPM-backed key.</summary>
    public byte[] Unwrap(byte[] wrapped) => PlatformCryptoProviderInterop.Unwrap(wrapped);

    protected override byte[] RecoverKey(byte[] wrapped) => Unwrap(wrapped);
}
