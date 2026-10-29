using System.Runtime.Versioning;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault;

/// <summary>
/// Linux TPM 2.0 <see cref="IHardwareKeyService"/>. Needs a TPM 2.0 device (or a reachable
/// simulator in dev/test — see below), so it only builds/runs on Linux — see
/// <c>HARDWARE_BACKENDS.md</c> and <c>MULTI_MACHINE_KEYING.md</c> for the design this
/// implements. The <see cref="Unlock"/> validation logic (base64 decode, 32-byte length check)
/// lives in <see cref="TpmHardwareServiceBase"/>, shared with <see cref="WindowsTpmHardwareService"/>.
///
/// <para><b>Primitive:</b> seal/unseal against a machine-bound key, via the <c>tpm2-tools</c>
/// CLI (through <see cref="Tpm2ToolsInterop"/> — see its header comment for the shellout
/// design, the primary-key determinism this relies on, and what's actually been verified
/// against swtpm). No primary key material is ever persisted; unlock reconstitutes it fresh
/// from the TPM's owner hierarchy and unseals <c>K_v</c> transiently in memory. The k≥2
/// threshold (Shamir shares instead of the whole key) is Phase 6 — see
/// <c>MULTI_MACHINE_KEYING.md</c>.</para>
///
/// <para><b>Where the blob lives (issue #154).</b> In a keyring vault (what <c>tswap init</c>
/// makes since brief T2) the self-contained sealed blob is this machine's machine slot's
/// <see cref="Keyring.Slot.HwBlob"/> and protects that slot's <c>KEK_slot</c>; it is versioned by
/// the keyring's AEAD-bound format version. In a single-slot vault made before keyring vaults it
/// is the legacy, unversioned <see cref="Config.TpmSealedKey"/> and protects the vault key itself.
/// <see cref="HardwareBlobLocator"/> picks the right one; <see cref="Enroll"/> produces it.</para>
///
/// <para><b>Status: developed and tested only against a software TPM simulator (swtpm), not
/// yet verified against real Linux TPM hardware</b> — see <c>HARDWARE_BACKENDS.md</c>'s Linux
/// TPM section before trusting this as a primary vault backend.</para>
///
/// <para>Registered at the composition root only on Linux — see <c>TswapCli/Program.cs</c>. On
/// other builds <see cref="VaultUnlocker"/> returns a clear "backend not supported" error for a
/// tpm vault.</para>
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxTpmHardwareService : TpmHardwareServiceBase, IHardwareEnrollmentService
{
    /// <summary>
    /// Enrollment seam (issue #151): generates a random <c>KEK_slot</c> and seals it to this
    /// machine's TPM via <see cref="Seal"/>. The returned blob is useless off this machine.
    /// </summary>
    public HardwareEnrollment Enroll()
    {
        var kekSlot = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return new HardwareEnrollment(kekSlot, Seal(kekSlot));
    }

    /// <summary>
    /// Enrollment side: seals <paramref name="plaintextKey"/> (the vault key) to a fresh
    /// TPM-bound primary key. The returned blob is useless off this machine.
    /// </summary>
    public byte[] Seal(byte[] plaintextKey) => Tpm2ToolsInterop.Seal(plaintextKey);

    /// <summary>Unlock side: unseals a payload produced by <see cref="Seal"/> using this TPM's regenerated primary key.</summary>
    public byte[] Unseal(byte[] wrapped) => Tpm2ToolsInterop.Unseal(wrapped);

    protected override byte[] RecoverKey(byte[] wrapped) => Unseal(wrapped);
}
