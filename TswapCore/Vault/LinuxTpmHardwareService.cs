using System.Runtime.Versioning;
using TswapCore.Keyring;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;

namespace TswapCore.Vault;

/// <summary>
/// Linux TPM 2.0 <see cref="IHardwareKeyService"/>. Needs a TPM 2.0 device (or a reachable
/// simulator in dev/test — see below), so it only builds/runs on Linux — see
/// <c>docs/design/hardware-backends.md</c> and <c>docs/design/multi-machine-keying.md</c> for the design this
/// implements. The <see cref="Unlock"/> validation logic (base64 decode, 32-byte length check)
/// lives in <see cref="TpmHardwareServiceBase"/>, shared with <see cref="WindowsTpmHardwareService"/>.
///
/// <para><b>Primitive:</b> seal/unseal against a machine-bound key, via the <c>tpm2-tools</c>
/// CLI (through <see cref="Tpm2ToolsInterop"/> — see its header comment for the shellout
/// design, the primary-key determinism this relies on, and what's actually been verified
/// against swtpm). No primary key material is ever persisted; unlock reconstitutes it fresh
/// from the TPM's owner hierarchy and unseals <c>K_v</c> transiently in memory. The k≥2
/// threshold (Shamir shares instead of the whole key) is Phase 6 — see
/// <c>docs/design/multi-machine-keying.md</c>.</para>
///
/// <para><b>Where the blob lives (issue #154).</b> In a keyring vault (what <c>tswap init</c>
/// makes since brief T2) the self-contained sealed blob is this machine's machine slot's
/// <see cref="Keyring.Slot.HwBlob"/> and protects that slot's <c>KEK_slot</c>; it is versioned by
/// the keyring's AEAD-bound format version. In a single-slot vault made before keyring vaults it
/// is the legacy, unversioned <see cref="Config.TpmSealedKey"/> and protects the vault key itself.
/// <see cref="HardwareBlobLocator"/> picks the right one; <see cref="Enroll"/> produces it.</para>
///
/// <para><b>Status:</b> verified on one physical TPM (an Intel PTT, #155) with the RSA-2048 primary;
/// new slots seal under an ECC P-256 primary (issue #261), tested against swtpm. See
/// <c>docs/design/hardware-backends.md</c>'s Linux TPM section for what is verified on real hardware
/// and what is still open.</para>
///
/// <para>Registered at the composition root only on Linux — see <c>TswapCli/Program.cs</c>. On
/// other builds <see cref="VaultUnlocker"/> returns a clear "backend not supported" error for a
/// tpm vault.</para>
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxTpmHardwareService : TpmHardwareServiceBase, IHardwareEnrollmentService
{
    /// <summary>Whether this machine can use the chip (a cheap presence check; creates no key). Lets the CLI probe without naming the interop.</summary>
    public static bool IsAvailable() => Tpm2ToolsInterop.IsAvailable();

    /// <summary><see cref="IsAvailable"/>, with why not (guided init lists the reason).</summary>
    public static (bool Available, string? Reason) Probe() => Tpm2ToolsInterop.Probe();

    /// <summary>
    /// Enrollment seam (issue #151): generates a random <c>KEK_slot</c> and seals it to this
    /// machine's TPM via <see cref="Seal"/>. The returned blob is useless off this machine. Issue #261: the package is
    /// sealed under the ECC P-256 primary, so the blob always has the <c>TSTP</c> header with
    /// <see cref="TpmSlotBlob.EccPrimary"/> (and <see cref="TpmSlotBlob.Password"/> for a password slot).
    /// </summary>
    public HardwareEnrollment Enroll(StretchedPassword? password)
    {
        var kekSlot = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return password is null
            ? new HardwareEnrollment(kekSlot, TpmSlotBlob.Wrap(Seal(kekSlot), TpmSlotBlob.EccPrimary))
            : new HardwareEnrollment(kekSlot,
                TpmSlotBlob.Wrap(Tpm2ToolsInterop.Seal(kekSlot, password), TpmSlotBlob.EccPrimary | TpmSlotBlob.Password));
    }

    /// <summary>
    /// Enrollment side: seals <paramref name="plaintextKey"/> (the vault key) under a fresh ECC P-256 storage
    /// primary. Returns the bare package (no <c>TSTP</c> header); the blob is useless off this machine.
    /// </summary>
    public byte[] Seal(byte[] plaintextKey) => Tpm2ToolsInterop.Seal(plaintextKey);

    /// <summary>
    /// Unlock side: unseals a bare package under this TPM's regenerated primary, ECC P-256 when
    /// <paramref name="eccPrimary"/> (a <see cref="Seal"/> package) and RSA-2048 otherwise (a slot sealed before issue #261).
    /// </summary>
    public byte[] Unseal(byte[] wrapped, bool eccPrimary) => Tpm2ToolsInterop.Unseal(wrapped, eccPrimary);

    protected override byte[] RecoverKey(byte[] wrapped, bool eccPrimary, StretchedPassword? password) =>
        password is null ? Unseal(wrapped, eccPrimary) : Tpm2ToolsInterop.Unseal(wrapped, eccPrimary, password);
}
