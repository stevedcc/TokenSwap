using System.Runtime.Versioning;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault;

/// <summary>
/// Linux TPM 2.0 <see cref="IHardwareKeyService"/>. Needs a TPM 2.0 device (or a reachable
/// simulator in dev/test — see below), so it only builds/runs on Linux — see
/// <c>HARDWARE_BACKENDS.md</c> and <c>MULTI_MACHINE_KEYING.md</c> for the design this
/// implements.
///
/// <para><b>Primitive:</b> seal/unseal against a machine-bound key, via the <c>tpm2-tools</c>
/// CLI (through <see cref="Tpm2ToolsInterop"/> — see its header comment for the shellout
/// design, the primary-key determinism this relies on, and what's actually been verified
/// against swtpm). No primary key material is ever persisted; unlock reconstitutes it fresh
/// from the TPM's owner hierarchy and unseals <c>K_v</c> transiently in memory. The k≥2
/// threshold (Shamir shares instead of the whole key) is Phase 6 — see
/// <c>MULTI_MACHINE_KEYING.md</c>.</para>
///
/// <para>This is today's single-machine, <c>k = 1</c> slice (implementation-ordering step 2 in
/// <c>MULTI_MACHINE_KEYING.md</c>): <see cref="Config.TpmSealedKey"/> carries a single
/// self-contained blob — the sealed object's public and private portions — produced and
/// consumed by <see cref="Tpm2ToolsInterop"/>. The general multi-machine keyring (multiple
/// slots, signed, `epoch`-guarded) is not built yet; this field is a single-slot precursor to
/// it, not the final on-disk format.</para>
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
public sealed class LinuxTpmHardwareService : IHardwareKeyService
{
    public HardwareBackend Backend => HardwareBackend.Tpm;

    /// <summary>Real hardware (or a swtpm simulator pointed to by the environment), not a test double. (Tests substitute a fake at the seam.)</summary>
    public bool IsSimulated => false;

    /// <summary>
    /// Recovers the vault master key by unsealing <see cref="Config.TpmSealedKey"/>.
    /// <paramref name="chooseSerial"/> is unused — a TPM is a single, non-removable device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
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

        var key = Unseal(sealedBlob);
        // Unseal is a generic primitive (Phase 6 will use it for Shamir shares of varying
        // size too — see MULTI_MACHINE_KEYING.md), so it doesn't itself enforce a length. This
        // call site specifically claims "the vault master key," so it does: a corrupted or
        // truncated sealed blob that still happens to unseal should fail here with a clear
        // message, not surface as an opaque downstream error.
        if (key.Length != 32)
            throw new TswapException(
                $"Config is corrupted: expected a 32-byte vault key from the TPM, got {key.Length}. " +
                "Restore config.json from backup or re-run 'tswap init'.");
        return key;
    }

    /// <summary>
    /// Enrollment side: seals <paramref name="plaintextKey"/> (the vault key) to a fresh
    /// TPM-bound primary key. The returned blob is useless off this machine.
    /// </summary>
    public byte[] Seal(byte[] plaintextKey) => Tpm2ToolsInterop.Seal(plaintextKey);

    /// <summary>Unlock side: unseals a payload produced by <see cref="Seal"/> using this TPM's regenerated primary key.</summary>
    public byte[] Unseal(byte[] wrapped) => Tpm2ToolsInterop.Unseal(wrapped);
}
