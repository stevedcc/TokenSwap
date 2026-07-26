using System.Runtime.Versioning;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault;

/// <summary>
/// Windows TPM 2.0 <see cref="IHardwareKeyService"/>. Needs a TPM 2.0 device exposed through
/// Windows' CNG "Microsoft Platform Crypto Provider", so it only builds/runs on Windows — see
/// <c>HARDWARE_BACKENDS.md</c> and <c>MULTI_MACHINE_KEYING.md</c> for the design this
/// implements.
///
/// <para><b>Primitive:</b> RSA-OAEP wrap/unwrap against a named, non-exportable, TPM-backed
/// key, via <see cref="PlatformCryptoProviderInterop"/> — see its header comment for why this is
/// wrap/unwrap rather than the TPM2 sealed-object seal/unseal the Linux backend uses (a real,
/// verified platform difference: PCP keys cannot be exported in any blob format, so there is no
/// self-contained key blob to hand back on its own — instead a fresh, randomly-named key is
/// created on every <see cref="Wrap"/> call and its name bundled into the returned blob, so the
/// blob as a whole is still self-contained and every vault gets its own isolated TPM key).</para>
///
/// <para>This is today's single-machine, <c>k = 1</c> slice (implementation-ordering step 2 in
/// <c>MULTI_MACHINE_KEYING.md</c>), sharing <see cref="Config.TpmSealedKey"/> with the Linux
/// backend: both write only an opaque, platform-specific blob there (RSA-OAEP ciphertext here,
/// a TPM2 sealed public/private pair on Linux) under the same <see cref="HardwareBackend.Tpm"/>
/// tag — a vault is inherently tied to one machine's OS already, so there's no need for a
/// separate config field per platform. The general multi-machine keyring (multiple slots,
/// signed, `epoch`-guarded) is not built yet; this field is a single-slot precursor to it, not
/// the final on-disk format.</para>
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
public sealed class WindowsTpmHardwareService : IHardwareKeyService
{
    public HardwareBackend Backend => HardwareBackend.Tpm;

    /// <summary>Real hardware (or this VM's virtual TPM), not a test double. (Tests substitute a fake at the seam.)</summary>
    public bool IsSimulated => false;

    /// <summary>
    /// Recovers the vault master key by unwrapping <see cref="Config.TpmSealedKey"/>.
    /// <paramref name="chooseSerial"/> is unused — a TPM is a single, non-removable device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        if (config.TpmSealedKey is not { Length: > 0 } sealedBase64)
            throw new TswapException(
                "Config is corrupted: vault uses the 'tpm' backend but has no sealed key. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        byte[] wrapped;
        try
        {
            wrapped = Convert.FromBase64String(sealedBase64);
        }
        catch (FormatException)
        {
            throw new TswapException(
                "Config is corrupted: the TPM sealed key is not valid base64. " +
                "Restore config.json from backup or re-run 'tswap init'.");
        }

        var key = Unwrap(wrapped);
        // Unwrap is a generic primitive, so it doesn't itself enforce a length. This call site
        // specifically claims "the vault master key," so it does: a corrupted or truncated
        // sealed blob that still happens to decrypt should fail here with a clear message, not
        // surface as an opaque downstream error.
        if (key.Length != 32)
            throw new TswapException(
                $"Config is corrupted: expected a 32-byte vault key from the TPM, got {key.Length}. " +
                "Restore config.json from backup or re-run 'tswap init'.");
        return key;
    }

    /// <summary>
    /// Enrollment side: wraps <paramref name="plaintextKey"/> (the vault key) to a fresh
    /// TPM-backed key. The returned blob is useless off this machine.
    /// </summary>
    public byte[] Wrap(byte[] plaintextKey) => PlatformCryptoProviderInterop.Wrap(plaintextKey);

    /// <summary>Unlock side: unwraps a payload produced by <see cref="Wrap"/> using this machine's named TPM-backed key.</summary>
    public byte[] Unwrap(byte[] wrapped) => PlatformCryptoProviderInterop.Unwrap(wrapped);
}

