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
public sealed class LinuxTpmHardwareService : TpmHardwareServiceBase
{
    /// <summary>
    /// Enrollment side: seals <paramref name="plaintextKey"/> (the vault key) to a fresh
    /// TPM-bound primary key. The returned blob is useless off this machine.
    /// </summary>
    public byte[] Seal(byte[] plaintextKey) => Tpm2ToolsInterop.Seal(plaintextKey);

    /// <summary>Unlock side: unseals a payload produced by <see cref="Seal"/> using this TPM's regenerated primary key.</summary>
    public byte[] Unseal(byte[] wrapped) => Tpm2ToolsInterop.Unseal(wrapped);

    protected override byte[] RecoverKey(byte[] wrapped) => Unseal(wrapped);
}
