using System.Runtime.Versioning;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault;

/// <summary>
/// Apple Secure Enclave <see cref="IHardwareKeyService"/>. Needs a physical Secure Enclave, so
/// it only builds/runs on macOS — see <c>HARDWARE_BACKENDS.md</c> and <c>MULTI_MACHINE_KEYING.md</c>
/// for the design this implements.
///
/// <para><b>Primitive:</b> ECIES wrap/unwrap against a <b>non-extractable P-256 key</b> created
/// fresh in the Secure Enclave on enrollment, via Apple's CryptoKit <c>SecureEnclave</c> API
/// (through the <see cref="AppleSecureEnclaveInterop"/> Swift shim — see its header comment for
/// why CryptoKit rather than raw Security.framework <c>SecItem</c> calls). No key material ever
/// leaves the Enclave; unlock unwraps <c>K_v</c> transiently in memory. The k≥2 threshold
/// (Shamir shares instead of the whole key) is Phase 6 — see <c>MULTI_MACHINE_KEYING.md</c>.</para>
///
/// <para>This is today's single-machine, <c>k = 1</c> slice (implementation-ordering step 2 in
/// <c>MULTI_MACHINE_KEYING.md</c>): <see cref="Config.SecureEnclaveWrappedKey"/> carries a
/// single self-contained blob — the Secure Enclave key's own <c>dataRepresentation</c> plus the
/// ECIES ciphertext — produced and consumed by <see cref="AppleSecureEnclaveInterop"/>. There is
/// no keychain entry and nothing to look up by tag: the key only exists as long as this blob is
/// kept, and only the physical Secure Enclave that created it can unwrap it. The general
/// multi-machine keyring (multiple slots, signed, `epoch`-guarded) is not built yet; this field
/// is a single-slot precursor to it, not the final on-disk format.</para>
///
/// <para>Registered at the composition root only on macOS — see <c>TswapCli/Program.cs</c>.
/// On other builds <see cref="VaultUnlocker"/> returns a clear "backend not supported" error
/// for a secure-enclave vault.</para>
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class SecureEnclaveHardwareService : IHardwareKeyService
{
    public HardwareBackend Backend => HardwareBackend.SecureEnclave;

    /// <summary>Real hardware, not a simulation. (Tests substitute a fake at the seam.)</summary>
    public bool IsSimulated => false;

    /// <summary>
    /// Recovers the vault master key by unwrapping <see cref="Config.SecureEnclaveWrappedKey"/>.
    /// <paramref name="chooseSerial"/> is unused — the Secure Enclave is a single,
    /// non-removable device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        if (config.SecureEnclaveWrappedKey is not { Length: > 0 } wrappedBase64)
            throw new TswapException(
                "Config is corrupted: vault uses the 'secure-enclave' backend but has no wrapped key. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        return Unwrap(Convert.FromBase64String(wrappedBase64));
    }

    /// <summary>
    /// Enrollment side: creates a new Secure Enclave key pair and ECIES-encrypts
    /// <paramref name="plaintextKey"/> (the vault key) to it. The returned blob is useless off
    /// this machine.
    /// </summary>
    public byte[] Wrap(byte[] plaintextKey) => AppleSecureEnclaveInterop.Wrap(plaintextKey);

    /// <summary>
    /// Unlock side: ECIES-decrypts a payload produced by <see cref="Wrap"/> using the Secure
    /// Enclave private key it was wrapped to — this triggers the Touch ID / presence prompt.
    /// </summary>
    public byte[] Unwrap(byte[] wrapped) => AppleSecureEnclaveInterop.Unwrap(wrapped);
}
