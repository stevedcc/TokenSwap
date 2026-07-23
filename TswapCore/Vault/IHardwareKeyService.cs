namespace TswapCore.Vault;

/// <summary>
/// A hardware root of trust that recovers the vault master key for this machine — the
/// backend seam behind <see cref="VaultUnlocker"/>. One implementation per backend:
/// <list type="bullet">
/// <item><see cref="YubiKeyHardwareService"/> — HMAC challenge-response with 1-of-2 XOR
///   redundancy (the scheme tswap has always used).</item>
/// <item>TPM 2.0 (Windows TBS/CNG, Linux tpm2) — seal/unseal a machine-bound key. Planned.</item>
/// <item>Apple Secure Enclave — ECIES wrap/unwrap against a non-extractable key. Planned.</item>
/// </list>
///
/// Each backend owns its own key scheme (derive vs. unseal vs. unwrap) — the abstraction
/// is deliberately "recover the key," not "run a challenge-response," because the Secure
/// Enclave cannot do HMAC or export key bytes and a TPM prefers seal/unseal. The backend
/// is chosen from <see cref="Config.Backend"/>.
///
/// Forward note (Phase 6 multi-machine keyring): the recovered value becomes the
/// per-machine key-encryption key (KEK) that unwraps a shared vault key, rather than the
/// master key itself. The single-machine contract here is the same shape one level down.
/// </summary>
public interface IHardwareKeyService
{
    /// <summary>Which <see cref="Config.Backend"/> value this implementation handles.</summary>
    HardwareBackend Backend { get; }

    /// <summary>
    /// True when the implementation simulates hardware (test mode). Commands that offer
    /// hardware-entropy paths fall back to system RNG when set.
    /// </summary>
    bool IsSimulated { get; }

    /// <summary>
    /// Recovers the 32-byte vault master key using this machine's hardware.
    /// <paramref name="chooseSerial"/> is consulted only by multi-token backends
    /// (YubiKey) when more than one device is connected; single-device backends
    /// (TPM, Secure Enclave) ignore it.
    /// </summary>
    byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial);
}
