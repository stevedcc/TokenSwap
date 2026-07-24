using System.Runtime.Versioning;

namespace TswapCore.Vault;

/// <summary>
/// Apple Secure Enclave <see cref="IHardwareKeyService"/> — <b>STUB, not yet implemented.</b>
///
/// Fill this in on a real Mac: it needs Security.framework and a physical Secure Enclave, so
/// it cannot be built against or tested on Linux/Windows. The design is already settled —
/// read these two docs first, they are the brief for this file:
/// <list type="bullet">
/// <item><c>HARDWARE_BACKENDS.md</c> — the "Adding a backend" checklist (steps 1–6) and the
///   Secure Enclave row of the per-backend table.</item>
/// <item><c>MULTI_MACHINE_KEYING.md</c> — why the Secure Enclave forces <b>wrap/unwrap</b>
///   (it cannot HMAC and never exports key bytes), and where the wrapped key/share lives in
///   the keyring.</item>
/// </list>
///
/// <para><b>Primitive:</b> ECIES wrap/unwrap against a <b>non-extractable P-256 key</b> created
/// in the Secure Enclave. No key material ever leaves the Enclave; unlock unwraps <c>K_v</c>
/// (or, once k≥2 threshold lands, this machine's Shamir share) transiently in memory.</para>
///
/// <para><b>Security.framework calls</b> (via P/Invoke — AOT-safe, no reflection):</para>
/// <list type="bullet">
/// <item>Create/find the key: <c>SecKeyCreateRandomKey</c> with
///   <c>kSecAttrTokenID = kSecAttrTokenIDSecureEnclave</c>,
///   <c>kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom</c>, 256-bit,
///   and a <c>kSecAttrAccessControl</c> that gates presence/biometry.</item>
/// <item>Presence/biometry policy: <c>SecAccessControlCreateWithFlags</c>
///   (<c>.biometryCurrentSet</c> / <c>.userPresence</c> / <c>.devicePasscode</c>).</item>
/// <item>Wrap: <c>SecKeyCreateEncryptedData(pubKey,
///   eciesEncryptionCofactorX963SHA256AESGCM, plaintext)</c>.</item>
/// <item>Unwrap: <c>SecKeyCreateDecryptedData(privKey, &lt;same algorithm&gt;, ciphertext)</c>
///   — this is the call that triggers the Touch ID / passcode prompt.</item>
/// </list>
///
/// <para><b>Enrollment</b> (writing the wrapped slot into config/keyring) is a separate flow —
/// see <c>HARDWARE_BACKENDS.md</c> step 5. This class owns only the wrap/unwrap primitive and
/// <see cref="Unlock"/>. The <see cref="Wrap"/>/<see cref="Unwrap"/> signatures below are a
/// starting point that matches the design docs; adjust them as the keyring/slot format lands.</para>
///
/// <para>Registered at the composition root only on macOS — see the commented example in
/// <c>TswapCli/Program.cs</c>. Until then <see cref="VaultUnlocker"/> returns a clear
/// "backend not supported" error for a secure-enclave vault on other builds.</para>
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class SecureEnclaveHardwareService : IHardwareKeyService
{
    public HardwareBackend Backend => HardwareBackend.SecureEnclave;

    /// <summary>Real hardware, not a simulation. (Tests substitute a fake at the seam.)</summary>
    public bool IsSimulated => false;

    /// <summary>
    /// Recovers the vault master key (<c>k = 1</c>) or this machine's Shamir share
    /// (<c>k ≥ 2</c>) by unwrapping the Secure-Enclave slot carried in
    /// <paramref name="config"/>. <paramref name="chooseSerial"/> is unused — the Secure
    /// Enclave is a single, non-removable device.
    /// <para>TODO (macOS): read this machine's slot from the config/keyring and return
    /// <see cref="Unwrap"/> of it. See <c>MULTI_MACHINE_KEYING.md</c> for the slot format.</para>
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
        => throw new NotImplementedException(
            "Secure Enclave unlock is not implemented yet. See HARDWARE_BACKENDS.md and MULTI_MACHINE_KEYING.md.");

    /// <summary>
    /// Enrollment side: ECIES-encrypt <paramref name="plaintextKey"/> (the vault key or a
    /// Shamir share) to this machine's Secure Enclave public key, returning the opaque slot
    /// payload to store in the keyring. The wrapped form is useless off this machine.
    /// <para>TODO (macOS): <c>SecKeyCreateEncryptedData</c> with
    /// <c>eciesEncryptionCofactorX963SHA256AESGCM</c>. See <c>HARDWARE_BACKENDS.md</c>.</para>
    /// </summary>
    public byte[] Wrap(byte[] plaintextKey)
        => throw new NotImplementedException(
            "SecKeyCreateEncryptedData not implemented. See HARDWARE_BACKENDS.md (Secure Enclave row).");

    /// <summary>
    /// Unlock side: ECIES-decrypt a slot payload produced by <see cref="Wrap"/> using the
    /// Secure Enclave private key (this triggers the biometry/presence prompt).
    /// <para>TODO (macOS): <c>SecKeyCreateDecryptedData</c> with the same algorithm as
    /// <see cref="Wrap"/>. See <c>HARDWARE_BACKENDS.md</c>.</para>
    /// </summary>
    public byte[] Unwrap(byte[] wrapped)
        => throw new NotImplementedException(
            "SecKeyCreateDecryptedData not implemented. See HARDWARE_BACKENDS.md (Secure Enclave row).");
}
