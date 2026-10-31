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
/// <para><b>Where the blob lives (issue #154).</b> In a keyring vault (what <c>tswap init</c>
/// makes since brief T2) the self-contained wrapped blob is this machine's machine slot's
/// <see cref="Keyring.Slot.HwBlob"/> and protects that slot's <c>KEK_slot</c>; it is versioned by
/// the keyring's AEAD-bound format version. In a single-slot vault made before keyring vaults it
/// is the legacy, unversioned <see cref="Config.SecureEnclaveWrappedKey"/> and protects the vault key itself.
/// <see cref="HardwareBlobLocator"/> picks the right one; <see cref="Enroll"/> produces it.</para>
///
/// <para>Built only by <c>TswapCli.HardwareServices</c> (brief T12), on macOS, which always wraps it
/// so that under sudo its calls run as the vault folder's owner (macOS then asks that user, not
/// root, for Touch ID); <c>SecureEnclaveFactoryScanTests</c> fails if it is built anywhere else.
/// On other builds <see cref="VaultUnlocker"/> returns a clear "backend not supported" error
/// for a secure-enclave vault.</para>
/// </summary>
/// <param name="requirePresence">
/// Brief T11: whether a key this service creates (<see cref="Enroll"/>, <see cref="Wrap"/>)
/// requires Touch ID or the login password on every unwrap. Defaults to true, so a code path that
/// forgets it gets the presence-gated key; only <c>--no-touch</c> passes false. Unlock doesn't use
/// it: the policy lives in the key.
/// </param>
[SupportedOSPlatform("macos")]
public sealed class SecureEnclaveHardwareService(bool requirePresence = true) : IHardwareKeyService, IHardwareEnrollmentService
{
    /// <summary>
    /// Enrollment seam (issue #151): generates a random <c>KEK_slot</c> and ECIES-wraps it to a
    /// new Secure Enclave key via <see cref="Wrap"/>. The returned blob is useless off this Mac.
    /// </summary>
    public HardwareEnrollment Enroll()
    {
        var kekSlot = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return new HardwareEnrollment(kekSlot, Wrap(kekSlot));
    }

    public HardwareBackend Backend => HardwareBackend.SecureEnclave;

    /// <summary>Real hardware, not a simulation. (Tests substitute a fake at the seam.)</summary>
    public bool IsSimulated => false;

    /// <summary>
    /// Recovers the 32 bytes this Mac's Secure Enclave protects by unwrapping its blob: the
    /// machine slot's <see cref="Keyring.Slot.HwBlob"/> in a keyring vault (<c>KEK_slot</c>), or
    /// <see cref="Config.SecureEnclaveWrappedKey"/> in a single-slot vault (the vault key itself);
    /// see <see cref="HardwareBlobLocator"/>.
    /// <paramref name="chooseSerial"/> is unused — the Secure Enclave is a single,
    /// non-removable device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        // A keyring vault's blob is in this machine's slot (issue #154); a single-slot vault's
        // in SecureEnclaveWrappedKey. Same "Config is corrupted" errors as before for the latter.
        var wrapped = HardwareBlobLocator.Read(config, HardwareBackend.SecureEnclave);

        var key = Unwrap(wrapped);
        // Unwrap is a generic primitive (Phase 6 will use it for Shamir shares of varying
        // size too — see MULTI_MACHINE_KEYING.md), so it doesn't itself enforce a length. This
        // call site specifically claims "the vault master key," so it does: a corrupted or
        // truncated wrapped blob that still happens to decrypt should fail here with a clear
        // message, not surface as an opaque AES-GCM key-size exception further downstream.
        if (key.Length != 32)
            throw new TswapException(
                $"Config is corrupted: expected a 32-byte vault key from the Secure Enclave, got {key.Length}. " +
                "Restore config.json from backup or re-run 'tswap init'.");
        return key;
    }

    /// <summary>
    /// Enrollment side: creates a new Secure Enclave key pair (presence required or not, as this
    /// service was constructed) and ECIES-encrypts <paramref name="plaintextKey"/> (the vault key)
    /// to it. The returned blob is useless off this machine.
    /// </summary>
    public byte[] Wrap(byte[] plaintextKey) => AppleSecureEnclaveInterop.Wrap(plaintextKey, requirePresence);

    /// <summary>
    /// Unlock side: ECIES-decrypts a payload produced by <see cref="Wrap"/> using the Secure
    /// Enclave private key it was wrapped to — this prompts for Touch ID or the login password
    /// when that key was created with presence required.
    /// </summary>
    public byte[] Unwrap(byte[] wrapped) => AppleSecureEnclaveInterop.Unwrap(wrapped);
}
