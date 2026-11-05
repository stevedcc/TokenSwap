using System.Runtime.Versioning;
using TswapCore.Keyring;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;

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
    /// <summary>Whether this machine can use the chip (a cheap presence check; creates no key). Lets the CLI probe without naming the interop.</summary>
    public static bool IsAvailable() => AppleSecureEnclaveInterop.IsAvailable();

    /// <summary>
    /// Enrollment seam (issue #151): generates a random <c>KEK_slot</c> and ECIES-wraps it to a
    /// new Secure Enclave key via <see cref="Wrap"/>. The returned blob is useless off this Mac.
    /// </summary>
    public HardwareEnrollment Enroll(StretchedPassword? password)
    {
        var kekSlot = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        // Brief T17 task 13: a password slot's key is made with .applicationPassword and the stretched
        // password as its credential, so the Enclave enforces it (ruling 19); its blob gets the TSSE header.
        return password is null
            ? new HardwareEnrollment(kekSlot, Wrap(kekSlot))
            : new HardwareEnrollment(kekSlot,
                SecureEnclaveSlotBlob.Wrap(AppleSecureEnclaveInterop.WrapWithPassword(kekSlot, requirePresence, password)));
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
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial, VaultPasswordProvider? password)
    {
        // A keyring vault's blob is in this machine's slot (issue #154); a single-slot vault's
        // in SecureEnclaveWrappedKey. Same "Config is corrupted" errors as before for the latter.
        var wrapped = HardwareBlobLocator.Read(config, HardwareBackend.SecureEnclave);

        // Brief T17: a password slot's blob carries the TSSE header; the provider is called only then, and
        // its result is disposed here (ruling 13).
        var (needsPassword, package) = SecureEnclaveSlotBlob.Split(wrapped);
        byte[] key;
        if (needsPassword)
        {
            if (password is null)
                throw new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal);
            using var stretched = password();
            key = AppleSecureEnclaveInterop.UnwrapWithPassword(package, stretched);
        }
        else if (config.RequiresTouch == false)
        {
            // T17 fix round 2: a slot recorded as made without presence (brief T11's --no-touch) never needs a
            // dialog, so none is allowed: a password slot whose TSSE header was stripped fails here at once instead
            // of waiting for an application-password dialog nobody can answer.
            key = AppleSecureEnclaveInterop.UnwrapWithoutInteraction(package);
        }
        else
        {
            // Presence required (or not recorded: every slot before T11 had it): the user is at the machine.
            key = Unwrap(package);
        }
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
