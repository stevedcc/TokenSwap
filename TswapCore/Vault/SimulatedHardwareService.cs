using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.VaultPassword;

namespace TswapCore.Vault;

/// <summary>
/// Simulated wrap/unwrap hardware backend for tests (issue #153), next to
/// <see cref="TestKeyYubiKeyService"/> and following its precedent: it is only ever selected
/// when the Debug-only <c>TSWAP_TEST_KEY</c> is set (see <c>TswapCli.HardwareServices</c>), and
/// the test key is its "machine". It implements both seams, <see cref="IHardwareKeyService"/>
/// and <see cref="IHardwareEnrollmentService"/>, for whichever <see cref="HardwareBackend"/> it
/// is constructed with, so <c>init --tpm</c>, a TPM keyring vault and its unlock run end to
/// end in CI.
///
/// <para>It models the shape the Secure Enclave and TPM backends share: <see cref="Enroll"/>
/// generates a random <c>KEK_slot</c> and wraps it into an opaque blob; <see cref="Unlock"/>
/// reads that blob from where the real backend would and recovers <c>KEK_slot</c>. The wrap is
/// AES-256-GCM under <paramref name="machineKey"/> (<c>nonce(12) || tag(16) || ciphertext</c>),
/// so a blob made on one simulated machine fails on another, the way a sealed TPM blob fails on
/// a different TPM: with a <see cref="TswapException"/>, never an AES exception.</para>
///
/// <para>It proves plumbing (dispatch, config shape, slot construction, round trips, error
/// paths), never the hardware root-of-trust property; that is what the trait-gated hardware
/// suites and the real-hardware verification are for.</para>
///
/// <para>Brief T11 decision 5: the presence choice it was constructed with is appended to the blob
/// as one flag byte (<c>1</c> presence required, <c>0</c> none), so tests read what reached the
/// backend from the saved slot blob. This blob format is test-only. <see cref="Unlock"/> accepts
/// the old length (read as presence) and the new one; it doesn't enforce the flag.</para>
///
/// <para>Brief T17: it enforces the vault password like the real backends. A password slot's
/// <c>KEK_slot</c> is wrapped under <c>HKDF-SHA256(machineKey || stretched, info
/// "tswap-simulated-password-v1")</c>, so a wrong password fails like a wrong machine (with ruling 18's
/// YubiKey/KDF text), and its blob is the backend's password header (<see cref="TpmSlotBlob"/> or
/// <see cref="SecureEnclaveSlotBlob"/>) around the package. The package also ends with one more byte,
/// <c>'P'</c> after the presence flag ("the object needs a password"), the simulated counterpart of a
/// TPM object's auth value: a package whose header was stripped fails with ruling 3's stripped-header
/// text, as <c>TPM_RC_AUTH_FAIL</c> does.</para>
/// </summary>
public sealed class SimulatedHardwareService : IHardwareKeyService, IHardwareEnrollmentService
{
    private const int KeySize = 32;
    private static readonly int NonceSize = AesGcm.NonceByteSizes.MaxSize;
    private static readonly int TagSize = AesGcm.TagByteSizes.MaxSize;

    private const byte PresenceFlag = 1;
    private const byte NeedsPasswordMarker = (byte)'P';
    private static ReadOnlySpan<byte> PasswordInfo => "tswap-simulated-password-v1"u8;

    private readonly byte[] _machineKey;
    private readonly bool _requirePresence;

    private static readonly AsyncLocal<Action<HardwareBackend, string>?> CallObserver = new();

    /// <summary>
    /// Brief T12 test seam: until the result is disposed, every <see cref="Enroll"/> and
    /// <see cref="Unlock"/> made in the caller's async flow first calls <paramref name="observer"/>
    /// with this service's backend and the call's name (<c>"Enroll"</c>, <c>"Unlock"</c>), so a
    /// test can see the identity a call ran as. Flow-local, so parallel tests don't see each other.
    /// </summary>
    public static IDisposable ObserveCalls(Action<HardwareBackend, string> observer)
    {
        var previous = CallObserver.Value;
        CallObserver.Value = observer;
        return new ObserverScope(previous);
    }

    private sealed class ObserverScope(Action<HardwareBackend, string>? previous) : IDisposable
    {
        public void Dispose() => CallObserver.Value = previous;
    }

    /// <param name="requirePresence">
    /// Brief T11: false only for a Secure Enclave enrolled with <c>--no-touch</c>; any other backend
    /// without presence throws, as <c>HardwareServices.Enrollment</c> does.
    /// </param>
    public SimulatedHardwareService(HardwareBackend backend, byte[] machineKey, bool requirePresence = true)
    {
        if (machineKey.Length != KeySize)
            throw new ArgumentException($"The simulated machine key must be {KeySize} bytes", nameof(machineKey));
        if (!requirePresence && backend != HardwareBackend.SecureEnclave)
            throw new ArgumentException($"Only a Secure Enclave enrolment can choose no presence, not '{backend.DisplayName}'", nameof(requirePresence));
        Backend = backend;
        _machineKey = (byte[])machineKey.Clone();
        _requirePresence = requirePresence;
    }

    public HardwareBackend Backend { get; }

    public bool IsSimulated => true;

    /// <summary>
    /// Generates a random <c>KEK_slot</c> and wraps it to this simulated machine; with
    /// <paramref name="password"/>, to the machine and the password (brief T17).
    /// </summary>
    public HardwareEnrollment Enroll(StretchedPassword? password)
    {
        CallObserver.Value?.Invoke(Backend, nameof(Enroll));
        var kekSlot = RandomNumberGenerator.GetBytes(KeySize);

        var blob = new byte[NonceSize + TagSize + kekSlot.Length + 1 + (password is null ? 0 : 1)];
        var nonce = blob.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        var wrapKey = WrapKey(password);
        try
        {
            using var aes = new AesGcm(wrapKey, TagSize);
            aes.Encrypt(nonce, kekSlot, blob.AsSpan(NonceSize + TagSize, KeySize), blob.AsSpan(NonceSize, TagSize));
        }
        finally
        {
            if (password is not null)
                CryptographicOperations.ZeroMemory(wrapKey);
        }
        if (password is null)
        {
            blob[^1] = _requirePresence ? PresenceFlag : (byte)0; // the test seam (brief T11 decision 5)
            return new HardwareEnrollment(kekSlot, blob);
        }

        blob[^2] = _requirePresence ? PresenceFlag : (byte)0;
        blob[^1] = NeedsPasswordMarker;
        return new HardwareEnrollment(kekSlot, Backend switch
        {
            HardwareBackend.Tpm => TpmSlotBlob.Wrap(blob),
            HardwareBackend.SecureEnclave => SecureEnclaveSlotBlob.Wrap(blob),
            _ => throw new InvalidOperationException($"The simulated '{Backend.DisplayName}' backend has no password slot blob"),
        });
    }

    /// <summary>The machine key, or for a password slot <c>HKDF(machineKey || stretched)</c>.</summary>
    private byte[] WrapKey(StretchedPassword? password)
    {
        if (password is null)
            return _machineKey;
        var ikm = new byte[KeySize + StretchedPassword.Size];
        try
        {
            _machineKey.CopyTo(ikm, 0);
            password.CopyTo(ikm.AsSpan(KeySize));
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KeySize, salt: [], info: PasswordInfo.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>
    /// Recovers <c>KEK_slot</c> from this backend's blob in <paramref name="config"/>.
    /// <paramref name="chooseSerial"/> is unused: a simulated TPM/Secure Enclave is one device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial, VaultPasswordProvider? password)
    {
        _ = chooseSerial;
        CallObserver.Value?.Invoke(Backend, nameof(Unlock));
        var hwBlob = HardwareBlobLocator.Read(config, Backend);

        // Brief T17: split off the password header, as the real backends do.
        var (needsPassword, blob) = Backend == HardwareBackend.SecureEnclave
            ? SecureEnclaveSlotBlob.Split(hwBlob)
            : TpmSlotBlob.Split(hwBlob);

        // The old length (no flag byte, read as presence), the new one with a flag of 0 or 1, or (brief
        // T17) a password object: the flag, then the 'P' marker.
        var sealedLength = NonceSize + TagSize + KeySize;
        var objectNeedsPassword = blob.Length == sealedLength + 2 && blob[^2] is 0 or 1 && blob[^1] == NeedsPasswordMarker;
        if (!(blob.Length == sealedLength || (blob.Length == sealedLength + 1 && blob[^1] is 0 or 1) || objectNeedsPassword))
            throw new TswapException(
                $"Config is corrupted: the simulated '{Backend.DisplayName}' blob has the wrong length. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        if (!needsPassword)
        {
            if (objectNeedsPassword)
                throw new VaultPasswordRefusedException(VaultPasswordMessages.StrippedHeader);
            return Decrypt(blob, _machineKey) ?? throw new TswapException(
                $"Simulated '{Backend.DisplayName}' operation failed while unwrapping the key: the blob was made " +
                "on a different machine or is corrupted.");
        }

        if (password is null)
            throw new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal);
        using var stretched = password();
        var wrapKey = WrapKey(stretched);
        try
        {
            return Decrypt(blob, wrapKey) ?? throw new VaultPasswordRefusedException(VaultPasswordMessages.WrongPasswordKdf);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    private static byte[]? Decrypt(byte[] blob, byte[] key)
    {
        var kekSlot = new byte[KeySize];
        using var aes = new AesGcm(key, TagSize);
        try
        {
            aes.Decrypt(blob.AsSpan(0, NonceSize), blob.AsSpan(NonceSize + TagSize, KeySize), blob.AsSpan(NonceSize, TagSize), kekSlot);
            return kekSlot;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
