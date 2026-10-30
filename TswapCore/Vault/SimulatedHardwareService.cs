using System.Security.Cryptography;

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
/// </summary>
public sealed class SimulatedHardwareService : IHardwareKeyService, IHardwareEnrollmentService
{
    private const int KeySize = 32;
    private static readonly int NonceSize = AesGcm.NonceByteSizes.MaxSize;
    private static readonly int TagSize = AesGcm.TagByteSizes.MaxSize;

    private readonly byte[] _machineKey;
    private readonly bool _requirePresence;

    /// <param name="requirePresence">
    /// Brief T11: false only for a Secure Enclave enrolled with <c>--no-touch</c>; any other backend
    /// without presence throws, as <c>HardwareServices.Enrollment</c> does.
    /// </param>
    public SimulatedHardwareService(HardwareBackend backend, byte[] machineKey, bool requirePresence = true)
    {
        if (machineKey.Length != KeySize)
            throw new ArgumentException($"The simulated machine key must be {KeySize} bytes", nameof(machineKey));
        if (!requirePresence && backend != HardwareBackend.SecureEnclave)
            throw new ArgumentException($"Only a Secure Enclave enrolment can choose no presence, not '{backend.DisplayName()}'", nameof(requirePresence));
        Backend = backend;
        _machineKey = (byte[])machineKey.Clone();
        _requirePresence = requirePresence;
    }

    public HardwareBackend Backend { get; }

    public bool IsSimulated => true;

    /// <summary>Generates a random <c>KEK_slot</c> and wraps it to this simulated machine.</summary>
    public HardwareEnrollment Enroll()
    {
        var kekSlot = RandomNumberGenerator.GetBytes(KeySize);

        var blob = new byte[NonceSize + TagSize + kekSlot.Length + 1];
        var nonce = blob.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_machineKey, TagSize);
        aes.Encrypt(nonce, kekSlot, blob.AsSpan(NonceSize + TagSize, KeySize), blob.AsSpan(NonceSize, TagSize));
        blob[^1] = _requirePresence ? (byte)1 : (byte)0; // the test seam (brief T11 decision 5)

        return new HardwareEnrollment(kekSlot, blob);
    }

    /// <summary>
    /// Recovers <c>KEK_slot</c> from this backend's blob in <paramref name="config"/>.
    /// <paramref name="chooseSerial"/> is unused: a simulated TPM/Secure Enclave is one device.
    /// </summary>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        _ = chooseSerial;
        var blob = HardwareBlobLocator.Read(config, Backend);

        // The old length (no flag byte, read as presence) or the new one with a flag of 0 or 1.
        var sealedLength = NonceSize + TagSize + KeySize;
        if (!(blob.Length == sealedLength || (blob.Length == sealedLength + 1 && blob[^1] is 0 or 1)))
            throw new TswapException(
                $"Config is corrupted: the simulated '{Backend.DisplayName()}' blob has the wrong length. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        var kekSlot = new byte[KeySize];
        using var aes = new AesGcm(_machineKey, TagSize);
        try
        {
            aes.Decrypt(blob.AsSpan(0, NonceSize), blob.AsSpan(NonceSize + TagSize, KeySize), blob.AsSpan(NonceSize, TagSize), kekSlot);
        }
        catch (CryptographicException)
        {
            throw new TswapException(
                $"Simulated '{Backend.DisplayName()}' operation failed while unwrapping the key: the blob was made " +
                "on a different machine or is corrupted.");
        }

        return kekSlot;
    }
}
