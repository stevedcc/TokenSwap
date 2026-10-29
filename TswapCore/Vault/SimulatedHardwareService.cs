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
/// </summary>
public sealed class SimulatedHardwareService : IHardwareKeyService, IHardwareEnrollmentService
{
    private const int KeySize = 32;
    private static readonly int NonceSize = AesGcm.NonceByteSizes.MaxSize;
    private static readonly int TagSize = AesGcm.TagByteSizes.MaxSize;

    private readonly byte[] _machineKey;

    public SimulatedHardwareService(HardwareBackend backend, byte[] machineKey)
    {
        if (machineKey.Length != KeySize)
            throw new ArgumentException($"The simulated machine key must be {KeySize} bytes", nameof(machineKey));
        Backend = backend;
        _machineKey = (byte[])machineKey.Clone();
    }

    public HardwareBackend Backend { get; }

    public bool IsSimulated => true;

    /// <summary>Generates a random <c>KEK_slot</c> and wraps it to this simulated machine.</summary>
    public HardwareEnrollment Enroll()
    {
        var kekSlot = RandomNumberGenerator.GetBytes(KeySize);

        var blob = new byte[NonceSize + TagSize + kekSlot.Length];
        var nonce = blob.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_machineKey, TagSize);
        aes.Encrypt(nonce, kekSlot, blob.AsSpan(NonceSize + TagSize), blob.AsSpan(NonceSize, TagSize));

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

        if (blob.Length != NonceSize + TagSize + KeySize)
            throw new TswapException(
                $"Config is corrupted: the simulated '{Backend.DisplayName()}' blob has the wrong length. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        var kekSlot = new byte[KeySize];
        using var aes = new AesGcm(_machineKey, TagSize);
        try
        {
            aes.Decrypt(blob.AsSpan(0, NonceSize), blob.AsSpan(NonceSize + TagSize), blob.AsSpan(NonceSize, TagSize), kekSlot);
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
