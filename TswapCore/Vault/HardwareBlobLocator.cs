namespace TswapCore.Vault;

/// <summary>
/// Finds a wrap/seal backend's blob in a <see cref="Config"/>: the single-slot field
/// (<see cref="Config.TpmSealedKey"/> for <see cref="HardwareBackend.Tpm"/>,
/// <see cref="Config.SecureEnclaveWrappedKey"/> for <see cref="HardwareBackend.SecureEnclave"/>),
/// decoded from base64. Throws <see cref="TswapException"/> with the same "Config is corrupted"
/// messages the real backends have always used, so the simulated backend fails the same way.
/// </summary>
public static class HardwareBlobLocator
{
    public static byte[] Read(Config config, HardwareBackend backend)
    {
        var (field, missing, notBase64) = backend switch
        {
            HardwareBackend.Tpm => (config.TpmSealedKey,
                "vault uses the 'tpm' backend but has no sealed key",
                "the TPM sealed key is not valid base64"),
            HardwareBackend.SecureEnclave => (config.SecureEnclaveWrappedKey,
                "vault uses the 'secure-enclave' backend but has no wrapped key",
                "the Secure Enclave wrapped key is not valid base64"),
            _ => throw new ArgumentOutOfRangeException(nameof(backend), backend, "Only wrap/seal backends store a blob"),
        };

        if (field is not { Length: > 0 })
            throw new TswapException($"Config is corrupted: {missing}. Restore config.json from backup or re-run 'tswap init'.");

        try
        {
            return Convert.FromBase64String(field);
        }
        catch (FormatException)
        {
            throw new TswapException($"Config is corrupted: {notBase64}. Restore config.json from backup or re-run 'tswap init'.");
        }
    }
}
