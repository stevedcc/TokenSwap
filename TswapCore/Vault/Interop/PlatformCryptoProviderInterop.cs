using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace TswapCore.Vault.Interop;

/// <summary>
/// Bridge to Windows' CNG "Microsoft Platform Crypto Provider" (PCP) — the TPM-backed Key
/// Storage Provider Windows itself uses for BitLocker/Windows Hello for Business keys. Reached
/// entirely through <c>System.Security.Cryptography.Cng</c> managed APIs
/// (<see cref="CngKey"/>/<see cref="RSACng"/>); no P/Invoke or native shim needed — unlike the
/// Secure Enclave (no C ABI) or Linux (chose a CLI shellout over a large P/Invoke surface), the
/// managed CNG surface already reaches PCP directly. See <c>HARDWARE_BACKENDS.md</c>'s Windows
/// TPM section for what's actually been verified here versus assumed.
///
/// <para><b>Primitive: RSA-OAEP wrap/unwrap against a named, non-exportable, TPM-backed key —
/// not TPM2 sealed-object seal/unseal like the Linux backend.</b> This is a real, verified
/// platform difference, not a stylistic choice: a PCP key created with
/// <see cref="CngExportPolicies.None"/> cannot be exported in <b>any</b> blob format —
/// <c>CngKeyBlobFormat.OpaqueTransportBlob</c> and every PCP-specific format name tried
/// (<c>PCPKEY_TPM20</c>, <c>PCPKEY_TPM12</c>, etc.) failed with "not supported" /
/// "invalid type specified" when tested directly against this backend's dev VM. So there is no
/// self-contained blob to hand back the way <c>AppleSecureEnclaveInterop.Wrap</c> or
/// <c>Tpm2ToolsInterop.Seal</c> do. Instead the key is created once under a fixed, well-known
/// persisted name and always re-opened by that name — <b>verified directly</b> that a key
/// created in one process is opened and used successfully by a completely separate process via
/// <see cref="CngKey.Open(string, CngProvider)"/> alone, no other state passed between them.
/// <see cref="Config.TpmSealedKey"/> therefore stores only the RSA-OAEP ciphertext (not a key
/// blob) — meaningless without the matching named key, which only exists on this machine's TPM.
/// </para>
///
/// <para><b>Re-init behavior, verified:</b> creating the key again with
/// <see cref="CngKeyCreationOptions.OverwriteExistingKey"/> cleanly replaces it — the new key
/// decrypts newly-produced ciphertext correctly and reproducibly fails (a TPM-reported
/// <see cref="CryptographicException"/>, not a crash or silent garbage) on ciphertext produced
/// by the key generation it replaced. That's the same "re-init invalidates the old vault key"
/// property <c>InitCommand</c>'s other hardware-init branches rely on.</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PlatformCryptoProviderInterop
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";

    // Fixed, well-known name: this is today's single-slot, k=1 precursor (same as
    // Config.TpmSealedKey/SecureEnclaveWrappedKey), not the Phase 6 multi-slot keyring — see
    // MULTI_MACHINE_KEYING.md. One tswap vault, one named key.
    private const string KeyName = "tswap-vault-key";

    private const int KeySizeBits = 2048;

    private static readonly CngProvider Provider = new(ProviderName);

    /// <summary>
    /// Cheap presence check. <b>Not independently verified against a machine with no TPM at
    /// all</b> — this dev VM always has a (virtual) TPM, so only the "provider exists but key
    /// doesn't" and "key exists and works" paths were tested directly. A missing-TPM machine is
    /// expected to fail the same way <see cref="CngKey.Open"/> fails for a missing key
    /// (<see cref="CryptographicException"/>), based on how CNG providers behave generally, but
    /// that specific claim is not empirically confirmed here.
    /// </summary>
    public static bool IsAvailable()
    {
        try
        {
            // Cheapest real probe available without creating a key: ask whether the named key
            // exists via the provider. Throws if the KSP can't be loaded at all.
            _ = CngKey.Exists(KeyName, Provider);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static void RequireAvailable()
    {
        if (!IsAvailable())
            throw new TswapException(
                "No usable TPM detected. This requires a TPM 2.0 device exposed through Windows' " +
                "\"Microsoft Platform Crypto Provider\". Use a different backend (YubiKey) on this machine.");
    }

    /// <summary>
    /// Enrollment: (re)creates the named TPM-backed key (overwriting any prior generation —
    /// verified this cleanly invalidates ciphertext from the previous generation) and
    /// RSA-OAEP-SHA256-encrypts <paramref name="plaintextKey"/> to it.
    /// </summary>
    public static byte[] Wrap(byte[] plaintextKey)
    {
        RequireAvailable();

        using var key = CreateKey();
        using var rsa = new RSACng(key);
        try
        {
            return rsa.Encrypt(plaintextKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException ex)
        {
            throw new TswapException($"TPM operation failed while wrapping the key: {ex.Message}");
        }
    }

    /// <summary>Unlock: opens the named TPM-backed key and RSA-OAEP-SHA256-decrypts a payload produced by <see cref="Wrap"/>.</summary>
    public static byte[] Unwrap(byte[] wrapped)
    {
        RequireAvailable();

        if (!CngKey.Exists(KeyName, Provider))
            throw new TswapException(
                "Config is corrupted: vault uses the 'tpm' backend but this machine has no " +
                "matching TPM key. Restore config.json from backup or re-run 'tswap init'.");

        using var key = CngKey.Open(KeyName, Provider);
        using var rsa = new RSACng(key);
        try
        {
            return rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException)
        {
            // Verified: both "sealed on a different machine/generation" (stale ciphertext
            // against a replaced key) and "malformed ciphertext" (wrong length, garbage bytes)
            // land here as CryptographicException with different messages from the TPM/CNG
            // stack. Collapsing to one message rather than parsing those strings, same
            // reasoning as Tpm2ToolsInterop.Unseal's UnlockFailed().
            throw new TswapException(
                "Could not unlock with the TPM. The sealed key may have been created on a " +
                "different machine or a prior 'tswap init', or config.json may be corrupted.");
        }
    }

    private static CngKey CreateKey()
    {
        var creationParams = new CngKeyCreationParameters
        {
            Provider = Provider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Decryption,
            KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
        };
        creationParams.Parameters.Add(new CngProperty(
            "Length", BitConverter.GetBytes(KeySizeBits), CngPropertyOptions.None));

        try
        {
            return CngKey.Create(CngAlgorithm.Rsa, KeyName, creationParams);
        }
        catch (CryptographicException ex)
        {
            throw new TswapException($"TPM operation failed while creating the TPM key: {ex.Message}");
        }
    }
}
