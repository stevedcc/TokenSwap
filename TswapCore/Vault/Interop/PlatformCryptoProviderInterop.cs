using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

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
/// "invalid type specified" when tested directly against this backend's dev VM.</para>
///
/// <para><b>The key name is random per <see cref="Wrap"/> call, not a single fixed name.</b> An
/// earlier version used one hard-coded persisted name for every vault on the machine — that
/// meant a second <c>tswap init --tpm</c> (a different vault via a different
/// <c>TSWAP_CONFIG_DIR</c>, or just the test suite) would silently overwrite the *first* vault's
/// key and permanently break its ability to unseal, since PCP key names are a single flat,
/// machine-wide namespace with no per-vault scoping of their own. <see cref="Wrap"/> instead
/// generates a fresh random name for every call and bundles it into the returned blob (4-byte
/// length-prefixed name, then the RSA-OAEP ciphertext) — the same "one self-contained blob"
/// shape <c>AppleSecureEnclaveInterop</c>/<c>Tpm2ToolsInterop</c> already use. <see cref="Unwrap"/>
/// reads the name back out of the blob and opens exactly that key. This means every vault, and
/// every test run, gets its own isolated TPM key with no shared state and nothing to configure —
/// not just "test vs. prod" but any number of independent vaults on one machine.</para>
///
/// <para><b>Re-init leaves the old named key orphaned in the PCP key store</b> rather than
/// reusing/overwriting it, since a fresh random name is generated every time. That's a minor key
/// store hygiene cost (harmless: PCP keys are cheap and this Windows TPM backend is single-slot,
/// k=1 today), not a correctness issue — the new key and its blob are fully independent of
/// whatever the old one was.</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PlatformCryptoProviderInterop
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const string KeyNamePrefix = "tswap-vault-key-";
    private const int KeySizeBits = 2048;

    private static readonly CngProvider Provider = new(ProviderName);

    /// <summary>Cheap, side-effect-free presence check — does not create or touch any key.</summary>
    public static bool IsAvailable()
    {
        try
        {
            // Cheapest real probe available without creating a key: ask whether some
            // definitely-nonexistent key exists via the provider. Throws if the KSP itself
            // can't be loaded at all; returns false (not an exception) for a normal "no such
            // key" answer either way, so this only tests provider availability.
            _ = CngKey.Exists(KeyNamePrefix + "availability-probe", Provider);
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
    /// Enrollment: creates a new, randomly-named, non-exportable TPM-backed key and
    /// RSA-OAEP-SHA256-encrypts <paramref name="plaintextKey"/> to it. The returned blob bundles
    /// the key's name with the ciphertext, so it is self-contained and useless off this machine.
    /// </summary>
    public static byte[] Wrap(byte[] plaintextKey)
    {
        RequireAvailable();

        var keyName = KeyNamePrefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        using var key = CreateKey(keyName);
        using var rsa = new RSACng(key);

        byte[] ciphertext;
        try
        {
            ciphertext = rsa.Encrypt(plaintextKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException ex)
        {
            throw new TswapException($"TPM operation failed while wrapping the key: {ex.Message}");
        }

        var nameBytes = Encoding.UTF8.GetBytes(keyName);
        var package = new byte[4 + nameBytes.Length + ciphertext.Length];
        BinaryPrimitives.WriteInt32LittleEndian(package, nameBytes.Length);
        Buffer.BlockCopy(nameBytes, 0, package, 4, nameBytes.Length);
        Buffer.BlockCopy(ciphertext, 0, package, 4 + nameBytes.Length, ciphertext.Length);
        return package;
    }

    /// <summary>Unlock: opens the named TPM-backed key from <paramref name="wrapped"/> and RSA-OAEP-SHA256-decrypts the ciphertext bundled alongside it.</summary>
    public static byte[] Unwrap(byte[] wrapped)
    {
        RequireAvailable();

        if (wrapped.Length < 4)
            throw new TswapException("Config is corrupted: the TPM sealed key is too short to be valid.");

        var nameLen = BinaryPrimitives.ReadInt32LittleEndian(wrapped);
        // Subtraction, not "4 + nameLen > wrapped.Length": nameLen comes straight off the wire
        // and addition can overflow for a huge value, wrapping to negative and defeating the
        // check. wrapped.Length - 4 can't underflow (already checked wrapped.Length >= 4 above).
        // ">=" (not ">") also requires at least 1 leftover byte for the ciphertext.
        if (nameLen < 0 || nameLen >= wrapped.Length - 4)
            throw new TswapException("Config is corrupted: the TPM sealed key has an invalid length prefix.");

        string keyName;
        try
        {
            keyName = Encoding.UTF8.GetString(wrapped.AsSpan(4, nameLen));
        }
        catch (DecoderFallbackException)
        {
            throw new TswapException("Config is corrupted: the TPM sealed key's embedded key name is not valid UTF-8.");
        }

        if (!keyName.StartsWith(KeyNamePrefix, StringComparison.Ordinal) || !CngKey.Exists(keyName, Provider))
            throw new TswapException(
                "Config is corrupted: vault uses the 'tpm' backend but this machine has no " +
                "matching TPM key. Restore config.json from backup or re-run 'tswap init'.");

        var ciphertext = wrapped.AsSpan(4 + nameLen).ToArray();

        try
        {
            // CngKey.Open and the RSACng construction are inside this try too, not just
            // Decrypt: the Exists() check above and this Open() are not atomic, so the key
            // can still legitimately vanish in between (TPM cleared, key store cleanup, a
            // concurrent re-init) — that must surface as the same clear TswapException, not a
            // raw CryptographicException from Open() escaping uncaught.
            using var key = CngKey.Open(keyName, Provider);
            using var rsa = new RSACng(key);
            return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException)
        {
            // Verified: both "sealed on a different machine/generation" (a stale blob whose
            // named key no longer matches) and "malformed ciphertext" (wrong length, garbage
            // bytes) land here as CryptographicException with different messages from the
            // TPM/CNG stack. Collapsing to one message rather than parsing those strings, same
            // reasoning as Tpm2ToolsInterop.Unseal's UnlockFailed().
            throw new TswapException(
                "Could not unlock with the TPM. The sealed key may have been created on a " +
                "different machine, or config.json may be corrupted.");
        }
    }

    private static CngKey CreateKey(string keyName)
    {
        var creationParams = new CngKeyCreationParameters
        {
            Provider = Provider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Decryption,
        };
        creationParams.Parameters.Add(new CngProperty(
            "Length", BitConverter.GetBytes(KeySizeBits), CngPropertyOptions.None));

        try
        {
            return CngKey.Create(CngAlgorithm.Rsa, keyName, creationParams);
        }
        catch (CryptographicException ex)
        {
            throw new TswapException($"TPM operation failed while creating the TPM key: {ex.Message}");
        }
    }
}

