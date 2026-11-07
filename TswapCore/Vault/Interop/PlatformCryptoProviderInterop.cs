using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Keyring;
using TswapCore.VaultPassword;

namespace TswapCore.Vault.Interop;

/// <summary>
/// Bridge to Windows' CNG "Microsoft Platform Crypto Provider" (PCP) — the TPM-backed Key
/// Storage Provider Windows itself uses for BitLocker/Windows Hello for Business keys. Reached
/// entirely through <c>System.Security.Cryptography.Cng</c> managed APIs
/// (<see cref="CngKey"/>/<see cref="RSACng"/>); no P/Invoke or native shim needed — unlike the
/// Secure Enclave (no C ABI) or Linux (chose a CLI shellout over a large P/Invoke surface), the
/// managed CNG surface already reaches PCP directly. See <c>docs/design/hardware-backends.md</c>'s Windows
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
/// <para><b>Brief T17 task 9: the vault password as the key's usage auth.</b> A password slot's key is
/// created with <c>PCP_USAGEAUTH</c> set to the 32 stretched bytes; at use it is opened
/// <see cref="CngKeyOpenOptions.Silent"/> (always, password or not, so Windows never shows its own password
/// dialog), given the same 32 bytes through <c>SetProperty("PCP_USAGEAUTH")</c>, and asked for exactly one
/// <c>Decrypt</c>: no retry, since Windows counts every failure towards its TPM lockout (ruling 17). Codes
/// from the owner's spike (2026-11-02) map to ruling 18's texts. No <c>NCRYPT_PCP_*</c> flag that would exempt
/// the key from dictionary-attack protection is set. <c>CngProperty</c> keeps its own copy of the auth bytes
/// on the GC heap, which tswap can't zero (ruling 1's best-effort derivation window).</para>
///
/// <para>All CNG calls go through <see cref="IPcpKeyStore"/>, so the logic here (parsing, error mapping, one
/// decrypt per password) is unit-tested on every OS with a fake store (<see cref="StoreOverride"/>).</para>
/// </summary>
internal static class PlatformCryptoProviderInterop
{
    private const string KeyNamePrefix = "tswap-vault-key-";
    private const int KeySizeBits = 2048;

    /// <summary>The property that carries a PCP key's usage auth (owner's spike: 32 raw bytes work).</summary>
    internal const string UsageAuthProperty = "PCP_USAGEAUTH";

    // Ruling 18's codes (owner's spike, 2026-11-02).
    internal const int NtePerm = unchecked((int)0x80090010);              // wrong usage auth
    internal const int NteDaLockout = unchecked((int)0x80090031);          // provider: dictionary-attack lockout
    internal const int TpmDaLockout = unchecked((int)0x80290409);          // Platform Crypto Device: lockout (also at Create)
    internal const int NteSilentContext = unchecked((int)0x80090022);      // silent open of a password key, no auth set

    /// <summary>Test seam: the CNG key store to use instead of the real Platform Crypto Provider.</summary>
    internal static IPcpKeyStore? StoreOverride { get; set; }

    private static IPcpKeyStore Store =>
        StoreOverride ?? (OperatingSystem.IsWindows()
            ? CngPcpKeyStore.Instance
            : throw new PlatformNotSupportedException("The Windows TPM backend runs only on Windows."));

    /// <summary>Cheap, side-effect-free presence check — does not create or touch any key.</summary>
    public static bool IsAvailable() => Store.IsAvailable();

    internal const string ProviderUnavailableReason =
        "the Microsoft Platform Crypto Provider isn't available (no TPM, or it is disabled)";

    /// <summary>
    /// <see cref="IsAvailable"/> with the reason when it isn't (guided init lists it): the real store's
    /// <see cref="CngPcpKeyStore.TryProbe"/>, or the test store's answer.
    /// </summary>
    public static (bool Available, string? Reason) Probe()
    {
        if (StoreOverride is { } fake)
            return ProbeOutcome(fake.IsAvailable(), null);
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The Windows TPM backend runs only on Windows.");
        var failure = CngPcpKeyStore.Instance.TryProbe();
        return ProbeOutcome(failure is null, failure);
    }

    /// <summary>The probe's answer: usable, or why not (CNG's message when it gave one).</summary>
    internal static (bool Available, string? Reason) ProbeOutcome(bool available, CryptographicException? failure) =>
        available ? (true, null)
        : (false, failure?.Message is { } message && !string.IsNullOrWhiteSpace(message) ? message : ProviderUnavailableReason);

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
    public static byte[] Wrap(byte[] plaintextKey) => WrapCore(plaintextKey, null);

    /// <summary>
    /// Brief T17 task 9: as <see cref="Wrap(byte[])"/>, but the key's usage auth is the stretched vault
    /// password (<c>PCP_USAGEAUTH</c>). The package layout is unchanged; the caller adds the <c>TSTP</c> header.
    /// </summary>
    public static byte[] Wrap(byte[] plaintextKey, StretchedPassword password) => WrapCore(plaintextKey, password);

    private static byte[] WrapCore(byte[] plaintextKey, StretchedPassword? password)
    {
        RequireAvailable();

        var keyName = KeyNamePrefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var auth = password is null ? null : AuthBytes(password);
        byte[] ciphertext;
        try
        {
            using var key = CreateKey(keyName, auth);
            try
            {
                ciphertext = key.Encrypt(plaintextKey);
            }
            catch (CryptographicException ex)
            {
                throw new TswapException($"TPM operation failed while wrapping the key: {ex.Message}");
            }
        }
        finally
        {
            if (auth is not null)
                CryptographicOperations.ZeroMemory(auth);
        }

        var nameBytes = Encoding.UTF8.GetBytes(keyName);
        var package = new byte[4 + nameBytes.Length + ciphertext.Length];
        BinaryPrimitives.WriteInt32LittleEndian(package, nameBytes.Length);
        Buffer.BlockCopy(nameBytes, 0, package, 4, nameBytes.Length);
        Buffer.BlockCopy(ciphertext, 0, package, 4 + nameBytes.Length, ciphertext.Length);
        return package;
    }

    /// <summary>Unlock: opens the named TPM-backed key from <paramref name="wrapped"/> and RSA-OAEP-SHA256-decrypts the ciphertext bundled alongside it.</summary>
    public static byte[] Unwrap(byte[] wrapped) => UnwrapCore(wrapped, null);

    /// <summary>Brief T17 task 9: unwraps a password slot's package (header removed) with the stretched vault password as usage auth.</summary>
    public static byte[] Unwrap(byte[] wrapped, StretchedPassword password) => UnwrapCore(wrapped, password);

    private static byte[] UnwrapCore(byte[] wrapped, StretchedPassword? password)
    {
        // Ruling 3: an unsplit password blob ("TSTP" read as a length is 0x50545354) must not be parsed
        // as a legacy package and called corrupted (issue #261: one without the password bit doesn't claim the password).
        if (TpmSlotBlob.HasHeader(wrapped))
            throw new TswapException(VaultPasswordMessages.UnsplitTpmHeader(wrapped));

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

        var ciphertext = wrapped.AsSpan(4 + nameLen).ToArray();
        var store = Store;

        try
        {
            // CngKey.Exists, CngKey.Open, and the RSACng construction are all inside this same
            // try as Decrypt, not just Decrypt: any of them can throw CryptographicException
            // for a genuine provider/key-store failure (distinct from Exists() simply
            // returning false for "no such key," which is not an exception and still throws
            // its own clear message below via the ordinary control flow) — including the case
            // where the key vanishes between Exists() and Open() (TPM cleared, key store
            // cleanup, a concurrent re-init), since the two calls are not atomic. Every TPM/CNG
            // failure from this point on should surface the same clear message.
            if (!keyName.StartsWith(KeyNamePrefix, StringComparison.Ordinal) || !store.Exists(keyName))
                throw new TswapException(
                    "Config is corrupted: vault uses the 'tpm' backend but this machine has no " +
                    "matching TPM key. Restore config.json from backup or re-run 'tswap init'.");

            // Brief T17: always silent, so Windows never shows its own password dialog.
            using var key = store.Open(keyName, PcpOpenOptions.Silent);
            if (password is not null)
            {
                var auth = AuthBytes(password);
                try
                {
                    key.SetUsageAuth(auth);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(auth);
                }
            }
            // Exactly one Decrypt per supplied password; no retry (ruling 17).
            return key.Decrypt(ciphertext);
        }
        catch (CryptographicException ex)
        {
            if (MapPasswordError(ex, passwordSupplied: password is not null) is { } refused)
                throw refused;
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

    /// <summary>
    /// Ruling 18 (and ruling 3 for a stripped header): the codes that mean the password, or Windows' lockout,
    /// refused the key. Null for any other code, which keeps the caller's own text.
    /// </summary>
    private static VaultPasswordRefusedException? MapPasswordError(CryptographicException ex, bool passwordSupplied) =>
        KnownCode(ex) switch
        {
            NteDaLockout or TpmDaLockout => new(VaultPasswordMessages.TpmLockoutWindows, VaultPasswordRefusal.Lockout),
            NtePerm when passwordSupplied => new(VaultPasswordMessages.WrongPasswordTpm, VaultPasswordRefusal.WrongPassword),
            // A Password slot always sets the auth, so this is a bug there; on a legacy (unsplit) blob it
            // is ruling 3's stripped header.
            NteSilentContext => passwordSupplied
                ? new(VaultPasswordMessages.WindowsSilentContextBug, VaultPasswordRefusal.Other)
                : new(VaultPasswordMessages.StrippedHeader, VaultPasswordRefusal.StrippedHeader),
            _ => null,
        };

    /// <summary>The first of ruling 18's codes in <paramref name="ex"/>'s chain, if any.</summary>
    private static int? KnownCode(Exception ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e.HResult is NtePerm or NteDaLockout or TpmDaLockout or NteSilentContext)
                return e.HResult;
        }
        return null;
    }

    private static byte[] AuthBytes(StretchedPassword password)
    {
        var auth = new byte[StretchedPassword.Size];
        password.CopyTo(auth);
        return auth;
    }

    private static IPcpKey CreateKey(string keyName, byte[]? usageAuth)
    {
        List<PcpProperty> properties = [new("Length", BitConverter.GetBytes(KeySizeBits))];
        if (usageAuth is not null)
            properties.Add(new(UsageAuthProperty, usageAuth));

        try
        {
            return Store.Create(keyName, properties);
        }
        catch (CryptographicException ex)
        {
            // 0x80290409 blocks key creation too while Windows' TPM lockout lasts (ruling 18).
            if (KnownCode(ex) is NteDaLockout or TpmDaLockout)
                throw new VaultPasswordRefusedException(VaultPasswordMessages.TpmLockoutWindows, VaultPasswordRefusal.Lockout);
            throw new TswapException($"TPM operation failed while creating the TPM key: {ex.Message}");
        }
    }
}

/// <summary>How <see cref="IPcpKeyStore.Open"/> opens a key; tswap always uses <see cref="Silent"/>.</summary>
internal enum PcpOpenOptions
{
    None,
    Silent,
}

/// <summary>A key creation property (<c>CngProperty</c> with <c>CngPropertyOptions.None</c>).</summary>
internal readonly record struct PcpProperty(string Name, byte[] Value);

/// <summary>The CNG surface <see cref="PlatformCryptoProviderInterop"/> uses: the seam for unit tests (brief T17 task 9).</summary>
internal interface IPcpKeyStore
{
    bool IsAvailable();
    bool Exists(string name);
    IPcpKey Create(string name, IReadOnlyList<PcpProperty> properties);
    IPcpKey Open(string name, PcpOpenOptions options);
}

/// <summary>An open PCP key: RSA-OAEP-SHA256 with its usage auth set or not.</summary>
internal interface IPcpKey : IDisposable
{
    void SetUsageAuth(byte[] auth);
    byte[] Encrypt(byte[] data);
    byte[] Decrypt(byte[] data);
}

/// <summary>The real Microsoft Platform Crypto Provider, through managed CNG.</summary>
[SupportedOSPlatform("windows")]
internal sealed class CngPcpKeyStore : IPcpKeyStore
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const string AvailabilityProbeName = "tswap-vault-key-availability-probe";

    public static CngPcpKeyStore Instance { get; } = new();

    private readonly CngProvider _provider = new(ProviderName);

    public bool IsAvailable() => TryProbe() is null;

    /// <summary>The provider's failure, or null when it can be used (guided init shows the reason).</summary>
    public CryptographicException? TryProbe()
    {
        try
        {
            // Cheapest real probe available without creating a key: ask whether some
            // definitely-nonexistent key exists via the provider. Throws if the KSP itself
            // can't be loaded at all; returns false (not an exception) for a normal "no such
            // key" answer either way, so this only tests provider availability.
            _ = CngKey.Exists(AvailabilityProbeName, _provider);
            return null;
        }
        catch (CryptographicException ex)
        {
            return ex;
        }
    }

    public bool Exists(string name) => CngKey.Exists(name, _provider);

    public IPcpKey Create(string name, IReadOnlyList<PcpProperty> properties)
    {
        var creationParams = new CngKeyCreationParameters
        {
            Provider = _provider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Decryption,
        };
        foreach (var property in properties)
            creationParams.Parameters.Add(new CngProperty(property.Name, property.Value, CngPropertyOptions.None));
        return new Key(CngKey.Create(CngAlgorithm.Rsa, name, creationParams));
    }

    public IPcpKey Open(string name, PcpOpenOptions options) =>
        new Key(CngKey.Open(name, _provider,
            options == PcpOpenOptions.Silent ? CngKeyOpenOptions.Silent : CngKeyOpenOptions.None));

    private sealed class Key(CngKey key) : IPcpKey
    {
        public void SetUsageAuth(byte[] auth) =>
            key.SetProperty(new CngProperty(PlatformCryptoProviderInterop.UsageAuthProperty, auth, CngPropertyOptions.None));

        public byte[] Encrypt(byte[] data)
        {
            using var rsa = new RSACng(key);
            return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        }

        public byte[] Decrypt(byte[] data)
        {
            using var rsa = new RSACng(key);
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
        }

        public void Dispose() => key.Dispose();
    }
}
