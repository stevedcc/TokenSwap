using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TswapCore.Vault.Interop;

/// <summary>
/// P/Invoke bridge to <c>libtswapse.dylib</c> — the small Swift/CryptoKit shim built from
/// <c>Vault/Interop/swift/TswapSecureEnclave.swift</c> (see that file's header comment for why
/// a Swift shim, rather than calling Security.framework's <c>SecItem</c> APIs directly, is
/// what lets this backend run without a Developer ID certificate or provisioning profile).
///
/// <see cref="Wrap"/> returns, and <see cref="Unwrap"/> consumes, a single self-contained
/// byte array: a 4-byte little-endian length prefix, the Secure Enclave key's own
/// <c>dataRepresentation</c> blob, then the ECIES-wrapped ciphertext package. Bundling both
/// into one blob means <see cref="TswapCore.Config.SecureEnclaveWrappedKey"/> stays a single
/// field — <see cref="Unwrap"/> never needs a second, separately-persisted value to find the
/// key by.
/// </summary>
[SupportedOSPlatform("macos")]
internal static partial class AppleSecureEnclaveInterop
{
    private const string Lib = "libtswapse";

    static AppleSecureEnclaveInterop()
    {
        NativeLibrary.SetDllImportResolver(typeof(AppleSecureEnclaveInterop).Assembly, (name, assembly, searchPath) =>
        {
            if (name != Lib)
                return IntPtr.Zero;

            var dylibPath = Path.Combine(AppContext.BaseDirectory, "libtswapse.dylib");
            if (!File.Exists(dylibPath))
                throw new TswapException(
                    $"tswap's Secure Enclave support library is missing ({dylibPath} not found). " +
                    "This usually means tswap was run from a raw download rather than installed — " +
                    "run 'tswap installscript', review it, then run the generated script, which " +
                    "installs this file alongside the binary.");

            return NativeLibrary.Load(dylibPath);
        });
    }

    [LibraryImport(Lib)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static partial bool tswap_se_available();

    [LibraryImport(Lib)]
    private static partial int tswap_se_wrap(
        byte[] plaintext, int plaintextLen,
        byte[] outBlob, ref int outBlobLen,
        byte[] outCiphertext, ref int outCiphertextLen);

    /// <summary>
    /// Brief T11 decision 3: <see cref="tswap_se_wrap"/> plus the presence choice (1: presence
    /// required, 0: none; anything else: no key, <see cref="SecureEnclaveReturnCodes.WrapInvalidPresence"/>).
    /// A new entry point rather than a new parameter on <see cref="tswap_se_wrap"/>, so an old
    /// dylib beside this binary fails with <see cref="EntryPointNotFoundException"/> instead of
    /// reading garbage as the choice. Every enrolment calls this one; the old one stays declared
    /// (and in the dylib, unchanged) so its signature stays pinned by the tests.
    /// </summary>
    [LibraryImport(Lib)]
    private static partial int tswap_se_wrap_v2(
        byte[] plaintext, int plaintextLen,
        byte[] outBlob, ref int outBlobLen,
        byte[] outCiphertext, ref int outCiphertextLen,
        int requirePresence);

    [LibraryImport(Lib)]
    private static partial int tswap_se_unwrap(
        byte[] blob, int blobLen,
        byte[] ciphertext, int ciphertextLen,
        byte[] outPlaintext, ref int outPlaintextLen);

    // Generous fixed buffers: a P-256 Secure Enclave key's dataRepresentation is ~430 bytes,
    // and the ECIES package is 65 (ephemeral pubkey) + 12 (nonce) + plaintext + 16 (tag) bytes.
    private const int BlobBufferSize = 2048;
    private const int CiphertextBufferSize = 2048;

    public static bool IsAvailable() => tswap_se_available();

    private static void RequireAvailable()
    {
        if (!IsAvailable())
            throw new TswapException(
                "This Mac does not have a usable Secure Enclave. Secure Enclave requires Apple " +
                "Silicon or a T2 chip — use a different backend (YubiKey) on this machine.");
    }

    /// <summary>
    /// Enrollment: creates a new Secure Enclave key and ECIES-wraps <paramref name="plaintextKey"/>
    /// to it. <paramref name="requirePresence"/> is fixed into the key's access control: true,
    /// every unwrap prompts for Touch ID or the login password; false, no prompt (brief T11). It
    /// can't be changed or read back from the key later.
    /// </summary>
    public static byte[] Wrap(byte[] plaintextKey, bool requirePresence)
    {
        RequireAvailable();

        var blob = new byte[BlobBufferSize];
        var blobLen = blob.Length;
        var ciphertext = new byte[CiphertextBufferSize];
        var ciphertextLen = ciphertext.Length;

        int rc;
        try
        {
            rc = tswap_se_wrap_v2(plaintextKey, plaintextKey.Length, blob, ref blobLen, ciphertext, ref ciphertextLen,
                requirePresence ? 1 : 0);
        }
        catch (EntryPointNotFoundException ex)
        {
            // An older dylib beside this binary: fail closed, never fall back to tswap_se_wrap.
            throw SecureEnclaveReturnCodes.MissingWrapV2(ex);
        }
        if (rc != 0)
            throw SecureEnclaveReturnCodes.WrapFailure(rc);

        var package = new byte[4 + blobLen + ciphertextLen];
        BinaryPrimitives.WriteInt32LittleEndian(package, blobLen);
        Buffer.BlockCopy(blob, 0, package, 4, blobLen);
        Buffer.BlockCopy(ciphertext, 0, package, 4 + blobLen, ciphertextLen);
        return package;
    }

    /// <summary>Unlock: reconstitutes the Secure Enclave key and decrypts the payload produced by <see cref="Wrap"/>. Prompts for Touch ID or the login password when the key was created with presence required.</summary>
    public static byte[] Unwrap(byte[] wrapped)
    {
        RequireAvailable();

        if (wrapped.Length < 4)
            throw new TswapException("Config is corrupted: the Secure Enclave wrapped key is too short to be valid.");

        var blobLen = BinaryPrimitives.ReadInt32LittleEndian(wrapped);
        // Subtraction, not "4 + blobLen > wrapped.Length": blobLen comes straight off the wire
        // and addition can overflow for a huge value, wrapping to negative and defeating the
        // check. wrapped.Length - 4 can't underflow (already checked wrapped.Length >= 4 above).
        // ">=" (not ">") also requires at least 1 leftover byte for the ciphertext package.
        if (blobLen < 0 || blobLen >= wrapped.Length - 4)
            throw new TswapException("Config is corrupted: the Secure Enclave wrapped key has an invalid length prefix.");

        var blob = new byte[blobLen];
        Buffer.BlockCopy(wrapped, 4, blob, 0, blobLen);
        var ciphertextLen = wrapped.Length - 4 - blobLen;
        var ciphertext = new byte[ciphertextLen];
        Buffer.BlockCopy(wrapped, 4 + blobLen, ciphertext, 0, ciphertextLen);

        var plaintext = new byte[256];
        var plaintextLen = plaintext.Length;
        var rc = tswap_se_unwrap(blob, blob.Length, ciphertext, ciphertext.Length, plaintext, ref plaintextLen);
        if (rc != 0)
            throw SecureEnclaveReturnCodes.UnwrapFailure(rc);

        Array.Resize(ref plaintext, plaintextLen);
        return plaintext;
    }
}
