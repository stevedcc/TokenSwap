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
internal static class AppleSecureEnclaveInterop
{
    private const string Lib = "libtswapse";

    static AppleSecureEnclaveInterop()
    {
        NativeLibrary.SetDllImportResolver(typeof(AppleSecureEnclaveInterop).Assembly, (name, assembly, searchPath) =>
            name == Lib
                ? NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "libtswapse.dylib"))
                : IntPtr.Zero);
    }

    [DllImport(Lib)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool tswap_se_available();

    [DllImport(Lib)]
    private static extern int tswap_se_wrap(
        byte[] plaintext, int plaintextLen,
        byte[] outBlob, ref int outBlobLen,
        byte[] outCiphertext, ref int outCiphertextLen);

    [DllImport(Lib)]
    private static extern int tswap_se_unwrap(
        byte[] blob, int blobLen,
        byte[] ciphertext, int ciphertextLen,
        byte[] outPlaintext, ref int outPlaintextLen);

    // Generous fixed buffers: a P-256 Secure Enclave key's dataRepresentation is ~430 bytes,
    // and the ECIES package is 65 (ephemeral pubkey) + 12 (nonce) + plaintext + 16 (tag) bytes.
    private const int BlobBufferSize = 2048;
    private const int CiphertextBufferSize = 2048;

    public static bool IsAvailable() => tswap_se_available();

    /// <summary>Enrollment: creates a new Secure Enclave key and ECIES-wraps <paramref name="plaintextKey"/> to it.</summary>
    public static byte[] Wrap(byte[] plaintextKey)
    {
        var blob = new byte[BlobBufferSize];
        var blobLen = blob.Length;
        var ciphertext = new byte[CiphertextBufferSize];
        var ciphertextLen = ciphertext.Length;

        var rc = tswap_se_wrap(plaintextKey, plaintextKey.Length, blob, ref blobLen, ciphertext, ref ciphertextLen);
        if (rc != 0)
            throw new CryptographicOperationException($"tswap_se_wrap failed (code {rc}).");

        var package = new byte[4 + blobLen + ciphertextLen];
        BinaryPrimitives.WriteInt32LittleEndian(package, blobLen);
        Buffer.BlockCopy(blob, 0, package, 4, blobLen);
        Buffer.BlockCopy(ciphertext, 0, package, 4 + blobLen, ciphertextLen);
        return package;
    }

    /// <summary>Unlock: reconstitutes the Secure Enclave key and decrypts the payload produced by <see cref="Wrap"/>. Triggers the Touch ID / presence prompt.</summary>
    public static byte[] Unwrap(byte[] wrapped)
    {
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
            throw new TswapException(
                "Could not unlock with the Secure Enclave. It may have been enrolled on a different Mac, " +
                "or presence/biometry verification failed or was cancelled.");

        Array.Resize(ref plaintext, plaintextLen);
        return plaintext;
    }
}

/// <summary>A Secure Enclave / CryptoKit call failed in a way that isn't a normal user-facing <see cref="TswapException"/>.</summary>
[SupportedOSPlatform("macos")]
public sealed class CryptographicOperationException(string message) : Exception(message);
