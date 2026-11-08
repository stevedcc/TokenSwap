using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.VaultPassword;

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
                    "Keep libtswapse.dylib in the same folder as tswap: the macOS release archive has both, " +
                    "so unpack all of it. Or run 'tswap installscript', review it, then run the generated " +
                    "script, which installs this file alongside the binary.");

            try
            {
                return NativeLibrary.Load(dylibPath);
            }
            catch (DllNotFoundException ex)
            {
                // The file is there but dyld refused it: with the hardened runtime (signed releases from v0.3.0),
                // library validation refuses a dylib of another build, e.g. "different Team IDs".
                throw new TswapException(LoadFailureMessage(dylibPath, ex.Message));
            }
        });
    }

    /// <summary>The message for a <c>libtswapse.dylib</c> that exists but won't load: dyld's reason, then what to do.</summary>
    internal static string LoadFailureMessage(string dylibPath, string reason) =>
        $"tswap's Secure Enclave support library {dylibPath} could not be loaded: {reason.TrimEnd('.', ' ')}. " +
        "tswap and libtswapse.dylib must come from the same release (from v0.3.0 they are signed together): " +
        "reinstall the package, or replace both from one archive.";

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

    /// <summary>
    /// T17 fix round 2: <see cref="tswap_se_unwrap"/> with the key restored under a context that allows no
    /// interaction (<c>interactionNotAllowed</c>), for a slot recorded as made without presence. Same parameters.
    /// </summary>
    [LibraryImport(Lib)]
    private static partial int tswap_se_unwrap_no_interaction(
        byte[] blob, int blobLen,
        byte[] ciphertext, int ciphertextLen,
        byte[] outPlaintext, ref int outPlaintextLen);

    /// <summary>
    /// Brief T17 (ruling 19): <see cref="tswap_se_wrap_v2"/> for a vault password slot. The key is created with
    /// <c>.applicationPassword</c> added to its flags, under a context carrying <paramref name="credential"/> (the
    /// 32 stretched bytes) through <c>LAContext.setCredential</c>. A new entry point, so an old dylib fails closed.
    /// Returns -6 for a credential that is not 32 bytes, before touching the Enclave.
    /// </summary>
    [LibraryImport(Lib)]
    private static partial int tswap_se_wrap_v3(
        byte[] plaintext, int plaintextLen,
        byte[] outBlob, ref int outBlobLen,
        byte[] outCiphertext, ref int outCiphertextLen,
        int requirePresence,
        byte[] credential, int credentialLen);

    /// <summary>
    /// Brief T17 (ruling 19): <see cref="tswap_se_unwrap"/> under a fresh context carrying the credential.
    /// -6: not 32 bytes; -7: key agreement failed with the credential (wrong password, or another Mac's blob);
    /// -8: an <c>LAError</c>.
    /// </summary>
    [LibraryImport(Lib)]
    private static partial int tswap_se_unwrap_v2(
        byte[] blob, int blobLen,
        byte[] ciphertext, int ciphertextLen,
        byte[] credential, int credentialLen,
        byte[] outPlaintext, ref int outPlaintextLen);

    /// <summary>The dylib itself.</summary>
    private sealed class NativeShim : ISecureEnclaveShim
    {
        public static NativeShim Instance { get; } = new();

        public bool Available() => tswap_se_available();

        public int WrapV2(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen,
            byte[] outCiphertext, ref int outCiphertextLen, int requirePresence) =>
            tswap_se_wrap_v2(plaintext, plaintextLen, outBlob, ref outBlobLen, outCiphertext, ref outCiphertextLen, requirePresence);

        public int WrapV3(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen,
            byte[] outCiphertext, ref int outCiphertextLen, int requirePresence, byte[] credential, int credentialLen) =>
            tswap_se_wrap_v3(plaintext, plaintextLen, outBlob, ref outBlobLen, outCiphertext, ref outCiphertextLen,
                requirePresence, credential, credentialLen);

        public int Unwrap(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] outPlaintext, ref int outPlaintextLen) =>
            tswap_se_unwrap(blob, blobLen, ciphertext, ciphertextLen, outPlaintext, ref outPlaintextLen);

        public int UnwrapNoInteraction(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] outPlaintext, ref int outPlaintextLen) =>
            tswap_se_unwrap_no_interaction(blob, blobLen, ciphertext, ciphertextLen, outPlaintext, ref outPlaintextLen);

        public int UnwrapV2(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] credential, int credentialLen,
            byte[] outPlaintext, ref int outPlaintextLen) =>
            tswap_se_unwrap_v2(blob, blobLen, ciphertext, ciphertextLen, credential, credentialLen, outPlaintext, ref outPlaintextLen);
    }

    private static readonly AsyncLocal<ISecureEnclaveShim?> ShimOverride = new();

    /// <summary>
    /// Test seam (brief T17 task 13): until the result is disposed, calls made in the caller's async flow go to
    /// <paramref name="shim"/> instead of the dylib. Flow-local, so parallel tests don't see each other.
    /// </summary>
    internal static IDisposable UseShim(ISecureEnclaveShim shim)
    {
        var previous = ShimOverride.Value;
        ShimOverride.Value = shim;
        return new ShimScope(previous);
    }

    private sealed class ShimScope(ISecureEnclaveShim? previous) : IDisposable
    {
        public void Dispose() => ShimOverride.Value = previous;
    }

    private static ISecureEnclaveShim Shim => ShimOverride.Value ?? NativeShim.Instance;

    // Generous fixed buffers: a P-256 Secure Enclave key's dataRepresentation is ~430 bytes,
    // and the ECIES package is 65 (ephemeral pubkey) + 12 (nonce) + plaintext + 16 (tag) bytes.
    private const int BlobBufferSize = 2048;
    private const int CiphertextBufferSize = 2048;

    public static bool IsAvailable() => Shim.Available();

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
            rc = Shim.WrapV2(plaintextKey, plaintextKey.Length, blob, ref blobLen, ciphertext, ref ciphertextLen,
                requirePresence ? 1 : 0);
        }
        catch (EntryPointNotFoundException ex)
        {
            // An older dylib beside this binary: fail closed, never fall back to tswap_se_wrap.
            throw SecureEnclaveReturnCodes.MissingWrapV2(ex);
        }
        if (rc != 0)
            throw SecureEnclaveReturnCodes.WrapFailure(rc);

        return Package(blob, blobLen, ciphertext, ciphertextLen);
    }

    /// <summary>
    /// Brief T17 task 13: as <see cref="Wrap"/>, but the key is created with <c>.applicationPassword</c> and the
    /// stretched vault password as its credential, so the Enclave refuses to use it without those 32 bytes
    /// (ruling 19). The package layout is unchanged; the caller adds the <c>TSSE</c> header.
    /// </summary>
    public static byte[] WrapWithPassword(byte[] plaintextKey, bool requirePresence, StretchedPassword password)
    {
        RequireAvailable();

        var blob = new byte[BlobBufferSize];
        var blobLen = blob.Length;
        var ciphertext = new byte[CiphertextBufferSize];
        var ciphertextLen = ciphertext.Length;
        var credential = new byte[StretchedPassword.Size];

        int rc;
        try
        {
            password.CopyTo(credential);
            rc = Shim.WrapV3(plaintextKey, plaintextKey.Length, blob, ref blobLen, ciphertext, ref ciphertextLen,
                requirePresence ? 1 : 0, credential, credential.Length);
        }
        catch (EntryPointNotFoundException ex)
        {
            // An older dylib: fail closed, never make a password-free key instead.
            throw SecureEnclaveReturnCodes.MissingWrapV3(ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credential);
        }
        if (rc != 0)
            throw SecureEnclaveReturnCodes.WrapV3Failure(rc);

        return Package(blob, blobLen, ciphertext, ciphertextLen);
    }

    private static byte[] Package(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen)
    {
        var package = new byte[4 + blobLen + ciphertextLen];
        BinaryPrimitives.WriteInt32LittleEndian(package, blobLen);
        Buffer.BlockCopy(blob, 0, package, 4, blobLen);
        Buffer.BlockCopy(ciphertext, 0, package, 4 + blobLen, ciphertextLen);
        return package;
    }

    /// <summary>
    /// Unlock: reconstitutes the Secure Enclave key and decrypts the payload produced by <see cref="Wrap"/>.
    /// Prompts for Touch ID or the login password when the key was created with presence required.
    /// </summary>
    /// <remarks>
    /// Brief T17, the controller's ruling for ruling 3: a password slot whose <c>TSSE</c> header was stripped
    /// lands here, in the old <c>tswap_se_unwrap</c> (Goal 4 keeps it byte for byte), which passes no credential.
    /// The Enclave still refuses the key, and the user gets today's generic text, not the stripped-header text
    /// (the shim's <c>-8</c> exists only on <c>tswap_se_unwrap_v2</c>). The TPM and YubiKey stripped cases are
    /// unaffected.
    /// </remarks>
    public static byte[] Unwrap(byte[] wrapped)
    {
        var (blob, ciphertext) = SplitPackage(wrapped);

        var plaintext = new byte[256];
        var plaintextLen = plaintext.Length;
        var rc = Shim.Unwrap(blob, blob.Length, ciphertext, ciphertext.Length, plaintext, ref plaintextLen);
        if (rc != 0)
            throw SecureEnclaveReturnCodes.UnwrapFailure(rc);

        // A copy of the key's length; the full buffer (holding the key too) is zeroed, not left to the GC.
        var key = plaintext.AsSpan(0, plaintextLen).ToArray();
        CryptographicOperations.ZeroMemory(plaintext);
        return key;
    }

    /// <summary>
    /// T17 fix round 2: <see cref="Unwrap"/> for a slot recorded as made without presence
    /// (<see cref="Config.RequiresTouch"/> false), through <c>tswap_se_unwrap_no_interaction</c>: no dialog can
    /// appear, so a key that would need one fails at once with today's generic text instead of waiting. That is a
    /// password slot whose <c>TSSE</c> header was stripped (its key wants the application password, which only the
    /// header's path supplies; the controller's ruling: fail fast, not wait). A key made without presence opens
    /// as before. An older dylib without the entry point fails closed: the interactive unwrap is never tried instead.
    /// </summary>
    public static byte[] UnwrapWithoutInteraction(byte[] wrapped)
    {
        var (blob, ciphertext) = SplitPackage(wrapped);

        var plaintext = new byte[256];
        var plaintextLen = plaintext.Length;
        int rc;
        try
        {
            rc = Shim.UnwrapNoInteraction(blob, blob.Length, ciphertext, ciphertext.Length, plaintext, ref plaintextLen);
        }
        catch (EntryPointNotFoundException ex)
        {
            throw SecureEnclaveReturnCodes.MissingUnwrapNoInteraction(ex);
        }
        if (rc != 0)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw SecureEnclaveReturnCodes.UnwrapFailure(rc); // -8 (interaction needed) gets the generic text too
        }

        // A copy of the key's length; the full buffer (holding the key too) is zeroed, not left to the GC.
        var key = plaintext.AsSpan(0, plaintextLen).ToArray();
        CryptographicOperations.ZeroMemory(plaintext);
        return key;
    }

    /// <summary>
    /// Brief T17 task 13: unwraps a password slot's package (its <c>TSSE</c> header removed) with the stretched
    /// vault password as the key's credential, through <c>tswap_se_unwrap_v2</c> only.
    /// </summary>
    public static byte[] UnwrapWithPassword(byte[] wrapped, StretchedPassword password)
    {
        var (blob, ciphertext) = SplitPackage(wrapped);

        var plaintext = new byte[256];
        var plaintextLen = plaintext.Length;
        var credential = new byte[StretchedPassword.Size];
        int rc;
        try
        {
            password.CopyTo(credential);
            rc = Shim.UnwrapV2(blob, blob.Length, ciphertext, ciphertext.Length, credential, credential.Length,
                plaintext, ref plaintextLen);
        }
        catch (EntryPointNotFoundException ex)
        {
            // An older dylib: fail closed, never try the credential-less unwrap instead.
            throw SecureEnclaveReturnCodes.MissingUnwrapV2(ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credential);
        }
        if (rc != 0)
            throw SecureEnclaveReturnCodes.UnwrapV2Failure(rc);

        // A copy of the key's length; the full buffer (holding the key too) is zeroed, not left to the GC.
        var key = plaintext.AsSpan(0, plaintextLen).ToArray();
        CryptographicOperations.ZeroMemory(plaintext);
        return key;
    }

    /// <summary>
    /// Test seam (brief T17 task 13): <c>tswap_se_unwrap_v2</c>'s return code for an arbitrary
    /// <paramref name="credential"/>, so CI can pin that a credential of the wrong length is refused (-6)
    /// without the Enclave. Not used by tswap itself.
    /// </summary>
    internal static int UnwrapV2ReturnCode(byte[] wrapped, byte[] credential)
    {
        var (blob, ciphertext) = SplitPackage(wrapped);
        var plaintext = new byte[256];
        var plaintextLen = plaintext.Length;
        var rc = Shim.UnwrapV2(blob, blob.Length, ciphertext, ciphertext.Length, credential, credential.Length, plaintext, ref plaintextLen);
        CryptographicOperations.ZeroMemory(plaintext);
        return rc;
    }

    /// <summary>The key's <c>dataRepresentation</c> and the ECIES package, from today's 4-byte length-prefixed layout.</summary>
    private static (byte[] Blob, byte[] Ciphertext) SplitPackage(byte[] wrapped)
    {
        // Ruling 3: an unsplit password blob ("TSSE" read as a length is huge) is not "corrupted": the caller
        // handed the legacy parser a password slot's blob.
        if (SecureEnclaveSlotBlob.HasHeader(wrapped))
            throw new TswapException(VaultPasswordMessages.LegacyParserNeedsNewerTswap(wrapped.Length > 4 ? wrapped[4] : 0));

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
        return (blob, ciphertext);
    }
}
