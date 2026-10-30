namespace TswapCore.Vault.Interop;

/// <summary>
/// What each return code of <c>libtswapse.dylib</c> means, one message per code (brief T11
/// decision 3). Plain C#, no platform attribute, so the messages are tested on every OS;
/// <see cref="AppleSecureEnclaveInterop"/> throws what this returns.
/// </summary>
internal static class SecureEnclaveReturnCodes
{
    /// <summary><c>tswap_se_wrap_v2</c>: a <c>requirePresence</c> other than 0 or 1; no key was created.</summary>
    public const int WrapInvalidPresence = -4;

    /// <summary><c>tswap_se_wrap_v2</c>: <c>SecAccessControlCreateWithFlags</c> returned nil; no key was created.</summary>
    public const int WrapAccessControlFailed = -5;

    private const string UpdateTogether = "update libtswapse.dylib together with tswap";

    /// <summary>The exception for a non-zero return code of <c>tswap_se_wrap_v2</c>.</summary>
    public static Exception WrapFailure(int code) => code switch
    {
        -1 => new CryptographicOperationException(
            "tswap_se_wrap_v2: the Secure Enclave key or wrapped ciphertext exceeded tswap's internal buffer size — " +
            "this is a tswap bug, not a config problem. No key was enrolled."),
        WrapInvalidPresence => new TswapException(
            "libtswapse.dylib rejected the presence choice tswap passed (code -4) and created no key. tswap and " +
            $"libtswapse.dylib beside it are from different builds: {UpdateTogether}."),
        WrapAccessControlFailed => new CryptographicOperationException(
            "The Secure Enclave key's access control could not be created (code -5), so no key was created."),
        _ => new CryptographicOperationException(
            $"tswap_se_wrap_v2 failed (code {code}); the Secure Enclave reported available but creating or wrapping " +
            "the key still failed. No key was enrolled."),
    };

    /// <summary>
    /// The exception for a <c>libtswapse.dylib</c> without <c>tswap_se_wrap_v2</c>: an older dylib
    /// beside a newer tswap. Fails closed: the old entry point is never called as a fallback.
    /// </summary>
    public static Exception MissingWrapV2(EntryPointNotFoundException cause) => new TswapException(
        "libtswapse.dylib beside tswap is older than tswap (it has no tswap_se_wrap_v2). " +
        $"No key was created: {UpdateTogether} (re-run 'tswap installscript', review it, then run the script). " +
        $"({cause.Message})");

    /// <summary>The exception for a non-zero return code of <c>tswap_se_unwrap</c>.</summary>
    public static Exception UnwrapFailure(int code) => code switch
    {
        // The three failure codes are genuinely different situations: collapsing them into one
        // message would hide config corruption and internal bugs behind "wrong machine or cancelled".
        -1 => new CryptographicOperationException(
            "tswap_se_unwrap: the decrypted value exceeded tswap's internal buffer size — this is a tswap bug, not a config problem."),
        -3 => new TswapException("Config is corrupted: the Secure Enclave ciphertext package is malformed."),
        // True for both postures (brief T11 decision 7): a no-touch key never prompts.
        _ => new TswapException(
            "Could not unlock with the Secure Enclave. It may have been enrolled on a different Mac, or, " +
            "if this Mac's slot requires Touch ID or a password, the verification failed or was cancelled."),
    };
}

/// <summary>
/// A Secure Enclave / CryptoKit call failed in a way that isn't a normal user-facing
/// <see cref="TswapException"/>. A plain exception (no platform attribute), so the messages in
/// <see cref="SecureEnclaveReturnCodes"/> are testable everywhere.
/// </summary>
internal sealed class CryptographicOperationException(string message) : Exception(message);
