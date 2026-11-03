using TswapCore.VaultPassword;

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
    /// <summary>Brief T17 (ruling 19): <c>tswap_se_wrap_v3</c> / <c>tswap_se_unwrap_v2</c> were given a credential that is not 32 bytes; the Enclave was not touched.</summary>
    public const int CredentialLength = -6;

    /// <summary>Brief T17: key agreement failed with a credential supplied: a wrong vault password, or a blob from another Mac.</summary>
    public const int WrongCredential = -7;

    /// <summary>Brief T17: an <c>LAError</c> (presence cancelled or failed, or interaction needed but not allowed).</summary>
    public const int AuthenticationFailed = -8;

    private static TswapException CredentialLengthRefused(string entryPoint) => new(
        $"libtswapse.dylib refused the vault password credential tswap passed to {entryPoint} (code -6: not 32 bytes). " +
        $"tswap and libtswapse.dylib beside it are from different builds: {UpdateTogether}.");

    /// <summary>The exception for a non-zero return code of <c>tswap_se_wrap_v3</c> (brief T17); the v2 codes keep their messages.</summary>
    public static Exception WrapV3Failure(int code) => code switch
    {
        CredentialLength => CredentialLengthRefused("tswap_se_wrap_v3"),
        AuthenticationFailed => new TswapException(
            "The Secure Enclave key could not be created: Touch ID or the login password was cancelled or failed (code -8). No key was enrolled."),
        _ => WrapFailure(code),
    };

    /// <summary>The exception for a non-zero return code of <c>tswap_se_unwrap_v2</c> (brief T17); <c>-1</c> to <c>-3</c> keep their messages.</summary>
    public static Exception UnwrapV2Failure(int code) => code switch
    {
        CredentialLength => CredentialLengthRefused("tswap_se_unwrap_v2"),
        // Ruling 18: no lockout sentence, the spike showed no Enclave rate limit.
        WrongCredential => new VaultPasswordRefusedException(VaultPasswordMessages.WrongPasswordSecureEnclave),
        AuthenticationFailed => new TswapException(
            "Could not unlock with the Secure Enclave: this slot also needs Touch ID or the login password, and that " +
            "was cancelled, failed, or could not be asked for (code -8)."),
        _ => UnwrapFailure(code),
    };

    /// <summary>Brief T17: a dylib without <c>tswap_se_wrap_v3</c> beside a newer tswap. Fails closed, as <see cref="MissingWrapV2"/>.</summary>
    public static Exception MissingWrapV3(EntryPointNotFoundException cause) => new TswapException(
        "libtswapse.dylib beside tswap is older than tswap (it has no tswap_se_wrap_v3, needed for a vault password slot). " +
        $"No key was created: {UpdateTogether} (re-run 'tswap installscript', review it, then run the script). " +
        $"({cause.Message})");

    /// <summary>Brief T17: a dylib without <c>tswap_se_unwrap_v2</c> beside a newer tswap. Fails closed: the old unwrap is never tried instead.</summary>
    public static Exception MissingUnwrapV2(EntryPointNotFoundException cause) => new TswapException(
        "libtswapse.dylib beside tswap is older than tswap (it has no tswap_se_unwrap_v2, needed for a vault password slot): " +
        $"{UpdateTogether} (re-run 'tswap installscript', review it, then run the script). ({cause.Message})");
}

/// <summary>
/// A Secure Enclave / CryptoKit call failed in a way that isn't a normal user-facing
/// <see cref="TswapException"/>. A plain exception (no platform attribute), so the messages in
/// <see cref="SecureEnclaveReturnCodes"/> are testable everywhere.
/// </summary>
internal sealed class CryptographicOperationException(string message) : Exception(message);
