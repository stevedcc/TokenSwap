namespace TswapCore.Vault.Interop;

/// <summary>
/// The C ABI of <c>libtswapse.dylib</c> (<c>swift/TswapSecureEnclave.swift</c>), one method per exported
/// entry point with the same parameters. The real one calls the dylib; tests put a fake behind it
/// (flow-local, <c>AppleSecureEnclaveInterop.UseShim</c>) so the interop's own logic (which entry point,
/// what credential, which return-code text) runs on every OS (brief T17 task 13). Plain C#, no platform
/// attribute.
/// </summary>
internal interface ISecureEnclaveShim
{
    /// <summary><c>tswap_se_available</c>.</summary>
    bool Available();

    /// <summary><c>tswap_se_wrap_v2</c>: every password-free enrolment (brief T11).</summary>
    int WrapV2(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen,
        byte[] outCiphertext, ref int outCiphertextLen, int requirePresence);

    /// <summary><c>tswap_se_wrap_v3</c> (brief T17): a key made with <c>.applicationPassword</c> and the credential.</summary>
    int WrapV3(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen,
        byte[] outCiphertext, ref int outCiphertextLen, int requirePresence, byte[] credential, int credentialLen);

    /// <summary><c>tswap_se_unwrap</c>: every password-free unlock.</summary>
    int Unwrap(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] outPlaintext, ref int outPlaintextLen);

    /// <summary><c>tswap_se_unwrap_v2</c> (brief T17): unwrap under a context carrying the credential.</summary>
    int UnwrapV2(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] credential, int credentialLen,
        byte[] outPlaintext, ref int outPlaintextLen);
}
