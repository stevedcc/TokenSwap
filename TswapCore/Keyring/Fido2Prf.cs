using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// The WebAuthn PRF salt transform (PRF transform version 1, <see cref="Fido2SlotBlob.PrfVersion"/>):
/// <c>SHA-256(UTF-8("WebAuthn PRF") || 0x00 || input)</c>. The result is the hmac-secret salt sent to the key.
/// Windows' <c>webauthn.dll</c> applies the same transform to a PRF input itself, so every path sends the key
/// the same salt for a slot and gets the same output back.
/// </summary>
public static class Fido2Prf
{
    /// <summary>The size of the salt (a SHA-256 digest).</summary>
    public const int SaltSize = 32;

    private static ReadOnlySpan<byte> Label => "WebAuthn PRF"u8;

    /// <summary>The hmac-secret salt for <paramref name="input"/> (a slot's <see cref="Fido2SlotBlob.PrfInput"/>).</summary>
    public static byte[] Salt(ReadOnlySpan<byte> input)
    {
        var buffer = new byte[Label.Length + 1 + input.Length];
        Label.CopyTo(buffer);
        input.CopyTo(buffer.AsSpan(Label.Length + 1));
        return SHA256.HashData(buffer);
    }
}
