using System.Security.Cryptography;

namespace YkSpike;

/// <summary>The WebAuthn PRF salt transform, which Windows' webauthn.dll applies to a PRF input before hmac-secret.</summary>
public static class Prf
{
    private static ReadOnlySpan<byte> Label => "WebAuthn PRF"u8;

    /// <summary>SHA-256(UTF8("WebAuthn PRF") || 0x00 || input).</summary>
    public static byte[] Salt(ReadOnlySpan<byte> input)
    {
        var buffer = new byte[Label.Length + 1 + input.Length];
        Label.CopyTo(buffer);
        input.CopyTo(buffer.AsSpan(Label.Length + 1));
        return SHA256.HashData(buffer);
    }
}
