using System.Security.Cryptography;

namespace TswapCore.Vault;

/// <summary>
/// The answer a slot 2 programmed for HMAC-SHA1 with HMAC_LT64 gives (how Yubico's challenge-response tooling and
/// <c>tswap yubikey setup</c> program it). The key always receives a 64-byte frame; with HMAC_LT64, "whatever is in
/// the last byte of the challenge is used as end of input marker (backtracking from end of payload)" (Yubico,
/// yubikey-personalization <c>ykpersonalize.1.adoc</c>, option <c>hmac-lt64</c>): every trailing byte equal to the
/// frame's last byte is stripped before the HMAC. For tswap's zero-padded challenges that is the zero padding; an
/// all-equal frame leaves no input.
/// </summary>
internal static class Slot2Verify
{
    internal static byte[] ExpectedResponse(ReadOnlySpan<byte> key20, ReadOnlySpan<byte> challenge64)
    {
        if (key20.Length != 20)
            throw new ArgumentException("The slot key is 20 bytes", nameof(key20));
        if (challenge64.Length != 64)
            throw new ArgumentException("The challenge frame is 64 bytes", nameof(challenge64));

        var input = challenge64.TrimEnd(challenge64[^1]);
        return HMACSHA1.HashData(key20, input);
    }
}
