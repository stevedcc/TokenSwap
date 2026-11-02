using System.Security.Cryptography;
using System.Text;

namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T16-S1: computes the <see cref="FingerprintSet"/> of a value version.
/// </summary>
public static class Fingerprinter
{
    /// <summary>
    /// The fingerprints of <paramref name="valueBytes"/>. The bytes are decoded with
    /// <see cref="Encoding.UTF8"/> exactly as the record store turns them into the string redaction
    /// matches (invalid sequences become U+FFFD), so a binary value is fingerprinted as the string
    /// <c>redact</c> and <c>run</c> see today, and redaction behaviour can't change.
    /// </summary>
    public static FingerprintSet Compute(byte[] valueBytes, FingerprintKeys keys)
    {
        var value = Encoding.UTF8.GetString(valueBytes);
        var variants = SecretVariants.For(value);
        var entries = new FingerprintEntry[variants.Count];
        for (var i = 0; i < variants.Count; i++)
        {
            var (kind, text) = variants[i];
            entries[i] = new FingerprintEntry(kind, text.Length, RollingHash.Of(text, keys.RollingBase), Hmac(text, keys));
        }
        return new FingerprintSet(SecretVariants.CurrentSetVersion, entries);
    }

    /// <summary>The first 16 bytes of <c>HMAC-SHA256(K_fp, UTF-8(text))</c>; the encoded text is zeroed.</summary>
    internal static byte[] Hmac(ReadOnlySpan<char> text, FingerprintKeys keys)
    {
        var bytes = new byte[Encoding.UTF8.GetMaxByteCount(text.Length)];
        Span<byte> mac = stackalloc byte[HMACSHA256.HashSizeInBytes];
        try
        {
            var count = Encoding.UTF8.GetBytes(text, bytes);
            HMACSHA256.HashData(keys.FingerprintKey, bytes.AsSpan(0, count), mac);
            return mac[..FingerprintEntry.HmacLength].ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(mac);
        }
    }
}
