using System.Security.Cryptography;
using System.Text;

namespace TswapCore;

public static class Crypto
{
    /// <summary>PBKDF2-SHA256 iteration count for both master-key and export-key derivation.</summary>
    public const int Pbkdf2Iterations = 100_000;

    // Fixed salt for master-key derivation. The "poc" name predates the project rename
    // and must not change: existing vaults are encrypted with keys derived from it.
    private static readonly byte[] MasterKeySalt = Encoding.UTF8.GetBytes("tswap-poc-v1");

    public static byte[] XorBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("Byte arrays must be same length for XOR");

        var result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }

    public static byte[] DeriveKey(byte[] k1, byte[] k2)
    {
        var combined = new byte[k1.Length + k2.Length];
        k1.CopyTo(combined, 0);
        k2.CopyTo(combined, k1.Length);

        return Rfc2898DeriveBytes.Pbkdf2(
            combined,
            MasterKeySalt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            32
        );
    }

    public static byte[] DeriveKeyFromPassphrase(string passphrase, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passphrase),
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            32
        );
    }

    // Encrypted payload layout: nonce | tag | ciphertext (all max-size for AES-GCM).
    public static byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;
        using var aes = new AesGcm(key, tagSize);

        var result = new byte[nonceSize + tagSize + plaintext.Length];
        var nonce = result.AsSpan(0, nonceSize);
        var tag = result.AsSpan(nonceSize, tagSize);
        var ciphertext = result.AsSpan(nonceSize + tagSize);

        RandomNumberGenerator.Fill(nonce);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return result;
    }

    public static byte[] Decrypt(byte[] encrypted, byte[] key)
    {
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;

        var nonce = encrypted.AsSpan(0, nonceSize);
        var tag = encrypted.AsSpan(nonceSize, tagSize);
        var ciphertext = encrypted.AsSpan(nonceSize + tagSize);

        using var aes = new AesGcm(key, tagSize);
        var plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
