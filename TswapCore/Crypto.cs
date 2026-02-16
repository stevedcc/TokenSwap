using System.Security.Cryptography;
using System.Text;

namespace TswapCore;

public static class Crypto
{
    public static byte[] XorBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("Byte arrays must be same length for XOR");

        return a.Zip(b, (x, y) => (byte)(x ^ y)).ToArray();
    }

    public static byte[] DeriveKey(byte[] k1, byte[] k2)
    {
        var combined = k1.Concat(k2).ToArray();
        var salt = Encoding.UTF8.GetBytes("tswap-poc-v1");

        return Rfc2898DeriveBytes.Pbkdf2(
            combined,
            salt,
            100000,
            HashAlgorithmName.SHA256,
            32
        );
    }

    public static byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        var tagSizeInBytes = AesGcm.TagByteSizes.MaxSize;
        using var aes = new AesGcm(key, tagSizeInBytes);

        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        var tag = new byte[tagSizeInBytes];
        var ciphertext = new byte[plaintext.Length];

        RandomNumberGenerator.Fill(nonce);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return nonce.Concat(tag).Concat(ciphertext).ToArray();
    }

    public static byte[] Decrypt(byte[] encrypted, byte[] key)
    {
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;

        var nonce = encrypted.Take(nonceSize).ToArray();
        var tag = encrypted.Skip(nonceSize).Take(tagSize).ToArray();
        var ciphertext = encrypted.Skip(nonceSize + tagSize).ToArray();

        using var aes = new AesGcm(key, tagSize);

        var plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
