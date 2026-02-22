using System.Security.Cryptography;
using System.Text;
using TswapCore;
using Xunit;

namespace TswapTests;

public class CryptoTests
{
    [Fact]
    public void XorBytes_RoundTrip()
    {
        var a = RandomNumberGenerator.GetBytes(20);
        var b = RandomNumberGenerator.GetBytes(20);

        var xor = Crypto.XorBytes(a, b);
        var recovered = Crypto.XorBytes(xor, b);

        Assert.Equal(a, recovered);
    }

    [Fact]
    public void XorBytes_SelfIsZero()
    {
        var a = new byte[] { 0xAA, 0xBB, 0xCC };
        var result = Crypto.XorBytes(a, a);

        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public void XorBytes_MismatchedLengthThrows()
    {
        Assert.Throws<ArgumentException>(() =>
            Crypto.XorBytes(new byte[3], new byte[5]));
    }

    [Fact]
    public void XorBytes_KnownValues()
    {
        var a = new byte[] { 0xFF, 0x00, 0xAA };
        var b = new byte[] { 0x0F, 0xF0, 0x55 };
        var expected = new byte[] { 0xF0, 0xF0, 0xFF };

        Assert.Equal(expected, Crypto.XorBytes(a, b));
    }

    [Fact]
    public void DeriveKey_Deterministic()
    {
        var k1 = Encoding.UTF8.GetBytes("key-one-padded!!");
        var k2 = Encoding.UTF8.GetBytes("key-two-padded!!");

        var derived1 = Crypto.DeriveKey(k1, k2);
        var derived2 = Crypto.DeriveKey(k1, k2);

        Assert.Equal(derived1, derived2);
    }

    [Fact]
    public void DeriveKey_Returns32Bytes()
    {
        var k1 = new byte[20];
        var k2 = new byte[20];

        var derived = Crypto.DeriveKey(k1, k2);

        Assert.Equal(32, derived.Length);
    }

    [Fact]
    public void DeriveKey_DifferentInputsDifferentOutput()
    {
        var k1a = Encoding.UTF8.GetBytes("aaaaaaaaaaaaaaaaaaa!");
        var k2a = Encoding.UTF8.GetBytes("bbbbbbbbbbbbbbbbbb!!");

        var k1b = Encoding.UTF8.GetBytes("cccccccccccccccccc!!");
        var k2b = Encoding.UTF8.GetBytes("dddddddddddddddddd!!");

        var derived1 = Crypto.DeriveKey(k1a, k2a);
        var derived2 = Crypto.DeriveKey(k1b, k2b);

        Assert.NotEqual(derived1, derived2);
    }

    [Fact]
    public void DeriveKey_OrderMatters()
    {
        var k1 = Encoding.UTF8.GetBytes("first-key-value!!");
        var k2 = Encoding.UTF8.GetBytes("second-key-value!");

        var forward = Crypto.DeriveKey(k1, k2);
        var reversed = Crypto.DeriveKey(k2, k1);

        Assert.NotEqual(forward, reversed);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("hello, world!");

        var encrypted = Crypto.Encrypt(plaintext, key);
        var decrypted = Crypto.Decrypt(encrypted, key);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_EmptyPlaintext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Array.Empty<byte>();

        var encrypted = Crypto.Encrypt(plaintext, key);
        var decrypted = Crypto.Decrypt(encrypted, key);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_LargePayload()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = RandomNumberGenerator.GetBytes(100_000);

        var encrypted = Crypto.Encrypt(plaintext, key);
        var decrypted = Crypto.Decrypt(encrypted, key);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_DifferentNonceEachTime()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("same text");

        var encrypted1 = Crypto.Encrypt(plaintext, key);
        var encrypted2 = Crypto.Encrypt(plaintext, key);

        // Ciphertext should differ due to random nonce
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Decrypt_WrongKeyThrows()
    {
        var key1 = RandomNumberGenerator.GetBytes(32);
        var key2 = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("secret data");

        var encrypted = Crypto.Encrypt(plaintext, key1);

        Assert.ThrowsAny<Exception>(() => Crypto.Decrypt(encrypted, key2));
    }

    [Fact]
    public void Decrypt_TamperedCiphertextThrows()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("secret data");

        var encrypted = Crypto.Encrypt(plaintext, key);

        // Tamper with the last byte of ciphertext
        encrypted[^1] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => Crypto.Decrypt(encrypted, key));
    }

    [Fact]
    public void YubiKeyXorReconstruction_Simulation()
    {
        // Simulate the YubiKey XOR redundancy scheme:
        // Two keys produce HMAC responses. XOR share stored.
        // Either key can reconstruct the other.
        var k1 = RandomNumberGenerator.GetBytes(20); // HMAC-SHA1 = 20 bytes
        var k2 = RandomNumberGenerator.GetBytes(20);

        var xorShare = Crypto.XorBytes(k1, k2);

        // Key 1 present: reconstruct key 2
        var k2_recovered = Crypto.XorBytes(k1, xorShare);
        Assert.Equal(k2, k2_recovered);

        // Key 2 present: reconstruct key 1
        var k1_recovered = Crypto.XorBytes(k2, xorShare);
        Assert.Equal(k1, k1_recovered);

        // Both paths derive the same master key
        var masterFromK1 = Crypto.DeriveKey(k1, k2_recovered);
        var masterFromK2 = Crypto.DeriveKey(k1_recovered, k2);
        Assert.Equal(masterFromK1, masterFromK2);
    }

    // --- DeriveKeyFromPassphrase ---

    [Fact]
    public void DeriveKeyFromPassphrase_Deterministic()
    {
        var salt = RandomNumberGenerator.GetBytes(32);
        var k1 = Crypto.DeriveKeyFromPassphrase("correct-horse-battery-staple", salt);
        var k2 = Crypto.DeriveKeyFromPassphrase("correct-horse-battery-staple", salt);
        Assert.Equal(k1, k2);
    }

    [Fact]
    public void DeriveKeyFromPassphrase_Returns32Bytes()
    {
        var key = Crypto.DeriveKeyFromPassphrase("passphrase", RandomNumberGenerator.GetBytes(32));
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void DeriveKeyFromPassphrase_DifferentSaltsDifferentKeys()
    {
        var salt1 = RandomNumberGenerator.GetBytes(32);
        var salt2 = RandomNumberGenerator.GetBytes(32);
        var k1 = Crypto.DeriveKeyFromPassphrase("same-passphrase", salt1);
        var k2 = Crypto.DeriveKeyFromPassphrase("same-passphrase", salt2);
        Assert.NotEqual(k1, k2);
    }

    [Fact]
    public void DeriveKeyFromPassphrase_DifferentPassphrasesDifferentKeys()
    {
        var salt = RandomNumberGenerator.GetBytes(32);
        var k1 = Crypto.DeriveKeyFromPassphrase("passphrase-one", salt);
        var k2 = Crypto.DeriveKeyFromPassphrase("passphrase-two", salt);
        Assert.NotEqual(k1, k2);
    }

    [Fact]
    public void DeriveKeyFromPassphrase_IndependentOfDeriveKey()
    {
        // Passphrase-derived key must not collide with YubiKey-derived key under same input
        var salt = Encoding.UTF8.GetBytes("tswap-poc-v1"); // same salt as DeriveKey uses
        var hmacBytes = RandomNumberGenerator.GetBytes(20);
        var passphraseKey = Crypto.DeriveKeyFromPassphrase(Encoding.UTF8.GetString(hmacBytes), salt);
        var yubiKey = Crypto.DeriveKey(hmacBytes, hmacBytes);
        Assert.NotEqual(passphraseKey, yubiKey);
    }
}
