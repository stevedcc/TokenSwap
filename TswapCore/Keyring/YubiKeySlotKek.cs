using System.Security.Cryptography;
using TswapCore.Vault;

namespace TswapCore.Keyring;

/// <summary>
/// <c>KEK_slot</c> for a one-key YubiKey slot (brief T4 decision 1, issue #184):
/// <c>HKDF-SHA256(ikm: the key's HMAC-SHA1 response to the slot's challenge, salt: the slot's
/// salt, info: "tswap/yubikey-slot/v1" || slotId)</c>, 32 bytes.
///
/// <para><b>HKDF, not PBKDF2:</b> the response is a uniformly random 160-bit MAC under a secret
/// that never leaves the key, so stretching adds nothing. The slot id in <c>info</c> binds the
/// key to this slot: two slots of the same key never share a <c>KEK_slot</c>, even with equal
/// challenges and salts.</para>
/// </summary>
public static class YubiKeySlotKek
{
    public const int KekSize = 32;

    /// <summary>The size of an HMAC-SHA1 response.</summary>
    public const int ResponseSize = 20;

    /// <summary>HKDF <c>info</c> prefix; the slot id follows it.</summary>
    public static ReadOnlySpan<byte> InfoPrefix => "tswap/yubikey-slot/v1"u8;

    /// <summary>
    /// Challenges <paramref name="blob"/>'s key with its challenge and derives <c>KEK_slot</c>. The
    /// response bytes are zeroed after use. Throws whatever <paramref name="yubiKeys"/> throws when
    /// the key is not plugged in.
    /// </summary>
    public static byte[] Recover(IYubiKeyService yubiKeys, YubiKeySlotBlob blob, byte[] slotId)
    {
        var response = yubiKeys.Challenge(blob.Serial, blob.ChallengeString);
        try
        {
            return Derive(response, blob.Salt, slotId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(response);
        }
    }

    /// <summary>The HKDF step alone, for a response already in hand.</summary>
    public static byte[] Derive(byte[] response, byte[] salt, byte[] slotId)
    {
        if (response.Length != ResponseSize)
            throw new TswapException(
                $"The YubiKey returned a {response.Length}-byte response; expected {ResponseSize} bytes (HMAC-SHA1). " +
                "Check that slot 2 is configured for HMAC-SHA1 challenge-response.");
        if (salt.Length != YubiKeySlotBlob.SaltSize)
            throw new ArgumentException($"The salt must be {YubiKeySlotBlob.SaltSize} bytes", nameof(salt));
        if (slotId.Length != KeyringFormat.SlotIdSize)
            throw new ArgumentException($"The slot id must be {KeyringFormat.SlotIdSize} bytes", nameof(slotId));

        var info = new byte[InfoPrefix.Length + slotId.Length];
        InfoPrefix.CopyTo(info);
        slotId.CopyTo(info.AsSpan(InfoPrefix.Length));
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, response, KekSize, salt, info);
    }
}
