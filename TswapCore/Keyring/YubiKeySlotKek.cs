using System.Security.Cryptography;
using TswapCore.Vault;
using TswapCore.VaultPassword;

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
///
/// <para><b>Password slots</b> (brief T17 ruling 3, blob version 2): <c>HKDF-SHA256(ikm: response(20) ||
/// stretched password(32), salt, info: "tswap/yubikey-slot/v2" || slotId)</c> (<see cref="DeriveV2"/>).
/// The KDF, not the key, enforces the password, so whoever holds the plugged-in key can guess it offline
/// at Argon2id's cost.</para>
/// </summary>
public static class YubiKeySlotKek
{
    public const int KekSize = 32;

    /// <summary>The size of an HMAC-SHA1 response.</summary>
    public const int ResponseSize = 20;

    /// <summary>HKDF <c>info</c> prefix; the slot id follows it.</summary>
    public static ReadOnlySpan<byte> InfoPrefix => "tswap/yubikey-slot/v1"u8;

    /// <summary>Brief T17: HKDF <c>info</c> prefix of a password slot (blob version 2); the slot id follows it.</summary>
    public static ReadOnlySpan<byte> InfoPrefixV2 => "tswap/yubikey-slot/v2"u8;

    /// <summary>
    /// Challenges <paramref name="blob"/>'s key with its challenge and derives <c>KEK_slot</c>. The
    /// response bytes are zeroed after use. Throws whatever <paramref name="yubiKeys"/> throws when
    /// the key is not plugged in.
    /// </summary>
    public static byte[] Recover(IYubiKeyService yubiKeys, YubiKeySlotBlob blob, byte[] slotId) =>
        Recover(yubiKeys, blob, slotId, password: null);

    /// <summary>
    /// As above; for a password slot (<see cref="YubiKeySlotBlob.RequiresPassword"/>) it calls
    /// <paramref name="password"/> once, before the challenge, derives with <see cref="DeriveV2"/>, and
    /// disposes what the provider returned in a <c>finally</c>. A password-free slot never calls it. A
    /// password slot without a provider throws <see cref="VaultPasswordUnavailableException"/>.
    /// </summary>
    public static byte[] Recover(IYubiKeyService yubiKeys, YubiKeySlotBlob blob, byte[] slotId, VaultPasswordProvider? password)
    {
        if (!blob.RequiresPassword)
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

        if (password is null)
            throw new VaultPasswordUnavailableException(
                $"YubiKey {blob.Serial}'s slot needs the vault password, and none was supplied.");
        using var stretched = password();
        var passwordResponse = yubiKeys.Challenge(blob.Serial, blob.ChallengeString);
        try
        {
            return DeriveV2(passwordResponse, stretched, blob.Salt, slotId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordResponse);
        }
    }

    /// <summary>The HKDF step alone, for a response already in hand.</summary>
    public static byte[] Derive(byte[] response, byte[] salt, byte[] slotId)
    {
        ValidateInputs(response, salt, slotId);

        var info = new byte[InfoPrefix.Length + slotId.Length];
        InfoPrefix.CopyTo(info);
        slotId.CopyTo(info.AsSpan(InfoPrefix.Length));
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, response, KekSize, salt, info);
    }

    /// <summary>
    /// Brief T17: a password slot's <c>KEK_slot</c>, <c>HKDF-SHA256(ikm = response(20) || stretched(32),
    /// salt, info = "tswap/yubikey-slot/v2" || slotId, 32)</c>. The concatenated input is zeroed after use.
    /// </summary>
    public static byte[] DeriveV2(byte[] response, StretchedPassword stretched, byte[] salt, byte[] slotId)
    {
        ValidateInputs(response, salt, slotId);

        var info = new byte[InfoPrefixV2.Length + slotId.Length];
        InfoPrefixV2.CopyTo(info);
        slotId.CopyTo(info.AsSpan(InfoPrefixV2.Length));
        var ikm = new byte[ResponseSize + StretchedPassword.Size];
        try
        {
            response.CopyTo(ikm, 0);
            stretched.CopyTo(ikm.AsSpan(ResponseSize));
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KekSize, salt, info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    private static void ValidateInputs(byte[] response, byte[] salt, byte[] slotId)
    {
        if (response.Length != ResponseSize)
            throw new TswapException(
                $"The YubiKey returned a {response.Length}-byte response; expected {ResponseSize} bytes (HMAC-SHA1). " +
                "Check that slot 2 is configured for HMAC-SHA1 challenge-response.");
        if (salt.Length != YubiKeySlotBlob.SaltSize)
            throw new ArgumentException($"The salt must be {YubiKeySlotBlob.SaltSize} bytes", nameof(salt));
        if (slotId.Length != KeyringFormat.SlotIdSize)
            throw new ArgumentException($"The slot id must be {KeyringFormat.SlotIdSize} bytes", nameof(slotId));
    }
}
