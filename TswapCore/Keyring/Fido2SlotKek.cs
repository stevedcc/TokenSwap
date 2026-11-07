using System.Security.Cryptography;
using TswapCore.VaultPassword;

namespace TswapCore.Keyring;

/// <summary>
/// <c>KEK_slot</c> for a FIDO2 hmac-secret slot (<see cref="Fido2SlotBlob"/>):
/// <c>HKDF-SHA256(ikm: the key's 32-byte hmac-secret output, salt: the slot's PRF input, info:
/// "tswap/fido2-slot/v1" || slotId)</c>, 32 bytes (<see cref="Derive"/>); a password slot mixes in the
/// stretched vault password, <c>ikm = output(32) || stretched(32)</c> under <c>"tswap/fido2-slot/v2"</c>
/// (<see cref="DeriveV2"/>).
///
/// <para>As with <see cref="YubiKeySlotKek"/>: HKDF, not PBKDF2, because the output is a uniformly random MAC
/// under a secret that never leaves the key; the slot id in <c>info</c> binds the KEK to the slot. The caller
/// zeroes the output after derivation; <see cref="DeriveV2"/> zeroes the input it builds.</para>
/// </summary>
public static class Fido2SlotKek
{
    /// <summary>The size of an hmac-secret output (one salt, HMAC-SHA-256).</summary>
    public const int OutputSize = 32;

    public const int KekSize = 32;

    /// <summary>HKDF <c>info</c> prefix of a password-free slot; the slot id follows it.</summary>
    public static ReadOnlySpan<byte> InfoPrefix => "tswap/fido2-slot/v1"u8;

    /// <summary>HKDF <c>info</c> prefix of a password slot; the slot id follows it.</summary>
    public static ReadOnlySpan<byte> InfoPrefixV2 => "tswap/fido2-slot/v2"u8;

    /// <summary>A password-free slot's <c>KEK_slot</c> from the key's output.</summary>
    public static byte[] Derive(byte[] output, byte[] salt, byte[] slotId)
    {
        ValidateInputs(output, salt, slotId);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, output, KekSize, salt, Info(InfoPrefix, slotId));
    }

    /// <summary>
    /// A password slot's <c>KEK_slot</c>, <c>HKDF-SHA256(ikm = output(32) || stretched(32), salt,
    /// info = "tswap/fido2-slot/v2" || slotId, 32)</c>. The concatenated input is zeroed after use.
    /// </summary>
    public static byte[] DeriveV2(byte[] output, StretchedPassword stretched, byte[] salt, byte[] slotId)
    {
        ValidateInputs(output, salt, slotId);
        var ikm = new byte[OutputSize + StretchedPassword.Size];
        try
        {
            output.CopyTo(ikm, 0);
            stretched.CopyTo(ikm.AsSpan(OutputSize));
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KekSize, salt, Info(InfoPrefixV2, slotId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    private static byte[] Info(ReadOnlySpan<byte> prefix, byte[] slotId)
    {
        var info = new byte[prefix.Length + slotId.Length];
        prefix.CopyTo(info);
        slotId.CopyTo(info.AsSpan(prefix.Length));
        return info;
    }

    private static void ValidateInputs(byte[] output, byte[] salt, byte[] slotId)
    {
        if (output.Length != OutputSize)
            throw new TswapException(
                $"The FIDO2 key returned a {output.Length}-byte hmac-secret output; expected {OutputSize} bytes.");
        if (salt.Length != Fido2SlotBlob.PrfInputSize)
            throw new ArgumentException($"The salt must be {Fido2SlotBlob.PrfInputSize} bytes", nameof(salt));
        if (slotId.Length != KeyringFormat.SlotIdSize)
            throw new ArgumentException($"The slot id must be {KeyringFormat.SlotIdSize} bytes", nameof(slotId));
    }
}
