using System.Security.Cryptography;
using System.Text;

namespace TswapCore.Keyring;

/// <summary>
/// Derives the recovery slot's key-encryption key (issue #120, <c>MULTI_MACHINE_KEYING.md</c>
/// §The recovery slot / §Per-backend wrap primitive) from an X25519 ECDH shared secret.
///
/// <para><b>Shape mirrors <c>AppleSecureEnclaveInterop</c>'s ECIES-equivalent construction</b>
/// (ephemeral ECDH + HKDF-SHA256 + AES-GCM, see that type's Swift counterpart's doc comments) —
/// this is the same idea ported to X25519 via <see cref="SlotKeyPair"/> instead of P-256 via
/// CryptoKit, so no native shim is needed for a backend that has no actual hardware.</para>
///
/// <para><b>Call shape mirrors <see cref="RecordKeyDerivation"/></b>, this module's other
/// <c>HKDF.DeriveKey</c> call site: a per-operation <c>salt</c> plus a fixed domain-separation
/// <c>info</c> string, not a different HKDF invocation shape. The salt here is the wrap-time
/// ephemeral public key itself — already unique per wrap (a fresh ephemeral keypair is minted
/// every time <see cref="RecoverySlotWrap.Wrap"/> runs) and already transmitted alongside the
/// ciphertext, so reusing it as salt is free and gives every wrap its own HKDF salt with no
/// extra field.</para>
/// </summary>
public static class RecoverySlotKek
{
    /// <summary>Domain-separation label for the HKDF "info" parameter.</summary>
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("tswap-recovery-slot-kek-v1");

    /// <summary>Derived key length in bytes — <see cref="SlotPayloadWrap.KekSlotSize"/> (AES-256).</summary>
    public const int KeySize = 32;

    /// <summary>
    /// Derives the 32-byte KEK from an X25519 <paramref name="sharedSecret"/>
    /// (<see cref="SlotKeyPair.ComputeSharedSecret"/>) and the wrap-time
    /// <paramref name="ephemeralPublicKey"/> (used only as the HKDF salt here — it is also
    /// stored in the clear as the recovery slot's <see cref="Slot.PublicKey"/>).
    /// </summary>
    public static byte[] Derive(byte[] sharedSecret, byte[] ephemeralPublicKey) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, KeySize, salt: ephemeralPublicKey, info: Info);
}
