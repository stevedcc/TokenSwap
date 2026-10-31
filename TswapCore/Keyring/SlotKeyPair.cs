using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// A keyring slot's X25519 keypair (issue #115). Every slot gets one of these: the private half
/// is meant to eventually be wrapped by that slot's own hardware-backed <c>KEK_slot</c> (issue
/// #116, a later wave — <b>not implemented here</b>), the public half is stored in the keyring
/// in the clear.
///
/// <code>
/// unlock: hardware -&gt; KEK_slot -&gt; slot private key -&gt; K_v
/// </code>
///
/// In exchange, any holder of <c>K_v</c> can write a fresh slot for any enrolled device
/// offline — including YubiKey slots, which otherwise have no public key to encrypt to
/// (challenge-response yields only a symmetric KEK, never a keypair). This is also what the
/// hand-carried enrollment exchange (<c>slot request</c>/<c>approve</c>/<c>accept</c>, issue
/// #121, a later wave) trades between machines.
///
/// <para><b>Why this gates v0 specifically</b> (see <c>MULTI_MACHINE_KEYING.md</c> §Per-slot
/// X25519 keypair): every other v0 format decision migrates mechanically later — read with the
/// old key, rewrite with the new, one pass, no ceremony. This is the one exception: retrofitting
/// it after the fact would need every enrolled device physically present again, which for a
/// YubiKey or a recovery keypair sitting in a drawer in another country is a migration that
/// never actually happens. This type only defines the keypair's shape and how to generate one;
/// the wrap/unwrap flow and the slot request/approve/accept commands are explicitly out of
/// scope here (issues #116 and #121).</para>
///
/// <para><b>Curve choice / dependency:</b> the BCL's <see cref="X25519DiffieHellman"/> (new in
/// .NET 11: OpenSSL on Linux, CNG on Windows, the platform provider on macOS). Until .NET 11 this
/// used <c>Rebex.Elliptic.Curve25519</c>; both are RFC 7748 X25519, so keys written by either
/// work with the other (pinned by <c>SlotKeyPairTests.ComputeSharedSecret_MatchesKeysWrittenByRebex</c>).</para>
/// </summary>
public sealed record SlotKeyPair(byte[] PublicKey, byte[] PrivateKey)
{
    /// <summary>Byte length of both the public and private key.</summary>
    public const int KeySize = 32;

    /// <summary>
    /// Generates a fresh, randomly-clamped X25519 keypair. Each call produces an independent
    /// keypair — callers enrolling a new slot call this once and persist both halves per the
    /// keyring's slot schema (public in the clear, private destined for hardware wrapping by a
    /// later wave).
    /// </summary>
    public static SlotKeyPair Generate()
    {
        using var key = X25519DiffieHellman.GenerateKey();
        return new SlotKeyPair(key.ExportPublicKey(), key.ExportPrivateKey());
    }

    /// <summary>
    /// Computes the X25519 shared secret between <paramref name="privateKey"/> and
    /// <paramref name="peerPublicKey"/>. Exposed here so this module's own tests can verify the
    /// keys <see cref="Generate"/> produces are standard, interoperable X25519 material (see the
    /// RFC 7748 known-answer test), and so a later wave (issue #116) doesn't need to
    /// reintroduce this curve dependency — this method is <b>not itself</b> the wrap/unwrap
    /// flow, just the underlying Diffie-Hellman primitive.
    ///
    /// Throws <see cref="CryptographicException"/> for a low-order <paramref name="peerPublicKey"/>
    /// (one that would give an all-zero shared secret), so a tampered public key fails instead of
    /// deriving a KEK from a known input.
    /// </summary>
    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] peerPublicKey)
    {
        using var key = X25519DiffieHellman.ImportPrivateKey(privateKey);
        using var peer = X25519DiffieHellman.ImportPublicKey(peerPublicKey);
        return key.DeriveRawSecretAgreement(peer);
    }
}
