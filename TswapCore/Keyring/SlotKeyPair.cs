using RebexCurve25519 = Rebex.Security.Cryptography.Curve25519;

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
/// <para><b>Curve choice / dependency:</b> the .NET BCL has no built-in X25519 as of this SDK
/// (its ECDH support covers only NIST curves). <c>Rebex.Elliptic.Curve25519</c> is a small,
/// pure-managed (no native/P-Invoke) port of D.J. Bernstein's reference implementation — chosen
/// over a libsodium binding specifically so this adds no NativeAOT publish complexity (no native
/// binary per OS/arch to bundle), unlike the existing hardware backends' unavoidable native
/// shims.</para>
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
        var curve = new RebexCurve25519();
        // GetPrivateKey() triggers the library's internal EnsurePrivateKey(), which generates
        // and RFC-7748-clamps 32 random bytes on first use and caches them; GetPublicKey() then
        // reuses that same cached private key rather than generating a second, unrelated one.
        var privateKey = curve.GetPrivateKey();
        var publicKey = curve.GetPublicKey();
        return new SlotKeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Computes the X25519 shared secret between <paramref name="privateKey"/> and
    /// <paramref name="peerPublicKey"/>. Exposed here so this module's own tests can verify the
    /// keys <see cref="Generate"/> produces are standard, interoperable X25519 material (see the
    /// RFC 7748 known-answer test), and so a later wave (issue #116) doesn't need to
    /// reintroduce this curve dependency — this method is <b>not itself</b> the wrap/unwrap
    /// flow, just the underlying Diffie-Hellman primitive.
    ///
    /// <paramref name="privateKey"/> must already be RFC-7748-clamped, as any key returned by
    /// <see cref="Generate"/> is; raw external randomness (e.g. from a known-answer test vector)
    /// must be clamped by the caller first — <c>Rebex.Elliptic.Curve25519</c> does this
    /// internally only for its own randomly-generated keys, not for keys supplied via
    /// <c>FromPrivateKey</c>.
    /// </summary>
    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] peerPublicKey)
    {
        var curve = new RebexCurve25519();
        curve.FromPrivateKey(privateKey);
        return curve.GetSharedSecret(peerPublicKey);
    }
}
