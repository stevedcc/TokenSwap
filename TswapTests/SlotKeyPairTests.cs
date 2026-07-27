using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the per-slot X25519 keypair (issue #115) — keypair generation and its underlying
/// Diffie-Hellman primitive only. The wrap/unwrap flow that will eventually protect the private
/// half with a slot's hardware-backed KEK is issue #116, a later wave, and is not implemented or
/// tested here.
/// </summary>
public class SlotKeyPairTests
{
    // RFC 7748 §6.1 X25519 test vector: an independent, published known-answer test proving
    // the key material this type generates is standard, interoperable X25519 — not merely
    // "whatever this library's Generate() happens to produce round-trips with itself."
    // https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    private const string RfcAlicePrivateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    private const string RfcAlicePublicHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    private const string RfcBobPrivateHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    private const string RfcBobPublicHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    private const string RfcSharedSecretHex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    // RFC 7748's test private keys are the raw scalar input to X25519(), which clamps
    // internally (§5); Rebex.Elliptic.Curve25519's GetPublicKey/GetSharedSecret require an
    // already-clamped key (its own random-generation path clamps for you, but FromPrivateKey
    // does not), so the known-answer test below clamps by hand per the RFC 7748 §5 recipe.
    private static byte[] Clamp(byte[] key)
    {
        key[0] &= 0xF8;
        key[31] &= 0x7F;
        key[31] |= 0x40;
        return key;
    }

    [Fact]
    public void ComputeSharedSecret_MatchesRfc7748KnownAnswerTest()
    {
        var alicePrivate = Clamp(Convert.FromHexString(RfcAlicePrivateHex));
        var bobPrivate = Clamp(Convert.FromHexString(RfcBobPrivateHex));

        var alicePublic = SlotKeyPair.ComputeSharedSecret(alicePrivate, PublicBasePoint());
        var bobPublic = SlotKeyPair.ComputeSharedSecret(bobPrivate, PublicBasePoint());

        Assert.Equal(RfcAlicePublicHex, Convert.ToHexStringLower(alicePublic));
        Assert.Equal(RfcBobPublicHex, Convert.ToHexStringLower(bobPublic));

        var sharedFromAlice = SlotKeyPair.ComputeSharedSecret(alicePrivate, bobPublic);
        var sharedFromBob = SlotKeyPair.ComputeSharedSecret(bobPrivate, alicePublic);

        Assert.Equal(RfcSharedSecretHex, Convert.ToHexStringLower(sharedFromAlice));
        Assert.Equal(RfcSharedSecretHex, Convert.ToHexStringLower(sharedFromBob));
    }

    // The X25519 base point u=9, encoded little-endian over 32 bytes — RFC 7748 §6.1's
    // "X25519(a, 9)" input, used here to derive each party's public key from their private key.
    private static byte[] PublicBasePoint()
    {
        var basePoint = new byte[32];
        basePoint[0] = 9;
        return basePoint;
    }

    [Fact]
    public void Generate_ReturnsDistinctThirtyTwoByteKeys()
    {
        var slot = SlotKeyPair.Generate();

        Assert.Equal(32, slot.PublicKey.Length);
        Assert.Equal(32, slot.PrivateKey.Length);
        Assert.NotEqual(slot.PublicKey, slot.PrivateKey);
    }

    [Fact]
    public void Generate_ProducesFreshKeypairEachCall()
    {
        var first = SlotKeyPair.Generate();
        var second = SlotKeyPair.Generate();

        Assert.NotEqual(first.PublicKey, second.PublicKey);
        Assert.NotEqual(first.PrivateKey, second.PrivateKey);
    }

    [Fact]
    public void Generate_KeypairIsValidForKeyAgreement()
    {
        // The public key Generate() returns must actually be X25519(privateKey, basepoint) —
        // i.e. a real, usable keypair, not two unrelated random byte blobs.
        var alice = SlotKeyPair.Generate();
        var bob = SlotKeyPair.Generate();

        var sharedFromAlice = SlotKeyPair.ComputeSharedSecret(alice.PrivateKey, bob.PublicKey);
        var sharedFromBob = SlotKeyPair.ComputeSharedSecret(bob.PrivateKey, alice.PublicKey);

        Assert.Equal(sharedFromAlice, sharedFromBob);
    }
}
