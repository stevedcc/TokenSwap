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
    // internally (§5). The known-answer test clamps by hand per the RFC 7748 §5 recipe, as it
    // did when SlotKeyPair used Rebex.Elliptic.Curve25519 (which needed a pre-clamped key);
    // clamping is idempotent, so the expected values are the same either way.
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
    public void Generate_PrivateKeyIsClamped()
    {
        // v0.1.0 (Rebex) stored RFC 7748 §5-clamped private keys, and Rebex used a supplied key
        // as it is, without clamping. Keys tswap writes now must keep that form so a v0.1.0
        // binary still computes the same shared secret with them (e.g. a recovery key made by a
        // newer tswap, used with an old build). The BCL providers need not clamp on export.
        for (var i = 0; i < 64; i++)
        {
            var key = SlotKeyPair.Generate().PrivateKey;

            Assert.Equal(0, key[0] & 0x07);
            Assert.Equal(0, key[31] & 0x80);
            Assert.Equal(0x40, key[31] & 0x40);
        }
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

    // A keypair and peer public key produced by Rebex.Elliptic.Curve25519 1.2.2 (the library
    // v0.1.0 generated every slot keypair with), with the shared secret Rebex computed. Throwaway
    // test material, not from any vault. Pins that slot keys already written to keyrings still
    // unwrap after the switch to the BCL's X25519DiffieHellman.
    private const string RebexPrivateHex = "08ea29b189e54de4d7cb00f26d169051af633b4f5651bfd4b9cc1ffb64fcdc7c";
    private const string RebexPublicHex = "01456d6abeb3113794f1d64e622445e456c13a0f991e10870aa494feeed3a84a";
    private const string RebexPeerPublicHex = "ee49cc94bedf133c6d25ec77d53f8ae041cca2fbee6376638691b5e22586ce68";
    private const string RebexSharedSecretHex = "8052e101c712742913e8e8f5e915714d14679e14cf41074ce50e295c29dd8075";

    [Fact]
    public void ComputeSharedSecret_MatchesKeysWrittenByRebex()
    {
        var privateKey = Convert.FromHexString(RebexPrivateHex);

        Assert.Equal(RebexPublicHex, Convert.ToHexStringLower(SlotKeyPair.ComputeSharedSecret(privateKey, PublicBasePoint())));
        Assert.Equal(RebexSharedSecretHex, Convert.ToHexStringLower(SlotKeyPair.ComputeSharedSecret(privateKey, Convert.FromHexString(RebexPeerPublicHex))));
    }

    // Low-order peer keys: X25519 with any of them yields an all-zero shared secret whatever the
    // private key (RFC 7748 §6.1 says implementations may check for this). These are all seven
    // entries of libsodium's X25519 small-order blocklist
    // (crypto_scalarmult/curve25519/ref10/x25519_ref10.c, has_small_order).
    public static TheoryData<string> LowOrderPeerKeys =>
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1 (order 4; libsodium labels it order 2)
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p (= 0)
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1 (= 1)
    ];

    [Theory]
    [MemberData(nameof(LowOrderPeerKeys))]
    public void ComputeSharedSecret_RejectsLowOrderPeerKey(string peerPublicHex)
    {
        // A peer key like that, e.g. a tampered recovery or ephemeral public key, must fail
        // loudly instead of feeding a known all-zero IKM into the slot KEK derivation.
        var slot = SlotKeyPair.Generate();

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => SlotKeyPair.ComputeSharedSecret(slot.PrivateKey, Convert.FromHexString(peerPublicHex)));
    }

    [Fact]
    public void BclX25519_IsSupportedOnThisPlatform()
    {
        // tswap ships for linux-x64, linux-arm64, osx-arm64 and win-x64; CI runs this on Linux,
        // macOS and Windows. Without platform support every slot operation would throw.
        Assert.True(System.Security.Cryptography.X25519DiffieHellman.IsSupported);
    }
}
