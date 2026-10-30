using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Broker.SshAgent;
using Xunit;

namespace TswapTests;

/// <summary>
/// T10 round 4 (GLM and MiMo on round 3): PKCS#8 edge shapes, built in-process with AsnWriter so
/// they run on every OS: the private scalar's range and length, trailing bytes, the ECPrivateKey
/// [0] parameters, [1] public keys in every position and form, round trips against the BCL's own
/// PKCS#8 writer, and the RSA v2 public key.
/// </summary>
public class SshAgentPkcs8EdgeTests
{
    private static readonly Asn1Tag Ctx0 = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag Ctx0Primitive = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag Ctx1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag Ctx1Constructed = new(TagClass.ContextSpecific, 1, true);

    private const string P256Oid = "1.2.840.10045.3.1.7";
    private const string P384Oid = "1.3.132.0.34";

    private static byte[] Pem(byte[] der) => Encoding.ASCII.GetBytes(PemEncoding.Write("PRIVATE KEY", der));

    /// <summary>How the ECPrivateKey's [0] parameters are written: none, explicit-tagged OID (RFC 5915), or a primitive [0].</summary>
    public enum InnerParams { None, ExplicitTagged, Primitive }

    /// <summary>A PKCS#8 EC key with every optional part chosen by the test.</summary>
    private static byte[] EcPkcs8(byte[] d, string curveOid = P256Oid, InnerParams inner = InnerParams.None, string? innerCurveOid = null,
        byte[]? innerPublic = null, int version = 0, byte[]? outerPublic = null, bool outerPublicConstructed = false)
    {
        var ec = new AsnWriter(AsnEncodingRules.DER);
        using (ec.PushSequence())
        {
            ec.WriteInteger(1);
            ec.WriteOctetString(d);
            if (inner == InnerParams.ExplicitTagged)
            {
                using (ec.PushSequence(Ctx0))
                    ec.WriteObjectIdentifier(innerCurveOid ?? curveOid);
            }
            else if (inner == InnerParams.Primitive)
            {
                var oid = new AsnWriter(AsnEncodingRules.DER);
                oid.WriteObjectIdentifier(innerCurveOid ?? curveOid);
                ec.WriteOctetString(oid.Encode()[2..], Ctx0Primitive); // the OID's content bytes under a primitive [0]
            }
            if (innerPublic != null)
            {
                using (ec.PushSequence(Ctx1Constructed))
                    ec.WriteBitString(innerPublic);
            }
        }
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(version);
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.2.840.10045.2.1");
                w.WriteObjectIdentifier(curveOid);
            }
            w.WriteOctetString(ec.Encode());
            if (outerPublic != null)
            {
                if (outerPublicConstructed)
                {
                    using (w.PushSequence(Ctx1Constructed))
                        w.WriteBitString(outerPublic);
                }
                else
                {
                    w.WriteBitString(outerPublic, 0, Ctx1);
                }
            }
        }
        return w.Encode();
    }

    private static (byte[] D, byte[] Q) NewP256(Func<byte[], bool>? until = null)
    {
        while (true)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var p = ecdsa.ExportParameters(true);
            if (until is null || until(p.D!))
                return (p.D!, [0x04, .. p.Q.X!, .. p.Q.Y!]);
        }
    }

    private static byte[] BlobOf(byte[] q, SshKeyType type = SshKeyType.EcdsaP256)
    {
        var size = (q.Length - 1) / 2;
        return SshPublicKey.EcdsaBlob(type, q.AsSpan(1, size), q.AsSpan(1 + size, size));
    }

    private static readonly byte[] P256Order = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    // ------------------------------------------------------------------ d

    [Theory]
    [InlineData(true)]   // RFC 5915's fixed-length octet string, starting with 0x00
    [InlineData(false)]  // a writer that trims the leading zero
    public void APrivateScalarWithALeadingZeroByte_Loads_WithTheRightPublicKey(bool fixedLength)
    {
        var (d, q) = NewP256(d => d[0] == 0); // about 1 key in 256
        var encoded = fixedLength ? d : d[1..];

        using var key = SshPrivateKey.Parse(Pem(EcPkcs8(encoded)));

        Assert.Equal(BlobOf(q), key.PublicBlob);
    }

    public static TheoryData<string> OutOfRangeD => ["zero", "empty", "n", "n+1", "all-ones"];

    [Theory]
    [MemberData(nameof(OutOfRangeD))]
    public void APrivateScalarOutsideOneToN_IsRefusedAsAKeyError(string which)
    {
        byte[] d = which switch
        {
            "zero" => new byte[32],
            "empty" => [],
            "n" => P256Order,
            "n+1" => [.. P256Order[..^1], (byte)(P256Order[^1] + 1)],
            _ => Enumerable.Repeat((byte)0xFF, 32).ToArray(),
        };

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(EcPkcs8(d))));

        // tswap's own range check answers, before any platform import (whose answer differs by OS).
        Assert.Contains(which is "zero" or "empty" ? "is zero" : "not below the curve's order", ex.Message);
    }

    // ------------------------------------------------------------------ explicit parameters' signs

    /// <summary>An explicit-parameter P-256 PKCS#8 key; <paramref name="negativeP"/> writes p as a negative INTEGER (no 0x00 sign byte).</summary>
    private static byte[] ExplicitP256(byte[] d, bool negativeP)
    {
        byte[] p = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(0);
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.2.840.10045.2.1");
                using (w.PushSequence())
                {
                    w.WriteInteger(1);
                    using (w.PushSequence())
                    {
                        w.WriteObjectIdentifier("1.2.840.10045.1.1");
                        if (negativeP)
                            w.WriteEncodedValue([0x02, (byte)p.Length, .. p]); // p's bytes as a negative INTEGER (no sign byte)
                        else
                            w.WriteIntegerUnsigned(p);
                    }
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"));
                        w.WriteOctetString(Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"));
                    }
                    w.WriteOctetString(Convert.FromHexString("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
                    w.WriteIntegerUnsigned(P256Order);
                    w.WriteInteger(1);
                }
            }
            var ec = new AsnWriter(AsnEncodingRules.DER);
            using (ec.PushSequence())
            {
                ec.WriteInteger(1);
                ec.WriteOctetString(d);
            }
            w.WriteOctetString(ec.Encode());
        }
        return w.Encode();
    }

    /// <summary>
    /// MiMo 6: "exactly P-256" includes the sign. p's bytes written without the 0x00 sign byte read as a
    /// negative INTEGER; for every supported curve such an encoding is also non-minimal (it starts
    /// FF FF), which DER refuses before the parameters are compared, and a positive-only check backs
    /// that up. Either way: a key error, never another exception.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExplicitParameters_MustBePositiveIntegers(bool negativeP)
    {
        var (d, q) = NewP256();

        if (!negativeP)
        {
            using var key = SshPrivateKey.Parse(Pem(ExplicitP256(d, negativeP)));
            Assert.Equal(BlobOf(q), key.PublicBlob);
        }
        else
        {
            Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(ExplicitP256(d, negativeP))));
        }
    }

    // ------------------------------------------------------------------ trailing bytes

    [Fact]
    public void EcKeyWithBytesAfterTheOuterSequence_IsRefused()
    {
        var (d, _) = NewP256();

        Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem([.. EcPkcs8(d), 0x00, 0x01])));
    }

    [Fact]
    public void Ed25519KeyWithBytesAfterTheOuterSequence_IsRefused()
    {
        var pem = Encoding.ASCII.GetString(SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)));
        var der = Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => l.Length > 0 && !l.StartsWith("-----"))));

        Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem([.. der, 0x05, 0x00])));
    }

    // ------------------------------------------------------------------ ECPrivateKey [0]

    [Fact]
    public void InnerParametersAsRfc5915Writes_ThemExplicitlyTagged_AreAccepted()
    {
        var (d, q) = NewP256();

        using var key = SshPrivateKey.Parse(Pem(EcPkcs8(d, inner: InnerParams.ExplicitTagged, innerPublic: q)));

        Assert.Equal(BlobOf(q), key.PublicBlob);
    }

    [Fact]
    public void InnerParametersNamingAnotherCurve_AreRefused()
    {
        var (d, _) = NewP256();

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(EcPkcs8(d, inner: InnerParams.ExplicitTagged, innerCurveOid: P384Oid))));

        Assert.Contains("curve", ex.Message);
    }

    [Fact]
    public void InnerParametersUnderAPrimitiveTag_AreRefused()
    {
        var (d, _) = NewP256();

        Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(EcPkcs8(d, inner: InnerParams.Primitive))));
    }

    // ------------------------------------------------------------------ [1] public keys

    [Fact]
    public void APublicKeyInAVersion0Key_IsRefused()
    {
        var (d, q) = NewP256();

        Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(EcPkcs8(d, version: 0, outerPublic: q))));
    }

    [Fact]
    public void AConstructedOuterPublicKey_IsRefused()
    {
        var (d, q) = NewP256();

        Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(EcPkcs8(d, version: 1, outerPublic: q, outerPublicConstructed: true))));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ACompressedEmbeddedPublicKey_IsAcceptedOnlyWhenItIsTheDerivedOne(bool sameParity)
    {
        var (d, q) = NewP256();
        var yIsOdd = (q[^1] & 1) == 1;
        var prefix = (byte)((yIsOdd == sameParity) ? 0x03 : 0x02);
        byte[] compressed = [prefix, .. q.AsSpan(1, 32)];

        if (sameParity)
        {
            using var key = SshPrivateKey.Parse(Pem(EcPkcs8(d, innerPublic: compressed)));
            Assert.Equal(BlobOf(q), key.PublicBlob);
        }
        else
        {
            var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(EcPkcs8(d, innerPublic: compressed))));
            Assert.Contains("public key", ex.Message);
        }
    }

    [Fact]
    public void AnEd25519PublicKeyOfTheWrongLength_IsRefusedAsAKeyError()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(1);
            using (w.PushSequence())
                w.WriteObjectIdentifier("1.3.101.112");
            var inner = new AsnWriter(AsnEncodingRules.DER);
            inner.WriteOctetString(seed);
            w.WriteOctetString(inner.Encode());
            w.WriteBitString(new byte[31], 0, Ctx1);
        }

        Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(w.Encode())));
    }

    // ------------------------------------------------------------------ against a real writer

    public static TheoryData<string> Curves => ["P-256", "P-384", "P-521"];

    [Theory]
    [MemberData(nameof(Curves))]
    public void KeysTheBclWritesAsPkcs8_LoadWithTheirPublicKey(string name)
    {
        var (curve, type) = name switch
        {
            "P-256" => (ECCurve.NamedCurves.nistP256, SshKeyType.EcdsaP256),
            "P-384" => (ECCurve.NamedCurves.nistP384, SshKeyType.EcdsaP384),
            _ => (ECCurve.NamedCurves.nistP521, SshKeyType.EcdsaP521),
        };
        using var ecdsa = ECDsa.Create(curve);
        var q = ecdsa.ExportParameters(false).Q;

        using var key = SshPrivateKey.Parse(Pem(ecdsa.ExportPkcs8PrivateKey()));

        Assert.Equal(type, key.Type);
        Assert.Equal(SshPublicKey.EcdsaBlob(type, q.X!, q.Y!), key.PublicBlob);
    }

    [Fact]
    public void AnEd25519Key_HasTheWireBlobOfRfc8709_ByteForByte()
    {
        // RFC 8032 §7.1 TEST 1; the blob written out by hand: uint32 11, "ssh-ed25519", uint32 32, A (RFC 8709 §4).
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var expected = Convert.FromHexString(
            "0000000b" + Convert.ToHexString("ssh-ed25519"u8) +
            "00000020" + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        using var key = SshPrivateKey.Parse(SshTestKeyMaker.Ed25519Pem(seed));

        Assert.Equal(expected, key.PublicBlob);
    }

    [Fact]
    public void TheEd25519Seed_IsZeroedWhenTheKeyIsDisposed()
    {
        var key = SshPrivateKey.Parse(SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32)));
        var seed = key.Ed25519SeedForTests!;
        Assert.Contains(seed, b => b != 0);

        key.Dispose();

        Assert.All(seed, b => Assert.Equal(0, b));
    }

    // ------------------------------------------------------------------ RSA v2 [1]

    private static byte[] RsaV2(RSA rsa, RSAParameters publicKey)
    {
        var v0 = new AsnReader(rsa.ExportPkcs8PrivateKey(), AsnEncodingRules.DER).ReadSequence();
        v0.ReadInteger();
        var algorithm = v0.ReadEncodedValue().ToArray();
        var privateKey = v0.ReadOctetString();
        var pub = new AsnWriter(AsnEncodingRules.DER);
        using (pub.PushSequence())
        {
            pub.WriteIntegerUnsigned(publicKey.Modulus);
            pub.WriteIntegerUnsigned(publicKey.Exponent);
        }
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(1);
            w.WriteEncodedValue(algorithm);
            w.WriteOctetString(privateKey);
            w.WriteBitString(pub.Encode(), 0, Ctx1);
        }
        return w.Encode();
    }

    [Fact]
    public void AnRsaV2KeyWithItsOwnPublicKey_Loads()
    {
        using var rsa = RSA.Create(3072);
        var p = rsa.ExportParameters(false);

        using var key = SshPrivateKey.Parse(Pem(RsaV2(rsa, p)));

        Assert.Equal(SshPublicKey.RsaBlob(p.Exponent, p.Modulus), key.PublicBlob);
    }

    [Fact]
    public void AnRsaV2KeyWithAnotherPublicKey_IsRefused()
    {
        using var rsa = RSA.Create(3072);
        using var other = RSA.Create(3072);

        var ex = Assert.Throws<SshKeyException>(() => SshPrivateKey.Parse(Pem(RsaV2(rsa, other.ExportParameters(false)))));

        Assert.Contains("public key", ex.Message);
    }
}

/// <summary>The private-scalar range check on its own (it runs before any platform import, so it holds on every OS).</summary>
public class SshAgentEcScalarTests
{
    [Theory]
    [InlineData("00", false)]
    [InlineData("0000", false)]
    [InlineData("01", true)]
    [InlineData("00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550", true)]   // n - 1, a leading zero
    [InlineData("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", false)]     // n
    [InlineData("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552", false)]     // n + 1
    [InlineData("010000000000000000000000000000000000000000000000000000000000000000", false)]   // 33 bytes: above n
    public void P256Scalars_AreAcceptedExactlyFromOneToBelowN(string hex, bool accepted)
    {
        var refusal = SshPrivateKey.EcScalarRefusal(SshKeyType.EcdsaP256, Convert.FromHexString(hex));

        Assert.Equal(accepted, refusal is null);
    }
}
