using System.Security.Cryptography;
using System.Text;
using Ed25519Bc = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace TswapCore.Broker.SshAgent;

/// <summary>
/// A parsed public key blob (wire doc section 7): <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256|384|521</c>
/// or <c>ssh-rsa</c>. Anything else (DSA, <c>sk-*</c>, certificates) is a <see cref="SshWireException"/>.
/// </summary>
public sealed class SshPublicKey
{
    private SshPublicKey(SshKeyType type, byte[] blob, byte[]? ed25519 = null, byte[]? qx = null, byte[]? qy = null, byte[]? e = null, byte[]? n = null)
    {
        Type = type;
        Blob = blob;
        Ed25519 = ed25519;
        QX = qx;
        QY = qy;
        Exponent = e;
        Modulus = n;
    }

    public SshKeyType Type { get; }

    /// <summary>The blob it was parsed from (a copy).</summary>
    public byte[] Blob { get; }

    /// <summary>Ed25519: the 32-byte ENC(A).</summary>
    public byte[]? Ed25519 { get; }

    /// <summary>ECDSA: the point's coordinates, each the curve's field size.</summary>
    public byte[]? QX { get; }

    public byte[]? QY { get; }

    /// <summary>RSA: big-endian magnitudes.</summary>
    public byte[]? Exponent { get; }

    public byte[]? Modulus { get; }

    /// <summary>The blob's key type name: <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistpNNN</c> or <c>ssh-rsa</c>.</summary>
    public static string KeyTypeName(SshKeyType type) => type switch
    {
        SshKeyType.Ed25519 => "ssh-ed25519",
        SshKeyType.EcdsaP256 => "ecdsa-sha2-nistp256",
        SshKeyType.EcdsaP384 => "ecdsa-sha2-nistp384",
        SshKeyType.EcdsaP521 => "ecdsa-sha2-nistp521",
        _ => "ssh-rsa",
    };

    /// <summary>ECDSA curve details (RFC 5656 §3.1, §6.2.1): the identifier, the BCL curve, the field size in bytes and the hash.</summary>
    public static (string Id, ECCurve Curve, int Size, HashAlgorithmName Hash) Curve(SshKeyType type) => type switch
    {
        SshKeyType.EcdsaP256 => ("nistp256", ECCurve.NamedCurves.nistP256, 32, HashAlgorithmName.SHA256),
        SshKeyType.EcdsaP384 => ("nistp384", ECCurve.NamedCurves.nistP384, 48, HashAlgorithmName.SHA384),
        SshKeyType.EcdsaP521 => ("nistp521", ECCurve.NamedCurves.nistP521, 66, HashAlgorithmName.SHA512),
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    /// <summary>The ECDSA type for a curve identifier (<c>nistp256</c>...), or null.</summary>
    public static SshKeyType? EcdsaTypeOf(ReadOnlySpan<byte> id) =>
        id.SequenceEqual("nistp256"u8) ? SshKeyType.EcdsaP256
        : id.SequenceEqual("nistp384"u8) ? SshKeyType.EcdsaP384
        : id.SequenceEqual("nistp521"u8) ? SshKeyType.EcdsaP521
        : null;

    /// <summary>Parses a whole blob (no trailing bytes).</summary>
    public static SshPublicKey Parse(ReadOnlySpan<byte> blob)
    {
        var reader = new SshReader(blob);
        var key = Read(ref reader, blob);
        reader.EnsureEnd();
        return key;
    }

    private static SshPublicKey Read(ref SshReader reader, ReadOnlySpan<byte> blob)
    {
        var name = reader.ReadString();
        if (name.SequenceEqual("ssh-ed25519"u8))
        {
            var a = reader.ReadString();
            if (a.Length != 32)
                throw new SshWireException("ssh-ed25519 key is not 32 bytes");
            return new SshPublicKey(SshKeyType.Ed25519, blob.ToArray(), ed25519: a.ToArray());
        }
        if (name.StartsWith("ecdsa-sha2-"u8))
        {
            var type = EcdsaTypeOf(name["ecdsa-sha2-".Length..]) ?? throw new SshWireException("unsupported ECDSA curve");
            if (!reader.ReadString().SequenceEqual(Encoding.ASCII.GetBytes(Curve(type).Id)))
                throw new SshWireException("ECDSA curve identifier doesn't match the key type");
            var (x, y) = ReadPoint(reader.ReadString(), Curve(type).Size);
            return new SshPublicKey(type, blob.ToArray(), qx: x, qy: y);
        }
        if (name.SequenceEqual("ssh-rsa"u8))
        {
            var e = reader.ReadPositiveMpint().ToArray();
            var n = reader.ReadPositiveMpint().ToArray();
            if (e.Length == 0 || n.Length == 0)
                throw new SshWireException("RSA key with a zero exponent or modulus");
            return new SshPublicKey(SshKeyType.Rsa, blob.ToArray(), e: e, n: n);
        }
        throw new SshWireException("unsupported key type");
    }

    /// <summary>An uncompressed SEC1 point (<c>0x04 ‖ X ‖ Y</c>) of a curve with <paramref name="size"/>-byte coordinates.</summary>
    public static (byte[] X, byte[] Y) ReadPoint(ReadOnlySpan<byte> q, int size)
    {
        if (q.Length != 1 + 2 * size || q[0] != 0x04)
            throw new SshWireException("ECDSA point is not an uncompressed point of the curve's size");
        return (q.Slice(1, size).ToArray(), q.Slice(1 + size, size).ToArray());
    }

    /// <summary>The smallest RSA host key whose signature a bind may carry (OpenSSH's <c>RequiredRSASize</c> default).</summary>
    public const int MinRsaHostBits = 2048;

    /// <summary>
    /// Verifies a signature blob (wire doc section 8) by this key over <paramref name="data"/>, as a
    /// session-bind's host-key signature over the session identifier is checked (wire doc section 6):
    /// Ed25519 (BouncyCastle), ECDSA with the curve's hash, RSA with <c>rsa-sha2-256/512</c> only.
    /// Returns null when it verifies, otherwise why not (<c>sha1</c>, <c>algorithm</c>,
    /// <c>rsa-too-small</c>, <c>invalid</c>).
    /// </summary>
    public string? VerifyRefusal(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        try
        {
            var reader = new SshReader(signatureBlob);
            var algorithm = reader.ReadString();
            var signature = reader.ReadString();
            reader.EnsureEnd();
            switch (Type)
            {
                case SshKeyType.Ed25519:
                    if (!algorithm.SequenceEqual("ssh-ed25519"u8))
                        return "algorithm";
                    if (signature.Length != Ed25519Bc.SignatureSize)
                        return "invalid";
                    var message = data.ToArray();
                    return Ed25519Bc.Verify(signature.ToArray(), 0, Ed25519!, 0, message, 0, message.Length) ? null : "invalid";
                case SshKeyType.Rsa:
                {
                    HashAlgorithmName hash;
                    if (algorithm.SequenceEqual("rsa-sha2-256"u8))
                        hash = HashAlgorithmName.SHA256;
                    else if (algorithm.SequenceEqual("rsa-sha2-512"u8))
                        hash = HashAlgorithmName.SHA512;
                    else
                        return algorithm.SequenceEqual("ssh-rsa"u8) ? "sha1" : "algorithm";
                    var n = Modulus!;
                    var bits = (n.Length - 1) * 8 + (32 - System.Numerics.BitOperations.LeadingZeroCount(n[0]));
                    if (bits < MinRsaHostBits)
                        return "rsa-too-small";
                    if (signature.Length > n.Length)
                        return "invalid";
                    var padded = new byte[n.Length]; // OpenSSH accepts a signature shorter than the modulus, left-padded
                    signature.CopyTo(padded.AsSpan(n.Length - signature.Length));
                    using var rsa = RSA.Create(new RSAParameters { Exponent = Exponent, Modulus = n });
                    return rsa.VerifyData(data, padded, hash, RSASignaturePadding.Pkcs1) ? null : "invalid";
                }
                default:
                {
                    if (!algorithm.SequenceEqual(Encoding.ASCII.GetBytes(KeyTypeName(Type))))
                        return "algorithm";
                    var (_, curve, size, hash) = Curve(Type);
                    var inner = new SshReader(signature);
                    var r = inner.ReadPositiveMpint(size);
                    var s = inner.ReadPositiveMpint(size);
                    inner.EnsureEnd();
                    var p1363 = new byte[2 * size];
                    r.CopyTo(p1363.AsSpan(size - r.Length));
                    s.CopyTo(p1363.AsSpan(2 * size - s.Length));
                    using var ecdsa = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = QX, Y = QY } });
                    return ecdsa.VerifyData(data, p1363, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation) ? null : "invalid";
                }
            }
        }
        catch (Exception ex) when (ex is SshWireException or CryptographicException)
        {
            return "invalid";
        }
    }

    /// <summary>The blob of an Ed25519 key.</summary>
    public static byte[] Ed25519Blob(ReadOnlySpan<byte> a) => new SshWriter().String("ssh-ed25519").String(a).ToArray();

    /// <summary>The blob of an ECDSA key (Q as an uncompressed point).</summary>
    public static byte[] EcdsaBlob(SshKeyType type, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        var (id, _, size, _) = Curve(type);
        var q = new byte[1 + 2 * size];
        q[0] = 0x04;
        x.CopyTo(q.AsSpan(1 + size - x.Length));
        y.CopyTo(q.AsSpan(1 + 2 * size - y.Length));
        return new SshWriter().String(KeyTypeName(type)).String(id).String(q).ToArray();
    }

    /// <summary>The blob of an RSA key: <c>string "ssh-rsa"</c>, <c>mpint e</c>, <c>mpint n</c>.</summary>
    public static byte[] RsaBlob(ReadOnlySpan<byte> e, ReadOnlySpan<byte> n) =>
        new SshWriter().String("ssh-rsa").PositiveMpint(e).PositiveMpint(n).ToArray();
}
