using System.Security.Cryptography;
using System.Text;

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
