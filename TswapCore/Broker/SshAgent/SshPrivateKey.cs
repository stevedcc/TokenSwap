using System.Buffers;
using System.Buffers.Text;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using Ed25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace TswapCore.Broker.SshAgent;

/// <summary>
/// A private key from a vault secret (wire doc section 9): <c>openssh-key-v1</c> (unencrypted) or an
/// unencrypted PKCS#8 PEM, Ed25519 (BouncyCastle), ECDSA P-256/384/521 or RSA ≥ 3072 bits (the BCL).
/// The public key is derived from the private key and, for <c>openssh-key-v1</c>, must equal both
/// public copies the file carries. Held only for one request: <see cref="Dispose"/> zeroes the
/// Ed25519 seed and disposes the BCL key objects.
/// </summary>
public sealed class SshPrivateKey : IDisposable
{
    public const int MinRsaBits = 3072;

    private byte[]? _seed;   // Ed25519
    private ECDsa? _ecdsa;
    private RSA? _rsa;

    private SshPrivateKey(SshKeyType type, byte[] publicBlob)
    {
        Type = type;
        PublicBlob = publicBlob;
    }

    public SshKeyType Type { get; }

    /// <summary>The public key blob derived from the private key (wire doc section 7).</summary>
    public byte[] PublicBlob { get; }

    private static ReadOnlySpan<byte> Magic => "openssh-key-v1\0"u8;

    /// <summary>Parses a key secret; throws <see cref="SshKeyException"/> saying what is wrong (never quoting key bytes).</summary>
    public static SshPrivateKey Parse(ReadOnlySpan<byte> secret)
    {
        if (secret.Length > SshAgentProtocol.MaxKeySecretLength)
            throw new SshKeyException($"the secret is larger than {SshAgentProtocol.MaxKeySecretLength} bytes, so it is not a private key.");
        var (label, der) = Unpem(secret);
        try
        {
            return label switch
            {
                "OPENSSH PRIVATE KEY" => ParseOpenSsh(der),
                "PRIVATE KEY" => ParsePkcs8(der),
                "ENCRYPTED PRIVATE KEY" => throw new SshKeyException(
                    "it is an encrypted PKCS#8 key. Store it unencrypted (the vault is the protection): openssl pkcs8 -in <file> -out <new file>"),
                "RSA PRIVATE KEY" or "EC PRIVATE KEY" => throw new SshKeyException(
                    $"'{label}' (PKCS#1/SEC1) is not accepted; store an OpenSSH key (ssh-keygen -p -f <copy> rewrites it) or PKCS#8."),
                _ => throw new SshKeyException("it is not an OpenSSH or PKCS#8 private key."),
            };
        }
        catch (SshWireException ex)
        {
            throw new SshKeyException($"it can't be parsed ({ex.Message}).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(der);
        }
    }

    // ------------------------------------------------------------------ PEM

    /// <summary>
    /// The PEM label and decoded body of a single PEM block (surrounding whitespace allowed), working
    /// on bytes so no string ever holds key material. The caller zeroes the body.
    /// </summary>
    private static (string Label, byte[] Der) Unpem(ReadOnlySpan<byte> text)
    {
        text = TrimAsciiWhitespace(text);
        var begin = "-----BEGIN "u8;
        if (!text.StartsWith(begin))
            throw new SshKeyException("it is not a PEM private key (no '-----BEGIN' line).");
        var rest = text[begin.Length..];
        var labelEnd = rest.IndexOf("-----"u8);
        if (labelEnd <= 0 || labelEnd > 40)
            throw new SshKeyException("its PEM header can't be read.");
        var labelBytes = rest[..labelEnd];
        foreach (var b in labelBytes)
            if (b is not ((>= (byte)'A' and <= (byte)'Z') or (byte)' ' or (>= (byte)'0' and <= (byte)'9')))
                throw new SshKeyException("its PEM header can't be read.");
        var label = System.Text.Encoding.ASCII.GetString(labelBytes);
        var body = rest[(labelEnd + 5)..];
        var end = System.Text.Encoding.ASCII.GetBytes($"-----END {label}-----");
        if (!body.EndsWith(end))
            throw new SshKeyException($"its PEM block has no matching '-----END {label}-----' line.");
        body = body[..^end.Length];

        var base64 = new byte[body.Length];
        var count = 0;
        foreach (var b in body)
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
                base64[count++] = b;
        try
        {
            var der = new byte[Base64.GetMaxDecodedFromUtf8Length(count)];
            if (Base64.DecodeFromUtf8(base64.AsSpan(0, count), der, out _, out var written) != OperationStatus.Done)
            {
                CryptographicOperations.ZeroMemory(der);
                throw new SshKeyException("its PEM body is not valid base64.");
            }
            if (written == der.Length)
                return (label, der);
            var exact = der.AsSpan(0, written).ToArray();
            CryptographicOperations.ZeroMemory(der);
            return (label, exact);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(base64);
        }
    }

    private static ReadOnlySpan<byte> TrimAsciiWhitespace(ReadOnlySpan<byte> s)
    {
        static bool Ws(byte b) => b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';
        var start = 0;
        while (start < s.Length && Ws(s[start]))
            start++;
        var end = s.Length;
        while (end > start && Ws(s[end - 1]))
            end--;
        return s[start..end];
    }

    // ------------------------------------------------------------------ openssh-key-v1 (PROTOCOL.key)

    private static SshPrivateKey ParseOpenSsh(byte[] der)
    {
        if (!der.AsSpan().StartsWith(Magic))
            throw new SshKeyException("it is not an openssh-key-v1 key.");
        var reader = new SshReader(der.AsSpan(Magic.Length));
        var cipher = reader.ReadString();
        var kdf = reader.ReadString();
        var kdfOptions = reader.ReadString();
        if (!cipher.SequenceEqual("none"u8) || !kdf.SequenceEqual("none"u8) || kdfOptions.Length != 0)
            throw new SshKeyException(
                "it is encrypted (passphrase-protected). Store it unencrypted, the vault is the protection: ssh-keygen -p -N '' -f <copy of the key>");
        if (reader.ReadUInt32() != 1)
            throw new SshKeyException("it holds more than one key; store one key per secret.");
        var outerPublic = reader.ReadString();
        var privateSection = reader.ReadString();
        reader.EnsureEnd();
        if (privateSection.Length % 8 != 0)
            throw new SshWireException("private section not a multiple of the block size");

        var p = new SshReader(privateSection);
        if (p.ReadUInt32() != p.ReadUInt32())
            throw new SshWireException("check integers differ");
        var typeName = p.ReadString();
        SshPrivateKey key;
        if (typeName.SequenceEqual("ssh-ed25519"u8))
            key = ReadOpenSshEd25519(ref p);
        else if (typeName.StartsWith("ecdsa-sha2-"u8))
            key = ReadOpenSshEcdsa(ref p, typeName["ecdsa-sha2-".Length..]);
        else if (typeName.SequenceEqual("ssh-rsa"u8))
            key = ReadOpenSshRsa(ref p);
        else
            throw new SshKeyException("its key type is not supported (ssh-ed25519, ecdsa-sha2-nistp256/384/521 and ssh-rsa are).");
        try
        {
            p.ReadString(); // the comment: ignored (an identity's comment is the key's name)
            var expected = 1; // an int: a byte counter would wrap after 255 and pass an overlong run
            while (!p.AtEnd)
                if (p.ReadByte() != (byte)expected++)
                    throw new SshWireException("bad padding");
            if (expected > 8)
                throw new SshWireException("padding longer than a block");
            if (!outerPublic.SequenceEqual(key.PublicBlob))
                throw new SshKeyException("its embedded public key differs from the public key derived from its private key.");
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>RFC 9987 §5.2.3 fields: <c>string ENC(A)</c>, <c>string k ‖ ENC(A)</c>.</summary>
    private static SshPrivateKey ReadOpenSshEd25519(ref SshReader p)
    {
        var a = p.ReadString();
        var ka = p.ReadString();
        if (a.Length != 32 || ka.Length != 64)
            throw new SshWireException("ssh-ed25519 key fields have the wrong length");
        var seed = ka[..32].ToArray();
        var key = FromEd25519Seed(seed);
        if (!ka[32..].SequenceEqual(a) || !key.PublicBlob.AsSpan().SequenceEqual(SshPublicKey.Ed25519Blob(a)))
        {
            key.Dispose();
            throw new SshKeyException("its embedded public key differs from the public key derived from its private key.");
        }
        return key;
    }

    /// <summary>Takes ownership of <paramref name="seed"/> (zeroed on dispose) and derives A.</summary>
    private static SshPrivateKey FromEd25519Seed(byte[] seed)
    {
        var a = new byte[Ed25519.PublicKeySize];
        Ed25519.GeneratePublicKey(seed, 0, a, 0);
        return new SshPrivateKey(SshKeyType.Ed25519, SshPublicKey.Ed25519Blob(a)) { _seed = seed };
    }

    /// <summary>RFC 9987 §5.2.2 fields: <c>string curve</c>, <c>string Q</c>, <c>mpint d</c>; Q is derived from d and compared.</summary>
    private static SshPrivateKey ReadOpenSshEcdsa(ref SshReader p, ReadOnlySpan<byte> curveFromType)
    {
        var type = SshPublicKey.EcdsaTypeOf(curveFromType)
            ?? throw new SshKeyException("its ECDSA curve is not supported (nistp256, nistp384 and nistp521 are).");
        if (SshPublicKey.EcdsaTypeOf(p.ReadString()) != type)
            throw new SshWireException("ECDSA curve identifier doesn't match the key type");
        var q = p.ReadString();
        var (_, curve, size, _) = SshPublicKey.Curve(type);
        var d = p.ReadPositiveMpint(size);
        var key = FromEcdsaD(type, curve, size, d);
        var (x, y) = SshPublicKey.ReadPoint(q, size);
        if (!key.PublicBlob.AsSpan().SequenceEqual(SshPublicKey.EcdsaBlob(type, x, y)))
        {
            key.Dispose();
            throw new SshKeyException("its embedded public key differs from the public key derived from its private key.");
        }
        return key;
    }

    /// <summary>Imports d alone; the platform derives Q = d·G, which becomes the public key.</summary>
    private static SshPrivateKey FromEcdsaD(SshKeyType type, ECCurve curve, int size, ReadOnlySpan<byte> d)
    {
        var padded = new byte[size];
        d.CopyTo(padded.AsSpan(size - d.Length));
        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportParameters(new ECParameters { Curve = curve, D = padded });
            var pub = ecdsa.ExportParameters(includePrivateParameters: false);
            return new SshPrivateKey(type, SshPublicKey.EcdsaBlob(type, pub.Q.X!, pub.Q.Y!)) { _ecdsa = ecdsa };
        }
        catch (CryptographicException)
        {
            ecdsa.Dispose();
            throw new SshKeyException("its ECDSA private key is not valid for the curve.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(padded);
        }
    }

    /// <summary>RFC 9987 §5.2.4 fields: <c>mpint n, e, d, iqmp, p, q</c>; n = p·q and the CRT values are checked.</summary>
    private static SshPrivateKey ReadOpenSshRsa(ref SshReader r)
    {
        // Every array that holds a private value goes into parts as soon as it exists, so each is
        // zeroed whatever fails later (fix round 1, MiMo M6).
        var parts = new List<byte[]>();
        byte[] Keep(byte[] value)
        {
            parts.Add(value);
            return value;
        }
        try
        {
            var n = r.ReadPositiveMpint().ToArray();
            var e = r.ReadPositiveMpint().ToArray();
            var d = Keep(r.ReadPositiveMpint().ToArray());
            var iqmp = Keep(r.ReadPositiveMpint().ToArray());
            var p = Keep(r.ReadPositiveMpint().ToArray());
            var q = Keep(r.ReadPositiveMpint().ToArray());
            if (n.Length == 0 || e.Length == 0)
                throw new SshWireException("RSA key with a zero modulus or exponent");
            CheckRsaSize(BitLength(n));
            CheckRsaPublic(e, n);
            // BigInteger can't be zeroed; it holds the private values only for this check and the
            // CRT exponents (documented in BROKER.md, like .NET strings).
            var bn = new BigInteger(n, isUnsigned: true, isBigEndian: true);
            var be = new BigInteger(e, isUnsigned: true, isBigEndian: true);
            var bd = new BigInteger(d, isUnsigned: true, isBigEndian: true);
            var bp = new BigInteger(p, isUnsigned: true, isBigEndian: true);
            var bq = new BigInteger(q, isUnsigned: true, isBigEndian: true);
            var bi = new BigInteger(iqmp, isUnsigned: true, isBigEndian: true);
            if (bp <= 1 || bq <= 1 || bp * bq != bn || (bi * bq) % bp != 1
                || (be * bd) % (bp - 1) != 1 || (be * bd) % (bq - 1) != 1)
                throw new SshKeyException("its RSA private values are inconsistent (n ≠ p·q, or d or iqmp don't match).");
            var half = (n.Length + 1) / 2;
            var dp = Keep((bd % (bp - 1)).ToByteArray(isUnsigned: true, isBigEndian: true));
            var dq = Keep((bd % (bq - 1)).ToByteArray(isUnsigned: true, isBigEndian: true));
            var parameters = new RSAParameters
            {
                Modulus = n,
                Exponent = e,
                D = Keep(Pad(d, n.Length)),
                P = Keep(Pad(p, half)),
                Q = Keep(Pad(q, half)),
                DP = Keep(Pad(dp, half)),
                DQ = Keep(Pad(dq, half)),
                InverseQ = Keep(Pad(iqmp, half)),
            };
            var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(parameters);
            }
            catch (CryptographicException)
            {
                rsa.Dispose();
                throw new SshKeyException("its RSA private key can't be imported.");
            }
            return new SshPrivateKey(SshKeyType.Rsa, SshPublicKey.RsaBlob(e, n)) { _rsa = rsa };
        }
        finally
        {
            foreach (var part in parts)
                CryptographicOperations.ZeroMemory(part);
        }
    }

    /// <summary>Refuses degenerate RSA public values (fix round 1, MiMo M5): an even modulus, an even exponent or one below 3.</summary>
    private static void CheckRsaPublic(ReadOnlySpan<byte> e, ReadOnlySpan<byte> n)
    {
        if (SshPublicKey.RsaParametersRefusal(e, n) != null)
            throw new SshKeyException("its RSA public exponent must be odd and at least 3, and its modulus odd.");
    }

    private static byte[] Pad(byte[] value, int length)
    {
        if (value.Length > length)
            throw new SshKeyException("its RSA private values are inconsistent (a value is longer than the modulus allows).");
        if (value.Length == length)
            return (byte[])value.Clone();
        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    private static int BitLength(ReadOnlySpan<byte> magnitude)
    {
        var i = 0;
        while (i < magnitude.Length && magnitude[i] == 0)
            i++;
        return i == magnitude.Length ? 0 : (magnitude.Length - i - 1) * 8 + (32 - BitOperations.LeadingZeroCount(magnitude[i]));
    }

    private static void CheckRsaSize(int bits)
    {
        if (bits < MinRsaBits)
            throw new SshKeyException($"its RSA modulus is {bits} bits; at least {MinRsaBits} are required.");
    }

    // ------------------------------------------------------------------ PKCS#8 (RFC 5208/5958)

    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string Ed25519Oid = "1.3.101.112";

    private static SshPrivateKey ParsePkcs8(byte[] der)
    {
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.DER);
            var info = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var version = info.ReadInteger();
            if (version != 0 && version != 1)
                throw new SshKeyException("its PKCS#8 version is not supported.");
            var algorithm = info.ReadSequence();
            var oid = algorithm.ReadObjectIdentifier();
            switch (oid)
            {
                case RsaOid:
                {
                    var rsa = RSA.Create();
                    try
                    {
                        rsa.ImportPkcs8PrivateKey(der, out var read);
                        if (read != der.Length)
                            throw new SshWireException("trailing bytes after the PKCS#8 structure");
                        CheckRsaSize(rsa.KeySize);
                        var pub = rsa.ExportParameters(includePrivateParameters: false);
                        CheckRsaPublic(pub.Exponent, pub.Modulus);
                        return new SshPrivateKey(SshKeyType.Rsa, SshPublicKey.RsaBlob(pub.Exponent!, pub.Modulus!)) { _rsa = rsa };
                    }
                    catch
                    {
                        rsa.Dispose();
                        throw;
                    }
                }
                case EcPublicKeyOid:
                {
                    var type = algorithm.ReadObjectIdentifier() switch
                    {
                        "1.2.840.10045.3.1.7" => SshKeyType.EcdsaP256,
                        "1.3.132.0.34" => SshKeyType.EcdsaP384,
                        "1.3.132.0.35" => SshKeyType.EcdsaP521,
                        _ => throw new SshKeyException("its ECDSA curve is not supported (P-256, P-384 and P-521 are)."),
                    };
                    var ecdsa = ECDsa.Create();
                    try
                    {
                        ecdsa.ImportPkcs8PrivateKey(der, out var read);
                        if (read != der.Length)
                            throw new SshWireException("trailing bytes after the PKCS#8 structure");
                        var pub = ecdsa.ExportParameters(includePrivateParameters: false);
                        if (pub.Curve.Oid?.Value != SshPublicKey.Curve(type).Curve.Oid.Value)
                            throw new SshKeyException("its ECDSA curve doesn't match its algorithm identifier.");
                        return new SshPrivateKey(type, SshPublicKey.EcdsaBlob(type, pub.Q.X!, pub.Q.Y!)) { _ecdsa = ecdsa };
                    }
                    catch
                    {
                        ecdsa.Dispose();
                        throw;
                    }
                }
                case Ed25519Oid:
                {
                    if (algorithm.HasData)
                        throw new SshWireException("Ed25519 algorithm identifier with parameters");
                    var wrapped = info.ReadOctetString();
                    try
                    {
                        if (info.HasData)
                            throw new SshKeyException("PKCS#8 Ed25519 keys with attributes or an embedded public key are not supported.");
                        var inner = new AsnReader(wrapped, AsnEncodingRules.DER);
                        var seed = inner.ReadOctetString();
                        if (inner.HasData || seed.Length != 32)
                        {
                            CryptographicOperations.ZeroMemory(seed);
                            throw new SshWireException("Ed25519 private key is not a 32-byte octet string");
                        }
                        return FromEd25519Seed(seed);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(wrapped);
                    }
                }
                default:
                    throw new SshKeyException("its PKCS#8 key type is not supported (RSA, ECDSA P-256/384/521 and Ed25519 are).");
            }
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            throw new SshKeyException("its PKCS#8 structure can't be parsed.");
        }
    }

    // ------------------------------------------------------------------ signing

    /// <summary>
    /// Signs <paramref name="data"/> (flags already checked by <see cref="SshKeySigner.FlagsRefusal"/>);
    /// returns the signature blob of wire doc section 8.
    /// </summary>
    public byte[] Sign(ReadOnlySpan<byte> data, uint flags)
    {
        if (SshKeySigner.FlagsRefusal(Type, flags) is { } refused)
            throw new SshSignRefusedException(refused);
        var algorithm = SshKeySigner.AlgorithmName(Type, flags);
        switch (Type)
        {
            case SshKeyType.Ed25519:
            {
                var seed = _seed ?? throw new ObjectDisposedException(nameof(SshPrivateKey));
                var message = data.ToArray();
                var sig = new byte[Ed25519.SignatureSize];
                Ed25519.Sign(seed, 0, message, 0, message.Length, sig, 0);
                return new SshWriter().String(algorithm).String(sig).ToArray();
            }
            case SshKeyType.Rsa:
            {
                var rsa = _rsa ?? throw new ObjectDisposedException(nameof(SshPrivateKey));
                var hash = flags == SshAgentProtocol.RsaSha2_512 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
                var sig = rsa.SignData(data.ToArray(), hash, RSASignaturePadding.Pkcs1);
                return new SshWriter().String(algorithm).String(sig).ToArray();
            }
            default:
            {
                var ecdsa = _ecdsa ?? throw new ObjectDisposedException(nameof(SshPrivateKey));
                var (_, _, size, hash) = SshPublicKey.Curve(Type);
                var rs = ecdsa.SignData(data.ToArray(), hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                var inner = new SshWriter().PositiveMpint(rs.AsSpan(0, size)).PositiveMpint(rs.AsSpan(size, size)).ToArray();
                return new SshWriter().String(algorithm).String(inner).ToArray();
            }
        }
    }

    public void Dispose()
    {
        if (_seed != null)
            CryptographicOperations.ZeroMemory(_seed);
        _seed = null;
        _ecdsa?.Dispose();
        _ecdsa = null;
        _rsa?.Dispose();
        _rsa = null;
    }
}
