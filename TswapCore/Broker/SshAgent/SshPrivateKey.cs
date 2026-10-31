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

    /// <summary>Test hook: the Ed25519 seed this key holds (its owner zeroes it on <see cref="Dispose"/>).</summary>
    internal byte[]? Ed25519SeedForTests => _seed;

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
        // The seed is owned from here on: held by the key (zeroed on Dispose, which every caller and
        // every refusal path runs), or zeroed here if deriving fails (round 4, GLM 4, MiMo 1).
        try
        {
            var a = new byte[Ed25519.PublicKeySize];
            Ed25519.GeneratePublicKey(seed, 0, a, 0);
            return new SshPrivateKey(SshKeyType.Ed25519, SshPublicKey.Ed25519Blob(a)) { _seed = seed };
        }
        catch
        {
            CryptographicOperations.ZeroMemory(seed);
            throw;
        }
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

    /// <summary>
    /// Why <paramref name="d"/> (big-endian, any leading zeros) can't be a private key of the curve, or
    /// null: it must satisfy 1 &lt;= d &lt; n (SEC 1 §3.2.1).
    /// </summary>
    internal static string? EcScalarRefusal(SshKeyType type, ReadOnlySpan<byte> d)
    {
        var magnitude = d;
        while (magnitude.Length > 0 && magnitude[0] == 0)
            magnitude = magnitude[1..];
        if (magnitude.Length == 0)
            return "its ECDSA private key is zero.";
        var n = KnownCurves.Single(c => c.Type == type).N;
        if (magnitude.Length > n.Length || (magnitude.Length == n.Length && magnitude.SequenceCompareTo(n) >= 0))
            return "its ECDSA private key is not below the curve's order.";
        return null;
    }

    /// <summary>Imports d alone; the platform derives Q = d·G, which becomes the public key.</summary>
    private static SshPrivateKey FromEcdsaD(SshKeyType type, ECCurve curve, int size, ReadOnlySpan<byte> d)
    {
        // Round 4 (GLM 3, MiMo 2): 1 <= d < n here, not left to the platform's import (which differs
        // by OS); a short d (a leading zero byte, about 1 key in 256) is left-padded below.
        if (EcScalarRefusal(type, d) is { } refused)
            throw new SshKeyException(refused);
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
        if (SshPublicKey.RsaParametersRefusal(e, n) is not null)
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
    private const string PrimeFieldOid = "1.2.840.10045.1.1";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag Context1Constructed = new(TagClass.ContextSpecific, 1, isConstructed: true);
    private static readonly Asn1Tag Context1Primitive = new(TagClass.ContextSpecific, 1);

    /// <summary>
    /// PrivateKeyInfo (RFC 5208) or OneAsymmetricKey v2 (RFC 5958): <c>version</c> 0 or 1,
    /// the algorithm, the private key, optional <c>[0]</c> attributes (ignored: metadata), and, in v2
    /// only, an optional <c>[1]</c> public key, which must equal the derived one. RSA goes to the
    /// platform's PKCS#8 import; ECDSA and Ed25519 are read here, so every OS accepts the same
    /// shapes (round 3: macOS's LibreSSL writes EC keys with explicit curve parameters).
    /// </summary>
    private static SshPrivateKey ParsePkcs8(byte[] der)
    {
        var stage = "PrivateKeyInfo";
        byte[]? privateKey = null;
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.DER);
            var info = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var version = info.ReadInteger();
            if (version != 0 && version != 1)
                throw new SshKeyException("its PKCS#8 version is not supported.");
            var algorithmEncoded = info.ReadEncodedValue().ToArray();
            var algorithmOuter = new AsnReader(algorithmEncoded, AsnEncodingRules.DER);
            var algorithm = algorithmOuter.ReadSequence();
            algorithmOuter.ThrowIfNotEmpty();
            var oid = algorithm.ReadObjectIdentifier();
            stage = "private key";
            privateKey = info.ReadOctetString();
            stage = "attributes";
            if (info.HasData && info.PeekTag().HasSameClassAndValue(Context0))
                info.ReadSetOf(skipSortOrderValidation: true, Context0); // attributes: metadata, ignored (a SET OF under IMPLICIT [0])
            stage = "public key";
            byte[]? outerPublic = null;
            if (info.HasData && info.PeekTag().HasSameClassAndValue(Context1Primitive))
            {
                if (version != 1)
                    throw new SshWireException("a [1] public key in a version 0 PrivateKeyInfo");
                outerPublic = ReadBitString(info, Context1Primitive);
            }
            info.ThrowIfNotEmpty();
            switch (oid)
            {
                case RsaOid:
                    stage = "RSA private key";
                    if (version == 0)
                        return ParsePkcs8Rsa(der, outerPublic);
                    var v0 = Pkcs8V0(algorithmEncoded, privateKey);
                    try
                    {
                        return ParsePkcs8Rsa(v0, outerPublic);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(v0);
                    }
                case EcPublicKeyOid:
                    stage = "EC parameters";
                    var type = ReadEcParameters(algorithm);
                    algorithm.ThrowIfNotEmpty();
                    stage = "ECPrivateKey";
                    return ParseEcPrivateKey(type, privateKey, outerPublic);
                case Ed25519Oid:
                    stage = "Ed25519 private key";
                    if (algorithm.HasData)
                        throw new SshWireException("Ed25519 algorithm identifier with parameters");
                    var inner = new AsnReader(privateKey, AsnEncodingRules.DER);
                    var seed = inner.ReadOctetString();
                    if (inner.HasData || seed.Length != 32)
                    {
                        CryptographicOperations.ZeroMemory(seed);
                        throw new SshWireException("Ed25519 private key is not a 32-byte octet string");
                    }
                    var key = FromEd25519Seed(seed);
                    if (outerPublic is not null && !SshPublicKey.Ed25519Blob(outerPublic).AsSpan().SequenceEqual(key.PublicBlob))
                    {
                        key.Dispose();
                        throw new SshKeyException("its embedded public key differs from the public key derived from its private key.");
                    }
                    return key;
                default:
                    throw new SshKeyException("its PKCS#8 key type is not supported (RSA, ECDSA P-256/384/521 and Ed25519 are).");
            }
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            throw new SshKeyException($"its PKCS#8 structure can't be parsed (at the {stage}).");
        }
        finally
        {
            if (privateKey is not null)
                CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    /// <summary>
    /// RSA through the platform's PKCS#8 import (version 0 only there, so a v2 key arrives rebuilt as
    /// v0); a v2 key's <c>[1]</c> RSAPublicKey must equal the derived (n, e) (round 4, GLM 5).
    /// </summary>
    private static SshPrivateKey ParsePkcs8Rsa(byte[] der, byte[]? outerPublic)
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
            if (outerPublic is not null)
            {
                var reader = new AsnReader(outerPublic, AsnEncodingRules.DER);
                var sequence = reader.ReadSequence();
                reader.ThrowIfNotEmpty();
                var n = sequence.ReadIntegerBytes().Span;
                var e = sequence.ReadIntegerBytes().Span;
                sequence.ThrowIfNotEmpty();
                if (!Trim(n).AsSpan().SequenceEqual(Trim(pub.Modulus)) || !Trim(e).AsSpan().SequenceEqual(Trim(pub.Exponent)))
                    throw new SshKeyException("its embedded public key differs from the public key derived from its private key.");
            }
            return new SshPrivateKey(SshKeyType.Rsa, SshPublicKey.RsaBlob(pub.Exponent!, pub.Modulus!)) { _rsa = rsa };
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>A version-0 PrivateKeyInfo of the same algorithm and private key (for the platform's import); the caller zeroes it.</summary>
    private static byte[] Pkcs8V0(byte[] algorithmEncoded, byte[] privateKey)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            writer.WriteEncodedValue(algorithmEncoded);
            writer.WriteOctetString(privateKey);
        }
        return writer.Encode();
    }

    /// <summary>A BIT STRING with no unused bits.</summary>
    private static byte[] ReadBitString(AsnReader reader, Asn1Tag? tag = null)
    {
        var bits = reader.ReadBitString(out var unused, tag);
        if (unused != 0)
            throw new SshWireException("a public key BIT STRING with unused bits");
        return bits;
    }

    /// <summary>
    /// ECParameters (RFC 5480 / SEC 1): a named curve OID, or explicit parameters that are exactly
    /// P-256, P-384 or P-521 (field, a, b, generator, order, cofactor 1; the seed is ignored).
    /// Anything else, including a curve that differs in one bit, is refused.
    /// </summary>
    private static SshKeyType ReadEcParameters(AsnReader parameters)
    {
        var tag = parameters.PeekTag();
        if (tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
        {
            return parameters.ReadObjectIdentifier() switch
            {
                "1.2.840.10045.3.1.7" => SshKeyType.EcdsaP256,
                "1.3.132.0.34" => SshKeyType.EcdsaP384,
                "1.3.132.0.35" => SshKeyType.EcdsaP521,
                _ => throw new SshKeyException("its ECDSA curve is not supported (P-256, P-384 and P-521 are)."),
            };
        }
        if (!tag.HasSameClassAndValue(Asn1Tag.Sequence))
            throw new SshKeyException("its ECDSA curve parameters are neither a named curve nor explicit parameters.");
        var domain = parameters.ReadSequence();
        var domainVersion = domain.ReadInteger();
        if (domainVersion < 1 || domainVersion > 3)
            throw new SshKeyException("its explicit ECDSA curve parameters have an unknown version.");
        var field = domain.ReadSequence();
        if (field.ReadObjectIdentifier() != PrimeFieldOid)
            throw new SshKeyException("its explicit ECDSA curve is not over a prime field, so not a supported curve.");
        var p = Positive(field.ReadIntegerBytes().Span);
        field.ThrowIfNotEmpty();
        var curve = domain.ReadSequence();
        var a = Trim(curve.ReadOctetString());
        var b = Trim(curve.ReadOctetString());
        if (curve.HasData)
            curve.ReadBitString(out _); // the seed: ignored
        curve.ThrowIfNotEmpty();
        var generator = domain.ReadOctetString();
        var order = Positive(domain.ReadIntegerBytes().Span);
        var cofactor = domain.HasData ? Positive(domain.ReadIntegerBytes().Span) : [1];
        domain.ThrowIfNotEmpty();
        foreach (var known in KnownCurves)
        {
            if (p.SequenceEqual(known.P) && a.SequenceEqual(known.A) && b.SequenceEqual(known.B)
                && generator.AsSpan().SequenceEqual(known.G) && order.SequenceEqual(known.N) && cofactor.SequenceEqual(new byte[] { 1 }))
                return known.Type;
        }
        throw new SshKeyException("its explicit ECDSA curve parameters are not exactly P-256, P-384 or P-521.");
    }

    /// <summary>An INTEGER's magnitude, refused when negative (round 4, MiMo 6: "exactly P-256" includes the sign).</summary>
    private static byte[] Positive(ReadOnlySpan<byte> integer)
    {
        if (integer.Length > 0 && (integer[0] & 0x80) != 0)
            throw new SshKeyException("its explicit ECDSA curve parameters contain a negative integer, so not a supported curve.");
        return Trim(integer);
    }

    private static byte[] Trim(ReadOnlySpan<byte> value)
    {
        var start = 0;
        while (start < value.Length - 1 && value[start] == 0)
            start++;
        return value[start..].ToArray();
    }

    /// <summary>The supported curves' domain parameters (SEC 2 / FIPS 186), leading zeros trimmed; G uncompressed.</summary>
    private static readonly (SshKeyType Type, byte[] P, byte[] A, byte[] B, byte[] G, byte[] N)[] KnownCurves =
    [
        (SshKeyType.EcdsaP256,
            Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            Convert.FromHexString("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")),
        (SshKeyType.EcdsaP384,
            Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
            Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),
            Convert.FromHexString("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
            Convert.FromHexString("04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),
            Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")),
        (SshKeyType.EcdsaP521,
            Convert.FromHexString("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            Convert.FromHexString("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"),
            Convert.FromHexString("51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
            Convert.FromHexString("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
            Convert.FromHexString("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")),
    ];

    /// <summary>
    /// ECPrivateKey (RFC 5915): version 1, the private key d, optional <c>[0]</c> parameters (which must
    /// name the same curve) and optional <c>[1]</c> public key. Q is derived from d; every public key
    /// the file carries (here and in OneAsymmetricKey's <c>[1]</c>) must equal it.
    /// </summary>
    private static SshPrivateKey ParseEcPrivateKey(SshKeyType type, byte[] encoded, byte[]? outerPublic)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        if (sequence.ReadInteger() != 1)
            throw new SshWireException("ECPrivateKey version is not 1");
        var d = sequence.ReadOctetString();
        try
        {
            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Context0))
            {
                var parameters = sequence.ReadSequence(Context0);
                if (ReadEcParameters(parameters) != type)
                    throw new SshKeyException("its ECPrivateKey names another curve than its algorithm identifier.");
                parameters.ThrowIfNotEmpty();
            }
            byte[]? innerPublic = null;
            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Context1Constructed))
            {
                var wrapped = sequence.ReadSequence(Context1Constructed);
                innerPublic = ReadBitString(wrapped);
                wrapped.ThrowIfNotEmpty();
            }
            sequence.ThrowIfNotEmpty();
            var (_, curve, size, _) = SshPublicKey.Curve(type);
            var magnitude = Trim(d);
            try
            {
                if (magnitude.Length > size)
                    throw new SshWireException("ECDSA private key longer than the curve");
                var key = FromEcdsaD(type, curve, size, magnitude);
                foreach (var embedded in new[] { innerPublic, outerPublic })
                {
                    if (embedded is not null && !PointMatches(embedded, key.PublicBlob, type))
                    {
                        key.Dispose();
                        throw new SshKeyException("its embedded public key differs from the public key derived from its private key.");
                    }
                }
                return key;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(magnitude);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(d);
        }
    }

    /// <summary>Whether an embedded SEC1 point (uncompressed, or compressed: X and Y's parity) is the derived key's Q.</summary>
    private static bool PointMatches(byte[] point, byte[] derivedBlob, SshKeyType type)
    {
        var size = SshPublicKey.Curve(type).Size;
        var parsed = SshPublicKey.Parse(derivedBlob);
        if (point.Length == 1 + 2 * size && point[0] == 0x04)
            return point.AsSpan(1, size).SequenceEqual(parsed.QX) && point.AsSpan(1 + size).SequenceEqual(parsed.QY);
        if (point.Length == 1 + size && point[0] is 0x02 or 0x03)
            return point.AsSpan(1).SequenceEqual(parsed.QX) && (parsed.QY![^1] & 1) == (point[0] & 1);
        return false;
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
        if (_seed is not null)
            CryptographicOperations.ZeroMemory(_seed);
        _seed = null;
        _ecdsa?.Dispose();
        _ecdsa = null;
        _rsa?.Dispose();
        _rsa = null;
    }
}
