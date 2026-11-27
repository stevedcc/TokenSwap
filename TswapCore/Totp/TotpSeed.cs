using System.Security.Cryptography;
using System.Text;
using OtpNet;

namespace TswapCore.Totp;

/// <summary>The three HMAC algorithms the Key Uri Format allows.</summary>
public enum TotpAlgorithm
{
    Sha1,
    Sha256,
    Sha512,
}

/// <summary>
/// Brief T58 (#374): a parsed TOTP seed, its key bytes, algorithm, digits and period. Disposing it zeroes the key bytes it
/// holds; Otp.NET's internal copy of the key can't be zeroed, like the resolved strings <c>VaultView</c> keeps.
/// The parse is tswap's own (input validation, not crypto), from the Key Uri Format (google/google-authenticator wiki),
/// RFC 3986 and RFC 4648; only canonical Base32 text reaches Otp.NET's lax <see cref="Base32Encoding.ToBytes"/>.
/// Every refusal is a <see cref="TotpSeedException"/> with one of the fixed reasons below and nothing of the value.
/// </summary>
public sealed class TotpSeed : IDisposable
{
    internal const string R0 = "the value holds an otpauth URI among other text; store the URI alone";
    internal const string R0Space =
        "a space is not allowed in an otpauth URI; store the URI alone, with any space in the label or issuer written as %20";
    internal const string R1 = "the URI doesn't start with otpauth://";
    internal const string R2 = "HOTP (counter-based) URIs aren't supported";
    internal const string R3 = "the URI's type isn't totp";
    internal const string R4 = "a '#' fragment isn't allowed";
    internal const string R5 = "the secret parameter is missing";
    internal static string R6(string known) => $"parameter names are lower case: '{known}'";
    internal static string R7(string known) => $"the parameter '{known}' appears more than once";
    internal static string R8(string known) => $"the parameter '{known}' has no value";
    internal const string R9 = "a parameter has a malformed percent-encoding";
    internal const string R10 = "algorithm must be SHA1, SHA256 or SHA512 (or SHA-1, SHA-256, SHA-512)";
    internal const string R11 = "digits must be 6 or 8";
    internal const string R12 = "period must be a whole number of seconds from 1 to 300";
    internal const string R14 = "the secret parameter contains a space (a URI's secret is Base32 without spaces)";
    internal const string B1 = "the seed isn't Base32 (letters A-Z, digits 2-7, '=' padding)";
    internal const string B2 = "the seed's length isn't a Base32 length";
    internal const string B3 = "the seed's '=' padding is wrong";
    internal const string B4 = "the seed isn't canonical Base32 (its last character has unused bits set)";
    internal const string B5 = "the seed is shorter than 16 Base32 characters (80 bits)";

    private const int MinimumSeedCharacters = 16;
    private static readonly string[] KnownNames = ["secret", "algorithm", "digits", "period"];
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly byte[] _key;

    private TotpSeed(byte[] key, TotpAlgorithm algorithm, int digits, int period, string canonicalBase32,
        string? secretAsWritten, string? secretDecoded)
    {
        _key = key;
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
        CanonicalBase32 = canonicalBase32;
        SecretAsWritten = secretAsWritten;
        SecretDecoded = secretDecoded;
    }

    /// <summary>The key bytes (the live array, zeroed by <see cref="Dispose"/>).</summary>
    public byte[] KeyBytes => _key;

    public TotpAlgorithm Algorithm { get; }

    /// <summary>6 or 8.</summary>
    public int Digits { get; }

    /// <summary>Seconds, 1 to 300.</summary>
    public int Period { get; }

    /// <summary>The seed as upper-case Base32 without padding (for a bare seed: after removing spaces).</summary>
    public string CanonicalBase32 { get; }

    /// <summary>The URI's <c>secret</c> parameter text as written, before percent-decoding; null for a bare seed.</summary>
    public string? SecretAsWritten { get; }

    /// <summary>The URI's <c>secret</c> parameter text percent-decoded; null for a bare seed.</summary>
    public string? SecretDecoded { get; }

    /// <summary><see cref="CanonicalBase32"/> with the <c>=</c> padding RFC 4648 gives its length.</summary>
    public string PaddedBase32 => CanonicalBase32 + new string('=', PaddingFor(CanonicalBase32.Length % 8));

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);

    /// <summary>Parses an <c>otpauth://totp/</c> URI (the value trimmed of white space at both ends).</summary>
    public static TotpSeed FromUri(string value)
    {
        var text = value.Trim();
        if (!text.StartsWith("otpauth:", StringComparison.OrdinalIgnoreCase)) throw new TotpSeedException(R0);
        // Code review round 1 (controller ruling, fail closed): the value is the one URI and nothing else. A control
        // character (a line break, a tab) or a second otpauth: means more text, such as a replacement URI or notes, so
        // the first URI's code is never given from it.
        if (text.Any(char.IsControl) || text.IndexOf("otpauth:", 1, StringComparison.OrdinalIgnoreCase) >= 0)
            throw new TotpSeedException(R0);
        // Controller ruling (code review round 1): RFC 3986 allows no raw space. One in the secret's value keeps R14 (its
        // own text, checked with the values); one anywhere else is R0's space text. Fix round 3: any white space
        // (char.IsWhiteSpace: NBSP, U+2000-200A, U+2028/2029, U+3000, ...), not only U+0020; %20 is not white space.
        if (OutsideTheSecret(text).Any(char.IsWhiteSpace)) throw new TotpSeedException(R0Space);
        if (!text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)) throw new TotpSeedException(R1);

        var rest = text["otpauth://".Length..];
        var typeEnd = rest.IndexOfAny(['/', '?', '#']);
        var type = typeEnd < 0 ? rest : rest[..typeEnd];
        if (type.Equals("hotp", StringComparison.OrdinalIgnoreCase)) throw new TotpSeedException(R2);
        if (!type.Equals("totp", StringComparison.OrdinalIgnoreCase)) throw new TotpSeedException(R3);
        if (rest.Contains('#')) throw new TotpSeedException(R4);

        // The label (after '/' up to '?') is not used and not checked.
        var queryStart = rest.IndexOf('?');
        var query = queryStart < 0 ? "" : rest[(queryStart + 1)..];

        var raw = new Dictionary<string, string>(StringComparer.Ordinal);
        var decoded = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var piece in query.Split('&'))
        {
            if (piece.Length == 0) continue;
            var eq = piece.IndexOf('=');
            var name = eq < 0 ? piece : piece[..eq];
            var known = KnownNames.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (known is null) continue; // issuer, image, counter, vendor additions: ignored, not decoded
            if (!known.Equals(name, StringComparison.Ordinal)) throw new TotpSeedException(R6(known));
            if (raw.ContainsKey(known)) throw new TotpSeedException(R7(known));
            if (eq < 0) throw new TotpSeedException(R8(known));
            var rawValue = piece[(eq + 1)..];
            raw[known] = rawValue;
            decoded[known] = PercentDecode(rawValue);
        }
        if (!decoded.TryGetValue("secret", out var secret)) throw new TotpSeedException(R5);

        var algorithm = decoded.TryGetValue("algorithm", out var a) ? ParseAlgorithm(a) : TotpAlgorithm.Sha1;
        var digits = decoded.TryGetValue("digits", out var d) ? ParseDigits(d) : 6;
        var period = decoded.TryGetValue("period", out var p) ? ParsePeriod(p) : 30;
        if (secret.Contains(' ')) throw new TotpSeedException(R14);

        var canonical = CanonicalBase32Of(secret);
        return new TotpSeed(Decode(canonical), algorithm, digits, period, canonical, raw["secret"], secret);
    }

    /// <summary>
    /// Parses a bare Base32 seed (SHA1, 6 digits, period 30): U+0020 spaces are removed first (a bare seed is often
    /// written in groups), then the text is trimmed.
    /// </summary>
    public static TotpSeed FromBase32(string value)
    {
        var canonical = CanonicalBase32Of(value.Replace(" ", "", StringComparison.Ordinal).Trim());
        return new TotpSeed(Decode(canonical), TotpAlgorithm.Sha1, 6, 30, canonical, null, null);
    }

    // Code review round 1: the six spellings in ASCII only, case ignored ordinally (no culture or invariant upper-casing,
    // which would map U+017F to 'S').
    /// <summary><paramref name="text"/> with the raw values of its <c>secret</c> parameters left out.</summary>
    private static string OutsideTheSecret(string text)
    {
        var queryStart = text.IndexOf('?');
        if (queryStart < 0)
            return text;
        var pieces = text[(queryStart + 1)..].Split('&')
            .Select(p => p.StartsWith("secret=", StringComparison.Ordinal) ? "secret=" : p);
        return text[..(queryStart + 1)] + string.Join('&', pieces);
    }

    private static TotpAlgorithm ParseAlgorithm(string text)
    {
        bool Is(string spelling) => System.Text.Ascii.EqualsIgnoreCase(text, spelling);
        return Is("SHA1") || Is("SHA-1") ? TotpAlgorithm.Sha1
            : Is("SHA256") || Is("SHA-256") ? TotpAlgorithm.Sha256
            : Is("SHA512") || Is("SHA-512") ? TotpAlgorithm.Sha512
            : throw new TotpSeedException(R10);
    }

    private static int ParseDigits(string text) => text switch
    {
        "6" => 6,
        "8" => 8,
        _ => throw new TotpSeedException(R11),
    };

    private static int ParsePeriod(string text)
    {
        if (text.Length is < 1 or > 3 || !text.All(char.IsAsciiDigit)) throw new TotpSeedException(R12);
        var period = int.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
        return period is >= 1 and <= 300 ? period : throw new TotpSeedException(R12);
    }

    /// <summary>RFC 3986 2.1: <c>%</c> and two hex digits in either case; the result strict UTF-8; <c>+</c> stays <c>+</c>.</summary>
    private static string PercentDecode(string text)
    {
        if (!text.Contains('%')) return text;
        var bytes = new List<byte>(text.Length);
        var literalStart = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '%') continue;
            AddLiteral(text[literalStart..i]);
            if (i + 2 >= text.Length || !char.IsAsciiHexDigit(text[i + 1]) || !char.IsAsciiHexDigit(text[i + 2]))
                throw new TotpSeedException(R9);
            bytes.Add(Convert.ToByte(text.Substring(i + 1, 2), 16));
            i += 2;
            literalStart = i + 1;
        }
        AddLiteral(text[literalStart..]);
        try
        {
            return StrictUtf8.GetString(bytes.ToArray());
        }
        catch (DecoderFallbackException)
        {
            throw new TotpSeedException(R9);
        }

        void AddLiteral(string literal)
        {
            try
            {
                bytes.AddRange(StrictUtf8.GetBytes(literal));
            }
            catch (EncoderFallbackException)
            {
                throw new TotpSeedException(R9);
            }
        }
    }

    /// <summary>RFC 4648 section 6, checks B1 to B5 in order; returns the text upper case without padding.</summary>
    private static string CanonicalBase32Of(string text)
    {
        if (!text.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '2' and <= '7' or '='))
            throw new TotpSeedException(B1);

        var firstPad = text.IndexOf('=');
        var unpadded = firstPad < 0 ? text : text[..firstPad];
        if (unpadded.Length % 8 is 1 or 3 or 6) throw new TotpSeedException(B2);

        var run = text.Length - unpadded.Length;
        if (text.AsSpan(unpadded.Length).ContainsAnyExcept('=')) throw new TotpSeedException(B3);
        if (run > 0 && run != PaddingFor(unpadded.Length % 8)) throw new TotpSeedException(B3);

        var canonical = unpadded.ToUpperInvariant();
        var unusedBits = canonical.Length * 5 % 8;
        if (canonical.Length > 0 && (ValueOf(canonical[^1]) & ((1 << unusedBits) - 1)) != 0)
            throw new TotpSeedException(B4);

        if (canonical.Length < MinimumSeedCharacters) throw new TotpSeedException(B5);
        return canonical;
    }

    private static int ValueOf(char c) => c is >= 'A' and <= 'Z' ? c - 'A' : c - '2' + 26;

    /// <summary>The '=' run RFC 4648 gives an unpadded length with this remainder mod 8 (1, 3 and 6 are not lengths).</summary>
    private static int PaddingFor(int remainder) => remainder switch { 2 => 6, 4 => 4, 5 => 3, 7 => 1, _ => 0 };

    private static byte[] Decode(string canonical)
    {
        var key = Base32Encoding.ToBytes(canonical);
        if (key.Length != 5 * canonical.Length / 8)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException("Otp.NET decoded a canonical Base32 seed to an unexpected length.");
        }
        return key;
    }
}
