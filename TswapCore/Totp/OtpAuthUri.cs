namespace TswapCore.Totp;

/// <summary>
/// Brief T58, decision D1: recognition of otpauth records is generous, the parse (<see cref="TotpSeed.FromUri"/>) strict.
/// A value is an otpauth record when it contains <c>otpauth:</c> or <c>otpauth-migration:</c> (brief T65, #436).
/// Recognition never decodes anything (no percent-decoding, base64 or protobuf).
/// </summary>
public static class OtpAuthUri
{
    private const string ExportMarker = "otpauth-migration:";

    /// <summary>
    /// True when <paramref name="value"/> contains <c>otpauth:</c> or <c>otpauth-migration:</c> (brief T65, #436)
    /// anywhere, case ignored. <c>otpauth:</c> is compared with <see cref="StringComparison.OrdinalIgnoreCase"/>, as
    /// before; <c>otpauth-migration:</c> with ASCII letters case-insensitive and every other character exact, the rule
    /// the byte overload applies, so that the string and byte forms agree on every value.
    /// </summary>
    public static bool IsOtpAuth(string value) =>
        value.Contains("otpauth:", StringComparison.OrdinalIgnoreCase) || IsExportLink(value);

    /// <summary>
    /// Brief T65 (#436): true when <paramref name="value"/> contains <c>otpauth-migration:</c> (an authenticator's
    /// export link), ASCII letters in either case and every other character exact. Nothing after the marker is read.
    /// </summary>
    internal static bool IsExportLink(string value)
    {
        for (var start = 0; start + ExportMarker.Length <= value.Length; start++)
        {
            var i = 0;
            while (i < ExportMarker.Length && MatchesMarker(value[start + i], ExportMarker[i]))
                i++;
            if (i == ExportMarker.Length)
                return true;
        }
        return false;
    }

    /// <summary>
    /// <see cref="IsOtpAuth(string)"/> on a value's UTF-8 bytes, without making a string of it (the broker zeroes the
    /// bytes it refuses). The markers are ASCII, and no byte of a multi-byte UTF-8 sequence is ASCII.
    /// </summary>
    public static bool IsOtpAuth(ReadOnlySpan<byte> utf8) =>
        Contains(utf8, "otpauth:"u8) || Contains(utf8, "otpauth-migration:"u8);

    // Brief T65 (#436): only the bytes A-Z are folded to lower case; folding every byte with | 0x20 would let a CR
    // (0x0D | 0x20 = '-') match the '-' of otpauth-migration:.
    private static bool Contains(ReadOnlySpan<byte> utf8, ReadOnlySpan<byte> marker)
    {
        for (var start = 0; start + marker.Length <= utf8.Length; start++)
        {
            var i = 0;
            while (i < marker.Length && MatchesMarker((char)utf8[start + i], (char)marker[i]))
                i++;
            if (i == marker.Length)
                return true;
        }
        return false;
    }

    /// <summary>
    /// <paramref name="c"/> is <paramref name="m"/> (a lower-case marker character), or an ASCII upper-case letter whose
    /// lower case is <paramref name="m"/>.
    /// </summary>
    private static bool MatchesMarker(char c, char m) => c == m || (c is >= 'A' and <= 'Z' && (char)(c | 0x20) == m);

    /// <summary>The broker's refusal of an otpauth record (decision D8).</summary>
    public static string BrokerRefusal(string name) =>
        $"secret '{name}' is a TOTP seed (an otpauth:// URI); the broker doesn't hand out TOTP seeds";
}
