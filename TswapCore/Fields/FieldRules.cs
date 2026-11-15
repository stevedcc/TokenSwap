using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace TswapCore.Fields;

/// <summary>
/// What a field may be (issue #311, spec "Fields"): names, value characters and length, the formats
/// of the well-known fields <c>kind</c> and <c>expires</c>, and the per-secret caps. Every check
/// returns null when the input is allowed, otherwise the refusal message.
/// </summary>
public static partial class FieldRules
{
    /// <summary>The most characters (Unicode scalar values, after NFC) a field value may have.</summary>
    public const int MaxValueLength = 4096;

    /// <summary>The most live fields a secret may have (delete markers don't count).</summary>
    public const int MaxLiveFields = 64;

    /// <summary>The most bytes a secret's encoded <c>Fields</c> extension may take (64 KiB, markers included).</summary>
    public const int MaxEncodedBytes = 64 * 1024;

    /// <summary>The values the well-known field <c>kind</c> takes.</summary>
    public static IReadOnlyList<string> KnownKinds { get; } =
        ["password", "token", "api-key", "private-key", "certificate", "connection-string", "other"];

    [GeneratedRegex("^[a-z0-9_-]{1,64}$")]
    private static partial Regex NamePattern();

    // ASCII digits only: \d would accept other scripts' digits.
    [GeneratedRegex("^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)?$")]
    private static partial Regex ExpiresPattern();

    /// <summary>
    /// <paramref name="value"/> in Unicode normal form C, as it is checked and stored. A value with a
    /// lone surrogate can't be normalised; it comes back unchanged, for <see cref="ValidateValue"/> to refuse.
    /// </summary>
    public static string NormaliseValue(string value) =>
        FindRefused(value) is { IsSurrogate: true } ? value : value.Normalize(NormalizationForm.FormC);

    /// <summary>
    /// The character rules and the length cap for a value (also a <c>--by</c> label), after
    /// <see cref="NormaliseValue"/>: line feeds are allowed, every other control (Cc), format (Cf),
    /// surrogate (Cs) or private-use (Co) character is refused, naming its code point.
    /// </summary>
    public static string? ValidateValue(string value)
    {
        var normalised = NormaliseValue(value);
        if (FindRefused(normalised) is { } refused)
            return $"The value contains {refused.CodePoint} ({refused.Kind}); a field holds no control, format, " +
                "surrogate or private-use characters other than a line feed.";
        var length = CountScalars(normalised);
        if (length > MaxValueLength)
            return $"The value has {length} characters; a field holds at most {MaxValueLength}.";
        return null;
    }

    /// <summary>
    /// The name rules, then <see cref="ValidateValue"/>, then the format of a well-known field
    /// (<c>kind</c>, <c>expires</c>); the message names the field.
    /// </summary>
    public static string? Validate(string name, string value)
    {
        if (!NamePattern().IsMatch(name))
            return $"Refused field name '{Escape(name)}': a field name is 1-64 characters of a-z, 0-9, '_' and '-'.";
        if (ValidateValue(value) is { } refusal)
            return $"Refused field '{name}': {refusal}";

        var normalised = NormaliseValue(value);
        return name switch
        {
            "kind" when !KnownKinds.Contains(normalised, StringComparer.Ordinal) =>
                $"Refused field 'kind': '{Escape(normalised)}' is not a known kind (use one of {string.Join(", ", KnownKinds)}).",
            "expires" when !IsExpires(normalised) =>
                $"Refused field 'expires': '{Escape(normalised)}' is not a date; use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ (UTC).",
            _ => null,
        };
    }

    /// <summary>
    /// The caps on a secret's fields, as a write would leave them: at most <see cref="MaxLiveFields"/>
    /// live fields and <see cref="MaxEncodedBytes"/> bytes encoded (delete markers count towards the
    /// bytes only). The caller names the secret.
    /// </summary>
    public static string? CheckCaps(FieldSet set)
    {
        var live = set.Live.Count();
        if (live > MaxLiveFields)
            return $"The secret would have {live} fields; a secret holds at most {MaxLiveFields}.";
        var bytes = FieldsCodec.Encode(set).Length;
        if (bytes > MaxEncodedBytes)
            return $"The secret's fields would take {bytes} bytes; they take at most {MaxEncodedBytes} (64 KiB).";
        return null;
    }

    private static bool IsExpires(string value) =>
        ExpiresPattern().IsMatch(value)
        && DateTime.TryParseExact(value, ["yyyy-MM-dd", "yyyy-MM-dd'T'HH:mm:ss'Z'"], CultureInfo.InvariantCulture,
            DateTimeStyles.None, out _);

    private readonly record struct Refused(string CodePoint, string Kind, bool IsSurrogate);

    /// <summary>The first character the value rules refuse, or null.</summary>
    private static Refused? FindRefused(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                var scalar = char.ConvertToUtf32(c, value[i + 1]);
                i++;
                if (KindOf(CharUnicodeInfo.GetUnicodeCategory(scalar)) is { } pairKind)
                    return new Refused(CodePoint(scalar), pairKind, false);
                continue;
            }
            if (char.IsSurrogate(c))
                return new Refused(CodePoint(c), "a lone surrogate", true);
            if (c != '\n' && KindOf(CharUnicodeInfo.GetUnicodeCategory(c)) is { } kind)
                return new Refused(CodePoint(c), kind, false);
        }
        return null;
    }

    private static string? KindOf(UnicodeCategory category) => category switch
    {
        UnicodeCategory.Control => "a control character",
        UnicodeCategory.Format => "a format character",
        UnicodeCategory.Surrogate => "a lone surrogate",
        UnicodeCategory.PrivateUse => "a private-use character",
        _ => null,
    };

    private static string CodePoint(int scalar) => $"U+{scalar:X4}";

    private static int CountScalars(string value)
    {
        var count = 0;
        foreach (var _ in value.EnumerateRunes())
            count++;
        return count;
    }

    /// <summary>A name or value for a message: anything outside printable ASCII as <c>U+XXXX</c>.</summary>
    private static string Escape(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
            builder.Append(c is >= ' ' and <= '~' ? c.ToString() : CodePoint(c));
        return builder.ToString();
    }
}
