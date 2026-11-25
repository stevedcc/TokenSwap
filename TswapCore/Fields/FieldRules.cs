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

    // \z, not $: $ also matches before a final line feed, which would let "url\n" through.
    [GeneratedRegex("^[a-z0-9_-]{1,64}\\z")]
    private static partial Regex NamePattern();

    // ASCII digits only: \d would accept other scripts' digits. \z, not $, as for names.
    [GeneratedRegex("^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)?\\z")]
    private static partial Regex ExpiresPattern();

    /// <summary>
    /// <paramref name="value"/> in Unicode normal form C, as it is checked and stored. A value with a
    /// lone surrogate can't be normalised; it comes back unchanged, for <see cref="ValidateValue"/> to refuse.
    /// </summary>
    public static string NormaliseValue(string value) =>
        FindLoneSurrogate(value) is null ? value.Normalize(NormalizationForm.FormC) : value;

    /// <summary>What <see cref="ValidateValue"/> checks, for its message: a field value, or a <c>--by</c> label.</summary>
    public enum ValueSubject { Field, Label }

    /// <summary>
    /// The character rules and the length cap for a value (also a <c>--by</c> label, <paramref name="subject"/>
    /// <see cref="ValueSubject.Label"/>: the message then names a label; the caller checks the label's own,
    /// shorter cap first), after <see cref="NormaliseValue"/>: line feeds are allowed, every other control (Cc),
    /// format (Cf), surrogate (Cs) or private-use (Co) character is refused, naming its code point.
    /// </summary>
    public static string? ValidateValue(string value, ValueSubject subject = ValueSubject.Field)
    {
        var (noun, holder) = subject == ValueSubject.Label ? ("label", "a label") : ("value", "a field");
        // A lone surrogate anywhere is named first: such a value can't be normalised.
        if (FindLoneSurrogate(value) is { } lone)
            return Refusal(new Refused(CodePoint(lone), "a lone surrogate"), noun, holder);
        var normalised = NormaliseValue(value);
        if (FindRefused(normalised) is { } refused)
            return Refusal(refused, noun, holder);
        var length = CountScalars(normalised);
        if (length > MaxValueLength)
            return $"The {noun} has {length} characters; {holder} holds at most {MaxValueLength}.";
        return null;
    }

    private static string Refusal(Refused refused, string noun, string holder) =>
        $"The {noun} contains {refused.CodePoint} ({refused.Kind}); {holder} holds no control, format, " +
        "surrogate or private-use characters other than a line feed.";

    /// <summary>The name rules alone (for a removal, which has no value): null when allowed, otherwise the refusal.</summary>
    public static string? ValidateName(string name) =>
        NamePattern().IsMatch(name)
            ? null
            : $"Refused field name '{Escape(name)}': a field name is 1-64 characters of a-z, 0-9, '_' and '-'.";

    /// <summary>
    /// The name rules, then <see cref="ValidateValue"/>, then the format of a well-known field
    /// (<c>kind</c>, <c>expires</c>); the message names the field. No refusal shows the value: a format
    /// refusal says "the value given" (it may be a secret pasted by mistake; GLM final 1), or with
    /// <paramref name="valueOf"/> "the value of 'valueOf'": <c>field adopt</c> passes the secret it adopts
    /// from. The character and length refusals name only a code point or a count.
    /// </summary>
    public static string? Validate(string name, string value, string? valueOf = null)
    {
        if (ValidateName(name) is { } nameRefusal)
            return nameRefusal;
        if (ValidateValue(value) is { } refusal)
            return $"Refused field '{name}': {refusal}";

        var normalised = NormaliseValue(value);
        var shown = valueOf is null ? "the value given" : $"the value of '{valueOf}'";
        return name switch
        {
            "kind" when !KnownKinds.Contains(normalised, StringComparer.Ordinal) =>
                $"Refused field 'kind': {shown} is not a known kind (use one of {string.Join(", ", KnownKinds)}).",
            "expires" when !IsExpires(normalised) =>
                $"Refused field 'expires': {shown} is not a date; use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ (UTC).",
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

    private readonly record struct Refused(string CodePoint, string Kind);

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
                    return new Refused(CodePoint(scalar), pairKind);
                continue;
            }
            if (char.IsSurrogate(c))
                return new Refused(CodePoint(c), "a lone surrogate");
            if (c != '\n' && KindOf(CharUnicodeInfo.GetUnicodeCategory(c)) is { } kind)
                return new Refused(CodePoint(c), kind);
        }
        return null;
    }

    /// <summary>The first surrogate without its partner, anywhere in the value, or null.</summary>
    private static int? FindLoneSurrogate(string value) => UnicodeText.FindLoneSurrogate(value);

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

    /// <summary>
    /// A name or value for a message: anything outside printable ASCII as <c>U+XXXX</c>, one per Unicode scalar
    /// (an astral character is one <c>U+XXXXX</c>); a lone surrogate by its code unit.
    /// </summary>
    public static string Escape(string text)
    {
        var builder = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c is >= ' ' and <= '~')
                builder.Append(c);
            else if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                builder.Append(CodePoint(char.ConvertToUtf32(c, text[++i])));
            else
                builder.Append(CodePoint(c));
        }
        return builder.ToString();
    }
}
