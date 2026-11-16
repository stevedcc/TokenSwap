using System.Globalization;

namespace TswapCore.Fingerprints;

/// <summary>Brief T30 (#314): how a short value's occurrences are matched.</summary>
public enum ShortValueMatching
{
    /// <summary>Every value is matched wherever it occurs (as before T30; the fields guards and <c>tocomment</c>).</summary>
    Anywhere,

    /// <summary>
    /// A short value version (<see cref="TokenBoundary.IsShort"/>), in every form of it, only where the
    /// occurrence is delimited (<see cref="TokenBoundary.IsDelimited"/>); every other value anywhere.
    /// </summary>
    WholeToken,
}

/// <summary>
/// Brief T30 (#314): a value shorter than <see cref="Validation.ShortValueLength"/> is masked by <c>redact</c>
/// and <c>run</c> only where it stands as a whole word or number. A <em>word character</em> is what
/// tocomment's <c>[-\w]</c> matches (a letter, a non-spacing mark, a decimal digit, connector punctuation,
/// or <c>-</c>); surrogate halves are not word characters. An occurrence is delimited when, at each of its
/// ends whose character is a word character, the character beyond that end is not one (the text's start
/// and end count as non-word neighbours); an end whose character is not a word character constrains nothing.
/// Neighbours are read in the input text, never in output with other values already masked.
/// </summary>
public static class TokenBoundary
{
    /// <summary>
    /// How far back <see cref="HoldOutsideWord"/> moves a pending point to the start of the word it would
    /// split. A multiple of the scanner's 256-character quantum, independent of every value.
    /// </summary>
    public const int WordHoldLimit = 256;

    /// <summary>True for a character tocomment's <c>[-\w]</c> matches.</summary>
    public static bool IsWordChar(char c) =>
        c == '-' || CharUnicodeInfo.GetUnicodeCategory(c) is
            UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter
            or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.NonSpacingMark
            or UnicodeCategory.DecimalDigitNumber or UnicodeCategory.ConnectorPunctuation;

    /// <summary>
    /// Whether <c>text[start, start + length)</c> stands on its own: neither of its word-character ends has
    /// a word character beyond it.
    /// </summary>
    public static bool IsDelimited(ReadOnlySpan<char> text, int start, int length)
    {
        var end = start + length;
        if (length > 0 && IsWordChar(text[start]) && start > 0 && IsWordChar(text[start - 1]))
            return false;
        if (length > 0 && IsWordChar(text[end - 1]) && end < text.Length && IsWordChar(text[end]))
            return false;
        return true;
    }

    /// <summary>
    /// For a stream: a pending point that would split a run of word characters (the character before it
    /// and the one at it, or the text's end, are word characters) moves back to the start of that run, if
    /// that is at most <see cref="WordHoldLimit"/> characters back; otherwise it is returned unchanged. The
    /// next window then starts on a word's first character, where treating its start as a boundary is
    /// right. Reads the text and a constant only (the hold-back is observable through timing).
    /// </summary>
    public static int HoldOutsideWord(ReadOnlySpan<char> text, int pending)
    {
        if (pending <= 0 || pending > text.Length || !IsWordChar(text[pending - 1]))
            return pending;
        if (pending < text.Length && !IsWordChar(text[pending]))
            return pending;
        var start = pending - 1;
        var lower = Math.Max(0, pending - WordHoldLimit);
        while (start > lower && IsWordChar(text[start - 1]))
            start--;
        if (start > 0 && IsWordChar(text[start - 1]))
            return pending; // the run starts more than WordHoldLimit back
        return start;
    }

    /// <summary>
    /// Whether the value version <paramref name="set"/> fingerprints is short: its plain entry (the value's
    /// own length in UTF-16 code units) is shorter than <see cref="Validation.ShortValueLength"/>. A set
    /// without a plain entry is not short (its entries keep matching anywhere: the masking side).
    /// </summary>
    public static bool IsShort(FingerprintSet set)
    {
        ArgumentNullException.ThrowIfNull(set);
        foreach (var entry in set.Entries)
            if (entry.Kind == VariantKind.Plain)
                return entry.Length < Validation.ShortValueLength;
        return false;
    }
}
