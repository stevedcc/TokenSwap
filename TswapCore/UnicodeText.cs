namespace TswapCore;

/// <summary>
/// Brief T54: Unicode checks shared by the paths that normalise text. <see cref="string.Normalize()"/> throws on a
/// lone surrogate, so every path that normalises a string which can hold one asks <see cref="FindLoneSurrogate"/>
/// first (text from a strict UTF-8 decode, as the FIDO2 PIN's and the broker's, can't hold one and needs no check).
/// </summary>
internal static class UnicodeText
{
    /// <summary>The first surrogate without its partner, anywhere in <paramref name="text"/>, or null.</summary>
    public static int? FindLoneSurrogate(ReadOnlySpan<char> text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                i++;
            else if (char.IsSurrogate(text[i]))
                return text[i];
        }
        return null;
    }
}
