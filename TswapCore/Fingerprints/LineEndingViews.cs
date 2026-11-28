namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T50a (#398): the line-ending views a text is matched in besides the raw text, built in one place so
/// <c>redact</c> (<see cref="SecretMatcher"/>) and <c>run</c>'s scanner (<see cref="FingerprintScanner"/>) map spans
/// back to the raw text the same way.
/// <list type="bullet">
/// <item>The <b>folded</b> view (when the text holds a <c>\r\n</c>): each <c>\r\n</c> as <c>\n</c>. A folded
/// <c>\n</c> maps to the raw <c>\r\n</c> (two raw characters).</item>
/// <item>The <b>unfolded</b> view (when the text holds a <c>\n</c> not preceded by <c>\r</c>, one at index 0
/// included): each such <c>\n</c> as <c>\r\n</c>. The inserted <c>\r</c> maps to the empty position just before
/// its raw <c>\n</c> (zero raw characters); the <c>\n</c> after it to itself.</item>
/// </list>
/// Every other view character maps to itself. A view index <c>i</c> maps to the raw range
/// <c>[rawStart[i], rawEnd[i])</c>; a hit over view indices <c>[s, s + L)</c> has the raw span
/// <c>[rawStart[s], rawEnd[s + L − 1])</c>. A hit holds a folded <c>\n</c> or an inserted <c>\r</c> exactly when
/// its raw length differs from <c>L</c>. Brief T65 (#434): <see cref="WriteBreaks"/> builds the views with every
/// break written as <c>\n</c>, <c>\r\n</c> or <c>\r</c>, for the fingerprint matchers; <c>tocomment</c> keeps the two
/// views above.
/// </summary>
internal static class LineEndingViews
{
    /// <summary>Whether <paramref name="text"/> has a folded view (it holds a <c>\r\n</c>).</summary>
    public static bool HasCrLf(ReadOnlySpan<char> text) => text.Contains("\r\n", StringComparison.Ordinal);

    /// <summary>Whether <paramref name="text"/> has an unfolded view (a <c>\n</c> not preceded by <c>\r</c>).</summary>
    public static bool HasBareLf(ReadOnlySpan<char> text)
    {
        for (var i = text.IndexOf('\n'); i >= 0; i = NextLf(text, i))
        {
            if (i == 0 || text[i - 1] != '\r')
                return true;
        }
        return false;
    }

    /// <summary>
    /// Brief T65 (#434): whether some <c>\r</c> of <paramref name="text"/> is its last character or is followed by a
    /// character other than <c>\n</c>.
    /// </summary>
    public static bool HasLoneCr(ReadOnlySpan<char> text)
    {
        for (var i = text.IndexOf('\r'); i >= 0; i = NextCr(text, i))
        {
            if (i + 1 == text.Length || text[i + 1] != '\n')
                return true;
        }
        return false;
    }

    /// <summary>
    /// Brief T65 (#434): writes <paramref name="text"/> with every line break (<c>\r\n</c>, a lone <c>\r</c>, a
    /// <c>\n</c>) written as <paramref name="lineBreak"/> (<c>"\n"</c>, <c>"\r\n"</c> or <c>"\r"</c>) into
    /// <paramref name="view"/> (at least <c>2 * text.Length</c> long, as are the maps) and returns its length; the
    /// view is <see cref="WithLineBreaks"/>' text. A break written as one character maps to its whole raw break; a raw
    /// <c>\r\n</c> written as <c>\r\n</c> maps character for character; an inserted <c>\n</c> after a lone <c>\r</c>
    /// maps to the empty position after it, an inserted <c>\r</c> before a <c>\n</c> to the empty position before it.
    /// Every other character maps to itself.
    /// </summary>
    public static int WriteBreaks(ReadOnlySpan<char> text, string lineBreak, Span<char> view, Span<int> rawStart, Span<int> rawEnd)
    {
        if (lineBreak is not ("\n" or "\r\n" or "\r"))
            throw new ArgumentException("the line break must be \\n, \\r\\n or \\r", nameof(lineBreak));
        var crLf = lineBreak.Length == 2;
        var m = 0;
        void Put(char c, int start, int end, Span<char> view, Span<int> rawStart, Span<int> rawEnd)
        {
            view[m] = c;
            rawStart[m] = start;
            rawEnd[m] = end;
            m++;
        }
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            var pair = c == '\r' && i + 1 < text.Length && text[i + 1] == '\n';
            if (c is not ('\r' or '\n'))
                Put(c, i, i + 1, view, rawStart, rawEnd);
            else if (!crLf)
                Put(lineBreak[0], i, pair ? i + 2 : i + 1, view, rawStart, rawEnd);
            else if (pair)
            {
                Put('\r', i, i + 1, view, rawStart, rawEnd);
                Put('\n', i + 1, i + 2, view, rawStart, rawEnd);
            }
            else if (c == '\r')
            {
                Put('\r', i, i + 1, view, rawStart, rawEnd);
                Put('\n', i + 1, i + 1, view, rawStart, rawEnd);
            }
            else
            {
                Put('\r', i, i, view, rawStart, rawEnd);
                Put('\n', i, i + 1, view, rawStart, rawEnd);
            }
            if (pair)
                i++;
        }
        return m;
    }

    /// <summary>
    /// Writes the folded view of <paramref name="text"/> into <paramref name="view"/> (at least
    /// <c>text.Length</c> long, as are the maps) and returns its length.
    /// </summary>
    public static int Fold(ReadOnlySpan<char> text, Span<char> view, Span<int> rawStart, Span<int> rawEnd)
    {
        var n = text.Length;
        var m = 0;
        for (var i = 0; i < n; i++)
        {
            // A folded "\n" stands for the raw "\r\n": its raw span starts at the "\r".
            var pair = text[i] == '\r' && i + 1 < n && text[i + 1] == '\n';
            view[m] = pair ? '\n' : text[i];
            rawStart[m] = i;
            if (pair) i++;
            rawEnd[m] = i + 1;
            m++;
        }
        return m;
    }

    /// <summary>
    /// Writes the unfolded view of <paramref name="text"/> into <paramref name="view"/> (at least
    /// <c>2 * text.Length</c> long, as are the maps) and returns its length.
    /// </summary>
    public static int Unfold(ReadOnlySpan<char> text, Span<char> view, Span<int> rawStart, Span<int> rawEnd)
    {
        var m = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r'))
            {
                // The inserted '\r': the empty position just before its raw '\n'.
                view[m] = '\r';
                rawStart[m] = i;
                rawEnd[m] = i;
                m++;
            }
            view[m] = text[i];
            rawStart[m] = i;
            rawEnd[m] = i + 1;
            m++;
        }
        return m;
    }

    /// <summary>
    /// Brief T63 (#412): <paramref name="text"/> with every line break (<c>\r\n</c>, a lone <c>\r</c>, a bare
    /// <c>\n</c>, in any mix) written as <paramref name="lineBreak"/>. <see cref="WriteBreaks"/> builds the same text
    /// with span maps, for the fingerprint matchers; this form is for checks that compare whole spellings (the field
    /// check).
    /// </summary>
    internal static string WithLineBreaks(string text, string lineBreak)
    {
        if (text.AsSpan().IndexOfAny('\r', '\n') < 0)
            return text;
        var sb = new System.Text.StringBuilder(text.Length + lineBreak.Length);
        for (var i = 0; i < text.Length; i++)
        {
            switch (text[i])
            {
                case '\r':
                    if (i + 1 < text.Length && text[i + 1] == '\n')
                        i++;
                    sb.Append(lineBreak);
                    break;
                case '\n':
                    sb.Append(lineBreak);
                    break;
                default:
                    sb.Append(text[i]);
                    break;
            }
        }
        return sb.ToString();
    }

    private static int NextCr(ReadOnlySpan<char> text, int from)
    {
        var next = text[(from + 1)..].IndexOf('\r');
        return next < 0 ? -1 : from + 1 + next;
    }

    private static int NextLf(ReadOnlySpan<char> text, int from)
    {
        var next = text[(from + 1)..].IndexOf('\n');
        return next < 0 ? -1 : from + 1 + next;
    }
}
