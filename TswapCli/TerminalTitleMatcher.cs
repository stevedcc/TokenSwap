using RedactingPty;

namespace TswapCli;

/// <summary>
/// Brief T35 Task 4 (#349): drops window-title sequences from a child's output on a Windows console: OSC 0, 1 and 2,
/// <c>ESC ] n ; text BEL</c> or <c>ESC ] n ; text ESC \</c>, each replaced by nothing. With VT processing on, the
/// pseudo console's OSC 0 would retitle the window to the child's path and outlive <c>run</c>. Any other OSC
/// (hyperlinks, colours) and every CSI sequence passes; so does an unterminated or overlong title, as text. A secret
/// inside a title goes with it (the redactor merges overlapping matches under the longest one's label).
/// Stateless and thread-safe, as <see cref="IStreamMatcher"/> requires.
/// </summary>
internal sealed class TerminalTitleMatcher : IStreamMatcher
{
    /// <summary>The longest title text matched, in UTF-16 code units.</summary>
    public const int MaxTitleLength = 4096;

    private const char Esc = '\u001b';
    private const char Bel = '\u0007';

    // ESC ] n ; before the text, ESC \ after it.
    private const int PrefixLength = 4;

    /// <inheritdoc />
    public int MaxMatchLength => MaxTitleLength + 6;

    /// <inheritdoc />
    public void FindMatches(ReadOnlySpan<char> window, ICollection<StreamMatch> matches)
    {
        var from = 0;
        while (from < window.Length)
        {
            var next = window[from..].IndexOf(Esc);
            if (next < 0)
                return;
            var start = from + next;
            if (IsTitleStart(window, start) && TitleEnd(window, start) is { } end)
            {
                matches.Add(new StreamMatch(start, end - start, ""));
                from = end;
            }
            else
            {
                from = start + 1;
            }
        }
    }

    /// <summary>
    /// The start of a trailing title sequence not terminated yet (a final ESC, or <c>ESC ]</c>, <c>ESC ] n</c>,
    /// <c>ESC ] n ;</c> and text with no BEL or ESC, perhaps ending in the terminator's ESC), else the window's
    /// length. Never the interface's default hold: RedactingPty's WindowsPty ignores <c>ReleaseWhenAwaitingInput</c>,
    /// so holding the last 4 KB would keep a prompt such as <c>[Y,N]?</c> from the user.
    /// </summary>
    public int PendingFrom(ReadOnlySpan<char> window)
    {
        for (var start = Math.Max(0, window.Length - (MaxMatchLength - 1)); start < window.Length; start++)
            if (window[start] == Esc && IsIncompleteTitle(window[start..]))
                return start;
        return window.Length;
    }

    private static bool IsTitleNumber(char c) => c is '0' or '1' or '2';

    private static bool IsTitleStart(ReadOnlySpan<char> window, int start) =>
        start + PrefixLength <= window.Length && window[start + 1] == ']' && IsTitleNumber(window[start + 2]) && window[start + 3] == ';';

    // The index just past the terminator of the title starting at `start`, or null (no terminator in the window,
    // an ESC that doesn't start ESC \, or text longer than MaxTitleLength).
    private static int? TitleEnd(ReadOnlySpan<char> window, int start)
    {
        var textStart = start + PrefixLength;
        var limit = Math.Min(window.Length, textStart + MaxTitleLength + 1);
        for (var i = textStart; i < limit; i++)
        {
            if (window[i] == Bel)
                return i + 1;
            if (window[i] == Esc)
                return i + 1 < window.Length && window[i + 1] == '\\' ? i + 2 : null;
        }
        return null;
    }

    // `tail` starts with ESC and runs to the window's end: could more output still complete it as a title?
    private static bool IsIncompleteTitle(ReadOnlySpan<char> tail)
    {
        if (tail.Length == 1)
            return true;
        if (tail[1] != ']')
            return false;
        if (tail.Length == 2)
            return true;
        if (!IsTitleNumber(tail[2]))
            return false;
        if (tail.Length == 3)
            return true;
        if (tail[3] != ';')
            return false;
        var text = tail[PrefixLength..];
        // A final ESC may be the start of the ESC \ terminator; it doesn't count as text.
        if (text.Length > 0 && text[^1] == Esc)
            text = text[..^1];
        return text.Length <= MaxTitleLength && text.IndexOfAny(Bel, Esc) < 0;
    }
}
