using System.Text.RegularExpressions;

namespace TswapCore;

/// <summary>
/// Replaces secret values (including any surrounding quotes) with <c>""  # tswap: name</c>.
/// Used by <c>tswap tocomment</c> to convert files with inline secrets to the marker format
/// that <c>tswap check</c> and <c>tswap run</c> understand; the matching is
/// <see cref="SecretMatcher.ToComment"/>'s, with the context rules below.
/// </summary>
public static class ToCommentProcessor
{
    // Optionally consume an existing tswap marker immediately following the value. This prevents
    // duplication when processing `tswap apply` output, which emits lines like:
    // key: "actual-secret"  # tswap: secret-name
    private const string ExistingMarker = @"(?:\s*#\s*tswap\s*:\s*[a-zA-Z0-9_-]+(?::previous)?)?";

    /// <summary>
    /// The value <paramref name="searchText"/> double-quoted, single-quoted, or unquoted, each as its
    /// own pattern anchored at the start position (<c>\G</c>), in the order the one regex tried them.
    /// The lookbehind/lookahead keep a secret from matching inside a larger value: it must not be
    /// preceded or followed by a dash or word character, so "myapp" doesn't match in "myapp-database".
    /// <para>
    /// Known limitation: a secret appearing in prose still matches if surrounded by spaces (e.g.
    /// "description: contact myapp support" would match "myapp"). This is acceptable since prose is
    /// rarely found in YAML value positions, and requiring colon-space context would fail on valid
    /// YAML like flow sequences or compact mappings.
    /// </para>
    /// </summary>
    internal static Regex[] AnchoredPatterns(string searchText)
    {
        var escaped = Regex.Escape(searchText);
        return
        [
            new($"\\G(?<![-\\w])\"{escaped}\"{ExistingMarker}(?![-\\w])"),
            new($"\\G(?<![-\\w])'{escaped}'{ExistingMarker}(?![-\\w])"),
            new($"\\G(?<![-\\w]){escaped}{ExistingMarker}(?![-\\w])"),
        ];
    }

    /// <summary>What a match of <paramref name="token"/> becomes.</summary>
    internal static string Replacement(string token) => $"\"\"  # tswap: {token}";

    /// <summary>
    /// The continuation lines of line <paramref name="index"/> (whose text before the replacement was
    /// <paramref name="original"/>): the following lines indented deeper that look like base64, so a
    /// value spanning several lines (a long base64 string formatted for readability) leaves no
    /// trailing garbage. Called only after a replacement on that line.
    /// </summary>
    internal static IEnumerable<int> ContinuationLines(string[] lines, int index, string original)
    {
        var baseIndent = LeadingWhitespace(original);
        for (var j = index + 1; j < lines.Length; j++)
        {
            var next = lines[j];
            if (string.IsNullOrWhiteSpace(next) || LeadingWhitespace(next) <= baseIndent || !IsLikelyBase64(next.Trim()))
                yield break;
            yield return j;
        }
    }

    /// <summary>A strict base64 heuristic: at least 16 characters, 95% of them from the standard base64 set.</summary>
    private static bool IsLikelyBase64(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length < 16)
            return false;
        var valid = value.Count(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=');
        return (double)valid / value.Length >= 0.95;
    }

    private static int LeadingWhitespace(string line)
    {
        var count = 0;
        while (count < line.Length && char.IsWhiteSpace(line[count]))
            count++;
        return count;
    }
}
