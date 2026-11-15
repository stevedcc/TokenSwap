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

    // Brief T20 (#315): a mapping key ending in ':', then '|', '|-' or '|+' and nothing else. An
    // indentation indicator ('|2') and folded '>' scalars are out of scope and never match.
    private static readonly Regex LiteralBlockKey = new(@"^(\s*)([^#\s][^#]*?:)\s*\|([+-]?)\s*$");

    /// <summary>
    /// Brief T20: a literal block scalar starting at a key line — the key line's indentation and key,
    /// its lines (<see cref="FirstLine"/> up to, not including, <see cref="EndLine"/>, 0-based) and the
    /// value it holds after chomping (<see cref="Candidate"/>).
    /// </summary>
    internal sealed record LiteralBlock(string Indent, string Key, int FirstLine, int EndLine, string Candidate);

    /// <summary>
    /// Brief T20: the literal block scalar whose key line is line <paramref name="index"/>, or null when
    /// that line is no such key, there is no block (no non-blank line after it, or the first one is not
    /// indented deeper than the key), or YAML would end the block on a line indented between the key and
    /// the content (then the block is not adopted). <paramref name="lines"/> is the file split on LF; a
    /// final empty element (the file's last newline) is not a line.
    /// </summary>
    internal static LiteralBlock? LiteralBlockAt(string[] lines, int index)
    {
        var key = LiteralBlockKey.Match(lines[index]);
        if (!key.Success)
            return null;
        var limit = lines.Length > 0 && lines[^1].Length == 0 ? lines.Length - 1 : lines.Length;
        var keyIndent = LeadingWhitespace(lines[index]);

        // The content indentation: the leading whitespace of the first non-blank line after the key.
        var first = index + 1;
        while (first < limit && IsBlank(lines[first]))
            first++;
        if (first >= limit)
            return null;
        var contentIndent = LeadingWhitespace(lines[first]);
        if (contentIndent <= keyIndent)
            return null;

        // One walk: blank lines and lines indented at least the content belong; the first line indented
        // less ends the block, and one still deeper than the key means YAML ends it there: not adopted.
        var end = index + 1;
        for (; end < limit; end++)
        {
            var line = lines[end];
            if (IsBlank(line))
                continue;
            var indent = LeadingWhitespace(line);
            if (indent >= contentIndent)
                continue;
            if (indent > keyIndent)
                return null;
            break;
        }

        var value = new System.Text.StringBuilder();
        for (var j = index + 1; j < end; j++)
        {
            if (!IsBlank(lines[j]))
                value.Append(lines[j], contentIndent, lines[j].Length - contentIndent);
            value.Append('\n');
        }
        return new LiteralBlock(key.Groups[1].Value, key.Groups[2].Value, index + 1, end, Chomp(value.ToString(), key.Groups[3].Value));
    }

    /// <summary>YAML chomping: <c>-</c> strips every trailing LF, none (clip) keeps exactly one, <c>+</c> keeps them all.</summary>
    private static string Chomp(string value, string indicator) => indicator switch
    {
        "-" => value.TrimEnd('\n'),
        "+" => value,
        _ => value.TrimEnd('\n') + "\n",
    };

    private static bool IsBlank(string line) => string.IsNullOrWhiteSpace(line);

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

/// <summary>
/// Brief T20 (#315): a removed line of a literal block scalar <c>tocomment</c> adopted. Its text is a
/// fragment of the secret (the redactor masks only complete occurrences), so <c>--dry-run</c> never
/// prints it: <c>- [removed block line]</c>.
/// </summary>
public sealed record BlockLineDiff(int LineNumber, string Before) : LineDiff(LineNumber, Before, "");
