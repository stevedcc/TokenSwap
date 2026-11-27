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
    private const string ExistingMarker = @"(?:\s*#\s*tswap\s*:\s*[a-zA-Z0-9_-]+(?::previous|:totp)?)?";

    /// <summary>
    /// The value <paramref name="searchText"/> double-quoted, single-quoted, or unquoted, each as its
    /// own pattern anchored at the start position (<c>\G</c>), in the order the one regex tried them.
    /// The lookbehind/lookahead keep a secret from matching inside a larger value: it must not be
    /// preceded or followed by a dash or word character, so "myapp" doesn't match in "myapp-database".
    /// A match is an occurrence; brief T50b (#394): the caller replaces it only where <see cref="FillsBack"/>
    /// holds, so a value in prose, a path or a command line is left (and reported), never replaced.
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

    // Brief T50b, rule (m): marker-shaped text as apply reads it, quote-blind: '#', 'tswap', ':'.
    private static readonly Regex MarkerText = new(@"#\s*tswap\s*:");

    /// <summary>
    /// Brief T50b (#394): whether an occurrence is a whole value <c>apply</c> fills back exactly, so replacing it
    /// with a marker loses nothing. All four hold, on the original text:
    /// (a) <paramref name="before"/> (the line up to the occurrence) has no <c>#</c> outside quote regions, ends
    /// outside every region and, without trailing spaces and tabs, is not empty and ends in <c>:</c> or <c>=</c>;
    /// (m) neither <paramref name="before"/> nor <paramref name="after"/> holds marker-shaped text, quoted or not;
    /// (a′) on a <c>=</c> line only an occurrence of the plain value without control characters qualifies
    /// (<paramref name="envForm"/>); (b) <paramref name="after"/> (the line after the occurrence) is empty, only
    /// spaces and tabs, or spaces/tabs and then a <c>#</c> comment. A <c># tswap:</c> marker the occurrence consumed
    /// (<paramref name="consumedMarker"/>, empty when none) counts only with a space or tab before its <c>#</c>.
    /// </summary>
    internal static bool FillsBack(string before, string consumedMarker, string after, bool envForm)
    {
        if (MarkerText.IsMatch(before) || MarkerText.IsMatch(after))
            return false;
        if (SeparatorBefore(before) is not { } separator)
            return false;
        if (separator == '=' && !envForm)
            return false;
        if (consumedMarker.Length > 0 && consumedMarker.AsSpan(0, consumedMarker.IndexOf('#')).IndexOfAny(' ', '\t') < 0)
            return false;
        var i = 0;
        while (i < after.Length && after[i] is ' ' or '\t')
            i++;
        return i == after.Length || (i > 0 && after[i] == '#');
    }

    /// <summary>
    /// Brief T50b, rule (a): the <c>:</c> or <c>=</c> that <paramref name="before"/> ends in (trailing spaces and
    /// tabs aside), or null when it ends otherwise, inside a quote region, or holds a <c>#</c> outside one. A
    /// <c>"</c> region closes at the next <c>"</c> not preceded by <c>\</c>; a <c>'</c> region at the next <c>'</c>
    /// that isn't part of <c>''</c> (the quote right after the opening one counts as such a pair, so an empty
    /// <c>''</c> stays open: fail closed).
    /// </summary>
    private static char? SeparatorBefore(string before)
    {
        char open = '\0';
        for (var i = 0; i < before.Length; i++)
        {
            var c = before[i];
            switch (open)
            {
                case '\0' when c == '#':
                    return null;
                case '\0' when c is '"':
                    open = c;
                    break;
                case '\0' when c is '\'':
                    open = c;
                    if (i + 1 < before.Length && before[i + 1] == '\'')
                        i++;
                    break;
                case '"' when c == '"' && before[i - 1] != '\\':
                    open = '\0';
                    break;
                case '\'' when c == '\'':
                    if (i + 1 < before.Length && before[i + 1] == '\'')
                        i++;
                    else
                        open = '\0';
                    break;
            }
        }
        if (open != '\0')
            return null;
        var trimmed = before.AsSpan().TrimEnd(" \t");
        return trimmed is [.., ':' or '='] ? trimmed[^1] : null;
    }

    /// <summary>
    /// Brief T50b (#394, owner decision 6): whether a secret's <b>name</b> marks it as a username (it holds
    /// <c>user</c>, <c>login</c>, <c>account</c> or <c>email</c>, ignoring case). Never decided from the value.
    /// </summary>
    public static bool IsUsernameName(string name) =>
        name.Contains("user", StringComparison.OrdinalIgnoreCase)
        || name.Contains("login", StringComparison.OrdinalIgnoreCase)
        || name.Contains("account", StringComparison.OrdinalIgnoreCase)
        || name.Contains("email", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The continuation lines of line <paramref name="index"/> (whose text before the replacement was
    /// <paramref name="original"/>): the following lines indented deeper that look like base64, so a
    /// value spanning several lines (a long base64 string formatted for readability) leaves no
    /// trailing garbage. Called only after a replacement on that line.
    /// </summary>
    internal static IEnumerable<int> ContinuationLines(string[] lines, int index, string original)
    {
        var baseIndent = Indentation.LeadingWhitespace(original);
        for (var j = index + 1; j < lines.Length; j++)
        {
            var next = lines[j];
            if (string.IsNullOrWhiteSpace(next) || Indentation.LeadingWhitespace(next) <= baseIndent || !IsLikelyBase64(next.Trim()))
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
        var keyIndent = Indentation.LeadingWhitespace(lines[index]);

        // The content indentation: the leading whitespace of the first non-blank line after the key.
        var first = index + 1;
        while (first < limit && IsBlank(lines[first]))
            first++;
        if (first >= limit)
            return null;
        var contentIndent = Indentation.LeadingWhitespace(lines[first]);
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
            var indent = Indentation.LeadingWhitespace(line);
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

    // Brief T22 (#319): a block start. After the indentation: a mapping key (LiteralBlockKey's shape), or a
    // sequence entry '- ' optionally followed by such a key; then node properties (an anchor '&name' and/or
    // a tag '!…', each followed by whitespace); then '|' or '>' with at most one chomping indicator and one
    // indentation digit in either order; then an optional ' # comment'. The node column is the key's
    // column, or the dash's for a bare '- |'. The key shape also takes a nested entry or an explicit key
    // ('- - key: |', '? key: |'); those count too, with the column of the key itself (KeyColumn).
    private static readonly Regex BlockStart = new(
        @"^\s*(?:(?<dash>-)[ ]+(?<key>[^#\s][^#]*?:)?|(?<key>[^#\s][^#]*?:))\s*(?:[&!]\S*\s+){0,2}[|>](?:[+-][1-9]?|[1-9][+-]?)?(?:\s+#.*)?\s*$");

    /// <summary>
    /// Brief T22 (#319): which lines of <paramref name="lines"/> (the file split on LF) are YAML
    /// block-scalar content: after a block start, every line that is blank or indented deeper than the
    /// start's node column, up to the first non-blank line at or left of that column. The union over every
    /// block, in one pass: a block start inside content is content and neither ends the outer block nor
    /// starts a region of its own. A final empty element (the file's last newline) is never content.
    /// </summary>
    internal static bool[] BlockScalarContent(string[] lines)
    {
        var content = new bool[lines.Length];
        var limit = lines.Length > 0 && lines[^1].Length == 0 ? lines.Length - 1 : lines.Length;
        for (var i = 0; i < limit; i++)
        {
            var start = BlockStart.Match(lines[i]);
            if (!start.Success)
                continue;
            var column = start.Groups["key"].Success ? KeyColumn(lines[i], start.Groups["key"].Index) : start.Groups["dash"].Index;
            var j = i + 1;
            for (; j < limit && (IsBlank(lines[j]) || Indentation.LeadingWhitespace(lines[j]) > column); j++)
                content[j] = true;
            i = j - 1;
        }
        return content;
    }

    /// <summary>
    /// Brief T22 (code review): the column of the key that starts at <paramref name="at"/>, past any nested
    /// sequence-entry dashes and explicit-key marks before it (<c>- - key:</c>, <c>? key:</c>), each a
    /// <c>-</c> or <c>?</c> followed by spaces. A dash with no space after it (<c>-key:</c>) is the key's own.
    /// </summary>
    private static int KeyColumn(string line, int at)
    {
        while (at + 1 < line.Length && line[at] is '-' or '?' && line[at + 1] == ' ')
        {
            at++;
            while (at < line.Length && line[at] == ' ')
                at++;
        }
        return at;
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
}

/// <summary>
/// Brief T20 (#315): a removed line of a literal block scalar <c>tocomment</c> adopted. Its text is a
/// fragment of the secret (the redactor masks only complete occurrences), so <c>--dry-run</c> never
/// prints it: <c>- [removed block line]</c>.
/// </summary>
public sealed record BlockLineDiff(int LineNumber, string Before) : LineDiff(LineNumber, Before, "");
