using System.Text.RegularExpressions;
using TswapCore.Fingerprints;

namespace TswapCore;

/// <summary>
/// Brief T16-S2: the engine of <c>redact</c> and <c>tocomment</c>. It finds secret values from their
/// keyed fingerprints alone (<see cref="FingerprintIndex"/>), so no value is decrypted, and replaces
/// them as the plaintext engine did, with three differences by design: nothing is matched inside
/// text it inserted (a value can never corrupt another's label or marker); <c>tocomment</c>'s quote,
/// boundary and marker checks see the original neighbours; <c>redact</c> scans the whole text, so a
/// multi-line value (a PEM key) is masked across lines.
/// <para>
/// Selection keeps today's order exactly: entries (one per matched text, token and variant) by
/// matched length descending, then the matched text ordinally, then live before burned, then token,
/// then match type; each entry's occurrences left to right, an occurrence taken when it overlaps
/// neither a span taken before nor that entry's previous taken occurrence (what one
/// <c>Regex.Replace</c> per entry did, minus matches in inserted text). All taken spans are then
/// replaced in one pass. A <c>name:previous</c> entry always counts as live, as it always has.
/// </para>
/// </summary>
/// <param name="index">The fingerprints of every value version to recognise.</param>
/// <param name="burned">Names whose current value has an outstanding burn (they lose ties to a live name).</param>
public sealed class SecretMatcher(FingerprintIndex index, IReadOnlySet<string> burned)
{
    private readonly record struct Entry(int Length, string Text, bool Burned, string Token, MatchType Type, VariantKind Kind);

    /// <summary>A taken occurrence; <see cref="Token"/> and <see cref="Kind"/> are its entry's (brief T22).</summary>
    private sealed record Span(int Start, int End, string Replacement, string Token, VariantKind Kind);

    /// <summary><c>redact</c>: every recognised value in <paramref name="content"/> replaced by its label (CRLF becomes LF).</summary>
    public string Redact(string content)
    {
        var text = content.Replace("\r\n", "\n");
        var taken = Select(text, (entry, start) => (start, start + entry.Length, RedactProcessor.Label(entry.Token, entry.Kind)));
        return Replace(text, taken);
    }

    /// <summary>
    /// <c>tocomment</c>: every recognised value (with its quotes and an existing marker) replaced by
    /// <c>""  # tswap: name</c>, line by line, and the base64-looking continuation lines of a
    /// replaced value removed. Returns the content (LF) and every changed line.
    /// </summary>
    public (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content)
    {
        var (result, changes, _) = ToCommentReporting(content);
        return (result, changes);
    }

    /// <summary>
    /// Brief T22 (#319): <see cref="ToComment"/> plus the lines it left unchanged. A marker is filled with
    /// a value's plain form, so on a line of YAML block-scalar content
    /// (<see cref="ToCommentProcessor.BlockScalarContent"/>) an encoded occurrence (base64, base64url,
    /// whitespace-stripped) that the line path would replace is never replaced: the whole line stays as
    /// it is, plain occurrences on it too, and each encoded token is reported once per line (by line,
    /// then token ordinally). Plain occurrences on other content lines are replaced as before, and the
    /// adoption of a whole block (T20) is unchanged.
    /// </summary>
    public (string Content, IReadOnlyList<LineDiff> Changes, IReadOnlyList<UnreplacedLine> Unreplaced) ToCommentReporting(string content)
    {
        var lines = content.Replace("\r\n", "\n").Split('\n');
        var blockContent = ToCommentProcessor.BlockScalarContent(lines);
        List<LineDiff> diffs = [];
        List<UnreplacedLine> unreplaced = [];
        HashSet<int> linesToRemove = [];
        for (var i = 0; i < lines.Length; i++)
        {
            if (linesToRemove.Contains(i))
                continue;
            var original = lines[i];
            // Brief T20 (#315): a literal block scalar holding exactly one stored value is adopted whole.
            if (ToCommentProcessor.LiteralBlockAt(lines, i) is { } block && WholeValueToken(block.Candidate) is { } token)
            {
                var keyLine = $"{block.Indent}{block.Key} {ToCommentProcessor.Replacement(token)}";
                diffs.Add(new LineDiff(i + 1, original, keyLine));
                lines[i] = keyLine;
                for (var j = block.FirstLine; j < block.EndLine; j++)
                {
                    linesToRemove.Add(j);
                    diffs.Add(new BlockLineDiff(j + 1, lines[j]));
                }
                continue;
            }
            var taken = SelectToComment(original);
            if (taken.Count == 0)
                continue;
            if (blockContent[i] && EncodedTokens(taken) is [_, ..] encoded)
            {
                unreplaced.AddRange(encoded.Select(t => new UnreplacedLine(i + 1, t)));
                continue;
            }
            var current = Replace(original, taken);
            diffs.Add(new LineDiff(i + 1, original, current));
            lines[i] = current;
            foreach (var j in ToCommentProcessor.ContinuationLines(lines, i, original))
            {
                // Brief T22: a content line holding an encoded occurrence stays (and is reported in its turn).
                if (blockContent[j] && EncodedTokens(SelectToComment(lines[j])) is [_, ..])
                    break;
                linesToRemove.Add(j);
                diffs.Add(new LineDiff(j + 1, lines[j], ""));
            }
        }
        return (string.Join('\n', lines.Where((_, i) => !linesToRemove.Contains(i))), diffs, unreplaced);
    }

    /// <summary>Brief T22: the distinct tokens of the encoded (not plain) spans in <paramref name="taken"/>, ordinally.</summary>
    private static List<string> EncodedTokens(SortedList<int, Span> taken) =>
        [.. taken.Values.Where(static s => s.Kind != VariantKind.Plain).Select(static s => s.Token).Distinct().Order(StringComparer.Ordinal)];

    /// <summary>
    /// Brief T20 (#315): the token (<c>name</c> or <c>name:previous</c>) of the stored value whose
    /// <b>plain</b> variant is the whole of <paramref name="candidate"/>, or the whole of it minus its
    /// single trailing LF (a value ingested without one); null when none is. Any retained version
    /// counts, burned ones too; never a base64, base64url or whitespace-stripped variant. The longest
    /// match wins, then a live value over a burned one, then the token ordinally.
    /// </summary>
    private string? WholeValueToken(string candidate)
    {
        var shorter = candidate.EndsWith('\n') ? candidate.Length - 1 : -1;
        (int Length, bool Burned, string Token)? best = null;
        foreach (var hit in index.Scan(candidate))
        {
            if (hit.Kind != VariantKind.Plain || hit.Start != 0 || (hit.Length != candidate.Length && hit.Length != shorter))
                continue;
            var found = (hit.Length, Burned: !hit.IsPrevious && burned.Contains(hit.Name),
                Token: hit.IsPrevious ? hit.Name + SecretsDb.PreviousSuffix : hit.Name);
            if (best is not { } b
                || found.Length > b.Length
                || (found.Length == b.Length && (found.Burned, b.Burned) is (false, true))
                || (found.Length == b.Length && found.Burned == b.Burned && string.CompareOrdinal(found.Token, b.Token) < 0))
                best = found;
        }
        return best?.Token;
    }

    /// <summary>The hits of <paramref name="text"/> grouped into entries, in priority order, each with its starts left to right.</summary>
    private List<(Entry Entry, List<int> Starts)> Entries(string text)
    {
        Dictionary<Entry, List<int>> byEntry = [];
        foreach (var hit in index.Scan(text))
        {
            var token = hit.IsPrevious ? hit.Name + SecretsDb.PreviousSuffix : hit.Name;
            var entry = new Entry(hit.Length, text.Substring(hit.Start, hit.Length), !hit.IsPrevious && burned.Contains(hit.Name),
                token, SecretProcessor.TypeOf(hit.Kind), hit.Kind);
            if (!byEntry.TryGetValue(entry, out var starts))
                byEntry[entry] = starts = [];
            if (starts.Count == 0 || starts[^1] != hit.Start)
                starts.Add(hit.Start);
        }
        List<(Entry Entry, List<int> Starts)> entries = [.. byEntry.Select(kv => (kv.Key, kv.Value))];
        entries.Sort(static (x, y) => Compare(x.Entry, y.Entry));
        foreach (var (_, starts) in entries)
            starts.Sort();
        return entries;
    }

    private static int Compare(Entry a, Entry b)
    {
        var cmp = b.Length.CompareTo(a.Length);
        if (cmp != 0) return cmp;
        cmp = string.CompareOrdinal(a.Text, b.Text);
        if (cmp != 0) return cmp;
        cmp = a.Burned.CompareTo(b.Burned);
        if (cmp != 0) return cmp;
        cmp = string.CompareOrdinal(a.Token, b.Token);
        if (cmp != 0) return cmp;
        cmp = a.Type.CompareTo(b.Type);
        return cmp != 0 ? cmp : a.Kind.CompareTo(b.Kind);
    }

    /// <summary>Selection for spans that are exactly the occurrence (<c>redact</c>).</summary>
    private SortedList<int, Span> Select(string text, Func<Entry, int, (int Start, int End, string Replacement)> span)
    {
        SortedList<int, Span> taken = [];
        foreach (var (entry, starts) in Entries(text))
        {
            var position = 0;
            foreach (var start in starts)
            {
                if (start < position)
                    continue;
                var (s, e, replacement) = span(entry, start);
                if (Overlaps(taken, s, e))
                    continue;
                taken.Add(s, new Span(s, e, replacement, entry.Token, entry.Kind));
                position = e;
            }
        }
        return taken;
    }

    /// <summary>
    /// Selection for <c>tocomment</c> on one line: an occurrence at <c>s</c> may be taken quoted
    /// (from <c>s − 1</c>) or bare (from <c>s</c>), as the regex finds it scanning left to right,
    /// with the regex's own checks run on the original line.
    /// </summary>
    private SortedList<int, Span> SelectToComment(string line)
    {
        SortedList<int, Span> taken = [];
        foreach (var (entry, starts) in Entries(line))
        {
            var patterns = ToCommentProcessor.AnchoredPatterns(entry.Text);
            var replacement = ToCommentProcessor.Replacement(entry.Token);
            List<(int At, int Alternative)> attempts = [];
            foreach (var start in starts)
            {
                attempts.Add((start - 1, 0));
                attempts.Add((start - 1, 1));
                attempts.Add((start, 2));
            }
            attempts.Sort();
            var position = 0;
            foreach (var (at, alternative) in attempts)
            {
                if (at < position)
                    continue;
                var match = patterns[alternative].Match(line, at);
                if (!match.Success)
                    continue;
                var end = at + match.Length;
                if (Overlaps(taken, at, end))
                    continue;
                taken.Add(at, new Span(at, end, replacement, entry.Token, entry.Kind));
                position = end;
            }
        }
        return taken;
    }

    private static bool Overlaps(SortedList<int, Span> taken, int start, int end)
    {
        var keys = taken.Keys;
        int lo = 0, hi = keys.Count - 1, before = -1;
        while (lo <= hi)
        {
            var mid = (lo + hi) / 2;
            if (keys[mid] < end) { before = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        // 'before' is the last span starting before 'end'; spans don't overlap each other, so it is
        // the only candidate.
        return before >= 0 && taken.Values[before].End > start;
    }

    private static string Replace(string text, SortedList<int, Span> taken)
    {
        if (taken.Count == 0)
            return text;
        var result = new System.Text.StringBuilder(text.Length);
        var position = 0;
        foreach (var span in taken.Values)
        {
            result.Append(text, position, span.Start - position).Append(span.Replacement);
            position = span.End;
        }
        return result.Append(text, position, text.Length - position).ToString();
    }
}
