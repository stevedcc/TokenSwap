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
/// <para>
/// Brief T30 (#314): in <c>redact</c> a value version shorter than <see cref="Validation.ShortValueLength"/>
/// is matched, in every form, only where it stands as a whole word or number
/// (<see cref="TokenBoundary.IsDelimited"/>, neighbours read in the input); longer values anywhere.
/// </para>
/// </summary>
/// <param name="index">The fingerprints of every value version to recognise.</param>
/// <param name="burned">Names whose current value has an outstanding burn (they lose ties to a live name).</param>
public sealed class SecretMatcher(FingerprintIndex index, IReadOnlySet<string> burned)
{
    private readonly record struct Entry(int Length, string Text, bool Burned, string Token, MatchType Type, VariantKind Kind);

    /// <summary>A taken occurrence; <see cref="Token"/> and <see cref="Kind"/> are its entry's (brief T22).</summary>
    private sealed record Span(int Start, int End, string Replacement, string Token, VariantKind Kind);

    /// <summary>
    /// <c>redact</c>: every recognised value in <paramref name="content"/> replaced by its label, then every
    /// <c>\r\n</c> left in the output turned into <c>\n</c>. Brief T50a (#398): values are matched on the raw
    /// content and on its line-ending views (<see cref="ViewHits"/>), so a value is found whatever its line
    /// endings and the file's; the raw span is what is replaced.
    /// </summary>
    public string Redact(string content)
    {
        var taken = Select(content);
        return Replace(content, taken).Replace("\r\n", "\n");
    }

    /// <summary>A hit with the text it matched (in its view) and its span in the raw text.</summary>
    private readonly record struct ViewHit(FingerprintHit Hit, string Text, int RawStart, int RawEnd);

    /// <summary>The hits of <paramref name="text"/> itself, each with its own span.</summary>
    private List<ViewHit> RawHits(string text) =>
        [.. index.Scan(text).Select(hit => new ViewHit(hit, text.Substring(hit.Start, hit.Length), hit.Start, hit.Start + hit.Length))];

    /// <summary>
    /// Brief T50a (#398): the hits of <paramref name="text"/> in its raw form, its folded view and its unfolded
    /// view (<see cref="LineEndingViews"/>), each with its raw span. A view's hit is kept only when it holds a
    /// folded <c>\n</c> or an inserted <c>\r</c> (its raw length differs from its own; any other is the raw
    /// view's hit again) and its raw span isn't empty.
    /// </summary>
    private List<ViewHit> ViewHits(string text)
    {
        var hits = RawHits(text);
        if (LineEndingViews.HasCrLf(text))
            AddViewHits(text, text.Length, LineEndingViews.Fold, hits);
        if (LineEndingViews.HasBareLf(text))
            AddViewHits(text, 2 * text.Length, LineEndingViews.Unfold, hits);
        return hits;
    }

    private delegate int ViewBuilder(ReadOnlySpan<char> text, Span<char> view, Span<int> rawStart, Span<int> rawEnd);

    private void AddViewHits(string text, int capacity, ViewBuilder build, List<ViewHit> hits)
    {
        var view = new char[capacity];
        var rawStart = new int[capacity];
        var rawEnd = new int[capacity];
        var m = build(text, view, rawStart, rawEnd);
        var viewText = new string(view, 0, m);
        foreach (var hit in index.Scan(viewText))
        {
            var start = rawStart[hit.Start];
            var end = rawEnd[hit.Start + hit.Length - 1];
            if (end - start == hit.Length || end <= start)
                continue;
            hits.Add(new ViewHit(hit, viewText.Substring(hit.Start, hit.Length), start, end));
        }
    }

    /// <summary>
    /// <c>tocomment</c>: every recognised value (with its quotes and an existing marker) replaced by
    /// <c>""  # tswap: name</c>, line by line, where it is a whole value <c>apply</c> fills back (brief T50b), and
    /// the base64-looking continuation lines of a replaced value removed. Returns the content (LF) and every
    /// changed line.
    /// </summary>
    public (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content)
    {
        var report = ToCommentReport(content);
        return (report.Content, report.Changes);
    }

    /// <summary>Brief T22 (#319): <see cref="ToComment"/> plus the lines it left unchanged (see <see cref="ToCommentReport"/>).</summary>
    public (string Content, IReadOnlyList<LineDiff> Changes, IReadOnlyList<UnreplacedLine> Unreplaced) ToCommentReporting(string content)
    {
        var report = ToCommentReport(content);
        return (report.Content, report.Changes, report.Unreplaced);
    }

    /// <summary>
    /// <c>tocomment</c>'s full report.
    /// <para>
    /// Brief T50b (#394): an occurrence (what <see cref="SelectToComment"/> finds) is replaced only where
    /// <see cref="ToCommentProcessor.FillsBack"/> holds on the original line; every other one stays and is reported
    /// as a <see cref="SkippedValue"/> (<see cref="SkippedReason.NotWholeValue"/>) unless a replacement overlaps it.
    /// </para>
    /// <para>
    /// Brief T22 (#319): a marker is filled with a value's plain form, so on a line of YAML block-scalar content
    /// (<see cref="ToCommentProcessor.BlockScalarContent"/>) holding an encoded occurrence (base64, base64url,
    /// whitespace-stripped; the rule's rejected ones included) the whole line stays as it is, each encoded token
    /// reported once per line (<see cref="UnreplacedLine"/>) and, since T50b, each plain occurrence on it as a
    /// <see cref="SkippedValue"/> (<see cref="SkippedReason.InBlockScalar"/>). The adoption of a whole block (T20) is
    /// unchanged.
    /// </para>
    /// <para>
    /// Brief T50b Task 3 (#399): first, values with a line break are found on the raw content and its line-ending views
    /// (<see cref="SelectMultiLine"/>); each is decided when the loop reaches its first line: replaced as one
    /// <see cref="MultiLineDiff"/> when the rule holds around it and none of its lines is block content, dropped with a
    /// block T20 adopted, otherwise left (reported over its lines unless a replacement overlaps it) while its lines go
    /// through the line path.
    /// </para>
    /// </summary>
    public ToCommentReport ToCommentReport(string content)
    {
        var lines = content.Replace("\r\n", "\n").Split('\n');
        var blockContent = ToCommentProcessor.BlockScalarContent(lines);
        // Brief T50b Task 3: line i of 'lines' starts at lineStarts[i] in the raw content (only a final '\r' differs).
        List<int> lineStarts = [0];
        for (var at = content.IndexOf('\n'); at >= 0; at = content.IndexOf('\n', at + 1))
            lineStarts.Add(at + 1);
        var multiLine = SelectMultiLine(content, lineStarts);
        Dictionary<int, MultiLineOccurrence> startingAt = multiLine.ToDictionary(static o => o.First);
        HashSet<int> multiLineLines = [.. multiLine.SelectMany(static o => Enumerable.Range(o.First, o.Last - o.First + 1))];
        List<(MultiLineOccurrence Occurrence, SkippedReason Reason)> left = [];
        List<(int Start, int End)> replacedRanges = [];
        bool InsideLeft(int start, int end) => left.Exists(l => l.Occurrence.Start <= start && end <= l.Occurrence.End);

        List<LineDiff> diffs = [];
        List<UnreplacedLine> unreplaced = [];
        List<SkippedValue> skipped = [];
        SortedSet<string> replacedNames = new(StringComparer.Ordinal);
        HashSet<int> linesToRemove = [];
        HashSet<int> mergedLines = [];
        for (var i = 0; i < lines.Length; i++)
        {
            var multi = startingAt.GetValueOrDefault(i);
            if (linesToRemove.Contains(i))
            {
                // Removed by a T20 adoption above: the adoption replaced that block, the occurrence goes with it.
                // Removed by a multi-line replacement: it can't be replaced on a line that no longer exists.
                if (multi is not null && mergedLines.Contains(i))
                    left.Add((multi, BlockReason(multi, blockContent)));
                continue;
            }
            var original = lines[i];
            if (multi is not null)
            {
                if (MultiLineReplacement(multi, lines, lineStarts, blockContent) is { } after)
                {
                    diffs.Add(new MultiLineDiff(i + 1, multi.Last + 1, string.Join('\n', lines[i..(multi.Last + 1)]), after));
                    replacedNames.Add(BaseName(multi.Token));
                    replacedRanges.Add((multi.Start, multi.End));
                    // What the line path's finder sees in the kept text: before the value on line a, after it (and after
                    // the marker it consumed) on line b.
                    ReportKept(original[..(multi.Start - lineStarts[i])], i, skipped);
                    ReportKept(lines[multi.Last][(multi.MarkerEnd - lineStarts[multi.Last])..], multi.Last, skipped);
                    lines[i] = after;
                    for (var j = i + 1; j <= multi.Last; j++)
                    {
                        linesToRemove.Add(j);
                        mergedLines.Add(j);
                    }
                    continue;
                }
                left.Add((multi, BlockReason(multi, blockContent)));
            }
            // Brief T20 (#315): a literal block scalar holding exactly one stored value is adopted whole.
            if (ToCommentProcessor.LiteralBlockAt(lines, i) is { } block && WholeValueToken(block.Candidate) is { } token)
            {
                var keyLine = $"{block.Indent}{block.Key} {ToCommentProcessor.Replacement(token)}";
                diffs.Add(new LineDiff(i + 1, original, keyLine));
                replacedNames.Add(BaseName(token));
                replacedRanges.Add((lineStarts[i], block.EndLine < lineStarts.Count ? lineStarts[block.EndLine] : content.Length));
                lines[i] = keyLine;
                for (var j = block.FirstLine; j < block.EndLine; j++)
                {
                    linesToRemove.Add(j);
                    diffs.Add(new BlockLineDiff(j + 1, lines[j]));
                }
                continue;
            }
            var (taken, rejected) = SelectToComment(original);
            if (taken.Count == 0 && rejected.Count == 0)
                continue;
            var offset = lineStarts[i];
            if (blockContent[i] && EncodedTokens([.. taken.Values, .. rejected]) is [_, ..] encoded)
            {
                unreplaced.AddRange(encoded.Select(t => new UnreplacedLine(i + 1, t)));
                // Brief T50b: the plain occurrences on a line T22 keeps whole are left too, none silently.
                foreach (var span in taken.Values.Concat(rejected).Where(static s => s.Kind == VariantKind.Plain))
                {
                    if (!InsideLeft(offset + span.Start, offset + span.End))
                        skipped.Add(new SkippedValue(i + 1, i + 1, span.Token, SkippedReason.InBlockScalar));
                }
                continue;
            }
            foreach (var span in Reportable(rejected, taken))
            {
                if (!InsideLeft(offset + span.Start, offset + span.End))
                    skipped.Add(new SkippedValue(i + 1, i + 1, span.Token, SkippedReason.NotWholeValue));
            }
            if (taken.Count == 0)
                continue;
            foreach (var span in taken.Values)
            {
                replacedNames.Add(BaseName(span.Token));
                replacedRanges.Add((offset + span.Start, offset + span.End));
            }
            var current = Replace(original, taken);
            diffs.Add(new LineDiff(i + 1, original, current));
            lines[i] = current;
            foreach (var j in ToCommentProcessor.ContinuationLines(lines, i, original))
            {
                // Brief T50b: never a line holding part of a multi-line occurrence.
                if (multiLineLines.Contains(j))
                    break;
                // Brief T22: a content line holding an encoded occurrence stays (and is reported in its turn).
                if (blockContent[j] && SelectToComment(lines[j]) is var (t, r) && EncodedTokens([.. t.Values, .. r]) is [_, ..])
                    break;
                linesToRemove.Add(j);
                diffs.Add(new LineDiff(j + 1, lines[j], ""));
            }
        }
        // A left multi-line occurrence is reported unless a replacement overlaps it.
        foreach (var (occurrence, reason) in left)
        {
            if (!replacedRanges.Exists(r => r.Start < occurrence.End && occurrence.Start < r.End))
                skipped.Add(new SkippedValue(occurrence.First + 1, occurrence.Last + 1, occurrence.Token, reason));
        }
        List<SkippedValue> ordered = [.. skipped.OrderBy(static s => s.FirstLine).ThenBy(static s => s.LastLine)
            .ThenBy(static s => s.Token, StringComparer.Ordinal)];
        return new ToCommentReport(string.Join('\n', lines.Where((_, i) => !linesToRemove.Contains(i))), diffs, unreplaced,
            ordered, [.. replacedNames]);
    }

    /// <summary>
    /// Brief T50b: the rejected spans to report: not overlapped by a taken one, and one per occurrence (a rejected span
    /// overlapping one of its own token already reported is the same occurrence in another form, a value's base64url
    /// inside its padded base64).
    /// </summary>
    private static List<Span> Reportable(List<Span> rejected, SortedList<int, Span> taken)
    {
        List<Span> reported = [];
        foreach (var span in rejected)
        {
            if (Overlaps(taken, span.Start, span.End)
                || reported.Exists(r => r.Token == span.Token && r.Start < span.End && span.Start < r.End))
                continue;
            reported.Add(span);
        }
        return reported;
    }

    /// <summary>Brief T50b Task 3: every occurrence the line path finds in <paramref name="kept"/> (text a multi-line replacement keeps on line <paramref name="line"/>), reported.</summary>
    private void ReportKept(string kept, int line, List<SkippedValue> skipped)
    {
        var (taken, rejected) = SelectToComment(kept);
        foreach (var span in Reportable([.. taken.Values, .. rejected], []))
            skipped.Add(new SkippedValue(line + 1, line + 1, span.Token, SkippedReason.NotWholeValue));
    }

    /// <summary>
    /// Brief T50b Task 3 (#399): a value found across a line break, with its quotes and a consumed marker:
    /// raw span <see cref="Start"/>..<see cref="End"/> (the value with its quotes, without the marker),
    /// <see cref="MarkerEnd"/> (the end of a consumed marker, or <see cref="End"/>), and its first and last line
    /// (0-based; a line break belongs to the line it ends). <see cref="AtLineBreak"/>: the value starts or ends with a
    /// line break, so it is never replaced.
    /// </summary>
    private sealed record MultiLineOccurrence(int Start, int End, int MarkerEnd, int First, int Last, string Token, bool AtLineBreak);

    private static readonly Regex ConsumedMarker = new(@"\G\s*#\s*tswap\s*:\s*[a-zA-Z0-9_-]+(?::previous)?(?![-\w])");

    /// <summary>
    /// Brief T50b Task 3 (#399): the occurrences in the raw <paramref name="content"/> (and its line-ending views)
    /// whose raw span holds a <c>\n</c>, selected as <see cref="Select"/> does: priority order, no overlap, short values
    /// only where delimited.
    /// </summary>
    private List<MultiLineOccurrence> SelectMultiLine(string content, List<int> lineStarts)
    {
        if (!content.Contains('\n'))
            return [];
        List<ViewHit> hits = [.. ViewHits(content).Where(h => content.AsSpan(h.RawStart, h.RawEnd - h.RawStart).Contains('\n'))];
        if (hits.Count == 0)
            return [];
        SortedList<int, Span> taken = [];
        foreach (var (entry, spans) in Entries(content, hits, wholeTokenShortValues: true))
        {
            var position = 0;
            foreach (var (s, e) in spans)
            {
                if (s < position || Overlaps(taken, s, e))
                    continue;
                taken.Add(s, new Span(s, e, "", entry.Token, entry.Kind));
                position = e;
            }
        }
        int LineOf(int at)
        {
            var index = lineStarts.BinarySearch(at);
            return index >= 0 ? index : ~index - 1;
        }
        List<MultiLineOccurrence> found = [];
        foreach (var span in taken.Values)
        {
            var (start, end) = (span.Start, span.End);
            // Code review (MiMo I-1): a final CR that is the CR of a CRLF, or the file's last character, ends at a line
            // break too: replacing it would consume the line break (or index past the normalised line).
            var atLineBreak = content[start] == '\n' || (content[start] == '\r' && start + 1 < content.Length && content[start + 1] == '\n')
                || content[end - 1] == '\n' || (content[end - 1] == '\r' && (end == content.Length || content[end] == '\n'));
            if (start > 0 && content[start - 1] is '"' or '\'' && end < content.Length && content[end] == content[start - 1])
                (start, end) = (start - 1, end + 1);
            var lineEnd = content.IndexOf('\n', end) is var lf and >= 0 ? lf : content.Length;
            var markerEnd = end;
            if (!atLineBreak && ConsumedMarker.Match(content[..lineEnd], end) is { Success: true } marker)
                markerEnd = end + marker.Length;
            found.Add(new MultiLineOccurrence(start, end, markerEnd, LineOf(start), LineOf(end - 1), span.Token, atLineBreak));
        }
        return found;
    }

    /// <summary>Brief T50b: R2 when any line of <paramref name="occurrence"/> is block-scalar content, else R1.</summary>
    private static SkippedReason BlockReason(MultiLineOccurrence occurrence, bool[] blockContent) =>
        Enumerable.Range(occurrence.First, occurrence.Last - occurrence.First + 1).Any(j => blockContent[j])
            ? SkippedReason.InBlockScalar
            : SkippedReason.NotWholeValue;

    /// <summary>
    /// Brief T50b Task 3: the one line that replaces lines a..b of <paramref name="occurrence"/>
    /// (<c>{before}""  # tswap: {token}{after}</c>), or null when it is left: it starts or ends with a line break, the
    /// whole-value rule fails (a line break is a control character, so only <c>:</c> qualifies), or a line of it is
    /// block-scalar content.
    /// </summary>
    private static string? MultiLineReplacement(MultiLineOccurrence occurrence, string[] lines, List<int> lineStarts, bool[] blockContent)
    {
        if (occurrence.AtLineBreak || BlockReason(occurrence, blockContent) == SkippedReason.InBlockScalar)
            return null;
        var before = lines[occurrence.First][..(occurrence.Start - lineStarts[occurrence.First])];
        var last = lines[occurrence.Last];
        var valueEnd = occurrence.End - lineStarts[occurrence.Last];
        var markerEnd = occurrence.MarkerEnd - lineStarts[occurrence.Last];
        var after = last[markerEnd..];
        if (!ToCommentProcessor.FillsBack(before, last[valueEnd..markerEnd], after, envForm: false))
            return null;
        return before + ToCommentProcessor.Replacement(occurrence.Token) + after;
    }

    /// <summary>Brief T50b: the secret's name in <paramref name="token"/>, without <c>:previous</c>.</summary>
    private static string BaseName(string token) =>
        token.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal) ? token[..^SecretsDb.PreviousSuffix.Length] : token;

    /// <summary>Brief T22: the distinct tokens of the encoded (not plain) spans in <paramref name="spans"/>, ordinally.</summary>
    private static List<string> EncodedTokens(IEnumerable<Span> spans) =>
        [.. spans.Where(static s => s.Kind != VariantKind.Plain).Select(static s => s.Token).Distinct().Order(StringComparer.Ordinal)];

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

    /// <summary>
    /// The <paramref name="hits"/> of <paramref name="text"/> grouped into entries, in priority order, each with
    /// its raw spans left to right (one per raw start: the first found). An entry's length and text are its
    /// hit's own (brief T50a: in its view). With <paramref name="wholeTokenShortValues"/> (brief T30,
    /// <c>redact</c>) a hit of a short value version whose raw span isn't delimited in <paramref name="text"/>
    /// is left out before grouping, so it never takes a span from another value.
    /// </summary>
    private List<(Entry Entry, List<(int Start, int End)> Spans)> Entries(string text, List<ViewHit> hits, bool wholeTokenShortValues)
    {
        Dictionary<Entry, List<(int Start, int End)>> byEntry = [];
        foreach (var (hit, matched, rawStart, rawEnd) in hits)
        {
            if (wholeTokenShortValues && index.IsShortValue(hit) && !TokenBoundary.IsDelimited(text, rawStart, rawEnd - rawStart))
                continue;
            var token = hit.IsPrevious ? hit.Name + SecretsDb.PreviousSuffix : hit.Name;
            var entry = new Entry(hit.Length, matched, !hit.IsPrevious && burned.Contains(hit.Name),
                token, SecretProcessor.TypeOf(hit.Kind), hit.Kind);
            if (!byEntry.TryGetValue(entry, out var spans))
                byEntry[entry] = spans = [];
            spans.Add((rawStart, rawEnd));
        }
        List<(Entry Entry, List<(int Start, int End)> Spans)> entries = [];
        foreach (var (entry, spans) in byEntry)
        {
            // Stable: of two spans at one raw start, the first found stays.
            List<(int Start, int End)> ordered = [];
            foreach (var span in spans.OrderBy(static s => s.Start))
            {
                if (ordered.Count == 0 || ordered[^1].Start != span.Start)
                    ordered.Add(span);
            }
            entries.Add((entry, ordered));
        }
        entries.Sort(static (x, y) => Compare(x.Entry, y.Entry));
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

    /// <summary>
    /// Selection for <c>redact</c>: each occurrence's raw span, replaced by its label (short values whole-token
    /// only, brief T30). Overlaps and an entry's previous taken occurrence are checked on raw positions.
    /// </summary>
    private SortedList<int, Span> Select(string text)
    {
        SortedList<int, Span> taken = [];
        foreach (var (entry, spans) in Entries(text, ViewHits(text), wholeTokenShortValues: true))
        {
            var replacement = RedactProcessor.Label(entry.Token, entry.Kind);
            var position = 0;
            foreach (var (s, e) in spans)
            {
                if (s < position || Overlaps(taken, s, e))
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
    /// with the regex's own checks run on the original line. Brief T50b (#394): an occurrence is taken only where
    /// <see cref="ToCommentProcessor.FillsBack"/> holds on the original line; a rejected one is returned apart and
    /// reserves its span against later attempts of its own entry only (as a match <c>Regex.Replace</c> kept),
    /// never against other entries.
    /// </summary>
    private (SortedList<int, Span> Taken, List<Span> Rejected) SelectToComment(string line)
    {
        SortedList<int, Span> taken = [];
        List<Span> rejected = [];
        // tocomment's own [-\w] boundary (AnchoredPatterns) already rejects every hit T30's rule rejects.
        foreach (var (entry, spans) in Entries(line, RawHits(line), wholeTokenShortValues: false))
        {
            var patterns = ToCommentProcessor.AnchoredPatterns(entry.Text);
            var replacement = ToCommentProcessor.Replacement(entry.Token);
            var envForm = entry.Kind == VariantKind.Plain && !Apply.HasControlCharacter(entry.Text);
            List<(int At, int Alternative)> attempts = [];
            foreach (var (start, _) in spans)
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
                var valueEnd = at + entry.Text.Length + (alternative < 2 ? 2 : 0);
                var span = new Span(at, end, replacement, entry.Token, entry.Kind);
                if (ToCommentProcessor.FillsBack(line[..at], line[valueEnd..end], line[end..], envForm))
                    taken.Add(at, span);
                else
                    rejected.Add(span);
                position = end;
            }
        }
        return (taken, rejected);
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
