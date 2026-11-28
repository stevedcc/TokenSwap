using System.Buffers;
using System.Security.Cryptography;

namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T16-S3: finds indexed values in streamed output from their fingerprints alone, fast enough for
/// <c>run</c>'s relay, and says how much of a chunk's end must be held back for a later chunk.
/// <para>
/// It finds what <see cref="FingerprintIndex.Scan"/> finds (the same (length, rolling hash) candidates,
/// confirmed on the HMAC; a rolling-hash match alone is never a hit; a window that cuts a surrogate pair,
/// <see cref="FingerprintIndex.SplitsASurrogatePair"/>, is never confirmed), but tries far fewer windows. Each
/// stored entry gets a class from data the set already holds: <em>whitespace-free</em> (a
/// whitespace-stripped entry, or the plain entry of a set without one), <em>base64</em>,
/// <em>base64url</em>, or <em>free</em> (the plain entry of a set that has a whitespace-stripped one: it may
/// hold line breaks, and exactly <c>W = L − S</c> of CR, LF, space and tab). A window is tried for an
/// entry length only while the class allows it: a run of allowed characters at least that long, or for
/// free entries exactly <c>W</c> of those four characters in the window. Window hashes come from prefix
/// hashes of the text, and a bitset over (length, hash) skips most dictionary lookups.
/// </para>
/// <para>
/// A PTY turns a value's <c>\n</c> into <c>\r\n</c> (and <c>\r\n</c> into <c>\r\r\n</c>), so free entries are
/// also tried on a view of the text with each <c>\r\n</c> folded to <c>\n</c>; such a hit is reported as the
/// raw span, folded <c>\r</c>s included. <see cref="MaxRawLength"/> allows for them. Brief T50a (#398): free
/// entries are also tried on the view with each <c>\n</c> not preceded by <c>\r</c> unfolded to <c>\r\n</c>
/// (a <c>\r\n</c> value printed with <c>\n</c> only); such a hit's raw span leaves the inserted <c>\r</c>s out,
/// so it is never longer than its entry and <see cref="MaxRawLength"/>, the caps and <see cref="PendingFrom(ReadOnlySpan{char})"/>
/// need nothing more. Both views are built by <see cref="LineEndingViews"/>, as <c>redact</c>'s are. Brief T65 (#434):
/// free entries are also tried on the views with every line break written as <c>\n</c>, <c>\r\n</c> or <c>\r</c>
/// (<see cref="LineEndingViews.WriteBreaks"/>); each such hit's raw span is at most <c>L + W</c> long and holds at most
/// <c>W</c> counted whitespace, so the caps and <c>PendingFrom</c> need nothing more. A window's trailing <c>\r</c> is
/// never carried: the next window decides it.
/// </para>
/// <para>
/// <see cref="PendingFrom"/> reads the text's characters and per-class aggregates only (each class's
/// longest raw length and the largest whitespace count of a free entry), both rounded up to a multiple
/// of 256, never a hash, bitset or HMAC: what it holds back is observable through timing, so it must not
/// tell a guess that shares a secret's prefix from any other word of its class. In whole-token mode
/// (brief T30) it then moves back to the start of a word it would split, by the text and a constant only
/// (<see cref="TokenBoundary.HoldOutsideWord"/>).
/// </para>
/// <para>
/// Like <see cref="FingerprintIndex"/>, the scanner keeps a reference to the <see cref="FingerprintKeys"/>
/// (no copy of the key or of anything derived from it) and works only while they stay undisposed. It is
/// immutable after <see cref="Build"/>, so concurrent scans are safe.
/// </para>
/// </summary>
public sealed class FingerprintScanner
{
    private const int Quantum = 256;
    private const int FilterBits = 1 << 20;

    private readonly FingerprintKeys _keys;
    private readonly Dictionary<(int Length, ulong Hash), Candidate[]> _candidates;
    private readonly ulong[] _filter = new ulong[FilterBits / 64];
    // Pruned classes: distinct lengths ascending, each with the classes that have an entry that long.
    private readonly (int Length, Classes Classes)[] _runLengths;
    // Free entries: distinct (length, whitespace count); a count of -1 means any (an unknown kind).
    private readonly (int Length, int Whitespace)[] _freeShapes;
    private readonly int _capWhitespaceFree, _capBase64, _capBase64Url, _capFree, _maxFreeWhitespace;
    // Brief T30: null in Anywhere mode; in WholeToken mode, whether each value version (name, previous) is short.
    private readonly Dictionary<(string Name, bool IsPrevious), bool>? _short;

    [Flags]
    private enum Classes : byte
    {
        None = 0,
        WhitespaceFree = 1,
        Base64 = 2,
        Base64Url = 4,
        // A plain entry of a set without a whitespace-stripped one is whitespace-free, or whitespace
        // only (its stripped form would be empty): also tried inside runs of whitespace.
        WhitespaceOnly = 8,
    }

    private sealed record Candidate(string Name, bool IsPrevious, VariantKind Kind, byte[] Hmac);

    private FingerprintScanner(
        FingerprintKeys keys,
        Dictionary<(int, ulong), Candidate[]> candidates,
        (int, Classes)[] runLengths,
        (int, int)[] freeShapes,
        Dictionary<(string, bool), bool>? isShort)
    {
        _keys = keys;
        _short = isShort;
        _candidates = candidates;
        _runLengths = runLengths;
        _freeShapes = freeShapes;
        foreach (var (length, hash) in candidates.Keys)
            SetFilter(length, hash);

        int Longest(Classes c) => runLengths.Where(r => (r.Item2 & c) != 0).Select(r => r.Item1).DefaultIfEmpty(0).Max();
        _capWhitespaceFree = RoundUp(Longest(Classes.WhitespaceFree));
        _capBase64 = RoundUp(Longest(Classes.Base64));
        _capBase64Url = RoundUp(Longest(Classes.Base64Url));
        _capFree = RoundUp(freeShapes.Select(f => RawLength(f.Item1, f.Item2)).DefaultIfEmpty(0).Max());
        _maxFreeWhitespace = freeShapes.Any(f => f.Item2 < 0)
            ? int.MaxValue
            : RoundUp(freeShapes.Select(f => f.Item2).DefaultIfEmpty(0).Max());

        // A whitespace-only entry (WhitespaceOnly) can be found folded, as a free entry can: up to one
        // raw '\r' per character.
        MaxRawLength = Math.Max(
            runLengths.Select(r => (r.Item2 & Classes.WhitespaceOnly) != 0 ? 2 * r.Item1 : r.Item1).DefaultIfEmpty(0).Max(),
            freeShapes.Select(f => RawLength(f.Item1, f.Item2)).DefaultIfEmpty(0).Max());
    }

    /// <summary>
    /// The longest raw span of a free shape: each folded line break adds one raw <c>\r</c>, so at most
    /// <paramref name="whitespace"/> more; for a kind this build doesn't know (-1), at most L more.
    /// </summary>
    private static int RawLength(int length, int whitespace) => length + (whitespace < 0 ? length : whitespace);

    /// <summary>
    /// The longest span <see cref="Scan"/> can report, in UTF-16 code units: the longest entry, or for a
    /// free entry its length plus its whitespace count (each folded line break adds at most one raw
    /// <c>\r</c>). 0 for an empty index.
    /// </summary>
    public int MaxRawLength { get; }

    /// <summary>
    /// Indexes every entry of every set; sets computed under other keys simply never match. With
    /// <see cref="ShortValueMatching.WholeToken"/> (brief T30, <c>run</c>) a short value version
    /// (<see cref="TokenBoundary.IsShort"/>) is reported, in every form, only where it is delimited in the
    /// scanned window (whose edges count as boundaries), and <see cref="PendingFrom(ReadOnlySpan{char})"/>
    /// never splits a word it can hold (<see cref="TokenBoundary.HoldOutsideWord"/>).
    /// </summary>
    public static FingerprintScanner Build(
        IEnumerable<(string Name, bool IsPrevious, FingerprintSet Set)> sets, FingerprintKeys keys,
        ShortValueMatching shortValues = ShortValueMatching.Anywhere)
    {
        ArgumentNullException.ThrowIfNull(sets);
        ArgumentNullException.ThrowIfNull(keys);

        Dictionary<(int, ulong), List<Candidate>> candidates = [];
        Dictionary<int, Classes> runLengths = [];
        HashSet<(int, int)> freeShapes = [];
        Dictionary<(string, bool), bool>? isShort = shortValues == ShortValueMatching.WholeToken ? [] : null;
        foreach (var (name, isPrevious, set) in sets)
        {
            // As FingerprintIndex: two sets under one key are short only if both are (the masking side).
            if (isShort is not null)
                isShort[(name, isPrevious)] = TokenBoundary.IsShort(set) && isShort.GetValueOrDefault((name, isPrevious), true);
            foreach (var entry in set.Entries)
            {
                if (entry.Length <= 0) continue;
                var key = (entry.Length, entry.RollingHash);
                if (!candidates.TryGetValue(key, out var list))
                    candidates[key] = list = [];
                list.Add(new Candidate(name, isPrevious, entry.Kind, entry.Hmac));

                // Brief T54: a form kind is classed as its base kind, and a plain entry pairs with the
                // whitespace-stripped entry of its own spelling (Plain with WhitespaceStripped, NfcPlain with
                // NfcWhitespaceStripped, NfdPlain with NfdWhitespaceStripped), whose length differs by that
                // spelling's whitespace only. Kinds above 11 come back unchanged and reach default.
                var baseKind = entry.Kind.BaseKind();
                var stripped = baseKind == VariantKind.Plain ? StrippedOf(set, entry.Kind) : null;
                switch (baseKind)
                {
                    case VariantKind.Plain when stripped is null:
                        AddRun(runLengths, entry.Length, Classes.WhitespaceFree | Classes.WhitespaceOnly);
                        break;
                    case VariantKind.WhitespaceStripped:
                        AddRun(runLengths, entry.Length, Classes.WhitespaceFree);
                        break;
                    case VariantKind.Base64:
                        AddRun(runLengths, entry.Length, Classes.Base64);
                        break;
                    case VariantKind.Base64Url:
                        AddRun(runLengths, entry.Length, Classes.Base64Url);
                        break;
                    case VariantKind.Plain:
                        var whitespace = entry.Length - stripped!.Length;
                        freeShapes.Add((entry.Length, whitespace > 0 ? whitespace : -1));
                        break;
                    default:
                        // A kind this build doesn't know: tried at every start, nothing pruned.
                        freeShapes.Add((entry.Length, -1));
                        break;
                }
            }
        }

        return new FingerprintScanner(
            keys,
            candidates.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray()),
            [.. runLengths.OrderBy(kv => kv.Key).Select(kv => (kv.Key, kv.Value))],
            [.. freeShapes.OrderBy(f => f.Item1).ThenBy(f => f.Item2)],
            isShort);

        static void AddRun(Dictionary<int, Classes> runs, int length, Classes c) =>
            runs[length] = runs.GetValueOrDefault(length) | c;

        static FingerprintEntry? StrippedOf(FingerprintSet set, VariantKind plainKind) =>
            set.Entries.FirstOrDefault(e => e.Kind == plainKind + 1 && e.Length > 0);
    }

    /// <summary>
    /// What one scan of a stream leaves for the next: the window, its prefix hashes and whitespace
    /// counts, its hits (before the per-start deduplication, each with its view and entry length), and the pending
    /// point <see cref="PendingFrom(ReadOnlySpan{char}, ScanState?)"/> returned for it. A streaming redactor's next
    /// window usually continues it up to <c>held</c> (the last window without a trailing <c>\r</c>); when it does
    /// (checked on the text, character by character), that part is neither hashed nor scanned again. Not thread-safe: one per stream (the stream matcher keeps one per thread).
    /// It holds the last window's text, i.e. output, until the next scan replaces it.
    /// </summary>
    public sealed class ScanState
    {
        internal string Text = "";
        internal ulong[] Prefix = [];
        internal int[] Counts = [];
        internal List<ScanHit> Hits = [];
        internal int Pending = -1;

        /// <summary>Forgets the last window (its text and arrays), so nothing of the output stays behind.</summary>
        public void Clear()
        {
            if (Prefix.Length > 0) ArrayPool<ulong>.Shared.Return(Prefix);
            if (Counts.Length > 0) ArrayPool<int>.Shared.Return(Counts);
            Text = "";
            Prefix = [];
            Counts = [];
            Hits = [];
            Pending = -1;
        }
    }

    /// <summary>
    /// Adds every confirmed hit in <paramref name="text"/> to <paramref name="hits"/>, in text
    /// coordinates, ordered by start, then length descending. Hits with an equal span are reported once:
    /// the first in tie order (name ordinal, current before previous, then kind). In whole-token mode a
    /// short version's hit that isn't delimited in <paramref name="text"/> is dropped first, so it never
    /// hides an equal span of another value.
    /// </summary>
    public void Scan(ReadOnlySpan<char> text, List<FingerprintHit> hits) => Scan(text, hits, state: null);

    /// <summary>
    /// <see cref="Scan(ReadOnlySpan{char}, List{FingerprintHit})"/>, reusing what <paramref name="state"/>
    /// carries from the previous window of the same stream when this window continues it from its pending
    /// point; the hits are the same either way. Updates <paramref name="state"/> for the next window.
    /// </summary>
    public void Scan(ReadOnlySpan<char> text, List<FingerprintHit> hits, ScanState? state)
    {
        ArgumentNullException.ThrowIfNull(hits);
        var b = _keys.RollingBase;
        if (text.Length == 0 || _candidates.Count == 0)
            return;

        // The carried part: the previous window from its pending point up to held, if this window starts with it.
        // Brief T65 (#434): a trailing \r is never carried; the next window decides it (it may be the \r of a \r\n,
        // which a view hit ending at it took for a whole line break).
        var carried = 0;
        var held = state is null ? 0 : state.Text.Length - (state.Text.EndsWith('\r') ? 1 : 0);
        if (state is { Pending: >= 0 } && state.Pending <= held
            && held - state.Pending <= text.Length
            && text[..(held - state.Pending)].SequenceEqual(state.Text.AsSpan(state.Pending, held - state.Pending)))
            carried = held - state.Pending;

        var found = new FoundHits();
        var prefix = ArrayPool<ulong>.Shared.Rent(text.Length + 1);
        var counts = _freeShapes.Length > 0 ? ArrayPool<int>.Shared.Rent(text.Length + 1) : null;
        var handedOver = false;
        try
        {
            if (carried > 0)
            {
                // Hashes and counts keep the previous window's origin: a window's hash and count are
                // differences, so any common origin gives the same values.
                state!.Prefix.AsSpan(state.Pending, carried + 1).CopyTo(prefix);
                if (counts is not null)
                    state.Counts.AsSpan(state.Pending, carried + 1).CopyTo(counts);
                foreach (var hit in state.Hits)
                    if (hit.Hit.Start >= state.Pending && hit.Hit.Start + hit.Hit.Length <= held)
                        found.Items.Add(hit with { Hit = hit.Hit with { Start = hit.Hit.Start - state.Pending } });
            }
            else
            {
                prefix[0] = 0;
                if (counts is not null) counts[0] = 0;
            }
            for (var i = carried; i < text.Length; i++)
                prefix[i + 1] = Reduce((UInt128)prefix[i] * b + text[i]);
            if (counts is not null)
                for (var i = carried; i < text.Length; i++)
                    counts[i + 1] = counts[i] + (IsWhitespace(text[i]) ? 1 : 0);

            // Each hit carries its view's index: 0 raw, 1 folded (the whitespace-run hits of TryFoldedWhitespaceRun
            // too), 2 unfolded, 3 every break as \n, 4 as \r\n, 5 as \r (brief T65, #434), the order they are scanned.
            if (_runLengths.Length > 0)
                ScanRuns(text, prefix, b, carried, found);
            if (_freeShapes.Length > 0)
            {
                found.View = 0;
                ScanFree(text, prefix, counts!, b, carried, rawStart: null, rawEnd: null, found);
                if (LineEndingViews.HasCrLf(text))
                {
                    found.View = 1;
                    ScanFolded(text, b, found);
                }
                if (LineEndingViews.HasBareLf(text))
                {
                    found.View = 2;
                    ScanUnfolded(text, b, found);
                }
                // Brief T65 (#434): each new view only when it can differ from the views already scanned.
                if (LineEndingViews.HasLoneCr(text))
                {
                    found.View = 3;
                    ScanBreaks(text, "\n", b, found);
                    found.View = 4;
                    ScanBreaks(text, "\r\n", b, found);
                }
                if (text.Contains('\n'))
                {
                    found.View = 5;
                    ScanBreaks(text, "\r", b, found);
                }
            }

            if (state is not null)
            {
                state.Clear();
                state.Text = text.ToString();
                state.Prefix = prefix;
                state.Counts = counts ?? [];
                state.Hits = found.Items;
                handedOver = true;
            }
        }
        finally
        {
            // Unless the state took them, the arrays go back (also when the scan threw).
            if (!handedOver)
            {
                ArrayPool<ulong>.Shared.Return(prefix);
                if (counts is not null) ArrayPool<int>.Shared.Return(counts);
            }
        }

        // Brief T65 (#434): one hit per raw start and candidate (start, name, previous, kind and entry length), the
        // earliest view's (the first found on a tie), as redact's Entries keeps the first span per raw start. Two such
        // hits are the same entry over the same value text and differ only in which break characters the span takes.
        // The view order is load-bearing: for abc def-gh\r in x: abc def-gh\n the unfolded view gives (3, 10) and the
        // \r view (3, 11); the unfolded one is kept, so run keeps the line feed as redact does
        // (FingerprintScannerTests.Scan_LineEndings_ExactlyOneHit).
        var first = new Dictionary<(int Start, string Name, bool IsPrevious, VariantKind Kind, int EntryLength), int>();
        var unique = new List<ScanHit>(found.Items.Count);
        foreach (var hit in found.Items)
        {
            var key = (hit.Hit.Start, hit.Hit.Name, hit.Hit.IsPrevious, hit.Hit.Kind, hit.EntryLength);
            if (!first.TryGetValue(key, out var at))
            {
                first[key] = unique.Count;
                unique.Add(hit);
            }
            else if (hit.View < unique[at].View)
                unique[at] = hit;
        }
        List<FingerprintHit> deduplicated = [.. unique.Select(static h => h.Hit)];
        deduplicated.Sort(static (x, y) =>
        {
            var cmp = x.Start.CompareTo(y.Start);
            if (cmp != 0) return cmp;
            cmp = y.Length.CompareTo(x.Length);
            if (cmp != 0) return cmp;
            cmp = string.CompareOrdinal(x.Name, y.Name);
            if (cmp != 0) return cmp;
            cmp = x.IsPrevious.CompareTo(y.IsPrevious);
            return cmp != 0 ? cmp : x.Kind.CompareTo(y.Kind);
        });
        // Brief T30: the state keeps the raw hits (a carried one is filtered again against the next window,
        // where its right neighbour may be known); the filter runs before the dedupe.
        var kept = deduplicated;
        if (_short is not null)
        {
            kept = new List<FingerprintHit>(deduplicated.Count);
            foreach (var hit in deduplicated)
                if (!(_short.TryGetValue((hit.Name, hit.IsPrevious), out var isShort) && isShort)
                    || TokenBoundary.IsDelimited(text, hit.Start, hit.Length))
                    kept.Add(hit);
        }
        for (var i = 0; i < kept.Count; i++)
        {
            if (i > 0 && kept[i].Start == kept[i - 1].Start && kept[i].Length == kept[i - 1].Length)
                continue;
            hits.Add(kept[i]);
        }
    }

    /// <summary>
    /// The smallest index from which an occurrence could still start in <paramref name="text"/> and end
    /// past it, <c>text.Length</c> when none can. Per class, a start must lie in the trailing run of the
    /// class's characters (whitespace-free, base64, base64url) or, for free entries, see at most the
    /// largest whitespace count (CR, LF, space, tab, counted with <c>\r\n</c> folded), and no earlier than
    /// <c>text.Length − (cap − 1)</c>; caps and the whitespace count are rounded up to a multiple of 256.
    /// With free entries at least the last character is always held, so a <c>\r</c> waiting for its
    /// <c>\n</c> is never emitted early. In whole-token mode (brief T30) a point inside a run of word
    /// characters moves back to the run's start when that is at most <see cref="TokenBoundary.WordHoldLimit"/>
    /// characters back.
    /// </summary>
    public int PendingFrom(ReadOnlySpan<char> text) => PendingFrom(text, state: null);

    /// <summary>
    /// <see cref="PendingFrom(ReadOnlySpan{char})"/>, remembered in <paramref name="state"/> when
    /// <paramref name="text"/> is the window the state's last scan saw (the value does not depend on it).
    /// </summary>
    public int PendingFrom(ReadOnlySpan<char> text, ScanState? state)
    {
        var pendingFrom = PendingFromCore(text);
        if (state is not null && text.SequenceEqual(state.Text))
            state.Pending = pendingFrom;
        return pendingFrom;
    }

    private int PendingFromCore(ReadOnlySpan<char> text)
    {
        var n = text.Length;
        var pending = n;
        if (_capWhitespaceFree > 0)
            pending = Math.Min(pending, Math.Max(TrailingRun(text, IsWhitespaceFree), n - (_capWhitespaceFree - 1)));
        if (_capBase64 > 0)
            pending = Math.Min(pending, Math.Max(TrailingRun(text, IsBase64), n - (_capBase64 - 1)));
        if (_capBase64Url > 0)
            pending = Math.Min(pending, Math.Max(TrailingRun(text, IsBase64Url), n - (_capBase64Url - 1)));
        if (_capFree > 0)
        {
            var lower = Math.Max(0, n - (_capFree - 1));
            var start = lower;
            var whitespace = 0;
            for (var i = n - 1; i >= lower; i--)
            {
                var c = text[i];
                if (IsWhitespace(c) && !(c == '\r' && i + 1 < n && text[i + 1] == '\n') && ++whitespace > _maxFreeWhitespace)
                {
                    start = i + 1;
                    break;
                }
            }
            pending = Math.Min(pending, start);
        }
        pending = Math.Max(0, pending);
        // Brief T30: the next window starts on a word's first character, where "the window's start is a
        // boundary" is true. Reads the text and a constant only, like everything above.
        if (_short is not null && _candidates.Count > 0)
            pending = TokenBoundary.HoldOutsideWord(text, pending);
        return pending;
    }

    // ── scanning ─────────────────────────────────────────────────────────────────────

    private void ScanRuns(ReadOnlySpan<char> text, ulong[] prefix, ulong b, int carried, FoundHits found)
    {
        found.View = 0;
        var powers = PowersOf(b, _runLengths.Select(r => r.Length));
        var n = text.Length;
        // The end of the current run of each class; recomputed when a start passes it.
        int whitespaceFreeEnd = 0, base64End = 0, base64UrlEnd = 0, whitespaceEnd = 0;
        for (var s = 0; s < n; s++)
        {
            if (IsWhitespace(text[s]))
            {
                if (whitespaceEnd <= s)
                {
                    whitespaceEnd = RunEnd(text, s, IsWhitespace);
                    TryFoldedWhitespaceRun(text, s, whitespaceEnd, b, carried, found);
                }
                for (var k = 0; k < _runLengths.Length && _runLengths[k].Length <= whitespaceEnd - s; k++)
                {
                    if ((_runLengths[k].Classes & Classes.WhitespaceOnly) != 0 && s + _runLengths[k].Length > carried)
                        Try(text, prefix, powers[k], s, _runLengths[k].Length, s, _runLengths[k].Length, found);
                }
                continue;
            }
            if (whitespaceFreeEnd <= s) whitespaceFreeEnd = RunEnd(text, s, IsWhitespaceFree);
            if (base64End <= s) base64End = IsBase64(text[s]) ? RunEnd(text, s, IsBase64) : s;
            if (base64UrlEnd <= s) base64UrlEnd = IsBase64Url(text[s]) ? RunEnd(text, s, IsBase64Url) : s;
            int whitespaceFreeRun = whitespaceFreeEnd - s, base64Run = base64End - s, base64UrlRun = base64UrlEnd - s;

            for (var k = 0; k < _runLengths.Length; k++)
            {
                var (length, classes) = _runLengths[k];
                if (length > whitespaceFreeRun)
                    break;
                if (s + length <= carried)
                    continue; // tried in the previous window; its hits are carried
                if ((classes & Classes.WhitespaceFree) != 0
                    || ((classes & Classes.Base64) != 0 && length <= base64Run)
                    || ((classes & Classes.Base64Url) != 0 && length <= base64UrlRun))
                    Try(text, prefix, powers[k], s, length, s, length, found);
            }
        }
    }

    /// <summary>
    /// Whitespace-only entries on a raw whitespace run printed through a PTY (each <c>\n</c> as
    /// <c>\r\n</c>): the run is folded on its own (runs are short, so this costs next to nothing) and its
    /// windows tried with their raw spans. Runs without a <c>\r\n</c> are covered by the raw tries.
    /// </summary>
    private void TryFoldedWhitespaceRun(ReadOnlySpan<char> text, int start, int end, ulong b, int carried, FoundHits found)
    {
        var run = text[start..end];
        if (!run.Contains("\r\n", StringComparison.Ordinal) || !_runLengths.Any(r => (r.Classes & Classes.WhitespaceOnly) != 0))
            return;
        Span<char> folded = run.Length <= 512 ? stackalloc char[run.Length] : new char[run.Length];
        Span<int> rawStart = run.Length <= 512 ? stackalloc int[run.Length] : new int[run.Length];
        Span<int> rawEnd = run.Length <= 512 ? stackalloc int[run.Length] : new int[run.Length];
        var m = 0;
        for (var i = 0; i < run.Length; i++)
        {
            var pair = run[i] == '\r' && i + 1 < run.Length && run[i + 1] == '\n';
            folded[m] = pair ? '\n' : run[i];
            rawStart[m] = start + i;
            if (pair) i++;
            rawEnd[m] = start + i + 1;
            m++;
        }
        for (var fs = 0; fs < m; fs++)
        {
            foreach (var (length, classes) in _runLengths)
            {
                if (fs + length > m)
                    break;
                if ((classes & Classes.WhitespaceOnly) == 0 || rawEnd[fs + length - 1] <= carried)
                    continue;
                var window = folded.Slice(fs, length);
                var view = found.View;
                found.View = 1;
                TryHash(window, RollingHash.Of(window, b), rawStart[fs], rawEnd[fs + length - 1] - rawStart[fs], found);
                found.View = view;
            }
        }
    }

    /// <summary>
    /// Free entries over one view. <paramref name="rawStart"/>/<paramref name="rawEnd"/> map a folded or
    /// unfolded view's indices back to the raw text (null: the view is the raw text); a window whose raw span
    /// would be empty is not tried.
    /// </summary>
    private void ScanFree(ReadOnlySpan<char> view, ulong[] prefix, int[] counts, ulong b, int carried, int[]? rawStart, int[]? rawEnd, FoundHits found)
    {
        var powers = PowersOf(b, _freeShapes.Select(f => f.Length));
        var n = view.Length;
        for (var s = 0; s < n; s++)
        {
            for (var k = 0; k < _freeShapes.Length; k++)
            {
                var (length, whitespace) = _freeShapes[k];
                if (s + length > n)
                    break;
                if (s + length <= carried)
                    continue; // tried in the previous window; its hits are carried
                if (whitespace >= 0 && counts[s + length] - counts[s] != whitespace)
                    continue;
                if (rawStart is null)
                    Try(view, prefix, powers[k], s, length, s, length, found);
                else if (rawEnd![s + length - 1] > rawStart[s])
                    Try(view, prefix, powers[k], s, length, rawStart[s], rawEnd[s + length - 1] - rawStart[s], found);
            }
        }
    }

    /// <summary>Free entries on the view with each <c>\r\n</c> folded to <c>\n</c>.</summary>
    private void ScanFolded(ReadOnlySpan<char> text, ulong b, FoundHits found)
    {
        var n = text.Length;
        var folded = ArrayPool<char>.Shared.Rent(n);
        var rawStart = ArrayPool<int>.Shared.Rent(n);
        var rawEnd = ArrayPool<int>.Shared.Rent(n);
        var prefix = ArrayPool<ulong>.Shared.Rent(n + 1);
        var counts = ArrayPool<int>.Shared.Rent(n + 1);
        try
        {
            var m = LineEndingViews.Fold(text, folded, rawStart, rawEnd);
            var view = folded.AsSpan(0, m);
            PrefixHashes(view, b, prefix);
            counts[0] = 0;
            for (var i = 0; i < m; i++)
                counts[i + 1] = counts[i] + (IsWhitespace(view[i]) ? 1 : 0);
            ScanFree(view, prefix, counts, b, carried: 0, rawStart, rawEnd, found);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(folded, clearArray: true);
            ArrayPool<int>.Shared.Return(rawStart);
            ArrayPool<int>.Shared.Return(rawEnd);
            ArrayPool<ulong>.Shared.Return(prefix);
            ArrayPool<int>.Shared.Return(counts);
        }
    }

    /// <summary>
    /// Brief T50a (#398): free entries on the view with each <c>\n</c> not preceded by <c>\r</c> unfolded to
    /// <c>\r\n</c> (<see cref="LineEndingViews.Unfold"/>). An inserted <c>\r</c> maps to the empty raw position
    /// before its <c>\n</c>, so a hit's raw span is never longer than its entry: <see cref="MaxRawLength"/>, the
    /// caps and <see cref="PendingFrom(ReadOnlySpan{char})"/> are unchanged. A hit with an empty raw span is dropped.
    /// </summary>
    private void ScanUnfolded(ReadOnlySpan<char> text, ulong b, FoundHits found)
    {
        var capacity = 2 * text.Length;
        var unfolded = ArrayPool<char>.Shared.Rent(capacity);
        var rawStart = ArrayPool<int>.Shared.Rent(capacity);
        var rawEnd = ArrayPool<int>.Shared.Rent(capacity);
        var prefix = ArrayPool<ulong>.Shared.Rent(capacity + 1);
        var counts = ArrayPool<int>.Shared.Rent(capacity + 1);
        try
        {
            var m = LineEndingViews.Unfold(text, unfolded, rawStart, rawEnd);
            var view = unfolded.AsSpan(0, m);
            PrefixHashes(view, b, prefix);
            counts[0] = 0;
            for (var i = 0; i < m; i++)
                counts[i + 1] = counts[i] + (IsWhitespace(view[i]) ? 1 : 0);
            ScanFree(view, prefix, counts, b, carried: 0, rawStart, rawEnd, found);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(unfolded, clearArray: true);
            ArrayPool<int>.Shared.Return(rawStart);
            ArrayPool<int>.Shared.Return(rawEnd);
            ArrayPool<ulong>.Shared.Return(prefix);
            ArrayPool<int>.Shared.Return(counts);
        }
    }

    /// <summary>
    /// Brief T65 (#434): free entries on the view with every line break (<c>\r\n</c>, a lone <c>\r</c>, <c>\n</c>)
    /// written as <paramref name="lineBreak"/> (<see cref="LineEndingViews.WriteBreaks"/>), built as
    /// <see cref="ScanUnfolded"/> is. A hit's raw span is at most <c>L + W</c> long (<c>L</c> in the <c>\r\n</c> view) and
    /// holds at most <c>W</c> counted whitespace, so <see cref="MaxRawLength"/>, the caps and
    /// <see cref="PendingFrom(ReadOnlySpan{char})"/> need nothing more. A hit with an empty raw span is dropped.
    /// </summary>
    private void ScanBreaks(ReadOnlySpan<char> text, string lineBreak, ulong b, FoundHits found)
    {
        var capacity = 2 * text.Length;
        var written = ArrayPool<char>.Shared.Rent(capacity);
        var rawStart = ArrayPool<int>.Shared.Rent(capacity);
        var rawEnd = ArrayPool<int>.Shared.Rent(capacity);
        var prefix = ArrayPool<ulong>.Shared.Rent(capacity + 1);
        var counts = ArrayPool<int>.Shared.Rent(capacity + 1);
        try
        {
            var m = LineEndingViews.WriteBreaks(text, lineBreak, written, rawStart, rawEnd);
            var view = written.AsSpan(0, m);
            PrefixHashes(view, b, prefix);
            counts[0] = 0;
            for (var i = 0; i < m; i++)
                counts[i + 1] = counts[i] + (IsWhitespace(view[i]) ? 1 : 0);
            ScanFree(view, prefix, counts, b, carried: 0, rawStart, rawEnd, found);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(written, clearArray: true);
            ArrayPool<int>.Shared.Return(rawStart);
            ArrayPool<int>.Shared.Return(rawEnd);
            ArrayPool<ulong>.Shared.Return(prefix);
            ArrayPool<int>.Shared.Return(counts);
        }
    }

    /// <summary>A found hit with the index of the view it was found in and its entry's length (brief T65, #434).</summary>
    internal readonly record struct ScanHit(FingerprintHit Hit, int View, int EntryLength);

    /// <summary>The hits of one scan, and the view now being scanned (one per scan, so concurrent scans stay safe).</summary>
    internal sealed class FoundHits
    {
        public List<ScanHit> Items { get; } = [];

        public int View { get; set; }
    }

    private void Try(ReadOnlySpan<char> view, ulong[] prefix, ulong power, int start, int length, int hitStart, int hitLength, FoundHits found)
    {
        // The window's hash from prefix hashes: H[s+L] − H[s]·b^L, the same value as RollingHash.Of.
        var hash = prefix[start + length] + RollingHash.Modulus - Reduce((UInt128)prefix[start] * power);
        if (hash >= RollingHash.Modulus) hash -= RollingHash.Modulus;
        TryHash(view.Slice(start, length), hash, hitStart, hitLength, found);
    }

    private void TryHash(ReadOnlySpan<char> window, ulong hash, int hitStart, int hitLength, FoundHits found)
    {
        var length = window.Length;
        if (!FilterHas(length, hash) || !_candidates.TryGetValue((length, hash), out var candidates))
            return;
        // A window that cuts a surrogate pair is never confirmed: UTF-8 is not injective on it.
        if (FingerprintIndex.SplitsASurrogatePair(window))
            return;

        var mac = Fingerprinter.Hmac(window, _keys);
        try
        {
            foreach (var c in candidates)
            {
                if (CryptographicOperations.FixedTimeEquals(mac, c.Hmac))
                    found.Items.Add(new ScanHit(new FingerprintHit(c.Name, c.IsPrevious, c.Kind, hitStart, hitLength), found.View, length));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mac);
        }
    }

    private static void PrefixHashes(ReadOnlySpan<char> view, ulong b, ulong[] prefix)
    {
        prefix[0] = 0;
        for (var i = 0; i < view.Length; i++)
            prefix[i + 1] = Reduce((UInt128)prefix[i] * b + view[i]);
    }

    private static ulong[] PowersOf(ulong b, IEnumerable<int> lengths) => [.. lengths.Select(l => RollingHash.Power(b, l))];

    /// <summary><c>x mod p</c> for <c>p = 2^61 − 1</c>, reduced as <see cref="RollingHash"/> does (inputs below 2^123).</summary>
    private static ulong Reduce(UInt128 x)
    {
        var folded = (ulong)(x & RollingHash.Modulus) + (ulong)(x >> 61);
        folded = (folded & RollingHash.Modulus) + (folded >> 61);
        return folded >= RollingHash.Modulus ? folded - RollingHash.Modulus : folded;
    }

    private static int FilterIndex(int length, ulong hash) =>
        (int)(((hash ^ ((ulong)length * 0x9E3779B97F4A7C15UL)) * 0xBF58476D1CE4E5B9UL) >> 44);

    private void SetFilter(int length, ulong hash)
    {
        var i = FilterIndex(length, hash);
        _filter[i >> 6] |= 1UL << (i & 63);
    }

    private bool FilterHas(int length, ulong hash)
    {
        var i = FilterIndex(length, hash);
        return (_filter[i >> 6] & (1UL << (i & 63))) != 0;
    }

    // ── character classes ────────────────────────────────────────────────────────────

    /// <summary>The whitespace <see cref="SecretVariants"/> strips: CR, LF, space, tab.</summary>
    private static bool IsWhitespace(char c) => c is '\r' or '\n' or ' ' or '\t';

    private static bool IsWhitespaceFree(char c) => !IsWhitespace(c);

    private static bool IsBase64(char c) => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=';

    private static bool IsBase64Url(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_';

    private static int RunEnd(ReadOnlySpan<char> text, int from, Func<char, bool> allowed)
    {
        var end = from;
        while (end < text.Length && allowed(text[end])) end++;
        return end;
    }

    private static int TrailingRun(ReadOnlySpan<char> text, Func<char, bool> allowed)
    {
        var start = text.Length;
        while (start > 0 && allowed(text[start - 1])) start--;
        return start;
    }

    private static int RoundUp(int value) => value <= 0 ? 0 : (value + Quantum - 1) / Quantum * Quantum;
}
