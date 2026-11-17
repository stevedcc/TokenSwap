using RedactingPty;
using TswapCore;
using TswapCore.Fingerprints;

namespace TswapCli;

/// <summary>
/// Brief T16-S3: <c>run</c>'s <see cref="IStreamMatcher"/>. It masks every fingerprinted value version of
/// the vault (current and previous, burned ones included) from the keyed fingerprints alone, through a
/// <see cref="FingerprintScanner"/>, with the label <c>run</c> gives its own tokens:
/// <c>[REDACTED: name]</c>, or <c>[REDACTED: name:previous]</c> for a previous value, for every kind of
/// variant. Each thread carries its own <see cref="FingerprintScanner.ScanState"/> from one window to
/// the next, so the held end of the output is not hashed and scanned again with every chunk; the state
/// is used only when the next window starts with that held text (checked on the text), so the results
/// are those of a fresh scan, and one matcher still serves both of the pipe runner's drain threads.
/// <para>
/// Brief T30 (#314): a value version shorter than 8 characters is masked only where it stands as a whole
/// word or number (<see cref="TokenBoundary.IsDelimited"/>), the window's edges counting as boundaries: the
/// scanner runs in <see cref="ShortValueMatching.WholeToken"/> mode, and <c>run</c>'s own short values
/// (substituted, <c>--env</c> and file values, every written form and encoding) come as plaintext
/// <em>short forms</em>, matched here rather than as RedactingPty replacements. An occurrence ending at the
/// window's end lies in the held tail and is decided by the next window; the pending point never splits a
/// word it can hold (<see cref="TokenBoundary.HoldOutsideWord"/>), so the next window starts on a word's start.
/// The short forms are held by class as the scanner holds its entries: the trailing run of non-whitespace
/// characters (at most a 256-quantised bound) for forms without whitespace, the 256-quantised bound itself for
/// forms with it (brief T39, #341).
/// </para>
/// </summary>
internal sealed class FingerprintStreamMatcher : IStreamMatcher, IDisposable
{
    private const int Quantum = 256;

    private readonly FingerprintScanner _scanner;
    private readonly (string Text, string Label)[] _shortForms;
    // Brief T39 (#341), after T30's amendment A2: how much each class of short forms holds back at most,
    // forms without whitespace and forms with it, each rounded up to a multiple of 256 like the scanner's
    // caps, never a figure derived exactly from a value's length (0: no short forms of that class).
    private readonly int _shortHoldWhitespaceFree, _shortHoldWithWhitespace;
    private readonly ThreadLocal<FingerprintScanner.ScanState> _state = new(() => new(), trackAllValues: true);

    private FingerprintStreamMatcher(FingerprintScanner scanner, IReadOnlyDictionary<string, string>? shortForms)
    {
        _scanner = scanner;
        _shortForms = shortForms is null ? [] : [.. shortForms.Where(f => f.Key.Length > 0).Select(f => (f.Key, f.Value))];
        var longest = _shortForms.Length == 0 ? 0 : _shortForms.Max(f => f.Text.Length);
        // Per class, at least its longest short form is held (an occurrence ending at the window's end waits
        // there for its right neighbour): RoundUp(longest + 1) - 1, which is RoundUp(longest) - 1 unless
        // longest is a multiple of 256, and never less than longest.
        static int Hold(IEnumerable<string> forms)
        {
            var longest = forms.Select(f => f.Length).DefaultIfEmpty(0).Max();
            return longest == 0 ? 0 : (longest + Quantum) / Quantum * Quantum - 1;
        }
        _shortHoldWhitespaceFree = Hold(_shortForms.Select(f => f.Text).Where(t => !t.Any(IsWhitespace)));
        _shortHoldWithWhitespace = Hold(_shortForms.Select(f => f.Text).Where(t => t.Any(IsWhitespace)));
        MaxMatchLength = Math.Max(1, Math.Max(scanner.MaxRawLength, longest));
    }

    /// <summary>
    /// A matcher for every retained version of every record in <paramref name="metadata"/> that has a
    /// fingerprint set (short ones whole-token only), and for <paramref name="shortForms"/> (text to label),
    /// each matched only where it is delimited. Works only while <paramref name="keys"/> stay undisposed.
    /// </summary>
    public static FingerprintStreamMatcher For(VaultMetadata metadata, FingerprintKeys keys, IReadOnlyDictionary<string, string>? shortForms = null)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var sets = metadata.Records
            .SelectMany(r => r.RetainedVersions()
                .Where(v => v.Fingerprints is not null)
                .Select(v => (r.Name, v.IsPrevious, v.Fingerprints!)));
        return new FingerprintStreamMatcher(FingerprintScanner.Build(sets, keys, ShortValueMatching.WholeToken), shortForms);
    }

    /// <summary>The scanner's longest raw span (fold slack included) or the longest short form, at least 1.</summary>
    public int MaxMatchLength { get; }

    public void FindMatches(ReadOnlySpan<char> window, ICollection<StreamMatch> matches)
    {
        List<FingerprintHit> hits = [];
        _scanner.Scan(window, hits, _state.Value);
        foreach (var hit in hits)
            matches.Add(new StreamMatch(hit.Start, hit.Length, Label(hit)));
        // Every delimited occurrence of every short form, overlapping ones included (the redactor merges them).
        foreach (var (text, label) in _shortForms)
        {
            for (var at = window.IndexOf(text, StringComparison.Ordinal); at >= 0;)
            {
                if (TokenBoundary.IsDelimited(window, at, text.Length))
                    matches.Add(new StreamMatch(at, text.Length, label));
                var next = window[(at + 1)..].IndexOf(text, StringComparison.Ordinal);
                at = next < 0 ? -1 : at + 1 + next;
            }
        }
    }

    public int PendingFrom(ReadOnlySpan<char> window)
    {
        var n = window.Length;
        var pending = _scanner.PendingFrom(window, _state.Value);
        // Brief T39: an occurrence of a form without whitespace that reaches the window's end lies inside the
        // trailing non-whitespace run, so holding from that run's start (or the class's bound, when the run is
        // longer) keeps it whole; a window that ends in a line break holds nothing for this class.
        if (_shortHoldWhitespaceFree > 0)
            pending = Math.Min(pending, Math.Max(TrailingNonWhitespace(window), n - _shortHoldWhitespaceFree));
        if (_shortHoldWithWhitespace > 0)
            pending = Math.Min(pending, Math.Max(0, n - _shortHoldWithWhitespace));
        if (_scanner.MaxRawLength > 0 || _shortForms.Length > 0)
            pending = TokenBoundary.HoldOutsideWord(window, pending);
        return pending;
    }

    /// <summary>Clears every thread's carried state (the last window's text is output) once the run is over.</summary>
    public void Dispose()
    {
        foreach (var state in _state.Values)
            state.Clear();
        _state.Dispose();
    }

    /// <summary>
    /// The whitespace <see cref="SecretVariants"/> strips: CR, LF, space, tab (the twin of
    /// <c>FingerprintScanner.IsWhitespace</c>). The class of a short form and the trailing run read this one set.
    /// </summary>
    private static bool IsWhitespace(char c) => c is '\r' or '\n' or ' ' or '\t';

    /// <summary>The start of the trailing run of characters other than whitespace (the text's length when it ends in whitespace).</summary>
    private static int TrailingNonWhitespace(ReadOnlySpan<char> text)
    {
        var start = text.Length;
        while (start > 0 && !IsWhitespace(text[start - 1])) start--;
        return start;
    }

    private static string Label(FingerprintHit hit) =>
        hit.IsPrevious ? $"[REDACTED: {hit.Name}:previous]" : $"[REDACTED: {hit.Name}]";
}
