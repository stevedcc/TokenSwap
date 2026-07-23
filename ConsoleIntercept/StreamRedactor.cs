namespace ConsoleIntercept;

/// <summary>
/// Stateful, streaming redactor for PTY/pipe output. Maintains a sliding-window overlap
/// between successive chunks so find-strings that straddle a read-buffer boundary are
/// still caught.
///
/// Usage pattern:
/// <code>
///   var r = new StreamRedactor(replacements);
///   foreach (var chunk in readLoop)
///       emit(r.ProcessChunk(chunk));
///   emit(r.Flush());
/// </code>
/// </summary>
public sealed class StreamRedactor
{
    private readonly IReadOnlyList<StreamReplacement> _replacements;
    private readonly int _overlap;
    private string _tail = "";

    public StreamRedactor(IReadOnlyList<StreamReplacement> replacements)
    {
        ArgumentNullException.ThrowIfNull(replacements);
        foreach (var r in replacements)
        {
            if (r is null)
                throw new ArgumentException("Replacement entries must not be null.", nameof(replacements));
            if (r.Find is null || r.Replace is null)
                throw new ArgumentException("StreamReplacement.Find and .Replace must not be null (use \"\" for an inert entry).", nameof(replacements));
        }

        // Defensive longest-Find-first sort: a shorter Find that shares a prefix with a
        // longer one must not clobber it. Callers typically pass a pre-sorted list, but
        // re-sorting is cheap and makes the class safe to use standalone.
        _replacements = replacements.OrderByDescending(r => r.Find.Length).ToList();
        // Retain (longestFind - 1) chars between chunks: the minimum overlap that guarantees
        // any single find-string, split at any position, is still seen in full.
        _overlap = _replacements.Count > 0 ? Math.Max(0, _replacements[0].Find.Length - 1) : 0;
    }

    /// <summary>
    /// Incorporates the next decoded chunk and returns the redacted prefix that is safe to emit.
    /// The tail (up to <c>overlap</c> chars) is held back and prepended to the next chunk.
    /// </summary>
    public string ProcessChunk(string chunk)
    {
        ArgumentNullException.ThrowIfNull(chunk);

        var window  = _tail + chunk;
        var safeLen = Math.Max(0, window.Length - _overlap);

        // A find-string may start before safeLen and end after it, meaning the naive split
        // would divide it across the emit/tail boundary and neither half would match. Fix:
        // pull safeLen back to the start of any such straddling match. Repeat until stable
        // (a pull can expose further straddling matches earlier in the window).
        bool adjusted;
        do
        {
            adjusted = false;
            foreach (var r in _replacements)
            {
                if (string.IsNullOrEmpty(r.Find)) continue;
                var idx = 0;
                while ((idx = window.IndexOf(r.Find, idx, StringComparison.Ordinal)) >= 0)
                {
                    var matchEnd = idx + r.Find.Length;
                    if (idx < safeLen && matchEnd > safeLen)
                    {
                        safeLen  = idx;
                        adjusted = true;
                    }
                    idx++;
                }
            }
        } while (adjusted);

        // Don't split a UTF-16 surrogate pair at the emit boundary.
        if (safeLen > 0 && safeLen < window.Length &&
            char.IsHighSurrogate(window[safeLen - 1]) && char.IsLowSurrogate(window[safeLen]))
            safeLen--;

        _tail = window[safeLen..];
        return ApplyReplacements(window[..safeLen]);
    }

    /// <summary>
    /// Flushes the retained tail after the last chunk. Must be called once at EOF.
    /// </summary>
    public string Flush()
    {
        var result = _tail.Length > 0 ? ApplyReplacements(_tail) : "";
        _tail = "";
        return result;
    }

    private string ApplyReplacements(string text)
    {
        foreach (var r in _replacements)
        {
            if (!string.IsNullOrEmpty(r.Find))
                text = text.Replace(r.Find, r.Replace);
        }
        return text;
    }
}
