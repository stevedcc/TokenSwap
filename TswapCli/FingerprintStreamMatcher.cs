using RedactingPty;
using TswapCore;
using TswapCore.Fingerprints;

namespace TswapCli;

/// <summary>
/// Brief T16-S3: <c>run</c>'s <see cref="IStreamMatcher"/>. It masks every fingerprinted value version of
/// the vault (current and previous, burned ones included) from the keyed fingerprints alone, through a
/// <see cref="FingerprintScanner"/>, with the label <c>run</c> gives its own tokens:
/// <c>[REDACTED: name]</c>, or <c>[REDACTED: name:previous]</c> for a previous value, for every kind of
/// variant. Stateless per call, so one matcher serves both of the pipe runner's drain threads.
/// </summary>
internal sealed class FingerprintStreamMatcher : IStreamMatcher
{
    private readonly FingerprintScanner _scanner;

    private FingerprintStreamMatcher(FingerprintScanner scanner)
    {
        _scanner = scanner;
        MaxMatchLength = Math.Max(1, scanner.MaxRawLength);
    }

    /// <summary>
    /// A matcher for every retained version of every record in <paramref name="metadata"/> that has a
    /// fingerprint set. Works only while <paramref name="keys"/> stay undisposed.
    /// </summary>
    public static FingerprintStreamMatcher For(VaultMetadata metadata, FingerprintKeys keys)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var sets = metadata.Records
            .SelectMany(r => r.RetainedVersions()
                .Where(v => v.Fingerprints is not null)
                .Select(v => (r.Name, v.IsPrevious, v.Fingerprints!)));
        return new FingerprintStreamMatcher(FingerprintScanner.Build(sets, keys));
    }

    /// <summary>The scanner's longest raw span (fold slack included), at least 1.</summary>
    public int MaxMatchLength { get; }

    public void FindMatches(ReadOnlySpan<char> window, ICollection<StreamMatch> matches)
    {
        List<FingerprintHit> hits = [];
        _scanner.Scan(window, hits);
        foreach (var hit in hits)
            matches.Add(new StreamMatch(hit.Start, hit.Length, Label(hit)));
    }

    public int PendingFrom(ReadOnlySpan<char> window) => _scanner.PendingFrom(window);

    private static string Label(FingerprintHit hit) =>
        hit.IsPrevious ? $"[REDACTED: {hit.Name}:previous]" : $"[REDACTED: {hit.Name}]";
}
