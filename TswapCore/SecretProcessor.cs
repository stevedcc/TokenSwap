using TswapCore.Fingerprints;

namespace TswapCore;

public enum MatchType { Plaintext, Base64, Base64Url }

public record LineDiff(int LineNumber, string Before, string After);

/// <summary>
/// Brief T50b Task 3 (#399): lines <see cref="LineDiff.LineNumber"/> to <see cref="LastLineNumber"/> of the input, a
/// value with a line break after <c>key:</c>, replaced by one line. <see cref="LineDiff.Before"/> is those lines joined
/// with <c>\n</c> (without <c>\r</c>); it is never printed (<c>--dry-run</c> shows <c>[value over N lines]</c>).
/// </summary>
public sealed record MultiLineDiff(int LineNumber, int LastLineNumber, string Before, string After)
    : LineDiff(LineNumber, Before, After);

/// <summary>
/// Brief T63 (#419): a continuation line of a replaced value that <c>tocomment</c> would have removed, commented out
/// (<c># </c> after its indentation) because it holds a stored value. Its text can hold a fragment of the replaced
/// value, as a removed line can, so it is never printed (<c>--dry-run</c> shows
/// <c>[continuation line holding a stored value]</c>).
/// </summary>
public sealed record CommentedLineDiff(int LineNumber, string Before, string After) : LineDiff(LineNumber, Before, After);

/// <summary>
/// Brief T22 (#319): a line <c>tocomment</c> left as it was because it is YAML block-scalar content
/// holding an encoded form (base64, base64url, whitespace-stripped) of the value of <see cref="Token"/>
/// (<c>name</c> or <c>name:previous</c>): a marker is filled with the plain value, so replacing it would
/// change the value. It carries no text of the line; it is not a <see cref="LineDiff"/>, so nothing that
/// prints changes prints it.
/// </summary>
public sealed record UnreplacedLine(int LineNumber, string Token);

/// <summary>Brief T50b (#394, #399): why <c>tocomment</c> left an occurrence of a value in place.</summary>
public enum SkippedReason
{
    /// <summary>Not a whole value <c>apply</c> fills back (<c>key: value</c>, or <c>KEY=value</c> without control characters).</summary>
    NotWholeValue,

    /// <summary>A plain value on a line of YAML block-scalar content that T22 leaves whole, or a multi-line value inside one.</summary>
    InBlockScalar,

    /// <summary>
    /// Brief T63 (#419): a continuation line of a replaced value (indented deeper, base64-like) that tocomment would have
    /// removed; it holds a stored value, so it was commented out instead.
    /// </summary>
    ContinuationLine,
}

/// <summary>
/// Brief T50b (#394, #399): an occurrence of the value of <see cref="Token"/> (<c>name</c> or <c>name:previous</c>)
/// that <c>tocomment</c> found and left in place, on lines <see cref="FirstLine"/> to <see cref="LastLine"/> of the
/// input file (equal for a value on one line). It carries no text.
/// </summary>
public sealed record SkippedValue(int FirstLine, int LastLine, string Token, SkippedReason Reason);

/// <summary>
/// Brief T50b: everything <c>tocomment</c> did to a file: the new content (LF), the changes, the lines T22 left
/// (<see cref="UnreplacedLine"/>), the occurrences left in place (<see cref="SkippedValue"/>, ordered by first line,
/// last line, then token ordinally) and the base name of every secret with at least one replaced occurrence
/// (distinct, ordinal).
/// </summary>
public sealed record ToCommentReport(string Content, IReadOnlyList<LineDiff> Changes,
    IReadOnlyList<UnreplacedLine> Unreplaced, IReadOnlyList<SkippedValue> Skipped,
    IReadOnlyList<string> ReplacedNames);

/// <summary>
/// The plaintext match list. Brief T16-S2: matching itself is <see cref="SecretMatcher"/>'s, from
/// fingerprints, with the labels of <see cref="RedactProcessor"/> and the replacement of
/// <see cref="ToCommentProcessor"/>; <see cref="BuildMatchList"/> stays as the definition of the
/// search texts and their order that the fingerprint engine reproduces (SecretVariantsTests pins its
/// variants against <see cref="SecretVariants"/> through a subclass, which is why this class and
/// <see cref="GetReplacement"/> remain).
/// </summary>
public abstract class SecretProcessor
{
    /// <summary>
    /// The ordered list of (name, matchType, searchText) entries for all secrets, including
    /// plaintext, Base64, Base64Url and whitespace-stripped variants; previous values as
    /// <c>name:previous</c>. Sorted by search text length descending, then search text, then live
    /// before burned, then name, then type.
    /// </summary>
    protected static IReadOnlyList<(string Name, MatchType Type, string SearchText)>
        BuildMatchList(SecretsDb db)
    {
        List<(string Name, MatchType Type, string SearchText)> list = [];

        // Fix round 3: a rotated-away value is a live credential until the service is switched, so
        // it is matched too, as 'name:previous' (never as 'name').
        var entries = db.Secrets.Select(kv => (Name: kv.Key, Value: kv.Value.Value))
            .Concat(db.Secrets.Where(kv => kv.Value.PreviousValue is not null)
                .Select(kv => (Name: kv.Key + SecretsDb.PreviousSuffix, Value: kv.Value.PreviousValue!)));
        // Brief T16-S1: the variants come from SecretVariants, the same list record format v3
        // fingerprints.
        foreach (var (name, value) in entries)
        {
            foreach (var (kind, text) in SecretVariants.For(value))
                list.Add((name, TypeOf(kind), text));
        }

        list.Sort((a, b) =>
        {
            int cmp = b.SearchText.Length.CompareTo(a.SearchText.Length);
            if (cmp != 0) return cmp;
            cmp = string.Compare(a.SearchText, b.SearchText, StringComparison.Ordinal);
            if (cmp != 0) return cmp;
            // Prefer non-burned: false (0) sorts before true (1)
            bool aBurned = db.Secrets.TryGetValue(a.Name, out var as_) && as_.BurnedAt.HasValue;
            bool bBurned = db.Secrets.TryGetValue(b.Name, out var bs_) && bs_.BurnedAt.HasValue;
            cmp = aBurned.CompareTo(bBurned);
            if (cmp != 0) return cmp;
            cmp = string.Compare(a.Name, b.Name, StringComparison.Ordinal);
            if (cmp != 0) return cmp;
            return a.Type.CompareTo(b.Type);
        });
        return list;
    }

    /// <summary>
    /// The match type of a variant: plain and whitespace-stripped are both plaintext. A form kind (brief T54) has its
    /// base kind's type, so a match never says which spelling was found.
    /// </summary>
    internal static MatchType TypeOf(VariantKind kind) => kind.BaseKind() switch
    {
        VariantKind.Base64 => MatchType.Base64,
        VariantKind.Base64Url => MatchType.Base64Url,
        _ => MatchType.Plaintext,
    };

    /// <summary>The string that replaces each match.</summary>
    protected abstract string GetReplacement(string secretName, MatchType matchType);
}
