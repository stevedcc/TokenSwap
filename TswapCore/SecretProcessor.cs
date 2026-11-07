using TswapCore.Fingerprints;

namespace TswapCore;

public enum MatchType { Plaintext, Base64, Base64Url }

public record LineDiff(int LineNumber, string Before, string After);

/// <summary>
/// Base of <see cref="RedactProcessor"/> and <see cref="ToCommentProcessor"/>: what each match
/// becomes (<see cref="GetReplacement"/>) and the plaintext match list. Brief T16-S2: matching
/// itself is <see cref="SecretMatcher"/>'s, from fingerprints; <see cref="BuildMatchList"/> stays as
/// the definition of the search texts and their order that the fingerprint engine reproduces (its
/// variants are pinned against <see cref="SecretVariants"/> by the tests).
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

    /// <summary>The match type of a variant: plain and whitespace-stripped are both plaintext.</summary>
    internal static MatchType TypeOf(VariantKind kind) => kind switch
    {
        VariantKind.Base64 => MatchType.Base64,
        VariantKind.Base64Url => MatchType.Base64Url,
        _ => MatchType.Plaintext,
    };

    /// <summary>The string that replaces each match.</summary>
    protected abstract string GetReplacement(string secretName, MatchType matchType);
}
