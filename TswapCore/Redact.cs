using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore.Fingerprints;

namespace TswapCore;

/// <summary>
/// Static facade over <see cref="SecretMatcher"/>, plus the standalone heuristic scanner for
/// unrecognized secrets.
/// </summary>
public static class Redact
{
    // Matches credential-keyword = value patterns for heuristic unknown-secret detection.
    private static readonly Regex CredentialHeuristic = new(
        @"(?:password|passwd|token|secret|key|apikey|api_key|pass)\s*[:=]\s*[""']?([A-Za-z0-9+/\-_]{12,}=*)[""']?",
        RegexOptions.IgnoreCase);

    /// <summary>
    /// <c>redact</c>: a copy of <paramref name="content"/> with every value <paramref name="matcher"/>
    /// recognises replaced by its <c>[REDACTED: name]</c> label.
    /// </summary>
    public static string RedactContent(string content, SecretMatcher matcher) => matcher.Redact(content);

    /// <summary>
    /// <c>tocomment</c>: a copy of <paramref name="content"/> with inline secret values replaced by
    /// <c>""  # tswap: name</c>, plus the list of changed lines for dry-run display.
    /// </summary>
    public static (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content, SecretMatcher matcher) =>
        matcher.ToComment(content);

    /// <summary>
    /// Brief T16-S2: <see cref="RedactContent(string, SecretMatcher)"/> over a loaded database, by
    /// fingerprinting its values under a random key. No command uses it (they never decrypt the
    /// values for this); it keeps the engine's tests written against plain values.
    /// </summary>
    internal static string RedactContent(string content, SecretsDb db) => WithMatcher(db, m => m.Redact(content));

    /// <summary>Brief T16-S2: <see cref="ToComment(string, SecretMatcher)"/> over a loaded database (see <see cref="RedactContent(string, SecretsDb)"/>).</summary>
    internal static (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content, SecretsDb db) =>
        WithMatcher(db, m => m.ToComment(content));

    private static T WithMatcher<T>(SecretsDb db, Func<SecretMatcher, T> use)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var keys = FingerprintKeys.Derive(key);
            List<(string, bool, FingerprintSet)> sets = [];
            foreach (var (name, secret) in db.Secrets)
            {
                sets.Add((name, false, Fingerprinter.Compute(Encoding.UTF8.GetBytes(secret.Value), keys)));
                if (secret.PreviousValue is { } previous)
                    sets.Add((name, true, Fingerprinter.Compute(Encoding.UTF8.GetBytes(previous), keys)));
            }
            var burned = db.Secrets.Where(kv => kv.Value.BurnedAt.HasValue).Select(kv => kv.Key).ToHashSet(StringComparer.Ordinal);
            return use(new SecretMatcher(FingerprintIndex.Build(sets, keys), burned));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Replaces secret values in <paramref name="line"/> with <c>[REDACTED: name]</c>.
    /// Caller is responsible for ordering — pass values longest-first to prevent a shorter
    /// value from clobbering a longer one that shares a prefix.
    /// (Streaming subprocess redaction lives in the RedactingPty package; this helper
    /// remains for single-line use.)
    /// </summary>
    public static string RedactLine(string line, IEnumerable<KeyValuePair<string, string>> secretValues)
    {
        foreach (var kvp in secretValues)
        {
            if (!string.IsNullOrEmpty(kvp.Value))
                line = line.Replace(kvp.Value, $"[REDACTED: {kvp.Key}]");
        }
        return line;
    }

    /// <summary>
    /// Scans <paramref name="content"/> for strings that look like unrecognized credentials
    /// (adjacent to a keyword like <c>password</c>, <c>token</c>, etc.). Returns the 1-based
    /// line number and the matched snippet for each hit.
    /// </summary>
    public static IReadOnlyList<(int Line, string Snippet)> FindUnknownSecrets(string content)
    {
        List<(int, string)> results = [];
        var lines = content.Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            var matches = CredentialHeuristic.Matches(lines[i]);
            if (matches.Count > 0)
                results.Add((i + 1, lines[i].Trim()));
        }

        return results;
    }
}
