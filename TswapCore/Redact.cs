using System.Text.RegularExpressions;

namespace TswapCore;

/// <summary>
/// Static facade over <see cref="SecretProcessor"/> subclasses, plus the standalone
/// heuristic scanner for unrecognized secrets.
/// </summary>
public static class Redact
{
    // Matches credential-keyword = value patterns for heuristic unknown-secret detection.
    private static readonly Regex CredentialHeuristic = new(
        @"(?:password|passwd|token|secret|key|apikey|api_key|pass)\s*[:=]\s*[""']?([A-Za-z0-9+/\-_]{12,}=*)[""']?",
        RegexOptions.IgnoreCase);

    /// <summary>
    /// Returns a copy of <paramref name="content"/> with all known secret values (and their
    /// Base64 variants) replaced by <c>[REDACTED: name]</c> labels.
    /// </summary>
    public static string RedactContent(string content, SecretsDb db)
        => new RedactProcessor().Process(content, db).Content;

    /// <summary>
    /// Returns a copy of <paramref name="content"/> with inline secret values replaced by
    /// <c>""  # tswap: name</c>, plus the list of changed lines for dry-run display.
    /// </summary>
    public static (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content, SecretsDb db)
        => new ToCommentProcessor().Process(content, db);

    /// <summary>
    /// Replaces secret values in <paramref name="line"/> with <c>[REDACTED: name]</c>.
    /// Caller is responsible for ordering — pass values longest-first to prevent a shorter
    /// value from clobbering a longer one that shares a prefix.
    /// (Streaming subprocess redaction lives in the ConsoleIntercept library; this helper
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
        var results = new List<(int, string)>();
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
