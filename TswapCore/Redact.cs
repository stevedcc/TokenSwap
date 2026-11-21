using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore.Fingerprints;

namespace TswapCore;

/// <summary>
/// Static facade over <see cref="SecretMatcher"/>, plus the standalone heuristic that masks
/// unrecognised secrets.
/// </summary>
public static class Redact
{
    // Matches credential-keyword = value patterns for heuristic unknown-secret detection.
    // Brief T45 (A4): the keyword and the value are named groups; what matches is unchanged.
    private static readonly Regex CredentialHeuristic = new(
        @"(?<keyword>password|passwd|token|secret|key|apikey|api_key|pass)\s*[:=]\s*[""']?(?<value>[A-Za-z0-9+/\-_]{12,}=*)[""']?",
        RegexOptions.IgnoreCase);

    /// <summary>What <see cref="MaskUnknownSecrets"/> puts in place of a suspected value.</summary>
    public const string PossibleSecretMask = "[POSSIBLE SECRET]";

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
    /// Brief T22 (#319): <see cref="ToComment(string, SecretMatcher)"/> plus the lines left unchanged
    /// because they are block-scalar content holding an encoded form of a value.
    /// </summary>
    public static (string Content, IReadOnlyList<LineDiff> Changes, IReadOnlyList<UnreplacedLine> Unreplaced) ToCommentReporting(
        string content, SecretMatcher matcher) =>
        matcher.ToCommentReporting(content);

    /// <summary>
    /// Brief T16-S2: <see cref="RedactContent(string, SecretMatcher)"/> over a loaded database, by
    /// fingerprinting its values under a random key. No command uses it (they never decrypt the
    /// values for this); it keeps the engine's tests written against plain values.
    /// </summary>
    internal static string RedactContent(string content, SecretsDb db) => WithMatcher(db, m => m.Redact(content));

    /// <summary>Brief T16-S2: <see cref="ToComment(string, SecretMatcher)"/> over a loaded database (see <see cref="RedactContent(string, SecretsDb)"/>).</summary>
    internal static (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content, SecretsDb db) =>
        WithMatcher(db, m => m.ToComment(content));

    /// <summary>Brief T22: <see cref="ToCommentReporting(string, SecretMatcher)"/> over a loaded database.</summary>
    internal static (string Content, IReadOnlyList<LineDiff> Changes, IReadOnlyList<UnreplacedLine> Unreplaced) ToCommentReporting(
        string content, SecretsDb db) =>
        WithMatcher(db, m => m.ToCommentReporting(content));

    private static T WithMatcher<T>(SecretsDb db, Func<SecretMatcher, T> use)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var keys = FingerprintKeys.Derive(key);
            List<(string, bool, FingerprintSet)> sets = [];
            foreach (var (name, secret) in db.Secrets)
            {
                sets.Add((name, false, Fingerprint(secret.Value, keys)));
                if (secret.PreviousValue is { } previous)
                    sets.Add((name, true, Fingerprint(previous, keys)));
            }
            var burned = db.Secrets.Where(kv => kv.Value.BurnedAt.HasValue).Select(kv => kv.Key).ToHashSet(StringComparer.Ordinal);
            return use(new SecretMatcher(FingerprintIndex.Build(sets, keys), burned));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static FingerprintSet Fingerprint(string value, FingerprintKeys keys)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            return Fingerprinter.Compute(bytes, keys);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
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
    /// Brief T45 (#389): <paramref name="content"/> with every value that looks like an unrecognised
    /// credential (a <see cref="CredentialHeuristic"/> match) replaced by <see cref="PossibleSecretMask"/>,
    /// and one hit per masked value: its 1-based line and the keyword as written. A hit holds no value
    /// character. The mask covers the whole run from the value's first character: up to the matching
    /// quote when a quote stands right before it, otherwise up to the next whitespace, <c>,</c>,
    /// <c>;</c>, <c>)</c>, <c>]</c> or <c>}</c>; either way at most to the end of the line. A match
    /// that starts inside a run already masked adds nothing. Line endings are kept as they are.
    /// </summary>
    public static (string Masked, IReadOnlyList<(int Line, string Keyword)> Hits) MaskUnknownSecrets(string content)
    {
        var masked = new StringBuilder(content.Length);
        List<(int, string)> hits = [];
        var lineNumber = 0;
        var lineStart = 0;
        while (lineStart <= content.Length)
        {
            lineNumber++;
            var newline = content.IndexOf('\n', lineStart);
            var next = newline < 0 ? content.Length : newline;
            // The line without its ending ('\n' or "\r\n"); the ending is copied as it is. A '\r' with no
            // '\n' after it (the end of the text) is part of the line.
            var end = newline >= 0 && next > lineStart && content[next - 1] == '\r' ? next - 1 : next;
            var line = content[lineStart..end];

            var copied = 0;
            foreach (Match match in CredentialHeuristic.Matches(line))
            {
                var value = match.Groups["value"];
                if (value.Index < copied)
                    continue; // inside the run just masked
                var runEnd = RunEnd(line, value.Index);
                masked.Append(line, copied, value.Index - copied).Append(PossibleSecretMask);
                copied = runEnd;
                hits.Add((lineNumber, match.Groups["keyword"].Value));
            }
            masked.Append(line, copied, line.Length - copied);

            if (newline < 0)
                break;
            masked.Append(content, end, newline + 1 - end);
            lineStart = newline + 1;
        }
        return (masked.ToString(), hits);
    }

    /// <summary>Where the run of a suspected value starting at <paramref name="start"/> ends (exclusive).</summary>
    private static int RunEnd(string line, int start)
    {
        if (start > 0 && line[start - 1] is '"' or '\'')
        {
            var close = line.IndexOf(line[start - 1], start);
            return close < 0 ? line.Length : close;
        }
        var end = start;
        while (end < line.Length && !char.IsWhiteSpace(line[end]) && line[end] is not (',' or ';' or ')' or ']' or '}'))
            end++;
        return end;
    }
}
