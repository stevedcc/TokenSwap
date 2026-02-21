using System.Text;
using System.Text.RegularExpressions;

namespace TswapCore;

public enum MatchType { Plaintext, Base64, Base64Url }

public record LineDiff(int LineNumber, string Before, string After);

/// <summary>
/// Base class for commands that find known secret values in content and replace each
/// occurrence with a computed string. Both <see cref="RedactProcessor"/> and
/// <see cref="ToCommentProcessor"/> share the match-building and line-processing loop;
/// subclasses only override <see cref="GetReplacement"/> (and optionally
/// <see cref="GetSearchPattern"/>) to define what each match becomes.
/// </summary>
public abstract class SecretProcessor
{
    /// <summary>
    /// Builds the ordered list of (name, matchType, searchText) entries for all non-burned
    /// secrets, including plaintext, Base64, and Base64Url variants. Sorted longest-first so
    /// that a longer value is never clobbered by a shorter value that shares a prefix.
    /// Also includes variants with whitespace normalized to handle cases where secrets are
    /// stored with newlines/spaces but files have them formatted differently.
    /// </summary>
    protected static IReadOnlyList<(string Name, MatchType Type, string SearchText)>
        BuildMatchList(SecretsDb db)
    {
        var list = new List<(string Name, MatchType Type, string SearchText)>();

        foreach (var (name, secret) in db.Secrets)
        {
            if (secret.BurnedAt.HasValue) continue;

            var value = secret.Value;
            if (string.IsNullOrEmpty(value)) continue;

            // Add original value
            list.Add((name, MatchType.Plaintext, value));

            // Add whitespace-normalized variant (newlines/spaces removed)
            // This helps match secrets that were stored with formatting but appear
            // without formatting in files, or vice versa
            var normalized = value.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "");
            if (normalized != value && !string.IsNullOrEmpty(normalized))
                list.Add((name, MatchType.Plaintext, normalized));

            var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
            if (base64 != value)
                list.Add((name, MatchType.Base64, base64));

            var base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
            if (base64Url != base64 && base64Url != value)
                list.Add((name, MatchType.Base64Url, base64Url));
        }

        // Longest search text first to prevent shorter values partially overlapping longer ones
        list.Sort((a, b) => b.SearchText.Length.CompareTo(a.SearchText.Length));
        return list;
    }

    /// <summary>
    /// Core loop: processes content line by line, applies all replacements in order, and
    /// records a <see cref="LineDiff"/> for every line that changes. The replacement is
    /// passed as a lambda to <see cref="Regex.Replace"/> so that special characters (e.g.
    /// <c>$</c>) in the replacement string are treated as literals.
    /// For <see cref="ToCommentProcessor"/>, also removes continuation lines after a replacement
    /// to avoid leaving "trailing garbage" when YAML values span multiple lines.
    /// </summary>
    public (string Content, IReadOnlyList<LineDiff> Changes) Process(string content, SecretsDb db)
    {
        var matchList = BuildMatchList(db);
        content = content.Replace("\r\n", "\n");
        var lines = content.Split('\n');
        
        var diffs = new List<LineDiff>();
        var linesToRemove = new HashSet<int>();  // Track continuation lines to remove

        for (int i = 0; i < lines.Length; i++)
        {
            if (linesToRemove.Contains(i))
                continue;  // Skip lines marked for removal

            var original = lines[i];
            var current = original;

            foreach (var (name, type, searchText) in matchList)
            {
                var pattern = GetSearchPattern(searchText);
                var replacement = GetReplacement(name, type);
                current = Regex.Replace(current, pattern, _ => replacement);
            }

            if (current != original)
            {
                diffs.Add(new LineDiff(i + 1, original, current));
                lines[i] = current;
                
                // Check if this processor should remove continuation lines
                if (ShouldRemoveContinuationLines())
                {
                    // Detect and mark continuation lines for removal
                    // This only runs AFTER a successful match, so continuation lines
                    // are only removed when they were part of a replaced secret value
                    var baseIndent = GetLeadingWhitespaceCount(original);
                    for (int j = i + 1; j < lines.Length; j++)
                    {
                        var nextLine = lines[j];
                        
                        // Stop if we hit an empty line or a line with same/less indentation
                        if (string.IsNullOrWhiteSpace(nextLine))
                            break;
                        
                        var nextIndent = GetLeadingWhitespaceCount(nextLine);
                        if (nextIndent <= baseIndent)
                            break;  // Not a continuation line
                        
                        // Check if this looks like a base64 continuation line
                        var trimmed = nextLine.Trim();
                        if (!IsLikelyBase64(trimmed))
                            break;  // Stop if it doesn't look like base64
                        
                        // This is a continuation line - mark for removal
                        linesToRemove.Add(j);
                        diffs.Add(new LineDiff(j + 1, nextLine, ""));  // Empty = removed
                    }
                }
            }
        }

        // Filter out lines marked for removal
        var result = new List<string>();
        for (int i = 0; i < lines.Length; i++)
        {
            if (!linesToRemove.Contains(i))
                result.Add(lines[i]);
        }

        return (string.Join('\n', result), diffs);
    }

    /// <summary>
    /// Heuristic to detect if a string looks like base64 data.
    /// Uses strict standard base64 character set to minimize false positives.
    /// </summary>
    private static bool IsLikelyBase64(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length < 16)
            return false;
        
        // Standard base64 consists of: A-Z, a-z, 0-9, +, /, and = (padding)
        // Require at least 95% of characters to be valid base64
        // Length should ideally be divisible by 4, but we allow some flexibility
        int validChars = 0;
        foreach (char c in value)
        {
            if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=')
                validChars++;
        }
        
        double ratio = (double)validChars / value.Length;
        return ratio >= 0.95;
    }

    /// <summary>
    /// Returns true if this processor should remove continuation lines after a replacement.
    /// Only ToCommentProcessor needs this behavior to avoid leaving trailing garbage.
    /// </summary>
    protected virtual bool ShouldRemoveContinuationLines() => false;

    /// <summary>
    /// Counts the number of leading whitespace characters in a line.
    /// </summary>
    private static int GetLeadingWhitespaceCount(string line)
    {
        int count = 0;
        foreach (char c in line)
        {
            if (char.IsWhiteSpace(c))
                count++;
            else
                break;
        }
        return count;
    }

    /// <summary>
    /// Regex pattern used to locate a secret value in a line.
    /// Default: exact (escaped) match. <see cref="ToCommentProcessor"/> overrides this to
    /// also consume surrounding quote characters so they are replaced cleanly.
    /// </summary>
    protected virtual string GetSearchPattern(string searchText) => Regex.Escape(searchText);

    /// <summary>
    /// The string that replaces each match. Subclasses must implement this.
    /// </summary>
    protected abstract string GetReplacement(string secretName, MatchType matchType);
}

/// <summary>
/// Replaces secret values with <c>[REDACTED: name]</c> (or base64 variant labels).
/// Used by <c>tswap redact</c> to produce agent-safe file output on stdout.
/// </summary>
public sealed class RedactProcessor : SecretProcessor
{
    protected override string GetReplacement(string secretName, MatchType matchType)
        => matchType switch
        {
            MatchType.Base64    => $"[REDACTED: {secretName} (base64)]",
            MatchType.Base64Url => $"[REDACTED: {secretName} (base64url)]",
            _                   => $"[REDACTED: {secretName}]"
        };
}

/// <summary>
/// Replaces secret values (including any surrounding quotes) with <c>""  # tswap: name</c>.
/// Used by <c>tswap tocomment</c> to convert files with inline secrets to the marker format
/// that <c>tswap check</c> and <c>tswap run</c> understand.
/// </summary>
public sealed class ToCommentProcessor : SecretProcessor
{
    // Match the value either double-quoted, single-quoted, or unquoted.
    // Use negative lookahead/lookbehind to prevent matching secrets that are substrings of larger values.
    // All three patterns are symmetric: secret must not be preceded or followed by dash or word chars.
    // This prevents matching "myapp" inside "myapp-database" or 'app' inside 'app-config'.
    //
    // Known limitation: A secret appearing in prose will still match if surrounded by spaces
    // (e.g. "description: contact myapp support" would match "myapp"). This is acceptable since
    // prose is rarely found in YAML value positions, and the alternative (requiring colon-space
    // context) would fail on valid YAML like flow sequences or compact mappings.
    protected override string GetSearchPattern(string searchText)
    {
        var escaped = Regex.Escape(searchText);
        return $"(?:(?<![-\\w])\"{escaped}\"(?![-\\w])|(?<![-\\w])'{escaped}'(?![-\\w])|(?<![-\\w]){escaped}(?![-\\w]))";
    }

    protected override string GetReplacement(string secretName, MatchType matchType)
        => $"\"\"  # tswap: {secretName}";

    /// <summary>
    /// Enable removal of continuation lines to avoid leaving trailing garbage when
    /// YAML values span multiple lines (e.g., long base64 strings formatted for readability).
    /// Continuation lines are only removed AFTER a successful match on the parent line.
    /// </summary>
    protected override bool ShouldRemoveContinuationLines() => true;
}

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
    /// Base64 variants) replaced by <c>[REDACTED: name]</c> labels. Burned secrets are skipped.
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
