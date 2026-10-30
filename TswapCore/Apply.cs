using System.Text.RegularExpressions;

namespace TswapCore;

public static class Apply
{
    // Fix round 1, B: '# tswap: name:previous' names the value the last rotation replaced.
    private static readonly Regex MarkerRegex = new(@"#\s*tswap\s*:\s*([a-zA-Z0-9_-]+(?::previous)?)");

    // Fix round 3/4: every marker on a line must be 'name' or 'name:previous'; any other
    // ':suffix' is a typo, refused (naming it) instead of applying 'name'.
    private static readonly Regex AnyMarkerRegex = new(@"#\s*tswap\s*:\s*([a-zA-Z0-9_-]+(?::[^\s#]*)*)");
    private static readonly Regex ValidMarkerTail = new(@"^[a-zA-Z0-9_-]+(?::previous)?$");
    
    // Match empty string patterns with quotes: key: "" or key: ''
    private static readonly Regex EmptyValueRegex = new(@"^(.*[:=]\s*)([""'])\2(\s*)$");
    
    // Match unquoted pattern: key: (followed by marker)
    private static readonly Regex UnquotedRegex = new(@"^(.*[:=]\s*)$");

    /// <summary>
    /// Apply secret values to a file containing <c># tswap: &lt;name&gt;</c> markers.
    /// Finds lines with empty values (e.g., <c>password: ""  # tswap: db-password</c>)
    /// and replaces the empty value with the actual secret value.
    /// Returns the modified content. Warnings are written to <paramref name="warnings"/>
    /// (discarded when null — callers that surface warnings must pass a writer).
    /// </summary>
    public static string ApplySecrets(string content, SecretsDb db, TextWriter? warnings = null)
    {
        warnings ??= TextWriter.Null;
        content = content.Replace("\r\n", "\n");
        var lines = content.Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var markerMatch = MarkerRegex.Match(line);

            if (!markerMatch.Success)
                continue;

            foreach (Match marker in AnyMarkerRegex.Matches(line))
                if (!ValidMarkerTail.IsMatch(marker.Groups[1].Value))
                    throw new TswapException(
                        $"Unknown marker '# tswap: {marker.Groups[1].Value}' (line {i + 1}): the only suffix is ':previous'.");

            var secretName = markerMatch.Groups[1].Value;

            // Check the secret exists (and, for name:previous, that it has a previous value).
            var baseName = secretName.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal)
                ? secretName[..^SecretsDb.PreviousSuffix.Length]
                : secretName;
            if (!db.Secrets.ContainsKey(baseName))
            {
                db.ThrowIfUnreadable(baseName);
                throw new Exception($"Secret '{baseName}' not found (line {i + 1})");
            }
            var value = db.ResolveToken(secretName, $" (line {i + 1})");
            var burned = db.IsBurnedToken(secretName);

            // Find and replace empty value patterns before the marker
            // Patterns to match:
            // - key: ""  # tswap: name
            // - key: ''  # tswap: name
            // - key: ""# tswap: name
            // - key: ''# tswap: name
            // Also handle YAML/JSON formats with or without quotes

            var beforeMarker = line.Substring(0, markerMatch.Index);
            var markerPart = line.Substring(markerMatch.Index);

            // Try to match empty string patterns (with quotes)
            var match = EmptyValueRegex.Match(beforeMarker);

            if (match.Success)
            {
                var prefix = match.Groups[1].Value;  // "key: "
                var quote = match.Groups[2].Value;   // " or '
                var whitespace = match.Groups[3].Value;  // optional whitespace

                // Escape the secret value for the appropriate quote style
                var escapedValue = EscapeForQuote(value, quote);
                if (burned)
                    warnings.WriteLine($"Warning: Secret '{secretName}' is burned (line {i + 1}) — applying anyway; rotate this secret after use");
                // Ensure at least one space before the marker so '#' is a valid YAML comment
                // (without whitespace, key: "value"# tswap: name is not a comment in YAML)
                var sep = whitespace.Length > 0 ? whitespace : " ";
                lines[i] = $"{prefix}{quote}{escapedValue}{quote}{sep}{markerPart}";
            }
            else
            {
                // Check for unquoted empty or placeholder pattern
                var unquotedMatch = UnquotedRegex.Match(beforeMarker);

                if (unquotedMatch.Success)
                {
                    var prefix = unquotedMatch.Groups[1].Value;
                    // Default to double quotes for safety
                    var escapedValue = EscapeForQuote(value, "\"");
                    if (burned)
                        warnings.WriteLine($"Warning: Secret '{secretName}' is burned (line {i + 1}) — applying anyway; rotate this secret after use");
                    lines[i] = $"{prefix}\"{escapedValue}\"  {markerPart}";
                }
                else
                {
                    // Value already populated - warn user
                    warnings.WriteLine($"Warning: Line {i + 1} has marker '# tswap: {secretName}' but value appears already populated. Skipping substitution.");
                }
            }
        }

        return string.Join('\n', lines);
    }

    private static string EscapeForQuote(string value, string quoteChar)
    {
        if (quoteChar == "\"")
        {
            // Escape backslashes first, then double quotes
            // This prevents double-escaping: \ -> \\ and " -> \"
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
        else if (quoteChar == "'")
        {
            // Escape single quotes for YAML: ' becomes ''
            // Backslashes don't need escaping in YAML single quotes
            return value.Replace("'", "''");
        }
        return value;
    }
}
