using System.Text.RegularExpressions;

namespace TswapCore;

public static class Apply
{
    private static readonly Regex MarkerRegex = new(@"#\s*tswap\s*:\s*([a-zA-Z0-9_-]+)");
    
    // Match empty string patterns with quotes: key: "" or key: ''
    private static readonly Regex EmptyValueRegex = new(@"^(.*[:=]\s*)([""'])\2(\s*)$");
    
    // Match unquoted pattern: key: (followed by marker)
    private static readonly Regex UnquotedRegex = new(@"^(.*[:=]\s*)$");

    /// <summary>
    /// Apply secret values to a file containing <c># tswap: &lt;name&gt;</c> markers.
    /// Finds lines with empty values (e.g., <c>password: ""  # tswap: db-password</c>)
    /// and replaces the empty value with the actual secret value.
    /// Returns the modified content.
    /// </summary>
    public static string ApplySecrets(string content, SecretsDb db)
    {
        content = content.Replace("\r\n", "\n");
        var lines = content.Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var markerMatch = MarkerRegex.Match(line);
            
            if (!markerMatch.Success)
                continue;

            var secretName = markerMatch.Groups[1].Value;

            // Check if secret exists
            if (!db.Secrets.TryGetValue(secretName, out var secret))
                throw new Exception($"Secret '{secretName}' not found (line {i + 1})");

            // Check if secret is burned
            if (secret.BurnedAt.HasValue)
                throw new Exception($"Secret '{secretName}' is burned and cannot be applied (line {i + 1})");

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
                var escapedValue = EscapeForQuote(secret.Value, quote);
                
                lines[i] = $"{prefix}{quote}{escapedValue}{quote}{whitespace}{markerPart}";
            }
            else
            {
                // Check for unquoted empty or placeholder pattern
                var unquotedMatch = UnquotedRegex.Match(beforeMarker);
                
                if (unquotedMatch.Success)
                {
                    var prefix = unquotedMatch.Groups[1].Value;
                    // Default to double quotes for safety
                    var escapedValue = EscapeForQuote(secret.Value, "\"");
                    lines[i] = $"{prefix}\"{escapedValue}\"  {markerPart}";
                }
                else
                {
                    // Value already populated - warn user
                    Console.Error.WriteLine($"Warning: Line {i + 1} has marker '# tswap: {secretName}' but value appears already populated. Skipping substitution.");
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
