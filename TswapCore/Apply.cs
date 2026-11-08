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
    /// (discarded when null — callers that surface warnings must pass a writer). Brief T16-S2: a
    /// value is resolved through <paramref name="db"/> only for a line it fills.
    /// </summary>
    public static string ApplySecrets(string content, ISecretLookup db, TextWriter? warnings = null)
        => ApplySecretsReporting(content, db, warnings).Content;

    /// <summary>True when <paramref name="content"/> has at least one <c># tswap: &lt;name&gt;</c> marker.</summary>
    public static bool HasMarkers(string content) => MarkerRegex.IsMatch(content);

    /// <summary>
    /// <see cref="ApplySecrets"/>, also reporting what it substituted (issue #251: <c>run</c>'s
    /// <c>{{@file}}</c> token redacts every form it wrote): one row per secret used, in the order of
    /// first use, with its marker name (<c>name</c> or <c>name:previous</c>), its raw value and every
    /// distinct string written into the file for it (the value escaped for its quotes).
    /// </summary>
    public static (string Content, IReadOnlyList<(string Name, string Raw, IReadOnlyList<string> WrittenForms)> Applied)
        ApplySecretsReporting(string content, ISecretLookup db, TextWriter? warnings)
    {
        warnings ??= TextWriter.Null;
        List<(string Name, string Raw, List<string> WrittenForms)> applied = [];
        void Report(string name, string raw, string written)
        {
            var row = applied.FindIndex(r => r.Name == name);
            if (row < 0)
                applied.Add((name, raw, [written]));
            else if (!applied[row].WrittenForms.Contains(written))
                applied[row].WrittenForms.Add(written);
        }
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
            if (!db.Contains(baseName))
            {
                db.ThrowIfUnreadable(baseName);
                throw new Exception($"Secret '{baseName}' not found (line {i + 1})");
            }
            // Brief T16-S2: ':previous' without a previous value fails here, in today's order, from
            // metadata; the value itself is decrypted only for a line that is filled in (Value()).
            var where = $" (line {i + 1})";
            if (secretName.Length != baseName.Length && !db.HasPreviousValue(baseName))
                db.ResolveToken(secretName, where); // throws the "no previous value" text
            string Value() => db.ResolveToken(secretName, where);
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
                var value = Value();
                var escapedValue = EscapeForQuote(value, quote);
                if (burned)
                    warnings.WriteLine($"Warning: Secret '{secretName}' is burned (line {i + 1}) — applying anyway; rotate this secret after use");
                // Ensure at least one space before the marker so '#' is a valid YAML comment
                // (without whitespace, key: "value"# tswap: name is not a comment in YAML)
                var sep = whitespace.Length > 0 ? whitespace : " ";
                lines[i] = $"{prefix}{quote}{escapedValue}{quote}{sep}{markerPart}";
                Report(secretName, value, escapedValue);
            }
            else
            {
                // Check for unquoted empty or placeholder pattern
                var unquotedMatch = UnquotedRegex.Match(beforeMarker);

                if (unquotedMatch.Success)
                {
                    var prefix = unquotedMatch.Groups[1].Value;
                    // Default to double quotes for safety
                    var value = Value();
                    var escapedValue = EscapeForQuote(value, "\"");
                    if (burned)
                        warnings.WriteLine($"Warning: Secret '{secretName}' is burned (line {i + 1}) — applying anyway; rotate this secret after use");
                    lines[i] = $"{prefix}\"{escapedValue}\"  {markerPart}";
                    Report(secretName, value, escapedValue);
                }
                else
                {
                    // Value already populated - warn user
                    warnings.WriteLine($"Warning: Line {i + 1} has marker '# tswap: {secretName}' but value appears already populated. Skipping substitution.");
                }
            }
        }

        return (string.Join('\n', lines),
            applied.Select(r => (r.Name, r.Raw, (IReadOnlyList<string>)r.WrittenForms)).ToList());
    }

    private static string EscapeForQuote(string value, string quoteChar) => quoteChar switch
    {
        // Escape backslashes first, then double quotes
        // This prevents double-escaping: \ -> \\ and " -> \"
        "\"" => value.Replace("\\", "\\\\").Replace("\"", "\\\""),
        // Escape single quotes for YAML: ' becomes ''
        // Backslashes don't need escaping in YAML single quotes
        "'" => value.Replace("'", "''"),
        _ => value,
    };
}
