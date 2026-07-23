using System.Text.RegularExpressions;

namespace TswapCore;

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
        // Optionally consume an existing tswap marker immediately following the value.
        // This prevents duplication when processing `tswap apply` output, which emits lines
        // like: key: "actual-secret"  # tswap: secret-name
        // Without this, the marker would survive as a YAML comment and tocomment would
        // append a second one, producing: key: ""  # tswap: secret-name  # tswap: secret-name
        var existingMarker = @"(?:\s*#\s*tswap\s*:\s*[a-zA-Z0-9_-]+)?";
        return $"(?:(?<![-\\w])\"{escaped}\"{existingMarker}(?![-\\w])|(?<![-\\w])'{escaped}'{existingMarker}(?![-\\w])|(?<![-\\w]){escaped}{existingMarker}(?![-\\w]))";
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
