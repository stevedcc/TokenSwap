namespace TswapCore;

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
