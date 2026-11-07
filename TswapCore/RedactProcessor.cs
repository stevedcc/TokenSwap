using TswapCore.Fingerprints;

namespace TswapCore;

/// <summary>
/// Replaces secret values with <c>[REDACTED: name]</c> (or base64 variant labels).
/// Used by <c>tswap redact</c> to produce agent-safe file output on stdout; the matching is
/// <see cref="SecretMatcher.Redact"/>'s.
/// </summary>
public static class RedactProcessor
{
    /// <summary>
    /// The label of a match of <paramref name="token"/> (<c>name</c> or <c>name:previous</c>) in the
    /// variant <paramref name="kind"/>: the one definition of <c>redact</c>'s labels.
    /// </summary>
    internal static string Label(string token, VariantKind kind) => kind switch
    {
        VariantKind.Base64 => $"[REDACTED: {token} (base64)]",
        VariantKind.Base64Url => $"[REDACTED: {token} (base64url)]",
        _ => $"[REDACTED: {token}]",
    };
}
