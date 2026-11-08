using System.Text;

namespace TswapCore.Fingerprints;

/// <summary>
/// Which transformation of a secret value a variant is. Stored in a fingerprint entry (one byte),
/// so the numbers are part of record format v3 and never change meaning.
/// </summary>
public enum VariantKind : byte
{
    Plain = 0,
    WhitespaceStripped = 1,
    Base64 = 2,
    Base64Url = 3,
}

/// <summary>
/// Brief T16-S1 task 1: the one list of strings a secret value is recognised by. Redaction
/// (<see cref="SecretProcessor"/>) matches these strings in plaintext and record format v3 stores
/// keyed fingerprints of them, so the two can never drift apart: a fingerprint scan finds exactly
/// what today's plaintext matcher finds.
/// </summary>
public static class SecretVariants
{
    /// <summary>
    /// The version of the variant computation below, stored with every fingerprint set. Bump it
    /// whenever <see cref="For"/> changes (a new variant, a different encoding): records
    /// fingerprinted by an older computation are then reported as "older variant set" and a
    /// <c>vault reindex</c> recomputes them, instead of silently missing the new variants.
    /// </summary>
    public const byte CurrentSetVersion = 1;

    /// <summary>
    /// The variants of <paramref name="value"/>, in this order: the value itself; the value with
    /// CR, LF, space and tab removed (when that differs and isn't empty: secrets stored with
    /// formatting often appear without it in files, or the reverse); the base64 of its UTF-8
    /// bytes (when that differs from the value); and base64url without padding (when it differs
    /// from both). An empty value has no variants (an empty string would match everywhere).
    /// </summary>
    public static IReadOnlyList<(VariantKind Kind, string Text)> For(string value)
    {
        if (string.IsNullOrEmpty(value)) return [];

        List<(VariantKind Kind, string Text)> variants = [(VariantKind.Plain, value)];

        var stripped = value.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "");
        if (stripped != value && stripped.Length > 0)
            variants.Add((VariantKind.WhitespaceStripped, stripped));

        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        if (base64 != value)
            variants.Add((VariantKind.Base64, base64));

        var base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        if (base64Url != base64 && base64Url != value)
            variants.Add((VariantKind.Base64Url, base64Url));

        return variants;
    }
}
