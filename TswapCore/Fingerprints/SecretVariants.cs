using System.Text;

namespace TswapCore.Fingerprints;

/// <summary>
/// Which transformation of a secret value a variant is. Stored in a fingerprint entry (one byte),
/// so the numbers are part of record format v3 and never change meaning. Values 4 to 11 (brief T54,
/// variant set version 2) are the base kinds of the value's NFC form (<c>Nfc*</c>) and its NFD form
/// (<c>Nfd*</c>); <see cref="VariantKinds.BaseKind"/> maps them back.
/// </summary>
public enum VariantKind : byte
{
    Plain = 0,
    WhitespaceStripped = 1,
    Base64 = 2,
    Base64Url = 3,
    NfcPlain = 4,
    NfcWhitespaceStripped = 5,
    NfcBase64 = 6,
    NfcBase64Url = 7,
    NfdPlain = 8,
    NfdWhitespaceStripped = 9,
    NfdBase64 = 10,
    NfdBase64Url = 11,
}

/// <summary>Brief T54: what a <see cref="VariantKind"/> is, whichever Unicode spelling of the value it is of.</summary>
public static class VariantKinds
{
    private const int FormKindCount = 4;
    private const VariantKind FirstFormKind = VariantKind.NfcPlain;
    private const VariantKind LastFormKind = VariantKind.NfdBase64Url;

    /// <summary>
    /// The base kind (<see cref="VariantKind.Plain"/> to <see cref="VariantKind.Base64Url"/>) of a form kind: 4 to 7
    /// and 8 to 11 map to 0 to 3. Every other value, a base kind or a kind this build doesn't define, comes back
    /// unchanged.
    /// </summary>
    public static VariantKind BaseKind(this VariantKind kind) =>
        kind is >= FirstFormKind and <= LastFormKind ? (VariantKind)(((int)kind - (int)FirstFormKind) % FormKindCount) : kind;
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
    /// Version 2 (brief T54) added the NFC and NFD spellings of the value and their encodings
    /// (<see cref="VariantKind.NfcPlain"/> to <see cref="VariantKind.NfdBase64Url"/>); a version 1
    /// set that proves its value ASCII counts as current all the same (<see cref="IsCurrent"/>).
    /// </summary>
    public const byte CurrentSetVersion = 2;

    /// <summary>
    /// The variants of <paramref name="value"/>, in this order. First the base kinds of the value
    /// itself: the value; the value with CR, LF, space and tab removed (when that differs and isn't
    /// empty: secrets stored with formatting often appear without it in files, or the reverse); the
    /// base64 of its UTF-8 bytes (when that differs from the value); and base64url without padding
    /// (when it differs from both). Then (brief T54), unless the value holds a lone surrogate (which
    /// can't be normalised), the same list for the value's NFC form under the <c>Nfc</c> kinds, and
    /// for its NFD form under the <c>Nfd</c> kinds, each form only when it differs from the value,
    /// and each text only when no earlier variant has it (the first kind keeps it). An empty value
    /// has no variants (an empty string would match everywhere).
    /// </summary>
    public static IReadOnlyList<(VariantKind Kind, string Text)> For(string value)
    {
        if (string.IsNullOrEmpty(value)) return [];

        var variants = BaseVariants(value);
        if (UnicodeText.FindLoneSurrogate(value) is not null)
            return variants;

        AddForm(variants, value, value.Normalize(NormalizationForm.FormC), VariantKind.NfcPlain);
        AddForm(variants, value, value.Normalize(NormalizationForm.FormD), VariantKind.NfdPlain);
        return variants;
    }

    private static void AddForm(List<(VariantKind Kind, string Text)> variants, string value, string form, VariantKind firstKind)
    {
        if (form == value) return;
        foreach (var (kind, text) in BaseVariants(form))
        {
            if (variants.Exists(v => v.Text == text)) continue;
            variants.Add(((VariantKind)((int)firstKind + (int)kind), text));
        }
    }

    /// <summary>The base kinds of one spelling of a value (the list <see cref="For"/> starts with).</summary>
    private static List<(VariantKind Kind, string Text)> BaseVariants(string value)
    {
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

    /// <summary>
    /// Brief T54: whether <paramref name="set"/> holds every variant this build would compute: it is of
    /// <see cref="CurrentSetVersion"/>, or it is of version 1 and proves its value ASCII (an ASCII value has no
    /// other Unicode spelling, so version 2 adds nothing to it). A version 1 set proves it when it has no entries
    /// (an empty value), or when it has a <see cref="VariantKind.Plain"/> entry of length <c>P</c> and either a
    /// <see cref="VariantKind.Base64Url"/> entry of length <c>U</c> with <c>floor(3U/4) == P</c>, or no base64url
    /// entry and a <see cref="VariantKind.Base64"/> entry of length <c>B</c> with <c>B % 4 == 0</c> and
    /// <c>3B/4 == P</c>. The reason: unpadded base64url gives the value's exact UTF-8 byte count; without a
    /// base64url entry (it was equal to the base64) the base64 has no padding; and the UTF-8 byte count equals the
    /// UTF-16 length exactly when every character is ASCII (any other character takes more UTF-8 bytes than UTF-16
    /// units).
    /// </summary>
    /// <summary>
    /// T54 fix round 1 (GLM Minor 1, controller ruling): whether <paramref name="stored"/>, a set of
    /// <see cref="CurrentSetVersion"/> for <paramref name="valueBytes"/>, lacks a form kind (NFC or NFD) that this
    /// machine's recomputation has. A machine without a Unicode library (.NET's invariant mode, no ICU) computes no form
    /// entries; with the value known, such a set is treated as out of date and recomputed. Only the kinds are
    /// compared: a form entry another library computed differently (same kind, another HMAC) is kept as written.
    /// ASCII values have no forms, so they are never recomputed for this.
    /// </summary>
    public static bool LacksFormsOf(FingerprintSet stored, byte[] valueBytes, FingerprintKeys keys)
    {
        ArgumentNullException.ThrowIfNull(stored);
        ArgumentNullException.ThrowIfNull(valueBytes);
        if (stored.VariantSetVersion != CurrentSetVersion || System.Text.Ascii.IsValid(valueBytes))
            return false;
        var have = stored.Entries.Select(static e => e.Kind).ToHashSet();
        return Fingerprinter.Compute(valueBytes, keys).Entries.Any(e => e.Kind.BaseKind() != e.Kind && !have.Contains(e.Kind));
    }

    public static bool IsCurrent(FingerprintSet set)
    {
        ArgumentNullException.ThrowIfNull(set);
        if (set.VariantSetVersion == CurrentSetVersion) return true;
        if (set.VariantSetVersion != 1) return false;
        if (set.Entries.Count == 0) return true;

        var plain = set.Entries.FirstOrDefault(e => e.Kind == VariantKind.Plain);
        if (plain is null) return false;
        if (set.Entries.FirstOrDefault(e => e.Kind == VariantKind.Base64Url) is { } url)
            return 3L * url.Length / 4 == plain.Length;
        return set.Entries.FirstOrDefault(e => e.Kind == VariantKind.Base64) is { } base64
            && base64.Length % 4 == 0 && 3L * base64.Length / 4 == plain.Length;
    }
}
