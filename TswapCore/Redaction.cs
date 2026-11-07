using TswapCore.Fingerprints;

namespace TswapCore;

/// <summary>
/// Issue #251: the strings <c>run</c> redacts from a child's output for one form of a secret (the raw
/// value, or a form <see cref="Apply"/> wrote into a filled file), for both token kinds.
/// </summary>
public static class Redaction
{
    /// <summary>
    /// <paramref name="writtenForm"/> itself and its base64 and base64url encodings, padded and
    /// unpadded; for a multi-line form also its <c>\r\n</c> form (a PTY turns <c>\n</c> into
    /// <c>\r\n</c> on output) and that form's base64 and base64url, padded and unpadded. Distinct, in
    /// that order; an empty form has none (it would match everywhere).
    /// </summary>
    public static IReadOnlyList<string> Variants(string writtenForm)
    {
        if (string.IsNullOrEmpty(writtenForm))
            return [];
        List<string> forms = [writtenForm];
        if (writtenForm.Contains('\n'))
            forms.Add(writtenForm.Replace("\r\n", "\n").Replace("\n", "\r\n"));

        List<string> variants = [];
        foreach (var form in forms)
        {
            // The base64 computation is SecretVariants' (what `tswap redact` and the fingerprints
            // match); it leaves the encoding out only when it equals the form itself.
            var base64 = SecretVariants.For(form).FirstOrDefault(v => v.Kind == VariantKind.Base64).Text ?? form;
            var base64Url = base64.Replace('+', '-').Replace('/', '_');
            variants.AddRange([form, base64, base64.TrimEnd('='), base64Url, base64Url.TrimEnd('=')]);
        }
        return variants.Where(v => v.Length > 0).Distinct(StringComparer.Ordinal).ToList();
    }
}
