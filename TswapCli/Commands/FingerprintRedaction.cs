using TswapCore;
using TswapCore.Fingerprints;

namespace TswapCli.Commands;

/// <summary>
/// Brief T16-S2: what <c>redact</c> and <c>tocomment</c> share. They recognise secrets by their
/// fingerprints, from the records' metadata sections, and decrypt no value.
/// </summary>
internal static class FingerprintRedaction
{
    /// <summary>
    /// The matcher over the vault's fingerprints. Fails closed, before the caller opens its input:
    /// on an unreadable record (as before), and on records without fingerprints (the refusal; no
    /// fallback to plaintext matching). Records fingerprinted by an older variant set get a note and
    /// are matched with what they have. <paramref name="keys"/> must stay undisposed while the
    /// matcher is used.
    /// </summary>
    public static SecretMatcher Matcher(CommandContext ctx, VaultView view, FingerprintKeys keys, string command, bool changesFile)
    {
        var metadata = view.LoadAll(FormatTwoRecords.Skip);
        view.ThrowIfAnyUnreadable(command);
        if (metadata.NotFingerprinted > 0)
            throw new TswapException(FingerprintTexts.Refusal(ctx.Prefix, command, metadata.NotFingerprinted, changesFile));
        FingerprintTexts.NoteOlderVariants(ctx.Console.Error, ctx.Prefix, metadata.OlderVariantSet);
        var burned = metadata.Secrets.Where(s => s.BurnedAt is not null).Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        return new SecretMatcher(view.BuildIndex(keys), burned);
    }
}
