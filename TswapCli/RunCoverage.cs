using TswapCore;

namespace TswapCli;

/// <summary>
/// Brief T16-S3: what <c>run</c> says when its output masking can't cover the whole vault (owner
/// decision D1: it keeps working). Printed once before the child starts and again after it exits, the
/// same text both times, so it is one line to look for. It carries counts and the fix only.
/// </summary>
internal static class RunCoverage
{
    /// <summary>
    /// Writes the coverage warning when some records are not fully fingerprinted or can't be read, and
    /// the older-variant note when some were fingerprinted by an older tswap. Both are part of the one
    /// text printed before and after the child, so the note, when there is one, comes twice too.
    /// </summary>
    public static void Warn(TextWriter error, string prefix, VaultMetadata metadata)
    {
        if (!metadata.IsFullyFingerprinted)
        {
            var unreadable = metadata.Unreadable.Count > 0 ? $", {metadata.Unreadable.Count} can't be read" : "";
            error.WriteLine(
                $"Warning: {metadata.NotFingerprinted} record(s) are not fully fingerprinted{unreadable}: 'run' masks the " +
                $"secrets it substitutes and the fingerprinted values, not these. Ask the user to run " +
                $"{ElevatedCommand.For(prefix, "vault reindex")}.");
        }
        FingerprintTexts.NoteOlderVariants(error, prefix, metadata.OlderVariantSet);
    }
}
