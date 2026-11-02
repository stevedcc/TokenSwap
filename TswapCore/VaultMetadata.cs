using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Brief T16-S1: what <see cref="RecordVaultStore.LoadMetadata"/> read from the vault's metadata
/// sections, without decrypting any value.
/// </summary>
/// <param name="Records">Every record whose metadata could be read and merged, tombstones included.</param>
/// <param name="NotFingerprinted">
/// Live records the fingerprint scan can't see: a format 2 main file or conflicted copy (never
/// decrypted on this path, ruling 12), or a retained value version without a fingerprint set.
/// Tombstones are never counted.
/// </param>
/// <param name="OlderVariantSet">
/// Records fingerprinted by an older variant computation than this build's
/// (<see cref="Fingerprints.SecretVariants.CurrentSetVersion"/>): still matched with what they have;
/// a <c>vault reindex</c> adds the newer variants.
/// </param>
/// <param name="Unreadable">Hashed file names of records that can't be read or whose copies can't be merged.</param>
public sealed record VaultMetadata(
    IReadOnlyList<RecordMetadata> Records,
    int NotFingerprinted,
    int OlderVariantSet,
    IReadOnlyList<string> Unreadable)
{
    /// <summary>
    /// The one definition of "fully fingerprinted" Stages 2 and 3 use: every live record can be found
    /// from its fingerprints, and no record is unreadable.
    /// </summary>
    public bool IsFullyFingerprinted => NotFingerprinted == 0 && Unreadable.Count == 0;
}
