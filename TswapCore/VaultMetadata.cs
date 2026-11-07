using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Brief T16-S1: what <see cref="RecordVaultStore.LoadMetadata"/> read from the vault's metadata
/// sections, without decrypting any value.
/// </summary>
/// <param name="Records">Every record whose metadata could be read and merged, tombstones included.</param>
/// <param name="NotFingerprinted">
/// Records the fingerprint scan may not see: any record with a format 2 main file or conflicted
/// copy (never decrypted on this path, ruling 12, so a format 2 tombstone is counted too: its type
/// is unknown without decrypting it), or a live record with a retained value version without a
/// fingerprint set. A format 3 tombstone is never counted.
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

    /// <summary>
    /// Brief T16-S2: the secrets of <see cref="Records"/> (every non-tombstone record, burned
    /// included), by name (ordinal).
    /// </summary>
    public IReadOnlyList<SecretInfo> Secrets =>
        field ??= [.. Records.Select(SecretInfo.From).OfType<SecretInfo>().OrderBy(s => s.Name, StringComparer.Ordinal)];

    /// <summary>
    /// Brief T16-S2: records with a format 2 main file or conflicted copy that
    /// <see cref="RecordVaultStore.LoadMetadata"/> decoded whole (<see cref="FormatTwoRecords.Decode"/>),
    /// tombstones included, one that failed to decrypt not; 0 with <see cref="FormatTwoRecords.Skip"/>.
    /// </summary>
    public int FormatTwoDecoded { get; init; }
}

/// <summary>
/// Brief T16-S2: what <see cref="RecordVaultStore.LoadMetadata"/> does with a record that has a format 2
/// file, which keeps name and value in one encrypted block.
/// </summary>
public enum FormatTwoRecords
{
    /// <summary>Not decrypted and not listed; only counted in <see cref="VaultMetadata.NotFingerprinted"/>.</summary>
    Skip,

    /// <summary>Decoded whole, listed without fingerprints, its values zeroed at once (owner decision 1).</summary>
    Decode,
}
