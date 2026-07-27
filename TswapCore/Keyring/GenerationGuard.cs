namespace TswapCore.Keyring;

/// <summary>
/// Stale-save detection for the Phase 6 vault generation counter (issue #118). Standalone
/// infrastructure, like #137's <see cref="DurableFileWriter"/>: this type has no dependency on
/// any <see cref="IVaultStore"/> or real multi-machine store (that's #119/#124, not landed yet)
/// — it just compares the generation a caller loaded a vault at against the generation currently
/// on disk, and refuses to let a stale write clobber a newer one.
///
/// <para>Uses <see cref="SecretRecord.OriginId"/> as the "last-writer id" rather than inventing a
/// second identifier — see that field's doc comment, which already reserves it for this exact
/// purpose.</para>
/// </summary>
public static class GenerationGuard
{
    /// <summary>
    /// True when <paramref name="onDiskGeneration"/> is strictly ahead of
    /// <paramref name="loadedGeneration"/> — i.e. some other writer has saved since this caller
    /// last loaded. Equal generations (the ordinary save-after-load case) are not stale, and
    /// neither is a loaded generation ahead of disk (disk simply hasn't caught up yet, e.g.
    /// immediately after a fresh load with nothing else having written since).
    /// </summary>
    public static bool IsStale(uint loadedGeneration, uint onDiskGeneration)
        => onDiskGeneration > loadedGeneration;

    /// <summary>
    /// Throws a <see cref="TswapException"/> naming both generations and both origin ids when
    /// <paramref name="onDiskGeneration"/> is ahead of <paramref name="loadedGeneration"/>
    /// (see <see cref="IsStale"/>); otherwise does nothing. Origin ids are rendered as hex since
    /// this layer has no human-readable machine-label mapping (e.g. "LAPTOP"/"DESKTOP", the
    /// issue's own example) — a future layer that maintains such a mapping could produce a
    /// friendlier message from the same ids.
    /// </summary>
    public static void CheckNotStale(uint loadedGeneration, byte[] loadedOriginId, uint onDiskGeneration, byte[] onDiskOriginId)
    {
        if (!IsStale(loadedGeneration, onDiskGeneration))
            return;

        throw new TswapException(
            $"Refusing stale save: on-disk generation {onDiskGeneration} from origin {Convert.ToHexString(onDiskOriginId)} " +
            $"is ahead of the loaded generation {loadedGeneration} from origin {Convert.ToHexString(loadedOriginId)} " +
            "-- reload before saving.");
    }
}
