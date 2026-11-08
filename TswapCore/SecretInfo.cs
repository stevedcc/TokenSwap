using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Brief T16-S2: what the reading commands (<c>names</c>, <c>list</c>, <c>burned</c>, <c>check</c>)
/// show about a secret, taken from its record's metadata alone, so no value is decrypted for it.
/// <see cref="RecordVaultStore.ToSecret"/> is built on <see cref="From"/>, so the two can't disagree.
/// </summary>
/// <param name="History">Past burns (of value versions a newer value superseded), oldest first; empty when none.</param>
/// <param name="HasPrevious">True when the record keeps the value a rotation replaced.</param>
/// <param name="PreviousBurned">True when that previous value's version was burned.</param>
public sealed record SecretInfo(string Name, DateTime Created, DateTime Modified, DateTime? BurnedAt,
    string? BurnReason, IReadOnlyList<PastBurn> History, bool HasPrevious, bool PreviousBurned)
{
    /// <summary>The secret <paramref name="metadata"/> describes, or null for a tombstone (no secret).</summary>
    public static SecretInfo? From(RecordMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (metadata.Type == RecordType.Tombstone)
            return null;
        var outstanding = metadata.Burns.FirstOrDefault(b => b.Version.Equals(metadata.Version));
        List<PastBurn> history = [.. metadata.Burns
            .Where(b => !ReferenceEquals(b, outstanding))
            .OrderBy(b => b.Burn)
            .Select(b => new PastBurn(Hlc.ToDisplayDate(b.Burn.Hlc.PhysicalMs), b.Reason))];
        return new SecretInfo(
            metadata.Name,
            Hlc.ToDisplayDate(metadata.CreatedMs),
            Hlc.ToDisplayDate(metadata.Version.Hlc.PhysicalMs),
            outstanding is null ? null : Hlc.ToDisplayDate(outstanding.Burn.Hlc.PhysicalMs),
            outstanding?.Reason,
            history,
            metadata.PreviousVersion is not null,
            metadata.PreviousVersion is { } previous && metadata.Burns.Any(b => b.Version.Equals(previous)));
    }
}
