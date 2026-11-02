using System.Security.Cryptography;

namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T16-S1: the fingerprint of one variant of one value version: its length in UTF-16 code
/// units, its keyed rolling hash (the scan prefilter) and the first 16 bytes of
/// <c>HMAC-SHA256(K_fp, UTF-8(variant))</c> (the confirmation).
/// <para>
/// Fingerprints only ever live inside an encrypted metadata section or in process memory, so
/// <see cref="ToString"/> prints the kind only: a log line or an exception message can't leak the
/// rolling hash, whose small domain would make a short secret guessable offline.
/// </para>
/// </summary>
public sealed record FingerprintEntry(VariantKind Kind, int Length, ulong RollingHash, byte[] Hmac)
{
    /// <summary>Bytes of the truncated HMAC.</summary>
    public const int HmacLength = 16;

    public bool Equals(FingerprintEntry? other) =>
        other is not null && Kind == other.Kind && Length == other.Length && RollingHash == other.RollingHash
        && CryptographicOperations.FixedTimeEquals(Hmac, other.Hmac);

    public override int GetHashCode() => HashCode.Combine(Kind, Length, RollingHash);

    public override string ToString() => Kind.ToString();
}

/// <summary>
/// Brief T16-S1: the fingerprints of one value version, one entry per
/// <see cref="SecretVariants.For"/> variant in that order, tagged with the variant-set version they
/// were computed by (<see cref="SecretVariants.CurrentSetVersion"/> for this build). An empty value
/// has a set with no entries: it is fingerprinted, there is just nothing to match.
/// </summary>
public sealed record FingerprintSet(byte VariantSetVersion, IReadOnlyList<FingerprintEntry> Entries)
{
    public bool Equals(FingerprintSet? other) =>
        other is not null && VariantSetVersion == other.VariantSetVersion && Entries.SequenceEqual(other.Entries);

    public override int GetHashCode() => HashCode.Combine(VariantSetVersion, Entries.Count);

    /// <summary>Counts only (see <see cref="FingerprintEntry"/>).</summary>
    public override string ToString() => $"FingerprintSet(v{VariantSetVersion}, {Entries.Count} entries)";
}
