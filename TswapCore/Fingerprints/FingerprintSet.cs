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

    /// <summary>
    /// Brief T54: whether the base entries (kinds <see cref="VariantKind.Plain"/> to <see cref="VariantKind.Base64Url"/>:
    /// the value's own spelling) of both sets are equal, in order (<see cref="FingerprintEntry.Equals(FingerprintEntry?)"/>,
    /// a fixed-time HMAC comparison). Every other entry (the NFC and NFD forms, and any kind this build doesn't define)
    /// is a form entry, which another machine's Unicode library may compute differently, so it is left out; base
    /// entries don't depend on the library or on the variant-set version.
    /// </summary>
    public bool SameBaseEntries(FingerprintSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return Entries.Where(static e => IsBase(e.Kind)).SequenceEqual(other.Entries.Where(static e => IsBase(e.Kind)));
    }

    /// <summary>
    /// Brief T54: one set holding every entry of <paramref name="a"/> and <paramref name="b"/>: the base entries, then
    /// the distinct form entries of both, sorted by kind, then length, then HMAC bytes ordinally (then rolling hash, so
    /// even a tampered pair sorts alike everywhere). <see cref="Fingerprinter.Compute"/> writes its form entries in that
    /// order already, so <c>Union(x, x)</c> equals <c>x</c>, and the result doesn't depend on the order of the inputs.
    /// More form entries can only add masking: the base entries still decide the value.
    /// </summary>
    /// <exception cref="ArgumentException">The sets are of different variant-set versions or their base entries differ.</exception>
    public static FingerprintSet Union(FingerprintSet a, FingerprintSet b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        if (a.VariantSetVersion != b.VariantSetVersion)
            throw new ArgumentException("Only fingerprint sets of one variant-set version can be joined");
        if (!a.SameBaseEntries(b))
            throw new ArgumentException("Only fingerprint sets with the same base entries can be joined");

        List<FingerprintEntry> forms = [];
        foreach (var entry in a.Entries.Concat(b.Entries))
        {
            if (!IsBase(entry.Kind) && !forms.Contains(entry))
                forms.Add(entry);
        }
        forms.Sort(static (x, y) =>
        {
            var cmp = x.Kind.CompareTo(y.Kind);
            if (cmp == 0) cmp = x.Length.CompareTo(y.Length);
            if (cmp == 0) cmp = x.Hmac.AsSpan().SequenceCompareTo(y.Hmac);
            if (cmp == 0) cmp = x.RollingHash.CompareTo(y.RollingHash);
            return cmp;
        });
        return new FingerprintSet(a.VariantSetVersion, [.. a.Entries.Where(static e => IsBase(e.Kind)), .. forms]);
    }

    private static bool IsBase(VariantKind kind) => kind <= VariantKind.Base64Url;

    /// <summary>Counts only (see <see cref="FingerprintEntry"/>).</summary>
    public override string ToString() => $"FingerprintSet(v{VariantSetVersion}, {Entries.Count} entries)";
}
