using System.Security.Cryptography;

namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T16-S1 (ruling 7): one confirmed occurrence of a variant of an indexed value in a text.
/// <paramref name="IsPrevious"/> is true for the value a rotation replaced (<c>name:previous</c>).
/// </summary>
public sealed record FingerprintHit(string Name, bool IsPrevious, VariantKind Kind, int Start, int Length);

/// <summary>
/// Brief T16-S1 (ruling 7): finds indexed values in a text from their fingerprints alone, without
/// any plaintext. For each distinct stored length it slides a window over the text, keeps the
/// window's rolling hash in O(1) per character, and looks up (length, hash); a candidate becomes a
/// hit only when the window's HMAC equals a stored HMAC (fixed-time). A rolling-hash match alone is
/// never a hit, so the 64-bit prefilter can collide without ever producing a false match.
/// <para>
/// The index holds a reference to the <see cref="FingerprintKeys"/> it was built with (no copy of
/// the key): it works only while the caller keeps them undisposed.
/// </para>
/// </summary>
public sealed class FingerprintIndex
{
    private readonly FingerprintKeys _keys;
    private readonly Dictionary<(int Length, ulong Hash), List<(string Name, bool IsPrevious, VariantKind Kind, byte[] Hmac)>> _entries;
    private readonly int[] _lengths;

    private FingerprintIndex(
        FingerprintKeys keys,
        Dictionary<(int Length, ulong Hash), List<(string Name, bool IsPrevious, VariantKind Kind, byte[] Hmac)>> entries)
    {
        _keys = keys;
        _entries = entries;
        _lengths = [.. entries.Keys.Select(k => k.Length).Distinct().Order()];
        MaxLength = _lengths.Length == 0 ? 0 : _lengths[^1];
    }

    /// <summary>The longest stored variant, in UTF-16 code units (0 for an empty index).</summary>
    public int MaxLength { get; }

    /// <summary>Indexes every entry of every set; sets computed under other keys simply never match.</summary>
    public static FingerprintIndex Build(IEnumerable<(string Name, bool IsPrevious, FingerprintSet Set)> sets, FingerprintKeys keys)
    {
        Dictionary<(int, ulong), List<(string, bool, VariantKind, byte[])>> entries = [];
        foreach (var (name, isPrevious, set) in sets)
        {
            foreach (var entry in set.Entries)
            {
                if (entry.Length <= 0) continue;
                var key = (entry.Length, entry.RollingHash);
                if (!entries.TryGetValue(key, out var list))
                    entries[key] = list = [];
                list.Add((name, isPrevious, entry.Kind, entry.Hmac));
            }
        }
        return new FingerprintIndex(keys, entries);
    }

    /// <summary>
    /// Every confirmed hit in <paramref name="text"/>, ordered by start, then length descending,
    /// then name (ordinal): the brief's pinned reporting order. Current before previous, then
    /// variant kind, only complete it into a total order (so equal keys can't come out in either
    /// order); they are not part of the pinned order and nothing should rely on them. This is a
    /// reporting order only; resolving overlaps (today's longest-first replacement) is the caller's
    /// job (Stage 2).
    /// </summary>
    public IReadOnlyList<FingerprintHit> Scan(ReadOnlySpan<char> text)
    {
        List<FingerprintHit> hits = [];
        var b = _keys.RollingBase;
        foreach (var length in _lengths)
        {
            if (length > text.Length) break;
            var top = RollingHash.Power(b, length - 1);
            var hash = RollingHash.Of(text[..length], b);
            for (var start = 0; ; start++)
            {
                if (_entries.TryGetValue((length, hash), out var candidates))
                    Confirm(text.Slice(start, length), start, candidates, hits);
                if (start + length >= text.Length) break;
                hash = RollingHash.Slide(hash, text[start], text[start + length], b, top);
            }
        }

        hits.Sort(static (x, y) =>
        {
            var cmp = x.Start.CompareTo(y.Start);
            if (cmp != 0) return cmp;
            cmp = y.Length.CompareTo(x.Length);
            if (cmp != 0) return cmp;
            cmp = string.CompareOrdinal(x.Name, y.Name);
            if (cmp != 0) return cmp;
            cmp = x.IsPrevious.CompareTo(y.IsPrevious);
            return cmp != 0 ? cmp : x.Kind.CompareTo(y.Kind);
        });
        return hits;
    }

    private void Confirm(
        ReadOnlySpan<char> window, int start,
        List<(string Name, bool IsPrevious, VariantKind Kind, byte[] Hmac)> candidates, List<FingerprintHit> hits)
    {
        var mac = Fingerprinter.Hmac(window, _keys);
        try
        {
            foreach (var (name, isPrevious, kind, hmac) in candidates)
            {
                if (CryptographicOperations.FixedTimeEquals(mac, hmac))
                    hits.Add(new FingerprintHit(name, isPrevious, kind, start, window.Length));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mac);
        }
    }
}
