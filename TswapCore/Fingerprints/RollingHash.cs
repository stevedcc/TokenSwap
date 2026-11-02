namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T16-S1: the polynomial rolling hash that prefilters a fingerprint scan,
/// <c>RollingHash(s) = (Σ s[i]·b^(L−1−i)) mod p</c> over UTF-16 code units with
/// <c>p = 2^61 − 1</c> and a keyed base <c>b</c> in [2, p−2] (<see cref="FingerprintKeys"/>).
/// <para>
/// It only nominates candidates: a window whose hash and length match a stored entry is confirmed
/// on the HMAC (<see cref="FingerprintIndex"/>), so a collision costs one HMAC, never a false hit.
/// The Mersenne modulus lets a 122-bit product reduce with shifts and adds instead of a division,
/// which keeps a scan O(1) per character per stored length.
/// </para>
/// </summary>
public static class RollingHash
{
    /// <summary><c>p = 2^61 − 1</c>, a Mersenne prime.</summary>
    public const ulong Modulus = (1UL << 61) - 1;

    /// <summary>The hash of <paramref name="text"/> under base <paramref name="b"/>.</summary>
    public static ulong Of(ReadOnlySpan<char> text, ulong b)
    {
        ulong hash = 0;
        foreach (var c in text)
            hash = Reduce((UInt128)hash * b + c);
        return hash;
    }

    /// <summary><c>b^exponent mod p</c>; the weight of a window's first character is <c>Power(b, L − 1)</c>.</summary>
    public static ulong Power(ulong b, int exponent)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(exponent);
        ulong result = 1, factor = b % Modulus;
        for (var e = exponent; e > 0; e >>= 1)
        {
            if ((e & 1) != 0)
                result = Reduce((UInt128)result * factor);
            factor = Reduce((UInt128)factor * factor);
        }
        return result;
    }

    /// <summary>
    /// Moves a window one character right: removes <paramref name="outgoing"/> (weighted by
    /// <paramref name="topPower"/> = <c>Power(b, L − 1)</c>) and appends <paramref name="incoming"/>.
    /// </summary>
    public static ulong Slide(ulong hash, char outgoing, char incoming, ulong b, ulong topPower)
    {
        var removed = Reduce((UInt128)outgoing * topPower);
        var rest = hash + Modulus - removed;
        if (rest >= Modulus) rest -= Modulus;
        return Reduce((UInt128)rest * b + incoming);
    }

    /// <summary>
    /// <c>x mod p</c> using <c>2^61 ≡ 1 (mod p)</c>, for <c>x &lt; 2^123</c>: the callers' largest input
    /// is <c>(p − 1)² + 0xFFFF</c> (a product of two residues plus a UTF-16 code unit), just above
    /// <c>2^122</c>. The first fold leaves less than <c>2^63</c>, the second at most <c>p + 3</c>, so one
    /// conditional subtraction finishes, and nothing overflows a <c>ulong</c> on the way.
    /// </summary>
    private static ulong Reduce(UInt128 x)
    {
        var folded = (ulong)(x & Modulus) + (ulong)(x >> 61);
        folded = (folded & Modulus) + (folded >> 61);
        return folded >= Modulus ? folded - Modulus : folded;
    }
}
