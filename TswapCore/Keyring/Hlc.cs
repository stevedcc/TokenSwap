using System.Globalization;

namespace TswapCore.Keyring;

/// <summary>
/// A hybrid logical clock value (brief T6 decision 3, owner decision on #132): physical
/// milliseconds since the Unix epoch plus a logical counter. The ordering authority of the
/// per-secret record store, together with an origin id as the tiebreak (<see cref="Stamp"/>).
/// <para>
/// A write takes <c>max(now, the highest HLC this machine has seen)</c> and steps the logical
/// counter when the physical part doesn't advance (<see cref="Next"/>), so it never runs backwards
/// and always orders after everything it has seen, even with a clock set back. In the normal NTP
/// case it behaves like "the latest change wins".
/// </para>
/// <para>The physical part is what <c>names</c> and <c>list</c> display; see <see cref="Display"/>.</para>
/// </summary>
public readonly record struct Hlc(long PhysicalMs, uint Logical) : IComparable<Hlc>
{
    /// <summary>The smallest value; every real write orders after it.</summary>
    public static Hlc Zero => new(0, 0);

    /// <summary>
    /// The stamp for a new write: <paramref name="nowMs"/> when it is ahead of
    /// <paramref name="highestSeen"/>, otherwise <paramref name="highestSeen"/>'s physical part with
    /// the logical counter stepped. Always strictly greater than <paramref name="highestSeen"/>.
    /// </summary>
    public static Hlc Next(Hlc highestSeen, long nowMs)
    {
        if (nowMs > highestSeen.PhysicalMs)
            return new Hlc(nowMs, 0);
        if (highestSeen.Logical == uint.MaxValue)
            return new Hlc(checked(highestSeen.PhysicalMs + 1), 0);
        return new Hlc(highestSeen.PhysicalMs, highestSeen.Logical + 1);
    }

    public int CompareTo(Hlc other)
    {
        var physical = PhysicalMs.CompareTo(other.PhysicalMs);
        return physical != 0 ? physical : Logical.CompareTo(other.Logical);
    }

    public static Hlc Max(Hlc a, Hlc b) => a.CompareTo(b) >= 0 ? a : b;

    public static bool operator <(Hlc a, Hlc b) => a.CompareTo(b) < 0;
    public static bool operator >(Hlc a, Hlc b) => a.CompareTo(b) > 0;
    public static bool operator <=(Hlc a, Hlc b) => a.CompareTo(b) <= 0;
    public static bool operator >=(Hlc a, Hlc b) => a.CompareTo(b) >= 0;

    /// <summary>The <c>config.json</c> form (<c>LastHlc</c>): <c>"&lt;ms&gt;.&lt;logical&gt;"</c>.</summary>
    public override string ToString() =>
        PhysicalMs.ToString(CultureInfo.InvariantCulture) + "." + Logical.ToString(CultureInfo.InvariantCulture);

    /// <summary>Parses <see cref="ToString"/>'s form; null or malformed gives null.</summary>
    public static Hlc? TryParse(string? text)
    {
        if (text == null)
            return null;
        var dot = text.IndexOf('.');
        if (dot <= 0
            || !long.TryParse(text.AsSpan(0, dot), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var ms)
            || !uint.TryParse(text.AsSpan(dot + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var logical))
            return null;
        return new Hlc(ms, logical);
    }

    /// <summary>Largest physical part that is a valid <see cref="DateTime"/> (UTC).</summary>
    public static readonly long MaxDisplayableMs = (DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond;

    /// <summary>
    /// The physical part as a UTC <see cref="DateTime"/> for display, clamped (decision 3, absurd
    /// stamps): beyond <see cref="DateTime.MaxValue"/> gives <see cref="DateTime.MaxValue"/>, before
    /// the epoch gives the epoch, so one bad clock can't make a listing throw.
    /// </summary>
    public static DateTime ToDisplayDate(long physicalMs)
    {
        if (physicalMs >= MaxDisplayableMs)
            return DateTime.MaxValue;
        if (physicalMs <= 0)
            return DateTime.UnixEpoch;
        return DateTime.UnixEpoch.AddMilliseconds(physicalMs);
    }

    /// <summary>
    /// <c>yyyy-MM-dd HH:mm</c> for a display date, or <c>far future</c> for a clamped one
    /// (<see cref="ToDisplayDate"/>).
    /// </summary>
    public static string Display(DateTime utc) =>
        utc == DateTime.MaxValue ? "far future" : utc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
}

/// <summary>
/// An ordering stamp: an <see cref="Hlc"/> plus the 16-byte origin id of the machine that made it
/// (brief T6 decision 3). (HLC, origin) is a total order: the larger HLC wins; at equal HLC the
/// larger origin id, compared bytewise, wins.
/// </summary>
public sealed class Stamp : IComparable<Stamp>, IEquatable<Stamp>
{
    public Stamp(Hlc hlc, byte[] origin)
    {
        if (origin.Length != KeyringFormat.OriginIdSize)
            throw new ArgumentException($"Origin must be {KeyringFormat.OriginIdSize} bytes", nameof(origin));
        Hlc = hlc;
        Origin = origin;
    }

    public Hlc Hlc { get; }

    public byte[] Origin { get; }

    /// <summary>The smallest stamp (HLC zero, all-zero origin).</summary>
    public static Stamp Zero { get; } = new(Hlc.Zero, new byte[KeyringFormat.OriginIdSize]);

    public int CompareTo(Stamp? other)
    {
        if (other is null)
            return 1;
        var hlc = Hlc.CompareTo(other.Hlc);
        return hlc != 0 ? hlc : Origin.AsSpan().SequenceCompareTo(other.Origin);
    }

    public bool Equals(Stamp? other) => other is not null && Hlc == other.Hlc && Origin.AsSpan().SequenceEqual(other.Origin);

    public override bool Equals(object? obj) => obj is Stamp s && Equals(s);

    public override int GetHashCode() => HashCode.Combine(Hlc, BitConverter.ToInt64(Origin, 0));

    public static Stamp Max(Stamp a, Stamp b) => a.CompareTo(b) >= 0 ? a : b;

    public override string ToString() => $"{Hlc}@{Convert.ToHexStringLower(Origin)[..8]}";
}
