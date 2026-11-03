namespace TswapCore.Agent;

/// <summary>
/// <c>--timeout</c> for <c>agent start</c> and <c>broker unlock</c> (brief T17 ruling 11): either
/// whole seconds (<c>90</c>, as in <c>ssh-add -t</c>) or a sequence of <c>&lt;n&gt;d|h|m|s</c> in that
/// order, each unit at most once, with no sign and no whitespace (<c>90m</c>, <c>8h</c>,
/// <c>1d12h30m</c>). The result must lie in 60 s to 30 d; anything else is a usage error.
/// </summary>
public static class AgentDuration
{
    public static readonly TimeSpan Minimum = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Maximum = TimeSpan.FromDays(30);

    public const string Usage =
        "--timeout <seconds> or <n>d<n>h<n>m<n>s (units in that order, 60s to 30d), e.g. 90m, 8h, 1d12h30m";

    private static readonly (char Unit, long Seconds)[] Units = [('d', 86400), ('h', 3600), ('m', 60), ('s', 1)];

    /// <summary>Parses <paramref name="text"/>; throws <see cref="UsageException"/> when it isn't a valid duration.</summary>
    public static TimeSpan Parse(string text)
    {
        var seconds = TryParseSeconds(text) ?? throw new UsageException(Usage);
        if (seconds < (long)Minimum.TotalSeconds || seconds > (long)Maximum.TotalSeconds)
            throw new UsageException(Usage);
        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>The total in seconds, or null for a malformed text or one that overflows.</summary>
    private static long? TryParseSeconds(string text)
    {
        if (text.Length == 0)
            return null;
        if (text.All(IsAsciiDigit))
            return ParseNumber(text);

        long total = 0;
        var nextUnit = 0;     // index into Units: each unit after the previous one
        var position = 0;
        while (position < text.Length)
        {
            var start = position;
            while (position < text.Length && IsAsciiDigit(text[position]))
                position++;
            if (position == start || position == text.Length)
                return null; // a unit with no number, or a number with no unit
            var number = ParseNumber(text[start..position]);
            var unit = text[position++];
            var index = Array.FindIndex(Units, nextUnit, u => u.Unit == unit);
            if (number is null || index < 0)
                return null; // overflow, an unknown unit, or one out of order (or repeated)
            nextUnit = index + 1;
            try
            {
                total = checked(total + checked(number.Value * Units[index].Seconds));
            }
            catch (OverflowException)
            {
                return null;
            }
        }
        return total;
    }

    private static long? ParseNumber(string digits) =>
        long.TryParse(digits, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n)
            ? n
            : null;

    private static bool IsAsciiDigit(char c) => c is >= '0' and <= '9';
}
