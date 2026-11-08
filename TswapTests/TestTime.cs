namespace TswapTests;

/// <summary>
/// A fixed instant for times a test only passes along as data (a <see cref="TswapCore.Config"/>'s <c>Created</c>, the
/// timestamps of an in-memory <see cref="TswapCore.Secret"/>), so such a test doesn't read the system clock. The same
/// instant <see cref="BrokerManualClock"/> starts at.
/// </summary>
internal static class TestTime
{
    public static readonly DateTime Fixed = new(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);
}
