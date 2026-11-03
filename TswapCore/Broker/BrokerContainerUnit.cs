namespace TswapCore.Broker;

/// <summary>
/// Brief I224 D1: the one predicate on the last segment of a bound cgroup path, shared by
/// <c>broker.json</c> validation and <c>socket bind --pid</c>. It is a deny-list of systemd units known
/// not to be containers (a user manager, a login session, the root scope), not a proof that a unit is
/// one.
/// </summary>
public static class BrokerContainerUnit
{
    /// <summary>
    /// Why <paramref name="lastSegment"/> can't name a container's unit, or null when it may. Every
    /// accepted segment ends in <c>.service</c> or <c>.scope</c>.
    /// </summary>
    public static string? Refusal(string lastSegment)
    {
        if (!lastSegment.EndsWith(".service", StringComparison.Ordinal) && !lastSegment.EndsWith(".scope", StringComparison.Ordinal))
            return "not a systemd unit"; // a slice (/user.slice/user-1001.slice) is every process of a user
        if (IsUserManager(lastSegment))
            return "the user manager: every process of that user";
        if (lastSegment is "init.scope" or "manager.scope")
            return "the user manager itself";
        // logind names sessions session-3.scope and session-c2.scope: anything after "session-".
        if (lastSegment.StartsWith("session-", StringComparison.Ordinal) && lastSegment.EndsWith(".scope", StringComparison.Ordinal))
            return "a login session";
        if (lastSegment == "-.scope")
            return "the root scope";
        return null;
    }

    /// <summary><c>user@&lt;digits&gt;.service</c>: a user's systemd manager, whose subtree holds every process of that user.</summary>
    public static bool IsUserManager(string segment)
    {
        const string prefix = "user@", suffix = ".service";
        if (!segment.StartsWith(prefix, StringComparison.Ordinal) || !segment.EndsWith(suffix, StringComparison.Ordinal))
            return false;
        var digits = segment.AsSpan(prefix.Length, segment.Length - prefix.Length - suffix.Length);
        return digits.Length > 0 && !digits.ContainsAnyExceptInRange('0', '9');
    }
}
