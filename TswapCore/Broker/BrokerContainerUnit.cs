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

    /// <summary>
    /// Brief I224 D6, <c>socket bind --pid</c>: the unit a process's cgroup belongs to. The path up to and
    /// including the <b>first</b> segment ending in <c>.service</c> or <c>.scope</c> that is not
    /// <c>user@&lt;digits&gt;.service</c> (a user manager holds every unit of its user): for a Quadlet container
    /// that is its service (<c>.../app.slice/lane1.service/libpod-payload-&lt;id&gt;</c> gives
    /// <c>.../lane1.service</c>); for a plain <c>podman run</c>, its <c>libpod-&lt;id&gt;.scope</c>, which is one
    /// container instance (<see cref="BrokerUnitDerivation.PerInstance"/>). Refused: a path with a <c>..</c>
    /// segment, one with no such unit, and a unit <see cref="Refusal"/> refuses.
    /// </summary>
    public static BrokerUnitDerivation Derive(string cgroupPath)
    {
        var segments = cgroupPath.TrimStart('/').Split('/');
        if (segments.Contains(".."))
            return new(null, "it has a \"..\" segment: the process is outside this cgroup namespace's view", false);
        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];
            if (!segment.EndsWith(".service", StringComparison.Ordinal) && !segment.EndsWith(".scope", StringComparison.Ordinal))
                continue;
            if (IsUserManager(segment))
                continue; // the user manager's subtree holds the user's units: look further down
            var unit = "/" + string.Join('/', segments[..(i + 1)]);
            if (Refusal(segment) is { } reason)
                return new(null, $"{unit} is not a container ({reason})", false);
            if (BrokerContainerIdentity.CgroupProblem(unit) is { } problem)
                return new(null, $"{unit} is not a valid cgroup path ({problem})", false);
            var perInstance = segment.StartsWith("libpod-", StringComparison.Ordinal) || cgroupPath.Contains("user-libpod_", StringComparison.Ordinal);
            return new(unit, null, perInstance);
        }
        return new(null, "it names no systemd unit (.service or .scope) other than a user manager", false);
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

/// <summary>
/// Brief I224 D6: what <see cref="BrokerContainerUnit.Derive"/> found: the unit path, or why there is none.
/// <see cref="PerInstance"/>: the unit is one plain-Podman container instance, which a re-created container
/// doesn't keep.
/// </summary>
public sealed record BrokerUnitDerivation(string? Unit, string? Refusal, bool PerInstance);
