using System.Text;

namespace TswapCore.Broker;

/// <summary>
/// Brief I224 D1: a validated container binding of one socket: the cgroup v2 path of the container's
/// systemd unit (a peer is admitted when its cgroup equals it or lies under it) and, optionally, the
/// exact SELinux label its processes carry (corroboration only).
/// </summary>
public sealed record BrokerContainerIdentity(string Cgroup, string? SelinuxLabel)
{
    /// <summary>The longest bound cgroup path, in bytes (ASCII: one byte a character).</summary>
    public const int MaxCgroupBytes = 1024;

    /// <summary>The longest bound SELinux label, in bytes.</summary>
    public const int MaxLabelBytes = 256;

    /// <summary>Validates <paramref name="config"/> for socket <paramref name="socket"/>; throws <see cref="BrokerConfigException"/>.</summary>
    public static BrokerContainerIdentity Validate(string socket, BrokerContainerConfig config)
    {
        var cgroup = config.Cgroup ?? "";
        if (CgroupProblem(cgroup) is { } problem)
            throw new BrokerConfigException($"socket {socket}: container.cgroup {Shown(cgroup)} is not a valid cgroup path ({problem})");
        if (BrokerContainerUnit.Refusal(cgroup[(cgroup.LastIndexOf('/') + 1)..]) is { } reason)
            throw new BrokerConfigException($"socket {socket}: container.cgroup {cgroup} is not a container ({reason})");
        if (config.SelinuxLabel is { } label && !IsWholeLabel(label))
            throw new BrokerConfigException(
                $"socket {socket}: container.selinux_label {Shown(label)} is not a whole SELinux label " +
                "(user:role:type:level, each part non-empty printable ASCII without spaces, at most 256 bytes)");
        return new BrokerContainerIdentity(cgroup, config.SelinuxLabel);
    }

    /// <summary>
    /// Why <paramref name="cgroup"/> is not a path D1 accepts, or null: printable ASCII (0x21-0x7E) only,
    /// at most 1024 bytes, starting with <c>/</c>, not ending with one, no empty, <c>.</c> or <c>..</c>
    /// segment.
    /// </summary>
    public static string? CgroupProblem(string cgroup)
    {
        if (!cgroup.StartsWith('/'))
            return "it doesn't start with /";
        if (!IsPrintableAscii(cgroup))
            return "it may use printable ASCII only, no spaces";
        if (cgroup.Length > MaxCgroupBytes)
            return $"it is longer than {MaxCgroupBytes} bytes";
        if (cgroup.Length > 1 && cgroup.EndsWith('/'))
            return "it ends with /";
        foreach (var segment in cgroup[1..].Split('/'))
            if (segment is "" or "." or "..")
                return "it has an empty, . or .. segment";
        return null;
    }

    /// <summary>
    /// A whole SELinux label as D1 binds it: four or more <c>:</c>-separated parts (a container's label
    /// carries a level), each non-empty printable ASCII without whitespace, at most 256 bytes. Stricter
    /// than <see cref="Agent.PeerIdentity.SelinuxLabel"/>, which accepts three parts.
    /// </summary>
    public static bool IsWholeLabel(string label) =>
        label.Length <= MaxLabelBytes && IsPrintableAscii(label) && label.Split(':') is { Length: >= 4 } parts && parts.All(p => p.Length > 0);

    private static bool IsPrintableAscii(string value) => value.All(c => c is >= '\x21' and <= '\x7e');

    /// <summary>A configured value for a refusal message: anything outside 0x20-0x7E shown as <c>?</c>, capped at 1024 characters.</summary>
    public static string Shown(string value)
    {
        var sb = new StringBuilder(Math.Min(value.Length, MaxCgroupBytes) + 1);
        foreach (var c in value)
        {
            if (sb.Length == MaxCgroupBytes)
                return sb.Append('…').ToString();
            sb.Append(c is >= '\x20' and <= '\x7e' ? c : '?');
        }
        return sb.ToString();
    }
}
