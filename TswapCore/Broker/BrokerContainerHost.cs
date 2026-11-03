using TswapCore.Agent;

namespace TswapCore.Broker;

/// <summary>
/// Brief I224 D2: the platform facts a socket with <c>container</c> needs, each behind a seam (tests
/// fake them through <see cref="BrokerServerOptions.ContainerHost"/>), and the start check built on them.
/// <c>serve</c> refuses a config at start, and keeps its current one on SIGHUP, when a socket has
/// <c>container</c> and this host can't check it. <c>uid_only</c> sockets never consult these facts.
/// </summary>
public sealed record BrokerContainerHost
{
    /// <summary>Whether this is Linux (the cgroup check reads <c>/proc</c>).</summary>
    public required Func<bool> IsLinux { get; init; }

    /// <summary>Whether the kernel gives <c>SO_PEERPIDFD</c> (probed on a <c>socketpair()</c>).</summary>
    public required Func<bool> PeerPidfdAvailable { get; init; }

    /// <summary>This process's <c>/proc/self/cgroup</c>, or null when it can't be read.</summary>
    public required Func<byte[]?> ReadOwnCgroup { get; init; }

    /// <summary>Whether SELinux is enabled (<c>/sys/fs/selinux/enforce</c> exists).</summary>
    public required Func<bool> SelinuxEnabled { get; init; }

    /// <summary>The real facts of this host.</summary>
    public static BrokerContainerHost Real { get; } = new()
    {
        IsLinux = OperatingSystem.IsLinux,
        PeerPidfdAvailable = BrokerNative.PeerPidfdAvailable,
        ReadOwnCgroup = ReadOwnCgroupFile,
        SelinuxEnabled = () => File.Exists("/sys/fs/selinux/enforce"),
    };

    /// <summary>
    /// Why <c>serve</c> may not use <paramref name="policy"/> on this host, naming the first socket (in
    /// ordinal order) whose binding can't be checked here, or null. Each fact is read at most once a call,
    /// and only when a socket has <c>container</c>.
    /// </summary>
    public string? StartRefusal(BrokerPolicy policy)
    {
        bool? linux = null, pidfd = null, selinux = null;
        string? cgroupProblem = null;
        var cgroupChecked = false;
        foreach (var (name, socket) in policy.Sockets.OrderBy(s => s.Key, StringComparer.Ordinal))
        {
            if (socket.Container is not { } container)
                continue;
            if (!(linux ??= IsLinux()))
                return $"socket {name}: \"container\" needs Linux (the broker reads the client's cgroup from /proc); use \"uid_only\": true on this platform";
            if (!(pidfd ??= PeerPidfdAvailable()))
                return $"socket {name}: \"container\" needs SO_PEERPIDFD (Linux 6.5 or later), which this kernel doesn't give";
            if (!cgroupChecked)
            {
                cgroupProblem = OwnCgroupProblem(ReadOwnCgroup());
                cgroupChecked = true;
            }
            if (cgroupProblem is not null)
                return $"socket {name}: {cgroupProblem}";
            if (container.SelinuxLabel is not null && !(selinux ??= SelinuxEnabled()))
                return $"socket {name}: container.selinux_label needs SELinux, which is not enabled (no /sys/fs/selinux/enforce)";
        }
        return null;
    }

    /// <summary>
    /// D2's whole check of this process's own cgroup: exactly one <c>0::/...</c> line (cgroup v2 only;
    /// v1 and hybrid hosts have more lines or other hierarchies), and no <c>..</c> segment (which shows a
    /// <c>serve</c> outside its cgroup namespace's view). Null when it passes. A <c>serve</c> in a nested
    /// cgroup namespace isn't caught here, but fails closed: its peers outside the namespace root show
    /// <c>..</c> and are refused.
    /// </summary>
    internal static string? OwnCgroupProblem(byte[]? content)
    {
        const string NotV2 = "\"container\" needs a cgroup v2 host (/proc/self/cgroup must be one \"0::/...\" line)";
        // The shape only (PeerIdentity.CgroupV2Path): "0::/" is accepted here, as serve may run in the root
        // cgroup; ParseCgroupV2 refuses it for peers, which are never the root (see its comment).
        if (content is null || PeerIdentity.CgroupV2Path(content) is not { } path)
            return NotV2;
        if (path.Split('/').Contains(".."))
            return "\"container\" needs serve in the host's root cgroup namespace (/proc/self/cgroup has a \"..\" segment)";
        return null;
    }

    /// <summary>
    /// D2's start lines, one per socket in ordinal order: <c>socket &lt;name&gt;: container &lt;cgroup&gt;[ label &lt;label&gt;]</c>
    /// or <c>socket &lt;name&gt;: uid-only (any process with a listed uid is admitted)</c>.
    /// </summary>
    public static IEnumerable<string> StartLines(BrokerPolicy policy) =>
        policy.Sockets.OrderBy(s => s.Key, StringComparer.Ordinal).Select(s => s.Value.Container is { } c
            ? $"socket {s.Key}: container {c.Cgroup}{(c.SelinuxLabel is null ? "" : " label " + c.SelinuxLabel)}"
            : $"socket {s.Key}: uid-only (any process with a listed uid is admitted)");

    private static byte[]? ReadOwnCgroupFile()
    {
        try
        {
            return File.ReadAllBytes("/proc/self/cgroup");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
