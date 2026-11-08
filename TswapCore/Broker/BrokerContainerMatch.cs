using System.Net.Sockets;
using TswapCore.Agent;

namespace TswapCore.Broker;

/// <summary>
/// Brief I224 D3: whether a peer is the container its socket is bound to. <see cref="Allowed"/> true means it
/// is; otherwise <see cref="Reason"/> is one of the reason words. The observed facts (what was read, or null)
/// are kept for the connection's later re-checks and for the log.
/// </summary>
public sealed record BrokerContainerResult(bool Allowed, string? Reason, string? ObservedCgroup, string? ObservedLabel)
{
    public static BrokerContainerResult Allow(string cgroup, string? label) => new(true, null, cgroup, label);

    public static BrokerContainerResult Refuse(string reason, string? cgroup = null, string? label = null) => new(false, reason, cgroup, label);
}

/// <summary>
/// Brief I224 D3: reads a peer's identity from the kernel (<see cref="Observe"/>) and compares it with a
/// socket's binding (<see cref="Check"/>). Only kernel facts are used, and only exact matches admit.
/// </summary>
public static class BrokerContainerMatch
{
    // The reason words (D5): logged as they are; the client never sees which one it was.
    public const string NoPidfd = "no-pidfd";
    public const string ProcHidden = "proc-hidden";
    public const string IdentityUnreadable = "identity-unreadable";
    public const string PeerExited = "peer-exited";
    public const string CgroupMismatch = "cgroup-mismatch";
    public const string LabelMismatch = "label-mismatch";

    private const int Enoent = 2, Eacces = 13;

    /// <summary>
    /// D3.6: <paramref name="observedCgroup"/> equals the bound path or lies under it (the bound path plus
    /// <c>/</c>), compared ordinally; never a bare prefix (<c>lane1.service</c> doesn't admit
    /// <c>lane1.service-x</c>) and never a substring. Then a bound label must equal the observed one exactly;
    /// a bound label with none observed is unreadable.
    /// </summary>
    public static BrokerContainerResult Check(BrokerContainerIdentity bound, string observedCgroup, string? observedLabel)
    {
        var under = string.Equals(observedCgroup, bound.Cgroup, StringComparison.Ordinal)
            || observedCgroup.StartsWith(bound.Cgroup + "/", StringComparison.Ordinal);
        if (!under)
            return BrokerContainerResult.Refuse(CgroupMismatch, observedCgroup, observedLabel);
        if (bound.SelinuxLabel is { } label)
        {
            if (observedLabel is null)
                return BrokerContainerResult.Refuse(IdentityUnreadable, observedCgroup, observedLabel);
            if (!string.Equals(observedLabel, label, StringComparison.Ordinal))
                return BrokerContainerResult.Refuse(LabelMismatch, observedCgroup, observedLabel);
        }
        return BrokerContainerResult.Allow(observedCgroup, observedLabel);
    }

    /// <summary>
    /// D3.1-5 on the accepted <paramref name="socket"/>, whose <c>SO_PEERCRED</c> uid
    /// (<paramref name="credsUid"/>) already passed the socket's uid check, then <see cref="Check"/> against
    /// <paramref name="bound"/>:
    /// <list type="number">
    /// <item>the pidfd (none: <c>no-pidfd</c>; the dirfd-only fallback of the agent sockets is not a pass here);</item>
    /// <item><c>/proc/&lt;pid&gt;</c> as a directory fd (ENOENT/EACCES with a live pidfd: <c>proc-hidden</c>; with
    /// a dead one: <c>peer-exited</c>; anything else: <c>identity-unreadable</c>);</item>
    /// <item><c>status</c> (its effective uid must be <paramref name="credsUid"/>) and <c>cgroup</c> through it;</item>
    /// <item><c>SO_PEERSEC</c>, only when a label is bound;</item>
    /// <item>the pidfd still alive after the reads (else <c>peer-exited</c>).</item>
    /// </list>
    /// Never throws: any exception is <c>identity-unreadable</c>.
    /// </summary>
    public static BrokerContainerResult Observe(Socket socket, uint credsUid, BrokerContainerIdentity bound)
    {
        try
        {
            return ObserveCore(socket, credsUid, bound);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return BrokerContainerResult.Refuse(IdentityUnreadable);
        }
    }

    private static BrokerContainerResult ObserveCore(Socket socket, uint credsUid, BrokerContainerIdentity bound)
    {
        var opened = PeerIdentity.OpenPeerDetailed(socket);
        if (opened.Peer is not { } peer)
        {
            if (!opened.GotPidfd)
                return BrokerContainerResult.Refuse(opened.Pid > 0 ? NoPidfd : IdentityUnreadable);
            if (opened.Errno is Enoent or Eacces)
                return BrokerContainerResult.Refuse(opened.PidfdAlive ? ProcHidden : PeerExited);
            return BrokerContainerResult.Refuse(IdentityUnreadable);
        }
        using (peer)
        {
            if (!peer.HasPidfd)
                return BrokerContainerResult.Refuse(NoPidfd);
            var statusUid = PeerIdentity.ReadStatusUid(peer);
            var cgroupBytes = PeerIdentity.ReadCgroup(peer);
            var label = bound.SelinuxLabel is null ? null : PeerIdentity.ReadPeerLabel(socket);
            // Only now: a live pidfd means every read above was of this same process (no pid reuse).
            if (!PeerIdentity.PidfdAlive(peer))
                return BrokerContainerResult.Refuse(PeerExited);
            var cgroup = cgroupBytes is null ? null : PeerIdentity.ParseCgroupV2(cgroupBytes);
            if (statusUid != credsUid || cgroup is null)
                return BrokerContainerResult.Refuse(IdentityUnreadable, cgroup, label);
            return Check(bound, cgroup, label);
        }
    }
}
