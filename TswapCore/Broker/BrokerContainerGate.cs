using System.Net.Sockets;

namespace TswapCore.Broker;

/// <summary>
/// Brief I224 D4: the one connection gate of <c>serve</c>, used by the HTTP sockets
/// (<c>BrokerServer.GateAsync</c>) and the ssh-agent sockets alike, before any byte is parsed; and the one
/// re-check, per request and per ssh message, of the facts stored at accept against the current policy.
/// A refusal closes the connection unanswered (D5): no new bytes reach the client, so it can't tell which
/// check failed.
/// </summary>
public sealed class BrokerContainerGate(BrokerServerOptions options)
{
    /// <summary>D3.2: said once per serve, the first time a client's <c>/proc</c> entry is hidden.</summary>
    public const string ProcHiddenEvent =
        "can't see client processes in /proc (hidepid?): mount /proc with gid=<group> and add the vault user to it";

    private int _procHiddenSaid;

    /// <summary>
    /// Admits the peer of <paramref name="socket"/> on <paramref name="socketName"/> (logged as
    /// <paramref name="logName"/>), or logs why not and returns null. One snapshot of the policy decides the
    /// own-uid, uid and container checks. For a socket bound to a container the identity is read from the
    /// kernel (<see cref="BrokerContainerMatch.Observe"/>) and stored on the returned peer.
    /// </summary>
    public BrokerPeer? Admit(Socket? socket, string socketName, string logName)
    {
        var creds = socket is null ? null : BrokerNative.TryGetPeerCredentials(socket);
        if (creds is not { } c)
        {
            options.Log.Connection(logName, null, null, "no-peer-credentials");
            return null;
        }
        // Brief T9: no client may share the broker's uid (the vault user's). A process with it could read the
        // broker's config and the vault directly, so the socket is not its way in, and refusing it keeps a
        // misconfigured container (rootless Podman run by the vault user) from looking like a client.
        if (c.Uid == options.Ownership.EffectiveUid && !options.AllowOwnUidForTests)
        {
            options.Log.Connection(logName, c.Uid, c.Pid, "own-uid");
            return null;
        }
        var policy = options.Policy.Current; // read once: every check below uses this snapshot
        if (!policy.Sockets.TryGetValue(socketName, out var allowed) || !allowed.AllowsUid(c.Uid))
        {
            options.Log.Connection(logName, c.Uid, c.Pid, allowed is null ? "socket-removed" : "uid-not-allowed");
            return null;
        }
        string? cgroup = null, label = null;
        if (allowed.Container is { } bound)
        {
            options.BeforeIdentityReadForTests?.Invoke();
            var observed = BrokerContainerMatch.Observe(socket!, c.Uid, bound);
            if (!observed.Allowed)
            {
                if (observed.Reason == BrokerContainerMatch.ProcHidden && Interlocked.Exchange(ref _procHiddenSaid, 1) == 0)
                    options.Log.Event(ProcHiddenEvent);
                options.Log.Connection(logName, c.Uid, c.Pid, observed.Reason ?? BrokerContainerMatch.IdentityUnreadable,
                    observed.ObservedCgroup, observed.ObservedLabel);
                return null;
            }
            (cgroup, label) = (observed.ObservedCgroup, observed.ObservedLabel);
        }
        var peer = new BrokerPeer(socketName, c.Uid, c.Pid, cgroup, label);
        options.OnAdmittedForTests?.Invoke(peer);
        return peer;
    }

    /// <summary>
    /// D4's re-check: why <paramref name="peer"/> (its uid and the identity stored at accept) may not go on under
    /// <paramref name="policy"/>, or null. Never reads <c>/proc</c> again. A socket bound since the connection
    /// was accepted on it as uid-only has no stored identity: <c>identity-unreadable</c>. An unbound
    /// (<c>uid_only</c>) socket ignores the stored identity.
    /// </summary>
    public static string? Recheck(BrokerPolicy policy, BrokerPeer peer)
    {
        if (!policy.Sockets.TryGetValue(peer.Socket, out var socket))
            return "socket-removed";
        if (!socket.AllowsUid(peer.Uid))
            return "uid-not-allowed";
        if (socket.Container is not { } bound)
            return null;
        if (peer.Cgroup is null)
            return BrokerContainerMatch.IdentityUnreadable;
        return BrokerContainerMatch.Check(bound, peer.Cgroup, peer.Label).Reason;
    }
}
