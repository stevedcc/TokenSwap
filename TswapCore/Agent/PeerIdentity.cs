using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using TswapCore.Broker;

namespace TswapCore.Agent;

/// <summary>
/// The peer process of a connected Unix socket, opened for ruling 20's checks: its pidfd (when the
/// kernel gives one, Linux ≥ 6.3) and a directory fd on <c>/proc/&lt;pid&gt;</c>. Reading through the
/// directory fd, then finding the pidfd still alive, proves the reads were of that same process.
/// </summary>
public sealed class PeerProcess(int pid, SafeFileHandle? pidfd, SafeFileHandle? directory) : IDisposable
{
    public int Pid { get; } = pid;
    public SafeFileHandle? Pidfd { get; } = pidfd;
    public SafeFileHandle? Directory { get; } = directory;
    public bool HasPidfd => Pidfd is { IsInvalid: false };

    public void Dispose()
    {
        Pidfd?.Dispose();
        Directory?.Dispose();
    }
}

/// <summary>
/// What a socket accepts (or, on the client side, which server it trusts).
/// </summary>
/// <param name="Uid">The one non-root uid allowed.</param>
/// <param name="AllowRoot">Whether uid 0 is allowed too (the agent: yes; the broker's control socket: no).</param>
/// <param name="CheckUserNamespace">Linux: refuse a peer (other than uid 0) in another user namespace, or whose namespace can't be read.</param>
/// <param name="CheckLabel">Linux with SELinux: refuse a container's label.</param>
/// <param name="NoProcMessage">Why a peer was refused because <c>/proc</c> isn't mounted (said once by the server).</param>
public sealed record PeerPolicy(uint Uid, bool AllowRoot, bool CheckUserNamespace, bool CheckLabel, string NoProcMessage)
{
    /// <summary>The agent's socket (rulings 7 and 20): its own uid and root; namespace (not for root) and label checks.</summary>
    public static PeerPolicy Agent(uint ownUid) => new(ownUid, AllowRoot: true, CheckUserNamespace: true, CheckLabel: true,
        PeerIdentity.NoProcAgentMessage);

    /// <summary>The broker's control socket (rulings 14 and 20): its own uid only, never root; namespace and label checks.</summary>
    public static PeerPolicy BrokerControl(uint ownUid) => new(ownUid, AllowRoot: false, CheckUserNamespace: true, CheckLabel: true,
        PeerIdentity.NoProcControlMessage);

    /// <summary>An agent client checking the agent (ruling 7): the vault owner's uid only, no namespace or label check (ruling 14).</summary>
    public static PeerPolicy AgentServer(uint ownerUid) => new(ownerUid, AllowRoot: false, CheckUserNamespace: false, CheckLabel: false, "");

    /// <summary>
    /// <c>broker unlock</c> checking the broker's control socket before it sends the password
    /// (ruling 14): the owner's uid, and on Linux the server's label and user namespace (an unreadable
    /// link is refused).
    /// </summary>
    public static PeerPolicy BrokerServerForUnlock(uint ownerUid) => new(ownerUid, AllowRoot: false, CheckUserNamespace: true,
        CheckLabel: true, PeerIdentity.NoProcControlMessage);

    /// <summary><c>broker lock</c> and <c>broker status</c> (ruling 14): the owner's uid and, on Linux, the label.</summary>
    public static PeerPolicy BrokerServerUidAndLabel(uint ownerUid) => new(ownerUid, AllowRoot: false, CheckUserNamespace: false,
        CheckLabel: true, "");
}

/// <summary>The outcome of <see cref="PeerIdentity.Check"/>: allowed, or the reason it was refused (for the log).</summary>
public readonly record struct PeerVerdict(bool Allowed, uint? Uid, int Pid, string? Reason)
{
    public static PeerVerdict Allow(uint uid, int pid) => new(true, uid, pid, null);
    public static PeerVerdict Refuse(uint? uid, int pid, string reason) => new(false, uid, pid, reason);
}

/// <summary>
/// Who is at the other end of a Unix socket (brief T17 rulings 7 and 20), shared by the agent's server,
/// the broker's control socket and the <c>broker unlock</c> client.
/// <list type="number">
/// <item>The uid from <c>SO_PEERCRED</c> (<c>getpeereid</c> on macOS) must be the policy's, or root
/// where the policy allows it.</item>
/// <item>Linux with SELinux: a peer whose <c>SO_PEERSEC</c> label has the type <c>container_t</c>,
/// <c>spc_t</c> or <c>container_runtime_t</c> is refused (uid 0 included). No SELinux label
/// (<c>ENOPROTOOPT</c>, empty, or another LSM's label such as AppArmor's) skips this check.</item>
/// <item>Linux, every peer but uid 0: its user namespace must be this process's. Against pid reuse:
/// take the peer's pidfd (<c>SO_PEERPIDFD</c>), open <c>/proc/&lt;pid&gt;</c> as a directory fd, read
/// <c>ns/user</c> and <c>status</c>'s <c>Uid:</c> line through it (the uid must be the credential's), then
/// check the pidfd is still alive (<c>pidfd_send_signal(pidfd, 0)</c>). Without <c>SO_PEERPIDFD</c>
/// (kernel &lt; 6.3) the directory fd and status uid alone. An unreadable namespace is refused. Without
/// <c>/proc</c> every such peer is refused with the policy's message.</item>
/// </list>
/// macOS has no user namespaces or labels: the uid is all there is. The seams let tests stand in for a
/// container peer, an unreadable link and a pidfd that died after the directory fd was opened.
/// </summary>
public static partial class PeerIdentity
{
    public const string NoProcAgentMessage = "/proc is not mounted: peers can't be checked, so only root may use the agent.";
    public const string NoProcControlMessage =
        "/proc is not mounted: peers can't be checked, so the broker can't be unlocked, locked or queried.";

    /// <summary>The SELinux types of container processes (ruling 20).</summary>
    public static readonly IReadOnlyList<string> ContainerTypes = ["container_t", "spc_t", "container_runtime_t"];

    // ------------------------------------------------------------------ seams

    /// <summary>The peer's uid and pid from the kernel (<c>SO_PEERCRED</c>/<c>getpeereid</c>), or null.</summary>
    internal static Func<Socket, (uint Uid, int Pid)?> ReadCredentials = BrokerNative.TryGetPeerCredentials;

    /// <summary>Opens the peer's pidfd and <c>/proc/&lt;pid&gt;</c> directory fd, or null when <c>/proc/&lt;pid&gt;</c> can't be opened.</summary>
    internal static Func<Socket, PeerProcess?> OpenPeer = socket => DefaultOpenPeer(socket);

    /// <summary>The peer's <c>ns/user</c> link (<c>user:[…]</c>), or null when unreadable.</summary>
    internal static Func<PeerProcess, string?> ReadUserNamespace = DefaultReadUserNamespace;

    /// <summary>The effective uid on the peer's <c>status</c> <c>Uid:</c> line, or null when unreadable.</summary>
    internal static Func<PeerProcess, uint?> ReadStatusUid = DefaultReadStatusUid;

    /// <summary>Whether the peer's pidfd still refers to a live process.</summary>
    internal static Func<PeerProcess, bool> PidfdAlive = DefaultPidfdAlive;

    /// <summary>The peer's SELinux label (<c>SO_PEERSEC</c>), or null when there is none (<c>ENOPROTOOPT</c>, empty, or not an SELinux context).</summary>
    internal static Func<Socket, string?> ReadPeerLabel = DefaultReadPeerLabel;

    /// <summary>This process's own <c>ns/user</c> link, or null.</summary>
    internal static Func<string?> ReadOwnUserNamespace = DefaultReadOwnUserNamespace;

    /// <summary>Whether <c>/proc</c> is mounted.</summary>
    internal static Func<bool> ProcMounted = DefaultProcMounted;

    internal static void ResetSeamsForTests()
    {
        ReadCredentials = BrokerNative.TryGetPeerCredentials;
        OpenPeer = socket => DefaultOpenPeer(socket);
        ReadUserNamespace = DefaultReadUserNamespace;
        ReadStatusUid = DefaultReadStatusUid;
        PidfdAlive = DefaultPidfdAlive;
        ReadPeerLabel = DefaultReadPeerLabel;
        ReadOwnUserNamespace = DefaultReadOwnUserNamespace;
        ProcMounted = DefaultProcMounted;
    }

    // ------------------------------------------------------------------ the check

    /// <summary>Checks the peer of <paramref name="socket"/> against <paramref name="policy"/>. Never throws.</summary>
    public static PeerVerdict Check(Socket socket, PeerPolicy policy)
    {
        try
        {
            return CheckCore(socket, policy);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or IOException or UnauthorizedAccessException)
        {
            return PeerVerdict.Refuse(null, -1, $"peer unreadable ({ex.GetType().Name})");
        }
    }

    private static PeerVerdict CheckCore(Socket socket, PeerPolicy policy)
    {
        if (ReadCredentials(socket) is not { } creds)
            return PeerVerdict.Refuse(null, -1, "no peer credentials");
        var (uid, pid) = creds;
        var root = uid == 0;
        if (root ? !policy.AllowRoot : uid != policy.Uid)
            return PeerVerdict.Refuse(uid, pid, $"uid {uid}");
        if (!OperatingSystem.IsLinux())
            return PeerVerdict.Allow(uid, pid);

        if (policy.CheckLabel && ReadPeerLabel(socket) is { Length: > 0 } label && LabelType(label) is { } type &&
            ContainerTypes.Contains(type))
            return PeerVerdict.Refuse(uid, pid, $"peer label {type}");

        // A rootless container never presents host uid 0, and host root is trusted: its link may be
        // unreadable (hidepid=2, a non-dumpable root client), so it is exempt (ruling 20).
        if (!policy.CheckUserNamespace || root)
            return PeerVerdict.Allow(uid, pid);
        if (!ProcMounted())
            return PeerVerdict.Refuse(uid, pid, policy.NoProcMessage);

        using var peer = OpenPeer(socket);
        if (peer is null)
            return PeerVerdict.Refuse(uid, pid, "peer's /proc entry unreadable");
        var theirs = ReadUserNamespace(peer);
        var statusUid = ReadStatusUid(peer);
        // Only now: a live pidfd means the pid wasn't recycled while we read through the directory fd.
        if (peer.HasPidfd && !PidfdAlive(peer))
            return PeerVerdict.Refuse(uid, pid, "peer exited (pidfd dead) during the check");
        if (theirs is null)
            return PeerVerdict.Refuse(uid, pid, "peer's user namespace unreadable");
        var ours = ReadOwnUserNamespace();
        if (ours is null || !string.Equals(theirs, ours, StringComparison.Ordinal))
            return PeerVerdict.Refuse(uid, pid, "peer in another user namespace");
        if (statusUid != uid)
            return PeerVerdict.Refuse(uid, pid, $"peer's status uid {statusUid?.ToString() ?? "?"} differs from its credential's");
        return PeerVerdict.Allow(uid, pid);
    }

    /// <summary>The type field of an SELinux context (<c>user:role:type:level</c>), or null.</summary>
    internal static string? LabelType(string label)
    {
        var fields = label.Split(':');
        return fields.Length >= 3 && fields[2].Length > 0 ? fields[2] : null;
    }

    // ------------------------------------------------------------------ defaults (Linux)

    private const int SolSocket = 1;
    private const int SoPeerSec = 31;
    private const int SoPeerPidfd = 77;
    private const int ORdonly = 0, ODirectory = 0x10000, OCloexec = 0x80000;
    private const long SysPidfdSendSignal = 424;

    internal static PeerProcess? DefaultOpenPeer(Socket socket) => DefaultOpenPeer(socket, usePidfd: true);

    /// <summary>
    /// Step 1, the pidfd (unless <paramref name="usePidfd"/> is false or the kernel has no
    /// <c>SO_PEERPIDFD</c>); step 2, <c>/proc/&lt;pid&gt;</c> as a directory fd, the pid from
    /// <c>SO_PEERCRED</c>.
    /// </summary>
    internal static PeerProcess? DefaultOpenPeer(Socket socket, bool usePidfd)
    {
        if (!OperatingSystem.IsLinux() || BrokerNative.TryGetPeerCredentials(socket) is not { Pid: > 0 } creds)
            return null;
        SafeFileHandle? pidfd = null;
        if (usePidfd)
        {
            try
            {
                Span<byte> value = stackalloc byte[4];
                if (socket.GetRawSocketOption(SolSocket, SoPeerPidfd, value) == 4)
                    pidfd = new SafeFileHandle(BitConverter.ToInt32(value), ownsHandle: true);
            }
            catch (SocketException)
            {
                // ENOPROTOOPT: a kernel older than 6.3. The fallback is the directory fd alone.
            }
        }
        var dirfd = open($"/proc/{creds.Pid}", ORdonly | ODirectory | OCloexec);
        if (dirfd < 0)
        {
            pidfd?.Dispose();
            return null;
        }
        return new PeerProcess(creds.Pid, pidfd, new SafeFileHandle(dirfd, ownsHandle: true));
    }

    internal static string? DefaultReadUserNamespace(PeerProcess peer)
    {
        if (peer.Directory is not { IsInvalid: false } dir)
            return null;
        return WithFd(dir, fd => ReadLinkAt(fd, "ns/user"));
    }

    internal static uint? DefaultReadStatusUid(PeerProcess peer)
    {
        if (peer.Directory is not { IsInvalid: false } dir)
            return null;
        var fd = WithFd(dir, d => (int?)openat(d, "status", ORdonly | OCloexec));
        if (fd is not >= 0)
            return null;
        using var handle = new SafeFileHandle(fd.Value, ownsHandle: true);
        using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 0);
        using var reader = new StreamReader(stream, Encoding.ASCII);
        while (reader.ReadLine() is { } line)
        {
            if (!line.StartsWith("Uid:", StringComparison.Ordinal))
                continue;
            // Uid: real effective saved filesystem; SO_PEERCRED holds the effective uid.
            var fields = line[4..].Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            return fields.Length >= 2 && uint.TryParse(fields[1], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var euid)
                ? euid
                : null;
        }
        return null;
    }

    internal static bool DefaultPidfdAlive(PeerProcess peer)
    {
        if (peer.Pidfd is not { IsInvalid: false } pidfd)
            return false;
        return WithFd(pidfd, fd => syscall(SysPidfdSendSignal, fd, 0, 0, 0) == 0);
    }

    internal static string? DefaultReadPeerLabel(Socket socket)
    {
        if (!OperatingSystem.IsLinux())
            return null;
        try
        {
            Span<byte> buffer = stackalloc byte[256];
            var length = socket.GetRawSocketOption(SolSocket, SoPeerSec, buffer);
            return SelinuxLabel(buffer[..length]);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ProtocolOption)
        {
            return null; // ENOPROTOOPT: no SELinux (no labelled networking)
        }
    }

    /// <summary>
    /// The SELinux context <c>SO_PEERSEC</c> returned, or null when it returned none. <c>SO_PEERSEC</c> answers
    /// with the label of whichever LSM provides it: on Ubuntu that is AppArmor (<c>unconfined</c>,
    /// <c>docker-default (enforce)</c>), which is not an SELinux context and carries no SELinux type, so it
    /// counts as no label (the check is SELinux's, ruling 20). A context is <c>user:role:type[:level]</c>:
    /// at least three non-empty fields and no whitespace.
    /// </summary>
    internal static string? SelinuxLabel(ReadOnlySpan<byte> raw)
    {
        var label = Encoding.UTF8.GetString(raw).TrimEnd('\0');
        if (label.Length == 0 || label.Any(char.IsWhiteSpace))
            return null;
        var fields = label.Split(':');
        return fields.Length >= 3 && fields[0].Length > 0 && fields[1].Length > 0 && fields[2].Length > 0 ? label : null;
    }

    internal static string? DefaultReadOwnUserNamespace()
    {
        try
        {
            return new FileInfo("/proc/self/ns/user").LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool DefaultProcMounted() => BrokerNative.LStat("/proc/self/ns/user") is { Type: BrokerNative.EntryType.Symlink };

    private static T WithFd<T>(SafeHandle handle, Func<int, T> use)
    {
        var added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            return use((int)handle.DangerousGetHandle());
        }
        finally
        {
            if (added)
                handle.DangerousRelease();
        }
    }

    private static unsafe string? ReadLinkAt(int dirfd, string path)
    {
        var buffer = stackalloc byte[256];
        var length = readlinkat(dirfd, path, buffer, 256);
        return length is <= 0 or >= 256 ? null : Encoding.UTF8.GetString(buffer, (int)length);
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int open(string path, int flags);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int openat(int dirfd, string path, int flags);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial nint readlinkat(int dirfd, string path, byte* buffer, nuint size);

    // long syscall(long number, ...): pidfd_send_signal(pidfd, sig, info, flags). The four arguments are
    // integers in registers on Linux x64 and arm64, so the fixed signature passes them as the variadic call would.
    [LibraryImport("libc", SetLastError = true)]
    private static partial long syscall(long number, long pidfd, long signal, nint info, long flags);
}
