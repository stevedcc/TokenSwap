using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace TswapCore.Broker;

/// <summary>
/// The Unix calls the broker needs (brief T8 decisions 1 to 3), all <see cref="LibraryImportAttribute"/>
/// (source-generated, NativeAOT-safe) or managed socket options: peer credentials of an accepted
/// Unix socket, <c>flock</c>, <c>prctl(PR_SET_DUMPABLE, 0)</c>, and <c>lstat</c>'s type, mode and owner.
/// </summary>
public static partial class BrokerNative
{
    // ------------------------------------------------------------------ peer credentials

    private const int SolSocket = 1;      // Linux SOL_SOCKET
    private const int SoPeerCred = 17;    // Linux SO_PEERCRED: struct ucred { pid_t pid; uid_t uid; gid_t gid; }
    private const int SolLocal = 0;       // macOS SOL_LOCAL
    private const int LocalPeerPid = 2;   // macOS LOCAL_PEERPID

    /// <summary>
    /// The uid and pid of the process at the other end of <paramref name="socket"/> (an
    /// <b>accepted</b> Unix socket), from the kernel: <c>SO_PEERCRED</c> on Linux, <c>getpeereid</c>
    /// (and <c>LOCAL_PEERPID</c>) on macOS. Null when they can't be read: the caller closes the
    /// connection (fail closed). The pid is -1 when only the uid is known.
    /// </summary>
    public static (uint Uid, int Pid)? TryGetPeerCredentials(Socket socket)
    {
        try
        {
            if (socket.AddressFamily != AddressFamily.Unix)
                return null;
            if (OperatingSystem.IsLinux())
            {
                Span<byte> ucred = stackalloc byte[12];
                if (socket.GetRawSocketOption(SolSocket, SoPeerCred, ucred) != 12)
                    return null;
                var pid = BitConverter.ToInt32(ucred[..4]);
                var uid = BitConverter.ToUInt32(ucred[4..8]);
                return (uid, pid);
            }
            if (OperatingSystem.IsMacOS())
            {
                if (getpeereid((int)socket.Handle, out var uid, out _) != 0)
                    return null;
                var pid = -1;
                Span<byte> pidBytes = stackalloc byte[4];
                if (socket.GetRawSocketOption(SolLocal, LocalPeerPid, pidBytes) == 4)
                    pid = BitConverter.ToInt32(pidBytes);
                return (uid, pid);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or PlatformNotSupportedException
                                       or DllNotFoundException or EntryPointNotFoundException)
        {
            // Unreadable: fail closed.
        }
        return null;
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int getpeereid(int fd, out uint uid, out uint gid);

    // ------------------------------------------------------------------ flock

    private const int LockEx = 2;
    private const int LockNb = 4;

    /// <summary>Takes an exclusive, non-blocking <c>flock</c> on <paramref name="fd"/>; false when another holder has it.</summary>
    public static bool TryLockExclusive(SafeHandle fd)
    {
        var added = false;
        try
        {
            fd.DangerousAddRef(ref added);
            return flock((int)fd.DangerousGetHandle(), LockEx | LockNb) == 0;
        }
        finally
        {
            if (added) fd.DangerousRelease();
        }
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int flock(int fd, int operation);

    // ------------------------------------------------------------------ prctl

    private const int PrSetDumpable = 4;
    private const int PrGetDumpable = 3;

    /// <summary>
    /// Linux: <c>prctl(PR_SET_DUMPABLE, 0)</c>, so no same-uid ptrace and no core dump holding
    /// secrets. Returns false when it failed; a no-op returning true elsewhere.
    /// </summary>
    public static bool MakeNonDumpable()
    {
        if (!OperatingSystem.IsLinux())
            return true;
        return prctl(PrSetDumpable, 0, 0, 0, 0) == 0;
    }

    /// <summary>Linux: <c>prctl(PR_GET_DUMPABLE)</c> (1 dumpable, 0 not); -1 elsewhere.</summary>
    public static int GetDumpable() => OperatingSystem.IsLinux() ? prctl(PrGetDumpable, 0, 0, 0, 0) : -1;

    [LibraryImport("libc", SetLastError = true)]
    private static partial int prctl(int option, nuint arg2, nuint arg3, nuint arg4, nuint arg5);

    // ------------------------------------------------------------------ realpath

    /// <summary><c>realpath(3)</c>: <paramref name="path"/> with every symlink and dot segment resolved, or null.</summary>
    public static string? RealPath(string path)
    {
        var resolved = realpath(path, 0);
        if (resolved == 0)
            return null;
        try
        {
            return Marshal.PtrToStringUTF8(resolved);
        }
        finally
        {
            free(resolved);
        }
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint realpath(string path, nint resolved);

    [LibraryImport("libc")]
    private static partial void free(nint pointer);

    // ------------------------------------------------------------------ lstat

    /// <summary>The kind of file system entry at a path, without following a symlink.</summary>
    public enum EntryType
    {
        Missing,
        Regular,
        Directory,
        Symlink,
        Socket,
        Other,
    }

    /// <summary>
    /// <c>lstat</c> of <paramref name="path"/>: its type, permission bits and owner uid (a symlink's
    /// own, never its target's). Null when it can't be read for another reason than not existing.
    /// </summary>
    public static unsafe (EntryType Type, UnixFileMode Mode, uint Uid)? LStat(string path)
    {
        var buffer = stackalloc byte[256];
        int result;
        uint mode, uid;
        if (OperatingSystem.IsLinux())
        {
            const int AtFdCwd = -100, AtSymlinkNoFollow = 0x100;
            const uint StatxType = 0x1, StatxMode = 0x2, StatxUid = 0x8;
            result = statx(AtFdCwd, path, AtSymlinkNoFollow, StatxType | StatxMode | StatxUid, buffer);
            mode = *(ushort*)(buffer + 28);
            uid = *(uint*)(buffer + 20);
        }
        else if (OperatingSystem.IsMacOS())
        {
            result = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? lstat_arm64(path, buffer)
                : lstat_inode64(path, buffer);
            mode = *(ushort*)(buffer + 4);
            uid = *(uint*)(buffer + 16);
        }
        else
        {
            return null;
        }
        if (result != 0)
        {
            const int Enoent = 2, Enotdir = 20;
            var errno = Marshal.GetLastPInvokeError();
            return errno is Enoent or Enotdir ? (EntryType.Missing, UnixFileMode.None, 0) : null;
        }
        var type = (mode & 0xF000) switch
        {
            0x8000 => EntryType.Regular,
            0x4000 => EntryType.Directory,
            0xA000 => EntryType.Symlink,
            0xC000 => EntryType.Socket,
            _ => EntryType.Other,
        };
        return (type, (UnixFileMode)(mode & 0xFFF), uid);
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int lstat_arm64(string path, byte* buffer);

    [LibraryImport("libc", EntryPoint = "lstat$INODE64", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int lstat_inode64(string path, byte* buffer);
}
