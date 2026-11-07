using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>The Unix calls <see cref="FilledFiles"/> needs beyond <see cref="BrokerNative"/>.</summary>
internal static partial class FilledFilesNative
{
    /// <summary>EEXIST (17 on Linux and macOS).</summary>
    public const int Eexist = 17;

    /// <summary>
    /// The hard-link count of <paramref name="path"/> itself (not following a symlink): <c>statx</c>
    /// on Linux (<c>stx_nlink</c> at 16), <c>lstat</c> on macOS (<c>st_nlink</c>, 16 bits at 6). Null when
    /// it can't be read.
    /// </summary>
    internal static unsafe long? LinkCount(string path)
    {
        var buffer = stackalloc byte[256];
        new Span<byte>(buffer, 256).Clear();
        try
        {
            if (OperatingSystem.IsLinux())
            {
                const int AtFdCwd = -100, AtSymlinkNoFollow = 0x100;
                const uint StatxNlink = 0x4;
                return statx(AtFdCwd, path, AtSymlinkNoFollow, StatxNlink, buffer) == 0 ? *(uint*)(buffer + 16) : null;
            }
            if (OperatingSystem.IsMacOS())
            {
                var result = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? lstat_arm64(path, buffer) : lstat_inode64(path, buffer);
                return result == 0 ? *(ushort*)(buffer + 6) : null;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Unknown: the caller doesn't zero.
        }
        return null;
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int lstat_arm64(string path, byte* buffer);

    [LibraryImport("libc", EntryPoint = "lstat$INODE64", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int lstat_inode64(string path, byte* buffer);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int mkdir(string path, uint mode);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int kill(int pid, int signal);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int getpgid(int pid);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int getpgrp();

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int open(string path, int flags);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int close(int fd);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int tcgetpgrp(int fd);

    [LibraryImport("libc", SetLastError = true)]
    internal static unsafe partial int proc_listchildpids(int ppid, int* buffer, int bufferSize);
}
