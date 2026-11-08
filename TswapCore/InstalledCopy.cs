using System.Runtime.InteropServices;

namespace TswapCore;

/// <summary>A file's identity: its device and inode (the same for every path, hard link or symlink to it).</summary>
public readonly record struct FileId(ulong Device, ulong Inode);

/// <summary>
/// Issue #240: is the running tswap the copy the macOS installer package put in <c>/usr/local/bin</c>? Then
/// <c>installscript</c> does only the per-user steps. Compared by device and inode, not by path: a symlink from
/// <c>~/bin</c> is the installed copy, and APFS's case-insensitive names can't make two paths look different.
/// </summary>
public static class InstalledCopy
{
    public const string MacOSInstallPath = "/usr/local/bin/tswap";
    public const string MacOSDylibPath = "/usr/local/bin/libtswapse.dylib";

    public static bool IsSame(FileId running, FileId? installed) => installed == running;
}

/// <summary>Reads what <see cref="InstalledCopy"/> compares; a seam so the command's choice is testable anywhere.</summary>
public interface IInstalledFiles
{
    /// <summary>The identity of the file at <paramref name="path"/>, following symlinks; null when there is none.</summary>
    FileId? Of(string path);

    /// <summary>The bytes of the file at <paramref name="path"/>; null when it can't be read.</summary>
    byte[]? Read(string path);
}

/// <summary>
/// The real <see cref="IInstalledFiles"/>: <c>statx</c> (following symlinks) on Linux; <c>stat</c> on macOS (64-bit-inode
/// layout: <c>st_dev</c> a 32-bit value at 0, <c>st_ino</c> at 8; on x64 the <c>stat$INODE64</c> entry point, as
/// <see cref="UnixOwnership"/> does for <c>lstat</c>). Null on Windows.
/// </summary>
public sealed partial class UnixFileIds : IInstalledFiles
{
    private const int AtFdCwd = -100;
    private const uint StatxIno = 0x00000100U;
    private const int BufferSize = 256;

    public unsafe FileId? Of(string path)
    {
        if (OperatingSystem.IsWindows())
            return null;
        var buffer = stackalloc byte[BufferSize];
        new Span<byte>(buffer, BufferSize).Clear();
        try
        {
            if (OperatingSystem.IsLinux())
            {
                // struct statx: stx_ino (u64) at 32; stx_dev_major and stx_dev_minor (u32) at 136 and 140.
                if (statx(AtFdCwd, path, 0, StatxIno, buffer) != 0)
                    return null;
                return new FileId(((ulong)*(uint*)(buffer + 136) << 32) | *(uint*)(buffer + 140), *(ulong*)(buffer + 32));
            }
            if (OperatingSystem.IsMacOS())
            {
                var result = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                    ? stat_arm64(path, buffer)
                    : stat_inode64(path, buffer);
                if (result != 0)
                    return null;
                return new FileId(*(uint*)buffer, *(ulong*)(buffer + 8));
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // An old libc without statx: unknown, so installscript prints the full script as before.
        }
        return null;
    }

    public byte[]? Read(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "stat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int stat_arm64(string path, byte* buffer);

    [LibraryImport("libc", EntryPoint = "stat$INODE64", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int stat_inode64(string path, byte* buffer);
}
