using System.Runtime.InteropServices;

namespace TswapCore;

/// <summary>
/// The Unix calls <see cref="DirectoryOwnerMatcher"/> needs, behind an interface so tests can
/// fake them (no real root needed). <see cref="UnixOwnership"/> is the real one.
/// </summary>
public interface IUnixOwnership
{
    /// <summary>True when the process runs as root (sudo).</summary>
    bool IsPrivileged { get; }

    /// <summary>The process's effective uid.</summary>
    uint EffectiveUid { get; }

    /// <summary>The owner and group of <paramref name="path"/>, or null when they can't be read.</summary>
    (uint Uid, uint Gid)? GetOwner(string path);

    /// <summary>Sets the owner and group of <paramref name="path"/>; throws on failure.</summary>
    void Chown(string path, uint uid, uint gid);
}

/// <summary>
/// T5 (found in the real-hardware test): a file tswap writes while privileged (sudo) into a folder
/// owned by another user (the vault's user, via <c>SUDO_USER</c> or <c>TSWAP_CONFIG_DIR</c>) would
/// be <c>root:root 0600</c>, and the vault's user then can't read their own config. So every file
/// tswap writes (config, secrets, backups, receipts, approve and export files) goes through
/// <see cref="Apply"/>: privileged on Unix and the folder owned by another uid ⇒ the file gets the
/// folder's owner and group, and mode 0600. Windows, unprivileged runs and a folder this uid owns:
/// nothing changes.
/// </summary>
public sealed class DirectoryOwnerMatcher(IUnixOwnership? ownership = null)
{
    private readonly IUnixOwnership _ownership = ownership ?? new UnixOwnership();

    /// <summary>The matcher every real <see cref="Storage"/> uses.</summary>
    public static DirectoryOwnerMatcher Default { get; } = new();

    /// <summary>Gives <paramref name="path"/> its folder's owner and group (see the type's comment).</summary>
    public void Apply(string path)
    {
        if (OperatingSystem.IsWindows() || !_ownership.IsPrivileged)
            return;

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (directory == null || _ownership.GetOwner(directory) is not { } owner || owner.Uid == _ownership.EffectiveUid)
            return;

        _ownership.Chown(fullPath, owner.Uid, owner.Gid);
        File.SetUnixFileMode(fullPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}

/// <summary>
/// The real <see cref="IUnixOwnership"/>: <c>geteuid</c>, <c>chown</c>, and the owner from
/// <c>statx</c> on Linux (its struct layout is the same on every architecture) or <c>stat</c> on
/// macOS (64-bit-inode layout: <c>st_uid</c> at 16, <c>st_gid</c> at 20). Source-generated
/// <see cref="LibraryImportAttribute"/> marshalling, so NativeAOT-safe.
/// </summary>
public sealed partial class UnixOwnership : IUnixOwnership
{
    private const int AtFdCwd = -100;
    private const uint StatxUid = 0x00000008U;
    private const uint StatxGid = 0x00000010U;
    private const int StatxSize = 256;

    public bool IsPrivileged => Environment.IsPrivilegedProcess;

    public uint EffectiveUid => OperatingSystem.IsWindows() ? 0 : geteuid();

    public unsafe (uint Uid, uint Gid)? GetOwner(string path)
    {
        if (OperatingSystem.IsWindows())
            return null;
        var buffer = stackalloc byte[StatxSize];
        new Span<byte>(buffer, StatxSize).Clear();
        try
        {
            if (OperatingSystem.IsLinux())
            {
                // struct statx: stx_mask(4) stx_blksize(4) stx_attributes(8) stx_nlink(4) stx_uid(4) stx_gid(4)
                if (statx(AtFdCwd, path, 0, StatxUid | StatxGid, buffer) != 0)
                    return null;
                return (*(uint*)(buffer + 20), *(uint*)(buffer + 24));
            }
            if (OperatingSystem.IsMacOS())
            {
                var result = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                    ? stat_arm64(path, buffer)
                    : stat_inode64(path, buffer);
                if (result != 0)
                    return null;
                return (*(uint*)(buffer + 16), *(uint*)(buffer + 20));
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // An old libc without statx: leave ownership as it is.
        }
        return null;
    }

    public void Chown(string path, uint uid, uint gid)
    {
        if (chown(path, uid, gid) != 0)
            throw new TswapException(
                $"Wrote {path}, but could not give it to uid {uid} (errno {Marshal.GetLastPInvokeError()}). " +
                $"Fix its owner with: sudo chown {uid}:{gid} '{path}'");
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial uint geteuid();

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int chown(string path, uint owner, uint group);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "stat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int stat_arm64(string path, byte* buffer);

    [LibraryImport("libc", EntryPoint = "stat$INODE64", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int stat_inode64(string path, byte* buffer);
}

/// <summary>
/// Config backups: <c>config.json.bak-&lt;UTC timestamp&gt;</c>, or the next free <c>-1</c>,
/// <c>-2</c>, ... suffix when two backups fall in one millisecond. Never overwrites a backup.
/// </summary>
public static class FileBackup
{
    public static string Copy(string file, DateTime utcNow) => Next(file, utcNow, backup => File.Copy(file, backup, overwrite: false));

    /// <summary>Moves <paramref name="file"/> aside under a backup name (keeps its owner and mode).</summary>
    public static string Move(string file, DateTime utcNow) => Next(file, utcNow, backup => File.Move(file, backup, overwrite: false));

    private static string Next(string file, DateTime utcNow, Action<string> create)
    {
        var stem = file + ".bak-" + utcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        for (var n = 0; ; n++)
        {
            var backup = n == 0 ? stem : $"{stem}-{n}";
            if (File.Exists(backup))
                continue;
            try
            {
                create(backup);
                return backup;
            }
            catch (IOException) when (File.Exists(backup))
            {
                // Created in between: take the next name.
            }
        }
    }
}
