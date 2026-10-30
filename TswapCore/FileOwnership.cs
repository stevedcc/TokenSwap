using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

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

    /// <summary>
    /// Sets the owner and group of the open <paramref name="file"/> (<c>fchown</c>: never by
    /// name, so no symlink is followed); <paramref name="path"/> is for the message. Throws on failure.
    /// </summary>
    void Chown(SafeFileHandle file, string path, uint uid, uint gid);
}

/// <summary>
/// Every file tswap writes (config, secrets, backups, receipts, approve and export files) goes
/// through here. Files are created mode 0600 (whatever the umask), with <c>O_EXCL</c>, so an
/// existing name or symlink is never written through.
/// <para>
/// T5 (found in the real-hardware test): a file written while privileged (sudo) into a folder
/// owned by another user (the vault's user, via <c>SUDO_USER</c> or <c>TSWAP_CONFIG_DIR</c>) would
/// be <c>root:root</c>, and the vault's user then can't read their own config. So, privileged on
/// Unix and the folder owned by another uid ⇒ the file gets the folder's owner and group. That
/// happens on the open file, before it gets its final name (MiMo review: a chown by name would
/// follow a symlink the folder's owner planted there, e.g. to <c>/etc/shadow</c>). Windows,
/// unprivileged runs and a folder this uid owns: no owner change.
/// </para>
/// </summary>
public sealed class DirectoryOwnerMatcher(IUnixOwnership? ownership = null)
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly IUnixOwnership _ownership = ownership ?? new UnixOwnership();

    /// <summary>The matcher every real <see cref="Storage"/> uses.</summary>
    public static DirectoryOwnerMatcher Default { get; } = new();

    /// <summary>
    /// Replaces <paramref name="path"/> atomically: a new temp file in the same folder, then a
    /// rename over the name (which replaces a symlink there instead of writing through it). An
    /// existing regular file keeps its mode unless the owner changes (then 0600).
    /// </summary>
    public void WriteAtomic(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        var owner = OwnerFor(fullPath);
        var tmp = $"{fullPath}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(6))}.tmp";
        try
        {
            using (var stream = CreateNew(tmp))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
                if (owner is { } o)
                    _ownership.Chown(stream.SafeFileHandle, fullPath, o.Uid, o.Gid);
            }
            var existing = new FileInfo(fullPath);
            if (OperatingSystem.IsWindows() && existing.Exists)
            {
                // File.Replace keeps the destination's ACLs and attributes on Windows.
                File.Replace(tmp, fullPath, destinationBackupFileName: null);
                return;
            }
            // Keep a mode the user chose for this file (e.g. a tightened one); never copied from
            // a symlink's target.
            if (!OperatingSystem.IsWindows() && owner == null && existing.Exists && existing.LinkTarget == null)
                File.SetUnixFileMode(tmp, existing.UnixFileMode);
            File.Move(tmp, fullPath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
            throw;
        }
    }

    /// <summary>Creates <paramref name="path"/>, which must not exist (<see cref="IOException"/> if it does).</summary>
    public void WriteNew(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        var owner = OwnerFor(fullPath);
        var created = false;
        try
        {
            using var stream = CreateNew(fullPath);
            created = true;
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
            if (owner is { } o)
                _ownership.Chown(stream.SafeFileHandle, fullPath, o.Uid, o.Gid);
        }
        catch when (created)
        {
            try { File.Delete(fullPath); } catch { /* best-effort cleanup */ }
            throw;
        }
    }

    /// <summary>
    /// The owner a file written to <paramref name="fullPath"/> must get, or null for no change.
    /// Privileged and the folder's owner unreadable: refuses, before anything is written (MiMo
    /// review: falling back silently would leave a root-owned file the vault's user can't read).
    /// </summary>
    private (uint Uid, uint Gid)? OwnerFor(string fullPath)
    {
        if (OperatingSystem.IsWindows() || !_ownership.IsPrivileged)
            return null;
        var directory = Path.GetDirectoryName(fullPath);
        if (directory == null)
            return null;
        if (_ownership.GetOwner(directory) is not { } owner)
            throw new TswapException(
                $"Running as root, but could not read the owner of {directory}; refusing to write " +
                $"{Path.GetFileName(fullPath)} there as root (its user could not read it afterwards).");
        return owner.Uid == _ownership.EffectiveUid ? null : owner;
    }

    private static FileStream CreateNew(string path)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = OwnerOnly;
        return new FileStream(path, options);
    }
}

/// <summary>
/// The real <see cref="IUnixOwnership"/>: <c>geteuid</c>, <c>fchown</c>, and the owner from
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
            // An old libc without statx: unknown (DirectoryOwnerMatcher then refuses to write as root).
        }
        return null;
    }

    public void Chown(SafeFileHandle file, string path, uint uid, uint gid)
    {
        if (fchown(file, uid, gid) != 0)
            throw new TswapException(
                $"Wrote {path}, but could not give it to uid {uid} (errno {Marshal.GetLastPInvokeError()}). " +
                $"Fix its owner with: sudo chown {uid}:{gid} '{path}'");
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial uint geteuid();

    [LibraryImport("libc", SetLastError = true)]
    private static partial int fchown(SafeFileHandle fd, uint owner, uint group);

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
    /// <summary>
    /// Copies <paramref name="file"/> to a new backup name, written by <paramref name="owner"/>
    /// (null: <see cref="DirectoryOwnerMatcher.Default"/>): mode 0600, never through a symlink.
    /// </summary>
    public static string Copy(string file, DateTime utcNow, DirectoryOwnerMatcher? owner = null)
    {
        var bytes = File.ReadAllBytes(file);
        return Next(file, utcNow, backup => (owner ?? DirectoryOwnerMatcher.Default).WriteNew(backup, bytes));
    }

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
