using System.Runtime.InteropServices;
using System.Security.Cryptography;

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

    /// <summary>
    /// The owner and group of <paramref name="path"/> itself (<c>lstat</c>: a symlink's own owner,
    /// not its target's), or null when they can't be read.
    /// </summary>
    (uint Uid, uint Gid)? GetOwner(string path);

    /// <summary>
    /// Switches the effective uid and gid to <paramref name="uid"/>/<paramref name="gid"/> (with no
    /// supplementary groups) until the result is disposed; <paramref name="path"/> is for the
    /// message. Throws, having changed nothing, when the switch fails.
    /// </summary>
    IDisposable ActAs(uint uid, uint gid, string path);
}

/// <summary>
/// Every file tswap reads or writes in a vault folder or as a command's output (config, secrets,
/// backups, receipts, request, approve and export files) goes through here. Files are created
/// mode 0600 (whatever the umask) under a random temp name with <c>O_EXCL</c>, then renamed over
/// the target (which replaces a symlink there instead of writing through it). New folders are 0700.
/// <para>
/// T5: run as root (sudo) on a folder owned by another user (the vault's user, via
/// <c>SUDO_USER</c> or <c>TSWAP_CONFIG_DIR</c>), tswap does that file work <b>as the folder's
/// owner</b> (effective uid and gid, no supplementary groups; the <c>sudoedit</c> approach), and
/// keeps root only for the hardware. So files come out owned by that user, and anything the user
/// planted in their own folder (a symlink to <c>/etc/shadow</c>, a folder swapped for a link
/// halfway through) gets no further than the user's own rights. Chowning as root instead (the
/// first fix) followed such links, on the read side too (reviews by MiMo and GLM).
/// </para>
/// <para>
/// The owner is read with <c>lstat</c>, of the nearest existing folder: a user can only create
/// entries they own, so a planted link makes tswap act as that user, never as root. A folder that
/// really is root's (or this uid's) is worked on unchanged. Windows and unprivileged runs: no switch.
/// </para>
/// <para>
/// The switch is process-wide (see <see cref="UnixOwnership"/>), so calls must not overlap:
/// tswap's CLI does all of this on one thread, one operation at a time.
/// </para>
/// </summary>
public sealed class DirectoryOwnerMatcher(IUnixOwnership? ownership = null)
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode FolderOwnerOnly = OwnerOnly | UnixFileMode.UserExecute;

    private readonly IUnixOwnership _ownership = ownership ?? new UnixOwnership();

    /// <summary>The matcher every real <see cref="Storage"/> uses.</summary>
    public static DirectoryOwnerMatcher Default { get; } = new();

    /// <summary>
    /// Replaces <paramref name="path"/> atomically: a new temp file in the same folder, then a
    /// rename over the name. An existing regular file keeps a mode the user chose for it.
    /// </summary>
    public void WriteAtomic(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath);
        var tmp = $"{fullPath}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(6))}.tmp";
        try
        {
            using (var stream = CreateNew(tmp))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            var existing = new FileInfo(fullPath);
            if (OperatingSystem.IsWindows() && existing.Exists)
            {
                // File.Replace keeps the destination's ACLs and attributes on Windows (no
                // symlink-follow concern there: nothing runs as another account).
                File.Replace(tmp, fullPath, destinationBackupFileName: null);
                return;
            }
            // Keep a mode the user chose for this file (e.g. a tightened one); never copied from
            // a symlink's target.
            if (!OperatingSystem.IsWindows() && existing.Exists && existing.LinkTarget == null)
                File.SetUnixFileMode(tmp, existing.UnixFileMode);
            File.Move(tmp, fullPath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
            throw;
        }
    }

    /// <summary>
    /// Brief T6 decision 10 / issue #137 work item 1: <see cref="WriteAtomic"/> for files that may
    /// live in a synced or network folder (records, the keyring). The temp file is opened with
    /// <see cref="FileOptions.WriteThrough"/> and flushed to disk, then renamed with a plain
    /// <see cref="File.Move(string, string, bool)"/> (never <see cref="File.Replace(string, string, string?)"/>,
    /// which some SMB servers implement badly), then the folder entry is fsynced (Unix, best
    /// effort). A symlink at the path is replaced, never written through. New files are 0600; an
    /// existing regular file's mode is not carried over (the vault folder's files are 0600).
    /// </summary>
    public void WriteDurable(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath);
        var tmp = $"{fullPath}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(6))}.tmp";
        try
        {
            using (var stream = CreateNew(tmp, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(tmp, fullPath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
            throw;
        }
        Keyring.UnixDirectoryFsync.TryFsync(Path.GetDirectoryName(fullPath)!);
    }

    /// <summary>Deletes <paramref name="path"/> (as its folder's owner); a missing file is not an error.</summary>
    public void Delete(string path)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath);
        File.Delete(fullPath);
    }

    /// <summary>
    /// Renames <paramref name="source"/> to <paramref name="destination"/> in the same folder (as
    /// the folder's owner), never overwriting; works for files and folders.
    /// </summary>
    public void Move(string source, string destination)
    {
        var fullSource = Path.GetFullPath(source);
        var fullDestination = Path.GetFullPath(destination);
        using var _ = AsOwnerOf(fullDestination);
        if (Directory.Exists(fullSource) && new DirectoryInfo(fullSource).LinkTarget == null)
            Directory.Move(fullSource, fullDestination);
        else
            File.Move(fullSource, fullDestination, overwrite: false);
    }

    /// <summary>Deletes the folder <paramref name="path"/> and everything in it (as its parent's owner); never follows links.</summary>
    public void DeleteDirectory(string path)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath);
        if (new DirectoryInfo(fullPath).LinkTarget != null)
            File.Delete(fullPath); // a link to a folder: remove the link only
        else if (Directory.Exists(fullPath))
            Directory.Delete(fullPath, recursive: true);
    }

    /// <summary>
    /// Runs <paramref name="action"/> as the owner of <paramref name="path"/>'s nearest existing
    /// folder (see the type's comment): for folder listings and mode changes in a vault folder.
    /// </summary>
    public T AsOwner<T>(string path, Func<T> action)
    {
        using var _ = AsOwnerOf(Path.GetFullPath(path));
        return action();
    }

    /// <summary>Creates <paramref name="path"/>, which must not exist (<see cref="IOException"/> if it does).</summary>
    public void WriteNew(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath);
        var created = false;
        try
        {
            using var stream = CreateNew(fullPath);
            created = true;
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        catch when (created)
        {
            try { File.Delete(fullPath); } catch { /* best-effort cleanup */ }
            throw;
        }
    }

    /// <summary>
    /// Reads <paramref name="path"/> (as its folder's owner, see the type's comment). A file that
    /// owner can't read is a <see cref="TswapException"/>: for a regular file (typically left
    /// root-owned by an earlier <c>sudo tswap</c>) with the <c>chown</c> that fixes it, never for a
    /// symlink (chown would follow it to whatever it points at).
    /// </summary>
    public byte[] ReadAllBytes(string path)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath, out var owner);
        try
        {
            return File.ReadAllBytes(fullPath);
        }
        catch (UnauthorizedAccessException) when (owner is { } o)
        {
            if (new FileInfo(fullPath).LinkTarget != null)
                throw new TswapException(
                    $"{fullPath} is a symlink its folder's owner (uid {o.Uid}) can't read through; " +
                    "tswap won't read it as root. Replace it with the real file.");
            // -h: if a link is swapped in after the check above, chown changes the link, not its target.
            throw new TswapException(
                $"{fullPath} can't be read by its folder's owner (uid {o.Uid}); an earlier 'sudo tswap' " +
                "probably left it (or a folder above it) owned by root. If the file is root's, fix it with: " +
                $"sudo chown -h {o.Uid}:{o.Gid} {ShellQuote(fullPath)}");
        }
    }

    /// <summary>True when <paramref name="path"/> is an existing file (as its folder's owner).</summary>
    public bool FileExists(string path)
    {
        var fullPath = Path.GetFullPath(path);
        using var _ = AsOwnerOf(fullPath);
        return File.Exists(fullPath);
    }

    /// <summary>Creates <paramref name="path"/> and missing parents, mode 0700 on Unix.</summary>
    public void CreateDirectory(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (Directory.Exists(fullPath))
            return;
        using var _ = AsOwnerOf(fullPath);
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(fullPath);
        else
            Directory.CreateDirectory(fullPath, FolderOwnerOnly);
    }

    /// <summary>
    /// Acts as the owner of <paramref name="fullPath"/>'s nearest existing parent folder until
    /// disposed, when privileged and that owner is another uid (see the type's comment).
    /// Privileged and the owner unreadable: refuses, before anything is read or written.
    /// </summary>
    private IDisposable? AsOwnerOf(string fullPath) => AsOwnerOf(fullPath, out _);

    /// <param name="owner">The identity switched to, or null when there was no switch.</param>
    private IDisposable? AsOwnerOf(string fullPath, out (uint Uid, uint Gid)? owner)
    {
        owner = null;
        if (OperatingSystem.IsWindows() || !_ownership.IsPrivileged)
            return null;
        var directory = Path.GetDirectoryName(fullPath);
        while (directory != null && !Directory.Exists(directory) && !File.Exists(directory))
            directory = Path.GetDirectoryName(directory);
        if (directory == null)
            return null;
        if (_ownership.GetOwner(directory) is not { } folderOwner)
            throw new TswapException(
                $"Running as root, but could not read the owner of {directory}; refusing to touch " +
                $"{Path.GetFileName(fullPath)} there as root.");
        if (folderOwner.Uid == _ownership.EffectiveUid)
            return null;
        var scope = _ownership.ActAs(folderOwner.Uid, folderOwner.Gid, fullPath);
        owner = folderOwner;
        return scope;
    }

    /// <summary>Single-quotes <paramref name="value"/> for a POSIX shell.</summary>
    private static string ShellQuote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    private static FileStream CreateNew(string path, FileOptions fileOptions = FileOptions.None)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = fileOptions };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = OwnerOnly;
        return new FileStream(path, options);
    }
}

/// <summary>
/// The real <see cref="IUnixOwnership"/>: <c>geteuid</c>; the owner from <c>statx</c> with
/// <c>AT_SYMLINK_NOFOLLOW</c> on Linux (its struct layout is the same on every architecture) or
/// <c>lstat</c> on macOS (64-bit-inode layout: <c>st_uid</c> at 16, <c>st_gid</c> at 20); and
/// <c>setgroups</c>/<c>setegid</c>/<c>seteuid</c> for <see cref="ActAs"/> (process-wide on both:
/// glibc applies them to every thread). Source-generated <see cref="LibraryImportAttribute"/>
/// marshalling, so NativeAOT-safe.
/// </summary>
public sealed partial class UnixOwnership : IUnixOwnership
{
    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;
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
                if (statx(AtFdCwd, path, AtSymlinkNoFollow, StatxUid | StatxGid, buffer) != 0)
                    return null;
                return (*(uint*)(buffer + 20), *(uint*)(buffer + 24));
            }
            if (OperatingSystem.IsMacOS())
            {
                var result = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                    ? lstat_arm64(path, buffer)
                    : lstat_inode64(path, buffer);
                if (result != 0)
                    return null;
                return (*(uint*)(buffer + 16), *(uint*)(buffer + 20));
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // An old libc without statx: unknown (DirectoryOwnerMatcher then refuses as root).
        }
        return null;
    }

    public unsafe IDisposable ActAs(uint uid, uint gid, string path)
    {
        var count = getgroups(0, null);
        var groups = new uint[Math.Max(count, 0)];
        fixed (uint* list = groups)
            if (count < 0 || getgroups(groups.Length, list) != groups.Length)
                throw new TswapException($"Could not read this process's groups (errno {Marshal.GetLastPInvokeError()}); nothing was done with {path}.");
        var identity = new Identity(geteuid(), getegid(), groups);
        if (SetGroups([]) != 0 || setegid(gid) != 0 || seteuid(uid) != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            identity.Dispose();
            throw new TswapException(
                $"Could not switch to uid {uid} (the owner of the folder) for {path} (errno {errno}); nothing was done with it.");
        }
        return identity;
    }

    /// <summary>Restores the saved identity: root's uid first (needed to set the rest).</summary>
    private sealed class Identity(uint uid, uint gid, uint[] groups) : IDisposable
    {
        public void Dispose()
        {
            if (seteuid(uid) != 0 || setegid(gid) != 0 || SetGroups(groups) != 0)
                Environment.FailFast($"tswap: could not switch back to uid {uid} (errno {Marshal.GetLastPInvokeError()}).");
        }
    }

    private static unsafe int SetGroups(uint[] groups)
    {
        fixed (uint* list = groups)
            return OperatingSystem.IsMacOS() ? setgroups_mac(groups.Length, list) : setgroups_linux((nuint)groups.Length, list);
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial uint geteuid();

    [LibraryImport("libc", SetLastError = true)]
    private static partial uint getegid();

    [LibraryImport("libc", SetLastError = true)]
    private static partial int seteuid(uint uid);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setegid(uint gid);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial int getgroups(int size, uint* list);

    [LibraryImport("libc", EntryPoint = "setgroups", SetLastError = true)]
    private static unsafe partial int setgroups_linux(nuint size, uint* list);

    [LibraryImport("libc", EntryPoint = "setgroups", SetLastError = true)]
    private static unsafe partial int setgroups_mac(int size, uint* list);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int lstat_arm64(string path, byte* buffer);

    [LibraryImport("libc", EntryPoint = "lstat$INODE64", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int lstat_inode64(string path, byte* buffer);
}

/// <summary>
/// Config backups: <c>config.json.bak-&lt;UTC timestamp&gt;</c>, or the next free <c>-1</c>,
/// <c>-2</c>, ... suffix when two backups fall in one millisecond. Never overwrites a backup.
/// </summary>
public static class FileBackup
{
    /// <summary>
    /// Copies <paramref name="file"/> to a new backup name, read and written by
    /// <paramref name="owner"/> (null: <see cref="DirectoryOwnerMatcher.Default"/>): mode 0600, as
    /// the folder's owner under sudo.
    /// </summary>
    public static string Copy(string file, DateTime utcNow, DirectoryOwnerMatcher? owner = null)
    {
        owner ??= DirectoryOwnerMatcher.Default;
        var bytes = owner.ReadAllBytes(file);
        return Next(file, utcNow, backup => owner.WriteNew(backup, bytes));
    }

    /// <summary>
    /// Moves <paramref name="file"/> aside under a backup name (keeps its owner and mode), renamed
    /// by <paramref name="owner"/> (null: <see cref="DirectoryOwnerMatcher.Default"/>): as the
    /// folder's owner under sudo.
    /// </summary>
    public static string Move(string file, DateTime utcNow, DirectoryOwnerMatcher? owner = null)
    {
        owner ??= DirectoryOwnerMatcher.Default;
        return Next(file, utcNow, backup => owner.Move(file, backup));
    }

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
