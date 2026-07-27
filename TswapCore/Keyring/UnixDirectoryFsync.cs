using System.Runtime.InteropServices;

namespace TswapCore.Keyring;

/// <summary>
/// Best-effort <c>fsync</c> on a directory's own file descriptor (Unix only) — the optional
/// sub-item of issue #137's work item 1. <see cref="FileStream.Flush(bool)"/> flushes a file's
/// contents to durable storage but not the directory entry a rename creates; on Unix the fix is
/// <c>fsync</c> on the directory itself, which .NET has no managed API for.
///
/// <para><b>Windows has no directory-fsync concept</b> (there is no POSIX-style directory file
/// descriptor to open/fsync); on Windows <see cref="TryFsync"/> is a deliberate no-op and this
/// codebase relies on the server/filesystem instead, matching the parent issue's guidance.</para>
///
/// <para>Uses <see cref="LibraryImport"/>, not <c>DllImport</c> — source-generated marshalling,
/// AOT/trim-safe by construction, matching the interop style this codebase already uses for
/// P/Invoke bridges (see <c>TswapCore/Vault/Interop/</c>).</para>
///
/// <para><b>Best-effort by design, not a correctness dependency:</b> <see cref="TryFsync"/>
/// never throws. If the directory can't be opened (permissions, an exotic filesystem, a
/// misbehaving container overlay) this silently degrades to "the file's own contents are
/// durable, the directory entry for the rename might not be yet" — exactly the guarantee this
/// codebase already had before this class existed. That degraded case is not covered by any
/// automated test (see <see cref="DurableFileWriter"/>'s doc comment on what is/isn't verified);
/// only the happy path — open/fsync/close succeed — is exercised by
/// <c>TswapTests/DurableFileWriterTests.cs</c>, indirectly, via a successful write.</para>
/// </summary>
internal static partial class UnixDirectoryFsync
{
    private const int ORdOnly = 0x0000;

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int open(string pathname, int flags);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int fsync(int fd);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fd);

    /// <summary>
    /// Opens <paramref name="directoryPath"/> read-only and fsyncs it. Never throws: any
    /// failure (unsupported platform, permission denied, fd exhaustion) is swallowed and this
    /// simply does nothing, per this class's doc comment.
    /// </summary>
    public static void TryFsync(string directoryPath)
    {
        if (OperatingSystem.IsWindows())
            return;

        int fd;
        try
        {
            fd = open(directoryPath, ORdOnly);
        }
        catch
        {
            // e.g. libc not resolvable on this platform at all -- treat exactly like a failed
            // open() below.
            return;
        }

        if (fd < 0)
            return;

        try
        {
            fsync(fd);
        }
        finally
        {
            close(fd);
        }
    }
}
