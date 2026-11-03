using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TswapCore.Vault.Interop;

/// <summary>
/// An anonymous in-memory file (<c>memfd_create</c>) that a child process inherits, for handing
/// <c>tpm2_create</c> the sealed object's auth value (brief T17 task 8).
///
/// <para><b>Why not a FIFO</b> (the brief's first plan; the controller's ruling replaced it). tpm2-tools 5.7
/// seeks every <c>file:</c> path except <c>file:-</c>; a FIFO fails with "Error getting current file offset …
/// Illegal seek" (checked on swtpm), for <c>-p</c> and for <c>-i</c> alike. stdin already carries the sealed
/// data. A memfd reopened through <c>/proc/self/fd/&lt;n&gt;</c> is seekable, has no name in any file system,
/// and never reaches a disk.</para>
///
/// <para><b>Inheritance.</b> It is created without <c>MFD_CLOEXEC</c>, so every child started while it is open
/// inherits it. tswap opens it only around the one <c>Process.Start</c> of <c>tpm2_create</c> (enrolment is a
/// single-threaded CLI step) and closes its own copy as soon as that child has started, and in a
/// <c>finally</c> on every failure path. Any other child started in that window would inherit it too.</para>
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed partial class UnixMemfd : IDisposable
{
    private int _fd;

    private UnixMemfd(int fd) => _fd = fd;

    /// <summary>The descriptor number; the child opens <see cref="ChildPath"/>.</summary>
    public int Fd => _fd >= 0 ? _fd : throw new ObjectDisposedException(nameof(UnixMemfd));

    /// <summary>The path a child that inherited the descriptor opens it by.</summary>
    public string ChildPath => $"/proc/self/fd/{Fd}";

    /// <summary>A new memfd named <paramref name="name"/> (shown only in <c>/proc/&lt;pid&gt;/fd</c>) holding <paramref name="content"/>.</summary>
    public static UnixMemfd Create(string name, ReadOnlySpan<byte> content)
    {
        var fd = memfd_create(name, 0); // no MFD_CLOEXEC: the child must inherit it
        if (fd < 0)
            throw new TswapException(
                $"TPM operation failed while preparing the password for the TPM: memfd_create failed (errno {Marshal.GetLastPInvokeError()}).");
        var memfd = new UnixMemfd(fd);
        try
        {
            var written = 0;
            while (written < content.Length)
            {
                nint n;
                unsafe
                {
                    fixed (byte* p = content[written..])
                        n = write(fd, p, (nuint)(content.Length - written));
                }
                if (n < 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    if (errno == 4) // EINTR
                        continue;
                    throw new TswapException(
                        $"TPM operation failed while preparing the password for the TPM: write failed (errno {errno}).");
                }
                written += (int)n;
            }
            return memfd;
        }
        catch
        {
            memfd.Dispose();
            throw;
        }
    }

    /// <summary>Closes this process's descriptor (a child keeps its own inherited copy). Idempotent.</summary>
    public void Dispose()
    {
        var fd = Interlocked.Exchange(ref _fd, -1);
        if (fd >= 0)
            _ = close(fd);
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int memfd_create(string name, uint flags);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial nint write(int fd, byte* buf, nuint count);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fd);
}
