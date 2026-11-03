using System.Runtime.InteropServices;

namespace TswapCore.Agent;

/// <summary>
/// Brief T17 ruling 10: once <c>agent serve</c> has printed its <c>ready</c> line, it lets go of the terminal
/// session that started it. On Unix its stdin, stdout and stderr are reopened on <c>/dev/null</c>, so a later
/// write can't hit <c>EPIPE</c> on the dead parent's pipes and the parent's reader sees end of file; then
/// <c>setsid()</c> makes it a session leader of its own, so a later Ctrl+C or hangup in that terminal no
/// longer reaches it. On Windows only .NET's console readers and writers are pointed at nothing (no write
/// reaches the parent's pipes after this); the std handles are not reopened on <c>NUL</c> or closed,
/// because <c>agent serve</c>'s own stdin stream still owns its handle, and closing it underneath that
/// stream would let a reused handle number be closed later. The parent's pipe ends close when it exits.
/// </summary>
public static partial class ProcessDetach
{
    /// <summary>Detaches this process. Returns the steps that failed (empty when all worked); never throws.</summary>
    public static IReadOnlyList<string> Detach()
    {
        List<string> failed = [];
        // Later writes go nowhere. (The getters are not touched: on Unix, .NET's console streams are dup()s of
        // fds 0 to 2 made at first use, which a reopen of the fds doesn't reach. agent serve writes its ready
        // line on fd 1 itself, so no such copy holds the parent's stdout pipe open.)
        Console.SetIn(TextReader.Null);
        Console.SetOut(TextWriter.Null);
        Console.SetError(TextWriter.Null);
        if (OperatingSystem.IsWindows())
            return failed;

        try
        {
            using var devNull = File.OpenHandle("/dev/null", FileMode.Open, FileAccess.ReadWrite);
            var fd = (int)devNull.DangerousGetHandle();
            for (var target = 0; target <= 2; target++)
                if (dup2(fd, target) < 0)
                    failed.Add($"dup2 onto fd {target} (errno {Marshal.GetLastPInvokeError()})");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            failed.Add($"open /dev/null ({ex.Message})");
        }
        if (setsid() < 0)
            failed.Add($"setsid (errno {Marshal.GetLastPInvokeError()})");
        return failed;
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int dup2(int oldFd, int newFd);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setsid();
}
