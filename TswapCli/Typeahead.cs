using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TswapCli;

/// <summary>
/// #293: throws away what was typed at the terminal and not yet read, as <c>ssh</c>'s <c>readpassphrase</c> and
/// <c>sudo</c> do before a prompt, so a stray touch on a YubiKey's OTP slot (a one-time code with no Enter) can't become
/// the next answer or a wrong PIN. Only the kernel's (or the console's) input queue: what .NET has already pulled into
/// its own reader is not reached. A failed discard is ignored: it is a convenience, not a check.
/// </summary>
internal static partial class Typeahead
{
    private const int StdInputHandle = -10;

    /// <summary>Discards stdin's typeahead (Linux and macOS: <c>tcflush</c>; Windows: <c>FlushConsoleInputBuffer</c>).</summary>
    public static void DiscardStdin()
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            _ = DiscardUnix(0);
        else if (OperatingSystem.IsWindows())
            _ = DiscardWindowsConsole();
    }

    /// <summary><c>tcflush(fd, TCIFLUSH)</c>; libc's result (0, or -1 when <paramref name="fd"/> is not a terminal).</summary>
    [UnsupportedOSPlatform("windows")]
    internal static int DiscardUnix(int fd) => tcflush(fd, TcIflush);

    // <termios.h>: Linux TCIFLUSH 0, TCOFLUSH 1; BSD and macOS TCIFLUSH 1, TCOFLUSH 2.
    private static int TcIflush => OperatingSystem.IsMacOS() ? 1 : 0;

    /// <summary><c>FlushConsoleInputBuffer</c> on stdin's handle; false when stdin is not a console.</summary>
    [SupportedOSPlatform("windows")]
    internal static bool DiscardWindowsConsole() => FlushConsoleInputBuffer(GetStdHandle(StdInputHandle));

    [LibraryImport("libc", SetLastError = true)]
    private static partial int tcflush(int fd, int queueSelector);

    [LibraryImport("kernel32", SetLastError = true)]
    private static partial nint GetStdHandle(int which);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlushConsoleInputBuffer(nint handle);
}
