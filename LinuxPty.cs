using System.Runtime.InteropServices;
using System.Runtime.Versioning;

/// <summary>
/// Linux PTY: forkpty was moved from libutil.so into libc.so.6 on glibc 2.34+.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxPty : UnixPty
{
    [DllImport("libc", EntryPoint = "forkpty")]
    private static extern int forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp);

    protected override int Forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp)
        => forkpty(out amaster, name, termp, ref winp);
}
