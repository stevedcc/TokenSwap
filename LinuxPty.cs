using System.Runtime.InteropServices;
using System.Runtime.Versioning;

/// <summary>
/// Linux PTY: forkpty was merged from libutil.so into libc.so.6 on glibc 2.34
/// (Fedora 35+, Ubuntu 22.04+). Older distributions still ship it in libutil.so.1.
/// We probe at startup to avoid an EntryPointNotFoundException at runtime.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxPty : UnixPty
{
    private static readonly bool _forkptyInLibc = CheckForkptyInLibc();

    private static bool CheckForkptyInLibc()
    {
        if (!NativeLibrary.TryLoad("libc", typeof(LinuxPty).Assembly, null, out var h))
            return false;
        var found = NativeLibrary.TryGetExport(h, "forkpty", out _);
        NativeLibrary.Free(h);
        return found;
    }

    [DllImport("libc",    EntryPoint = "forkpty")]
    private static extern int forkpty_libc(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp);

    [DllImport("libutil", EntryPoint = "forkpty")]
    private static extern int forkpty_libutil(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp);

    protected override int Forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp)
        => _forkptyInLibc
            ? forkpty_libc(out amaster, name, termp, ref winp)
            : forkpty_libutil(out amaster, name, termp, ref winp);
}
