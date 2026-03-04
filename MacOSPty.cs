using System.Runtime.InteropServices;
using System.Runtime.Versioning;

/// <summary>
/// macOS PTY: forkpty is declared in &lt;util.h&gt; and lives in libutil.dylib.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class MacOSPty : UnixPty
{
    [DllImport("libutil", EntryPoint = "forkpty")]
    private static extern int forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp);

    protected override int Forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp)
        => forkpty(out amaster, name, termp, ref winp);
}
