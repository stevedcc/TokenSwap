using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using TswapCore;

/// <summary>
/// Shared POSIX PTY implementation for Linux and macOS. Spawns the child process inside a
/// pseudo-terminal so programs see a real TTY (enabling colour output, progress bars,
/// and interactive prompts), while tswap intercepts the master side to apply redaction.
///
/// Safety: all strings are marshaled to native memory BEFORE forkpty() so the child
/// never runs any managed code — it only calls execvp_native() and _exit(), both
/// async-signal-safe with pre-allocated IntPtr arguments.
///
/// Subclasses override <see cref="Forkpty"/> to supply the platform-specific DllImport
/// (libc on Linux, libutil on macOS).
/// </summary>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal abstract class UnixPty : IPtyRunner
{
    [StructLayout(LayoutKind.Sequential)]
    protected struct Winsize
    {
        public ushort ws_row, ws_col, ws_xpixel, ws_ypixel;
    }

    // execvp using raw IntPtr params so the child never touches managed memory.
    // path: native char* (full path bypasses PATH lookup).
    // argv: native char** — pointer to a null-terminated array of char* pointers.
    [DllImport("libc", EntryPoint = "execvp")]
    private static extern int execvp_native(IntPtr path, IntPtr argv);

    // Async-signal-safe process exit (does not flush stdio buffers).
    [DllImport("libc", EntryPoint = "_exit")]
    private static extern void _exit(int status);

    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern nint read(int fd, [Out] byte[] buf, nint count);

    [DllImport("libc", EntryPoint = "write")]
    private static extern nint write(int fd, [In] byte[] buf, nint count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int close(int fd);

    [DllImport("libc", EntryPoint = "waitpid", SetLastError = true)]
    private static extern int waitpid(int pid, ref int status, int options);

    private const int EINTR = 4; // POSIX: interrupted system call

    /// <summary>
    /// Platform-specific forkpty call. Linux imports from libc; macOS from libutil.
    /// forkpty = openpty + fork + login_tty (setsid + TIOCSCTTY + dup2 slave to stdio).
    /// Returns child pid in the parent, 0 in the child, or -1 on error.
    /// </summary>
    protected abstract int Forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp);

    /// <summary>
    /// Runs <paramref name="command"/> via /bin/bash -c inside a PTY, writing redacted
    /// output to stdout. Returns the child process's exit code.
    /// </summary>
    public int Run(string command, IReadOnlyList<KeyValuePair<string, string>> sortedSecrets)
    {
        int consoleRows, consoleCols;
        try { consoleRows = Console.WindowHeight; consoleCols = Console.WindowWidth; }
        catch { consoleRows = 0; consoleCols = 0; }
        var winsize = new Winsize
        {
            ws_row = (ushort)(consoleRows > 0 ? consoleRows : 24),
            ws_col = (ushort)(consoleCols > 0 ? consoleCols : 80),
        };

        // Marshal all strings to native memory BEFORE fork so the child never needs
        // to allocate from the managed heap (which may have GC locks from other threads).
        var nativeBash = Marshal.StringToHGlobalAnsi("/bin/bash");
        var nativeName = Marshal.StringToHGlobalAnsi("bash");
        var nativeDashC = Marshal.StringToHGlobalAnsi("-c");
        var nativeCmd   = Marshal.StringToHGlobalAnsi(command);

        // Build argv in native memory: char*[] = { "bash", "-c", cmd, NULL }
        int ptrSize = IntPtr.Size;
        var nativeArgv = Marshal.AllocHGlobal(ptrSize * 4);
        Marshal.WriteIntPtr(nativeArgv, 0 * ptrSize, nativeName);
        Marshal.WriteIntPtr(nativeArgv, 1 * ptrSize, nativeDashC);
        Marshal.WriteIntPtr(nativeArgv, 2 * ptrSize, nativeCmd);
        Marshal.WriteIntPtr(nativeArgv, 3 * ptrSize, IntPtr.Zero);

        int pid = Forkpty(out int masterFd, IntPtr.Zero, IntPtr.Zero, ref winsize);

        if (pid == 0)
        {
            // Child — only async-signal-safe native calls; no managed allocation.
            // execvp replaces the process image; _exit is the async-signal-safe exit.
            execvp_native(nativeBash, nativeArgv);
            _exit(127);
            return 0; // unreachable
        }

        // Parent: free native strings (child has its own copy via CoW, replaced by exec).
        Marshal.FreeHGlobal(nativeBash);
        Marshal.FreeHGlobal(nativeName);
        Marshal.FreeHGlobal(nativeDashC);
        Marshal.FreeHGlobal(nativeCmd);
        Marshal.FreeHGlobal(nativeArgv);

        if (pid < 0)
            throw new Exception("forkpty failed");

        // Forward stdin → PTY master so interactive programs work (ssh, kubectl exec, etc.)
        var stdinThread = new Thread(() =>
        {
            try
            {
                var buf = new byte[256];
                var stdin = Console.OpenStandardInput();
                int n;
                while ((n = stdin.Read(buf, 0, buf.Length)) > 0)
                {
                    // write(2) can return a short count (partial write). Loop until all bytes
                    // are written, only treating 0/negative as PTY-closed or fatal error.
                    var writeOffset = 0;
                    while (writeOffset < n)
                    {
                        nint written;
                        if (writeOffset == 0)
                        {
                            written = write(masterFd, buf, n);
                        }
                        else
                        {
                            // Partial write occurred — copy the remainder into a temporary
                            // slice (write(2) has no offset parameter).
                            var remaining = n - writeOffset;
                            var slice = new byte[remaining];
                            Buffer.BlockCopy(buf, writeOffset, slice, 0, remaining);
                            written = write(masterFd, slice, remaining);
                        }
                        if (written <= 0) return; // PTY closed or fatal error
                        writeOffset += (int)written;
                    }
                }
            }
            catch { /* stdin closed or PTY gone */ }
        }) { IsBackground = true };
        stdinThread.Start();

        // Read PTY output (stdout+stderr merged), redact secrets, write to our stdout.
        // StreamRedactor maintains a sliding-window overlap between chunks so secrets that
        // straddle a read-buffer boundary are still caught. See TswapCore.StreamRedactor.
        var readBuf  = new byte[4096];
        var encoding = Console.OutputEncoding;
        var decoder  = encoding.GetDecoder();
        var charBuf  = new char[encoding.GetMaxCharCount(readBuf.Length)];
        var stdout   = Console.OpenStandardOutput();
        var redactor = new StreamRedactor(sortedSecrets);
        while (true)
        {
            int n = (int)read(masterFd, readBuf, (nint)readBuf.Length);
            if (n == 0) break; // EOF
            if (n < 0)
            {
                if (Marshal.GetLastPInvokeError() == EINTR) continue; // signal interrupted, retry
                break; // EIO or other error (slave side closed after child exit)
            }
            var charCount = decoder.GetChars(readBuf, 0, n, charBuf, 0);
            var redacted  = redactor.ProcessChunk(new string(charBuf, 0, charCount));
            var outBytes  = encoding.GetBytes(redacted);
            stdout.Write(outBytes, 0, outBytes.Length);
            // Flush after every chunk so output appears immediately in the terminal.
            // PTY is used for interactive commands (kubectl, helm, ssh) where real-time
            // streaming matters more than raw throughput.
            stdout.Flush();
        }
        var tail = redactor.Flush();
        if (tail.Length > 0)
        {
            stdout.Write(encoding.GetBytes(tail));
            stdout.Flush();
        }

        close(masterFd);

        // Loop waitpid on EINTR so a signal delivery during the wait doesn't
        // leave status uninitialised and produce a garbage exit code.
        int status = 0;
        int wret;
        do { wret = waitpid(pid, ref status, 0); }
        while (wret < 0 && Marshal.GetLastPInvokeError() == EINTR);

        // Decode waitpid status: WIFEXITED vs WIFSIGNALED
        return (status & 0x7f) == 0
            ? (status >> 8) & 0xff   // WEXITSTATUS
            : 128 + (status & 0x7f); // 128 + signal number (shell convention)
    }
}
