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
/// never invokes the CLR marshaler. The child calls execvp_native() (async-signal-safe)
/// and on failure writes a diagnostic via write_ptr() using a pre-pinned IntPtr buffer,
/// then calls _exit() — no managed allocation or CLR re-entry on either path.
///
/// Subclasses override <see cref="Forkpty"/> to supply the platform-specific DllImport
/// (libc on Linux, libutil on macOS).
/// </summary>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal abstract class UnixPty : IPtyRunner
{
    // Message written to stderr when execvp fails in the child after fork().
    // The byte[] is pinned for the process lifetime so the GC never moves it; the child
    // writes via the IntPtr overload of write() to avoid invoking the P/Invoke marshaler
    // (which re-enters the CLR and is not async-signal-safe / fork-safe).
    private static readonly byte[]   ExecFailedMsg    = "tswap: exec failed (command not found or not executable)\n"u8.ToArray();
    private static readonly GCHandle ExecFailedMsgPin = GCHandle.Alloc(ExecFailedMsg, GCHandleType.Pinned);

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

    [DllImport("libc", EntryPoint = "write", SetLastError = true)]
    private static extern nint write(int fd, [In] byte[] buf, nint count);

    // IntPtr overload used in the child after fork() — avoids the P/Invoke marshaler
    // touching managed memory, which is not async-signal-safe.
    [DllImport("libc", EntryPoint = "write")]
    private static extern nint write_ptr(int fd, IntPtr buf, nint count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int close(int fd);

    [DllImport("libc", EntryPoint = "waitpid", SetLastError = true)]
    private static extern int waitpid(int pid, ref int status, int options);

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd { public int fd; public short events; public short revents; }

    [DllImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static extern int poll(ref PollFd fds, uint nfds, int timeout);

    private const short POLLIN   = 1;   // POSIX: fd has data to read (Linux and macOS)
    private const short POLLOUT  = 4;   // POSIX: fd is ready for writing
    private const short POLLERR  = 8;   // POSIX: error condition on fd
    private const short POLLNVAL = 32;  // POSIX: invalid fd

    private const int EINTR  = 4;  // POSIX: interrupted system call
    // EAGAIN differs by OS: Linux=11, macOS=35 (same value as EWOULDBLOCK on macOS).
    private static readonly int EAGAIN = OperatingSystem.IsLinux() ? 11 : 35;

    /// <summary>
    /// Platform-specific forkpty call. Linux imports from libc; macOS from libutil.
    /// forkpty = openpty + fork + login_tty (setsid + TIOCSCTTY + dup2 slave to stdio).
    /// Returns child pid in the parent, 0 in the child, or -1 on error.
    /// </summary>
    protected abstract int Forkpty(out int amaster, IntPtr name, IntPtr termp, ref Winsize winp);

    /// <summary>
    /// Directly executes <paramref name="argv"/>[0] with the remaining elements as its
    /// argument list inside a PTY (no shell wrapper), writing redacted output to stdout.
    /// Returns the child process's exit code.
    /// </summary>
    public int Run(string[] argv, IReadOnlyList<KeyValuePair<string, string>> sortedSecrets)
    {
        if (argv is not { Length: > 0 } || string.IsNullOrEmpty(argv[0]))
            throw new ArgumentException("argv must be non-empty and argv[0] must be a non-empty executable name.", nameof(argv));

        int consoleRows, consoleCols;
        try { consoleRows = Console.WindowHeight; consoleCols = Console.WindowWidth; }
        catch { consoleRows = 0; consoleCols = 0; }
        var winsize = new Winsize
        {
            ws_row = (ushort)(consoleRows > 0 ? consoleRows : 24),
            ws_col = (ushort)(consoleCols > 0 ? consoleCols : 80),
        };

        // Marshal all argv strings to native memory BEFORE fork so the child never needs
        // to allocate from the managed heap (which may have GC locks from other threads).
        var nativeStrings = new IntPtr[argv.Length];
        for (int i = 0; i < argv.Length; i++)
            nativeStrings[i] = Marshal.StringToHGlobalAnsi(argv[i]);

        // Build null-terminated argv array in native memory: char*[] = { argv[0], ..., NULL }
        int ptrSize = IntPtr.Size;
        var nativeArgv = Marshal.AllocHGlobal(ptrSize * (argv.Length + 1));
        for (int i = 0; i < argv.Length; i++)
            Marshal.WriteIntPtr(nativeArgv, i * ptrSize, nativeStrings[i]);
        Marshal.WriteIntPtr(nativeArgv, argv.Length * ptrSize, IntPtr.Zero);

        // Copy the executable pointer to a stack-local so the child can read it without
        // touching the managed nativeStrings array after fork.
        var nativeExe = nativeStrings[0];

        // Allocate read-loop infrastructure BEFORE fork so the parent thread can
        // enter read(masterFd) with minimum latency after Forkpty() returns.
        // The child begins executing the moment Forkpty() returns in the parent;
        // any managed allocation or thread creation that happens between fork and
        // the first read() call is a window during which the child's early output
        // sits in the PTY kernel buffer. Preparing everything here collapses that
        // window to just the unavoidable work: freeing pre-allocated native strings
        // and scheduling the read Task.
        var readBuf  = new byte[4096];
        var encoding = Console.OutputEncoding;
        var decoder  = encoding.GetDecoder();
        var charBuf  = new char[encoding.GetMaxCharCount(readBuf.Length)];
        var stdout   = Console.OpenStandardOutput();
        var redactor = new StreamRedactor(sortedSecrets);

        int pid = Forkpty(out int masterFd, IntPtr.Zero, IntPtr.Zero, ref winsize);

        if (pid == 0)
        {
            // Child — only async-signal-safe native calls; no managed allocation.
            // execvp replaces the process image; _exit is the async-signal-safe exit.
            execvp_native(nativeExe, nativeArgv);
            // execvp only returns on failure (command not found / not executable).
            // Write a diagnostic to stderr via the IntPtr overload — avoids the P/Invoke
            // marshaler (not fork-safe); uses the pre-pinned unmanaged address directly.
            write_ptr(2, ExecFailedMsgPin.AddrOfPinnedObject(), (nint)ExecFailedMsg.Length);
            _exit(127);
            return 0; // unreachable
        }

        // Parent: free native strings (child has its own copy via CoW, replaced by exec).
        for (int i = 0; i < nativeStrings.Length; i++)
            Marshal.FreeHGlobal(nativeStrings[i]);
        Marshal.FreeHGlobal(nativeArgv);

        if (pid < 0)
            throw new Exception("forkpty failed");

        // cancelDrain is set by the main thread to ask the read loop to stop polling and exit.
        // Volatile.Read/Write provides acquire/release semantics sufficient for a single-writer
        // cancellation flag. The loop's 200 ms poll timeout bounds how long before the flag
        // is observed, avoiding any cross-thread fd-close (which is UB on POSIX).
        var cancelDrain = false;

        // Schedule the read loop on the thread pool immediately — before the stdin
        // thread and before waitpid — so it races to call read(masterFd) while the
        // child is still in its earliest execution. All read-loop state was allocated
        // above (pre-fork) so the Task body needs no additional setup.
        //
        // Read PTY output (stdout+stderr merged), redact secrets, write to our stdout.
        // StreamRedactor maintains a sliding-window overlap between chunks so secrets
        // that straddle a read-buffer boundary are still caught.
        var readTask = Task.Run(() =>
        {
            while (!Volatile.Read(ref cancelDrain))
            {
                // Poll with a 200 ms timeout so we re-check cancelDrain regularly even
                // when the child is idle. This avoids blocking indefinitely in read().
                var pfd = new PollFd { fd = masterFd, events = POLLIN };
                int pr = poll(ref pfd, 1, 200);
                if (pr == 0) continue;           // timeout — loop back and check cancelDrain
                if (pr < 0)
                {
                    if (Marshal.GetLastPInvokeError() == EINTR) continue;
                    break;
                }
                // Only call read() when the fd actually has data. POLLERR/POLLNVAL signal
                // a broken or invalid fd; POLLHUP without POLLIN means the slave was closed
                // with no buffered data. Break in all cases rather than risk a blocking read().
                if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) break;
                if ((pfd.revents & POLLIN) == 0) break;
                int n = (int)read(masterFd, readBuf, (nint)readBuf.Length);
                if (n == 0) break; // EOF
                if (n < 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    if (errno == EINTR || errno == EAGAIN) continue; // retry
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
            // If cancelled (30s drain timeout), suppress the redactor tail: the sliding-window
            // buffer may contain a partial, unredacted secret fragment from a truncated stream.
            // Emitting it risks leaking secret material, so we discard it and signal truncation.
            if (Volatile.Read(ref cancelDrain))
            {
                var marker = encoding.GetBytes("[output truncated]" + Environment.NewLine);
                stdout.Write(marker, 0, marker.Length);
                stdout.Flush();
            }
            else
            {
                var tail = redactor.Flush();
                if (tail.Length > 0)
                {
                    stdout.Write(encoding.GetBytes(tail));
                    stdout.Flush();
                }
            }
        });

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
                        if (written < 0)
                        {
                            var err = Marshal.GetLastPInvokeError();
                            if (err == EINTR) continue; // signal interrupted, retry immediately
                            if (err == EAGAIN)
                            {
                                // PTY master write buffer full — wait for writability (POLLOUT)
                                // with a 200 ms timeout to avoid a hot spin under back-pressure.
                                var wpfd = new PollFd { fd = masterFd, events = POLLOUT };
                                while (true)
                                {
                                    int pr = poll(ref wpfd, 1, 200);
                                    if (pr < 0)
                                    {
                                        if (Marshal.GetLastPInvokeError() == EINTR) continue; // interrupted, re-poll
                                        return; // poll error — treat as fatal
                                    }
                                    if (pr == 0 || (wpfd.revents & POLLOUT) == 0) return; // timeout or error event
                                    break; // fd writable — retry write
                                }
                                continue;
                            }
                            return; // PTY closed or fatal error
                        }
                        if (written == 0) return; // PTY closed
                        writeOffset += (int)written;
                    }
                }
            }
            catch { /* stdin closed or PTY gone */ }
        }) { IsBackground = true };
        stdinThread.Start();

        // Loop waitpid on EINTR so a signal delivery during the wait doesn't
        // leave status uninitialised and produce a garbage exit code.
        int status = 0;
        int wret;
        do { wret = waitpid(pid, ref status, 0); }
        while (wret < 0 && Marshal.GetLastPInvokeError() == EINTR);

        if (wret < 0)
        {
            // Capture errno before any further native call can overwrite it.
            var errno = Marshal.GetLastPInvokeError();
            Volatile.Write(ref cancelDrain, true);
            // readTask.Wait() can throw (e.g. stdout write failure); swallow it here
            // because the waitpid failure is the primary error, and always close the fd.
            try { readTask.Wait(); } catch { /* secondary to waitpid failure */ }
            finally { close(masterFd); }
            throw new Exception($"waitpid failed (errno {errno})");
        }

        // Child has exited, but its descendants may still hold inherited slave PTY fds open,
        // keeping the slave alive. Give the read task up to 30 s to drain any remaining
        // kernel-buffered output naturally (via EIO once all slave fds close), then signal
        // cancellation so it exits within one poll timeout (≤ 200 ms) without a cross-thread
        // fd close, which is undefined behaviour on POSIX.
        // 30 s provides headroom for slow stdout consumers and large kernel buffers; any finite
        // timeout may truncate output from zombie descendants that stay alive indefinitely.
        // try/finally ensures close(masterFd) runs even if readTask.Wait() throws.
        if (!readTask.Wait(TimeSpan.FromSeconds(30)))
            Volatile.Write(ref cancelDrain, true);
        try { readTask.Wait(); } // if cancelled, exits within ≤ 200 ms; else already done
        finally { close(masterFd); }

        // Decode waitpid status: WIFEXITED vs WIFSIGNALED
        return (status & 0x7f) == 0
            ? (status >> 8) & 0xff   // WEXITSTATUS
            : 128 + (status & 0x7f); // 128 + signal number (shell convention)
    }
}
