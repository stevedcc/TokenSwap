using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using TswapCore;

/// <summary>
/// Windows ConPTY support via P/Invoke to kernel32. Spawns the child process inside a
/// pseudo-console so programs see a real TTY (enabling colour output, progress bars,
/// and interactive prompts), while tswap intercepts the output pipe to apply redaction.
///
/// Requires Windows 10 v1809 (build 17763) or later — CreatePseudoConsole (ConPTY) was added in RS5.
/// stdout and stderr from the child are merged into a single PTY output stream, matching
/// the behaviour of the POSIX forkpty() implementations on Linux and macOS.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsPty : IPtyRunner
{
    [StructLayout(LayoutKind.Sequential)]
    private struct COORD
    {
        public short X, Y;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int    cb;
        public IntPtr lpReserved;   // LPWSTR — always null
        public IntPtr lpDesktop;    // LPWSTR — null = inherit
        public IntPtr lpTitle;      // LPWSTR — null = inherit
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars;
        public int    dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2;  // LPBYTE — always null
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr      lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int    dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int    nLength;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }

    private const uint EXTENDED_STARTUPINFO_PRESENT        = 0x00080000;
    private const int  PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint INFINITE                            = 0xFFFFFFFF;
    private const uint WAIT_FAILED                         = 0xFFFFFFFF;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out IntPtr hReadPipe, out IntPtr hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    // Returns HRESULT: S_OK (0) on success, negative on failure.
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(
        COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    // lpValue is a PVOID pointing to the HPCON handle value; pass via ref IntPtr.
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
        ref IntPtr lpValue, IntPtr cbSize,
        IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    // lpCommandLine must be a mutable buffer — Windows may write to it in some edge cases.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string? lpApplicationName, [In] char[] lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(
        IntPtr hFile, [In] byte[] lpBuffer, uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    /// <summary>
    /// Directly executes <paramref name="argv"/>[0] with the remaining elements as its
    /// argument list inside a ConPTY (no shell wrapper), writing redacted output to stdout.
    /// Returns the child process's exit code.
    /// </summary>
    public int Run(string[] argv, IReadOnlyList<KeyValuePair<string, string>> sortedSecrets)
    {
        if (argv is not { Length: > 0 } || string.IsNullOrEmpty(argv[0]))
            throw new ArgumentException("argv must be non-empty and argv[0] must be a non-empty executable name.", nameof(argv));

        int consoleCols, consoleRows;
        try { consoleCols = Console.WindowWidth; consoleRows = Console.WindowHeight; }
        catch { consoleCols = 0; consoleRows = 0; }
        var size = new COORD
        {
            X = (short)(consoleCols > 0 ? consoleCols : 80),
            Y = (short)(consoleRows > 0 ? consoleRows : 24),
        };

        // Pre-declare all handles as Zero so the finally block can safely close whatever
        // was successfully opened, regardless of where an exception is thrown.
        var hPipeInRd  = IntPtr.Zero;
        var hPipeInWr  = IntPtr.Zero;
        var hPipeOutRd = IntPtr.Zero;
        var hPipeOutWr = IntPtr.Zero;
        var hPC        = IntPtr.Zero;
        var attrList   = IntPtr.Zero;
        var hProcess   = IntPtr.Zero;
        bool attrListInitialized = false;

        try
        {
            // Create two anonymous pipe pairs.
            //   PTY stdin:  we write to hPipeInWr;  child reads from hPipeInRd (via ConPTY).
            //   PTY stdout: child writes to hPipeOutWr (via ConPTY); we read from hPipeOutRd.
            var secAttr = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>() };
            if (!CreatePipe(out hPipeInRd,  out hPipeInWr,  ref secAttr, 0))
                throw new Exception($"CreatePipe (stdin) failed (Win32 error {Marshal.GetLastWin32Error()})");
            if (!CreatePipe(out hPipeOutRd, out hPipeOutWr, ref secAttr, 0))
                throw new Exception($"CreatePipe (stdout) failed (Win32 error {Marshal.GetLastWin32Error()})");

            // Create the ConPTY: it reads from hPipeInRd and writes to hPipeOutWr.
            int hpcHr;
            if ((hpcHr = CreatePseudoConsole(size, hPipeInRd, hPipeOutWr, 0, out hPC)) != 0)
                throw new Exception($"CreatePseudoConsole failed (HRESULT 0x{hpcHr:X8})");

            // The ConPTY now owns those ends — null our copies so finally won't double-close.
            CloseHandle(hPipeInRd);  hPipeInRd  = IntPtr.Zero;
            CloseHandle(hPipeOutWr); hPipeOutWr = IntPtr.Zero;

            // Build a process-thread attribute list containing the ConPTY handle.
            IntPtr attrListSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrListSize);
            attrList = Marshal.AllocHGlobal(attrListSize);
            if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrListSize))
                throw new Exception("InitializeProcThreadAttributeList failed");
            attrListInitialized = true;

            // Pass the HPCON by reference so Windows receives a pointer to the handle value.
            var hPCValue = hPC;
            if (!UpdateProcThreadAttribute(attrList, 0,
                    new IntPtr(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE),
                    ref hPCValue, new IntPtr(IntPtr.Size),
                    IntPtr.Zero, IntPtr.Zero))
                throw new Exception("UpdateProcThreadAttribute failed");

            var si = new STARTUPINFOEX
            {
                StartupInfo     = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFOEX>() },
                lpAttributeList = attrList,
            };

            // Build the command line for CreateProcess from argv using Windows quoting rules
            // (CommandLineToArgvW-compatible: backslash-quote for embedded quotes, double-quote
            // wrapping for args that contain spaces or quotes). No cmd.exe wrapper is needed;
            // we execute argv[0] directly so argument structure is preserved exactly.
            var cmdStr = BuildWindowsCommandLine(argv);
            var cmdLine = new char[cmdStr.Length + 1]; // +1 for null terminator
            cmdStr.CopyTo(0, cmdLine, 0, cmdStr.Length);

            if (!CreateProcess(null, cmdLine,
                    IntPtr.Zero, IntPtr.Zero, false,
                    EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null,
                    ref si, out var pi))
                throw new Exception($"CreateProcess failed (Win32 error {Marshal.GetLastWin32Error()})");

            hProcess = pi.hProcess;
            CloseHandle(pi.hThread); // hThread is not needed after process is created

            // Forward stdin → PTY input pipe so interactive programs work.
            var stdinThread = new Thread(() =>
            {
                try
                {
                    var buf = new byte[256];
                    var stdin = Console.OpenStandardInput();
                    int n;
                    while ((n = stdin.Read(buf, 0, buf.Length)) > 0)
                    {
                        if (!WriteFile(hPipeInWr, buf, (uint)n, out _, IntPtr.Zero))
                            return; // pipe broken or closed
                    }
                }
                catch { /* stdin closed or pipe broken */ }
            }) { IsBackground = true };
            stdinThread.Start();

            // Read ConPTY output (stdout+stderr merged), redact secrets, write to our stdout.
            // StreamRedactor maintains a sliding-window overlap between chunks so secrets that
            // straddle a read-buffer boundary are still caught. See TswapCore.StreamRedactor.
            //
            // The read loop runs on a Task so the main thread can wait for the child process
            // and then close the ConPTY. The ConPTY holds the pipe write-end open even after
            // the child exits, so ReadFile would block forever if ClosePseudoConsole were
            // called only from the finally block (which can't run until the read loop ends).
            var readBuf  = new byte[4096];
            var encoding = Console.OutputEncoding;
            var decoder  = encoding.GetDecoder();
            var charBuf  = new char[encoding.GetMaxCharCount(readBuf.Length)];
            var stdout   = Console.OpenStandardOutput();
            var redactor = new StreamRedactor(sortedSecrets);
            var readTask = Task.Run(() =>
            {
                while (ReadFile(hPipeOutRd, readBuf, (uint)readBuf.Length, out uint nRead, IntPtr.Zero) && nRead > 0)
                {
                    var charCount = decoder.GetChars(readBuf, 0, (int)nRead, charBuf, 0);
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
            });

            // Wait for the child, then close the ConPTY to signal EOF to the read task.
            if (WaitForSingleObject(hProcess, INFINITE) == WAIT_FAILED)
                throw new Exception($"WaitForSingleObject failed (Win32 error {Marshal.GetLastWin32Error()})");
            if (!GetExitCodeProcess(hProcess, out uint exitCode))
                throw new Exception($"GetExitCodeProcess failed (Win32 error {Marshal.GetLastWin32Error()})");
            ClosePseudoConsole(hPC);
            hPC = IntPtr.Zero; // prevent double-close in finally

            readTask.Wait(); // drain any buffered output before returning
            return (int)exitCode;
        }
        finally
        {
            if (hProcess   != IntPtr.Zero) CloseHandle(hProcess);
            if (hPipeInWr  != IntPtr.Zero) CloseHandle(hPipeInWr);
            if (hPipeOutRd != IntPtr.Zero) CloseHandle(hPipeOutRd);
            if (hPipeInRd  != IntPtr.Zero) CloseHandle(hPipeInRd);
            if (hPipeOutWr != IntPtr.Zero) CloseHandle(hPipeOutWr);
            if (hPC        != IntPtr.Zero) ClosePseudoConsole(hPC);
            if (attrListInitialized)       DeleteProcThreadAttributeList(attrList);
            if (attrList   != IntPtr.Zero) Marshal.FreeHGlobal(attrList);
        }
    }

    /// <summary>
    /// Builds a Windows command line string from <paramref name="argv"/> using the quoting
    /// rules required by <c>CommandLineToArgvW</c>: each argument containing spaces, tabs,
    /// or double-quotes is wrapped in double-quotes; embedded double-quotes are escaped as
    /// <c>\"</c>; backslashes immediately before a double-quote (or the closing quote) are
    /// doubled. Arguments that need no quoting are appended verbatim.
    /// </summary>
    private static string BuildWindowsCommandLine(string[] argv)
    {
        var parts = new string[argv.Length];
        for (int i = 0; i < argv.Length; i++)
            parts[i] = WindowsQuoteArg(argv[i]);
        return string.Join(' ', parts);
    }

    private static string WindowsQuoteArg(string arg)
    {
        // Empty arg must be quoted so it survives as an empty token.
        if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
            return arg;

        var sb = new System.Text.StringBuilder("\"");
        int backslashes = 0;
        foreach (char c in arg)
        {
            if (c == '\\')
            {
                backslashes++;
            }
            else if (c == '"')
            {
                // Each preceding backslash plus the quote itself must be escaped.
                sb.Append('\\', backslashes * 2 + 1);
                sb.Append('"');
                backslashes = 0;
            }
            else
            {
                if (backslashes > 0) { sb.Append('\\', backslashes); backslashes = 0; }
                sb.Append(c);
            }
        }
        // Trailing backslashes before the closing quote must be doubled.
        sb.Append('\\', backslashes * 2);
        sb.Append('"');
        return sb.ToString();
    }
}
