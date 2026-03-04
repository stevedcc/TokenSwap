using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using TswapCore;

/// <summary>
/// Windows ConPTY support via P/Invoke to kernel32. Spawns the child process inside a
/// pseudo-console so programs see a real TTY (enabling colour output, progress bars,
/// and interactive prompts), while tswap intercepts the output pipe to apply redaction.
///
/// Requires Windows 10 v1809 (build 17763) or later — ConPseudoConsole was added in RS5.
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
    /// Runs <paramref name="command"/> via cmd.exe /c inside a ConPTY, writing redacted
    /// output to stdout. Returns the child process's exit code.
    /// </summary>
    public int Run(string command, List<KeyValuePair<string, string>> sortedSecrets)
    {
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
                throw new Exception("CreatePipe (stdin) failed");
            if (!CreatePipe(out hPipeOutRd, out hPipeOutWr, ref secAttr, 0))
                throw new Exception("CreatePipe (stdout) failed");

            // Create the ConPTY: it reads from hPipeInRd and writes to hPipeOutWr.
            if (CreatePseudoConsole(size, hPipeInRd, hPipeOutWr, 0, out hPC) != 0)
                throw new Exception("CreatePseudoConsole failed");

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

            // Provide a mutable char[] for the command line (Windows spec requires writable buffer).
            var cmdStr = $"cmd.exe /c \"{command.Replace("\"", "\\\"")}\"";
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
                        WriteFile(hPipeInWr, buf, (uint)n, out _, IntPtr.Zero);
                }
                catch { /* stdin closed or pipe broken */ }
            }) { IsBackground = true };
            stdinThread.Start();

            // Read ConPTY output (stdout+stderr merged), redact secrets, write to our stdout.
            // StreamRedactor maintains a sliding-window overlap between chunks so secrets that
            // straddle a read-buffer boundary are still caught. See TswapCore.StreamRedactor.
            var readBuf  = new byte[4096];
            var decoder  = Encoding.UTF8.GetDecoder();
            var charBuf  = new char[4096];
            var stdout   = Console.OpenStandardOutput();
            var redactor = new StreamRedactor(sortedSecrets);
            while (ReadFile(hPipeOutRd, readBuf, (uint)readBuf.Length, out uint nRead, IntPtr.Zero) && nRead > 0)
            {
                var charCount = decoder.GetChars(readBuf, 0, (int)nRead, charBuf, 0);
                var redacted  = redactor.ProcessChunk(new string(charBuf, 0, charCount));
                var outBytes  = Encoding.UTF8.GetBytes(redacted);
                stdout.Write(outBytes, 0, outBytes.Length);
                stdout.Flush();
            }
            var tail = redactor.Flush();
            if (tail.Length > 0)
            {
                stdout.Write(Encoding.UTF8.GetBytes(tail));
                stdout.Flush();
            }

            WaitForSingleObject(hProcess, INFINITE);
            GetExitCodeProcess(hProcess, out uint exitCode);
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
}
