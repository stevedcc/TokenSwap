using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TswapCli;

/// <summary>
/// FIDO2 plan, task 6: the binary's <see cref="ITerminal"/>. "A terminal" is the plan's definition: on Linux and macOS
/// <c>/dev/tty</c> opens (the process has a controlling terminal, whatever stdin, stdout and stderr are); on Windows
/// stdin, stdout or stderr is a console (<c>GetConsoleMode</c> succeeds on its handle). <see cref="Open"/> returns
/// null otherwise. On Linux and macOS secrets are read from <c>/dev/tty</c> with its echo off, so a PIN typed there
/// works while stdin carries <c>--recovery-key-stdin</c>; the echo comes back on after the line, and on SIGINT or
/// SIGTERM during the read. On Windows the FIDO2 PIN is Windows' dialog's: this console terminal is only there to say
/// one is present.
/// </summary>
internal static partial class ControllingTerminal
{
    /// <summary>The controlling terminal, or null when there is none.</summary>
    public static ITerminal? Open()
    {
        if (OperatingSystem.IsWindows())
            return WindowsConsole.IsPresent() ? new WindowsConsole() : null;
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            return UnixTty.TryOpen();
        return null;
    }

    /// <summary><c>/dev/tty</c>, through libc: reads one byte at a time, so nothing typed after the line is consumed.</summary>
    private sealed partial class UnixTty : ITerminal
    {
        private const int ORdWr = 2;
        private const int EIntr = 4;
        private const int TcsaNow = 0;
        private const int TcsaFlush = 2;
        private const ulong Echo = 0x8;

        // struct termios: Linux tcflag_t is 32 bits (c_lflag at byte 12); macOS tcflag_t is unsigned long (c_lflag at
        // byte 24). Both structs are well under this size; only c_lflag's ECHO bit is changed.
        private const int TermiosBufferSize = 256;

        private readonly int _fd;

        private UnixTty(int fd) => _fd = fd;

        public static UnixTty? TryOpen()
        {
            var flags = ORdWr | (OperatingSystem.IsMacOS() ? 0x1000000 : 0x80000); // O_CLOEXEC
            var fd = open("/dev/tty", flags);
            return fd < 0 ? null : new UnixTty(fd);
        }

        public void Write(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            var done = 0;
            while (done < bytes.Length)
            {
                var n = WriteBytes(bytes.AsSpan(done));
                if (n < 0 && Marshal.GetLastPInvokeError() == EIntr)
                    continue;
                if (n <= 0)
                    return; // the terminal went away: nothing more can be shown
                done += n;
            }
        }

        public string? ReadLine()
        {
            var bytes = ReadBytesLine();
            if (bytes is null)
                return null;
            try
            {
                return Encoding.UTF8.GetString(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        public unsafe byte[]? ReadSecret()
        {
            var saved = new byte[TermiosBufferSize];
            fixed (byte* p = saved)
            {
                if (tcgetattr(_fd, p) != 0)
                    return ReadBytesLine(); // not a terminal device after all: nothing to switch off
            }
            var quiet = (byte[])saved.Clone();
            ClearEcho(quiet);

            void Restore()
            {
                fixed (byte* p = saved)
                    tcsetattr(_fd, TcsaNow, p);
            }

            using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, _ => Restore());
            using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => Restore());
            fixed (byte* p = quiet)
                tcsetattr(_fd, TcsaFlush, p);
            try
            {
                return ReadBytesLine();
            }
            finally
            {
                Restore();
                Write("\n"); // the Enter the terminal didn't echo
            }
        }

        private static void ClearEcho(byte[] termios)
        {
            if (OperatingSystem.IsMacOS())
                BitConverter.TryWriteBytes(termios.AsSpan(24), BitConverter.ToUInt64(termios, 24) & ~Echo);
            else
                BitConverter.TryWriteBytes(termios.AsSpan(12), BitConverter.ToUInt32(termios, 12) & ~(uint)Echo);
        }

        /// <summary>One line (without its line ending) as bytes; null at the end of input with nothing typed.</summary>
        private byte[]? ReadBytesLine()
        {
            var buffer = new byte[64];
            var length = 0;
            Span<byte> one = stackalloc byte[1];
            try
            {
                while (true)
                {
                    var n = ReadBytes(one);
                    if (n < 0 && Marshal.GetLastPInvokeError() == EIntr)
                        continue;
                    if (n <= 0)
                    {
                        if (length == 0)
                            return null;
                        break;
                    }
                    if (one[0] == (byte)'\n')
                        break;
                    if (length == buffer.Length)
                    {
                        var bigger = new byte[buffer.Length * 2];
                        buffer.CopyTo(bigger, 0);
                        CryptographicOperations.ZeroMemory(buffer);
                        buffer = bigger;
                    }
                    buffer[length++] = one[0];
                }
                if (length > 0 && buffer[length - 1] == (byte)'\r')
                    length--;
                return buffer[..length];
            }
            finally
            {
                one.Clear();
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        private unsafe int ReadBytes(Span<byte> into)
        {
            fixed (byte* p = into)
                return (int)read(_fd, p, (nuint)into.Length);
        }

        private unsafe int WriteBytes(ReadOnlySpan<byte> from)
        {
            fixed (byte* p = from)
                return (int)write(_fd, p, (nuint)from.Length);
        }

        public void Dispose() => close(_fd);

        [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int open(string path, int flags);

        [LibraryImport("libc", SetLastError = true)]
        private static unsafe partial nint read(int fd, byte* buffer, nuint count);

        [LibraryImport("libc", SetLastError = true)]
        private static unsafe partial nint write(int fd, byte* buffer, nuint count);

        [LibraryImport("libc", SetLastError = true)]
        private static partial int close(int fd);

        [LibraryImport("libc", SetLastError = true)]
        private static unsafe partial int tcgetattr(int fd, byte* termios);

        [LibraryImport("libc", SetLastError = true)]
        private static unsafe partial int tcsetattr(int fd, int optionalActions, byte* termios);
    }

    /// <summary>The console, on Windows: present when one of the standard handles is a console.</summary>
    private sealed partial class WindowsConsole : ITerminal
    {
        private const int StdInput = -10;
        private const int StdOutput = -11;
        private const int StdError = -12;

        public static bool IsPresent() =>
            IsConsole(StdInput) || IsConsole(StdOutput) || IsConsole(StdError);

        private static bool IsConsole(int which)
        {
            var handle = GetStdHandle(which);
            return handle != 0 && handle != -1 && GetConsoleMode(handle, out _);
        }

        public void Write(string text) => Console.Error.Write(text);

        public string? ReadLine() => Console.ReadLine();

        public byte[]? ReadSecret() => Encoding.UTF8.GetBytes(new SystemConsole().ReadPassword(Console.Error));

        public void Dispose()
        {
        }

        [LibraryImport("kernel32", SetLastError = true)]
        private static partial nint GetStdHandle(int which);

        [LibraryImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GetConsoleMode(nint handle, out uint mode);
    }
}
