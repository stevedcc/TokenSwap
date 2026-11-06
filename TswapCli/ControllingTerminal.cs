using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TswapCli;

/// <summary>
/// FIDO2 plan, task 6: the binary's <see cref="ITerminal"/>. "A terminal" is the plan's definition: on Linux and macOS
/// <c>/dev/tty</c> opens (the process has a controlling terminal, whatever stdin, stdout and stderr are); on Windows
/// stdin, stdout or stderr is a console (<c>GetConsoleMode</c> succeeds on its handle). <see cref="Open"/> returns
/// null otherwise. On Linux and macOS secrets are read from <c>/dev/tty</c> with its echo off, so a PIN typed there
/// works while stdin carries <c>--recovery-key-stdin</c>; the echo comes back on after the line, and on SIGINT,
/// SIGTERM, SIGQUIT or SIGHUP during the read (Ctrl+Z stops the process as usual; <c>fg</c> turns the echo off
/// again). On Windows the FIDO2 PIN is Windows' dialog's: this console terminal is only there to say
/// one is present, and it refuses every read.
/// </summary>
internal static partial class ControllingTerminal
{
    /// <summary>The controlling terminal, or null when there is none.</summary>
    public static ITerminal? Open()
    {
        if (OperatingSystem.IsWindows())
            return WindowsConsole.IsPresent() ? new WindowsConsole() : null;
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            return UnixTty.OpenPath("/dev/tty");
        return null;
    }

    /// <summary><c>/dev/tty</c>, through libc: reads one byte at a time, so nothing typed after the line is consumed.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    internal sealed partial class UnixTty : ITerminal
    {
        private const int ORdWr = 2;
        private const int EIntr = 4;
        private const int TcsaNow = 0;
        private const int TcsaFlush = 2;
        private const ulong Echo = 0x8;

        // struct termios: Linux tcflag_t is 32 bits (c_lflag at byte 12); macOS tcflag_t is unsigned long (c_lflag at
        // byte 24). Both structs are well under this size; only c_lflag's ECHO bit is changed.
        private const int TermiosBufferSize = 256;

        /// <summary>Where c_lflag sits in struct termios on this OS.</summary>
        internal static int LflagOffset => OperatingSystem.IsMacOS() ? 24 : 12;

        /// <summary><c>tcgetattr</c> and <c>tcsetattr</c> (a seam: a test makes the echo switch fail).</summary>
        internal interface ITermiosCalls
        {
            int Get(int fd, Span<byte> termios);

            int Set(int fd, int when, ReadOnlySpan<byte> termios);
        }

        private sealed unsafe class LibcTermios : ITermiosCalls
        {
            public static readonly LibcTermios Instance = new();

            public int Get(int fd, Span<byte> termios)
            {
                fixed (byte* p = termios)
                    return tcgetattr(fd, p);
            }

            public int Set(int fd, int when, ReadOnlySpan<byte> termios)
            {
                fixed (byte* p = termios)
                    return tcsetattr(fd, when, p);
            }
        }

        private readonly int _fd;
        private readonly ITermiosCalls _termios;

        private UnixTty(int fd, ITermiosCalls termios) => (_fd, _termios) = (fd, termios);

        /// <summary><paramref name="path"/> opened for reading and writing (<c>/dev/tty</c>; a test opens a plain file), or null.</summary>
        internal static UnixTty? OpenPath(string path, ITermiosCalls? termios = null)
        {
            var flags = ORdWr | (OperatingSystem.IsMacOS() ? 0x1000000 : 0x80000); // O_CLOEXEC
            var fd = open(path, flags);
            return fd < 0 ? null : new UnixTty(fd, termios ?? LibcTermios.Instance);
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

        public byte[]? ReadSecret()
        {
            var saved = new byte[TermiosBufferSize];
            // Fail closed: echo that can't be switched off would show the secret, so nothing is read (a cancel).
            if (_termios.Get(_fd, saved) != 0)
                return null;
            var quiet = (byte[])saved.Clone();
            ClearEcho(quiet);

            int Apply(byte[] termios, int when) => _termios.Set(_fd, when, termios);

            void Restore() => Apply(saved, TcsaNow);

            // Signals during the read (final review; measured on .NET 10, see the fix report): a handler registered
            // for SIGINT, SIGTERM, SIGQUIT or SIGHUP keeps the signal's default action, so the process still ends
            // (Ctrl+C exits 130) and the handler only puts the echo back first. SIGTSTP (Ctrl+Z) is deliberately not
            // intercepted: a handler for it swallows the stop, so the read went on with the echo restored and a PIN
            // typed after Ctrl+Z was echoed. With the default action the process really stops (the shell puts its own
            // terminal settings back while it is stopped), and on SIGCONT (fg) the echo goes off again. That handler
            // cancels .NET's own SIGCONT handling, which would otherwise run after it and put back the terminal
            // settings .NET holds, echo on (measured: the PIN typed after fg was echoed).
            using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, _ => Restore());
            using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => Restore());
            using var quit = PosixSignalRegistration.Create(PosixSignal.SIGQUIT, _ => Restore());
            using var hangup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, _ => Restore());
            using var resume = PosixSignalRegistration.Create(PosixSignal.SIGCONT, context =>
            {
                Apply(quiet, TcsaNow);
                context.Cancel = true;
            });
            if (Apply(quiet, TcsaFlush) != 0)
            {
                Restore(); // fail closed: nothing is read with the echo on, so this is a cancel
                return null;
            }
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
                BitConverter.TryWriteBytes(termios.AsSpan(LflagOffset), BitConverter.ToUInt64(termios, LflagOffset) & ~Echo);
            else
                BitConverter.TryWriteBytes(termios.AsSpan(LflagOffset), BitConverter.ToUInt32(termios, LflagOffset) & ~(uint)Echo);
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
    internal sealed partial class WindowsConsole : ITerminal
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

        /// <summary>Never reads: Windows' dialog asks for the PIN and picks the key, so tswap reads nothing here (not stdin either).</summary>
        public const string NeverReads = "Windows' dialog owns PIN entry: tswap reads no PIN or answer from the console on Windows.";

        public string? ReadLine() => throw new InvalidOperationException(NeverReads);

        public byte[]? ReadSecret() => throw new InvalidOperationException(NeverReads);

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
