using System.Runtime.InteropServices;
using System.Text;

namespace TswapCli;

/// <summary>One of the process's standard output streams.</summary>
internal enum StandardStream
{
    Output,
    Error,
}

/// <summary>The console calls <see cref="ConsoleOutputEncoding"/> makes: the real ones, or a test's fake.</summary>
internal interface IConsoleEncodingHost
{
    bool IsWindows { get; }

    /// <summary>True when <paramref name="stream"/> is a console (not redirected to a file or pipe).</summary>
    bool IsConsole(StandardStream stream);

    /// <summary><see cref="Console.OutputEncoding"/>; setting it sets the console's output code page.</summary>
    Encoding OutputEncoding { get; set; }

    /// <summary>Flushes <see cref="Console.Out"/> and <see cref="Console.Error"/>.</summary>
    void Flush();
}

/// <summary>
/// Brief T35 Task 3 (#348.2, #294.4, #355): on Windows, while both stdout and stderr are consoles, tswap writes UTF-8
/// (code page 65001), so its symbols and box lines show instead of the OEM code page's best fit, and RedactingPty's
/// <c>WindowsPty</c>, which decodes ConPTY's UTF-8 with <see cref="Console.OutputEncoding"/>, sees a non-ASCII secret
/// as it is and redacts it. With either stream redirected nothing changes (A1): the library writes a child's output
/// to the raw streams in <see cref="Console.OutputEncoding"/>, so a mixed setting would put two encodings in one
/// file. The old code page is put back at dispose; a Ctrl+C or a killed tswap leaves the window at 65001 (no
/// signal handler, by ruling).
/// </summary>
internal static partial class ConsoleOutputEncoding
{
    private const int Utf8CodePage = 65001;

    /// <summary>
    /// Sets the console's output encoding to UTF-8 (without a byte order mark) when the rule above allows it, and
    /// returns what puts the original back (flushing both writers first).
    /// </summary>
    public static IDisposable Utf8OnWindows(IConsoleEncodingHost host)
    {
        if (!host.IsWindows || !host.IsConsole(StandardStream.Output) || !host.IsConsole(StandardStream.Error))
            return Unchanged.Instance;
        var original = host.OutputEncoding;
        if (original.CodePage == Utf8CodePage)
            return Unchanged.Instance;
        host.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        return new Restore(host, original);
    }

    /// <summary>The process's real console.</summary>
    public static IConsoleEncodingHost System { get; } = new SystemHost();

    private sealed class Unchanged : IDisposable
    {
        public static readonly Unchanged Instance = new();

        public void Dispose()
        {
        }
    }

    private sealed class Restore(IConsoleEncodingHost host, Encoding original) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            host.Flush();
            host.OutputEncoding = original;
        }
    }

    private sealed partial class SystemHost : IConsoleEncodingHost
    {
        private const int StdOutput = -11;
        private const int StdError = -12;

        public bool IsWindows => OperatingSystem.IsWindows();

        public bool IsConsole(StandardStream stream)
        {
            // As ControllingTerminal.WindowsConsole.IsConsole, whose import is private (A12).
            var handle = GetStdHandle(stream == StandardStream.Output ? StdOutput : StdError);
            return handle != 0 && handle != -1 && GetConsoleMode(handle, out _);
        }

        public Encoding OutputEncoding
        {
            get => Console.OutputEncoding;
            set => Console.OutputEncoding = value;
        }

        public void Flush()
        {
            Console.Out.Flush();
            Console.Error.Flush();
        }

        [LibraryImport("kernel32", SetLastError = true)]
        private static partial nint GetStdHandle(int which);

        [LibraryImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GetConsoleMode(nint handle, out uint mode);
    }
}
