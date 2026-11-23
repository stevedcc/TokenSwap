using System.Text;
using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T35 Task 3 (#348.2, #294.4, #355): <see cref="ConsoleOutputEncoding.Utf8OnWindows"/> over a fake console.
/// UTF-8 only on Windows with both stdout and stderr a console and a code page other than 65001 (A1); the original
/// encoding back at dispose, after a flush.
/// </summary>
public sealed class ConsoleOutputEncodingTests
{
    private static readonly Encoding Original = Encoding.Latin1;

    private sealed class FakeHost(bool windows, bool stdoutConsole, bool stderrConsole, Encoding encoding) : IConsoleEncodingHost
    {
        private Encoding _encoding = encoding;

        public List<string> Calls { get; } = [];
        public List<Encoding> Sets { get; } = [];

        public bool IsWindows => windows;

        public bool IsConsole(StandardStream stream) => stream == StandardStream.Output ? stdoutConsole : stderrConsole;

        public Encoding OutputEncoding
        {
            get => _encoding;
            set
            {
                Calls.Add($"set {value.CodePage}");
                Sets.Add(value);
                _encoding = value;
            }
        }

        public void Flush() => Calls.Add("flush");

        /// <summary>Brief T52 (A5): counted here, not in <see cref="Calls"/>.</summary>
        public int OpenStandardOutputCalls { get; private set; }

        public Stream OpenStandardOutput()
        {
            OpenStandardOutputCalls++;
            return new MemoryStream();
        }
    }

    /// <summary>Off Windows only <see cref="IsWindows"/> may be read.</summary>
    private sealed class NotWindowsHost : IConsoleEncodingHost
    {
        public bool IsWindows => false;

        public bool IsConsole(StandardStream stream) => throw new InvalidOperationException("IsConsole");

        public Encoding OutputEncoding
        {
            get => throw new InvalidOperationException("get OutputEncoding");
            set => throw new InvalidOperationException("set OutputEncoding");
        }

        public void Flush() => throw new InvalidOperationException("Flush");

        public Stream OpenStandardOutput() => throw new InvalidOperationException("OpenStandardOutput");
    }

    [Fact]
    public void Windows_BothConsoles_Utf8WhileRunning_OriginalAfter()
    {
        var host = new FakeHost(windows: true, stdoutConsole: true, stderrConsole: true, Original);

        var scope = ConsoleOutputEncoding.Utf8OnWindows(host);

        Assert.Equal(65001, host.OutputEncoding.CodePage);
        Assert.Empty(host.OutputEncoding.GetPreamble());
        Assert.Equal(["set 65001"], host.Calls);

        scope.Dispose();

        Assert.Same(Original, host.OutputEncoding);
        Assert.Equal(["set 65001", "flush", $"set {Original.CodePage}"], host.Calls);
    }

    [Fact]
    public void Windows_StdoutRedirected_NothingSet()
    {
        var host = new FakeHost(windows: true, stdoutConsole: false, stderrConsole: true, Original);

        ConsoleOutputEncoding.Utf8OnWindows(host).Dispose();

        Assert.Empty(host.Sets);
        Assert.Same(Original, host.OutputEncoding);
    }

    [Fact]
    public void Windows_StderrRedirected_NothingSet()
    {
        var host = new FakeHost(windows: true, stdoutConsole: true, stderrConsole: false, Original);

        ConsoleOutputEncoding.Utf8OnWindows(host).Dispose();

        Assert.Empty(host.Sets);
        Assert.Same(Original, host.OutputEncoding);
    }

    [Fact]
    public void Windows_NeitherIsAConsole_NothingSet()
    {
        var host = new FakeHost(windows: true, stdoutConsole: false, stderrConsole: false, Original);

        ConsoleOutputEncoding.Utf8OnWindows(host).Dispose();

        Assert.Empty(host.Sets);
    }

    [Fact]
    public void Windows_AlreadyUtf8_NothingSet()
    {
        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);
        var host = new FakeHost(windows: true, stdoutConsole: true, stderrConsole: true, utf8);

        ConsoleOutputEncoding.Utf8OnWindows(host).Dispose();

        Assert.Empty(host.Sets);
        Assert.Same(utf8, host.OutputEncoding);
    }

    [Fact]
    public void NotWindows_NothingTouched()
    {
        using var scope = ConsoleOutputEncoding.Utf8OnWindows(new NotWindowsHost());
    }
}
