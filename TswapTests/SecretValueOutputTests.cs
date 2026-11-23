using System.Text;
using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T52 (#403): on Windows, a command that prints a secret value or a filled file (<c>get</c>, <c>apply</c>)
/// writes a redirected stdout as UTF-8. Which commands those are, decided from the arguments as
/// <see cref="CommandRegistry.Dispatch"/> decides the command.
/// </summary>
public sealed class SecretValueOutputTests
{
    [Theory]
    [InlineData("get x")]
    [InlineData("apply f.yaml")]
    [InlineData("-v get x")]
    [InlineData("--verbose -v apply f")]
    [InlineData("GET x")]
    [InlineData("get --help")]
    public void PrintsSecretValues_GetOrApply_IsTrue(string commandLine) =>
        Assert.True(CommandRegistry.PrintsSecretValues(Args(commandLine)), commandLine);

    [Theory]
    [InlineData("")]
    [InlineData("-v")]
    [InlineData("run get")]
    [InlineData("run tswap get x")]
    [InlineData("names")]
    [InlineData("field show x")]
    [InlineData("nosuch")]
    [InlineData("--version")]
    public void PrintsSecretValues_AnyOtherCommand_IsFalse(string commandLine) =>
        Assert.False(CommandRegistry.PrintsSecretValues(Args(commandLine)), commandLine);

    /// <summary>The arguments of a space-separated command line ("" is none).</summary>
    private static string[] Args(string commandLine) => commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>A new command that prints a value must decide: add it here and set its <c>PrintsSecretValues</c>.</summary>
    [Fact]
    public void OnlyGetAndApplyPrintSecretValues() =>
        Assert.Equal(["apply", "get"], CommandRegistry.All.Where(c => c.PrintsSecretValues).Select(c => c.Name).Order());

    // ---- Task 2: the UTF-8 writer (ConsoleOutputEncoding.Utf8StdoutForSecretValues)

    /// <summary>A console with a given OS and stdout; stdout's raw stream is a <see cref="MemoryStream"/>.</summary>
    private sealed class FakeHost(bool windows, bool stdoutConsole) : IConsoleEncodingHost
    {
        public MemoryStream Stdout { get; } = new();
        public int OpenCalls { get; private set; }
        public int EncodingSets { get; private set; }

        public bool IsWindows => windows;

        public bool IsConsole(StandardStream stream) => stream == StandardStream.Output
            ? stdoutConsole
            : throw new InvalidOperationException("IsConsole(Error) is not part of this decision");

        public Encoding OutputEncoding
        {
            get => Encoding.Latin1;
            set => EncodingSets++;
        }

        public void Flush()
        {
        }

        public Stream OpenStandardOutput()
        {
            OpenCalls++;
            return Stdout;
        }
    }

    /// <summary>Every member throws except <see cref="IsWindows"/> when <paramref name="windowsAllowed"/>.</summary>
    private sealed class ThrowingHost(bool windowsAllowed) : IConsoleEncodingHost
    {
        public bool IsWindows => windowsAllowed ? false : throw new InvalidOperationException("IsWindows");

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
    public void Windows_StdoutRedirected_GetsAUtf8Writer_OverTheRawStream()
    {
        var host = new FakeHost(windows: true, stdoutConsole: false);

        var writer = ConsoleOutputEncoding.Utf8StdoutForSecretValues(host, printsSecretValues: true);

        Assert.NotNull(writer);
        writer.Write("é");
        Assert.Equal([0xC3, 0xA9], host.Stdout.ToArray()); // UTF-8, no BOM, flushed (AutoFlush)
        Assert.Equal(1, host.OpenCalls);
        Assert.Equal(0, host.EncodingSets);
    }

    [Fact]
    public void Windows_StdoutAConsole_NoWriter()
    {
        var host = new FakeHost(windows: true, stdoutConsole: true);

        Assert.Null(ConsoleOutputEncoding.Utf8StdoutForSecretValues(host, printsSecretValues: true));
        Assert.Equal(0, host.OpenCalls);
        Assert.Equal(0, host.EncodingSets);
    }

    [Fact]
    public void NotWindows_NoWriter_OnlyIsWindowsRead() =>
        Assert.Null(ConsoleOutputEncoding.Utf8StdoutForSecretValues(new ThrowingHost(windowsAllowed: true), printsSecretValues: true));

    [Fact]
    public void NotAValuePrintingCommand_NoWriter_NoHostMemberRead() =>
        Assert.Null(ConsoleOutputEncoding.Utf8StdoutForSecretValues(new ThrowingHost(windowsAllowed: false), printsSecretValues: false));

    /// <summary>
    /// Every corpus value with a character above U+007F comes out as its UTF-8 bytes and the newline, with no byte
    /// order mark (A2: the writer is the one <c>Utf8StdoutForSecretValues</c> returns). Failures name the case,
    /// never the value.
    /// </summary>
    [Fact]
    public void Utf8Writer_EveryNonAsciiCorpusValue_IsItsUtf8Bytes()
    {
        var strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        var failures = new List<string>();
        var checkedCases = 0;
        foreach (var c in EvilValues.Cases.Where(c => c.Value.Any(ch => ch > '\u007F')))
        {
            var host = new FakeHost(windows: true, stdoutConsole: false);
            var writer = ConsoleOutputEncoding.Utf8StdoutForSecretValues(host, printsSecretValues: true)
                ?? throw new InvalidOperationException("no writer");
            writer.WriteLine(c.Value);
            var expected = strict.GetBytes(c.Value + Environment.NewLine);
            var actual = host.Stdout.ToArray();
            checkedCases++;
            if (!expected.AsSpan().SequenceEqual(actual))
                failures.Add($"{c.Name}: expected {expected.Length} bytes, got {actual.Length}, first difference at byte {FirstDifference(expected, actual)}");
        }

        Assert.True(checkedCases > 0, "no non-ASCII corpus case");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private static int FirstDifference(byte[] a, byte[] b) => a.AsSpan().CommonPrefixLength(b);
}
