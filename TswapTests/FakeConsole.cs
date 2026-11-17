using TswapCli;

namespace TswapTests;

/// <summary>
/// Scripted <see cref="IConsole"/> for in-process command tests: input comes from a
/// string, output and error are captured. <see cref="IsInputRedirected"/> is true by default,
/// mirroring how the subprocess harness behaved (the test host's stdin is
/// redirected, so spawned tswap processes always saw redirected stdin too).
/// </summary>
public sealed class FakeConsole(string stdin = "") : IConsole
{
    private readonly StringWriter _out = new();
    private readonly StringWriter _err = new();
    private readonly StringReader _in = new(stdin);

    public TextWriter Out => _out;
    public TextWriter Error => Interleaved ? _out : _err;

    /// <summary>T7 fix round 1: stdout and stderr into one writer, so a test can check their order.</summary>
    public bool Interleaved { get; init; }
    public TextReader In => _in;
    // True (piped stdin) unless a test plays an interactive terminal (brief T5: slot merge asks
    // for a fingerprint confirmation only on a terminal).
    public bool IsInputRedirected { get; init; } = true;

    /// <summary>Guided init: false (stdout a terminal) unless a test plays a piped stdout.</summary>
    public bool IsOutputRedirected { get; init; }

    /// <summary>Brief T7 item 4: how many times a command read a line or password from stdin.</summary>
    public int Reads { get; private set; }

    /// <summary>
    /// Brief T34: when true and stdin plays a terminal (<see cref="IsInputRedirected"/> false), <see cref="ReadLine"/>
    /// writes the line it read and a newline to <see cref="Out"/> (what a terminal in line mode shows), and
    /// <see cref="ReadPassword"/> one <c>*</c> per character before its newline (as <see cref="SystemConsole"/> does).
    /// </summary>
    public bool EchoesTypedLines { get; init; }

    private bool Echoes => EchoesTypedLines && !IsInputRedirected;

    public string? ReadLine()
    {
        Reads++;
        var line = _in.ReadLine();
        if (Echoes && line is not null)
            _out.WriteLine(line);
        return line;
    }

    // Mirrors SystemConsole's redirected-stdin path: read a line, echo a newline.
    public string ReadPassword(TextWriter? echo = null)
    {
        Reads++;
        var line = _in.ReadLine() ?? "";
        if (Echoes)
            (echo ?? Out).Write(new string('*', line.Length));
        (echo ?? Out).WriteLine();
        return line;
    }

    /// <summary>Brief T34: a read that shows nothing, ever (the caller writes the newline).</summary>
    public string? ReadLineWithoutEcho()
    {
        Reads++;
        return _in.ReadLine();
    }

    public void SetForeground(ConsoleColor colour) { }
    public void ResetColor() { }

    public string OutText => _out.ToString();
    public string ErrorText => _err.ToString();
}
