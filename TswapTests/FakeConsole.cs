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
    public TextWriter Error => _err;
    public TextReader In => _in;
    // True (piped stdin) unless a test plays an interactive terminal (brief T5: slot merge asks
    // for a fingerprint confirmation only on a terminal).
    public bool IsInputRedirected { get; init; } = true;

    /// <summary>Brief T7 item 4: how many times a command read a line or password from stdin.</summary>
    public int Reads { get; private set; }

    public string? ReadLine()
    {
        Reads++;
        return _in.ReadLine();
    }

    // Mirrors SystemConsole's redirected-stdin path: read a line, echo a newline.
    public string ReadPassword(TextWriter? echo = null)
    {
        Reads++;
        var line = _in.ReadLine() ?? "";
        (echo ?? Out).WriteLine();
        return line;
    }

    public void SetForeground(ConsoleColor color) { }
    public void ResetColor() { }

    public string OutText => _out.ToString();
    public string ErrorText => _err.ToString();
}
