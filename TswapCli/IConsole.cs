namespace TswapCli;

/// <summary>
/// Console seam for the CLI layer: every command talks to the terminal through this
/// interface so tests can script input and capture output in-process.
/// Deliberately minimal — one interface, two implementations (SystemConsole and a
/// test fake), not a TUI framework.
/// </summary>
public interface IConsole
{
    TextWriter Out { get; }
    TextWriter Error { get; }
    bool IsInputRedirected { get; }
    string? ReadLine();

    /// <summary>
    /// Reads a password with masked echo (*, backspace handling, Ctrl+C cancels).
    /// <paramref name="echo"/> receives the masking feedback; defaults to <see cref="Out"/>.
    /// Pass <see cref="Error"/> for commands whose stdout must stay clean when piped.
    /// </summary>
    string ReadPassword(TextWriter? echo = null);

    void SetForeground(ConsoleColor color);
    void ResetColor();
}
