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
    TextReader In { get; }
    bool IsInputRedirected { get; }

    /// <summary>Whether stdout is a pipe or file: guided init asks only when both ends are a terminal.</summary>
    bool IsOutputRedirected { get; }

    /// <summary>
    /// One line of input. On a terminal (stdin not redirected) what was typed before the read is discarded first
    /// (#293), so a stray keystroke burst can't become the answer; piped input is read as it is.
    /// </summary>
    string? ReadLine();

    /// <summary>
    /// Reads a password with masked echo (*, backspace handling, Ctrl+C cancels).
    /// <paramref name="echo"/> receives the masking feedback; defaults to <see cref="Out"/>.
    /// Pass <see cref="Error"/> for commands whose stdout must stay clean when piped. On a terminal what was typed
    /// before the read is discarded first (#293); piped input is read as one line, as it is.
    /// </summary>
    string ReadPassword(TextWriter? echo = null);

    /// <summary>
    /// Brief T34 (#337.5): one line, nothing shown while it is typed; null at the end of input. On a terminal what was
    /// typed before the read is discarded first (#293), and Ctrl-C throws <see cref="OperationCanceledException"/>; piped
    /// input is read as it is. The caller writes the newline.
    /// </summary>
    string? ReadLineWithoutEcho();

    void SetForeground(ConsoleColor colour);
    void ResetColor();
}
