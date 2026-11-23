using System.Text;

namespace TswapCli;

/// <summary>Production <see cref="IConsole"/> backed by <see cref="Console"/>.</summary>
public sealed class SystemConsole : IConsole
{
    private readonly IConsoleInput _input;
    private readonly TextWriter? _stdout;

    /// <param name="stdout">Brief T52 (#403): the writer for stdout instead of <see cref="Console.Out"/> (null: Console.Out).</param>
    public SystemConsole(TextWriter? stdout = null) : this(new ConsoleInput(), stdout)
    {
    }

    internal SystemConsole(IConsoleInput input, TextWriter? stdout = null)
    {
        _input = input;
        _stdout = stdout;
    }

    public TextWriter Out => _stdout ?? Console.Out;
    public TextWriter Error => Console.Error;
    /// <summary>Brief T48: redirected stdin through the one strict UTF-8 reader (<see cref="StrictStdin"/>), a terminal as it is.</summary>
    public TextReader In => _input.IsInputRedirected ? StrictStdin.Shared : Console.In;
    public bool IsInputRedirected => _input.IsInputRedirected;
    public bool IsOutputRedirected => Console.IsOutputRedirected;

    /// <summary>One line; on a terminal (stdin not redirected) what was typed before the read is discarded first (#293).</summary>
    public string? ReadLine()
    {
        DiscardTypeaheadOnATerminal();
        return _input.ReadLine();
    }

    /// <summary>
    /// #293: anything typed before the read (a YubiKey's one-time code from a stray touch, say) is thrown away, so it
    /// can't become the answer. Piped or redirected stdin is never touched: <c>printf 'yes\n' | tswap …</c> works.
    /// </summary>
    private void DiscardTypeaheadOnATerminal()
    {
        if (!_input.IsInputRedirected)
            _input.DiscardTypeahead();
    }

    public void SetForeground(ConsoleColor colour) => Console.ForegroundColor = colour;
    public void ResetColor() => Console.ResetColor();

    /// <summary>
    /// Brief T34 (#337.5): one line that shows nothing. Piped: the line as it is. On a terminal: what was typed before is
    /// discarded (#293), then keys are read without echo (as <see cref="ReadPassword"/>, but writing nothing at all):
    /// Enter returns the text, Ctrl-C throws <see cref="OperationCanceledException"/>, Ctrl-D on an empty line is the
    /// end of input (null) and is ignored mid-line, Backspace removes the last character, other control keys are ignored.
    /// </summary>
    public string? ReadLineWithoutEcho()
    {
        if (_input.IsInputRedirected)
            return _input.ReadLine();

        _input.DiscardTypeahead();
        var prevTreatCtrlC = _input.TreatControlCAsInput;
        _input.TreatControlCAsInput = true;
        try
        {
            var line = new StringBuilder();
            while (true)
            {
                var key = _input.ReadKey();
                if (key.Key == ConsoleKey.Enter)
                    return line.ToString();
                var control = key.Modifiers.HasFlag(ConsoleModifiers.Control);
                if (key.Key == ConsoleKey.C && control)
                    throw new OperationCanceledException();
                if (key.Key == ConsoleKey.D && control)
                {
                    if (line.Length == 0)
                        return null;
                    continue;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (line.Length > 0)
                        line.Remove(line.Length - 1, 1);
                }
                else if (!char.IsControl(key.KeyChar))
                    line.Append(key.KeyChar);
            }
        }
        finally
        {
            _input.TreatControlCAsInput = prevTreatCtrlC;
        }
    }

    public string ReadPassword(TextWriter? echo = null)
    {
        echo ??= Out;
        // When stdin is redirected (e.g. in tests or piped input) skip interactive masking.
        // Write a newline to echo so the next line of stderr output starts on a fresh line
        // (the caller writes the prompt with Write, not WriteLine).
        if (_input.IsInputRedirected)
        {
            var line = _input.ReadLine() ?? "";
            echo.WriteLine();
            return line;
        }

        _input.DiscardTypeahead(); // #293: on a terminal only (piped input returned above)
        var prevTreatCtrlC = _input.TreatControlCAsInput;
        _input.TreatControlCAsInput = true;
        try
        {
            var password = new StringBuilder();
            while (true)
            {
                var key = _input.ReadKey();
                if (key.Key == ConsoleKey.Enter)
                {
                    echo.WriteLine();
                    break;
                }
                if (key.Key == ConsoleKey.C && key.Modifiers.HasFlag(ConsoleModifiers.Control))
                {
                    echo.WriteLine();
                    throw new OperationCanceledException();
                }
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    echo.Write("\b \b");
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                    echo.Write("*");
                }
            }
            return password.ToString();
        }
        finally
        {
            _input.TreatControlCAsInput = prevTreatCtrlC;
        }
    }
}

/// <summary>The input side of <see cref="SystemConsole"/> (a seam: tests script it).</summary>
internal interface IConsoleInput
{
    bool IsInputRedirected { get; }

    void DiscardTypeahead();

    string? ReadLine();

    /// <summary>One key, not echoed.</summary>
    ConsoleKeyInfo ReadKey();

    bool TreatControlCAsInput { get; set; }
}

file sealed class ConsoleInput : IConsoleInput
{
    public bool IsInputRedirected => Console.IsInputRedirected;

    public void DiscardTypeahead() => Typeahead.DiscardStdin();

    /// <summary>Brief T48: piped, a line of the one strict UTF-8 reader (<see cref="StrictStdin"/>); on a terminal as it is.</summary>
    public string? ReadLine() => Console.IsInputRedirected ? StrictStdin.Shared.ReadLine() : Console.ReadLine();

    public ConsoleKeyInfo ReadKey() => Console.ReadKey(intercept: true);

    public bool TreatControlCAsInput
    {
        get => Console.TreatControlCAsInput;
        set => Console.TreatControlCAsInput = value;
    }
}
