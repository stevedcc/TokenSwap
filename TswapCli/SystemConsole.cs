using System.Text;

namespace TswapCli;

/// <summary>Production <see cref="IConsole"/> backed by <see cref="Console"/>.</summary>
public sealed class SystemConsole : IConsole
{
    private readonly IConsoleInput _input;

    public SystemConsole() : this(new ConsoleInput())
    {
    }

    internal SystemConsole(IConsoleInput input) => _input = input;

    public TextWriter Out => Console.Out;
    public TextWriter Error => Console.Error;
    public TextReader In => Console.In;
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

    public string ReadPassword(TextWriter? echo = null)
    {
        echo ??= Console.Out;
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

    public string? ReadLine() => Console.ReadLine();

    public ConsoleKeyInfo ReadKey() => Console.ReadKey(intercept: true);

    public bool TreatControlCAsInput
    {
        get => Console.TreatControlCAsInput;
        set => Console.TreatControlCAsInput = value;
    }
}
