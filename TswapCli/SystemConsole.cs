using System.Text;

namespace TswapCli;

/// <summary>Production <see cref="IConsole"/> backed by <see cref="Console"/>.</summary>
public sealed class SystemConsole : IConsole
{
    public TextWriter Out => Console.Out;
    public TextWriter Error => Console.Error;
    public TextReader In => Console.In;
    public bool IsInputRedirected => Console.IsInputRedirected;
    public string? ReadLine() => Console.ReadLine();
    public void SetForeground(ConsoleColor color) => Console.ForegroundColor = color;
    public void ResetColor() => Console.ResetColor();

    public string ReadPassword(TextWriter? echo = null)
    {
        echo ??= Console.Out;
        // When stdin is redirected (e.g. in tests or piped input) skip interactive masking.
        // Write a newline to echo so the next line of stderr output starts on a fresh line
        // (the caller writes the prompt with Write, not WriteLine).
        if (Console.IsInputRedirected)
        {
            var line = Console.ReadLine() ?? "";
            echo.WriteLine();
            return line;
        }

        var prevTreatCtrlC = Console.TreatControlCAsInput;
        Console.TreatControlCAsInput = true;
        try
        {
            var password = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(true);
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
            Console.TreatControlCAsInput = prevTreatCtrlC;
        }
    }
}
