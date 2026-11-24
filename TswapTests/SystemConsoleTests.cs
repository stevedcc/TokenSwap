using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// #293: <see cref="SystemConsole"/> discards what was typed before a read when stdin is a terminal, and never touches
/// piped input. The console's input side is a seam (<see cref="IConsoleInput"/>); the platform call itself is tested
/// against a real pseudo-terminal (<c>ControllingTerminalPtyTests.Typeahead_DiscardUnix_DropsWhatWasTypedBeforeIt</c>).
/// </summary>
public sealed class SystemConsoleTests
{
    [Fact]
    public void ReadLine_OnATerminal_DiscardsTypeaheadFirst()
    {
        var input = new ScriptedInput(redirected: false, lines: ["yes"]);
        var console = new SystemConsole(input);

        Assert.Equal("yes", console.ReadLine());
        Assert.Equal(["discard", "line"], input.Log);
    }

    [Fact]
    public void ReadLine_Piped_KeepsEveryLine()
    {
        var input = new ScriptedInput(redirected: true, lines: ["first", "second"]);
        var console = new SystemConsole(input);

        Assert.Equal("first", console.ReadLine());
        Assert.Equal("second", console.ReadLine());
        Assert.Equal(["line", "line"], input.Log);
    }

    [Fact]
    public void ReadPassword_OnATerminal_DiscardsTypeaheadBeforeTheFirstKey()
    {
        var input = new ScriptedInput(redirected: false, keys: [Key('p'), Key('w'), Enter]);
        var console = new SystemConsole(input);
        var echo = new StringWriter();

        Assert.Equal("pw", console.ReadPassword(echo));
        Assert.Equal(["discard", "key", "key", "key"], input.Log);
        Assert.Equal("**" + echo.NewLine, echo.ToString());
    }

    [Fact]
    public void ReadPassword_Piped_ReadsTheLineWithoutDiscarding()
    {
        var input = new ScriptedInput(redirected: true, lines: ["pw"]);
        var console = new SystemConsole(input);
        var echo = new StringWriter();

        Assert.Equal("pw", console.ReadPassword(echo));
        Assert.Equal(["line"], input.Log);
        Assert.Equal(echo.NewLine, echo.ToString());
    }

    [Fact]
    public void ReadPassword_CtrlC_CancelsAndPutsTheSettingBack()
    {
        var input = new ScriptedInput(redirected: false, keys: [Key('p'), CtrlC]);
        var console = new SystemConsole(input);

        Assert.Throws<OperationCanceledException>(() => console.ReadPassword(new StringWriter()));
        Assert.Equal([true, false], input.ControlCSets); // on for the read, then back to what it was (false)
        Assert.False(input.TreatControlCAsInput);
    }

    // ---- brief T52 (#403): a given stdout writer

    [Fact]
    public void Out_GivenStdout_IsThatWriter()
    {
        var writer = new StringWriter();

        Assert.Same(writer, new SystemConsole(new ScriptedInput(redirected: true), writer).Out);
    }

    [Fact]
    public void Out_NoStdoutGiven_IsConsoleOut() =>
        Assert.Same(Console.Out, new SystemConsole(new ScriptedInput(redirected: true)).Out);

    [Fact]
    public void ReadPassword_Redirected_EchoesToGivenStdout()
    {
        var writer = new StringWriter();
        var console = new SystemConsole(new ScriptedInput(redirected: true, lines: ["pw"]), writer);

        Assert.Equal("pw", console.ReadPassword());
        Assert.Equal(writer.NewLine, writer.ToString());
    }

    // ---- brief T54 Task 5: backspace removes a whole character

    [Fact]
    public void ReadPassword_BackspaceAfterASurrogatePair_RemovesTheWholeCharacter()
    {
        var input = new ScriptedInput(redirected: false, keys: [Key('a'), Unit('\uD83D'), Unit('\uDE00'), Backspace, Key('b'), Enter]);
        var console = new SystemConsole(input);
        var echo = new StringWriter();

        Assert.Equal("ab", console.ReadPassword(echo));
        Assert.Equal("***" + "\b \b\b \b" + "*" + echo.NewLine, echo.ToString());
    }

    [Fact]
    public void ReadLineWithoutEcho_BackspaceAfterASurrogatePair_RemovesTheWholeCharacter()
    {
        var input = new ScriptedInput(redirected: false, keys: [Key('a'), Unit('\uD83D'), Unit('\uDE00'), Backspace, Enter]);
        var console = new SystemConsole(input);

        Assert.Equal("a", console.ReadLineWithoutEcho());
    }

    // ---- brief T34 (#337.5): ReadLineWithoutEcho

    [Fact]
    public void ReadLineWithoutEcho_OnATerminal_DiscardsTypeaheadFirst()
    {
        var input = new ScriptedInput(redirected: false, keys: [Digit('1'), Digit('2'), Backspace, Digit('3'), Enter]);
        var console = new SystemConsole(input);

        Assert.Equal("13", console.ReadLineWithoutEcho());
        Assert.Equal(["discard", "key", "key", "key", "key", "key"], input.Log);
        Assert.Equal([true, false], input.ControlCSets);
    }

    [Fact]
    public void ReadLineWithoutEcho_CtrlD_OnAnEmptyLine_IsEndOfInput()
    {
        var input = new ScriptedInput(redirected: false, keys: [CtrlD]);
        var console = new SystemConsole(input);

        Assert.Null(console.ReadLineWithoutEcho());
        Assert.False(input.TreatControlCAsInput);
    }

    [Fact]
    public void ReadLineWithoutEcho_CtrlD_MidLine_IsIgnored()
    {
        var input = new ScriptedInput(redirected: false, keys: [Digit('1'), CtrlD, Digit('2'), Enter]);
        var console = new SystemConsole(input);

        Assert.Equal("12", console.ReadLineWithoutEcho());
    }

    [Fact]
    public void ReadLineWithoutEcho_CtrlC_Cancels_AndPutsTheSettingBack()
    {
        var input = new ScriptedInput(redirected: false, keys: [Digit('1'), CtrlC]);
        var console = new SystemConsole(input);

        Assert.Throws<OperationCanceledException>(() => console.ReadLineWithoutEcho());
        Assert.Equal([true, false], input.ControlCSets); // on for the read, then back to what it was (false)
        Assert.False(input.TreatControlCAsInput);
    }

    [Fact]
    public void ReadLineWithoutEcho_Piped_ReadsTheLine()
    {
        var input = new ScriptedInput(redirected: true, lines: ["typed", "next"]);
        var console = new SystemConsole(input);

        Assert.Equal("typed", console.ReadLineWithoutEcho());
        Assert.Equal(["line"], input.Log);
    }

    private static ConsoleKeyInfo Digit(char c) => new(c, ConsoleKey.D0 + (c - '0'), shift: false, alt: false, control: false);

    private static readonly ConsoleKeyInfo Backspace = new('\b', ConsoleKey.Backspace, false, false, false);

    /// <summary>A key that types one UTF-16 unit (half of a surrogate pair, say), as a console delivers it.</summary>
    private static ConsoleKeyInfo Unit(char c) => new(c, 0, shift: false, alt: false, control: false);

    private static readonly ConsoleKeyInfo CtrlD = new('\x04', ConsoleKey.D, shift: false, alt: false, control: true);

    private static ConsoleKeyInfo Key(char c) => new(c, ConsoleKey.A + (c - 'a'), shift: false, alt: false, control: false);

    private static readonly ConsoleKeyInfo Enter = new('\r', ConsoleKey.Enter, false, false, false);

    private static readonly ConsoleKeyInfo CtrlC = new('\x03', ConsoleKey.C, shift: false, alt: false, control: true);

    /// <summary>Scripted lines and keys; logs every discard, line read and key read in order.</summary>
    private sealed class ScriptedInput(bool redirected, string[]? lines = null, ConsoleKeyInfo[]? keys = null) : IConsoleInput
    {
        private readonly Queue<string> _lines = new(lines ?? []);
        private readonly Queue<ConsoleKeyInfo> _keys = new(keys ?? []);
        private bool _treatControlC;

        public List<string> Log { get; } = [];
        public List<bool> ControlCSets { get; } = [];

        public bool IsInputRedirected => redirected;

        public void DiscardTypeahead() => Log.Add("discard");

        public string? ReadLine()
        {
            Log.Add("line");
            return _lines.Count > 0 ? _lines.Dequeue() : null;
        }

        public ConsoleKeyInfo ReadKey()
        {
            Log.Add("key");
            return _keys.Dequeue();
        }

        public bool TreatControlCAsInput
        {
            get => _treatControlC;
            set
            {
                ControlCSets.Add(value);
                _treatControlC = value;
            }
        }
    }
}
