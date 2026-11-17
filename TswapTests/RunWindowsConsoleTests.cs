using RedactingPty;
using TswapCli;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T35 Task 4 (#349): on a Windows console, <c>run</c> turns VT processing on for tswap's stdout while the
/// child runs (and puts the old mode back after it, also when the runner throws), and drops window-title sequences
/// from the child's output. Driven through the <see cref="CommandContext.StdoutConsoleMode"/> seam with a fake console
/// mode; null (Linux, macOS, redirected stdout) changes nothing.
/// </summary>
public sealed class RunWindowsConsoleTests : IDisposable
{
    private const string DbValue = "vt-db-value-91c2";
    private const string Title = "\u001b]0;C:\\WINDOWS\\system32\\choice.exe\u0007";

    private static string Capture(string shown) =>
        "\u001b[?9001h\u001b[?1004h\u001b[?25l\u001b[2J\u001b[m\u001b[H" + shown + " [Y,N]?" + Title + "\u001b[?25h\r\n\u001b[?9001l\u001b[?1004l";

    private readonly FleetMachine _m = new("run-windows-console", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();

    public RunWindowsConsoleTests()
    {
        InitRecordVault(_m);
        _m.Ok(DbValue, "ingest", "db-pw");
    }

    public void Dispose() => _m.Dispose();

    /// <summary>A console output mode that records every set.</summary>
    private sealed class FakeConsoleMode(uint mode) : IConsoleOutputMode
    {
        public uint Mode { get; private set; } = mode;
        public List<uint> Sets { get; } = [];

        public bool TrySetMode(uint mode)
        {
            Sets.Add(mode);
            Mode = mode;
            return true;
        }
    }

    /// <summary>A runner that fails after the child started (a local copy of RunVaultRedactionTests' FailingPty).</summary>
    private sealed class FailingPty : IPtyRunner
    {
        public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements) => throw new NotSupportedException();

        public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements, RedactionOptions options)
        {
            _ = new StreamRedactor(replacements, options.Matchers).ProcessChunk("first chunk of child output\n");
            throw new InvalidOperationException("Redaction failed: a matcher reported a match at 3 of length 9000 in a window of 40 characters.");
        }
    }

    private (int Exit, string Out, string Err) Run(Func<IConsoleOutputMode?> stdoutMode, IPtyRunner? runner = null, params string[] args)
    {
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => runner ?? _pty, StdoutConsoleMode = stdoutMode };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    [Fact]
    public void WindowsConsole_VtOnWhileTheChildRuns_RestoredAfter()
    {
        var fake = new FakeConsoleMode(0x3);
        uint? during = null;
        _pty.During = () => during = fake.Mode;

        var (exit, _, err) = Run(() => fake, null, "tool", "{{db-pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(0x7u, during);
        Assert.Equal([0x7u, 0x3u], fake.Sets);
        Assert.Equal(0x3u, fake.Mode);
    }

    [Fact]
    public void WindowsConsole_VtAlreadyOn_NoModeChange()
    {
        var fake = new FakeConsoleMode(0x7);

        var (exit, _, err) = Run(() => fake, null, "tool", "{{db-pw}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Empty(fake.Sets);
    }

    [Fact]
    public void WindowsConsole_ChildThrows_ModeRestored()
    {
        var fake = new FakeConsoleMode(0x3);

        var (exit, _, err) = Run(() => fake, new FailingPty(), "tool", "{{db-pw}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("Redaction failed", err);
        Assert.Equal([0x7u, 0x3u], fake.Sets);
    }

    [Fact]
    public void WindowsConsole_TitleDroppedFromChildOutput()
    {
        var fake = new FakeConsoleMode(0x3);
        _pty.Child = _ => Capture(DbValue);

        var (exit, stdout, stderr) = Run(() => fake, null, "tool", "{{db-pw}}");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Capture("[REDACTED: db-pw]").Replace(Title, ""), _pty.Output.ToString());
        Assert.Equal(2, _pty.Options!.Matchers.Count);
        Assert.DoesNotContain(DbValue, stdout + stderr + _pty.Output);
    }

    [Fact]
    public void NoConsole_TitleUntouched_NoMatcherAdded()
    {
        _pty.Child = _ => Capture(DbValue);

        var (exit, stdout, stderr) = Run(() => null, null, "tool", "{{db-pw}}");

        Assert.True(exit == 0, stderr);
        Assert.Single(_pty.Options!.Matchers);
        Assert.Equal(Capture("[REDACTED: db-pw]"), _pty.Output.ToString());
        Assert.DoesNotContain(DbValue, stdout + stderr + _pty.Output);
    }

    [Fact]
    public void Refused_ModeNeverTouched()
    {
        var fake = new FakeConsoleMode(0x3);
        var asked = 0;

        var (exit, _, stderr) = Run(() => { asked++; return fake; }, null, "echo", "{{db-pw}}");

        Assert.Equal(1, exit);
        Assert.Contains("'echo' would expose secret values", stderr);
        Assert.Empty(fake.Sets);
        Assert.Equal(0, asked);
        Assert.Equal(0, _pty.Starts);
    }

    /// <summary>
    /// The real seam: on Windows a mode exactly when stdout is a console (under a test runner it is usually
    /// redirected, so null); elsewhere always null. The Windows half runs on CI only.
    /// </summary>
    [Fact]
    public void ForThisProcess_FollowsStdout()
    {
        var mode = WindowsVirtualTerminal.ForThisProcess();

        if (OperatingSystem.IsWindows())
            Assert.Equal(Console.IsOutputRedirected, mode is null);
        else
            Assert.Null(mode);
    }

    [Fact]
    public void FleetMachine_NeverReachesARealConsole()
    {
        var ctx = _m.Context(new FakeConsole(""), ["run"]);

        // A15: FleetMachine replaces the real seam, so no in-process test reaches a console (also on a Windows console).
        Assert.NotEqual<Func<IConsoleOutputMode?>>(WindowsVirtualTerminal.ForThisProcess, ctx.StdoutConsoleMode);
        Assert.Null(ctx.StdoutConsoleMode());
    }
}
