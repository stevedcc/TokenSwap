using System.Text;
using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 6 follow-up: the binary's terminal (<see cref="ControllingTerminal"/>) never reads a secret it
/// can't hide, and on Windows never reads at all (Windows' dialog owns PIN entry, so stdin is never read for one).
/// The real <c>/dev/tty</c> echo switch and its signal handling need a terminal: they are on the owner's runbook.
/// </summary>
public class ControllingTerminalTests : IDisposable
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), "tswap-tty-" + Guid.NewGuid().ToString("N")[..8]);

    public void Dispose()
    {
        if (File.Exists(_file))
            File.Delete(_file);
    }

    [Fact]
    public void UnixTty_NotATerminal_ReadSecretFailsClosed()
    {
        if (OperatingSystem.IsWindows())
            return; // no /dev/tty reader on Windows
        File.WriteAllText(_file, "123456\nsecond line\n");

        // A file descriptor whose echo can't be switched off (tcgetattr fails): the secret is not read, it's a cancel.
        using (var notATty = ControllingTerminal.UnixTty.OpenPath(_file))
        {
            Assert.NotNull(notATty);
            Assert.Null(notATty.ReadSecret());
            // The line is still there to read echoed: ReadSecret refused it, it didn't consume it.
            Assert.Equal("123456", notATty.ReadLine());
        }
    }

    [Fact]
    public void UnixTty_MissingDevice_IsNoTerminal()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Null(ControllingTerminal.UnixTty.OpenPath(_file + "-absent"));
    }

    [Fact]
    public void WindowsConsole_NeverReads()
    {
        using var console = new ControllingTerminal.WindowsConsole();

        var line = Assert.Throws<InvalidOperationException>(() => console.ReadLine());
        var secret = Assert.Throws<InvalidOperationException>(() => console.ReadSecret());

        Assert.Contains("Windows' dialog owns PIN entry", line.Message);
        Assert.Contains("Windows' dialog owns PIN entry", secret.Message);
    }
}
