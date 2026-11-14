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

    // Final review (GLM p6a I1): tcgetattr succeeds but switching the echo off fails: nothing is read with the echo
    // on; the saved settings are put back and the read is a cancel.
    [Fact]
    public void UnixTty_EchoOffFails_RestoresAndCancels()
    {
        if (OperatingSystem.IsWindows())
            return;
        File.WriteAllText(_file, "123456\nsecond line\n");
        var calls = new FailingSetAttr();

        int setsByReadSecret;
        using (var tty = ControllingTerminal.UnixTty.OpenPath(_file, calls))
        {
            Assert.NotNull(tty);
            Assert.Null(tty.ReadSecret());
            setsByReadSecret = calls.Sets.Count; // ReadLine sets its own line mode since #296: counted apart
            Assert.Equal("123456", tty.ReadLine()); // not consumed: nothing was read with the echo on
        }

        Assert.Equal(2, setsByReadSecret);
        Assert.False(calls.Sets[0].EchoOn); // the echo-off attempt, which failed
        Assert.True(calls.Sets[1].EchoOn);  // the saved settings, put back
    }

    // Follow-up review: after a resume (SIGCONT, fg) the echo-off is applied again; when that fails, what is typed
    // next was typed with the echo on, so the pending read is a cancel. A real SIGCONT reaches a read blocked on a FIFO.
    [Fact]
    public async Task UnixTty_EchoOffFailsAfterResume_ReadIsCancelled()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal(0, mkfifo(_file, 0x180)); // 0600
        var calls = new FailingAfterResume();
        using var tty = ControllingTerminal.UnixTty.OpenPath(_file, calls);
        Assert.NotNull(tty);

        var read = Task.Run(tty.ReadSecret);
        Assert.True(calls.EchoOffApplied.Wait(TimeSpan.FromSeconds(10)), "the read never switched the echo off");
        Assert.Equal(0, kill(Environment.ProcessId, SigCont));
        Assert.True(calls.ResumeRefused.Wait(TimeSpan.FromSeconds(10)), "the resume never re-applied the echo-off");
        using (var writer = new FileStream(_file, FileMode.Open, FileAccess.Write))
            writer.Write("123456\n"u8);

        Assert.Null(await read.WaitAsync(TimeSpan.FromSeconds(10))); // a TimeoutException: the read didn't end
        Assert.True(calls.Sets[^1].EchoOn); // the saved settings, put back at the end
    }

    private static readonly int SigCont = OperatingSystem.IsMacOS() ? 19 : 18;

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int mkfifo(string path, uint mode);

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int signal);

    /// <summary>The first echo-off succeeds; the next (the re-apply after a resume) fails.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private sealed class FailingAfterResume : ControllingTerminal.UnixTty.ITermiosCalls
    {
        private int _echoOffs;

        public List<(int When, bool EchoOn)> Sets { get; } = [];
        public ManualResetEventSlim EchoOffApplied { get; } = new();
        public ManualResetEventSlim ResumeRefused { get; } = new();

        public int Get(int fd, Span<byte> termios)
        {
            termios.Clear();
            termios[ControllingTerminal.UnixTty.LflagOffset] = 0x8; // ECHO
            return 0;
        }

        public int Set(int fd, int when, ReadOnlySpan<byte> termios)
        {
            var echoOn = (termios[ControllingTerminal.UnixTty.LflagOffset] & 0x8) != 0;
            lock (Sets)
                Sets.Add((when, echoOn));
            if (echoOn)
                return 0;
            if (Interlocked.Increment(ref _echoOffs) == 1)
            {
                EchoOffApplied.Set();
                return 0;
            }
            ResumeRefused.Set();
            return -1;
        }
    }

    /// <summary>tcgetattr gives settings with ECHO on; every tcsetattr that clears ECHO fails.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private sealed class FailingSetAttr : ControllingTerminal.UnixTty.ITermiosCalls
    {
        public List<(int When, bool EchoOn)> Sets { get; } = [];

        public int Get(int fd, Span<byte> termios)
        {
            termios.Clear();
            termios[ControllingTerminal.UnixTty.LflagOffset] = 0x8; // ECHO
            return 0;
        }

        public int Set(int fd, int when, ReadOnlySpan<byte> termios)
        {
            var echoOn = (termios[ControllingTerminal.UnixTty.LflagOffset] & 0x8) != 0;
            Sets.Add((when, echoOn));
            return echoOn ? 0 : -1;
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
