using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// #295, #296: <see cref="ControllingTerminal.UnixTty"/> against a real pseudo-terminal, so the kernel's line discipline
/// (canonical mode, CR to NL, erase, the flush on resume) does what it does for a person at a terminal.
/// <para>
/// .NET's own console leaves the terminal non-canonical, without CR-to-NL mapping and with the echo off once it has
/// read a line (<c>Console.ReadLine</c>; measured on .NET 10 and 11, Linux). The guided <c>init</c> reads its answers
/// that way before the FIDO2 PIN, so Enter (CR) never ended the PIN's line, Backspace became part of the PIN, and what
/// was typed before Ctrl+Z was sent with what came after <c>fg</c>. <see cref="DotNetAfterReadLine"/> sets up that
/// state on the pty's terminal side.
/// </para>
/// </summary>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class ControllingTerminalPtyTests : IDisposable
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private readonly Pty? _pty = OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() ? Pty.Open() : null;

    public void Dispose() => _pty?.Dispose();

    [Fact]
    public async Task ReadSecret_AfterDotNetReadLine_EnterEndsThePin()
    {
        if (_pty is null)
            return; // no pseudo-terminals on Windows (and no /dev/tty reader there)
        _pty.DotNetAfterReadLine();
        var calls = new ObservedTermios();
        using var tty = ControllingTerminal.UnixTty.OpenPath(_pty.TerminalPath, calls)!;

        var read = Task.Run(tty.ReadSecret);
        Assert.True(calls.FirstSet.Wait(Wait), "the read never set its terminal mode");
        _pty.Type("1234\r"); // Enter is CR

        var pin = await read.WaitAsync(Wait); // before #296: a TimeoutException, the read waited for LF
        Assert.Equal("1234", Encoding.UTF8.GetString(pin!));
    }

    [Fact]
    public async Task ReadSecret_AfterDotNetReadLine_BackspaceErases()
    {
        if (_pty is null)
            return;
        _pty.DotNetAfterReadLine();
        var calls = new ObservedTermios();
        using var tty = ControllingTerminal.UnixTty.OpenPath(_pty.TerminalPath, calls)!;

        var read = Task.Run(tty.ReadSecret);
        Assert.True(calls.FirstSet.Wait(Wait), "the read never set its terminal mode");
        _pty.Type("12x\x7f" + "34\n"); // a typo, Backspace (DEL), the rest; LF so this test doesn't depend on CR

        var pin = await read.WaitAsync(Wait);
        Assert.Equal("1234", Encoding.UTF8.GetString(pin!)); // before: "12x\x7f34", a wrong PIN sent to the key
    }

    [Fact]
    public async Task ReadSecret_PutsTheTerminalBackAsItWas()
    {
        if (_pty is null)
            return;
        _pty.DotNetAfterReadLine();
        var before = _pty.Flags();
        var calls = new ObservedTermios();
        using var tty = ControllingTerminal.UnixTty.OpenPath(_pty.TerminalPath, calls)!;

        var read = Task.Run(tty.ReadSecret);
        Assert.True(calls.FirstSet.Wait(Wait), "the read never set its terminal mode");
        var during = _pty.Flags();
        _pty.Type("1234\n");
        await read.WaitAsync(Wait);

        Assert.True(during.Canonical && during.CrToNl && !during.Echo, $"during the read: {during}");
        Assert.Equal(before, _pty.Flags()); // .NET's console finds its own settings again
    }

    [Fact]
    public async Task ReadSecret_Resume_DiscardsWhatWasTypedBeforeTheStop()
    {
        if (_pty is null)
            return;
        var calls = new ObservedTermios();
        using var tty = ControllingTerminal.UnixTty.OpenPath(_pty.TerminalPath, calls)!;

        var read = Task.Run(tty.ReadSecret);
        Assert.True(calls.FirstSet.Wait(Wait), "the read never set its terminal mode");
        _pty.Type("99"); // typed, then Ctrl+Z; the stop itself can't be sent to the test process, its SIGCONT can
        Assert.Equal(0, kill(Environment.ProcessId, SigCont));
        Assert.True(calls.SecondSet.Wait(Wait), "the resume never set the terminal mode again");
        _pty.Type("1234\n"); // fg, then the whole PIN, as the resume text asks

        var pin = await read.WaitAsync(Wait);
        Assert.Equal("1234", Encoding.UTF8.GetString(pin!)); // before #295: "991234"
        Assert.Contains(ControllingTerminal.UnixTty.ResumedText, _pty.Shown(Wait, ControllingTerminal.UnixTty.ResumedText));
    }

    [Fact]
    public async Task ReadLine_AfterDotNetReadLine_EnterEndsTheAnswerAndItIsEchoed()
    {
        if (_pty is null)
            return;
        _pty.DotNetAfterReadLine();
        var calls = new ObservedTermios();
        using var tty = ControllingTerminal.UnixTty.OpenPath(_pty.TerminalPath, calls)!;

        var read = Task.Run(tty.ReadLine);
        Assert.True(calls.FirstSet.Wait(Wait), "the read never set its terminal mode");
        var during = _pty.Flags();
        _pty.Type("yes\r");

        Assert.Equal("yes", await read.WaitAsync(Wait)); // before #296: a TimeoutException (OfferPin's yes/no)
        Assert.True(during.Canonical && during.CrToNl && during.Echo, $"during the read: {during}");
    }

    private static readonly int SigCont = OperatingSystem.IsMacOS() ? 19 : 18;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int signal);

    /// <summary>The real tcgetattr/tcsetattr, with events for the first and second tcsetattr.</summary>
    private sealed class ObservedTermios : ControllingTerminal.UnixTty.ITermiosCalls
    {
        private int _sets;

        public ManualResetEventSlim FirstSet { get; } = new();
        public ManualResetEventSlim SecondSet { get; } = new();

        public int Get(int fd, Span<byte> termios) => Pty.GetAttr(fd, termios);

        public int Set(int fd, int when, ReadOnlySpan<byte> termios)
        {
            var result = Pty.SetAttr(fd, when, termios);
            switch (Interlocked.Increment(ref _sets))
            {
                case 1: FirstSet.Set(); break;
                case 2: SecondSet.Set(); break;
            }
            return result;
        }
    }

    internal readonly record struct TtyFlags(bool Canonical, bool CrToNl, bool Echo);

    /// <summary>A pseudo-terminal pair: the test types on the controller side, tswap reads the terminal side.</summary>
    private sealed class Pty : IDisposable
    {
        private const int ORdWr = 2;
        private const int TcsaNow = 0;
        private static int ONoCtty => OperatingSystem.IsMacOS() ? 0x20000 : 0x100;
        private static int IflagOffset => 0;
        private static int LflagOffset => OperatingSystem.IsMacOS() ? 24 : 12;
        private static ulong Icanon => OperatingSystem.IsMacOS() ? 0x100UL : 0x2UL;
        private const ulong Echo = 0x8;
        private const ulong Icrnl = 0x100;

        private readonly int _controller;
        private readonly int _terminal; // kept open so the terminal side's settings stay while tswap opens and closes it
        private readonly StringBuilder _shown = new();

        public string TerminalPath { get; }

        private Pty(int controller, int terminal, string path) => (_controller, _terminal, TerminalPath) = (controller, terminal, path);

        public static Pty Open()
        {
            var controller = posix_openpt(ORdWr | ONoCtty);
            Assert.True(controller >= 0, "posix_openpt failed");
            Assert.Equal(0, grantpt(controller));
            Assert.Equal(0, unlockpt(controller));
            var path = Marshal.PtrToStringAnsi(ptsname(controller))!;
            var terminal = open(path, ORdWr | ONoCtty);
            Assert.True(terminal >= 0, $"open {path} failed");
            return new Pty(controller, terminal, path);
        }

        /// <summary>What .NET's console leaves after <c>Console.ReadLine</c>: -icanon -icrnl -echo.</summary>
        public void DotNetAfterReadLine()
        {
            var t = new byte[256];
            Assert.Equal(0, GetAttr(_terminal, t));
            Update(t, IflagOffset, v => v & ~Icrnl);
            Update(t, LflagOffset, v => v & ~(Icanon | Echo));
            // VMIN 1, VTIME 0: one byte per read, as .NET sets them (Linux c_cc at byte 17, VMIN 6, VTIME 5;
            // macOS c_cc at byte 32, VMIN 16, VTIME 17).
            if (OperatingSystem.IsMacOS())
                (t[32 + 16], t[32 + 17]) = (1, 0);
            else
                (t[17 + 6], t[17 + 5]) = (1, 0);
            Assert.Equal(0, SetAttr(_terminal, TcsaNow, t));
        }

        public TtyFlags Flags()
        {
            var t = new byte[256];
            Assert.Equal(0, GetAttr(_terminal, t));
            var i = Read(t, IflagOffset);
            var l = Read(t, LflagOffset);
            return new TtyFlags((l & Icanon) != 0, (i & Icrnl) != 0, (l & Echo) != 0);
        }

        public void Type(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            Assert.Equal(bytes.Length, (int)write(_controller, bytes, (nuint)bytes.Length));
        }

        /// <summary>What tswap wrote to the terminal so far, read until <paramref name="expected"/> shows or the time is up.</summary>
        public string Shown(TimeSpan wait, string expected)
        {
            var until = DateTime.UtcNow + wait;
            var buffer = new byte[4096];
            while (!_shown.ToString().Contains(expected) && DateTime.UtcNow < until)
            {
                var fds = new PollFd[] { new() { Fd = _controller, Events = 1 } }; // POLLIN
                if (poll(fds, 1, 200) <= 0)
                    continue;
                var n = (int)read(_controller, buffer, (nuint)buffer.Length);
                if (n <= 0)
                    break;
                _shown.Append(Encoding.UTF8.GetString(buffer, 0, n));
            }
            return _shown.ToString();
        }

        public void Dispose()
        {
            close(_terminal);
            close(_controller);
        }

        private static ulong Read(byte[] t, int offset) =>
            OperatingSystem.IsMacOS() ? BitConverter.ToUInt64(t, offset) : BitConverter.ToUInt32(t, offset);

        private static void Update(byte[] t, int offset, Func<ulong, ulong> change)
        {
            var value = change(Read(t, offset));
            if (OperatingSystem.IsMacOS())
                BitConverter.TryWriteBytes(t.AsSpan(offset), value);
            else
                BitConverter.TryWriteBytes(t.AsSpan(offset), (uint)value);
        }

        public static int GetAttr(int fd, Span<byte> termios)
        {
            var buffer = new byte[termios.Length];
            var result = tcgetattr(fd, buffer);
            buffer.CopyTo(termios);
            return result;
        }

        public static int SetAttr(int fd, int when, ReadOnlySpan<byte> termios) => tcsetattr(fd, when, termios.ToArray());

        [StructLayout(LayoutKind.Sequential)]
        private struct PollFd
        {
            public int Fd;
            public short Events;
            public short Revents;
        }

        [DllImport("libc", SetLastError = true)] private static extern int posix_openpt(int flags);
        [DllImport("libc", SetLastError = true)] private static extern int grantpt(int fd);
        [DllImport("libc", SetLastError = true)] private static extern int unlockpt(int fd);
        [DllImport("libc", SetLastError = true)] private static extern nint ptsname(int fd);
        [DllImport("libc", SetLastError = true)] private static extern int open(string path, int flags);
        [DllImport("libc", SetLastError = true)] private static extern int close(int fd);
        [DllImport("libc", SetLastError = true)] private static extern nint write(int fd, byte[] buffer, nuint count);
        [DllImport("libc", SetLastError = true)] private static extern nint read(int fd, byte[] buffer, nuint count);
        [DllImport("libc", SetLastError = true)] private static extern int poll([In, Out] PollFd[] fds, nuint count, int timeout);
        [DllImport("libc", SetLastError = true)] private static extern int tcgetattr(int fd, byte[] termios);
        [DllImport("libc", SetLastError = true)] private static extern int tcsetattr(int fd, int when, byte[] termios);
    }
}
