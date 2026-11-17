using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>A console output handle's mode (Windows' <c>GetConsoleMode</c> / <c>SetConsoleMode</c>), or a test's fake.</summary>
internal interface IConsoleOutputMode
{
    uint Mode { get; }

    /// <summary>Sets the mode; false when the console refused it.</summary>
    bool TrySetMode(uint mode);
}

/// <summary>
/// Brief T35 Task 4 (#349): <c>run</c>'s child writes into a pseudo console (ConPTY), whose output carries VT
/// sequences; the classic console prints them as text unless the writer's output handle has
/// <see cref="EnableVirtualTerminalProcessing"/>. <see cref="AroundChild"/> turns it on for the child's run and puts
/// the old mode back after it (also when the runner throws). A console that has it already (Windows Terminal) is
/// left alone. No signal handler restores it after a Ctrl+C or a kill (ruling, as for the code page).
/// </summary>
internal static partial class WindowsVirtualTerminal
{
    public const uint EnableVirtualTerminalProcessing = 0x0004;

    private const int StdOutput = -11;

    /// <summary>tswap's stdout as a console, or null (not Windows, or stdout redirected).</summary>
    public static IConsoleOutputMode? ForThisProcess()
    {
        if (!OperatingSystem.IsWindows())
            return null;
        // Its own imports, as ControllingTerminal.WindowsConsole's are private (A12).
        var handle = GetStdHandle(StdOutput);
        return handle != 0 && handle != -1 && GetConsoleMode(handle, out _) ? new ConsoleHandle(handle) : null;
    }

    /// <summary>VT processing on <paramref name="stdout"/> until dispose, which puts the original mode back.</summary>
    public static IDisposable AroundChild(IConsoleOutputMode stdout)
    {
        var original = stdout.Mode;
        if ((original & EnableVirtualTerminalProcessing) != 0 || !stdout.TrySetMode(original | EnableVirtualTerminalProcessing))
            return Unchanged.Instance;
        return new Restore(stdout, original);
    }

    private sealed class Unchanged : IDisposable
    {
        public static readonly Unchanged Instance = new();

        public void Dispose()
        {
        }
    }

    private sealed class Restore(IConsoleOutputMode stdout, uint original) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            stdout.TrySetMode(original);
        }
    }

    private sealed class ConsoleHandle(nint handle) : IConsoleOutputMode
    {
        public uint Mode => GetConsoleMode(handle, out var mode) ? mode : 0;

        public bool TrySetMode(uint mode) => SetConsoleMode(handle, mode);
    }

    [LibraryImport("kernel32", SetLastError = true)]
    private static partial nint GetStdHandle(int which);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleMode(nint handle, out uint mode);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleMode(nint handle, uint mode);
}
