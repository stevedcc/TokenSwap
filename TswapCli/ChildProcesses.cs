using System.Diagnostics;
using System.Globalization;

namespace TswapCli;

/// <summary>
/// The real <see cref="FilledFilesEnvironment.SignalChildren"/>: tswap's own child processes (the
/// PTY runner doesn't expose its child), found through <c>/proc</c> (Linux), <c>proc_listchildpids</c>
/// (macOS) or a Toolhelp snapshot (Windows).
/// </summary>
internal static class ChildProcesses
{
    public static int Signal(int signal)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return SignalWindows(signal);
            var children = OperatingSystem.IsLinux() ? LinuxChildren() : OperatingSystem.IsMacOS() ? MacChildren() : [];
            var ownGroup = FilledFilesNative.getpgrp();
            var foreground = ForegroundGroup();
            var count = 0;
            foreach (var pid in children)
            {
                if (Target(pid, FilledFilesNative.getpgid(pid), ownGroup, signal, foreground) is not { } target)
                    count++; // the terminal already delivered it
                else if (FilledFilesNative.kill(target, signal) == 0)
                    count++;
            }
            return count;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DllNotFoundException
                                       or EntryPointNotFoundException or InvalidOperationException)
        {
            return 0;
        }
    }

    /// <summary>
    /// Whom a signal for child <paramref name="pid"/> goes to: its process group (<c>-pid</c>) when it
    /// leads one (a PTY child leads its own session), otherwise the child alone, never tswap's own group
    /// (that would reach tswap's parent shell's pipeline). Null when it was already delivered: a SIGINT
    /// while the child shares tswap's group and that group is the terminal's foreground group came from
    /// the terminal (Ctrl+C), which sent it to the whole group (SIGQUIT is registered only on Windows,
    /// where this rule isn't used); a second one makes
    /// tools like helm or terraform abort their own cleanup. (A <c>kill -INT</c> of tswap alone at that
    /// moment then reaches only tswap; the child is killed after the grace period.)
    /// </summary>
    internal static int? Target(int pid, int childPgid, int ownPgid, int signal, int? foregroundPgid)
    {
        if (childPgid == pid && pid != ownPgid) // a reused pid equal to tswap's own group id is not the child's group
            return -pid;
        if (childPgid == ownPgid && signal == 2 && foregroundPgid == ownPgid)
            return null;
        return pid;
    }

    /// <summary>
    /// Windows: the children of <paramref name="parent"/> in a Toolhelp
    /// snapshot. Toolhelp's parent id goes stale when the parent exits and pids are reused, so an entry
    /// counts only when its creation time, read by <paramref name="startOf"/>, is later than the
    /// parent's: unreadable or earlier ones are never signalled or killed.
    /// </summary>
    internal static List<int> SelectWindowsChildren(IEnumerable<(int Pid, int ParentPid)> snapshot, int parent,
        DateTime parentStart, Func<int, DateTime?> startOf) =>
        snapshot.Where(e => e.ParentPid == parent && e.Pid != parent)
            .Where(e => startOf(e.Pid) is { } started && started > parentStart)
            .Select(e => e.Pid).ToList();

    // The foreground process group of tswap's controlling terminal, or null without one.
    private static int? ForegroundGroup()
    {
        var noCtty = OperatingSystem.IsMacOS() ? 0x20000 : 0x100;
        var fd = FilledFilesNative.open("/dev/tty", noCtty); // O_RDONLY | O_NOCTTY
        if (fd < 0)
            return null;
        try
        {
            var group = FilledFilesNative.tcgetpgrp(fd);
            return group > 0 ? group : null;
        }
        finally
        {
            FilledFilesNative.close(fd);
        }
    }

    private static List<int> LinuxChildren()
    {
        var me = Environment.ProcessId;
        List<int> children = [];
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                continue;
            string stat;
            try
            {
                stat = File.ReadAllText(Path.Combine(dir, "stat"));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue; // exited meanwhile
            }
            // pid (comm) state ppid ...: comm may hold spaces and parentheses, so read after the last ')'.
            var fields = stat[(stat.LastIndexOf(')') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length > 1 && int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var ppid) && ppid == me)
                children.Add(pid);
        }
        return children;
    }

    private static unsafe List<int> MacChildren()
    {
        var buffer = new int[1024];
        int count;
        fixed (int* pids = buffer)
            count = FilledFilesNative.proc_listchildpids(Environment.ProcessId, pids, buffer.Length * sizeof(int));
        return count <= 0 ? [] : buffer.Take(Math.Min(count, buffer.Length)).Where(p => p > 0).ToList();
    }

    // Windows: a Ctrl+C reaches a child on tswap's console by itself; a ConPTY child can't be sent
    // one from here, so the grace period runs and the kill (9) terminates the children (and their trees:
    // .NET's tree walk checks start times the same way).
    private static int SignalWindows(int signal)
    {
        DateTime ownStart;
        using (var self = Process.GetCurrentProcess())
            ownStart = self.StartTime.ToUniversalTime();
        var children = SelectWindowsChildren(WindowsToolhelp.Snapshot(), Environment.ProcessId, ownStart, StartOf);
        if (signal == 9)
            foreach (var pid in children)
            {
                try
                {
                    using var process = Process.GetProcessById(pid);
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    // Exited meanwhile.
                }
            }
        return children.Count;
    }

    private static DateTime? StartOf(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.StartTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception
                                       or NotSupportedException)
        {
            return null; // gone, or not ours to read: not verifiable
        }
    }
}
