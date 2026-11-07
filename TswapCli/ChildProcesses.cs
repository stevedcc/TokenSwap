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
            var count = 0;
            foreach (var pid in children)
            {
                // A PTY child leads its own session and process group: signal the group. A child that
                // shares tswap's group (no PTY): only the child, never tswap's own group (that would
                // reach tswap's parent shell's pipeline).
                var target = FilledFilesNative.getpgid(pid) == pid ? -pid : pid;
                if (FilledFilesNative.kill(target, signal) == 0)
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
    // one from here, so the grace period runs and the kill (9) terminates the children.
    private static int SignalWindows(int signal)
    {
        var children = WindowsToolhelp.Children(Environment.ProcessId);
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
}
