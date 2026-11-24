namespace TswapCore;

/// <summary>
/// Brief T55 (#402): <c>run</c>'s child on Windows as an MSYS2 program (Git Bash, MSYS2's own programs), which parses
/// its command line by MSYS2's rules, not Microsoft's C runtime's. Everything here works on Windows path strings
/// without <see cref="System.IO.Path"/>, so the unit tests run on every OS: a folder and a name are joined with one
/// <c>\</c> (the folder's trailing <c>\</c> and <c>/</c> trimmed), and a folder's parent is the text before its last
/// <c>\</c> or <c>/</c> (trailing separators trimmed first).
/// </summary>
public static class MsysTarget
{
    /// <summary>
    /// What <see cref="Resolve"/> reads of the machine: the folder tswap was started from, the current folder, the
    /// system and Windows folders, the environment (tswap's own, as CreateProcess searches with it) and the file system.
    /// </summary>
    public sealed record Probe(string? ExeDirectory, string CurrentDirectory, string SystemDirectory, string WindowsDirectory,
        Func<string, string?> GetVariable, Func<string, bool> FileExists)
    {
        /// <summary>The real machine on Windows; null on every other OS.</summary>
        public static Probe? ForThisProcess() =>
            OperatingSystem.IsWindows()
                ? new Probe(Path.GetDirectoryName(Environment.ProcessPath), Environment.CurrentDirectory, Environment.SystemDirectory,
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetEnvironmentVariable, File.Exists)
                : null;
    }

    /// <summary>
    /// The file <c>CreateProcess</c> starts for <paramref name="program"/> as the first word of a command line with no
    /// application name, or null when there is none. <c>.exe</c> is appended when the name's last component has no
    /// <c>.</c>, also for a name holding a path (brief T55 spike round 2: Windows started <c>&lt;folder&gt;\t55probe2</c>
    /// as <c>t55probe2.exe</c>). A name holding <c>\</c> or <c>:</c> is not searched: one starting with <c>\</c> or a
    /// drive letter and <c>:</c> is taken as is, any other is joined to the current folder. Otherwise the first of: the
    /// folder tswap was started from, the current folder (unless <c>NoDefaultCurrentDirectoryInExePath</c> is set),
    /// the system folder, <c>&lt;Windows&gt;\System</c>, the Windows folder, then each <c>PATH</c> entry.
    /// </summary>
    /// <remarks>
    /// Accepted divergences from Windows (brief T55, review round 1 amendment 10): an empty <c>PATH</c> entry is skipped,
    /// and a drive-relative name (<c>C:file.exe</c>, relative to that drive's current folder) is taken as is.
    /// </remarks>
    public static string? Resolve(string program, Probe probe)
    {
        var name = program.Replace('/', '\\');
        if (name.Length == 0)
            return null;
        var lastComponent = name[(name.LastIndexOfAny(['\\', ':']) + 1)..];
        if (!lastComponent.Contains('.'))
            name += ".exe";

        if (name.Contains('\\') || name.Contains(':'))
        {
            var candidate = name.StartsWith('\\') || (name.Length >= 2 && char.IsAsciiLetter(name[0]) && name[1] == ':')
                ? name
                : Join(probe.CurrentDirectory, name);
            return probe.FileExists(candidate) ? candidate : null;
        }

        return SearchFolders(probe).Select(folder => Join(folder, name)).FirstOrDefault(probe.FileExists);
    }

    private static IEnumerable<string> SearchFolders(Probe probe)
    {
        if (probe.ExeDirectory is not null)
            yield return probe.ExeDirectory;
        if (probe.GetVariable("NoDefaultCurrentDirectoryInExePath") is null)
            yield return probe.CurrentDirectory;
        yield return probe.SystemDirectory;
        yield return Join(probe.WindowsDirectory, "System");
        yield return probe.WindowsDirectory;
        foreach (var entry in (probe.GetVariable("PATH") ?? "").Split(';'))
        {
            var folder = entry.Trim('"');
            if (folder.Length > 0)
                yield return folder;
        }
    }

    /// <summary>
    /// Whether <paramref name="path"/> (a file <see cref="Resolve"/> returned) is an MSYS2 program: <c>msys-2.0.dll</c>
    /// lies beside it, or it is Git for Windows' launcher, a <c>bash.exe</c> or <c>sh.exe</c> in a <c>bin</c> folder
    /// whose parent holds <c>usr\bin\msys-2.0.dll</c> (the launcher passes its command line on to
    /// <c>usr\bin\bash.exe</c> verbatim). Anything else, WSL's <c>System32\bash.exe</c> included, is not.
    /// </summary>
    public static bool IsMsys2(string path, Func<string, bool> fileExists)
    {
        var file = path.Replace('/', '\\');
        if (Parent(file) is not { } folder)
            return false;
        if (fileExists(Join(folder, "msys-2.0.dll")))
            return true;
        var name = LastComponent(file);
        return (name.Equals("bash.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("sh.exe", StringComparison.OrdinalIgnoreCase))
               && LastComponent(folder).Equals("bin", StringComparison.OrdinalIgnoreCase)
               && Parent(folder) is { } root
               && fileExists(Join(root, @"usr\bin\msys-2.0.dll"));
    }

    private static string Join(string folder, string name) => folder.TrimEnd('\\', '/') + "\\" + name;

    private static string? Parent(string path)
    {
        var trimmed = path.TrimEnd('\\', '/');
        var separator = trimmed.LastIndexOfAny(['\\', '/']);
        return separator < 0 ? null : trimmed[..separator];
    }

    private static string LastComponent(string path)
    {
        var trimmed = path.TrimEnd('\\', '/');
        return trimmed[(trimmed.LastIndexOfAny(['\\', '/']) + 1)..];
    }
}
