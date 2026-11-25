using System.Text;

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

    /// <summary>
    /// The arguments part of an MSYS2 program's command line: each argument in <c>"</c>, every <c>\</c> and <c>"</c> in it
    /// preceded by one <c>\</c>, joined by one space. By MSYS2's rules (<c>build_argv</c>, <c>quoted</c> and <c>globify</c>
    /// in msys2-runtime's <c>dcrt0.cc</c>) each is one word, never split (CR and LF are inside the quotes), never an
    /// <c>@file</c> (it starts with <c>"</c>) and never expanded, and <c>\\</c> and <c>\"</c> decode to <c>\</c> and
    /// <c>"</c>. Brief T55 spike round 2: every tested value arrived exactly, through Git's launcher and MSYS2's bash.
    /// </summary>
    public static string QuoteArguments(IReadOnlyList<string> arguments) =>
        string.Join(' ', arguments.Select(a => "\"" + a.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""));

    /// <summary>Brief T55 amendment 13 (R4): the longest argument, in UTF-8 bytes, an MSYS2 child gets.</summary>
    public const int MaxArgumentBytes = 8000;

    private const string EnvironmentWay = "the secret in the environment ('run --env PW={{name}} -- <bash.exe> ./script.sh', read as \"$PW\").";

    /// <summary>
    /// The refusal of an MSYS2 child's <paramref name="arguments"/> (argv without the program) that
    /// <see cref="QuoteArguments"/> can't pass exactly, or null. <paramref name="childVariable"/> reads the child's
    /// environment (names ignoring case). In order, the first that finds anything: R1, <c>MSYS</c> changes the glob
    /// option (MSYS2's spellings, amendment 14: <c>noglob</c>, <c>-glob</c>, <c>glob:</c>, <c>glob=</c>, ...) and an
    /// argument holds <c>\</c> or <c>"</c>; R2, the locale (the first non-empty of <c>LC_ALL</c>, <c>LC_CTYPE</c>,
    /// <c>LANG</c>) is set and is not <c>C</c>, <c>POSIX</c> or a UTF-8 charset, and an argument holds a character above
    /// U+007F; R3, an argument holds a character from U+F000 to U+F0FF (older runtimes turn them into ASCII); R4, an
    /// argument is longer than <see cref="MaxArgumentBytes"/> bytes in UTF-8 (MSYS2 cuts a longer quoted word without an
    /// error). The text names the tokens whose substituted text holds what the rule found, for R4 the tokens in a
    /// too-long argument (<paramref name="tokens"/>, whose <c>ArgIndex</c> counts the program as 0, so a token in the
    /// program is never named), in argv order and each once, and never a value, a variable's value or the character.
    /// </summary>
    public static string? Refusal(IReadOnlyList<string> arguments, IReadOnlyList<Validation.SubstitutedToken> tokens,
        Func<string, string?> childVariable)
    {
        string What(Func<char, bool> found) => WhatOf(t => t.Value.Any(found));
        string WhatOf(Func<Validation.SubstitutedToken, bool> found)
        {
            var named = tokens.Where(t => t.ArgIndex > 0 && found(t))
                .OrderBy(t => t.ArgIndex)
                .Select(t => t.IsFile ? $"'{{{{@{Validation.Printable(t.Name)}}}}}'" : $"'{t.Name}'")
                .Distinct(StringComparer.Ordinal)
                .ToList();
            return named.Count == 0 ? "an argument" : "the argument(s) from " + string.Join(", ", named);
        }
        bool Any(Func<char, bool> found) => arguments.Any(a => a.Any(found));

        static bool GlobCharacter(char c) => c is '\\' or '"';
        if (ChangesGlobOption(childVariable("MSYS")) && Any(GlobCharacter))
            return "Refused: MSYS changes the glob option and an argument holds a backslash or double quote; with that option " +
                   "Git Bash (MSYS2) reads backslashes and double quotes in its arguments differently, so tswap can't pass " +
                   $"{What(GlobCharacter)} exactly. Remove the glob option from MSYS for this command, or pass {EnvironmentWay}";

        static bool NonAscii(char c) => c > '\u007F';
        if (!IsUtf8Locale(childVariable) && Any(NonAscii))
            return "Refused: the locale (LC_ALL, LC_CTYPE or LANG) is not UTF-8, and in it Git Bash (MSYS2) can read part of a " +
                   $"non-ASCII character as a backslash, so tswap can't pass {What(NonAscii)} exactly. Use a UTF-8 locale for " +
                   $"this command, or pass {EnvironmentWay}";

        static bool PrivateUse(char c) => c is >= '\uF000' and <= '\uF0FF';
        if (Any(PrivateUse))
            return $"Refused: {What(PrivateUse)} holds a character from U+F000 to U+F0FF, which older MSYS2 runtimes turn into " +
                   "ASCII such as a quote or a space before reading the command line. Pass " + EnvironmentWay;

        // Brief T55 amendment 13 (spike round 3): MSYS2 cuts a quoted word after 8,186 characters (UTF-8 locales) or
        // 8,191 bytes (LANG=C) without an error; 8,000 UTF-8 bytes is under both in every locale R2 lets through.
        static bool TooLong(string argument) => Encoding.UTF8.GetByteCount(argument) > MaxArgumentBytes;
        if (arguments.Any(TooLong))
            return $"Refused: {WhatOf(t => t.ArgIndex - 1 < arguments.Count && TooLong(arguments[t.ArgIndex - 1]))} is longer " +
                   "than 8,000 bytes, and Git Bash (MSYS2) cuts a longer argument without an error, so tswap can't pass it " +
                   "exactly. Pass " + EnvironmentWay;

        return null;
    }

    // Brief T55 amendment 14 (spike round 3, msys runtime 3.6.10): whether MSYS turns globbing off, fail closed. Each word
    // (split at spaces and tabs) loses its double quotes, then any run of leading "no" and "-" prefixes (ignoring case);
    // what is left must be "glob", optionally followed by ':' or '=' and a value. The word changes the option when a
    // prefix was stripped (noglob, -glob) or the separator is there with an empty value (glob:, glob=, glob:""). A
    // non-empty value with no prefix (glob:ignorecase, glob:off) leaves globbing on. Accepted over-refusals: nonoglob,
    // --glob, no-glob and "no"glob leave globbing on but count as changed.
    private static bool ChangesGlobOption(string? msys) =>
        msys is not null && msys.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Any(WordChangesGlobOption);

    private static bool WordChangesGlobOption(string word)
    {
        var rest = word.Replace("\"", "").AsSpan();
        var prefixed = false;
        while (true)
        {
            if (rest.StartsWith("no", StringComparison.OrdinalIgnoreCase))
                rest = rest[2..];
            else if (rest.StartsWith('-'))
                rest = rest[1..];
            else
                break;
            prefixed = true;
        }
        if (!rest.StartsWith("glob", StringComparison.OrdinalIgnoreCase))
            return false;
        rest = rest[4..];
        if (rest.IsEmpty)
            return prefixed;
        if (rest[0] is not (':' or '='))
            return false;
        return prefixed || rest.Length == 1;
    }

    // The runtime's locale: the first non-empty of LC_ALL, LC_CTYPE, LANG; unset, C and POSIX convert as UTF-8. A
    // locale without a charset part is not UTF-8 (spike round 2: de_DE converts as ISO-8859-1).
    private static bool IsUtf8Locale(Func<string, string?> childVariable)
    {
        var locale = new[] { "LC_ALL", "LC_CTYPE", "LANG" }.Select(childVariable).FirstOrDefault(v => !string.IsNullOrEmpty(v));
        if (locale is null or "C" or "POSIX")
            return true;
        var dot = locale.IndexOf('.');
        if (dot < 0)
            return false;
        var charset = locale[(dot + 1)..];
        var at = charset.IndexOf('@');
        if (at >= 0)
            charset = charset[..at];
        return charset.Equals("UTF-8", StringComparison.OrdinalIgnoreCase) || charset.Equals("utf8", StringComparison.OrdinalIgnoreCase);
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
