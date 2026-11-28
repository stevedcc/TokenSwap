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
    /// What <see cref="Resolve"/> reads of the machine: the folder the tswap executable is in, the current folder,
    /// the system and Windows folders, the environment (tswap's own, as CreateProcess searches with it) and the file
    /// system.
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
    /// folder the tswap executable is in, the current folder (unless <c>NoDefaultCurrentDirectoryInExePath</c> is
    /// set), the system folder, <c>&lt;Windows&gt;\System</c>, the Windows folder, then each <c>PATH</c> entry.
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
    /// argument holds <c>\</c> or <c>"</c>, and then (brief T62) <c>MSYS</c> holds a double quote it never closes and an
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
        if (Any(GlobCharacter) && ChangesGlobOption(childVariable("MSYS")))
            return "Refused: MSYS changes the glob option and an argument holds a backslash or double quote; with that option " +
                   "Git Bash (MSYS2) reads backslashes and double quotes in its arguments differently, so tswap can't pass " +
                   $"{What(GlobCharacter)} exactly. Remove the glob option from MSYS for this command, or pass {EnvironmentWay}";
        if (Any(GlobCharacter) && HasUnclosedQuote(childVariable("MSYS")))
            return "Refused: MSYS holds a double quote that is never closed, after which Git Bash (MSYS2) reads past the end of " +
                   "MSYS and may turn the glob option off, and an argument holds a backslash or double quote, so tswap can't pass " +
                   $"{What(GlobCharacter)} exactly. Close the quote in MSYS for this command, or pass {EnvironmentWay}";

        static bool NonAscii(char c) => c > '\u007F';
        if (!IsUtf8Locale(childVariable) && Any(NonAscii))
            return "Refused: the locale (LC_ALL, LC_CTYPE or LANG) is not UTF-8, and in it Git Bash (MSYS2) can read part of a " +
                   $"non-ASCII character as a backslash, so tswap can't pass {What(NonAscii)} exactly. Use a UTF-8 locale for " +
                   $"this command, or pass {EnvironmentWay}";

        static bool PrivateUse(char c) => c is >= '\uF000' and <= '\uF0FF';
        if (Any(PrivateUse))
            return $"Refused: {What(PrivateUse)} holds a character from U+F000 to U+F0FF, which older MSYS2 runtimes turn into " +
                   "ASCII such as a quote or a space before reading the command line. Pass " + EnvironmentWay;

        // Brief T55 amendment 13 (spike round 3), brief T62: MSYS2 cuts a quoted word after 8,186 characters (UTF-8
        // locales) or 8,191 bytes (LANG=C) without an error. glob.cc: MAXPATHLEN is 8192 and the copy loops
        // `while (bufend - bufnext >= MB_CUR_MAX)`, so it keeps 8192 - MB_CUR_MAX characters (8,186 with MB_CUR_MAX 6, 8,191
        // in C); dcrt0.cc runs globify only while globbing is on (and only for a word with a glob or quoting character).
        // 8,000 UTF-8 bytes is under both in every locale R2 lets through. R4 refuses whatever MSYS says, which
        // over-refuses when globbing is off (fail closed).
        static bool TooLong(string argument) => Encoding.UTF8.GetByteCount(argument) > MaxArgumentBytes;
        if (arguments.Any(TooLong))
            return $"Refused: {WhatOf(t => t.ArgIndex - 1 < arguments.Count && TooLong(arguments[t.ArgIndex - 1]))} is longer " +
                   "than 8,000 bytes, and Git Bash (MSYS2) cuts a longer argument without an error, so tswap can't pass it " +
                   "exactly. Pass " + EnvironmentWay;

        return null;
    }

    // Brief T55 amendments 14 and 16 (spike round 3, msys runtime 3.6.10; MiMo round 2 I1), brief T62 (#427): whether
    // MSYS turns globbing off, fail closed. What msys2-runtime does (branch msys2-3.6.12, 50c44b7c03c8,
    // winsup/cygwin/environ.cc):
    // - strbrk (:141-177) skips spaces and tabs. A token whose first '"' comes before its first space or tab is quoted:
    //   the opening '"' is removed, and the token ends at the next '"' not preceded by '\'; a '\"' inside is unescaped,
    //   so a quoted token can span spaces. The text after the closing '"' starts the next token.
    // - parse_options (:218-224) strips at most one "no" or one '-' prefix, then splits at the first '=', or else the
    //   first ':'.
    // The model here is wider than that rule: MSYS is split at spaces and tabs, and each word at every '"' into pieces;
    // every contiguous run of pieces, joined without the quotes, is judged. A run loses any run of leading "no" and '-'
    // prefixes (ignoring case); what is left must be "glob", optionally followed by ':' or '=' and a value. The run
    // changes the option when a prefix was stripped (noglob, -glob) or the separator is there with an empty value
    // (glob:, glob=, the run glob: of glob:"":x). A non-empty value with no prefix (glob:ignorecase, "glob:ignorecase")
    // leaves globbing on. Every token strbrk produces that changes the option begins with such a run that changes it
    // too (the run up to the separator, in one space-separated word, starting at the word's start or after a '"' and
    // ending at a '"' or the word's end, or reaching the separator), so the model never misses one; the converse does
    // not hold. Accepted over-refusals: nonoglob, --glob, no-glob, "no"glob and glob:"x" leave globbing on but count as
    // changed.
    // The scan is linear (brief T62): s is the word without its quotes, and boundary[i] marks 0, s.Length and every
    // position where a '"' stood. P[x] (prefix[x]) is the length of the greedy run of "no" and '-' units at x. Some run
    // starting at a boundary a changes the option exactly when, with g = a + P[a], s[g..g+4] "glob" (case ignored) and
    // e = g + 4, either P[a] > 0 and (boundary[e] or s[e] is ':' or '='), or P[a] == 0, s[e] is ':' or '=' and
    // boundary[e + 1]; the word changes it when that holds for some a. The condition is about a start, not one run: in
    // -"glob:x (s = -glob:x, boundaries 0, 1 and 7) it holds at a = 0 through the run s[0..7], while the run s[0..1]
    // ("-") changes nothing. Greedy stripping is deterministic, "glob" starts with neither 'n' nor '-', and a prefixed
    // run with a separator can always be extended to the word's end, so only the start matters. step (tests only) is
    // called once per position visited.
    private static bool ChangesGlobOption(string? msys) => ChangesGlobOption(msys, null);

    internal static bool ChangesGlobOption(string? msys, Action? step) =>
        msys is not null && msys.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Any(w => WordChangesGlobOption(w, step));

    private static bool WordChangesGlobOption(string word, Action? step)
    {
        var text = new StringBuilder(word.Length);
        var boundary = new bool[word.Length + 1];
        boundary[0] = true;
        foreach (var c in word)
        {
            if (c == '"')
                boundary[text.Length] = true;
            else
                text.Append(c);
        }
        var s = text.ToString();
        boundary[s.Length] = true;

        var prefix = new int[s.Length + 1];
        for (var x = s.Length; x >= 0; x--)
        {
            step?.Invoke();
            prefix[x] = x == s.Length ? 0
                : s[x] == '-' ? 1 + prefix[x + 1]
                : x + 2 <= s.Length && s.AsSpan(x, 2).Equals("no", StringComparison.OrdinalIgnoreCase) ? 2 + prefix[x + 2]
                : 0;
        }

        bool Separator(int i) => i < s.Length && s[i] is ':' or '=';
        for (var a = 0; a <= s.Length; a++)
        {
            if (!boundary[a])
                continue;
            step?.Invoke();
            var g = a + prefix[a];
            if (g + 4 > s.Length || !s.AsSpan(g, 4).Equals("glob", StringComparison.OrdinalIgnoreCase))
                continue;
            var e = g + 4;
            if (prefix[a] > 0 ? boundary[e] || Separator(e) : Separator(e) && boundary[e + 1])
                return true;
        }
        return false;
    }

    /// <summary>
    /// Brief T62 (#427): whether <paramref name="msys"/> holds a double quote that msys2-runtime's <c>strbrk</c> never
    /// finds closed (a port of its quote handling, linear). Spaces and tabs are skipped; a token whose first <c>"</c>
    /// comes before its first space or tab is quoted, and its quote is closed by the next <c>"</c> not preceded by
    /// <c>\</c>. Unclosed, <c>strbrk</c> reads past the end of the copy (<c>buf = sep + 1</c> with <c>sep</c> the NUL), so
    /// what it reads next is undefined. No parity count: <c>"a\"</c> has two quotes and is unclosed, <c>"a\"b"</c> three
    /// and is closed.
    /// </summary>
    internal static bool HasUnclosedQuote(string? msys)
    {
        if (msys is null)
            return false;
        var i = 0;
        while (true)
        {
            while (i < msys.Length && msys[i] is ' ' or '\t')
                i++;
            if (i == msys.Length)
                return false;
            var next = msys.AsSpan(i).IndexOfAny('"', ' ', '\t');
            if (next < 0)
                return false;
            var q = i + next;
            if (msys[q] != '"')
            {
                i = q + 1;
                continue;
            }
            var close = msys.IndexOf('"', q + 1);
            while (close >= 0 && msys[close - 1] == '\\')
                close = msys.IndexOf('"', close + 1);
            if (close < 0)
                return true;
            i = close + 1;
        }
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
