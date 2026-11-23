using System.Text.RegularExpressions;

namespace TswapCore;

public static class Validation
{
    // Fix round 1, B: '{{name:previous}}' names the value the last rotation replaced. ':' is not a
    // name character (ValidNameRegex), so the suffix can't collide with a secret name.
    public static readonly Regex TokenRegex = new(@"\{\{([a-zA-Z0-9_-]+(?::previous)?)\}\}");

    // Fix round 3: any other '{{name:suffix}}' is a typo, never passed through as literal text.
    private static readonly Regex SuffixedTokenRegex = new(@"\{\{([a-zA-Z0-9_-]+:[^{}]*)\}\}");

    /// <summary>Throws for a <c>{{name:suffix}}</c> token whose suffix is not <c>previous</c>, naming it.</summary>
    public static void ThrowIfUnknownTokenSuffix(string command)
    {
        foreach (Match m in SuffixedTokenRegex.Matches(command))
            if (!m.Groups[1].Value.EndsWith(":previous", StringComparison.Ordinal) || m.Groups[1].Value.Count(ch => ch == ':') != 1)
                throw new TswapException(
                    $"Unknown token '{{{{{m.Groups[1].Value}}}}}': the only suffix is ':previous' (the value the last rotation replaced).");
    }

    // A '{{…}}' without braces inside that starts with a secret name followed by a dot. Anything else with a dot
    // ('{{.State.Pid}}', '{{range .items}}', '{{ .Name }}', a '{{@file}}' token) is left alone, as before #311.
    private static readonly Regex DottedTokenRegex = new(@"\{\{([a-zA-Z0-9_-]+\.[^{}]*)\}\}");

    /// <summary>
    /// #311 (owner decision A): commands never substitute fields. Throws for a <c>{{…}}</c> token that starts
    /// with a secret name and a dot: <c>{{NAME.FIELD}}</c> (a valid field name) with the field message, any
    /// other such shape (<c>{{a.b.c}}</c>, <c>{{x.}}</c>, <c>{{a.B}}</c>, <c>{{a.b:previous}}</c>) as not a valid
    /// token. Final review I1 (ruling): text with no secret name right after <c>{{</c> (<c>{{.x}}</c>, Go
    /// templates such as <c>{{.State.Pid}}</c> or <c>{{range .items}}</c>) passes through literally.
    /// </summary>
    public static void ThrowIfFieldOrMalformedToken(string command)
    {
        foreach (Match m in DottedTokenRegex.Matches(command))
        {
            var inner = m.Groups[1].Value;
            var shown = Printable(m.Value);
            var dot = inner.IndexOf('.');
            var name = inner[..dot];
            var field = inner[(dot + 1)..];
            if (inner.Count(ch => ch == '.') == 1 && ValidNameRegex.IsMatch(name) && IsFieldName(field))
                throw new TswapException(FieldTokenMessage(shown, name));
            throw new TswapException(
                $"'{shown}' is not a valid token: a token is {{{{NAME}}}} or {{{{NAME:previous}}}}, " +
                "and fields aren't substituted into commands.");
        }
    }

    /// <summary>Text echoed in a message: anything outside printable ASCII becomes '?' (no terminal or log injection).</summary>
    public static string Printable(string text) => Regex.Replace(text, @"[^\x20-\x7E]", "?");

    /// <summary>True when <paramref name="text"/> is a valid field name.</summary>
    public static bool IsFieldName(string text) => TswapCore.Fields.FieldRules.ValidateName(text) is null;

    /// <summary>The refusal for a field named where a command (token or marker) would substitute it.</summary>
    public static string FieldTokenMessage(string shown, string name) =>
        $"'{shown}' is a field: fields aren't substituted into commands. " +
        $"Read it with 'tswap field show {name}' and write the value into the command.";

    private static readonly Regex ValidNameRegex = new(@"^[a-zA-Z0-9_-]+$");
    private const int MaxNameLength = 64;
    private const int MaxGeneratedLength = 4096;
    private const int MaxIngestedLength = 65536;

    private static readonly HashSet<string> BlockedCommands = new(StringComparer.OrdinalIgnoreCase)
        { "echo", "printf", "cat", "env", "printenv", "set", "tee" };

    /// <summary>
    /// Validate a secret name: must be non-empty and contain only [a-zA-Z0-9_-].
    /// Throws a user-friendly exception on failure.
    /// </summary>
    public static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name))
            throw new Exception("Secret name must not be empty.");
        if (name.Length > MaxNameLength)
            throw new Exception($"Secret name is too long ({name.Length} chars). Maximum allowed is {MaxNameLength} characters.");
        if (!ValidNameRegex.IsMatch(name))
        {
            // Escape the user-supplied value before embedding in the message to prevent
            // terminal/log injection via control characters or ANSI escape sequences.
            var safe = Regex.Replace(name, @"[^\x20-\x7E]", "?");
            throw new Exception($"Invalid secret name '{safe}'. Names must contain only letters, digits, underscores, and hyphens ([a-zA-Z0-9_-]).");
        }
    }

    /// <summary>
    /// Brief T16-S2b (owner decision 5): true when <paramref name="value"/>'s last character is
    /// whitespace (<see cref="char.IsWhiteSpace(char)"/>), so also for a value of whitespace only;
    /// false for an empty value. <c>add</c> warns about such a value (usually a paste mistake).
    /// </summary>
    public static bool EndsInWhitespace(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Length > 0 && char.IsWhiteSpace(value[^1]);
    }

    /// <summary>
    /// Brief T21 (#314): values shorter than this many characters (UTF-16 code units, the unit
    /// <c>create</c>'s length uses) get a warning when they are stored. Brief T30: <c>run</c> and
    /// <c>redact</c> match such a value, in every form, only where it stands as a whole word or number
    /// (<see cref="Fingerprints.TokenBoundary"/>), and longer values anywhere; <c>tocomment</c>'s own
    /// boundary applies to every value. One threshold for the warning and the matching.
    /// </summary>
    public const int ShortValueLength = 8;

    /// <summary>Brief T21: true when <paramref name="value"/> is shorter than <see cref="ShortValueLength"/>.</summary>
    public static bool IsShortValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Length < ShortValueLength;
    }

    /// <summary>
    /// Validate a requested secret length: must be between 1 and 4096.
    /// Throws a user-friendly exception on failure.
    /// </summary>
    public static void ValidateLength(int length)
    {
        if (length < 1)
            throw new Exception($"Secret length must be at least 1 character (got {length}).");
        if (length > MaxGeneratedLength)
            throw new Exception($"Secret length must be at most {MaxGeneratedLength} characters (got {length}).");
    }

    /// <summary>
    /// Read from <paramref name="reader"/> up to <see cref="MaxIngestedLength"/> characters,
    /// then trim trailing whitespace. Throws immediately if the stream exceeds the limit,
    /// so the process never allocates more than MaxIngestedLength + 1 characters from stdin.
    /// </summary>
    public static string ReadBoundedStdin(TextReader reader)
    {
        var buf = new char[MaxIngestedLength + 1];
        int total = 0;
        int read;
        while ((read = reader.Read(buf, total, buf.Length - total)) > 0)
        {
            total += read;
            if (total > MaxIngestedLength)
                throw new Exception($"Secret value is too long. Maximum allowed is {MaxIngestedLength} characters.");
        }
        var value = new string(buf, 0, total).TrimEnd();
        if (value.Contains('\0'))
            throw new Exception(
                "Secret value contains a NUL byte (\\0), which cannot be used as a " +
                "process argument. Re-ingest the secret without embedded NUL bytes.");
        return value;
    }

    /// <summary>
    /// Extract distinct token names from a command string.
    /// </summary>
    public static List<string> ExtractTokens(string command)
    {
        return TokenRegex.Matches(command)
            .Select(m => m.Groups[1].Value)
            .Distinct()
            .ToList();
    }

    // Issue #251: '{{@path}}' hands the child a filled copy of the file. '@' can't start a secret
    // name, so the two token kinds never collide.
    public static readonly Regex FileTokenRegex = new(@"\{\{@([^{}]+)\}\}");

    // Both token kinds, for the one substitution pass over the command as typed.
    private static readonly Regex AnyTokenRegex = new(@"\{\{(?:@([^{}]+)|([a-zA-Z0-9_-]+(?::previous)?))\}\}");

    /// <summary>The distinct paths of the <c>{{@path}}</c> tokens in <paramref name="command"/>, in order.</summary>
    public static IReadOnlyList<string> ExtractFileTokens(string command) =>
        FileTokenRegex.Matches(command).Select(m => m.Groups[1].Value).Distinct(StringComparer.Ordinal).ToList();

    /// <summary>
    /// Scans every <c>{{@</c> in <paramref name="command"/> (<see cref="FileTokenRegex"/> can't see a
    /// malformed one) and throws, naming the token, for an empty <c>{{@}}</c>, one with nested or
    /// unbalanced braces, or one that is never closed.
    /// </summary>
    public static void ValidateFileTokens(string command)
    {
        for (var start = command.IndexOf("{{@", StringComparison.Ordinal); start >= 0;
             start = command.IndexOf("{{@", start + 3, StringComparison.Ordinal))
        {
            var close = command.IndexOf("}}", start + 3, StringComparison.Ordinal);
            if (close < 0)
                throw MalformedFileToken(command[start..], "it is never closed with '}}'");
            var token = command[start..(close + 2)];
            var path = command[(start + 3)..close];
            if (path.Length == 0)
                throw MalformedFileToken(token, "it names no file");
            if (path.IndexOfAny(['{', '}']) >= 0)
                throw MalformedFileToken(token, "it has nested or unbalanced braces");
            if (close + 2 < command.Length && command[close + 2] == '}')
                throw MalformedFileToken(token + "}", "it has unbalanced braces");
        }
    }

    private static TswapException MalformedFileToken(string token, string reason) =>
        new($"Malformed file token '{token}': {reason}. A file token is {{{{@path}}}}, the path without braces.");

    // Issue #251: with a {{@file}} token, any word of the command that prints, encodes or copies a
    // file refuses (the filled copy is data for a tool, never something to show). A shallow guard
    // (docs/security-model.md): it refuses the obvious one-step printers, nothing more.
    private static readonly HashSet<string> FilePrinters = new(StringComparer.OrdinalIgnoreCase)
    {
        "cat", "echo", "printf", "tee", "base64", "base32", "basenc", "xxd", "od", "hexdump", "hd", "strings",
        "uuencode", "iconv", "cp", "mv", "dd", "rsync", "scp", "tar", "zip", "gzip", "bzip2", "xz",
        "zstd", "openssl", "gpg", "less", "more", "head", "tail", "nl", "sort", "uniq", "rev", "tac", "split", "ln",
        "certutil",
    };

    // Copiers refused only as the program (argv[0], or the command a wrapper or find -exec runs): as an
    // argument the word is common and harmless ('helm install app ./chart', owner decision 2026-11-07).
    private static readonly HashSet<string> FileProgramPrinters = new(StringComparer.OrdinalIgnoreCase) { "install" };

    /// <summary>
    /// Issue #251: the extra check for a command with a <c>{{@file}}</c> token. Refused: a file token as
    /// the program; <c>install</c> as the program, also behind simple wrappers (<c>nice -n 5 install</c>)
    /// and as the command <c>find -exec</c> runs;
    /// and any word (the basename of each argument as typed, a file token counting as its
    /// file's basename) that is a printer, encoder or copier, in the existing blocklist, or a shell or
    /// interpreter (sed included). Null when allowed.
    /// </summary>
    public static BlockedInvocation? GetFileTokenRefusal(IReadOnlyList<string> argv)
    {
        if (argv.Count == 0)
            return null;
        if (FileTokenRegex.IsMatch(argv[0]))
            return new(argv[0], "A {{@file}} token can't be the program: the file is data for a tool, never a program to run.");
        foreach (var program in ProgramWords(argv))
            if (FileProgramPrinters.Contains(program))
                return new(program, $"'{program}' copies files, which would expose the filled copy of a {{{{@file}}}} token. " +
                    "The file is data for a tool, never something to copy.");
        foreach (var arg in argv)
        {
            var files = FileTokenRegex.Matches(arg).Select(m => ProgramName(m.Groups[1].Value));
            var words = FileTokenRegex.Match(arg) is { Success: true } whole && whole.Length == arg.Length
                ? files
                : files.Prepend(ProgramName(arg));
            foreach (var word in words)
            {
                if (FilePrinters.Contains(word) || BlockedCommands.Contains(word))
                    return new(word, $"'{word}' prints, encodes or copies files, which would expose the filled copy of a {{{{@file}}}} token. " +
                        FileTokenWayOut(word));
                if (IsInterpreter(word) || word.Equals("sed", StringComparison.OrdinalIgnoreCase))
                    return new(word, $"'{word}' is a shell or interpreter, which can print the filled copy of a {{{{@file}}}} token past redaction. " +
                        FileTokenWayOut(word));
            }
        }
        return null;
    }

    // argv[0] and, through simple wrappers (nice, timeout, sudo, ...: their options and leading
    // positional skipped as CheckWrapper does) and find's -exec family, the command each runs. Tools
    // with subcommands (docker, npm, ...) end the walk: their later words aren't a program on this machine.
    // Normalised (ProgramName), for GetFileTokenRefusal; ProgramPositions keeps the raw word (brief T47, A20).
    internal static IEnumerable<string> ProgramWords(IReadOnlyList<string> argv) =>
        ProgramPositions(argv).Select(i => ProgramName(argv[i]));

    /// <summary>Brief T47 (A20): the walk of <see cref="ProgramWords"/>, as positions in <paramref name="argv"/>.</summary>
    internal static IEnumerable<int> ProgramPositions(IReadOnlyList<string> argv)
    {
        var i = 0;
        while (i < argv.Count)
        {
            var program = ProgramName(argv[i]);
            yield return i;
            if (program.Equals("find", StringComparison.OrdinalIgnoreCase))
            {
                for (var j = i + 1; j < argv.Count; j++)
                    if (FindExecOptions.Contains(argv[j]))
                        foreach (var position in ProgramPositions(argv.Skip(j + 1).TakeWhile(a => a is not (";" or "+")).ToList()))
                            yield return j + 1 + position;
                yield break;
            }
            if (!Wrappers.Contains(program) || SubcommandTools.Contains(program))
                yield break;
            WrapperValued.TryGetValue(program, out var valued);
            var skipLeading = WrapperLeadingPositional.Contains(program);
            var next = -1;
            for (var j = i + 1; j < argv.Count && next < 0; j++)
            {
                var arg = argv[j];
                if (arg == "--")
                    continue;
                if (arg.StartsWith('-'))
                {
                    if (valued is not null && valued.Contains(arg, StringComparer.Ordinal))
                        j++;
                    continue;
                }
                if (arg.Contains('=') && !arg.StartsWith('/') && program.Equals("sudo", StringComparison.OrdinalIgnoreCase))
                    continue; // sudo VAR=value
                if (skipLeading)
                {
                    skipLeading = false;
                    continue;
                }
                next = j;
            }
            if (next < 0)
                yield break;
            i = next;
        }
    }

    /// <summary>
    /// Brief T47: a token <c>run</c> substituted into argv: a secret token (<c>name</c> or <c>name:previous</c>) or,
    /// with <paramref name="IsFile"/>, a <c>{{@path}}</c> token (<paramref name="Name"/> is the path as typed); the
    /// argv index it went into, and the text it was replaced with (the value, or the filled copy's path).
    /// </summary>
    public readonly record struct SubstitutedToken(string Name, int ArgIndex, string Value, bool IsFile = false);

    /// <summary>
    /// Brief T47: every token of <paramref name="args"/> (the command as typed) that
    /// <see cref="SubstituteAllTokensInArgs"/> replaces, in argv order, with the text it is replaced with.
    /// </summary>
    public static IReadOnlyList<SubstitutedToken> SubstitutedTokens(IReadOnlyList<string> args,
        IReadOnlyDictionary<string, string> secretValues, IReadOnlyDictionary<string, string> filePaths)
    {
        List<SubstitutedToken> tokens = [];
        for (var i = 0; i < args.Count; i++)
            foreach (Match m in AnyTokenRegex.Matches(args[i]))
            {
                if (m.Groups[1].Success && filePaths.TryGetValue(m.Groups[1].Value, out var path))
                    tokens.Add(new(m.Groups[1].Value, i, path, IsFile: true));
                else if (m.Groups[2].Success && secretValues.TryGetValue(m.Groups[2].Value, out var value))
                    tokens.Add(new(m.Groups[2].Value, i, value));
            }
        return tokens;
    }

    // Brief T47 (A3): what cmd.exe interprets in a batch file's arguments, which it parses again at launch.
    private static readonly System.Buffers.SearchValues<char> BatchCharacters =
        System.Buffers.SearchValues.Create("\"&|<>^%!()\r\n");

    private const string BatchCharacterList = "one of \" & | < > ^ % ! ( ) or a line break";

    /// <summary>
    /// Brief T47 (A4): whether <paramref name="program"/> starts as a batch file or is cmd itself: its last component,
    /// normalised as Windows does (<see cref="WindowsFileName"/>: a drive prefix and trailing dots and spaces dropped,
    /// and a <c>:stream</c> suffix dropped only after a name ending in <c>.exe</c>, <c>.cmd</c>, <c>.bat</c> or
    /// <c>.com</c>, reviews F15 and F17), ends in <c>.cmd</c> or <c>.bat</c>, or is <c>cmd</c> (<c>cmd.exe</c>), ignoring
    /// case.
    /// </summary>
    public static bool IsBatchTarget(string program)
    {
        var name = WindowsFileName(program);
        return name.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
            || ProgramName(name).Equals("cmd", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Brief T47 (A13, A20): the refusal of a command line that hands a batch file (or cmd) a substituted text holding
    /// a character cmd.exe interprets (batch files re-parse arguments), or null. Review fix F11: every word of the
    /// command, raw and trimmed, is tested with <see cref="IsBatchTarget"/>, whatever program or position it is in.
    /// With a batch target, every substituted token counts (failing closed: any program's arguments can reach it). Names every refused token in argv order, never a value or which character.
    /// </summary>
    /// <remarks>
    /// The given name is checked, not one resolved through PATH and PATHEXT: neither of run's start paths (RedactingPty's
    /// FallbackPty through .NET's process start, WindowsPty through CreateProcessW with no application name) starts a
    /// batch file from a name without its extension; CreateProcess appends only ".exe". If a start path ever resolves
    /// PATHEXT, this check must resolve the name the same way first, or it fails open.
    /// </remarks>
    public static string? BatchArgumentRefusal(IReadOnlyList<string> argv, IReadOnlyList<SubstitutedToken> tokens)
    {
        if (!BatchTargets(argv).Any())
            return null;
        var refused = tokens.Where(t => t.Value.AsSpan().ContainsAny(BatchCharacters))
            .OrderBy(t => t.ArgIndex)
            .DistinctBy(t => (t.Name, t.IsFile))
            .ToList();
        if (refused.Count == 0)
            return null;

        // Controller ruling 3: a copy's path is the temporary folder and the source's base name; say which holds the
        // character, and never print the folder's path.
        var files = refused.Where(t => t.IsFile).ToList();
        var nameToBlame = files.Any(t => FileNamePart(t.Value).AsSpan().ContainsAny(BatchCharacters));
        var folderToBlame = files.Any(t => t.Value[..^FileNamePart(t.Value).Length].AsSpan().ContainsAny(BatchCharacters));
        var secrets = refused.Where(t => !t.IsFile).ToList();
        if (secrets.Count == 0)
        {
            var copies = $"Refused: tswap won't pass the copy of {string.Join(", ", refused.Select(t => $"'{Printable(t.Name)}'"))} to a batch file: ";
            return folderToBlame
                ? copies + $"the temporary folder's path (%TEMP%) contains characters cmd.exe interprets ({BatchCharacterList}). " +
                  "Set TMP and TEMP to a folder without them, or use a PowerShell script." + (nameToBlame ? " Rename the file." : "")
                : copies + $"its name contains characters cmd.exe interprets ({BatchCharacterList}). Rename the file.";
        }

        var names = string.Join(", ", refused.Select(t => t.IsFile ? $"'{{{{@{Printable(t.Name)}}}}}'" : $"'{t.Name}'"));
        var first = secrets[0].Name;
        var message =
            $"Refused: tswap won't pass secret(s) {names} to a batch file. cmd.exe parses a batch file's arguments again, " +
            $"and their values contain characters it interprets ({BatchCharacterList}; tswap's generated values often do). " +
            $"Use a PowerShell script ('run powershell -File .\\script.ps1 {{{{{first}}}}}', read as $args[0]), or the " +
            $"environment ('run --env PW={{{{{first}}}}} deploy.cmd', read with setlocal EnableDelayedExpansion as !PW!).";
        return message + (nameToBlame ? " Rename the file." : "") +
               (folderToBlame ? " The temporary folder's path (%TEMP%) contains such characters too: set TMP and TEMP to a folder without them." : "");
    }

    // The last component of a path, either separator.
    private static string FileNamePart(string path) => path[(path.LastIndexOfAny(['/', '\\']) + 1)..];

    // Review fix F11 (replaces the program walk and F10's PowerShell rule): every word of the command, raw and
    // trimmed, that is a batch target, whatever program or position it is in. Which program starts a word can't be
    // told from the text (Windows normalises "pwsh.exe.", "pwsh.exe::$DATA", 8.3 names; an unknown wrapper runs its
    // arguments), so failing closed: a batch file's name passed as plain data next to such a secret is refused too.
    private static IEnumerable<int> BatchTargets(IReadOnlyList<string> argv) =>
        Enumerable.Range(0, argv.Count).Where(i => IsBatchTarget(argv[i].Trim()));

    private static string FileTokenWayOut(string word) =>
        $"With a {{{{@file}}}} token no word of the command may be '{word}': rename the file if that is its name, " +
        "or pass the secret with a plain {{name}} token instead.";

    /// <summary>
    /// Substitutes both token kinds in one pass over each argument as typed (issue #251): a
    /// <c>{{name}}</c> gets its raw value from <paramref name="secretValues"/>, a <c>{{@path}}</c> the
    /// filled copy's path from <paramref name="filePaths"/>. Substituted text is never scanned again (a
    /// value containing <c>{{@…}}</c> stays plain text). Values are not shell-quoted: the program is
    /// executed directly, never through a shell. Null and NUL-containing values are refused
    /// (<see cref="TswapException"/>): native APIs would silently truncate them.
    /// </summary>
    public static string[] SubstituteAllTokensInArgs(string[] args, IReadOnlyDictionary<string, string> secretValues,
        IReadOnlyDictionary<string, string> filePaths)
    {
        foreach (var (token, value) in secretValues)
            if (value is null || value.Contains('\0'))
                throw new TswapException(
                    $"Secret '{token}' has a null or NUL-containing value, which cannot be " +
                    "passed as a process argument. Re-ingest the secret with a valid value.");

        return args.Select(arg => AnyTokenRegex.Replace(arg, m =>
            m.Groups[1].Success
                ? filePaths.TryGetValue(m.Groups[1].Value, out var path) ? path : m.Value
                : secretValues.TryGetValue(m.Groups[2].Value, out var value) ? value : m.Value)).ToArray();
    }

    /// <summary>
    /// Check if a base command is blocked for exfiltration prevention.
    /// Returns the blocked command name or null if allowed. Compared by basename, so
    /// <c>/bin/echo</c> counts as <c>echo</c>.
    /// </summary>
    public static string? GetBlockedCommand(string baseCommand)
    {
        var name = ProgramName(baseCommand);
        return BlockedCommands.Contains(name) ? name.ToLowerInvariant() : null;
    }

    /// <summary>A refused <c>run</c> command line: the program and why.</summary>
    public sealed record BlockedInvocation(string Program, string Reason);

    // Issue #105: a shell or interpreter given inline code can transform a substituted secret
    // (split, reverse, encode) before printing it, which run's output redaction can't recognise.
    // So code must come from a file: inline-code options, code from stdin, and programs whose
    // ordinary argument is code are refused. Still a shallow blocklist (docs/security-model.md §Threat model and non-goals):
    // a script file or any other program can misuse a secret it is given.
    // An interpreter's command-line syntax, as far as the check needs it.
    //   Inline:     short option letters that mean "code follows" (in a cluster too: -ec, -nle).
    //   InlineLong: long options that mean the same (--eval, --command).
    //   Valued:     short option letters that take a value, attached (-Ilib, -mcalendar) or as
    //               the next argument (-o pipefail); the rest of the cluster is that value, so
    //               its letters are never read as flags.
    //   ValuedLong: long options whose value is the next argument (--rcfile rc).
    //   EndsOptions: an option that ends option parsing like a script does (python -m module).
    //   Plus:       '+' options exist (bash +o posix).
    //   AttachedOnly: letters whose (optional) value can only be attached (julia -O3, perl -xdir):
    //               the rest of the cluster is the value, never the next argument.
    //   ScriptOption: a letter whose value is the script file (expect -f script.exp), checked
    //               like a script name (stdin is refused).
    private sealed record InterpreterSyntax(string Inline, string[] InlineLong, string Valued,
        string[] ValuedLong, string? EndsOptions = null, bool Plus = false, string AttachedOnly = "",
        string ScriptOption = "");

    private static readonly InterpreterSyntax ShellSyntax = new("cs", [], "oO", ["--rcfile", "--init-file"], Plus: true);

    private static readonly Dictionary<string, InterpreterSyntax> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sh"] = ShellSyntax, ["bash"] = ShellSyntax, ["zsh"] = ShellSyntax, ["dash"] = ShellSyntax,
        ["ksh"] = ShellSyntax, ["mksh"] = ShellSyntax, ["ash"] = ShellSyntax, ["tcsh"] = ShellSyntax,
        ["csh"] = ShellSyntax,
        ["fish"] = ShellSyntax with { InlineLong = ["--command"] },
        ["perl"] = new("eE", [], "IMm", [], AttachedOnly: "x"),
        ["ruby"] = new("e", [], "IrCE", []),
        ["node"] = new("ep", ["--eval", "--print"], "rC", ["--require", "--import", "--loader", "--conditions"]),
        ["nodejs"] = new("ep", ["--eval", "--print"], "rC", ["--require", "--import", "--loader", "--conditions"]),
        ["bun"] = new("ep", ["--eval", "--print"], "r", ["--preload", "--cwd", "--config"]),
        ["php"] = new("rBRE", [], "cdzt", []),
        ["lua"] = new("e", [], "l", []),
        ["julia"] = new("eE", ["--eval", "--print"], "JLtpC",
            ["--sysimage", "--load", "--threads", "--procs", "--cpu-target", "--machine-file", "--gcthreads"],
            AttachedOnly: "Og"),
        ["rscript"] = new("e", [], "", []),
        ["osascript"] = new("e", [], "ls", []),
        ["expect"] = new("c", [], "", [], ScriptOption: "f"),
        ["tclsh"] = new("", [], "", []),
        ["wish"] = new("", [], "", []),
        ["jshell"] = new("", [], "", []),
    };

    private static readonly InterpreterSyntax PythonSyntax = new("c", [], "WXQ", [], EndsOptions: "m");
    private static readonly Regex PythonName = new(@"^(python|pypy)[0-9.]*t?$", RegexOptions.IgnoreCase);

    // Their normal argument is code or a command line, or they run it through sh -c internally.
    private static readonly HashSet<string> CodeRunners = new(StringComparer.OrdinalIgnoreCase)
        { "xargs", "busybox", "watch", "parallel", "script" };

    private static readonly HashSet<string> AwkNames = new(StringComparer.OrdinalIgnoreCase)
        { "awk", "gawk", "mawk", "nawk" };

    private static readonly HashSet<string> FindExecOptions = new(StringComparer.Ordinal)
        { "-exec", "-execdir", "-ok", "-okdir" };

    // Run a command that follows them: the check applies to that command. Includes launchers
    // (uv run, poetry run, npx, bundle exec) and container/remote runners (docker run, kubectl exec).
    private static readonly HashSet<string> Wrappers = new(StringComparer.OrdinalIgnoreCase)
        { "nohup", "nice", "timeout", "stdbuf", "setsid", "time", "command", "sudo", "doas",
          "ionice", "chrt", "taskset", "flock", "unbuffer", "exec", "strace", "ltrace", "valgrind",
          "xvfb-run", "dbus-run-session", "systemd-run", "firejail", "bwrap", "unshare", "nsenter",
          "chroot", "caffeinate", "uv", "uvx", "poetry", "pipenv", "pdm", "hatch", "conda", "pixi",
          "npx", "pnpx", "bunx", "npm", "pnpm", "yarn", "bundle", "docker", "podman", "nerdctl",
          "kubectl", "oc", "lxc", "incus", "flatpak", "snap", "machinectl", "toolbox", "distrobox", "wsl" };

    // Run their -c/--command argument through the target user's shell.
    private static readonly HashSet<string> ShellAsUser = new(StringComparer.OrdinalIgnoreCase)
        { "su", "runuser" };

    // ssh options that take a value; a non-option argument after the host is a remote command.
    private const string SshValued = "BbcDEeFIiJLlmOoPpQRSWw";

    // Script paths that are really stdin.
    private static readonly HashSet<string> StdinScripts = new(StringComparer.Ordinal)
        { "-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0" };

    private const string WayOut =
        "Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' " +
        "(the script reads the value as $1).";

    // Brief T35 (#348.3): Windows has no ./script.sh or $1. A .ps1 run by Windows PowerShell (on every Windows),
    // never a .cmd, whose cmd.exe would parse a secret's & | ^ % " again.
    private const string WindowsWayOut =
        "Put the commands in a script file and run that instead, e.g. 'run powershell -File .\\script.ps1 {{secret}}' " +
        "(the script reads the value as $args[0]; in PowerShell quote the token: '{{secret}}').";

    /// <summary>
    /// Brief T35: the way out of an inline-code refusal. <see cref="GetBlockedInvocation"/> always appends the Unix
    /// sentence (<paramref name="windows"/> false) whole, at the end of the reason; <c>run</c> swaps it on Windows.
    /// </summary>
    public static string WayOutFor(bool windows) => windows ? WindowsWayOut : WayOut;

    /// <summary>
    /// Checks a whole <c>run</c> command line (issue #105). Returns null when allowed, or the
    /// program and the reason when refused: the existing blocklist (by basename), a shell or
    /// interpreter given inline code or code from stdin, a program whose argument is code
    /// (awk without -f, xargs, busybox, watch, parallel, script), find -exec and ssh running
    /// such a command, and any of these behind a wrapper or launcher (timeout, sudo, uv run,
    /// docker run, kubectl exec ...).
    /// </summary>
    public static BlockedInvocation? GetBlockedInvocation(IReadOnlyList<string> argv)
    {
        if (argv.Count == 0)
            return null;

        var program = ProgramName(argv[0]);
        var args = argv.Skip(1).ToList();

        if (BlockedCommands.Contains(program))
            return new(program, $"'{program}' would expose secret values. The 'run' command is for programs that *use* secrets, not display them.");

        if (Wrappers.Contains(program))
            return CheckWrapper(program, args);

        if (ShellAsUser.Contains(program))
        {
            // runuser [-u user] cmd runs cmd: after the -c check below, treat it like a wrapper.
            // su/runuser -c runs shell code; runuser -u user -- cmd runs cmd (checked like a wrapper).
            // Only su's own options count: scanning stops at '--' (runuser -u u -- tar -czf ...).
            var own = args.TakeWhile(a => a != "--").ToList();
            var command = own.FirstOrDefault(a => a is "-c" or "--command" or "--session-command"
                || a.StartsWith("--command=", StringComparison.Ordinal) || a.StartsWith("--session-command=", StringComparison.Ordinal)
                || (a.StartsWith('-') && !a.StartsWith("--", StringComparison.Ordinal) && a.Contains('c')));
            if (command is not null)
                return new(program, InlineReason(program, command));
            // su without -c starts a (login) shell reading stdin; runuser [-u user] cmd runs cmd.
            return program.Equals("runuser", StringComparison.OrdinalIgnoreCase) ? CheckWrapper(program, args)
                : new(program, $"'{program}' without -c starts a shell reading stdin, which can transform and print secrets past redaction. {WayOut}");
        }

        if (CodeRunners.Contains(program))
            return new(program, $"'{program}' runs code or commands given on its command line, which can transform and print secrets past redaction. {WayOut}");

        if (AwkNames.Contains(program))
        {
            // Program text from a file (-f) is allowed; inline program text or -e/--source isn't.
            // Parse awk's options letter by letter: v, F, W take a value (attached or next),
            // f names a program file (attached or next), e is inline program text (gawk).
            var inlineSource = false;
            List<string> programFiles = [];
            for (var i = 0; i < args.Count; i++)
            {
                var a = args[i];
                if (a == "--")
                    break;
                if (a.StartsWith("--", StringComparison.Ordinal))
                {
                    if (a.StartsWith("--source", StringComparison.Ordinal))
                        inlineSource = true;
                    else if (a.StartsWith("--file=", StringComparison.Ordinal))
                        programFiles.Add(a["--file=".Length..]);
                    else if (a == "--file" && i + 1 < args.Count)
                        programFiles.Add(args[++i]);
                    continue;
                }
                if (!a.StartsWith('-') || a.Length < 2)
                    break; // the program text or the first input file
                for (var j = 1; j < a.Length; j++)
                {
                    var letter = a[j];
                    if (letter == 'e')
                    {
                        inlineSource = true;
                        break;
                    }
                    if (letter is 'f' or 'v' or 'F' or 'W')
                    {
                        var value = j < a.Length - 1 ? a[(j + 1)..] : (i + 1 < args.Count ? args[++i] : "");
                        if (letter == 'f')
                            programFiles.Add(value);
                        break;
                    }
                }
            }
            if (programFiles.Any(f => StdinScripts.Contains(f) || f.Length == 0))
                return new(program, $"'{program} -f -' reads its program from stdin, which can transform and print secrets past redaction. Put the program in a file.");
            var fromFile = programFiles.Count > 0;
            return fromFile && !inlineSource ? null
                : new(program, $"'{program}' with an inline program can transform and print secrets past redaction. Put the program in a file and use '{program} -f prog.awk'.");
        }

        if (program.Equals("find", StringComparison.OrdinalIgnoreCase))
        {
            // Check the command each -exec runs, up to its ';' or '+'.
            for (var i = 0; i < args.Count; i++)
            {
                if (!FindExecOptions.Contains(args[i]))
                    continue;
                var command = WithImageProgram(args.Skip(i + 1).TakeWhile(a => a is not (";" or "+")).ToList());
                var inner = command.Count == 0 ? null : GetBlockedInvocation(command);
                if (inner is not null)
                    return inner with { Reason = $"'find {args[i]}' runs '{inner.Program}': {inner.Reason}" };
            }
            return null;
        }

        if (program.Equals("ssh", StringComparison.OrdinalIgnoreCase))
            return CheckSsh(args);

        if (program.Equals("deno", StringComparison.OrdinalIgnoreCase))
            return args.FirstOrDefault(a => !a.StartsWith('-')) is "eval" or "repl"
                ? new(program, InlineReason(program, "eval")) : null;

        if (program.Equals("cmd", StringComparison.OrdinalIgnoreCase)
            && args.Any(a => a.Equals("/c", StringComparison.OrdinalIgnoreCase) || a.Equals("/k", StringComparison.OrdinalIgnoreCase)))
            return new(program, InlineReason(program, "/c"));

        if (program.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || program.Equals("powershell", StringComparison.OrdinalIgnoreCase))
        {
            var flag = args.FirstOrDefault(IsPowerShellInline);
            return flag is not null ? new(program, InlineReason(program, flag)) : null;
        }

        if (PythonName.IsMatch(program))
            return CheckInterpreter(program, args, PythonSyntax);
        if (Interpreters.TryGetValue(program, out var syntax))
            return CheckInterpreter(program, args, syntax);

        return null;
    }

    // Wrapper options that take a separate value, so the value isn't taken for the command.
    private static readonly Dictionary<string, string[]> WrapperValued = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sudo"] = ["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-R", "-t", "-U", "-T", "--user", "--group",
            "--chdir", "--chroot", "--close-from", "--host", "--prompt", "--role", "--type",
            "--command-timeout", "--other-user", "-a", "--auth-type"],
        ["stdbuf"] = ["-i", "-o", "-e", "--input", "--output", "--error"],
        ["time"] = ["-f", "-o", "--format", "--output"],
        ["flock"] = ["-w", "-E", "--timeout", "--wait", "--conflict-exit-code"],
        ["doas"] = ["-u", "-C", "-a"],
        ["timeout"] = ["-s", "-k", "--signal", "--kill-after"],
        ["nice"] = ["-n", "--adjustment"],
        ["ionice"] = ["-c", "-n", "-p", "--class", "--classdata", "--pid"],
        ["strace"] = ["-o", "-e", "-p", "-s", "-u"],
        ["ltrace"] = ["-o", "-e", "-p", "-s", "-u"],
        ["nsenter"] = ["-t", "--target"],
        ["chroot"] = ["--userspec", "--groups"],
        ["chrt"] = ["-s", "-T", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"],
        ["runuser"] = ["-u", "-g", "-G", "--user", "--group", "--supp-group", "-s", "--shell"],
        ["npx"] = ["-p", "--package"],
        ["systemd-run"] = ["-p", "--property", "-u", "--unit", "-E", "--setenv", "-M", "--machine"],
        // Review fix F19: wsl's -e/--exec take no value of their own: the word after them is the command.
        ["wsl"] = ["-d", "--distribution", "-u", "--user", "--cd"],
    };

    // Wrappers whose first positional argument is not the command (timeout DURATION cmd,
    // flock FILE cmd, chroot DIR cmd, taskset MASK cmd, chrt PRIO cmd).
    private static readonly HashSet<string> WrapperLeadingPositional = new(StringComparer.OrdinalIgnoreCase)
        { "timeout", "flock", "chroot", "taskset", "chrt" };

    // Tools with subcommands: these subcommands run a command, the others don't.
    private static readonly HashSet<string> SubcommandTools = new(StringComparer.OrdinalIgnoreCase)
        { "uv", "poetry", "pipenv", "pdm", "hatch", "conda", "pixi", "npm", "pnpm", "yarn", "bundle",
          "docker", "podman", "nerdctl", "kubectl", "oc", "lxc", "incus", "flatpak", "snap", "machinectl",
          "toolbox", "distrobox" };

    private static readonly HashSet<string> ExecSubcommands = new(StringComparer.OrdinalIgnoreCase)
        { "run", "exec", "x", "dlx", "shell", "enter", "debug", "attach", "start", "create", "compose" };

    // Wrapped command: for a simple wrapper, the first positional argument after its options (and a
    // leading duration/file/dir/mask where the wrapper has one) is the command, checked in full. An
    // ordinary program there (sudo apt install python3) is allowed. For a tool with subcommands, a
    // non-executing subcommand (docker pull python) is allowed; under run/exec the first checked
    // program after it is the command, checked in full, so a bare interpreter reading stdin
    // (docker run -i img python) is refused.
    private static BlockedInvocation? CheckWrapper(string program, List<string> args)
    {
        BlockedInvocation? Wrapped(int from)
        {
            var inner = GetBlockedInvocation(WithImageProgram(args.Skip(from).ToList()));
            return inner is null ? null : inner with { Reason = $"'{program}' runs '{inner.Program}': {inner.Reason}" };
        }

        if (program.Equals("command", StringComparison.OrdinalIgnoreCase) && args.Any(a => a is "-v" or "-V"))
            return null; // command -v only looks the name up

        // sudo -s/-i run a shell (with any command through its -c), npx -c and flock -c run shell
        // code. Only the wrapper's own options count, before its command (sudo mv -i a b passes).
        var ownOptions = OwnOptions(program, args);
        if ((program is "sudo" or "doas" && ownOptions.Any(a => a is "--shell" or "--login" || ShortCluster(a, program == "doas" ? "s" : "si", "ugCDhprRtUT")))
            || (program.Equals("npx", StringComparison.OrdinalIgnoreCase) && args.Any(a => a is "-c" or "--call"))
            || (program.Equals("flock", StringComparison.OrdinalIgnoreCase) && FlockRunsShell(args)))
            return new(program, $"'{program}' with a shell option runs shell code, which can transform and print secrets past redaction. {WayOut}");

        if (SubcommandTools.Contains(program))
        {
            // --entrypoint <interpreter>: its code arguments come after the image, which the
            // check can't tell apart from the image name, so refuse it outright.
            for (var e = 0; e < args.Count; e++)
            {
                var entry = args[e] == "--entrypoint" && e + 1 < args.Count ? args[e + 1]
                    : args[e].StartsWith("--entrypoint=", StringComparison.Ordinal) ? args[e]["--entrypoint=".Length..] : null;
                if (entry is not null && IsInterpreter(ProgramName(entry)))
                    return new(program, $"'{program} --entrypoint {entry}' runs an interpreter whose code arguments can't be checked. {WayOut}");
            }
            var sub = args.FindIndex(a => !a.StartsWith('-'));
            if (sub < 0 || !ExecSubcommands.Contains(args[sub]))
                return null; // pull, install, build ...: nothing is run
            if (program.Equals("machinectl", StringComparison.OrdinalIgnoreCase) && args[sub] is "shell" or "login"
                && !args.Skip(sub + 1).Where(a => !a.StartsWith('-')).Skip(1).Any())
                return new(program, $"'machinectl {args[sub]}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {WayOut}");
            for (var i = sub + 1; i < args.Count; i++)
                if (IsWrappedCheckedProgram(args[i]) && Wrapped(i) is { } blocked)
                    return blocked;
            return null;
        }

        WrapperValued.TryGetValue(program, out var valued);
        var skipLeading = WrapperLeadingPositional.Contains(program);
        // taskset -c LIST (or -cLIST, --cpu-list=LIST): an attached list is the leading
        // positional itself, so nothing more is skipped; a separate list is skipped as usual.
        if (program.Equals("taskset", StringComparison.OrdinalIgnoreCase)
            && args.Any(a => (a.StartsWith("-c", StringComparison.Ordinal) && a.Length > 2 && !a.StartsWith("--", StringComparison.Ordinal))
                || a.StartsWith("--cpu-list=", StringComparison.Ordinal)))
            skipLeading = false;
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == "--")
                continue;
            if (arg.StartsWith('-'))
            {
                if (valued is not null && valued.Contains(arg, StringComparer.Ordinal))
                    i++;
                continue;
            }
            if (arg.Contains('=') && !arg.StartsWith('/') && program.Equals("sudo", StringComparison.OrdinalIgnoreCase))
                continue; // sudo VAR=value
            if (skipLeading)
            {
                skipLeading = false;
                continue;
            }
            // The wrapped command, checked in full (a bare interpreter reading stdin is refused).
            if (IsWrappedCheckedProgram(arg) && Wrapped(i) is { } wrapped)
                return wrapped;
            // Not a checked program, or one that passes. For a wrapper whose options this check knows
            // completely, it is the command (sudo apt install python3 passes). For any other wrapper it
            // may be the value of an unknown option (bwrap --ro-bind / / python; review fix F22:
            // bwrap --tmpfs /python bash -c ..., whatever word the value is), so keep scanning and refuse
            // any later checked program that would be refused on its own, a bare interpreter reading
            // stdin included: failing closed.
            if (TrustedWrappers.Contains(program))
                return null;
            for (var k = i + 1; k < args.Count; k++)
                if (IsWrappedCheckedProgram(args[k]) && Wrapped(k) is { } later)
                    return later;
            return null;
        }
        // No command at all: these wrappers then start a shell that reads stdin.
        return ShellWhenNoCommand.Contains(program)
            ? new(program, $"'{program}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {WayOut}")
            : null;
    }

    // Review fix F18: in a wrapper's command (CheckWrapper, find -exec), a word whose last path component, with a
    // trailing '@<digest>' (F21) and ':<tag>' removed, names a checked program is a container image of it (python:3.12,
    // mcr.microsoft.com/powershell:7.4), checked as that program with the words after it as its arguments. Null when
    // the word isn't such a tag, or already names a checked program as it is.
    private static string? ImageProgram(string word)
    {
        if (IsCheckedProgram(ProgramName(word)))
            return null;
        var last = word.Replace('\\', '/');
        last = last[(last.LastIndexOf('/') + 1)..];
        // F21: a digest first (python@sha256:..., python:3.12@sha256:...), then the tag.
        if (last.LastIndexOf('@') is var at and > 0)
            last = last[..at];
        if (last.IndexOf(':') is var colon and > 0)
            last = last[..colon];
        return ProgramName(last) is var name && IsCheckedProgram(name) ? name : null;
    }

    private static bool IsWrappedCheckedProgram(string word) =>
        IsCheckedProgram(ProgramName(word)) || ImageProgram(word) is not null;

    // The wrapped command with an image tag's program (ImageProgram) in place of its first word.
    private static List<string> WithImageProgram(List<string> command)
    {
        if (command.Count > 0 && ImageProgram(command[0]) is { } program)
            command[0] = program;
        return command;
    }

    private static readonly HashSet<string> ShellWhenNoCommand = new(StringComparer.OrdinalIgnoreCase)
        { "nsenter", "runuser", "doas", "chroot", "unshare" };

    // Wrappers whose options WrapperValued covers completely: their first positional argument
    // is the command.
    private static readonly HashSet<string> TrustedWrappers = new(StringComparer.OrdinalIgnoreCase)
        { "sudo", "doas", "timeout", "nice", "nohup", "setsid", "time", "stdbuf", "ionice", "flock",
          "chroot", "taskset", "chrt" };

    // flock [options] FILE -c COMMAND: -c is flock's own when it comes before the file or right
    // after it; a -c further on belongs to the wrapped command (flock FILE git -c x fetch).
    private static bool FlockRunsShell(List<string> args)
    {
        string[] valued = ["-w", "-E", "--timeout", "--wait", "--conflict-exit-code"];
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a is "-c" or "--command" || a.StartsWith("--command=", StringComparison.Ordinal) || ShortCluster(a, "c", "wE"))
                return true;
            if (valued.Contains(a))
            {
                i++;
                continue;
            }
            if (a.StartsWith('-'))
                continue;
            // The lock file: only the argument right after it can still be flock's -c.
            return i + 1 < args.Count && args[i + 1] is "-c" or "--command";
        }
        return false;
    }

    // True when a single-dash option cluster (-Es, -si) contains one of the letters before a
    // letter that takes a value (whose attached rest is that value, not more letters).
    private static bool ShortCluster(string arg, string letters, string valuedLetters)
    {
        if (!arg.StartsWith('-') || arg.StartsWith("--", StringComparison.Ordinal))
            return false;
        foreach (var letter in arg.AsSpan(1))
        {
            if (letters.Contains(letter))
                return true;
            if (valuedLetters.Contains(letter))
                return false;
        }
        return false;
    }

    // The wrapper's own options: everything before its command (the first positional argument,
    // after skipping known option values).
    private static List<string> OwnOptions(string program, List<string> args)
    {
        WrapperValued.TryGetValue(program, out var valued);
        List<string> own = [];
        for (var i = 0; i < args.Count; i++)
        {
            if (args[i] == "--" || !args[i].StartsWith('-'))
                break;
            own.Add(args[i]);
            if (valued is not null && valued.Contains(args[i], StringComparer.Ordinal))
                i++;
        }
        return own;
    }

    private static bool IsInterpreter(string name) =>
        PythonName.IsMatch(name) || Interpreters.ContainsKey(name) || AwkNames.Contains(name)
        || name.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || name.Equals("powershell", StringComparison.OrdinalIgnoreCase)
        || name.Equals("cmd", StringComparison.OrdinalIgnoreCase) || name.Equals("deno", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Review fix F9: a PowerShell host parameter as PowerShell 7's own parser reads it
    /// (<c>CommandLineParameterParser.GetSwitchKey</c>, <c>CharExtensions.IsDash</c>): surrounding whitespace trimmed,
    /// then every leading <c>/</c>, <c>-</c>, U+2013, U+2014 or U+2015 stripped (any number of them, which fails
    /// closed where Windows PowerShell 5.1's closed parser may take fewer), lower-cased. Null when nothing was stripped
    /// (not a parameter) or nothing is left.
    /// </summary>
    private static string? PowerShellParameterKey(string arg)
    {
        var trimmed = arg.Trim();
        var key = trimmed.TrimStart('/', '-', '\u2013', '\u2014', '\u2015');
        return key.Length == trimmed.Length || key.Length == 0 ? null : key.ToLowerInvariant();
    }

    // PowerShell takes any prefix of a parameter's name down to its short form, and resolves -c and -e (and -co, -en)
    // to -Command and -EncodedCommand itself (F9: PowerShell's own rule, fail closed): every prefix of the three
    // inline-code parameters counts, as do their aliases -ec and -cwa.
    private static bool IsPowerShellInline(string arg) =>
        PowerShellParameterKey(arg) is { } key
        && (key is "ec" or "cwa"
            || "command".StartsWith(key, StringComparison.Ordinal)
            || "encodedcommand".StartsWith(key, StringComparison.Ordinal)
            || "commandwithargs".StartsWith(key, StringComparison.Ordinal));

    // ssh host [command]: a remote command is remote shell code.
    private static BlockedInvocation? CheckSsh(List<string> args)
    {
        string? host = null;
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (host is null)
            {
                if (arg == "--")
                    continue;
                if (arg.StartsWith('-') && arg.Length > 1)
                {
                    // Flags in a cluster, until a valued letter (whose value is attached or next).
                    for (var j = 1; j < arg.Length; j++)
                    {
                        if (!SshValued.Contains(arg[j]))
                            continue;
                        if (j == arg.Length - 1)
                            i++;
                        break;
                    }
                    continue;
                }
                host = arg;
                continue;
            }
            return new("ssh", $"'ssh {host} <command>' runs the command in a remote shell, which can transform and print secrets past redaction. Put the commands in a script on the remote host and run that, or pass the secret another way.");
        }
        return null;
    }

    // Options before the script name decide; everything after the script belongs to the script.
    private static BlockedInvocation? CheckInterpreter(string program, List<string> args, InterpreterSyntax syntax)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == "--")
                continue;
            if (StdinScripts.Contains(arg))
                return new(program, $"'{program} {arg}' reads code from stdin, which can transform and print secrets past redaction. {WayOut}");
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                var name = arg.Split('=', 2)[0];
                if (syntax.InlineLong.Contains(name, StringComparer.Ordinal))
                    return new(program, InlineReason(program, name));
                if (syntax.ValuedLong.Contains(name, StringComparer.Ordinal) && !arg.Contains('='))
                    i++;
                continue;
            }
            if (arg.StartsWith('-') || (syntax.Plus && arg.StartsWith('+')))
            {
                // A short option cluster: inline letters refuse; a valued letter takes the rest of
                // the cluster (or the next argument) as its value, so no later letter is read.
                for (var j = 1; j < arg.Length; j++)
                {
                    var letter = arg[j];
                    if (syntax.EndsOptions is not null && syntax.EndsOptions.Contains(letter))
                        return null; // e.g. python -m module: the module is the script
                    if (syntax.Inline.Contains(letter) && arg[0] == '-')
                        return new(program, InlineReason(program, arg));
                    if (syntax.ScriptOption.Contains(letter))
                    {
                        // The value is the script file: attached, or the next argument. Options
                        // after it can still carry inline code (expect -f s.exp -c '...').
                        var script = j < arg.Length - 1 ? arg[(j + 1)..] : (i + 1 < args.Count ? args[i + 1] : "");
                        if (StdinScripts.Contains(script) || script.Length == 0)
                            return new(program, $"'{program} {arg} {script}' reads code from stdin, which can transform and print secrets past redaction. {WayOut}");
                        var later = args.Skip(i + (j < arg.Length - 1 ? 1 : 2))
                            .FirstOrDefault(a => a.StartsWith('-') && !a.StartsWith("--", StringComparison.Ordinal) && a.Skip(1).Any(syntax.Inline.Contains));
                        return later is not null ? new(program, InlineReason(program, later)) : null;
                    }
                    if (syntax.AttachedOnly.Contains(letter))
                        break; // any rest of the cluster is its value; never the next argument
                    if (syntax.Valued.Contains(letter))
                    {
                        if (j == arg.Length - 1)
                            i++;
                        break;
                    }
                }
                continue;
            }
            return null; // the script file
        }
        return new(program, $"'{program}' with no script file reads code from stdin, which can transform and print secrets past redaction. {WayOut}");
    }

    private static string InlineReason(string program, string flag) =>
        $"'{program} {flag}' runs inline code, which can transform and print secrets past redaction. {WayOut}";

    private static bool IsCheckedProgram(string name) =>
        BlockedCommands.Contains(name) || PythonName.IsMatch(name) || Interpreters.ContainsKey(name)
        || CodeRunners.Contains(name) || AwkNames.Contains(name) || Wrappers.Contains(name) || ShellAsUser.Contains(name)
        || name.Equals("find", StringComparison.OrdinalIgnoreCase) || name.Equals("ssh", StringComparison.OrdinalIgnoreCase)
        || name.Equals("deno", StringComparison.OrdinalIgnoreCase) || name.Equals("cmd", StringComparison.OrdinalIgnoreCase)
        || name.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || name.Equals("powershell", StringComparison.OrdinalIgnoreCase);

    // Basename without a Windows executable extension: /bin/sh → sh, cmd.exe → cmd.
    /// <summary>
    /// Brief T47 (A4), review fix F12: the last component of <paramref name="path"/> as Windows names the file it
    /// starts: a drive prefix (<c>C:</c>) dropped, either separator, a <c>:stream</c> suffix dropped (F15: only after
    /// a name ending in .exe, .cmd, .bat or .com), and trailing dots
    /// and spaces dropped (<c>pwsh.exe.</c>, <c>pwsh.exe </c>, <c>pwsh.exe::$DATA</c> are <c>pwsh.exe</c>). Shared by
    /// <see cref="IsBatchTarget"/> and <see cref="ProgramName"/>, on every OS (fail closed).
    /// </summary>
    private static string WindowsFileName(string path)
    {
        var name = path.Length >= 2 && path[1] == ':' && char.IsAsciiLetter(path[0]) ? path[2..] : path;
        name = name.Replace('\\', '/');
        name = name[(name.LastIndexOf('/') + 1)..];
        // Review fix F15: a ':stream' suffix only on a name that is a program file before its first ':', so an image
        // tag (python:3.12, node:20) keeps its ':' and is not read as the interpreter. F17: that head is tested as
        // Windows names it, trailing dots and spaces dropped (x.cmd.:s, pwsh.exe ::$DATA).
        if (name.IndexOf(':') is var colon and >= 0 && name[..colon].TrimEnd('.', ' ') is var head && HasProgramExtension(head))
            name = head;
        return name.TrimEnd('.', ' ');
    }

    private static bool HasProgramExtension(string name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".com", StringComparison.OrdinalIgnoreCase);

    private static string ProgramName(string path)
    {
        var name = WindowsFileName(path);
        foreach (var ext in new[] { ".exe", ".cmd", ".bat", ".com" })
            if (name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                return name[..^ext.Length];
        return name;
    }

    /// <summary>
    /// Check if a command string contains pipes or output redirection.
    /// </summary>
    public static bool HasPipeOrRedirect(string command)
    {
        return Regex.IsMatch(command, @"[|>]");
    }

    /// <summary>
    /// Substitute tokens in each argument with raw secret values.
    /// Values are not shell-quoted because the program is executed directly via
    /// execvp/Process — the OS passes each element as a literal string to the child
    /// process without any shell interpretation.
    ///
    /// <para><b>Shell-target warning:</b> inline shell code (<c>sh -c</c>) is refused by
    /// <see cref="GetBlockedInvocation"/> since #105, but a script given a secret as an
    /// argument can still pass it on to a shell, and the shell will interpret
    /// metacharacters in the substituted value (<c>$(…)</c>, backticks, <c>;</c>,
    /// newlines, redirects, etc.) as shell syntax. This differs from the previous
    /// behaviour where values were single-quote-escaped before being passed to
    /// <c>bash -c</c>. Callers that embed secrets inside shell scripts must ensure
    /// the secret values are intended to be executed as shell code, or must apply
    /// their own POSIX quoting before passing the argument to this method.</para>
    ///
    /// <para>Values containing NUL (<c>\0</c>) are rejected: native APIs treat NUL
    /// as a string terminator and would silently truncate the argument.</para>
    /// </summary>
    public static string[] SubstituteTokensInArgs(string[] args, Dictionary<string, string> secretValues)
    {
        // Reject null and NUL-containing values before substitution.
        // Null can occur if the secrets DB was tampered/corrupted (System.Text.Json can
        // populate null for non-nullable string properties). NUL bytes are silently truncated
        // by native APIs (execvp, CreateProcess), potentially altering the executed command.
        foreach (var (token, value) in secretValues)
            if (value is null || value.Contains('\0'))
                throw new Exception(
                    $"Secret '{token}' has a null or NUL-containing value, which cannot be " +
                    "passed as a process argument. Re-ingest the secret with a valid value.");

        // The one substitution pass run uses (name tokens only here).
        return SubstituteAllTokensInArgs(args, secretValues, new Dictionary<string, string>());
    }

    /// <summary>
    /// Sanitise a command by replacing all tokens (file tokens too) with ********.
    /// </summary>
    public static string SanitizeCommand(string command)
    {
        return FileTokenRegex.Replace(TokenRegex.Replace(command, "********"), "********");
    }
}
