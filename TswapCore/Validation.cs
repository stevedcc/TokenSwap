using System.Text.RegularExpressions;

namespace TswapCore;

public static class Validation
{
    // Fix round 1, B: '{{name:previous}}' names the value the last rotation replaced. ':' is not a
    // name character (ValidNameRegex), so the suffix can't collide with a secret name. Brief T58 (#374):
    // '{{name:totp}}' names the current code of a TOTP seed. One suffix at most.
    public static readonly Regex TokenRegex = new(@"\{\{([a-zA-Z0-9_-]+(?::previous|:totp)?)\}\}");

    // Fix round 3: any other '{{name:suffix}}' is a typo, never passed through as literal text.
    private static readonly Regex SuffixedTokenRegex = new(@"\{\{([a-zA-Z0-9_-]+:[^{}]*)\}\}");

    /// <summary>
    /// Throws for a <c>{{name:suffix}}</c> token whose suffix is not <c>previous</c> or <c>totp</c> (one suffix
    /// at most: <c>{{name:previous:totp}}</c> is unknown), naming it.
    /// </summary>
    public static void ThrowIfUnknownTokenSuffix(string command)
    {
        foreach (Match m in SuffixedTokenRegex.Matches(command))
        {
            var inner = m.Groups[1].Value;
            if (inner.Count(ch => ch == ':') != 1
                || !(inner.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal) || inner.EndsWith(SecretsDb.TotpSuffix, StringComparison.Ordinal)))
                throw new TswapException(
                    $"Unknown token '{{{{{inner}}}}}': the suffixes are ':previous' (the value the last rotation replaced) and ':totp' (the current code of a TOTP seed).");
        }
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
                $"'{shown}' is not a valid token: a token is {{{{NAME}}}}, {{{{NAME:previous}}}} or {{{{NAME:totp}}}}, " +
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
    private static readonly Regex AnyTokenRegex = new(@"\{\{(?:@([^{}]+)|([a-zA-Z0-9_-]+(?::previous|:totp)?))\}\}");

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
            if (WrappedCommand(argv, i, argv.Count, program) is not { } next)
                yield break;
            i = next;
        }
    }

    /// <summary>
    /// The position of the command the simple wrapper <paramref name="program"/> at <paramref name="i"/> runs, looking no
    /// further than <paramref name="end"/>: its options and the values in <see cref="WrapperValued"/> skipped, and a
    /// leading positional (<see cref="WrapperLeadingPositional"/>); null when it has none.
    /// </summary>
    private static int? WrappedCommand(IReadOnlyList<string> argv, int i, int end, string program)
    {
        WrapperValued.TryGetValue(program, out var valued);
        var skipLeading = WrapperLeadingPositional.Contains(program);
        for (var j = i + 1; j < end; j++)
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
            return j;
        }
        return null;
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
    /// <c>.com</c>, or a head Windows trimmed (F23), reviews F15 and F17), ends in <c>.cmd</c> or <c>.bat</c>, or is <c>cmd</c> (<c>cmd.exe</c>), ignoring
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
          "kubectl", "oc", "lxc", "incus", "flatpak", "snap", "machinectl", "toolbox", "distrobox", "wsl",
          // Brief T64 Task 2a: so the shared walk (ProgramPositions) reaches runuser's command. GetBlockedInvocation
          // checks ShellAsUser first, so runuser keeps its -c refusal.
          "runuser" };

    // Run their -c/--command argument through the target user's shell.
    private static readonly HashSet<string> ShellAsUser = new(StringComparer.OrdinalIgnoreCase)
        { "su", "runuser" };

    // ssh options that take a value; a non-option argument after the host is a remote command.
    private const string SshValued = "BbcDEeFIiJLlmOoPpQRSWw";

    // Script paths that are really stdin, resolved (IsStdinScript). Review fix G1: compared ignoring case (fail closed:
    // a case-insensitive file system, or /dev/STDIN given on purpose).
    private static readonly HashSet<string> StdinPaths = new(StringComparer.OrdinalIgnoreCase)
        { "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "/proc/thread-self/fd/0" };

    private static readonly Regex ProcPidStdin = new("^/proc/[0-9]+/fd/0$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// Review fix I1: whether <paramref name="word"/>, as a script path, is stdin: <c>-</c> (after trimming), or a path
    /// that resolves to <c>/dev/stdin</c>, <c>/dev/fd/0</c>, <c>/proc/self/fd/0</c>, <c>/proc/thread-self/fd/0</c> or
    /// <c>/proc/&lt;pid&gt;/fd/0</c>, ignoring case. The path is resolved as the kernel walks it (relative to the current
    /// folder, repeated separators and <c>.</c>/<c>..</c> collapsed) with <see cref="Path.GetFullPath(string)"/>, so
    /// <c>/dev/./stdin</c>, <c>//dev//stdin</c> and <c>../../dev/stdin</c> count; a word it can't resolve is no path. A
    /// symbolic link to stdin under another name is not followed. Brief T51: every stdin check of
    /// <see cref="GetBlockedInvocation"/> uses the wider <see cref="IsInputPath"/>, which includes this.
    /// </summary>
    public static bool IsStdinScript(string word)
    {
        var trimmed = word.Trim();
        if (trimmed == "-")
            return true;
        return ResolveScriptPath(trimmed) is { } full && (StdinPaths.Contains(full) || ProcPidStdin.IsMatch(full));
    }

    /// <summary>
    /// Brief T51 (#407): whether <paramref name="word"/>, as a script or program file, can read <c>run</c>'s stdin or
    /// the terminal. True for every <see cref="IsStdinScript"/> word, for a path that resolves (as
    /// <see cref="IsStdinScript"/> resolves it) to <c>/dev</c> or <c>/proc</c> or anything under them, ignoring case,
    /// except <c>/dev/null</c> and <c>/dev/shm/</c> (proc(5): <c>/proc/&lt;pid&gt;/root</c>, <c>cwd</c> and
    /// <c>task/&lt;tid&gt;/</c> reach any path, and under a pseudo-terminal fds 0, 1, 2 and <c>/dev/tty</c> read the
    /// terminal's input), and on every OS for a Win32 device path (<c>\\.\</c>) or a Windows console name (<c>CON</c>,
    /// <c>CONIN$</c>, <c>CONOUT$</c>) as the last component, with a drive prefix, an extension or a stream ignored.
    /// Fail closed: a symbolic link elsewhere isn't followed, and a relative word is resolved against this process's
    /// folder only.
    /// </summary>
    public static bool IsInputPath(string word)
    {
        if (IsStdinScript(word))
            return true;
        var trimmed = word.Trim();
        if (ResolveScriptPath(trimmed) is { } full
            && (full.Equals("/dev", StringComparison.OrdinalIgnoreCase) || full.Equals("/proc", StringComparison.OrdinalIgnoreCase)
                || full.StartsWith("/dev/", StringComparison.OrdinalIgnoreCase) || full.StartsWith("/proc/", StringComparison.OrdinalIgnoreCase))
            && !full.Equals("/dev/null", StringComparison.OrdinalIgnoreCase)
            && !full.StartsWith("/dev/shm/", StringComparison.OrdinalIgnoreCase))
            return true;
        return IsWindowsConsolePath(trimmed);
    }

    // CreateFileW ("Consoles"): CON opened for reading is the console's input, CONIN$ always is, CONOUT$ the screen
    // buffer; a DOS device name ignores a folder, an extension and a stream. Amendment A1: both separators, an X: drive
    // prefix dropped, the last component cut at its first '.' or ':', then trailing dots and spaces trimmed.
    private static readonly HashSet<string> ConsoleNames = new(StringComparer.OrdinalIgnoreCase) { "CON", "CONIN$", "CONOUT$" };

    private static bool IsWindowsConsolePath(string word)
    {
        var path = word.Replace('\\', '/');
        if (path.StartsWith("//./", StringComparison.Ordinal))
            return true; // the Win32 device namespace
        if (path.Length >= 2 && path[1] == ':' && char.IsAsciiLetter(path[0]))
            path = path[2..];
        var name = path[(path.LastIndexOf('/') + 1)..];
        if (name.IndexOfAny(['.', ':']) is var cut and >= 0)
            name = name[..cut];
        return ConsoleNames.Contains(name.TrimEnd('.', ' '));
    }

    // The trimmed word as a path, resolved as the kernel walks it (IsStdinScript); null when it can't be resolved.
    private static string? ResolveScriptPath(string trimmed)
    {
        if (trimmed.Length == 0)
            return null;
        if (OperatingSystem.IsWindows())
        {
            // Windows' GetFullPath maps /dev/stdin to a drive path; resolve a '/'-rooted word by the Unix rules
            // instead, so the check is the same on every OS (fail closed). A relative word has no Unix
            // folder to resolve against there.
            return trimmed[0] == '/' ? ResolveUnixPath(trimmed) : null;
        }
        try
        {
            return Path.GetFullPath(trimmed);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    // '/'-rooted path, resolved as Path.GetFullPath does on Unix: empty and '.' segments dropped, '..' pops (not past /).
    private static string ResolveUnixPath(string path)
    {
        List<string> parts = [];
        foreach (var segment in path.Split('/'))
        {
            if (segment is "" or ".")
                continue;
            if (segment == "..")
            {
                if (parts.Count > 0)
                    parts.RemoveAt(parts.Count - 1);
                continue;
            }
            parts.Add(segment);
        }
        return "/" + string.Join('/', parts);
    }

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

        // Review fix F23: an image tag or digest as the program itself (python:3.12 -c ...) is that program.
        var program = ImageProgram(argv[0]) ?? ProgramName(argv[0]);
        var args = argv.Skip(1).ToList();

        if (BlockedCommands.Contains(program))
            return new(program, $"'{program}' would expose secret values. The 'run' command is for programs that *use* secrets, not display them.");

        // Brief T64 Task 2a: before the Wrappers branch, which also holds runuser, so its -c refusal runs first.
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

        if (Wrappers.Contains(program))
            return CheckWrapper(program, args);

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
            if (programFiles.Any(f => IsInputPath(f) || f.Length == 0))
                return new(program, $"'{program} -f -' reads its program from stdin or the terminal, which can transform and print secrets past redaction. Put the program in a file.");
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
            return CheckDeno(program, args);

        if (program.Equals("cmd", StringComparison.OrdinalIgnoreCase))
            // Review fix G2: with /c or /k cmd runs inline code; without them it starts a shell reading stdin.
            return args.Any(a => a.Equals("/c", StringComparison.OrdinalIgnoreCase) || a.Equals("/k", StringComparison.OrdinalIgnoreCase))
                ? new(program, InlineReason(program, "/c")) : NoCommandShell(program);

        if (program.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || program.Equals("powershell", StringComparison.OrdinalIgnoreCase))
        {
            var flag = args.FirstOrDefault(IsPowerShellInline);
            if (flag is not null)
                return new(program, InlineReason(program, flag));
            // Review fix H1, brief T51: an input path (IsInputPath) anywhere after PowerShell is refused, whatever
            // parameter comes before it (pwsh reads -i as -Interactive, not -InputFormat), fail closed; a script
            // argument that is literally '-' or an input path is refused too (accepted over-refusal).
            if (args.Any(IsInputPath))
                return PowerShellStdin(program);
            return program.Equals("powershell", StringComparison.OrdinalIgnoreCase)
                ? CheckWindowsPowerShell(program, args) : CheckPwsh(program, args);
        }

        if (PythonName.IsMatch(program))
            return CheckInterpreter(program, args, PythonSyntax);
        if (Interpreters.TryGetValue(program, out var syntax))
            return CheckInterpreter(program, args, syntax);

        return null;
    }

    /// <summary>
    /// Brief T64 (#411): the refusal of a bash that may be WSL's launcher, or null. WSL's bash.exe (System32's, or the WSL
    /// app's bash.exe alias) runs its whole command line as /bin/bash -c "/bin/bash &lt;command line&gt;" (microsoft/WSL
    /// 65719878ad3c, WslClient.cpp BashMain), so a substituted value is parsed again. It looks at program positions only,
    /// the ones CheckWrapper checks (run's program, a wrapper's or runner's command), and, in wsl's exec mode, at wsl's
    /// command, which runs inside the distribution, where a bash.exe is the launcher again through interop.
    /// </summary>
    /// <remarks>
    /// On Windows a word naming bash is allowed only when it resolves (<see cref="MsysTarget.Resolve"/>, the raw word) to
    /// a file <see cref="MsysTarget.IsMsys2"/> accepts, and behind a wrapper or runner only as an absolute path. Off
    /// Windows, and for the words of a container tool or of wsl's exec command, any word naming bash.exe is refused.
    /// A word with quote characters, white space at either end, a trailing <c>.</c>, <c>\</c> or <c>/</c>, or an NTFS
    /// stream after a bash or wsl name is refused outright.
    /// </remarks>
    public static BlockedInvocation? BashLauncherRefusal(IReadOnlyList<string> argv, bool windows, MsysTarget.Probe? probe) =>
        argv.Count == 0 ? null : BashLauncherWalk(argv, 0, argv.Count, windows, probe).Verdict;

    private const string BashLauncherWindowsReason =
        @"'bash' here is not a bash.exe that 'run' recognises as Git Bash or MSYS2 (msys-2.0.dll beside it, or Git's bin\bash.exe launcher). It may be WSL's launcher (System32's bash.exe, or the WSL app's bash.exe alias), which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. A bash at a program position (run's own program, or the command of a wrapper or runner such as sudo or uv run) is refused unless it is Git Bash or MSYS2's bash; behind a wrapper or runner it must be given by its full path. For WSL give the command after -e: 'wsl -e ./deploy.sh {{secret}}'; for Git Bash name it by its path: 'run ""C:\Program Files\Git\bin\bash.exe"" ./deploy.sh {{secret}}'.";

    private const string BashLauncherReason =
        @"'bash.exe' is a Windows program: under WSL it is System32's bash.exe, WSL's launcher, reached through Windows interop, which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. Run the Linux shell instead: 'run bash ./deploy.sh {{secret}}'.";

    private const string PaddedWslReason =
        @"'wsl' written with quote characters, surrounding white space or a trailing dot can't be checked: run reads it as another program, but Windows starts wsl.exe, which runs its command line through the Linux shell. Write it plainly: 'wsl -e ./deploy.sh {{secret}}'.";

    private static readonly BlockedInvocation BashLauncherWindowsRefusal = new("bash", BashLauncherWindowsReason);
    private static readonly BlockedInvocation BashLauncherRefusalOffWindows = new("bash.exe", BashLauncherReason);
    private static readonly BlockedInvocation PaddedWslRefusal = new("wsl", PaddedWslReason);

    /// <summary>A walk's verdict; <paramref name="Ended"/> when a wsl word was reached, whose walk owns the rest.</summary>
    private readonly record struct BashWalk(BlockedInvocation? Verdict, bool Ended);

    private enum BashWord { Other, Bash, Wsl }

    /// <summary>
    /// What a word at a program position names (bash on Windows, bash.exe off Windows, or wsl), and whether it is padded
    /// (refused outright). The word is read with every <c>"</c> removed (cmd.exe's quote toggling), white space trimmed at
    /// both ends and trailing <c>.</c>, <c>\</c> and <c>/</c> trimmed; a file-name part holding <c>:</c> is cut at its
    /// first <c>:</c> (an NTFS stream), and a head naming bash or wsl is padded too.
    /// </summary>
    private static (BashWord Kind, bool Padded) NameBashWord(string word, bool windows)
    {
        // Fail closed: white space, '.', '\' and '/' trimmed from the end until none is left (bash. \ names bash too).
        var n = word.Replace("\"", "", StringComparison.Ordinal).TrimStart();
        while (n.Length > 0 && (char.IsWhiteSpace(n[^1]) || n[^1] is '.' or '\\' or '/'))
            n = n[..^1];
        var padded = word.Contains('"')
            || (word.Length > 0 && (char.IsWhiteSpace(word[0]) || char.IsWhiteSpace(word[^1]) || word[^1] is '.' or '\\' or '/'));

        // The stream cut (round 6 I-1): the file-name part is after the last separator, or after an X: drive prefix.
        var separator = n.LastIndexOfAny(['\\', '/']);
        var nameStart = separator >= 0 ? separator + 1
            : n.Length >= 2 && char.IsAsciiLetter(n[0]) && n[1] == ':' ? 2 : 0;
        var colon = n.IndexOf(':', nameStart);
        if (colon >= 0)
        {
            var head = n[..colon];
            var headKind = Names(head);
            if (headKind != BashWord.Other)
                return (headKind, true);
        }
        return (Names(n), padded);

        BashWord Names(string name) =>
            ProgramName(name).Equals("wsl", StringComparison.OrdinalIgnoreCase) ? BashWord.Wsl
            : windows ? (ProgramName(name).Equals("bash", StringComparison.OrdinalIgnoreCase) ? BashWord.Bash : BashWord.Other)
            : WindowsFileName(name).Equals("bash.exe", StringComparison.OrdinalIgnoreCase) ? BashWord.Bash : BashWord.Other;
    }

    // C:\..., c:/..., \\server\..., \\?\C:\... ; not \Program Files\... (rooted on the current drive), .\bash or sub\bash.exe.
    private static bool IsAbsoluteWindowsPath(string word) =>
        (word.Length >= 3 && char.IsAsciiLetter(word[0]) && word[1] == ':' && word[2] is '\\' or '/')
        || (word.Length >= 2 && word[0] is '\\' or '/' && word[1] is '\\' or '/');

    /// <summary>
    /// The rule for a word naming bash at a program position: <paramref name="runProgram"/> is run's own program
    /// (argv[0]), <paramref name="windows"/> false the off-Windows rule (also a container tool's words, wsl's command).
    /// </summary>
    private static BlockedInvocation? BashRule(string word, bool padded, bool runProgram, bool windows, MsysTarget.Probe? probe)
    {
        if (!windows)
            return BashLauncherRefusalOffWindows;
        if (padded || probe is null)
            return BashLauncherWindowsRefusal;
        if (!runProgram && !IsAbsoluteWindowsPath(word))
            return BashLauncherWindowsRefusal;
        return MsysTarget.Resolve(word, probe) is { } file && MsysTarget.IsMsys2(file, probe.FileExists)
            ? null : BashLauncherWindowsRefusal;
    }

    /// <summary>Rule 4: a wsl word at <paramref name="k"/>, its command checked by the off-Windows rule in exec mode.</summary>
    private static BlockedInvocation? WslRule(IReadOnlyList<string> argv, int k, int end)
    {
        var args = argv.Skip(k + 1).Take(end - k - 1).ToList();
        var walk = WalkWsl("wsl", args);
        if (walk.Ended || !walk.Exec || walk.Command >= args.Count)
            return null;
        var inner = args.Skip(walk.Command).ToList();
        return BashLauncherWalk(inner, 0, inner.Count, windows: false, probe: null).Verdict is { } refusal
            ? refusal with { Reason = $"'wsl' runs '{refusal.Program}': {refusal.Reason}" }
            : null;
    }

    /// <summary>
    /// Rules 2 and 3: every word of <paramref name="argv"/> from <paramref name="from"/> to <paramref name="end"/> that
    /// names bash, by the rule of <paramref name="windows"/> as a position behind a wrapper; at the first word naming wsl
    /// the scan stops and that word's walk decides (round 4 M-5).
    /// </summary>
    private static BashWalk BashScan(IReadOnlyList<string> argv, int from, int end, bool windows, MsysTarget.Probe? probe)
    {
        for (var w = from; w < end; w++)
        {
            var (kind, padded) = NameBashWord(argv[w], windows);
            if (kind == BashWord.Wsl)
                return new(padded ? PaddedWslRefusal : WslRule(argv, w, end), Ended: true);
            if (kind == BashWord.Bash && BashRule(argv[w], padded, runProgram: false, windows, probe) is { } refusal)
                return new(refusal, Ended: false);
        }
        return new(null, Ended: false);
    }

    // The container, remote and sandbox tools: their command runs elsewhere, taken to be Linux (round 4 M-2).
    private static readonly HashSet<string> ElsewhereRunners = new(StringComparer.OrdinalIgnoreCase)
        { "docker", "podman", "nerdctl", "kubectl", "oc", "lxc", "incus", "machinectl", "toolbox", "distrobox", "flatpak", "snap" };

    /// <summary>
    /// Rule 1: the program positions of <paramref name="argv"/> from <paramref name="start"/> to <paramref name="end"/>,
    /// as <see cref="ProgramPositions"/> walks them (simple wrappers, <c>find -exec</c>), stopping at <c>command -v</c>,
    /// with rules 2 to 4 at each.
    /// </summary>
    private static BashWalk BashLauncherWalk(IReadOnlyList<string> argv, int start, int end, bool windows, MsysTarget.Probe? probe)
    {
        var i = start;
        while (i < end)
        {
            var (kind, padded) = NameBashWord(argv[i], windows);
            if (kind == BashWord.Wsl)
                return new(padded ? PaddedWslRefusal : WslRule(argv, i, end), Ended: true);
            if (kind == BashWord.Bash)
                return new(BashRule(argv[i], padded, runProgram: i == 0, windows, probe), Ended: false);

            var program = ProgramName(argv[i]);
            if (program.Equals("find", StringComparison.OrdinalIgnoreCase))
            {
                for (var j = i + 1; j < end; j++)
                {
                    if (!FindExecOptions.Contains(argv[j]))
                        continue;
                    var sliceEnd = j + 1;
                    while (sliceEnd < end && argv[sliceEnd] is not (";" or "+"))
                        sliceEnd++;
                    if (BashLauncherWalk(argv, j + 1, sliceEnd, windows, probe).Verdict is { } refusal)
                        return new(refusal, Ended: false);
                }
                return new(null, Ended: false);
            }
            if (program.Equals("command", StringComparison.OrdinalIgnoreCase)
                && argv.Skip(i + 1).Take(end - i - 1).Any(a => a is "-v" or "-V"))
                return new(null, Ended: false); // command -v only looks the name up
            if (!Wrappers.Contains(program))
                return new(null, Ended: false);

            if (SubcommandTools.Contains(program))
            {
                var rule = windows && !ElsewhereRunners.Contains(program);
                // Rule 3: an option before the subcommand hides where it is (uv --directory /x run): every later word.
                if (i + 1 < end && argv[i + 1].StartsWith('-'))
                    return BashScan(argv, i + 1, end, rule, probe);
                if (i + 1 < end && ExecSubcommands.Contains(argv[i + 1]))
                    return BashScan(argv, i + 2, end, rule, probe);
                return new(null, Ended: false);
            }

            // Rule 2: behind a wrapper whose options this check doesn't know completely, every later word.
            if (!TrustedWrappers.Contains(program) && BashScan(argv, i + 1, end, windows, probe) is var scan
                && (scan.Ended || scan.Verdict is not null))
                return scan;

            if (WrappedCommand(argv, i, end, program) is not { } next)
                return new(null, Ended: false);
            i = next;
        }
        return new(null, Ended: false);
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
        ["runuser"] = ["-u", "-g", "-G", "--user", "--group", "--supp-group", "-s", "--shell", "-w", "--whitelist-environment"],
        ["npx"] = ["-p", "--package"],
        ["systemd-run"] = ["-p", "--property", "-u", "--unit", "-E", "--setenv", "-M", "--machine"],
        // Review fix F19: wsl's -e/--exec take no value of their own: the word after them is the command. Brief T51:
        // every run option of wsl.exe that takes the next word (WslValued).
        ["wsl"] = ["-d", "--distribution", "--distribution-id", "-u", "--user", "--cd", "--shell-type", "--parent-console"],
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

        // Brief T51 Task 4 (#405): wsl by wsl.exe's own walk, terminal (A6): nothing below runs for wsl.
        if (program.Equals("wsl", StringComparison.OrdinalIgnoreCase))
            return CheckWsl(program, args);

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
        return ShellWhenNoCommand.Contains(program) ? NoCommandShell(program) : null;
    }

    // wsl.exe (microsoft/WSL at 65719878ad3c, src/windows/common/WslClient.cpp WslMain and ParseLegacyArguments; names in
    // src/windows/inc/wsl.h): its run options that take the next word as their value.
    private static readonly HashSet<string> WslValued = new(StringComparer.Ordinal)
        { "-d", "--distribution", "--distribution-id", "-u", "--user", "--cd", "--parent-console" };

    // Its management options: wsl runs the action and returns, starting no Linux command.
    private static readonly HashSet<string> WslManagement = new(StringComparer.Ordinal)
    {
        "--help", "--list", "-l", "--status", "--version", "-v", "--shutdown", "--terminate", "-t",
        "--set-default", "-s", "--setdefault", "--set-default-version", "--set-version",
        "--export", "--import", "--import-in-place", "--unregister",
        "--mount", "--unmount", "--manage", "--update", "--uninstall",
    };

    private const string WslShellModeReason =
        "'wsl' without -e (or --shell-type none) runs its command line through the Linux shell ($SHELL -c), which parses " +
        "a substituted value again and can transform and print secrets past redaction. Give the command after -e: " +
        "'wsl -e ./deploy.sh {{secret}}'. " + WayOut;

    private const string WslUnknownReason =
        "'wsl': an option this check doesn't know (wsl.exe matches its options exactly), so it can't tell what wsl runs. " +
        "Give the command after -e: 'wsl -e ./deploy.sh {{secret}}'. " + WayOut;

    /// <summary>
    /// Brief T51 Task 4 (#405): <c>wsl</c> by wsl.exe's own walk, its words compared exactly and case-sensitively as
    /// wsl.exe compares them. Valued run options skip their value; <c>--shell-type</c> <c>none</c> selects exec mode
    /// and <c>login</c>/<c>standard</c> shell mode (the last wins); <c>--</c> ends the options in the mode so far;
    /// <c>-e</c>/<c>--exec</c> select exec mode and end them; a management option runs no Linux command;
    /// <c>--debug-shell</c> and <c>--install</c> start a shell; any other <c>-</c> word is an error in wsl.exe and
    /// unknown here (fail closed); any other word (a legacy <c>~</c> or GUID included) begins the command. In shell
    /// mode wsl.exe runs a command line as <c>$SHELL -c &lt;commandline&gt;</c> and an empty one as a login shell; in
    /// exec mode it runs the command directly, which is checked as what it runs.
    /// </summary>
    private static BlockedInvocation? CheckWsl(string program, List<string> args)
    {
        var walk = WalkWsl(program, args);
        if (walk.Ended)
            return walk.Verdict;
        var (exec, command) = (walk.Exec, walk.Command);
        if (command >= args.Count)
            return exec ? null : NoCommandShell(program); // exec mode with no command: E_INVALIDARG, nothing runs
        if (!exec)
            return new(program, WslShellModeReason);
        var inner = GetBlockedInvocation(WithImageProgram(args.Skip(command).ToList()));
        return inner is null ? null : inner with { Reason = $"'{program}' runs '{inner.Program}': {inner.Reason}" };
    }

    /// <summary>
    /// Brief T64: <see cref="CheckWsl"/>'s option walk, shared with <see cref="BashLauncherRefusal"/>. <c>Ended</c>: the
    /// walk decided on its own (an unknown option, a <c>--shell-type</c> other than <c>none</c>, <c>login</c> or
    /// <c>standard</c>, a management option, <c>--debug-shell</c> or <c>--install</c>), with <c>Verdict</c>; otherwise
    /// <c>Exec</c> (exec mode) and <c>Command</c>, the index in <paramref name="args"/> where the command begins.
    /// </summary>
    private readonly record struct WslWalk(bool Ended, BlockedInvocation? Verdict, bool Exec, int Command);

    private static WslWalk WalkWsl(string program, List<string> args)
    {
        var exec = false;
        var command = args.Count;
        for (var i = 0; i < args.Count; i++)
        {
            var word = args[i];
            if (WslValued.Contains(word))
            {
                i++;
                continue;
            }
            if (word == "--shell-type")
            {
                var mode = i + 1 < args.Count ? args[++i] : null;
                if (mode == "none")
                    exec = true;
                else if (mode is "login" or "standard")
                    exec = false;
                else
                    return new(true, new(program, WslUnknownReason), false, 0);
                continue;
            }
            if (word == "--system")
                continue;
            if (word == "--")
            {
                command = i + 1;
                break;
            }
            if (word is "-e" or "--exec")
            {
                exec = true;
                command = i + 1;
                break;
            }
            if (WslManagement.Contains(word))
                return new(true, null, false, 0);
            if (word is "--debug-shell" or "--install")
                return new(true, NoCommandShell(program), false, 0);
            if (word.StartsWith('-'))
                return new(true, new(program, WslUnknownReason), false, 0);
            command = i;
            break;
        }
        return new(false, null, exec, command);
    }

    private static BlockedInvocation NoCommandShell(string program) =>
        new(program, $"'{program}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {WayOut}");

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

    /// <summary>
    /// Brief T49 (#401, A1): Windows PowerShell 5.1's own parameters as tswap trusts them, after exactly one leading
    /// <c>-</c> or <c>/</c> (case-insensitive): the full names, and the widely used short forms only. 5.1's parser is
    /// closed source and its docs document no abbreviations, so any other prefix, alias or spelling (a Unicode dash,
    /// <c>--</c>) is not a 5.1 parameter here (fail closed). <c>-Help</c>, <c>-?</c>, <c>/?</c> and
    /// <c>-EncodedArguments</c> are deliberately left out, so they are refused too. The value says whether the
    /// parameter takes the next word as its value.
    /// </summary>
    private static readonly Dictionary<string, (string Name, bool Valued)> WindowsPowerShellParameters =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["PSConsoleFile"] = ("PSConsoleFile", true),
            ["Version"] = ("Version", true),
            ["NoLogo"] = ("NoLogo", false),
            ["nol"] = ("NoLogo", false),
            ["NoExit"] = ("NoExit", false),
            ["noe"] = ("NoExit", false),
            ["Sta"] = ("Sta", false),
            ["Mta"] = ("Mta", false),
            ["NoProfile"] = ("NoProfile", false),
            ["nop"] = ("NoProfile", false),
            ["NonInteractive"] = ("NonInteractive", false),
            ["noni"] = ("NonInteractive", false),
            ["InputFormat"] = ("InputFormat", true),
            ["if"] = ("InputFormat", true),
            ["OutputFormat"] = ("OutputFormat", true),
            ["of"] = ("OutputFormat", true),
            ["WindowStyle"] = ("WindowStyle", true),
            ["w"] = ("WindowStyle", true),
            ["ConfigurationName"] = ("ConfigurationName", true),
            ["ExecutionPolicy"] = ("ExecutionPolicy", true),
            ["ep"] = ("ExecutionPolicy", true),
            ["ex"] = ("ExecutionPolicy", true),
            ["File"] = ("File", true),
            ["f"] = ("File", true),
        };

    // pwsh parameters that take the next word as a value (CommandLineParameterParser), by full name; a key that is a
    // prefix of one of them, or one of the aliases, consumes the next word (fail closed: an ambiguous prefix such as
    // -i, which pwsh reads as -Interactive, then needs a script after the word it consumed).
    private static readonly string[] PwshValuedParameters =
    [
        "configurationname", "configurationfile", "custompipename", "encodedarguments", "executionpolicy",
        "inputformat", "outputformat", "settingsfile", "windowstyle", "workingdirectory",
    ];

    private static readonly string[] PwshValuedAliases = ["ep", "if", "of", "wd"];

    // Review fix G1: pwsh's parameters that take no value (CommandLineParameterParser), by full name, and its '?' alias.
    // A key that is a prefix of none of these, of the valued ones and of file is no parameter: pwsh reads that word as
    // its positional script file (GetSwitchKey, ParseFile), so '/dev/stdin' or '/opt/x.ps1' is the script.
    private static readonly string[] PwshSwitchParameters =
    [
        "version", "help", "?", "login", "interactive", "noexit", "noprofile", "noprofileloadtime", "nologo",
        "noninteractive", "servermode", "namedpipeservermode", "sshservermode", "socketservermode", "mta", "sta",
        "removeworkingdirectorytrailingcharacter",
    ];

    /// <summary>
    /// Brief T49 (#401): Windows PowerShell 5.1 reads its first argument that is not one of its own parameters as
    /// -Command. Its parameters are walked (each valued one consumes the next word, A1's strict spellings only); the
    /// first other word decides: the word after a <c>-File</c> is the script (allowed, unless it is stdin), anything
    /// else is refused, as is <c>-NoExit</c> before the script and the end of the words with no script. No reason
    /// repeats a word: the walk also runs after substitution, so the word could be a secret's value.
    /// </summary>
    private static BlockedInvocation? CheckWindowsPowerShell(string program, List<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var word = args[i];
            if (word.Length < 2 || word[0] is not ('-' or '/')
                || !WindowsPowerShellParameters.TryGetValue(word[1..], out var parameter))
            {
                return word.Length > 0 && word[0] is '-' or '/' or '\u2013' or '\u2014' or '\u2015'
                    ? new(program, $"'{program}': a parameter spelling tswap doesn't trust (it trusts one - or / before Windows PowerShell 5.1's full parameter names and its common short forms), and 5.1 would read it as -Command, which can transform and print secrets past redaction. {WayOut}")
                    : new(program, $"'{program}' without -File runs its first argument as code (Windows PowerShell 5.1 reads it as -Command), which can transform and print secrets past redaction. {WayOut}");
            }
            if (parameter.Name == "NoExit")
                return PowerShellNoScript(program);
            if (parameter.Name == "File")
                return PowerShellScript(program, args, i + 1);
            if (parameter.Valued)
                i++;
        }
        return PowerShellNoScript(program);
    }

    /// <summary>
    /// Brief T49 (A2, A7): PowerShell 7 reads a plain first argument as the script file (-File), so only the stdin
    /// shapes are refused: a script from stdin, <c>-NoExit</c> before the script, and no script at all. Its parameters
    /// are read with <see cref="PowerShellParameterKey"/> (any spelling pwsh accepts).
    /// </summary>
    private static BlockedInvocation? CheckPwsh(string program, List<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var key = PowerShellParameterKey(args[i]);
            if (key is null)
                return PowerShellScript(program, args, i);
            if ("file".StartsWith(key, StringComparison.Ordinal))
                return PowerShellScript(program, args, i + 1);
            if (key.Length >= 3 && "noexit".StartsWith(key, StringComparison.Ordinal))
                return PowerShellNoScript(program);
            if (PwshValuedAliases.Contains(key) || PwshValuedParameters.Any(p => p.StartsWith(key, StringComparison.Ordinal)))
                i++;
            else if (!PwshSwitchParameters.Any(p => p.StartsWith(key, StringComparison.Ordinal)))
                return PowerShellScript(program, args, i); // G1: no parameter, so the positional script
        }
        return PowerShellNoScript(program);
    }

    // The script word at args[at]: missing is no script; an input path (or empty, fail closed) reads code from stdin or
    // the terminal.
    private static BlockedInvocation? PowerShellScript(string program, List<string> args, int at)
    {
        if (at >= args.Count)
            return PowerShellNoScript(program);
        var script = args[at];
        return IsInputPath(script) || script.Trim().Length == 0 ? PowerShellStdin(program) : null;
    }

    private static BlockedInvocation PowerShellStdin(string program) =>
        new(program, $"'{program} -File -' reads code from stdin or the terminal, which can transform and print secrets past redaction. {WayOut}");

    private static BlockedInvocation PowerShellNoScript(string program) =>
        new(program, $"'{program}' with no script (or -NoExit) reads code from stdin, which can transform and print secrets past redaction. {WayOut}");

    // Brief T51 (#406): deno's root defaults to 'run' ('deno <script>'), and 'deno' with no script starts its REPL.
    private const string DenoNoScriptReason =
        "'deno' with no script starts its REPL, which reads code from stdin and can transform and print secrets past " +
        "redaction. Write 'deno run <script>'. " + WayOut;

    private const string DenoOptionsReason =
        "'deno' with options but no subcommand runs a script whose position this check can't find, or starts its REPL. " +
        "Write 'deno run <options> <script>'. " + WayOut;

    /// <summary>
    /// Brief T51 Task 3 (#406): <c>deno</c> by deno's own parser (denoland/deno v2.9.8, <c>libs/cli_parser</c>). An input
    /// path in any word, of any subcommand and in any position (an option's separate value included: <c>run</c>'s
    /// valued options take even a word starting with <c>-</c>, and their list grows), reads code from stdin or the
    /// terminal. Otherwise the global options are walked as <c>resolve_subcommand</c> walks them, and the word it stops
    /// at decides: none is the REPL, <c>eval</c>/<c>repl</c> inline code, an option a run option with no subcommand
    /// (fail closed), anything else a subcommand or a bare script.
    /// </summary>
    private static BlockedInvocation? CheckDeno(string program, List<string> args)
    {
        if (args.Any(IsInputPath))
            return new(program, $"'{program} run -' reads code from stdin or the terminal, which can transform and print secrets past redaction. {WayOut}");

        // resolve_subcommand: a long option counts by its exact global name (--env-file, --help, --version,
        // --log-level, --quiet); a single-dash word by its second letter only (h, V, L, q). Bare --log-level, --env-file,
        // --help, -L and -h take the next word; the '=' forms take nothing. resolve_subcommand doesn't match the aliases
        // --env and -v, but those flags are require_equals(), so this walk matches resolve_subcommand; the resulting
        // over-refusals (deno -- app.ts, deno --env=x run app.ts, deno -v x) are accepted (A5, A11).
        var i = 0;
        while (i < args.Count)
        {
            var word = args[i];
            if (word is "--log-level" or "--env-file" or "--help" or "-L" or "-h")
                i += 2;
            else if (word is "--quiet" or "--version"
                     || word.StartsWith("--help=", StringComparison.Ordinal) || word.StartsWith("--env-file=", StringComparison.Ordinal)
                     || word.StartsWith("--log-level=", StringComparison.Ordinal)
                     || (word.Length > 1 && word[0] == '-' && word[1] is 'h' or 'V' or 'L' or 'q'))
                i++;
            else
                break;
        }

        if (i >= args.Count)
            return new(program, DenoNoScriptReason);
        var stop = args[i];
        if (stop is "eval" or "repl")
            return new(program, InlineReason(program, "eval"));
        return stop.StartsWith('-') ? new(program, DenoOptionsReason) : null;
    }

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
            if (IsInputPath(arg))
                return new(program, $"'{program} {arg}' reads code from stdin or the terminal, which can transform and print secrets past redaction. {WayOut}");
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
                        if (IsInputPath(script) || script.Length == 0)
                            return new(program, $"'{program} {arg} {script}' reads code from stdin or the terminal, which can transform and print secrets past redaction. {WayOut}");
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
    /// a name ending in .exe, .cmd, .bat or .com, or a head Windows trimmed (F23)), and trailing dots
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
        // F23: also when Windows had to trim the head, extension or not (cmd.:s, pwsh.:s); an untrimmed head without
        // a program extension keeps its ':' (python:3.12, node:20, cmd:x).
        if (name.IndexOf(':') is var colon and >= 0 && name[..colon] is var raw && raw.TrimEnd('.', ' ') is var head
            && (HasProgramExtension(head) || head != raw))
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
