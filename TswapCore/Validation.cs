using System.Text.RegularExpressions;

namespace TswapCore;

public static class Validation
{
    public static readonly Regex TokenRegex = new(@"\{\{([a-zA-Z0-9_-]+)\}\}");

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
    // ordinary argument is code are refused. Still a shallow blocklist (README §Threat model):
    // a script file or any other program can misuse a secret it is given.
    private static readonly HashSet<string> Shells = new(StringComparer.OrdinalIgnoreCase)
        { "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh" };

    // Interpreter → its short inline-code option letters, long inline-code options, and the
    // options that take a separate value (skipped, so the value isn't taken for the script).
    private static readonly Dictionary<string, (string Letters, string[] Long, string[] Valued)> Interpreters =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["perl"] = ("eE", [], ["-I", "-x"]),
            ["ruby"] = ("e", [], ["-I", "-r", "-C", "-E"]),
            ["node"] = ("ep", ["--eval", "--print"], ["-r", "--require", "--import", "--loader", "-C", "--conditions"]),
            ["nodejs"] = ("ep", ["--eval", "--print"], ["-r", "--require", "--import", "--loader", "-C", "--conditions"]),
            ["php"] = ("r", [], ["-c", "-d", "-z", "-t"]),
            ["lua"] = ("e", [], ["-l"]),
        };

    private static readonly string[] ShellValued = ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"];
    private static readonly string[] PythonValued = ["-W", "-X"];

    private static readonly Regex PythonName = new(@"^python[0-9.]*$", RegexOptions.IgnoreCase);

    // Their normal argument is code, or they run another program on their arguments.
    private static readonly HashSet<string> CodeRunners = new(StringComparer.OrdinalIgnoreCase)
        { "awk", "gawk", "mawk", "nawk", "xargs", "busybox" };

    private static readonly HashSet<string> FindExecOptions = new(StringComparer.Ordinal)
        { "-exec", "-execdir", "-ok", "-okdir" };

    // Run the command that follows them: the check applies to that command.
    private static readonly HashSet<string> Wrappers = new(StringComparer.OrdinalIgnoreCase)
        { "nohup", "nice", "timeout", "stdbuf", "setsid", "time", "command", "sudo", "doas",
          "ionice", "chrt", "taskset", "flock", "unbuffer", "exec" };

    // Script paths that are really stdin.
    private static readonly HashSet<string> StdinScripts = new(StringComparer.Ordinal)
        { "-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0" };

    private const string WayOut =
        "Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' " +
        "(the script reads the value as $1).";

    /// <summary>
    /// Checks a whole <c>run</c> command line (issue #105). Returns null when allowed, or the
    /// program and the reason when refused: the existing blocklist (by basename), a shell or
    /// interpreter given inline code or code from stdin, a program whose argument is code
    /// (awk, xargs, busybox, find -exec), and any of these behind a wrapper (timeout, nice, sudo...).
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
        {
            // Follow the wrapped command: the first later argument that is itself checked.
            for (var i = 0; i < args.Count; i++)
            {
                var inner = GetBlockedInvocation(args.Skip(i).ToList());
                if (inner != null && IsCheckedProgram(ProgramName(args[i])))
                    return inner with { Reason = $"'{program}' runs '{inner.Program}': {inner.Reason}" };
            }
            return null;
        }

        if (CodeRunners.Contains(program))
            return new(program, $"'{program}' runs code or commands given on its command line, which can transform and print secrets past redaction. {WayOut}");

        if (program.Equals("find", StringComparison.OrdinalIgnoreCase) && args.Any(FindExecOptions.Contains))
            return new(program, $"'find -exec' runs a command on the secret, which can print it past redaction. {WayOut}");

        if (program.Equals("cmd", StringComparison.OrdinalIgnoreCase)
            && args.Any(a => a.Equals("/c", StringComparison.OrdinalIgnoreCase) || a.Equals("/k", StringComparison.OrdinalIgnoreCase)))
            return new(program, InlineReason(program, "/c"));

        if (program.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || program.Equals("powershell", StringComparison.OrdinalIgnoreCase))
        {
            string[] inline = ["-c", "-command", "-e", "-ec", "-encodedcommand"];
            var flag = args.FirstOrDefault(a => inline.Contains(a, StringComparer.OrdinalIgnoreCase));
            return flag != null ? new(program, InlineReason(program, flag)) : null;
        }

        if (Shells.Contains(program))
            return CheckInterpreter(program, args, "cs", program.Equals("fish", StringComparison.OrdinalIgnoreCase) ? ["--command"] : [], ShellValued, plusOptions: true);
        if (PythonName.IsMatch(program))
            return CheckInterpreter(program, args, "c", [], PythonValued, plusOptions: false);
        if (Interpreters.TryGetValue(program, out var spec))
            return CheckInterpreter(program, args, spec.Letters, spec.Long, spec.Valued, plusOptions: false);

        return null;
    }

    // Options before the script name decide; everything after the script belongs to the script.
    private static BlockedInvocation? CheckInterpreter(string program, List<string> args, string inlineLetters,
        string[] inlineLong, string[] valued, bool plusOptions)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == "--")
                continue;
            // An option that takes a separate value: skip the value, or it would be taken for
            // the script name and end the check early (bash -o pipefail -c ...).
            if (valued.Contains(arg, StringComparer.Ordinal))
            {
                i++;
                continue;
            }
            if (plusOptions && arg.StartsWith('+'))
                continue;
            if (StdinScripts.Contains(arg))
                return new(program, $"'{program} {arg}' reads code from stdin, which can transform and print secrets past redaction. {WayOut}");
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                var name = arg.Split('=', 2)[0];
                if (inlineLong.Contains(name, StringComparer.Ordinal))
                    return new(program, InlineReason(program, name));
                continue;
            }
            if (arg.StartsWith('-'))
            {
                if (arg.Skip(1).Any(inlineLetters.Contains))
                    return new(program, InlineReason(program, arg));
                continue;
            }
            return null; // the script file
        }
        return new(program, $"'{program}' with no script file reads code from stdin, which can transform and print secrets past redaction. {WayOut}");
    }

    private static string InlineReason(string program, string flag) =>
        $"'{program} {flag}' runs inline code, which can transform and print secrets past redaction. {WayOut}";

    private static bool IsCheckedProgram(string name) =>
        BlockedCommands.Contains(name) || Shells.Contains(name) || PythonName.IsMatch(name)
        || Interpreters.ContainsKey(name) || CodeRunners.Contains(name) || Wrappers.Contains(name)
        || name.Equals("find", StringComparison.OrdinalIgnoreCase) || name.Equals("cmd", StringComparison.OrdinalIgnoreCase)
        || name.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || name.Equals("powershell", StringComparison.OrdinalIgnoreCase);

    // Basename without a Windows executable extension: /bin/sh → sh, cmd.exe → cmd.
    private static string ProgramName(string path)
    {
        var name = path.Replace('\\', '/');
        name = name[(name.LastIndexOf('/') + 1)..];
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

        var result = new string[args.Length];
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            foreach (var (token, value) in secretValues)
                a = a.Replace($"{{{{{token}}}}}", value);
            result[i] = a;
        }
        return result;
    }

    /// <summary>
    /// Sanitize a command by replacing all tokens with ********.
    /// </summary>
    public static string SanitizeCommand(string command)
    {
        return TokenRegex.Replace(command, "********");
    }
}
