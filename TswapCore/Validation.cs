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
    // An interpreter's command-line syntax, as far as the check needs it.
    //   Inline:     short option letters that mean "code follows" (in a cluster too: -ec, -nle).
    //   InlineLong: long options that mean the same (--eval, --command).
    //   Valued:     short option letters that take a value, attached (-Ilib, -mcalendar) or as
    //               the next argument (-o pipefail); the rest of the cluster is that value, so
    //               its letters are never read as flags.
    //   ValuedLong: long options whose value is the next argument (--rcfile rc).
    //   EndsOptions: an option that ends option parsing like a script does (python -m module).
    //   Plus:       '+' options exist (bash +o posix).
    private sealed record InterpreterSyntax(string Inline, string[] InlineLong, string Valued,
        string[] ValuedLong, string? EndsOptions = null, bool Plus = false);

    private static readonly InterpreterSyntax ShellSyntax = new("cs", [], "oO", ["--rcfile", "--init-file"], Plus: true);

    private static readonly Dictionary<string, InterpreterSyntax> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sh"] = ShellSyntax, ["bash"] = ShellSyntax, ["zsh"] = ShellSyntax, ["dash"] = ShellSyntax,
        ["ksh"] = ShellSyntax, ["mksh"] = ShellSyntax, ["ash"] = ShellSyntax, ["tcsh"] = ShellSyntax,
        ["csh"] = ShellSyntax,
        ["fish"] = ShellSyntax with { InlineLong = ["--command"] },
        ["perl"] = new("eE", [], "IMmx", []),
        ["ruby"] = new("e", [], "IrCE", []),
        ["node"] = new("ep", ["--eval", "--print"], "rC", ["--require", "--import", "--loader", "--conditions"]),
        ["nodejs"] = new("ep", ["--eval", "--print"], "rC", ["--require", "--import", "--loader", "--conditions"]),
        ["bun"] = new("ep", ["--eval", "--print"], "r", ["--preload", "--cwd", "--config"]),
        ["php"] = new("rBRE", [], "cdzt", []),
        ["lua"] = new("e", [], "l", []),
        ["julia"] = new("eE", ["--eval", "--print"], "JLOp", ["--project", "--sysimage", "--load"]),
        ["rscript"] = new("e", [], "", []),
        ["osascript"] = new("e", [], "ls", []),
        ["expect"] = new("c", [], "f", []),
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
          "npx", "pnpx", "bunx", "pnpm", "yarn", "bundle", "docker", "podman", "nerdctl", "kubectl",
          "oc" };

    // ssh options that take a value; a non-option argument after the host is a remote command.
    private const string SshValued = "BbcDEeFIiJLlmOoPpQRSWw";

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
        {
            // Follow the wrapped command: the first later argument naming a checked program.
            for (var i = 0; i < args.Count; i++)
            {
                if (!IsCheckedProgram(ProgramName(args[i])))
                    continue;
                var inner = GetBlockedInvocation(args.Skip(i).ToList());
                if (inner != null)
                    return inner with { Reason = $"'{program}' runs '{inner.Program}': {inner.Reason}" };
            }
            return null;
        }

        if (CodeRunners.Contains(program))
            return new(program, $"'{program}' runs code or commands given on its command line, which can transform and print secrets past redaction. {WayOut}");

        if (AwkNames.Contains(program))
        {
            // Program text from a file (-f) is allowed; inline program text or -e/--source isn't.
            var inlineSource = args.Any(a => a == "-e" || a.StartsWith("--source", StringComparison.Ordinal));
            var fromFile = args.Any(a => a == "-f" || a.StartsWith("--file", StringComparison.Ordinal) || (a.StartsWith("-f", StringComparison.Ordinal) && a.Length > 2));
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
                var command = args.Skip(i + 1).TakeWhile(a => a is not (";" or "+")).ToList();
                var inner = command.Count == 0 ? null : GetBlockedInvocation(command);
                if (inner != null)
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
            return flag != null ? new(program, InlineReason(program, flag)) : null;
        }

        if (PythonName.IsMatch(program))
            return CheckInterpreter(program, args, PythonSyntax);
        if (Interpreters.TryGetValue(program, out var syntax))
            return CheckInterpreter(program, args, syntax);

        return null;
    }

    // PowerShell accepts unambiguous prefixes of its parameters (-comm = -Command).
    private static bool IsPowerShellInline(string arg)
    {
        var a = arg.ToLowerInvariant();
        if (a is "-c" or "-e" or "-ec" or "-cwa")
            return true;
        return (a.Length >= 4 && "-command".StartsWith(a, StringComparison.Ordinal))
            || (a.Length >= 4 && "-encodedcommand".StartsWith(a, StringComparison.Ordinal))
            || (a.Length >= 9 && "-commandwithargs".StartsWith(a, StringComparison.Ordinal));
    }

    // ssh host [command]: a remote command is remote shell code.
    private static BlockedInvocation? CheckSsh(List<string> args)
    {
        string? host = null;
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (host == null)
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
                    if (syntax.EndsOptions != null && syntax.EndsOptions.Contains(letter))
                        return null; // e.g. python -m module: the module is the script
                    if (syntax.Inline.Contains(letter) && arg[0] == '-')
                        return new(program, InlineReason(program, arg));
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
        || CodeRunners.Contains(name) || AwkNames.Contains(name) || Wrappers.Contains(name)
        || name.Equals("find", StringComparison.OrdinalIgnoreCase) || name.Equals("ssh", StringComparison.OrdinalIgnoreCase)
        || name.Equals("deno", StringComparison.OrdinalIgnoreCase) || name.Equals("cmd", StringComparison.OrdinalIgnoreCase)
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
