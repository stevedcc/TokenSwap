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
          "kubectl", "oc", "lxc", "incus", "flatpak", "snap", "machinectl", "toolbox", "distrobox" };

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
            if (command != null)
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
            var programFiles = new List<string>();
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
            var inner = GetBlockedInvocation(args.Skip(from).ToList());
            return inner == null ? null : inner with { Reason = $"'{program}' runs '{inner.Program}': {inner.Reason}" };
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
                if (entry != null && IsInterpreter(ProgramName(entry)))
                    return new(program, $"'{program} --entrypoint {entry}' runs an interpreter whose code arguments can't be checked. {WayOut}");
            }
            var sub = args.FindIndex(a => !a.StartsWith('-'));
            if (sub < 0 || !ExecSubcommands.Contains(args[sub]))
                return null; // pull, install, build ...: nothing is run
            if (program.Equals("machinectl", StringComparison.OrdinalIgnoreCase) && args[sub] is "shell" or "login"
                && !args.Skip(sub + 1).Where(a => !a.StartsWith('-')).Skip(1).Any())
                return new(program, $"'machinectl {args[sub]}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {WayOut}");
            for (var i = sub + 1; i < args.Count; i++)
                if (IsCheckedProgram(ProgramName(args[i])) && Wrapped(i) is { } blocked)
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
                if (valued != null && valued.Contains(arg, StringComparer.Ordinal))
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
            if (IsCheckedProgram(ProgramName(arg)))
                return Wrapped(i);
            // Not a checked program. For a wrapper whose options this check knows completely,
            // it is the command (sudo apt install python3 passes). For any other wrapper it may
            // be the value of an unknown option (bwrap --ro-bind / / python), so keep scanning
            // and refuse any later checked program that would be refused on its own, a bare
            // interpreter reading stdin included: failing closed.
            if (TrustedWrappers.Contains(program))
                return null;
            for (var k = i + 1; k < args.Count; k++)
                if (IsCheckedProgram(ProgramName(args[k])) && Wrapped(k) is { } later)
                    return later;
            return null;
        }
        // No command at all: these wrappers then start a shell that reads stdin.
        return ShellWhenNoCommand.Contains(program)
            ? new(program, $"'{program}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {WayOut}")
            : null;
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
        var own = new List<string>();
        for (var i = 0; i < args.Count; i++)
        {
            if (args[i] == "--" || !args[i].StartsWith('-'))
                break;
            own.Add(args[i]);
            if (valued != null && valued.Contains(args[i], StringComparer.Ordinal))
                i++;
        }
        return own;
    }

    private static bool IsInterpreter(string name) =>
        PythonName.IsMatch(name) || Interpreters.ContainsKey(name) || AwkNames.Contains(name)
        || name.Equals("pwsh", StringComparison.OrdinalIgnoreCase) || name.Equals("powershell", StringComparison.OrdinalIgnoreCase)
        || name.Equals("cmd", StringComparison.OrdinalIgnoreCase) || name.Equals("deno", StringComparison.OrdinalIgnoreCase);

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
                    if (syntax.ScriptOption.Contains(letter))
                    {
                        // The value is the script file: attached, or the next argument. Options
                        // after it can still carry inline code (expect -f s.exp -c '...').
                        var script = j < arg.Length - 1 ? arg[(j + 1)..] : (i + 1 < args.Count ? args[i + 1] : "");
                        if (StdinScripts.Contains(script) || script.Length == 0)
                            return new(program, $"'{program} {arg} {script}' reads code from stdin, which can transform and print secrets past redaction. {WayOut}");
                        var later = args.Skip(i + (j < arg.Length - 1 ? 1 : 2))
                            .FirstOrDefault(a => a.StartsWith('-') && !a.StartsWith("--", StringComparison.Ordinal) && a.Skip(1).Any(syntax.Inline.Contains));
                        return later != null ? new(program, InlineReason(program, later)) : null;
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
