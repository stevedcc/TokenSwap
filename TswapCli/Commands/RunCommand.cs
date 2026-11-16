using RedactingPty;
using TswapCore;
using TswapCore.Fingerprints;

namespace TswapCli.Commands;

public sealed class RunCommand : ICliCommand
{
    public string Name => "run";
    public string HelpUsage => Usage;
    public string Description => "Execute with {{token}} and {{@file}} substitution; --env sets a secret in the command's environment instead of its arguments";
    public bool RequiresSudo => false;

    /// <summary>
    /// The usage: the help's, and the bare-<c>run</c> error's, also when the <c>--env</c> options are followed
    /// by no command (brief T26 round 2: one usage, so the error matches the option just typed).
    /// </summary>
    private const string Usage = "run [--env NAME={{name}}]... [--] <cmd> [args...]";

    /// <summary>The broker's cap on a template's env entries, also <c>run</c>'s on <c>--env</c> pairs.</summary>
    private const int MaxEnvPairs = 64;

    /// <summary>
    /// Brief T26: the arguments the registry's <c>--help</c> and <c>-v</c> scans look at: the value after a
    /// separate <c>--env</c> is skipped (there the <c>--env</c> shape refusal wins), and <c>--</c> ends them.
    /// </summary>
    public static string[] LeadingOptions(string[] args)
    {
        List<string> leading = [];
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--")
                break;
            if (args[i] == "--env")
            {
                i++;
                continue;
            }
            leading.Add(args[i]);
        }
        return [.. leading];
    }

    /// <summary>One <c>--env NAME={{token}}</c> pair: the variable's name and its one token.</summary>
    private sealed record EnvPair(string Name, string Token);

    public int Execute(CommandContext ctx, string[] args)
    {
        var (envPairs, commandArgs) = ParseOptions(args);
        if (commandArgs is [])
            throw new UsageException($"{ctx.Prefix} {Usage}");

        // Join for scanning only — NOT used for execution. Executing via shell would require
        // re-quoting and would destroy the argument structure the caller's shell already
        // parsed correctly (issue #75).
        var commandJoined = string.Join(" ", commandArgs);

        // Issue #251: a malformed {{@file}} token is refused first, before the "no tokens" check, also
        // next to valid {{name}} tokens. Per argument: a token split across arguments is never closed.
        foreach (var arg in commandArgs)
            Validation.ValidateFileTokens(arg);

        // Find {{tokens}} (an unknown '{{name:suffix}}' is an error, never literal text) and {{@file}} tokens.
        Validation.ThrowIfUnknownTokenSuffix(commandJoined);
        // #311 (owner decision A): fields never reach a command; a dotted token is refused before unlock.
        Validation.ThrowIfFieldOrMalformedToken(commandJoined);
        var tokens = Validation.ExtractTokens(commandJoined);
        var fileTokens = commandArgs.SelectMany(Validation.ExtractFileTokens).Distinct(StringComparer.Ordinal).ToList();

        // Brief T26: the tokens of the --env values count as run's tokens; each is resolved once, with the others.
        var envTokens = envPairs.Select(p => p.Token).Distinct(StringComparer.Ordinal).ToList();
        var allTokens = tokens.Union(envTokens, StringComparer.Ordinal).ToList();

        if (allTokens.Count == 0 && fileTokens.Count == 0)
            throw new TswapException("No {{tokens}} or {{@file}} tokens found in command");

        // Block obvious attempts to exfiltrate secrets via run: the blocklist, and shells or
        // interpreters given inline code (#105). Pre-substitution check catches them in the template.
        ThrowIfBlocked(Validation.GetBlockedInvocation(commandArgs));
        // Issue #251: with a {{@file}} token, no word of the command may print, encode or copy files,
        // or be a shell or interpreter, and the file is never the program.
        if (fileTokens.Count > 0)
            ThrowIfBlocked(Validation.GetFileTokenRefusal(commandArgs));

        // Block shell output redirection in the command template (secrets could be written
        // to readable files). Note: this check runs before token substitution. Secret values
        // that contain '|' or '>' are safe when exec'd directly because no shell interprets
        // them; only the command template itself is scanned here.
        if (Validation.HasPipeOrRedirect(commandJoined))
            throw new TswapException(
                "Pipes and output redirection are not allowed in 'run' commands.\n" +
                "Secrets could be captured to files or piped to other programs.\n" +
                "Use 'sudo ... get <name>' to retrieve a secret value.");

        var filesEnv = fileTokens.Count > 0 ? ctx.FilledFilesEnvironment ?? FilledFilesEnvironment.FromSystem() : null;
        // Root never creates a secret file in a user's folder (Windows: an elevated tswap is allowed;
        // the per-user temp folder and the ACL keep the copy private).
        if (filesEnv is not null && !OperatingSystem.IsWindows() && filesEnv.EffectiveUid() == 0)
            throw new TswapException(
                $"'{ctx.Prefix} run' with a {{{{@file}}}} token doesn't run as root: run it as your own user, without sudo.");

        if (ctx.Verbose)
        {
            ctx.Console.Out.WriteLine($"Found tokens: {string.Join(", ", allTokens)}");
            if (fileTokens.Count > 0)
                ctx.Console.Out.WriteLine($"Found files: {string.Join(", ", fileTokens)}");
            // The names only, never the values.
            if (envPairs.Count > 0)
                ctx.Console.Out.WriteLine($"Environment: {string.Join(", ", envPairs.Select(p => p.Name))}");
        }

        // Unlock. Brief T16-S3: only the value versions run substitutes are decrypted (its tokens and
        // the markers of its files, each once); every record's metadata is read without decrypting a
        // value, which also warns, naming the file, about a record nobody named that can't be read.
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        using var view = ctx.OpenVault(key);
        var metadata = view.LoadAll(FormatTwoRecords.Skip);
        // Every other fingerprinted value version of the vault is masked too (the matcher), and what
        // can't be is said before the child starts and again after it exits.
        RunCoverage.Warn(ctx.Console.Error, ctx.Prefix, metadata);

        // The format 2 line comes after the child's output, and also when run fails after it opened the
        // vault (as the other commands that decrypt values do), before the error.
        try
        {
            // Resolve every token first: a missing secret, a missing previous value or an unreadable record
            // (named by its hashed file) refuses before anything is written or started.
            // A token is a name or 'name:previous'.
            Dictionary<string, string> resolved = [];
            foreach (var token in allTokens)
            {
                resolved[token] = view.ResolveToken(token);
                // Warn about a burned value (current or previous), as apply does.
                if (view.IsBurnedToken(token))
                    ctx.Console.Error.WriteLine($"Warning: '{token}' is a burned value — using it anyway; rotate it after use.");
            }

            // Brief T26: the child's environment, kept apart from the argv tokens' values: an env value is
            // never in argv, so it never goes to the substitution, the word checks after it or NameCulprit.
            Dictionary<string, string> environment = new(StringComparer.Ordinal);
            foreach (var (name, token) in envPairs)
            {
                var value = resolved[token];
                if (value is null || value.Contains('\0'))
                    throw new TswapException(
                        $"Secret '{token}' has a null or NUL-containing value, which can't be set in a process's environment ('--env {name}'). " +
                        "Re-ingest the secret with a valid value.");
                environment[name] = value;
            }
            var secretValues = tokens.ToDictionary(token => token, token => resolved[token]);

            // Redact every form of every value: raw, and its base64/base64url (and \r\n) variants. An --env
            // value is masked exactly like a {{name}} in argv. Brief T30 (#314): every form of a short value
            // (under Validation.ShortValueLength) goes to the matcher, which masks it only where it stands as a
            // whole word or number; a long value's forms are masked anywhere, as RedactingPty replacements.
            Dictionary<string, string> redactions = new(StringComparer.Ordinal);
            Dictionary<string, string> shortForms = new(StringComparer.Ordinal);
            void Redact(string name, string raw, IEnumerable<string> written)
            {
                var target = !string.IsNullOrEmpty(raw) && Validation.IsShortValue(raw) ? shortForms : redactions;
                foreach (var form in written.Prepend(raw))
                    foreach (var variant in Redaction.Variants(form))
                        target.TryAdd(variant, $"[REDACTED: {name}]");
            }
            foreach (var (token, value) in resolved)
                Redact(token, value, []);

            // Issue #251: every file is resolved and filled in memory before anything is written; a
            // missing or unreadable file, one without markers or a marker naming a missing secret refuses
            // here, before any folder exists or any child starts.
            List<(string Token, string Source, string Filled)> filled = [];
            if (filesEnv is not null)
            {
                Dictionary<string, string> bySource = new(FilledFiles.SourcePathComparer);
                foreach (var token in fileTokens)
                {
                    var source = FullSourcePath(token, filesEnv.CurrentDirectory);
                    if (!bySource.TryGetValue(source, out var content))
                    {
                        var (text, applied) = Apply.ApplySecretsReporting(ReadSource(token, source), view, ctx.Console.Error);
                        foreach (var (name, raw, written) in applied)
                            Redact(name, raw, written);
                        bySource[source] = content = text;
                    }
                    filled.Add((token, source, content));
                }
            }

            // The same word check on what the {{name}} tokens expand to (file tokens still as
            // typed), before anything is written: a secret whose value is 'base64' can't be the printer. The
            // refusal names the token, never the word, which came from its value. All tokens
            // substituted at once decide (a word can come from two: {{a}}{{b}}, or {{w}} {{p}} as wrapper and
            // program); one token at a time only picks the one to name, else every token is named.
            if (filesEnv is not null && secretValues.Count > 0
                && Validation.GetFileTokenRefusal(Validation.SubstituteAllTokensInArgs(commandArgs, secretValues, new Dictionary<string, string>())) is not null)
            {
                var named = NameCulprit(commandArgs, secretValues, new Dictionary<string, string>(),
                    argv => Validation.GetFileTokenRefusal(argv) is not null, "is", "together make");
                throw new TswapException(
                    $"With a {{{{@file}}}} token, {named} a program or word that prints, " +
                    "encodes or copies files, or a shell or interpreter, which would expose the filled copy. " +
                    "Pass that secret another way, or run the command without the {{@file}} token.");
            }

            FilledFiles? files = null;
            FingerprintKeys? fingerprintKeys = null;
            FingerprintStreamMatcher? matcher = null;
            var childStarted = false;
            try
            {
                Dictionary<string, string> filePaths = new(StringComparer.Ordinal);
                if (filesEnv is not null)
                {
                    files = new FilledFiles(filesEnv); // signal handlers first, then the folder
                    files.SweepStale();
                    foreach (var (token, source, content) in filled)
                        filePaths[token] = files.Add(source, content);
                }

                // Substitute tokens — raw values, no shell quoting (we exec directly, no shell wrapper) —
                // and the filled copies' paths, in one pass: substituted text is never scanned again.
                var argv = Validation.SubstituteAllTokensInArgs(commandArgs, secretValues, filePaths);

                // Re-check after substitution: a token in the program or option position (e.g.
                // `run {{cmd}} arg` where {{cmd}} expands to `echo`, or `run sh {{opt}} ...` expanding
                // to `-c`) would bypass the pre-substitution check above.
                // The word refused here came from a secret's value, so the refusal names the token.
                if (Validation.GetBlockedInvocation(argv) is { } blocked)
                {
                    if (secretValues.Count == 0)
                        ThrowIfBlocked(blocked);
                    var named = NameCulprit(commandArgs, secretValues, filePaths,
                        a => Validation.GetBlockedInvocation(a) is not null, "makes", "together make");
                    throw new TswapException(
                        $"After substitution, {named} this a command 'run' refuses, which could expose secret values: " +
                        "a program that prints its arguments or environment, or a shell or interpreter given inline code " +
                        "or code from stdin, which can print them past redaction. The refusal doesn't repeat the word, " +
                        "which came from a secret's value.\nUse 'sudo ... get <name>' to view a secret.");
                }

                // Show the sanitised command
                if (ctx.Verbose)
                {
                    var sanitized = string.Join(" ", commandArgs.Select(Validation.SanitizeCommand));
                    ctx.Console.Out.WriteLine($"\nExecuting: {sanitized}");
                    ctx.Console.Out.WriteLine();
                }

                // Execute command via PTY so child processes see a real terminal — enabling colour
                // output, progress bars, and interactive prompts (kubectl exec, helm install, etc.).
                // PTY output is still intercepted and redacted before reaching our terminal.
                // Longest value first so a shorter secret sharing a prefix never clobbers a longer one.
                // A text that is also a long value's form is masked anywhere, with that value's label (brief T30).
                foreach (var text in redactions.Keys)
                    shortForms.Remove(text);
                var replacements = redactions
                    .OrderByDescending(kv => kv.Key.Length)
                    .Select(kv => new StreamReplacement(kv.Key, kv.Value))
                    .ToList();

                // Always with the matcher (an empty index holds nothing and matches nothing), so run has one
                // resolution path; output held back for a possible multi-line secret is released when the
                // child waits for terminal input.
                fingerprintKeys = FingerprintKeys.Derive(key);
                var options = new RedactionOptions
                {
                    Matchers = [matcher = FingerprintStreamMatcher.For(metadata, fingerprintKeys, shortForms)],
                    ReleaseWhenAwaitingInput = true,
                    // Brief T26: set for the child only, never in its argv; tswap's own environment is unchanged.
                    Environment = environment.Count > 0 ? environment : null,
                };
                var runner = ctx.PtyRunner();
                childStarted = true;
                var exitCode = files is null
                    ? runner.Run(argv, replacements, options)
                    : files.RunChild(() => runner.Run(argv, replacements, options));

                return exitCode;
            }
            finally
            {
                files?.Dispose();
                // After the child's output, also when its redaction failed: the coverage warning again
                // (then, in the outer finally, the format 2 line).
                if (childStarted)
                    RunCoverage.Warn(ctx.Console.Error, ctx.Prefix, metadata);
                matcher?.Dispose();
                fingerprintKeys?.Dispose();
            }
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Substitute);
        }
    }

    /// <summary>
    /// Brief T26: the leading <c>--env NAME={{token}}</c> pairs (also <c>--env=NAME={{token}}</c>, split at the
    /// first <c>=</c>), up to an optional <c>--</c>; the first other argument starts the command. Every refusal
    /// here comes before the vault is opened.
    /// </summary>
    private static (List<EnvPair> Pairs, string[] Command) ParseOptions(string[] args)
    {
        List<EnvPair> pairs = [];
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
        var i = 0;
        for (; i < args.Length; i++)
        {
            string pair;
            if (args[i] == "--")
            {
                i++;
                break;
            }
            if (args[i] == "--env")
            {
                if (++i == args.Length)
                    throw NoPair();
                pair = args[i];
            }
            else if (args[i].StartsWith("--env=", StringComparison.Ordinal))
                pair = args[i]["--env=".Length..];
            else
                break;

            var equals = pair.IndexOf('=');
            if (equals < 0)
                throw NoPair();
            var (name, value) = (pair[..equals], pair[(equals + 1)..]);
            ThrowIfRefusedName(name);
            var token = EnvToken(name, value);
            if (!names.Add(name))
                throw new TswapException($"'--env' sets {name} twice (names are compared ignoring case).");
            if (names.Count > MaxEnvPairs)
                throw new TswapException($"At most {MaxEnvPairs} '--env' variables.");
            pairs.Add(new EnvPair(name, token));
        }
        return (pairs, args[i..]);
    }

    private static TswapException NoPair() =>
        new("'--env' needs NAME={{name}} after it: the variable's name, '=' and one {{name}} token.");

    /// <summary>
    /// The broker's name rules (<see cref="ChildEnvironmentRules"/>), ignoring case, plus run's own: the macOS
    /// loader's <c>DYLD_*</c> and Windows' <c>PATHEXT</c>, <c>ComSpec</c> and <c>PSModulePath</c>.
    /// </summary>
    private static void ThrowIfRefusedName(string name)
    {
        var kind = ChildEnvironmentRules.Classify(name, StringComparison.OrdinalIgnoreCase);
        if (kind == ChildEnvironmentName.Allowed)
            kind = name.StartsWith("DYLD_", StringComparison.OrdinalIgnoreCase) ? ChildEnvironmentName.Loader
                : name.Equals("PATHEXT", StringComparison.OrdinalIgnoreCase) ? ChildEnvironmentName.Baseline
                : name.Equals("ComSpec", StringComparison.OrdinalIgnoreCase) || name.Equals("PSModulePath", StringComparison.OrdinalIgnoreCase)
                    ? ChildEnvironmentName.Code
                : ChildEnvironmentName.Allowed;
        switch (kind)
        {
            case ChildEnvironmentName.BadShape:
                throw new TswapException(
                    $"'--env': '{TswapCore.Broker.BrokerPolicy.Printable(name)}' is not a valid environment variable name " +
                    "(a letter or '_', then letters, digits and '_', at most 64 characters).");
            case ChildEnvironmentName.Baseline:
                throw new TswapException(
                    $"'--env' may not set {name}: it decides which program runs, or where and how it runs. Set it in your shell if you need it.");
            case ChildEnvironmentName.Loader:
                throw new TswapException(
                    $"'--env' may not set {name}: {(name.StartsWith("DYLD_", StringComparison.OrdinalIgnoreCase) ? "DYLD_" : "LD_")}* changes how every program loads.");
            case ChildEnvironmentName.Code:
                throw new TswapException(
                    $"'--env' may not set {name}: it can make a shell, interpreter, library or tool run extra code, or load, trust or " +
                    "write files it names. Set it in your shell if it isn't a secret.");
        }
    }

    /// <summary>An --env value: exactly one <c>{{name}}</c> or <c>{{name:previous}}</c>, nothing else.</summary>
    private static string EnvToken(string name, string value)
    {
        const string exactly = "the value must be exactly one {{name}} or {{name:previous}} token";
        if (value.Contains("{{@", StringComparison.Ordinal))
            throw new TswapException(
                $"'--env {name}': a {{{{@file}}}} token can't be an --env value (a file path isn't a secret): put it in the command.");
        Validation.ThrowIfUnknownTokenSuffix(value);
        // #311: a field token in an --env value gets the same refusal as one in the command (before unlock).
        Validation.ThrowIfFieldOrMalformedToken(value);
        if (Validation.TokenRegex.Match(value) is { Success: true } whole && whole.Length == value.Length)
            return whole.Groups[1].Value;
        if (!value.Contains("{{", StringComparison.Ordinal))
            throw new TswapException(
                $"'--env {name}': {exactly}, not a literal. A literal isn't a secret: set it in your shell, where the child inherits it.");
        throw new TswapException($"'--env {name}': {exactly}, with nothing around it.");
    }

    // A source file's text, or a refusal naming it (never a raw IO exception).
    private static string FullSourcePath(string token, string currentDirectory)
    {
        try
        {
            return Path.GetFullPath(token, currentDirectory);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new TswapException($"'{{{{@{token}}}}}' is not a valid path: {ex.Message}");
        }
    }

    private static string ReadSource(string token, string path)
    {
        string content;
        try
        {
            content = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new TswapException($"File '{token}' ({path}) not found.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new TswapException($"Can't read '{token}' ({path}): {ex.Message}");
        }
        if (!Apply.HasMarkers(content))
            throw new TswapException(
                $"'{token}' has no '# tswap:' markers, so there is nothing to fill: pass the file to the program as it is.");
        return content;
    }

    // Names the token whose value alone makes `refused` true ("the value of {{a}} <one>"), else every
    // token: a word can come from two ({{a}}{{b}}, or {{w}} {{p}} as wrapper and program).
    private static string NameCulprit(string[] commandArgs, Dictionary<string, string> secretValues,
        IReadOnlyDictionary<string, string> filePaths, Func<string[], bool> refused, string one, string together)
    {
        var culprit = secretValues.Keys.FirstOrDefault(token => refused(Validation.SubstituteAllTokensInArgs(
            commandArgs, new Dictionary<string, string> { [token] = secretValues[token] }, filePaths)));
        return culprit is not null
            ? $"the value of {{{{{culprit}}}}} {one}"
            : $"the values of {string.Join(", ", secretValues.Keys.Select(t => $"{{{{{t}}}}}"))} {together}";
    }

    private static void ThrowIfBlocked(Validation.BlockedInvocation? blocked)
    {
        if (blocked is not null)
            throw new TswapException($"{blocked.Reason}\nUse 'sudo ... get <name>' to view a secret.");
    }
}
