using RedactingPty;
using TswapCore;

namespace TswapCli.Commands;

public sealed class RunCommand : ICliCommand
{
    public string Name => "run";
    public string HelpUsage => "run <cmd> [args...]";
    public string Description => "Execute with {{token}} and {{@file}} substitution";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is [])
            throw new UsageException($"{ctx.Prefix} run <command> [args...]");

        var commandArgs = args;
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
        var tokens = Validation.ExtractTokens(commandJoined);
        var fileTokens = commandArgs.SelectMany(Validation.ExtractFileTokens).Distinct(StringComparer.Ordinal).ToList();

        if (tokens.Count == 0 && fileTokens.Count == 0)
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
            ctx.Console.Out.WriteLine($"Found tokens: {string.Join(", ", tokens)}");
            if (fileTokens.Count > 0)
                ctx.Console.Out.WriteLine($"Found files: {string.Join(", ", fileTokens)}");
        }

        // Unlock and get secrets
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        // Verify all tokens exist and have non-null values. Null can appear if the secrets DB
        // was tampered/corrupted (System.Text.Json can produce null for non-nullable properties).
        // A token is a name or 'name:previous' (SecretsDb.ResolveToken).
        Dictionary<string, string> secretValues = [];
        foreach (var token in tokens)
        {
            secretValues[token] = db.ResolveToken(token)
                ?? throw new TswapException($"Secret '{token}' has a null value in the database — data may be corrupted.");
            // Warn about a burned value (current or previous), as apply does.
            if (db.IsBurnedToken(token))
                ctx.Console.Error.WriteLine($"Warning: '{token}' is a burned value — using it anyway; rotate it after use.");
        }

        // Redact every form of every value: raw, and its base64/base64url (and \r\n) variants.
        Dictionary<string, string> redactions = new(StringComparer.Ordinal);
        void Redact(string name, string raw, IEnumerable<string> written)
        {
            foreach (var form in written.Prepend(raw))
                foreach (var variant in Redaction.Variants(form))
                    redactions.TryAdd(variant, $"[REDACTED: {name}]");
        }
        foreach (var (token, value) in secretValues)
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
                    var (text, applied) = Apply.ApplySecretsReporting(ReadSource(token, source), db, ctx.Console.Error);
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
            var replacements = redactions
                .OrderByDescending(kv => kv.Key.Length)
                .Select(kv => new StreamReplacement(kv.Key, kv.Value))
                .ToList();

            var runner = ctx.PtyRunner();
            return files is null ? runner.Run(argv, replacements) : files.RunChild(() => runner.Run(argv, replacements));
        }
        finally
        {
            files?.Dispose();
        }
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
