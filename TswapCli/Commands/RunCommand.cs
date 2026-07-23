using ConsoleIntercept;
using TswapCore;

namespace TswapCli.Commands;

public sealed class RunCommand : ICliCommand
{
    public string Name => "run";
    public string HelpUsage => "run <cmd> [args...]";
    public string Description => "Execute with {{token}} substitution";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} run <command> [args...]");

        var commandArgs = args;
        // Join for scanning only — NOT used for execution. Executing via shell would require
        // re-quoting and would destroy the argument structure the caller's shell already
        // parsed correctly (issue #75).
        var commandJoined = string.Join(" ", commandArgs);

        // Find {{tokens}}
        var tokens = Validation.ExtractTokens(commandJoined);

        if (tokens.Count == 0)
            throw new TswapException("No {{tokens}} found in command");

        // Block obvious attempts to exfiltrate secrets via run.
        // Pre-substitution check catches literal blocked commands in the template.
        var blocked = Validation.GetBlockedCommand(commandArgs[0]);
        if (blocked != null)
            throw new TswapException(
                $"The command '{blocked}' would expose secret values.\n" +
                "The 'run' command is for programs that *use* secrets, not display them.\n" +
                "Use 'sudo ... get <name>' to view a secret.");

        // Block shell output redirection in the command template (secrets could be written
        // to readable files). Note: this check runs before token substitution. Secret values
        // that contain '|' or '>' are safe when exec'd directly because no shell interprets
        // them; only the command template itself is scanned here.
        if (Validation.HasPipeOrRedirect(commandJoined))
            throw new TswapException(
                "Pipes and output redirection are not allowed in 'run' commands.\n" +
                "Secrets could be captured to files or piped to other programs.\n" +
                "Use 'sudo ... get <name>' to retrieve a secret value.");

        if (ctx.Verbose) ctx.Console.Out.WriteLine($"Found tokens: {string.Join(", ", tokens)}");

        // Unlock and get secrets
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.Storage.LoadSecrets(key);

        // Verify all tokens exist and have non-null values. Null can appear if the secrets DB
        // was tampered/corrupted (System.Text.Json can produce null for non-nullable properties).
        foreach (var token in tokens)
        {
            if (!db.Secrets.ContainsKey(token))
                throw new TswapException($"Secret '{token}' not found");
            if (db.Secrets[token].Value == null)
                throw new TswapException($"Secret '{token}' has a null value in the database — data may be corrupted.");
        }

        // Substitute tokens — raw values, no shell quoting (we exec directly, no shell wrapper).
        var secretValues = tokens.ToDictionary(t => t, t => db.Secrets[t].Value);
        var argv = Validation.SubstituteTokensInArgs(commandArgs, secretValues);

        // Re-check the blocklist against argv[0] after substitution: a token in the executable
        // position (e.g. `run {{cmd}} arg` where {{cmd}} expands to `echo`) would bypass the
        // pre-substitution check above.
        var blockedPost = Validation.GetBlockedCommand(argv[0]);
        if (blockedPost != null)
            throw new TswapException(
                $"The command '{blockedPost}' would expose secret values.\n" +
                "The 'run' command is for programs that *use* secrets, not display them.\n" +
                "Use 'sudo ... get <name>' to view a secret.");

        // Show sanitized version
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
        var replacements = secretValues
            .OrderByDescending(kv => kv.Value.Length)
            .Select(kv => new StreamReplacement(kv.Value, $"[REDACTED: {kv.Key}]"))
            .ToList();

        return PtyRunnerFactory.Create().Run(argv, replacements);
    }
}
