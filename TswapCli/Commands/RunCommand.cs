using RedactingPty;
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

        // Find {{tokens}} (an unknown '{{name:suffix}}' is an error, never literal text).
        Validation.ThrowIfUnknownTokenSuffix(commandJoined);
        var tokens = Validation.ExtractTokens(commandJoined);

        if (tokens.Count == 0)
            throw new TswapException("No {{tokens}} found in command");

        // Block obvious attempts to exfiltrate secrets via run: the blocklist, and shells or
        // interpreters given inline code (#105). Pre-substitution check catches them in the template.
        ThrowIfBlocked(Validation.GetBlockedInvocation(commandArgs));

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
        var db = ctx.LoadSecrets(key);

        // Verify all tokens exist and have non-null values. Null can appear if the secrets DB
        // was tampered/corrupted (System.Text.Json can produce null for non-nullable properties).
        // Fix round 1, B: a token is a name or 'name:previous' (SecretsDb.ResolveToken).
        var secretValues = new Dictionary<string, string>();
        foreach (var token in tokens)
        {
            secretValues[token] = db.ResolveToken(token)
                ?? throw new TswapException($"Secret '{token}' has a null value in the database — data may be corrupted.");
            // Fix round 3: warn about a burned value (current or previous), as apply does.
            if (db.IsBurnedToken(token))
                ctx.Console.Error.WriteLine($"Warning: '{token}' is a burned value — using it anyway; rotate it after use.");
        }

        // Substitute tokens — raw values, no shell quoting (we exec directly, no shell wrapper).
        var argv = Validation.SubstituteTokensInArgs(commandArgs, secretValues);

        // Re-check after substitution: a token in the program or option position (e.g.
        // `run {{cmd}} arg` where {{cmd}} expands to `echo`, or `run sh {{opt}} ...` expanding
        // to `-c`) would bypass the pre-substitution check above.
        ThrowIfBlocked(Validation.GetBlockedInvocation(argv));

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

    private static void ThrowIfBlocked(Validation.BlockedInvocation? blocked)
    {
        if (blocked != null)
            throw new TswapException($"{blocked.Reason}\nUse 'sudo ... get <name>' to view a secret.");
    }
}
