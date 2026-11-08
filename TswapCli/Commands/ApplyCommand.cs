using TswapCore;

namespace TswapCli.Commands;

public sealed class ApplyCommand : ICliCommand
{
    public string Name => "apply";
    public string HelpUsage => "apply <file>";
    public string Description => "Print a file with # tswap: markers filled in (human use; agents: run … {{@file}})";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var filePath, ..])
            throw new UsageException($"{ctx.Prefix} apply <file>");

        ctx.RequireSudo("apply",
            $"Agents: do not use sudo. To use a file with secrets in a command, run:\n  {ctx.Prefix} run … {{{{@file}}}}\n(for Helm: {ctx.Prefix} run helm upgrade --install app ./chart -f {{{{@values.yaml}}}})");

        if (!File.Exists(filePath))
            throw new TswapException($"File not found: {filePath}");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // Brief T16-S2: only the records its markers name, and only the value versions it fills in.
        using var view = ctx.OpenVault(key);
        try
        {
            var content = File.ReadAllText(filePath);
            var applied = Apply.ApplySecrets(content, view, warnings: ctx.Console.Error);
            ctx.Console.Out.Write(applied);
            return 0;
        }
        finally
        {
            // Also when a later marker fails: the records used so far were decrypted (owner decision 1).
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Substitute);
        }
    }
}
