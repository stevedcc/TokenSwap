using TswapCore;

namespace TswapCli.Commands;

public sealed class BurnCommand : ICliCommand
{
    public string Name => "burn";
    public string HelpUsage => "burn <name> [reason]";
    public string Description => "Mark a secret as burned";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} burn <name> [reason]");
        var name = args[0];
        var reason = args.Length >= 2 ? string.Join(" ", args.Skip(1)) : null;

        Validation.ValidateName(name);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        var db = ctx.Storage.LoadSecrets(key);

        if (!db.Secrets.ContainsKey(name))
            throw new TswapException($"Secret '{name}' not found");

        var existing = db.Secrets[name];
        if (existing.BurnedAt.HasValue)
        {
            var originalReason = existing.BurnReason ?? "(no reason given)";
            throw new TswapException($"Secret '{name}' is already burned (since {existing.BurnedAt:yyyy-MM-dd HH:mm}: {originalReason})");
        }

        db.Secrets[name] = existing with { BurnedAt = DateTime.UtcNow, BurnReason = reason };
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n⚠ Secret '{name}' marked as BURNED");
        ctx.Console.Out.WriteLine("  This secret should be rotated as soon as possible.");
        return 0;
    }
}
