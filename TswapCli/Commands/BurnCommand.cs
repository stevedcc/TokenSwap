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
        if (args is not [var name, ..])
            throw new UsageException($"{ctx.Prefix} burn <name> [reason]");
        var reason = args.Length >= 2 ? string.Join(" ", args.Skip(1)) : null;

        Validation.ValidateName(name);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        // Brief T16-S2b: only this record is read; a burn copies every value section, decrypting none.
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            if (writer.Find(name) is not { } existing)
            {
                writer.ThrowIfUnreadable(name);
                throw new TswapException($"Secret '{name}' not found");
            }

            if (existing.BurnedAt.HasValue)
            {
                var originalReason = existing.BurnReason ?? "(no reason given)";
                throw new TswapException($"Secret '{name}' is already burned (since {existing.BurnedAt:yyyy-MM-dd HH:mm}: {originalReason})");
            }

            writer.Burn(name, reason);
            writer.Commit();

            ctx.Console.Out.WriteLine($"\n⚠ Secret '{name}' marked as BURNED");
            ctx.Console.Out.WriteLine("  This secret should be rotated as soon as possible.");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }
}
