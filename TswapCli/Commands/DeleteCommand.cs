using TswapCore;

namespace TswapCli.Commands;

public sealed class DeleteCommand : ICliCommand
{
    public string Name => "delete";
    public string HelpUsage => "delete <name>";
    public string Description => "Delete a secret";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var name, ..])
            throw new UsageException($"{ctx.Prefix} delete <name>");

        Validation.ValidateName(name);
        ctx.RequireSudo("delete");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // Brief T16-S2b: only this record is read; one tombstone for one name, no value decrypted.
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            if (writer.Find(name) is null)
            {
                writer.ThrowIfUnreadable(name);
                throw new TswapException($"Secret '{name}' not found");
            }

            writer.Delete(name);
            writer.Commit();

            ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' deleted");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }
}
