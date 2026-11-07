using TswapCore;

namespace TswapCli.Commands;

public sealed class AddCommand : ICliCommand
{
    public string Name => "add";
    public string HelpUsage => "add <name>";
    public string Description => "Add a secret (user-provided value)";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var name, ..])
            throw new UsageException($"{ctx.Prefix} add <name>");

        Validation.ValidateName(name);
        ctx.RequireSudo("add");
        var config = ctx.Storage.LoadConfig();

        ctx.Console.Out.Write($"Secret value for '{name}': ");
        var value = ctx.Console.ReadPassword();
        ctx.Console.Out.Write("Confirm value: ");
        var confirm = ctx.Console.ReadPassword();

        if (value != confirm)
            throw new TswapException("Values don't match");

        var key = ctx.Unlock(config);
        // Brief T16-S2b: only this name's record is read; whether the value changed is decided from
        // its stored fingerprints (one value is decrypted only when they can't tell).
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            writer.SetValue(name, value, ctx.Time.GetUtcNow().UtcDateTime);
            writer.Commit();

            ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' added successfully");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }
}
