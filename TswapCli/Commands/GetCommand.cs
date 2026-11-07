using TswapCore;

namespace TswapCli.Commands;

public sealed class GetCommand : ICliCommand
{
    public string Name => "get";
    public string HelpUsage => "get <name>";
    public string Description => "Get a secret value";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var name, ..])
            throw new UsageException($"{ctx.Prefix} get <name>");

        Validation.ValidateName(name);
        ctx.RequireSudo("get");
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // Brief T16-S2: only this secret's record, and only its current value section (format 2:
        // that record, decoded whole, and the format 2 warning). Errors as before.
        using var view = ctx.OpenVault(key);
        try
        {
            ctx.Console.Out.WriteLine(view.ResolveToken(name));
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Substitute);
        }
    }
}
