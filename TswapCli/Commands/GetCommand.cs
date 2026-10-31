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
        var db = ctx.LoadSecrets(key);

        if (!db.Secrets.ContainsKey(name))
        {
            db.ThrowIfUnreadable(name);
            throw new TswapException($"Secret '{name}' not found");
        }

        ctx.Console.Out.WriteLine(db.Secrets[name].Value);
        return 0;
    }
}
