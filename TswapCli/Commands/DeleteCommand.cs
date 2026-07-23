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
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} delete <name>");
        var name = args[0];

        Validation.ValidateName(name);
        ctx.RequireSudo("delete");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        if (!db.Secrets.ContainsKey(name))
            throw new TswapException($"Secret '{name}' not found");

        db.Secrets.Remove(name);
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' deleted");
        return 0;
    }
}
