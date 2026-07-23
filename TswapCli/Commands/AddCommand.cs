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
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} add <name>");
        var name = args[0];

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
        var db = ctx.Storage.LoadSecrets(key);

        db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' added successfully");
        return 0;
    }
}
