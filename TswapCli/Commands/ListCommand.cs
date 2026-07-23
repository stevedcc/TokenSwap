namespace TswapCli.Commands;

public sealed class ListCommand : ICliCommand
{
    public string Name => "list";
    public string HelpUsage => "list";
    public string Description => "List all secrets (names and dates, no values)";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("list");
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        if (db.Secrets.Count == 0)
        {
            ctx.Console.Out.WriteLine("No secrets stored.");
            return 0;
        }

        var nameWidth = Math.Max(20, db.Secrets.Keys.Max(n => n.Length));
        var lineWidth = nameWidth + 2 + 16 + 2 + 16; // name + gaps + two date columns

        ctx.Console.Out.WriteLine($"\nSecrets ({db.Secrets.Count}):");
        ctx.Console.Out.WriteLine($"{"NAME".PadRight(nameWidth)}  {"CREATED".PadRight(16)}  MODIFIED");
        ctx.Console.Out.WriteLine("".PadRight(lineWidth, '-'));

        foreach (var (name, secret) in db.Secrets.OrderBy(s => s.Key))
        {
            ctx.Console.Out.WriteLine($"{name.PadRight(nameWidth)}  {secret.Created:yyyy-MM-dd HH:mm}  {secret.Modified:yyyy-MM-dd HH:mm}");
        }
        return 0;
    }
}
