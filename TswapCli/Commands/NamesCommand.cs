using System.Text.Json;

namespace TswapCli.Commands;

public sealed class NamesCommand : ICliCommand
{
    public string Name => "names";
    public string HelpUsage => "names [--json]";
    public string Description => "List secret names (no values)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var json = JsonFlag.Consume(ref args);

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        var db = ctx.LoadSecrets(key);

        if (json)
        {
            var entries = db.Secrets
                .OrderBy(kv => kv.Key)
                .Select(kv => new NameEntry(kv.Key, kv.Value.BurnedAt.HasValue, kv.Value.BurnedAt))
                .ToList();
            ctx.Console.Out.WriteLine(JsonSerializer.Serialize(entries, CliJsonContext.Default.ListNameEntry));
            return 0;
        }

        if (db.Secrets.Count == 0)
        {
            ctx.Console.Out.WriteLine("No secrets stored.");
            return 0;
        }

        foreach (var name in db.Secrets.Keys.OrderBy(n => n))
        {
            var burned = db.Secrets[name].BurnedAt.HasValue ? " [BURNED]" : "";
            ctx.Console.Out.WriteLine($"{name}{burned}");
        }
        return 0;
    }
}
