using System.Text.Json;

namespace TswapCli.Commands;

public sealed class BurnedCommand : ICliCommand
{
    public string Name => "burned";
    public string HelpUsage => "burned [--json]";
    public string Description => "List all burned secrets";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var json = JsonFlag.Consume(ref args);

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        var db = ctx.LoadSecrets(key);

        var burned = db.Secrets
            .Where(s => s.Value.BurnedAt.HasValue)
            .OrderBy(s => s.Value.BurnedAt)
            .ToList();

        if (json)
        {
            var entries = burned
                .Select(s => new BurnedEntry(s.Key, s.Value.BurnedAt, s.Value.BurnReason))
                .ToList();
            ctx.Console.Out.WriteLine(JsonSerializer.Serialize(entries, CliJsonContext.Default.ListBurnedEntry));
            return 0;
        }

        if (burned.Count == 0)
        {
            ctx.Console.Out.WriteLine("No burned secrets. All secrets are clean.");
            return 0;
        }

        var nameWidth = Math.Min(40, burned.Max(s => s.Key.Length));
        var dateWidth = 18; // "yyyy-MM-dd HH:mm" + 2 spaces
        var headerWidth = nameWidth + 2 + dateWidth + 2 + 6; // 6 = "REASON".Length

        ctx.Console.Out.WriteLine($"\n⚠ Burned Secrets ({burned.Count}):");
        ctx.Console.Out.WriteLine($"{"NAME".PadRight(nameWidth)}  {"BURNED AT".PadRight(dateWidth)}  REASON");
        ctx.Console.Out.WriteLine("".PadRight(Math.Max(headerWidth, 60), '-'));

        foreach (var (name, secret) in burned)
        {
            var reason = secret.BurnReason ?? "(no reason given)";
            if (name.Length <= nameWidth)
            {
                ctx.Console.Out.WriteLine($"{name.PadRight(nameWidth)}  {secret.BurnedAt:yyyy-MM-dd HH:mm}  {reason}");
            }
            else
            {
                ctx.Console.Out.WriteLine(name);
                ctx.Console.Out.WriteLine($"{"".PadRight(nameWidth)}  {secret.BurnedAt:yyyy-MM-dd HH:mm}  {reason}");
            }
        }

        ctx.Console.Out.WriteLine($"\n→ Rotate these secrets, then 'delete' and re-create them.");
        return 0;
    }
}
