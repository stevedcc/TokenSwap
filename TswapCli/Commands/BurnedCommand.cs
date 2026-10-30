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
            .Select(s => (Name: s.Key, BurnedAt: s.Value.BurnedAt!.Value, Reason: s.Value.BurnReason))
            .OrderBy(s => s.BurnedAt)
            .ToList();
        // Brief T6 decision 7: a burn a newer value superseded (a rotation) is history, not outstanding.
        var rotated = db.Secrets
            .SelectMany(s => (s.Value.History ?? []).Select(h => (Name: s.Key, h.BurnedAt, h.Reason)))
            .OrderBy(s => s.BurnedAt)
            .ToList();

        if (json)
        {
            var entries = burned.Select(s => new BurnedEntry(s.Name, s.BurnedAt, s.Reason, "outstanding"))
                .Concat(rotated.Select(s => new BurnedEntry(s.Name, s.BurnedAt, s.Reason, "rotated")))
                .ToList();
            ctx.Console.Out.WriteLine(JsonSerializer.Serialize(entries, CliJsonContext.Default.ListBurnedEntry));
            return 0;
        }

        if (burned.Count == 0 && rotated.Count == 0)
        {
            ctx.Console.Out.WriteLine("No burned secrets. All secrets are clean.");
            return 0;
        }

        if (burned.Count == 0)
        {
            ctx.Console.Out.WriteLine("No outstanding burned secrets.");
        }
        else
        {
            ctx.Console.Out.WriteLine($"\n⚠ Burned Secrets ({burned.Count}):");
            PrintTable(ctx, burned);
            ctx.Console.Out.WriteLine($"\n→ Rotate these secrets: {ctx.Prefix} rotate <name> [len], or <source> | {ctx.Prefix} ingest --rotate <name>.");
        }

        if (rotated.Count > 0)
        {
            ctx.Console.Out.WriteLine($"\nRotated (burn superseded by a newer value) ({rotated.Count}):");
            PrintTable(ctx, rotated);
        }
        return 0;
    }

    private static void PrintTable(CommandContext ctx, List<(string Name, DateTime BurnedAt, string? Reason)> rows)
    {
        var nameWidth = Math.Min(40, rows.Max(s => s.Name.Length));
        var dateWidth = 18; // "yyyy-MM-dd HH:mm" + 2 spaces
        var headerWidth = nameWidth + 2 + dateWidth + 2 + 6; // 6 = "REASON".Length

        ctx.Console.Out.WriteLine($"{"NAME".PadRight(nameWidth)}  {"BURNED AT".PadRight(dateWidth)}  REASON");
        ctx.Console.Out.WriteLine("".PadRight(Math.Max(headerWidth, 60), '-'));
        foreach (var (name, burnedAt, burnReason) in rows)
        {
            var reason = burnReason ?? "(no reason given)";
            var when = TswapCore.Keyring.Hlc.Display(burnedAt);
            if (name.Length <= nameWidth)
            {
                ctx.Console.Out.WriteLine($"{name.PadRight(nameWidth)}  {when}  {reason}");
            }
            else
            {
                ctx.Console.Out.WriteLine(name);
                ctx.Console.Out.WriteLine($"{"".PadRight(nameWidth)}  {when}  {reason}");
            }
        }
    }
}
