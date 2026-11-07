using System.Text.Json;
using TswapCore;

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
        // Brief T16-S2: metadata only (a format 2 record is decoded whole, its values wiped, and warned about).
        using var view = ctx.OpenVault(key);
        try
        {
            Write(ctx, view.LoadAll(FormatTwoRecords.Decode).Secrets, json);
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Read);
        }
    }

    private static void Write(CommandContext ctx, IReadOnlyList<SecretInfo> secrets, bool json)
    {
        var burned = secrets
            .Where(s => s.BurnedAt.HasValue)
            .Select(s => (Name: s.Name, BurnedAt: s.BurnedAt!.Value, Reason: s.BurnReason))
            .OrderBy(s => s.BurnedAt)
            .ToList();
        // Brief T6 decision 7: a burn a newer value superseded (a rotation) is history, not outstanding.
        var rotated = secrets
            .SelectMany(s => s.History.Select(h => (Name: s.Name, h.BurnedAt, h.Reason)))
            .OrderBy(s => s.BurnedAt)
            .ToList();

        if (json)
        {
            var entries = burned.Select(s => new BurnedEntry(s.Name, s.BurnedAt, s.Reason, "outstanding"))
                .Concat(rotated.Select(s => new BurnedEntry(s.Name, s.BurnedAt, s.Reason, "rotated")))
                .ToList();
            ctx.Console.Out.WriteLine(JsonSerializer.Serialize(entries, CliJsonContext.Default.ListBurnedEntry));
            return;
        }

        if (burned.Count == 0 && rotated.Count == 0)
        {
            ctx.Console.Out.WriteLine("No burned secrets. All secrets are clean.");
            return;
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
