using System.Text.Json;
using TswapCore;

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
        if (json)
        {
            var entries = secrets
                .OrderBy(s => s.Name)
                .Select(s => new NameEntry(s.Name, s.BurnedAt.HasValue, s.BurnedAt))
                .ToList();
            ctx.Console.Out.WriteLine(JsonSerializer.Serialize(entries, CliJsonContext.Default.ListNameEntry));
            return;
        }

        if (secrets.Count == 0)
        {
            ctx.Console.Out.WriteLine("No secrets stored.");
            return;
        }

        // Brief T6 decision 3: the time shown is when the current value was written (for a record
        // store, its HLC's physical part; "far future" when a bad clock put it beyond DateTime).
        var width = Math.Min(40, secrets.Max(s => s.Name.Length));
        foreach (var secret in secrets.OrderBy(s => s.Name))
        {
            var burned = secret.BurnedAt.HasValue ? " [BURNED]" : "";
            ctx.Console.Out.WriteLine($"{secret.Name.PadRight(width)}  {TswapCore.Keyring.Hlc.Display(secret.Modified)}{burned}");
        }
    }
}
