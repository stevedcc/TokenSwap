using TswapCore;

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
        // Brief T16-S2: metadata only (a format 2 record is decoded whole, its values wiped, and warned about).
        using var view = ctx.OpenVault(key);
        try
        {
            var secrets = view.LoadAll(FormatTwoRecords.Decode).Secrets;
            view.ThrowIfAnyUnreadable("list");
            Write(ctx, secrets);
            return 0;
        }
        finally
        {
            // Also when it refuses: the format 2 records were decrypted all the same (owner decision 1).
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Read);
        }
    }

    private static void Write(CommandContext ctx, IReadOnlyList<SecretInfo> secrets)
    {
        if (secrets.Count == 0)
        {
            ctx.Console.Out.WriteLine("No secrets stored.");
            return;
        }

        var nameWidth = Math.Max(20, secrets.Max(s => s.Name.Length));
        var lineWidth = nameWidth + 2 + 16 + 2 + 16; // name + gaps + two date columns

        ctx.Console.Out.WriteLine($"\nSecrets ({secrets.Count}):");
        ctx.Console.Out.WriteLine($"{"NAME".PadRight(nameWidth)}  {"CREATED".PadRight(16)}  MODIFIED");
        ctx.Console.Out.WriteLine("".PadRight(lineWidth, '-'));

        foreach (var secret in secrets.OrderBy(s => s.Name))
            ctx.Console.Out.WriteLine($"{secret.Name.PadRight(nameWidth)}  {secret.Created:yyyy-MM-dd HH:mm}  {secret.Modified:yyyy-MM-dd HH:mm}");
    }
}
