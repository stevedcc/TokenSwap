using TswapCore;

namespace TswapCli.Commands;

public sealed class IngestCommand : ICliCommand
{
    public string Name => "ingest";
    public string HelpUsage => "ingest [--rotate] <name>";
    public string Description => "Pipe secret from stdin (no display); --rotate replaces an existing one (sudo unless it is burned)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        // Brief T6 decision 7: --rotate writes a newer version of an existing secret.
        var rotate = args.Contains("--rotate");
        args = args.Where(a => a != "--rotate").ToArray();
        if (args is not [var name] || name.StartsWith("--"))
            throw new UsageException($"<source> | {ctx.Prefix} ingest [--rotate] <name>");

        Validation.ValidateName(name);

        if (ctx.Console.IsInputRedirected == false)
            throw new TswapException($"No input piped. Use: <source> | {ctx.Prefix} ingest <name>\nFor interactive input, use: sudo {ctx.Prefix} add <name>");

        var value = Validation.ReadBoundedStdin(ctx.Console.In);
        if (string.IsNullOrEmpty(value))
            throw new TswapException("Empty input received. Nothing to store.");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);

        if (rotate)
        {
            var db = ctx.LoadSecrets(key);
            var existing = SecretRotation.Check(ctx, db, name, "ingest --rotate");
            SecretRotation.Write(ctx, db, key, name, existing, value);
            SecretRotation.Report(ctx, name, existing, "new value from stdin");
            return 0;
        }

        // Brief T16-S2b: only this name's record is read (its metadata; existence needs no value).
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            writer.ThrowIfUnreadable(name);
            if (writer.Find(name) is not null)
                throw new TswapException(
                    $"Secret '{name}' already exists. To replace its value, use: <source> | {ctx.Prefix} ingest --rotate {name}");

            writer.SetValue(name, value, ctx.Time.GetUtcNow().UtcDateTime);
            writer.Commit();

            ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' ingested from stdin");
            ctx.Console.Out.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }
}
