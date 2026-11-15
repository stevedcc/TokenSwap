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
        // Fields first: a field value or --by label of "--rotate" is not the flag.
        using var fields = ValueCommandFields.Take(args, () => new UsageException($"<source> | {ctx.Prefix} ingest [--rotate] <name>"), out args);
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

        fields.ResolveWho(ctx);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);

        // Brief T16-S2b: only this name's record is read (its metadata; existence needs no value).
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            if (rotate)
            {
                var existing = SecretRotation.Check(ctx, writer, name, "ingest --rotate");
                SecretRotation.Write(ctx, key, writer, fields, name, value, "ingest --rotate");
                SecretRotation.Report(ctx, name, existing, "new value from stdin");
                fields.Report(ctx, warnIfValueInAField: true);
                ValueWarnings.WarnIfShort(ctx, name, value);
                return 0;
            }

            writer.ThrowIfUnreadable(name);
            if (writer.Find(name) is not null)
                throw new TswapException(
                    $"Secret '{name}' already exists. To replace its value, use: <source> | {ctx.Prefix} ingest --rotate {name}");

            fields.Stage(ctx, key, writer, name, value, ctx.Time.GetUtcNow().UtcDateTime, always: false, "ingest");
            writer.Commit();

            ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' ingested from stdin");
            ctx.Console.Out.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
            fields.Report(ctx, warnIfValueInAField: true);
            ValueWarnings.WarnIfShort(ctx, name, value);
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded + fields.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }
}
