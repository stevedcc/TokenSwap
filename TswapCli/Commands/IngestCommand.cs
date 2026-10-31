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
        if (args.Length != 1 || args[0].StartsWith("--"))
            throw new UsageException($"<source> | {ctx.Prefix} ingest [--rotate] <name>");
        var name = args[0];

        Validation.ValidateName(name);

        if (ctx.Console.IsInputRedirected == false)
            throw new TswapException($"No input piped. Use: <source> | {ctx.Prefix} ingest <name>\nFor interactive input, use: sudo {ctx.Prefix} add <name>");

        var value = Validation.ReadBoundedStdin(ctx.Console.In);
        if (string.IsNullOrEmpty(value))
            throw new TswapException("Empty input received. Nothing to store.");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        if (rotate)
        {
            var existing = SecretRotation.Check(ctx, db, name, "ingest --rotate");
            SecretRotation.Write(ctx, db, key, name, existing, value);
            SecretRotation.Report(ctx, name, existing, "new value from stdin");
            return 0;
        }

        db.ThrowIfUnreadable(name);
        if (db.Secrets.ContainsKey(name))
            throw new TswapException(
                $"Secret '{name}' already exists. To replace its value, use: <source> | {ctx.Prefix} ingest --rotate {name}");

        db.Secrets[name] = new Secret(value, ctx.Time.GetUtcNow().UtcDateTime, ctx.Time.GetUtcNow().UtcDateTime);
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' ingested from stdin");
        ctx.Console.Out.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
        return 0;
    }
}
