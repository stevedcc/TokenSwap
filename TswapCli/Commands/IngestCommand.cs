using TswapCore;

namespace TswapCli.Commands;

public sealed class IngestCommand : ICliCommand
{
    public string Name => "ingest";
    public string HelpUsage => "ingest <name>";
    public string Description => "Pipe secret from stdin (no display)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"<source> | {ctx.Prefix} ingest <name>");
        var name = args[0];

        Validation.ValidateName(name);

        if (ctx.Console.IsInputRedirected == false)
            throw new TswapException($"No input piped. Use: <source> | {ctx.Prefix} ingest <name>\nFor interactive input, use: sudo {ctx.Prefix} add <name>");

        var value = Validation.ReadBoundedStdin(Console.In);
        if (string.IsNullOrEmpty(value))
            throw new TswapException("Empty input received. Nothing to store.");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        if (db.Secrets.ContainsKey(name))
            throw new TswapException($"Secret '{name}' already exists. Use 'delete' first to rotate.");

        db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' ingested from stdin");
        ctx.Console.Out.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
        return 0;
    }
}
