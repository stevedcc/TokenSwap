using TswapCore;

namespace TswapCli.Commands;

public sealed class RedactCommand : ICliCommand
{
    public string Name => "redact";
    public string HelpUsage => "redact <file>";
    public string Description => "Output file with secret values redacted";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} redact <file>");
        var filePath = args[0];

        if (!File.Exists(filePath))
            throw new TswapException($"File not found: {filePath}");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        var content = File.ReadAllText(filePath);
        var redacted = Redact.RedactContent(content, db);

        ctx.Console.Out.Write(redacted);

        var unknowns = Redact.FindUnknownSecrets(redacted);
        foreach (var (line, snippet) in unknowns)
            ctx.Console.Error.WriteLine($"⚠ Line {line}: possible unrecognized secret: {snippet}");
        return 0;
    }
}
