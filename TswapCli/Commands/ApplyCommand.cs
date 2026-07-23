using TswapCore;

namespace TswapCli.Commands;

public sealed class ApplyCommand : ICliCommand
{
    public string Name => "apply";
    public string HelpUsage => "apply <file>";
    public string Description => "Output file with # tswap: markers substituted";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} apply <file>");
        var filePath = args[0];

        if (!File.Exists(filePath))
            throw new TswapException($"File not found: {filePath}");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        var content = File.ReadAllText(filePath);
        var applied = Apply.ApplySecrets(content, db, warnings: ctx.Console.Error);

        ctx.Console.Out.Write(applied);
        return 0;
    }
}
