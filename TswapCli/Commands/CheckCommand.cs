using TswapCore;

namespace TswapCli.Commands;

public sealed class CheckCommand : ICliCommand
{
    public string Name => "check";
    public string HelpUsage => "check <path>";
    public string Description => "Verify # tswap: markers in file/dir";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} check <path>");
        var path = args[0];

        var markers = Check.ScanPath(path);

        if (markers.Count == 0)
        {
            ctx.Console.Out.WriteLine("No # tswap: markers found.");
            return 0;
        }

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        var db = ctx.Storage.LoadSecrets(key);

        var results = Check.CheckMarkers(markers, db);

        var byFile = results.GroupBy(r => r.Marker.FilePath).OrderBy(g => g.Key);

        int okCount = 0, warnCount = 0, missingCount = 0;

        foreach (var fileGroup in byFile)
        {
            ctx.Console.Out.WriteLine($"\n{fileGroup.Key}:");
            foreach (var result in fileGroup.OrderBy(r => r.Marker.LineNumber))
            {
                switch (result.Status)
                {
                    case Check.SecretStatus.Ok:
                        ctx.Console.Out.WriteLine($"  ✓ {result.Marker.SecretName} (line {result.Marker.LineNumber})");
                        okCount++;
                        break;
                    case Check.SecretStatus.Burned:
                        ctx.Console.Out.WriteLine($"  ⚠ {result.Marker.SecretName} (line {result.Marker.LineNumber}) — BURNED, needs rotation");
                        warnCount++;
                        break;
                    case Check.SecretStatus.Missing:
                        ctx.Console.Out.WriteLine($"  ✗ {result.Marker.SecretName} (line {result.Marker.LineNumber}) — NOT FOUND");
                        missingCount++;
                        break;
                }
            }
        }

        ctx.Console.Out.WriteLine($"\nSummary: {okCount} ok, {warnCount} warning(s), {missingCount} missing");

        // Exit-code precedence: missing secrets (1) take priority over burned/warn secrets (2)
        if (missingCount > 0)
            return 1;
        if (warnCount > 0)
            return 2;
        return 0;
    }
}
