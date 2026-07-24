using System.Text.Json;
using TswapCore;

namespace TswapCli.Commands;

public sealed class CheckCommand : ICliCommand
{
    public string Name => "check";
    public string HelpUsage => "check <path> [--json]";
    public string Description => "Verify # tswap: markers in file/dir";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var json = JsonFlag.Consume(ref args);

        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} check <path> [--json]");
        var path = args[0];

        var markers = Check.ScanPath(path);

        if (markers.Count == 0)
        {
            if (json)
            {
                ctx.Console.Out.WriteLine(JsonSerializer.Serialize(
                    new CheckReport([], 0, 0, 0), CliJsonContext.Default.CheckReport));
                return 0;
            }
            ctx.Console.Out.WriteLine("No # tswap: markers found.");
            return 0;
        }

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        var db = ctx.LoadSecrets(key);

        var results = Check.CheckMarkers(markers, db);

        if (json)
            return WriteJson(ctx, results);

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

    // Same data and exit-code precedence as the human-readable path, emitted as one JSON
    // object so callers can branch on the report instead of scraping formatted lines.
    private static int WriteJson(CommandContext ctx, IReadOnlyList<Check.CheckResult> results)
    {
        int ok = 0, warning = 0, missing = 0;
        var entries = new List<CheckEntry>(results.Count);

        foreach (var r in results.OrderBy(r => r.Marker.FilePath).ThenBy(r => r.Marker.LineNumber))
        {
            var status = r.Status switch
            {
                Check.SecretStatus.Ok => "ok",
                Check.SecretStatus.Burned => "burned",
                _ => "missing",
            };
            switch (r.Status)
            {
                case Check.SecretStatus.Ok: ok++; break;
                case Check.SecretStatus.Burned: warning++; break;
                default: missing++; break;
            }
            entries.Add(new CheckEntry(r.Marker.FilePath, r.Marker.LineNumber, r.Marker.SecretName, status));
        }

        ctx.Console.Out.WriteLine(JsonSerializer.Serialize(
            new CheckReport(entries, ok, warning, missing), CliJsonContext.Default.CheckReport));

        if (missing > 0)
            return 1;
        if (warning > 0)
            return 2;
        return 0;
    }
}
