using TswapCore;

namespace TswapCli.Commands;

public sealed class ToCommentCommand : ICliCommand
{
    public string Name => "tocomment";
    public string HelpUsage => "tocomment <file>";
    public string Description => "Replace inline secrets with # tswap: comments";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} tocomment <file> [--dry-run]");
        var filePath = args[0];
        var dryRun = args.Contains("--dry-run");

        if (!File.Exists(filePath))
            throw new TswapException($"File not found: {filePath}");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.Storage.LoadSecrets(key);

        var content = File.ReadAllText(filePath);
        var (newContent, changes) = Redact.ToComment(content, db);

        if (changes.Count == 0)
        {
            ctx.Console.Error.WriteLine("No secrets found. File unchanged.");
            return 0;
        }

        // Pre-compute redacted forms in a single pass so BuildMatchList is called once.
        var normalDiffs = changes.Where(d => d.After != "").ToList();
        var redactedBefores = Redact.RedactContent(
            string.Join('\n', normalDiffs.Select(d => d.Before)), db).Split('\n');
        var redactedByLineNumber = normalDiffs
            .Select((d, idx) => (d.LineNumber, Redacted: redactedBefores[idx]))
            .ToDictionary(x => x.LineNumber, x => x.Redacted);

        foreach (var diff in changes)
        {
            ctx.Console.Error.WriteLine($"  line {diff.LineNumber}:");
            if (diff.After == "")
            {
                // Continuation line being removed. Its content is a raw base64 fragment that
                // cannot be fully redacted (it is only part of the secret's full base64 value),
                // so suppress it rather than risk printing sensitive data.
                ctx.Console.Error.WriteLine($"  - [removed continuation line]");
                ctx.Console.Error.WriteLine($"  + (removed)");
            }
            else
            {
                ctx.Console.Error.WriteLine($"  - {redactedByLineNumber[diff.LineNumber]}");
                ctx.Console.Error.WriteLine($"  + {diff.After}");
            }
        }

        if (dryRun)
        {
            ctx.Console.Error.WriteLine($"\n(dry run) {changes.Count} line(s) would be modified.");
            return 0;
        }

        File.WriteAllText(filePath, newContent);
        ctx.Console.Error.WriteLine($"\n✓ {changes.Count} line(s) updated in {filePath}");
        return 0;
    }
}
