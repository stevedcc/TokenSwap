using TswapCore;
using TswapCore.Fingerprints;

namespace TswapCli.Commands;

public sealed class ToCommentCommand : ICliCommand
{
    public string Name => "tocomment";
    public string HelpUsage => "tocomment <file> [--dry-run]";
    public string Description => "Replace inline secrets with # tswap: comments";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var filePath, ..])
            throw new UsageException($"{ctx.Prefix} tocomment <file> [--dry-run]");
        var dryRun = args.Contains("--dry-run");

        if (!File.Exists(filePath))
            throw new TswapException($"File not found: {filePath}");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // Brief T16-S2: metadata only, no value decrypted; refuses before the file is opened.
        using var view = ctx.OpenVault(key);
        using var keys = FingerprintKeys.Derive(key);
        var matcher = FingerprintRedaction.Matcher(ctx, view, keys, "tocomment", changesFile: true);

        var content = File.ReadAllText(filePath);
        var (newContent, changes) = Redact.ToComment(content, matcher);

        if (changes.Count == 0)
        {
            ctx.Console.Error.WriteLine("No secrets found. File unchanged.");
            return 0;
        }

        // Redact the "before" lines in a single pass, with the same matcher.
        var normalDiffs = changes.Where(d => d.After != "").ToList();
        var redactedBefores = Redact.RedactContent(
            string.Join('\n', normalDiffs.Select(d => d.Before)), matcher).Split('\n');
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
