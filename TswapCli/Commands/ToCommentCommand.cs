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
        var report = Redact.ToCommentReport(content, matcher);
        var changes = report.Changes;

        // Brief T50b (owner decision 6): a note per replaced secret whose name marks it as a username, never its value.
        foreach (var name in report.ReplacedNames.Where(ToCommentProcessor.IsUsernameName))
            ctx.Console.Error.WriteLine(
                $"Note: '{name}' looks like a username; if it is a username (never a password), keep it in a field instead " +
                $"({ElevatedCommand.For(ctx.Prefix, $"field adopt NAME username --from {name}")}), so tocomment leaves it alone.");

        if (changes.Count == 0)
        {
            // Brief T22: nothing replaced, so nothing is written (a CRLF file keeps its line ends).
            if (report.Unreplaced.Count == 0 && report.Skipped.Count == 0)
            {
                ctx.Console.Error.WriteLine("No secrets found. File unchanged.");
                return 0;
            }
            WriteWarnings(ctx, report);
            ctx.Console.Error.WriteLine("File unchanged.");
            return 0;
        }

        foreach (var diff in changes)
        {
            if (diff is MultiLineDiff multi)
            {
                // Brief T50b Task 3 (#399): one change over several lines; the value's text is never printed.
                ctx.Console.Error.WriteLine($"  lines {multi.LineNumber}-{multi.LastLineNumber}:");
                ctx.Console.Error.WriteLine($"  - [value over {multi.LastLineNumber - multi.LineNumber + 1} lines]");
                ctx.Console.Error.WriteLine($"  + {Redact.RedactContent(multi.After, matcher)}");
                continue;
            }
            ctx.Console.Error.WriteLine($"  line {diff.LineNumber}:");
            if (diff is BlockLineDiff)
            {
                // Brief T20 (#315): a removed line of an adopted block scalar is a fragment of the
                // secret, which the redactor (complete occurrences only) can't mask: never printed.
                ctx.Console.Error.WriteLine($"  - [removed block line]");
                ctx.Console.Error.WriteLine($"  + (removed)");
            }
            else if (diff.After == "")
            {
                // Continuation line being removed. Its content is a raw base64 fragment that
                // cannot be fully redacted (it is only part of the secret's full base64 value),
                // so suppress it rather than risk printing sensitive data.
                ctx.Console.Error.WriteLine($"  - [removed continuation line]");
                ctx.Console.Error.WriteLine($"  + (removed)");
            }
            else
            {
                // Brief T50b: each text redacted on its own (no join and split), the "after" text too: a changed
                // line can keep an occurrence it left in place (a second value in its comment).
                ctx.Console.Error.WriteLine($"  - {Redact.RedactContent(diff.Before, matcher)}");
                ctx.Console.Error.WriteLine($"  + {Redact.RedactContent(diff.After, matcher)}");
            }
        }

        WriteWarnings(ctx, report);

        if (dryRun)
        {
            ctx.Console.Error.WriteLine($"\n(dry run) {changes.Count} line(s) would be modified.");
            return 0;
        }

        File.WriteAllText(filePath, report.Content);
        ctx.Console.Error.WriteLine($"\n✓ {changes.Count} line(s) updated in {filePath}");
        return 0;
    }

    /// <summary>
    /// Brief T50b (#394, #399): one warning per occurrence left in place, naming where it is and the token only, never
    /// the line's text or any form of the value; after T22's warnings. A warning, not a refusal: the exit code stays 0.
    /// </summary>
    private static void WriteWarnings(CommandContext ctx, ToCommentReport report)
    {
        WriteWarnings(ctx, report.Unreplaced);
        foreach (var value in report.Skipped)
        {
            var where = value.FirstLine == value.LastLine ? $"line {value.FirstLine}" : $"lines {value.FirstLine}-{value.LastLine}";
            var reason = value.Reason == SkippedReason.InBlockScalar
                ? "it is inside a YAML block scalar"
                : "it is not a whole value that apply fills back ('key: value', or 'KEY=value' without control characters)";
            ctx.Console.Error.WriteLine(
                $"Warning: {where}: the value of '{value.Token}' (or an encoded form of it) was left in place: {reason}. If it is the secret there, move it out by hand.");
        }
    }

    /// <summary>
    /// Brief T22 (#319): one warning per line left unchanged, naming the line and the token only, never the
    /// line's text or any form of the value. A warning, not a refusal: the exit code stays 0.
    /// </summary>
    private static void WriteWarnings(CommandContext ctx, IReadOnlyList<UnreplacedLine> unreplaced)
    {
        foreach (var line in unreplaced)
            ctx.Console.Error.WriteLine(
                $"Warning: line {line.LineNumber} holds an encoded form (base64 or similar) of the value of '{line.Token}' inside a YAML block scalar. " +
                "A '# tswap:' marker is filled with the plain value, so it was not replaced: move the value out of the block by hand, or keep the block as a whole secret.");
    }
}
