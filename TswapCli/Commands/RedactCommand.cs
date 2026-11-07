using TswapCore;
using TswapCore.Fingerprints;

namespace TswapCli.Commands;

public sealed class RedactCommand : ICliCommand
{
    public string Name => "redact";
    public string HelpUsage => "redact <file>";
    public string Description => "Output file with secret values redacted";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var filePath, ..])
            throw new UsageException($"{ctx.Prefix} redact <file>");

        if (!File.Exists(filePath))
            throw new TswapException($"File not found: {filePath}");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // Brief T16-S2: metadata only, no value decrypted; refuses before the file is opened.
        using var view = ctx.OpenVault(key);
        using var keys = FingerprintKeys.Derive(key);
        var matcher = FingerprintRedaction.Matcher(ctx, view, keys, "redact", changesFile: false);

        var content = File.ReadAllText(filePath);
        var redacted = Redact.RedactContent(content, matcher);

        ctx.Console.Out.Write(redacted);

        var unknowns = Redact.FindUnknownSecrets(redacted);
        foreach (var (line, snippet) in unknowns)
            ctx.Console.Error.WriteLine($"⚠ Line {line}: possible unrecognized secret: {snippet}");
        return 0;
    }
}
