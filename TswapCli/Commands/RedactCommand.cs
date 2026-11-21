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
        // Brief T45 (#389): a value that looks like a credential the vault doesn't know is masked too,
        // and its warning names the line and the keyword, never the value.
        var (masked, hits) = Redact.MaskUnknownSecrets(redacted);

        ctx.Console.Out.Write(masked);

        foreach (var (line, keyword) in hits)
            ctx.Console.Error.WriteLine($"⚠ Line {line}: possible unrecognised secret after '{keyword}', masked");
        return 0;
    }
}
