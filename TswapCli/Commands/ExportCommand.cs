using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;

namespace TswapCli.Commands;

public sealed class ExportCommand : ICliCommand
{
    public string Name => "export";
    public string HelpUsage => "export <file>";
    public string Description => "Export all secrets to an encrypted backup";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"sudo {ctx.Prefix} export <file>");
        var path = args[0];

        ctx.RequireSudo("export");

        if (File.Exists(path))
        {
            ctx.Console.Error.Write($"File '{path}' already exists. Overwrite? (yes/no): ");
            var overwriteResponse = ctx.Console.ReadLine();
            if (ctx.Console.IsInputRedirected) ctx.Console.Error.WriteLine();
            if (overwriteResponse?.ToLower() != "yes")
                throw new TswapException("Export cancelled.");
        }

        ctx.Console.Error.Write("Export passphrase: ");
        var passphrase = ctx.Console.ReadPassword(ctx.Console.Error);
        ctx.Console.Error.Write("Confirm passphrase: ");
        var confirm = ctx.Console.ReadPassword(ctx.Console.Error);
        if (passphrase != confirm)
            throw new TswapException("Passphrases don't match");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        var salt = RandomNumberGenerator.GetBytes(32);
        var exportKey = Crypto.DeriveKeyFromPassphrase(passphrase, salt);
        var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(db, TswapJsonContext.Default.SecretsDb));
        var ciphertext = Crypto.Encrypt(plaintext, exportKey);

        var exportFile = new ExportFile(
            ExportFile.CurrentVersion,
            DateTime.UtcNow,
            Convert.ToBase64String(salt),
            Convert.ToBase64String(ciphertext)
        );
        File.WriteAllText(path, JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

        var nonBurned = db.Secrets.Count(kv => kv.Value.BurnedAt == null);
        var burned = db.Secrets.Count(kv => kv.Value.BurnedAt != null);
        ctx.Console.Out.WriteLine($"\n✓ Exported {nonBurned} secret(s) to: {path}");
        if (burned > 0)
            ctx.Console.Out.WriteLine($"  ({burned} burned secret(s) included — skipped on import by default; use 'sudo {ctx.Prefix} import --include-burned {path}' to preserve them)");
        ctx.Console.Out.WriteLine("  Keep this file and its passphrase secure.");
        return 0;
    }
}
