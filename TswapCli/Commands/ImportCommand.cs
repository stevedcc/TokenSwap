using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;

namespace TswapCli.Commands;

public sealed class ImportCommand : ICliCommand
{
    public string Name => "import";
    public string HelpUsage => "import [--include-burned] <file>";
    public string Description => "Import secrets from an encrypted backup (burned secrets skipped by default)";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        var remaining = args.Where(a => a != "--include-burned").ToArray();
        var includeBurned = remaining.Length != args.Length;
        if (remaining.Length != 1)
            throw new UsageException($"sudo {ctx.Prefix} import [--include-burned] <file>");
        var path = remaining[0];

        ctx.RequireSudo("import");

        if (!File.Exists(path))
            throw new TswapException($"Export file not found: {path}");

        ctx.Console.Error.Write("Import passphrase: ");
        var passphrase = ctx.Console.ReadPassword(ctx.Console.Error);

        ExportFile exportFile;
        try
        {
            exportFile = JsonSerializer.Deserialize(File.ReadAllText(path), TswapJsonContext.Default.ExportFile)
                ?? throw new TswapException("Invalid export file");
        }
        catch (JsonException ex)
        {
            throw new TswapException($"Export file is not valid JSON: {ex.Message}");
        }

        if (exportFile.Version != "tswap-export-v1")
            throw new TswapException($"Unsupported export version: {exportFile.Version}");

        var salt = Convert.FromBase64String(exportFile.Salt);
        var exportKey = Crypto.DeriveKeyFromPassphrase(passphrase, salt);

        byte[] plaintext;
        try { plaintext = Crypto.Decrypt(Convert.FromBase64String(exportFile.Ciphertext), exportKey); }
        catch (CryptographicException) { throw new TswapException("Decryption failed — wrong passphrase or file tampered"); }
        catch (FormatException) { throw new TswapException("Export file is corrupted (base64 decode failed)"); }

        SecretsDb exportedDb;
        try
        {
            exportedDb = JsonSerializer.Deserialize(Encoding.UTF8.GetString(plaintext), TswapJsonContext.Default.SecretsDb)
                ?? throw new TswapException("Invalid export data");
        }
        catch (JsonException ex)
        {
            throw new TswapException($"Export data is corrupted (decrypted payload is not valid JSON): {ex.Message}");
        }

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.Storage.LoadSecrets(key);

        int imported = 0, skippedExisting = 0, skippedBurned = 0, skippedNul = 0;
        foreach (var (name, secret) in exportedDb.Secrets.OrderBy(kv => kv.Key))
        {
            if (secret.BurnedAt != null && !includeBurned)
            {
                ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (was burned in source vault; use --include-burned to import)");
                skippedBurned++;
                continue;
            }
            if (db.Secrets.ContainsKey(name))
            {
                ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (already exists)");
                skippedExisting++;
                continue;
            }
            if (secret.Value == null || secret.Value.Contains('\0'))
            {
                // System.Text.Json can produce null for non-nullable string properties when the
                // source JSON has "Value": null or omits the field entirely (e.g. a tampered file).
                // Treat null the same as NUL: reject rather than propagate a bad value.
                ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (value is null or contains a NUL byte — cannot be used as a process argument)");
                skippedNul++;
                continue;
            }
            db.Secrets[name] = secret;
            imported++;
        }

        ctx.Storage.SaveSecrets(db, key);
        ctx.Console.Out.WriteLine($"\n✓ Imported {imported} secret(s)");
        if (skippedBurned > 0)   ctx.Console.Out.WriteLine($"  Skipped {skippedBurned} burned secret(s)");
        if (skippedExisting > 0) ctx.Console.Out.WriteLine($"  Skipped {skippedExisting} already-existing secret(s)");
        if (skippedNul > 0)      ctx.Console.Out.WriteLine($"  Skipped {skippedNul} secret(s) with null or NUL-byte values (re-export from source after fixing values)");
        return 0;
    }
}
