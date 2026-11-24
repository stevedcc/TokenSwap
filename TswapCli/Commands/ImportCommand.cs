using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Fields;

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

        // A version 1 file (PBKDF2) may have been made with an empty passphrase and still imports; Argon2id has none.
        if (passphrase.Length == 0 && exportFile.Version != ExportFile.V1)
            throw new TswapException("No import passphrase was entered.");
        var salt = Convert.FromBase64String(exportFile.Salt);

        // Brief T54: an export since T54 derives from the NFC passphrase; an older one from the bytes as typed then.
        // Each candidate in order (ExportCrypto.PassphraseCandidates); the first that authenticates wins, and every
        // key that fails is zeroed.
        byte[]? plaintext = null;
        foreach (var candidate in ExportCrypto.PassphraseCandidates(passphrase))
        {
            var exportKey = ExportCrypto.DeriveKey(candidate, salt, exportFile);
            try
            {
                plaintext = Crypto.Decrypt(Convert.FromBase64String(exportFile.Ciphertext), exportKey);
                break;
            }
            catch (CryptographicException)
            {
            }
            catch (FormatException) { throw new TswapException("Export file is corrupted (base64 decode failed)"); }
            finally
            {
                CryptographicOperations.ZeroMemory(exportKey);
            }
        }
        if (plaintext is null)
            throw new TswapException("Decryption failed — wrong passphrase or file tampered");

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
        // Brief T16-S2b: only the records of the names in the export are read (their metadata), no
        // vault value is decrypted, and every write is staged and committed at once: a refusal
        // (an unreadable record, one changed on disk) writes nothing.
        using var writer = ctx.OpenVaultForWrite(key);
        // Issue #311: imported fields are a change made here, now: stamped fresh, by this machine
        // (spec "Export and import"; guard rail 1 does not check them).
        var who = FieldWhoSource.Current(ctx, by: null);
        try
        {
            int imported = 0, skippedExisting = 0, skippedBurned = 0, skippedNul = 0;
            foreach (var (name, secret) in exportedDb.Secrets.OrderBy(kv => kv.Key))
            {
                if (secret.BurnedAt is not null && !includeBurned)
                {
                    ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (was burned in source vault; use --include-burned to import)");
                    skippedBurned++;
                    continue;
                }
                if (writer.Find(name) is not null)
                {
                    ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (already exists)");
                    skippedExisting++;
                    continue;
                }
                if (secret.Value is null || secret.Value.Contains('\0'))
                {
                    // System.Text.Json can produce null for non-nullable string properties when the
                    // source JSON has "Value": null or omits the field entirely (e.g. a tampered file).
                    // Treat null the same as NUL: reject rather than propagate a bad value.
                    ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (value is null or contains a NUL byte — cannot be used as a process argument)");
                    skippedNul++;
                    continue;
                }
                if (secret.Fields?.FirstOrDefault(f => f.Value is null) is { Key: { } nullField })
                {
                    // As for a null Value above: a JSON null for a field value is a tampered file, never an unset.
                    ctx.Console.Out.WriteLine($"  ⚠ Skipped '{name}' (field '{FieldRules.Escape(nullField)}' is null — the export file was altered)");
                    skippedNul++;
                    continue;
                }
                // A v1/v2 file has no fields; a v3 file's fields are written with the value, in one write. No caps
                // (final review I2 ruling): an export may hold a secret a merge legally left over them, as a merge does.
                var fields = secret.Fields?.OrderBy(f => f.Key, StringComparer.Ordinal).Select(f => new FieldEdit(f.Key, f.Value)).ToList();
                writer.SetValue(name, secret.Value, secret.Created, importedBurnAt: secret.BurnedAt, importedBurnReason: secret.BurnReason,
                    fields: fields, who: who, checkFieldCaps: false);
                imported++;
            }

            writer.Commit();
            ctx.Console.Out.WriteLine($"\n✓ Imported {imported} secret(s)");
            if (skippedBurned > 0)   ctx.Console.Out.WriteLine($"  Skipped {skippedBurned} burned secret(s)");
            if (skippedExisting > 0) ctx.Console.Out.WriteLine($"  Skipped {skippedExisting} already-existing secret(s)");
            if (skippedNul > 0)      ctx.Console.Out.WriteLine($"  Skipped {skippedNul} secret(s) with null or NUL-byte values, or null fields (re-export from source after fixing values)");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }
}
