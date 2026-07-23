using System.Text;
using System.Text.Json;

namespace TswapCore;

/// <summary>
/// Default <see cref="IVaultStore"/>: the single-file backend (<c>config.json</c> +
/// <c>secrets.json.enc</c>) that has always shipped with tswap. Writes go through an
/// atomic temp-then-rename so a crash mid-write cannot destroy an existing file.
/// </summary>
public class Storage : IVaultStore
{
    public string ConfigDir { get; }
    public string ConfigFile { get; }
    public string SecretsFile { get; }

    public Storage(string configDir)
    {
        ConfigDir = configDir;
        ConfigFile = Path.Combine(configDir, "config.json");
        SecretsFile = Path.Combine(configDir, "secrets.json.enc");
    }

    public Config LoadConfig()
    {
        if (!File.Exists(ConfigFile))
            throw new TswapException("Not initialized. Run: tswap init");

        var json = File.ReadAllText(ConfigFile);
        return JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)
            ?? throw new TswapException("Invalid config");
    }

    public void SaveConfig(Config config)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        WriteFileAtomic(ConfigFile, Encoding.UTF8.GetBytes(json));
    }

    /// <summary>
    /// Loads and decrypts the secrets database. A missing vault or config directory
    /// is recoverable (returns an empty database); the explanation is written to
    /// <paramref name="warnings"/> when provided, so the library itself never
    /// touches the console.
    /// </summary>
    public SecretsDb LoadSecrets(byte[] key, TextWriter? warnings = null)
    {
        byte[] encrypted;
        try
        {
            encrypted = File.ReadAllBytes(SecretsFile);
        }
        catch (FileNotFoundException)
        {
            warnings?.WriteLine(
                $"Warning: vault file not found ({SecretsFile}). Starting with empty vault. " +
                "To recover: restore secrets.json.enc alongside its original config.json from backup. " +
                "To start fresh: run 'tswap init' (this will overwrite config.json).");
            return new SecretsDb(new Dictionary<string, Secret>());
        }
        catch (DirectoryNotFoundException)
        {
            warnings?.WriteLine(
                $"Warning: config directory not found ({ConfigDir}). Starting with empty vault. " +
                "To recover: restore the config directory from backup. " +
                "To start fresh: run 'tswap init' (this will overwrite config.json).");
            return new SecretsDb(new Dictionary<string, Secret>());
        }
        var decrypted = Crypto.Decrypt(encrypted, key);
        var json = Encoding.UTF8.GetString(decrypted);
        return JsonSerializer.Deserialize(json, TswapJsonContext.Default.SecretsDb)
            ?? new SecretsDb(new Dictionary<string, Secret>());
    }

    public void SaveSecrets(SecretsDb db, byte[] key)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(db, TswapJsonContext.Default.SecretsDb);
        var plaintext = Encoding.UTF8.GetBytes(json);
        var encrypted = Crypto.Encrypt(plaintext, key);
        WriteFileAtomic(SecretsFile, encrypted);
    }

    // Write-temp-then-rename so a crash mid-write can never destroy the existing
    // file: the rename either fully replaces it or leaves it untouched.
    private static void WriteFileAtomic(string path, byte[] bytes)
    {
        var tmp = path + ".tmp";
        try
        {
            File.WriteAllBytes(tmp, bytes);
            if (File.Exists(path))
            {
                // Preserve the existing file's permissions: a plain rename would give the
                // result the temp file's default (umask) mode, silently *widening* access
                // to the vault/config if the user had tightened it (e.g. chmod 600).
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(tmp, File.GetUnixFileMode(path));
                // File.Replace preserves the destination's ACLs/attributes on Windows
                // (rename semantics elsewhere).
                File.Replace(tmp, path, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tmp, path);
            }
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
            throw;
        }
    }
}
