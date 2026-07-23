using System.Text;
using System.Text.Json;

namespace TswapCore;

public class Storage
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
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, path, overwrite: true);
    }
}
