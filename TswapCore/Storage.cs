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
            throw new Exception("Not initialized. Run: tswap init");

        var json = File.ReadAllText(ConfigFile);
        return JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)
            ?? throw new Exception("Invalid config");
    }

    public void SaveConfig(Config config)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        File.WriteAllText(ConfigFile, json);
    }

    public SecretsDb LoadSecrets(byte[] key)
    {
        byte[] encrypted;
        try
        {
            encrypted = File.ReadAllBytes(SecretsFile);
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine(
                $"Warning: vault file not found ({SecretsFile}). Starting with empty vault. " +
                "To recover: restore secrets.json.enc alongside its original config.json from backup. " +
                "To start fresh: run 'tswap init' (this will overwrite config.json).");
            return new SecretsDb(new Dictionary<string, Secret>());
        }
        catch (DirectoryNotFoundException)
        {
            Console.Error.WriteLine(
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
        File.WriteAllBytes(SecretsFile, encrypted);
    }
}
