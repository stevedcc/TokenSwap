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
        if (!File.Exists(SecretsFile))
            return new SecretsDb(new Dictionary<string, Secret>());

        var encrypted = File.ReadAllBytes(SecretsFile);
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
