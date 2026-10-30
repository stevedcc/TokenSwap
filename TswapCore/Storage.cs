using System.Text;
using System.Text.Json;

namespace TswapCore;

/// <summary>
/// Default <see cref="IVaultStore"/>: the single-file backend (<c>config.json</c> +
/// <c>secrets.json.enc</c>) that has always shipped with tswap. Writes go through
/// <see cref="DirectoryOwnerMatcher.WriteAtomic"/> (temp-then-rename) so a crash mid-write cannot
/// destroy an existing file.
/// Implements <see cref="IFileVaultStore"/> (not just the base interface) since it
/// genuinely is file-backed and exposes the paths some commands need.
/// </summary>
public class Storage : IFileVaultStore
{
    public string ConfigDir { get; }
    public string ConfigFile { get; }
    public string SecretsFile { get; }

    private readonly DirectoryOwnerMatcher _owner;

    /// <param name="owner">
    /// Writes every file, and gives files written under sudo the config folder's owner (T5; see
    /// <see cref="DirectoryOwnerMatcher"/>). Null: <see cref="DirectoryOwnerMatcher.Default"/>.
    /// </param>
    public Storage(string configDir, DirectoryOwnerMatcher? owner = null)
    {
        ConfigDir = configDir;
        ConfigFile = Path.Combine(configDir, "config.json");
        SecretsFile = Path.Combine(configDir, "secrets.json.enc");
        _owner = owner ?? DirectoryOwnerMatcher.Default;
    }

    /// <inheritdoc/>
    public string BackupConfig()
    {
        return FileBackup.Copy(ConfigFile, DateTime.UtcNow, _owner);
    }

    /// <inheritdoc/>
    public void WriteFile(string path, string contents) => _owner.WriteAtomic(path, Encoding.UTF8.GetBytes(contents));

    public Config LoadConfig()
    {
        if (!_owner.FileExists(ConfigFile))
            throw new TswapException("Not initialized. Run: tswap init");

        var json = Encoding.UTF8.GetString(_owner.ReadAllBytes(ConfigFile));
        return JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)
            ?? throw new TswapException("Invalid config");
    }

    public void SaveConfig(Config config)
    {
        _owner.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        _owner.WriteAtomic(ConfigFile, Encoding.UTF8.GetBytes(json));
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
            encrypted = _owner.ReadAllBytes(SecretsFile);
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
        _owner.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(db, TswapJsonContext.Default.SecretsDb);
        var plaintext = Encoding.UTF8.GetBytes(json);
        var encrypted = Crypto.Encrypt(plaintext, key);
        _owner.WriteAtomic(SecretsFile, encrypted);
    }
}
