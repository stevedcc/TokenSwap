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
    private readonly TextWriter? _warnings;
    private bool _modesChecked;

    /// <inheritdoc/>
    public DirectoryOwnerMatcher Owner => _owner;

    /// <param name="owner">
    /// Writes every file, and gives files written under sudo the config folder's owner (T5; see
    /// <see cref="DirectoryOwnerMatcher"/>). Null: <see cref="DirectoryOwnerMatcher.Default"/>.
    /// </param>
    /// <param name="warnings">Where the one notice about tightened permissions goes (stderr); null: none.</param>
    public Storage(string configDir, DirectoryOwnerMatcher? owner = null, TextWriter? warnings = null)
    {
        ConfigDir = configDir;
        ConfigFile = Path.Combine(configDir, "config.json");
        SecretsFile = Path.Combine(configDir, "secrets.json.enc");
        _owner = owner ?? DirectoryOwnerMatcher.Default;
        _warnings = warnings;
    }

    /// <summary>
    /// Brief T7 item 6 (#194, rest): before this store's first write, narrows the config folder to
    /// 0700 and config.json and secrets.json.enc to 0600 where they are wider (a vault made before
    /// T5 under umask 022), with one notice naming what changed, as the record store does. The
    /// atomic write then keeps the narrowed mode. Never on a read; never through a symlink
    /// (<see cref="DirectoryOwnerMatcher.Tighten"/>); Windows: no change.
    /// </summary>
    private void TightenModes()
    {
        if (_modesChecked || OperatingSystem.IsWindows())
            return;
        _modesChecked = true;
        List<string> changed = [];
        foreach (var path in new[] { ConfigDir, ConfigFile, SecretsFile })
        {
            try
            {
                // Checked first without acting as the folder's owner: a vault that is already tight
                // (every vault made since T5) needs no identity switch under sudo.
                if (IsWider(path) && _owner.Tighten(path))
                    changed.Add(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _warnings?.WriteLine($"Warning: could not narrow the permissions of {path} ({ex.Message}).");
            }
        }
        if (changed.Count > 0)
            _warnings?.WriteLine(
                $"Notice: tightened permissions (folders 0700, files 0600; they were readable by others) on: {string.Join(", ", changed)}");
    }

    /// <inheritdoc/>
    public string BackupConfig()
    {
        return FileBackup.Copy(ConfigFile, DateTime.UtcNow, _owner);
    }

    /// <inheritdoc/>
    public void WriteFile(string path, string contents) => _owner.WriteAtomic(path, Encoding.UTF8.GetBytes(contents));

    /// <summary>True for an existing folder wider than 0700 or regular file wider than 0600 (never a symlink).</summary>
    private static bool IsWider(string path)
    {
        if (OperatingSystem.IsWindows())
            return false;
        var info = new FileInfo(path);
        if (info.LinkTarget is not null)
            return false;
        if (Directory.Exists(path))
            return (File.GetUnixFileMode(path) & ~(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute)) != 0;
        return info.Exists && (info.UnixFileMode & ~(UnixFileMode.UserRead | UnixFileMode.UserWrite)) != 0;
    }

    public Config LoadConfig()
    {
        if (!_owner.FileExists(ConfigFile))
            throw new TswapException("Not initialized. Run: tswap init");

        // Like File.ReadAllText: honour a byte-order mark (an editor may have added one).
        using var reader = new StreamReader(new MemoryStream(_owner.ReadAllBytes(ConfigFile)), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var json = reader.ReadToEnd();
        return JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)
            ?? throw new TswapException("Invalid config");
    }

    public void SaveConfig(Config config)
    {
        TightenModes();
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
            return new SecretsDb([]);
        }
        catch (DirectoryNotFoundException)
        {
            warnings?.WriteLine(
                $"Warning: config directory not found ({ConfigDir}). Starting with empty vault. " +
                "To recover: restore the config directory from backup. " +
                "To start fresh: run 'tswap init' (this will overwrite config.json).");
            return new SecretsDb([]);
        }
        var decrypted = Crypto.Decrypt(encrypted, key);
        var json = Encoding.UTF8.GetString(decrypted);
        return JsonSerializer.Deserialize(json, TswapJsonContext.Default.SecretsDb)
            ?? new SecretsDb([]);
    }

    public void SaveSecrets(SecretsDb db, byte[] key)
    {
        TightenModes();
        _owner.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(db, TswapJsonContext.Default.SecretsDb);
        var plaintext = Encoding.UTF8.GetBytes(json);
        var encrypted = Crypto.Encrypt(plaintext, key);
        _owner.WriteAtomic(SecretsFile, encrypted);
    }
}
