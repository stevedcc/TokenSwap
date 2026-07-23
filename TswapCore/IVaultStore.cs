namespace TswapCore;

/// <summary>
/// Persistence seam for the vault: load/save of the <see cref="Config"/> and the
/// encrypted <see cref="SecretsDb"/>. <see cref="Storage"/> is the default
/// single-file implementation (<c>config.json</c> + <c>secrets.json.enc</c>);
/// alternative backends contemplated by the refactoring plan — an age-encrypted
/// file, an OS keychain, or the Phase 6 per-record multi-machine store — implement
/// this same contract, so the composition root can swap them without touching any
/// command.
///
/// The file-path members (<see cref="ConfigFile"/>, <see cref="SecretsFile"/>) are
/// specific to file-backed stores and exist for the few commands that manage those
/// files directly (e.g. <c>init</c> backups). Non-file backends are free to surface
/// synthetic paths or throw; command logic that depends on them is a known
/// file-store coupling to revisit when a second backend lands.
/// </summary>
public interface IVaultStore
{
    /// <summary>Directory holding this store's on-disk state.</summary>
    string ConfigDir { get; }

    /// <summary>Path to the config file (file-backed stores only).</summary>
    string ConfigFile { get; }

    /// <summary>Path to the encrypted secrets file (file-backed stores only).</summary>
    string SecretsFile { get; }

    /// <summary>Loads and deserializes the vault config. Throws if not initialized.</summary>
    Config LoadConfig();

    /// <summary>Persists the vault config.</summary>
    void SaveConfig(Config config);

    /// <summary>
    /// Loads and decrypts the secrets database. A missing vault or config directory
    /// is recoverable (returns an empty database); the explanation is written to
    /// <paramref name="warnings"/> when provided, so the library never touches the
    /// console.
    /// </summary>
    SecretsDb LoadSecrets(byte[] key, TextWriter? warnings = null);

    /// <summary>Encrypts and persists the secrets database.</summary>
    void SaveSecrets(SecretsDb db, byte[] key);
}
