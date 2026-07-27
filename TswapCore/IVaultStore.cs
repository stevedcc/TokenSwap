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
/// Deliberately keyed by nothing more than "this store" — no filesystem path is
/// assumed here, so a future blob or row store can implement this interface
/// without adopting file-path semantics it doesn't have (see issue #124). Backends
/// that really are file-backed additionally implement <see cref="IFileVaultStore"/>.
/// </summary>
public interface IVaultStore
{
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

/// <summary>
/// An <see cref="IVaultStore"/> that is backed by plain files on disk, and is willing
/// to say so. The three path members exist for the few commands that manage those
/// files directly (e.g. <c>init</c> backing up the previous config/vault before
/// re-initializing) — they are inherently file-store-specific, so they live here
/// rather than on the base interface. A future non-file backend (blob store, row
/// store) simply doesn't implement this interface, and command logic that wants a
/// path narrows to it explicitly (typically via a pattern match) instead of assuming
/// every <see cref="IVaultStore"/> has one.
/// </summary>
public interface IFileVaultStore : IVaultStore
{
    /// <summary>Directory holding this store's on-disk state.</summary>
    string ConfigDir { get; }

    /// <summary>Path to the config file.</summary>
    string ConfigFile { get; }

    /// <summary>Path to the encrypted secrets file.</summary>
    string SecretsFile { get; }
}
