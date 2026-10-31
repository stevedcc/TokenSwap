using System.Text;
using System.Text.Json;

namespace TswapCore;

/// <summary>
/// Picks the store for a config dir at the composition root (brief T6 decision 1): a
/// <see cref="RecordVaultStore"/> when <c>config.json</c> says <c>"Store": "records"</c>, otherwise
/// the classic <see cref="Storage"/>. Decided by that field only, never by which files are present.
/// </summary>
public static class VaultStores
{
    /// <param name="time">The store's clock: HLC stamps and backup names (null: the system clock).</param>
    /// <param name="warnings">Where a record store reports what it finds on load, and either store
    /// its one notice about tightened permissions (stderr).</param>
    public static IFileVaultStore Open(string configDir, DirectoryOwnerMatcher? owner = null, TimeProvider? time = null, TextWriter? warnings = null)
    {
        owner ??= DirectoryOwnerMatcher.Default;
        return IsRecordStore(configDir, owner)
            ? new RecordVaultStore(configDir, owner, time, warnings)
            : new Storage(configDir, owner, warnings, time);
    }

    /// <summary>True when <paramref name="configDir"/>'s <c>config.json</c> names the record store.</summary>
    public static bool IsRecordStore(string configDir, DirectoryOwnerMatcher? owner = null)
    {
        owner ??= DirectoryOwnerMatcher.Default;
        var configFile = Path.Combine(configDir, "config.json");
        try
        {
            if (!owner.FileExists(configFile))
                return false;
            using var reader = new StreamReader(new MemoryStream(owner.ReadAllBytes(configFile)), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var config = JsonSerializer.Deserialize(reader.ReadToEnd(), TswapJsonContext.Default.Config);
            return config?.Store == RecordVaultStore.StoreName;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or TswapException)
        {
            // Unreadable or malformed: the classic store reports it with its usual message.
            return false;
        }
    }
}
