using System.Text.Json.Serialization;

namespace TswapCore;

/// <summary>
/// Entropy source for generated secrets. Serialized as lowercase strings
/// ("system"/"yubikey") for compatibility with existing config.json files;
/// a null <see cref="Config.RngMode"/> means not yet configured (pre-migration).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RngMode>))]
public enum RngMode
{
    [JsonStringEnumMemberName("system")]
    System,
    [JsonStringEnumMemberName("yubikey")]
    YubiKey,
}

public static class RngModeExtensions
{
    /// <summary>The lowercase name used in config files and CLI output.</summary>
    public static string DisplayName(this RngMode mode)
        => mode == RngMode.YubiKey ? "yubikey" : "system";
}

/// <summary>
/// The hardware root of trust that protects a vault. Serialized as lowercase strings
/// ("yubikey"/"tpm"/"secure-enclave"). A null <see cref="Config.Backend"/> means YubiKey
/// — the only backend that existed before this field — so pre-existing vaults keep
/// working and their <c>config.json</c> is left unchanged (the field is omitted when null).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<HardwareBackend>))]
public enum HardwareBackend
{
    [JsonStringEnumMemberName("yubikey")]
    YubiKey,
    [JsonStringEnumMemberName("tpm")]
    Tpm,
    [JsonStringEnumMemberName("secure-enclave")]
    SecureEnclave,
}

public static class HardwareBackendExtensions
{
    /// <summary>The lowercase name used in config files and error messages.</summary>
    public static string DisplayName(this HardwareBackend backend) => backend switch
    {
        HardwareBackend.Tpm => "tpm",
        HardwareBackend.SecureEnclave => "secure-enclave",
        _ => "yubikey",
    };
}

public record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created, bool? RequiresTouch = null, RngMode? RngMode = null, string? UnlockChallenge = null,
    // Null means YubiKey (every vault created before hardware backends existed). Omitted
    // from config.json when null so existing YubiKey vaults serialize byte-for-byte as before.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HardwareBackend? Backend = null);
public record Secret(string Value, DateTime Created, DateTime Modified, DateTime? BurnedAt = null, string? BurnReason = null);
public record SecretsDb(Dictionary<string, Secret> Secrets);

public record ExportFile(string Version, DateTime Created, string Salt, string Ciphertext)
{
    public const string CurrentVersion = "tswap-export-v1";
}

[JsonSerializable(typeof(Config))]
[JsonSerializable(typeof(SecretsDb))]
[JsonSerializable(typeof(ExportFile))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class TswapJsonContext : JsonSerializerContext { }
