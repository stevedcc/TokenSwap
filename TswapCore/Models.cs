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

public record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created, bool? RequiresTouch = null, RngMode? RngMode = null, string? UnlockChallenge = null);
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
