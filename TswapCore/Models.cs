using System.Text.Json.Serialization;

namespace TswapCore;

public record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created, bool? RequiresTouch = null, string? RngMode = null, string? UnlockChallenge = null);
public record Secret(string Value, DateTime Created, DateTime Modified, DateTime? BurnedAt = null, string? BurnReason = null);
public record SecretsDb(Dictionary<string, Secret> Secrets);
public record ExportFile(string Version, DateTime Created, string Salt, string Ciphertext);

[JsonSerializable(typeof(Config))]
[JsonSerializable(typeof(SecretsDb))]
[JsonSerializable(typeof(ExportFile))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class TswapJsonContext : JsonSerializerContext { }
