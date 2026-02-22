using System.Text.Json.Serialization;

namespace TswapCore;

public record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created, bool? RequiresTouch = null, string RngMode = "system", string? UnlockChallenge = null);
public record Secret(string Value, DateTime Created, DateTime Modified, DateTime? BurnedAt = null, string? BurnReason = null);
public record SecretsDb(Dictionary<string, Secret> Secrets);

[JsonSerializable(typeof(Config))]
[JsonSerializable(typeof(SecretsDb))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class TswapJsonContext : JsonSerializerContext { }
