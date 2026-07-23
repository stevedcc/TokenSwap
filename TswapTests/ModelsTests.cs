using System.Text.Json;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Golden-file tests pinning the on-disk JSON formats. These guard refactoring:
/// existing config.json and export files in the wild must keep loading, and new
/// writes must keep producing the same shapes (notably RngMode as a lowercase
/// string, not an enum ordinal or PascalCase name).
/// </summary>
public class ModelsTests
{
    [Fact]
    public void Config_RngMode_SerializesAsLegacyLowercaseString()
    {
        var config = new Config([1, 2], "aabb", DateTime.UtcNow, RngMode: RngMode.System);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.Contains("\"RngMode\": \"system\"", json);

        var yk = config with { RngMode = RngMode.YubiKey };
        json = JsonSerializer.Serialize(yk, TswapJsonContext.Default.Config);
        Assert.Contains("\"RngMode\": \"yubikey\"", json);
    }

    [Fact]
    public void Config_LegacyJson_Deserializes()
    {
        // Shape written by historical versions (string RngMode; null for pre-migration).
        const string legacy = """
            {
              "YubiKeySerials": [11111111, 22222222],
              "RedundancyXor": "00ff",
              "Created": "2024-05-01T00:00:00Z",
              "RequiresTouch": null,
              "RngMode": "yubikey",
              "UnlockChallenge": null
            }
            """;
        var config = JsonSerializer.Deserialize(legacy, TswapJsonContext.Default.Config)!;
        Assert.Equal(RngMode.YubiKey, config.RngMode);
        Assert.Null(config.UnlockChallenge);
        Assert.Equal([11111111, 22222222], config.YubiKeySerials);
    }

    [Fact]
    public void Config_NullRngMode_RoundTrips()
    {
        var config = new Config([1], "00", DateTime.UtcNow);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.Contains("\"RngMode\": null", json);
        var back = JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!;
        Assert.Null(back.RngMode);
    }

    [Fact]
    public void ExportFile_VersionTag_Unchanged()
    {
        Assert.Equal("tswap-export-v1", ExportFile.CurrentVersion);
        var export = new ExportFile(ExportFile.CurrentVersion, DateTime.UtcNow, "c2FsdA==", "Y2lwaGVy");
        var json = JsonSerializer.Serialize(export, TswapJsonContext.Default.ExportFile);
        Assert.Contains("\"Version\": \"tswap-export-v1\"", json);
    }
}
