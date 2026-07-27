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
    public void Config_NullBackend_IsOmittedFromJson()
    {
        // Backward-compat guarantee: a YubiKey vault (Backend unset) must serialize with
        // no Backend field at all, so existing config.json files are byte-for-byte unchanged.
        var config = new Config([1, 2], "aabb", DateTime.UtcNow, RngMode: RngMode.System);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.DoesNotContain("Backend", json);
        Assert.Null(config.Backend);
    }

    [Fact]
    public void Config_Backend_SerializesAsLowercaseAndRoundTrips()
    {
        var tpm = new Config([1, 2], "aabb", DateTime.UtcNow, Backend: HardwareBackend.Tpm);
        var json = JsonSerializer.Serialize(tpm, TswapJsonContext.Default.Config);
        Assert.Contains("\"Backend\": \"tpm\"", json);
        Assert.Equal(HardwareBackend.Tpm, JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!.Backend);

        var se = tpm with { Backend = HardwareBackend.SecureEnclave };
        json = JsonSerializer.Serialize(se, TswapJsonContext.Default.Config);
        Assert.Contains("\"Backend\": \"secure-enclave\"", json);
        Assert.Equal(HardwareBackend.SecureEnclave,
            JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!.Backend);
    }

    [Fact]
    public void Config_LegacyJsonWithoutBackend_DeserializesAsYubiKey()
    {
        // A config from before hardware backends existed has no Backend key; it must load
        // with Backend == null, which VaultUnlocker treats as YubiKey.
        const string legacy = """
            {
              "YubiKeySerials": [11111111, 22222222],
              "RedundancyXor": "00ff",
              "Created": "2024-05-01T00:00:00Z"
            }
            """;
        var config = JsonSerializer.Deserialize(legacy, TswapJsonContext.Default.Config)!;
        Assert.Null(config.Backend);
    }

    [Fact]
    public void Config_NullTpmSealedKey_IsOmittedFromJson()
    {
        // Same backward-compat guarantee as SecureEnclaveWrappedKey: a non-TPM vault must
        // serialize with no TpmSealedKey field at all.
        var config = new Config([1, 2], "aabb", DateTime.UtcNow, RngMode: RngMode.System);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.DoesNotContain("TpmSealedKey", json);
        Assert.Null(config.TpmSealedKey);
    }

    [Fact]
    public void Config_TpmSealedKey_RoundTrips()
    {
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm, TpmSealedKey: "c2VhbGVk");
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.Contains("\"TpmSealedKey\": \"c2VhbGVk\"", json);
        Assert.Equal("c2VhbGVk", JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!.TpmSealedKey);
    }

    [Fact]
    public void Config_NullMasterKeySalt_IsOmittedFromJson()
    {
        // Same backward-compat guarantee as TpmSealedKey/SecureEnclaveWrappedKey: a vault
        // that hasn't opted into a per-vault salt must serialize with no MasterKeySalt field
        // at all, so every existing config.json on disk stays byte-for-byte unchanged.
        var config = new Config([1, 2], "aabb", DateTime.UtcNow, RngMode: RngMode.System);
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.DoesNotContain("MasterKeySalt", json);
        Assert.Null(config.MasterKeySalt);
    }

    [Fact]
    public void Config_MasterKeySalt_RoundTrips()
    {
        var config = new Config([1, 2], "aabb", DateTime.UtcNow, MasterKeySalt: "c2FsdHNhbHQ=");
        var json = JsonSerializer.Serialize(config, TswapJsonContext.Default.Config);
        Assert.Contains("\"MasterKeySalt\": \"c2FsdHNhbHQ=\"", json);
        Assert.Equal("c2FsdHNhbHQ=", JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!.MasterKeySalt);
    }

    [Fact]
    public void Config_LegacyJsonWithoutMasterKeySalt_DeserializesAsNull()
    {
        // A config from before this field existed has no MasterKeySalt key; it must load
        // with MasterKeySalt == null, which Crypto.DeriveKey treats as "use the legacy
        // hardcoded salt constant".
        const string legacy = """
            {
              "YubiKeySerials": [11111111, 22222222],
              "RedundancyXor": "00ff",
              "Created": "2024-05-01T00:00:00Z"
            }
            """;
        var config = JsonSerializer.Deserialize(legacy, TswapJsonContext.Default.Config)!;
        Assert.Null(config.MasterKeySalt);
    }

    [Fact]
    public void ExportFile_V1VersionTag_Unchanged()
    {
        // The v1 tag and its (Kdf-less) shape must never change — every export file ever
        // produced with this version tag must keep importing bit-for-bit as before (#108).
        Assert.Equal("tswap-export-v1", ExportFile.V1);
        var export = new ExportFile(ExportFile.V1, DateTime.UtcNow, "c2FsdA==", "Y2lwaGVy");
        var json = JsonSerializer.Serialize(export, TswapJsonContext.Default.ExportFile);
        Assert.Contains("\"Version\": \"tswap-export-v1\"", json);
        Assert.DoesNotContain("Kdf", json);
        Assert.Null(export.Kdf);
    }

    [Fact]
    public void ExportFile_CurrentVersion_IsV2WithExplicitKdfParams()
    {
        // #30 + #108: fresh exports now stamp v2 and explicit Argon2id KDF params.
        Assert.Equal("tswap-export-v2", ExportFile.V2);
        Assert.Equal(ExportFile.V2, ExportFile.CurrentVersion);

        var kdf = new KdfParams(KdfAlgorithm.Argon2id, MemoryKiB: 19 * 1024, TimeCost: 2, Parallelism: 1);
        var export = new ExportFile(ExportFile.CurrentVersion, DateTime.UtcNow, "c2FsdA==", "Y2lwaGVy", kdf);
        var json = JsonSerializer.Serialize(export, TswapJsonContext.Default.ExportFile);

        Assert.Contains("\"Version\": \"tswap-export-v2\"", json);
        Assert.Contains("\"Algorithm\": \"argon2id\"", json);
        Assert.Contains("\"MemoryKiB\": 19456", json);

        var roundTripped = JsonSerializer.Deserialize(json, TswapJsonContext.Default.ExportFile)!;
        Assert.Equal(kdf, roundTripped.Kdf);
    }

    [Fact]
    public void KdfParams_Pbkdf2Shape_RoundTrips()
    {
        // Even though nothing writes this today (v1 leaves Kdf null and implies PBKDF2), the
        // PBKDF2 shape of KdfParams must itself serialize/deserialize correctly per #30, since
        // the whole point is a format that can describe either algorithm.
        var kdf = new KdfParams(KdfAlgorithm.Pbkdf2Sha256, Iterations: 100_000, HashAlgorithm: "SHA256");
        var json = JsonSerializer.Serialize(kdf, TswapJsonContext.Default.KdfParams);
        Assert.Contains("\"Algorithm\": \"pbkdf2-sha256\"", json);
        Assert.Contains("\"Iterations\": 100000", json);
        Assert.DoesNotContain("MemoryKiB", json);

        var roundTripped = JsonSerializer.Deserialize(json, TswapJsonContext.Default.KdfParams);
        Assert.Equal(kdf, roundTripped);
    }
}

