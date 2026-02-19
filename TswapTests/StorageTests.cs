using System.Security.Cryptography;
using TswapCore;
using Xunit;

namespace TswapTests;

public class StorageTests : IDisposable
{
    private readonly string _tempDir;
    private readonly Storage _storage;
    private readonly byte[] _key;

    public StorageTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _storage = new Storage(_tempDir);
        _key = RandomNumberGenerator.GetBytes(32);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    // --- Config ---

    [Fact]
    public void Config_SaveAndLoad_RoundTrip()
    {
        var config = new Config(
            new List<int> { 12345678, 87654321 },
            "AABBCCDD",
            new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        );

        _storage.SaveConfig(config);
        var loaded = _storage.LoadConfig();

        Assert.Equal(config.YubiKeySerials, loaded.YubiKeySerials);
        Assert.Equal(config.RedundancyXor, loaded.RedundancyXor);
        Assert.Equal(config.Created, loaded.Created);
    }

    [Fact]
    public void Config_LoadMissing_Throws()
    {
        Assert.Throws<Exception>(() => _storage.LoadConfig());
    }

    // --- Secrets ---

    [Fact]
    public void Secrets_SaveAndLoad_RoundTrip()
    {
        var now = DateTime.UtcNow;
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["db-pass"] = new Secret("hunter2", now, now),
            ["api-key"] = new Secret("abc123", now, now)
        });

        _storage.SaveSecrets(db, _key);
        var loaded = _storage.LoadSecrets(_key);

        Assert.Equal(2, loaded.Secrets.Count);
        Assert.Equal("hunter2", loaded.Secrets["db-pass"].Value);
        Assert.Equal("abc123", loaded.Secrets["api-key"].Value);
    }

    [Fact]
    public void Secrets_LoadMissing_ReturnsEmpty()
    {
        var db = _storage.LoadSecrets(_key);
        Assert.Empty(db.Secrets);
    }

    [Fact]
    public void Secrets_WrongKey_Throws()
    {
        var now = DateTime.UtcNow;
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["test"] = new Secret("value", now, now)
        });

        _storage.SaveSecrets(db, _key);

        var wrongKey = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<Exception>(() => _storage.LoadSecrets(wrongKey));
    }

    [Fact]
    public void Secrets_OverwriteAndReload()
    {
        var now = DateTime.UtcNow;

        // Save initial
        var db1 = new SecretsDb(new Dictionary<string, Secret>
        {
            ["old-secret"] = new Secret("old-value", now, now)
        });
        _storage.SaveSecrets(db1, _key);

        // Overwrite
        var db2 = new SecretsDb(new Dictionary<string, Secret>
        {
            ["new-secret"] = new Secret("new-value", now, now)
        });
        _storage.SaveSecrets(db2, _key);

        var loaded = _storage.LoadSecrets(_key);
        Assert.Single(loaded.Secrets);
        Assert.True(loaded.Secrets.ContainsKey("new-secret"));
        Assert.False(loaded.Secrets.ContainsKey("old-secret"));
    }

    [Fact]
    public void Secrets_EmptyDb_SaveAndLoad()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>());
        _storage.SaveSecrets(db, _key);
        var loaded = _storage.LoadSecrets(_key);
        Assert.Empty(loaded.Secrets);
    }

    // --- Burn tracking via storage ---

    [Fact]
    public void Secrets_BurnTracking_RoundTrip()
    {
        var now = DateTime.UtcNow;
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["clean"] = new Secret("val1", now, now),
            ["burned"] = new Secret("val2", now, now, BurnedAt: now, BurnReason: "leaked in logs")
        });

        _storage.SaveSecrets(db, _key);
        var loaded = _storage.LoadSecrets(_key);

        Assert.Null(loaded.Secrets["clean"].BurnedAt);
        Assert.Null(loaded.Secrets["clean"].BurnReason);
        Assert.NotNull(loaded.Secrets["burned"].BurnedAt);
        Assert.Equal("leaked in logs", loaded.Secrets["burned"].BurnReason);
    }

    [Fact]
    public void Secrets_BurnUpdate_PreservesValue()
    {
        var now = DateTime.UtcNow;
        var original = new Secret("my-secret-value", now, now);

        var burned = original with { BurnedAt = DateTime.UtcNow, BurnReason = "seen in output" };

        Assert.Equal("my-secret-value", burned.Value);
        Assert.Equal(now, burned.Created);
        Assert.NotNull(burned.BurnedAt);
        Assert.Equal("seen in output", burned.BurnReason);
    }

    [Fact]
    public void Secrets_BurnIdempotent_UpdatesTimestamp()
    {
        var created = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var burn1 = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        var burn2 = new DateTime(2025, 7, 1, 0, 0, 0, DateTimeKind.Utc);

        var secret = new Secret("val", created, created, BurnedAt: burn1, BurnReason: "first");
        var reburned = secret with { BurnedAt = burn2, BurnReason = "second reason" };

        Assert.Equal(burn2, reburned.BurnedAt);
        Assert.Equal("second reason", reburned.BurnReason);
        Assert.Equal("val", reburned.Value);
    }
}
