using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b test support: a record vault folder with a fixed vault key, origin id and clock,
/// and no keyring (the record store's load and save don't read it), so a history of writes gives
/// the same records, stamps and fingerprints on every run; only the random nonces of the sealed
/// sections differ. <see cref="Legacy"/> mutates it as the commands did before brief T16-S2b
/// (<see cref="RecordVaultStore.LoadSecrets"/>, then <see cref="RecordVaultStore.SaveSecrets"/>).
/// </summary>
internal sealed class BareRecordVault : IDisposable
{
    public static readonly byte[] Key = [.. Enumerable.Range(0x40, 32).Select(i => (byte)i)];
    public static readonly byte[] Origin = [.. Enumerable.Repeat((byte)0x5A, 16)];

    private BareRecordVault(string dir)
    {
        Dir = dir;
    }

    /// <summary>A new, empty vault; marked <c>record-format 3</c> when <paramref name="marked"/>, else format 2 (as tswap 0.1 made it).</summary>
    public static BareRecordVault Create(string name, bool marked, long startMs)
    {
        var vault = new BareRecordVault(Path.Combine(Path.GetTempPath(), $"tswap-bare-{name}-" + Guid.NewGuid().ToString("N")[..8]))
        {
            NowMs = startMs,
        };
        Directory.CreateDirectory(vault.VaultDir);
        Directory.CreateDirectory(vault.RecordsDir);
        File.WriteAllText(vault.ConfigPath, JsonSerializer.Serialize(new Config([], "", DateTime.UnixEpoch)
        {
            Store = RecordVaultStore.StoreName, VaultDir = vault.VaultDir, OriginId = Convert.ToBase64String(Origin),
        }, TswapJsonContext.Default.Config));
        if (marked)
            File.WriteAllText(Path.Combine(vault.VaultDir, RecordVaultStore.RecordFormatMarkerFileName), "3\n");
        return vault;
    }

    /// <summary>A copy of this vault (folder and config, same origin id and <c>LastHlc</c>), with its own clock starting where this one is.</summary>
    public BareRecordVault Copy(string name)
    {
        var copy = new BareRecordVault(Path.Combine(Path.GetTempPath(), $"tswap-bare-{name}-" + Guid.NewGuid().ToString("N")[..8]))
        {
            NowMs = NowMs,
        };
        RecordVaultTestSupport.CopyFolder(VaultDir, copy.VaultDir);
        var config = JsonSerializer.Deserialize(File.ReadAllText(ConfigPath), TswapJsonContext.Default.Config)!;
        File.WriteAllText(copy.ConfigPath, JsonSerializer.Serialize(config with { VaultDir = copy.VaultDir }, TswapJsonContext.Default.Config));
        return copy;
    }

    public string Dir { get; }

    public string ConfigPath => Path.Combine(Dir, "config.json");

    public string VaultDir => Path.Combine(Dir, "vault");

    public string RecordsDir => Path.Combine(VaultDir, RecordVaultStore.RecordsFolderName);

    /// <summary>The fixed clock (Unix ms); a test moves it.</summary>
    public long NowMs { get; set; }

    public DateTime Now => DateTimeOffset.FromUnixTimeMilliseconds(NowMs).UtcDateTime;

    public string? LastHlc => JsonSerializer.Deserialize(File.ReadAllText(ConfigPath), TswapJsonContext.Default.Config)!.LastHlc;

    /// <summary>A store as one command opens it, on this vault's clock.</summary>
    public RecordVaultStore Store(TextWriter? warnings = null) =>
        new(Dir, time: new FuncTimeProvider(() => DateTimeOffset.FromUnixTimeMilliseconds(NowMs)), warnings: warnings ?? TextWriter.Null);

    public string FileOf(string name) => FilenameHasher.ComputeFilename(RecordKeyDerivation.DeriveNamesKey(Key), name);

    public string PathOf(string name) => Path.Combine(RecordsDir, FileOf(name));

    /// <summary>Every main record file (hashed name), decoded whole with v0.2's reader, in ordinal order.</summary>
    public List<(string File, byte Format, SecretRecord State)> Records() =>
    [
        .. Directory.GetFiles(RecordsDir)
            .Select(Path.GetFileName)
            .Where(f => f!.Length == 64)
            .Order(StringComparer.Ordinal)
            .Select(f =>
            {
                var bytes = File.ReadAllBytes(Path.Combine(RecordsDir, f!));
                return (f!, SecretRecordCodec.FormatVersionOf(bytes) ?? 0, SecretRecordCodec.Decode(bytes, Key));
            }),
    ];

    public void Dispose()
    {
        try
        {
            Directory.Delete(Dir, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    /// <summary>A record's decoded state as JSON, without the write-independent random parts (the sealed sections).</summary>
    public static JsonObject Describe(string file, byte format, SecretRecord state) => new()
    {
        ["file"] = file,
        ["format"] = format,
        ["write"] = Describe(state.Write),
        ["type"] = state.Type.ToString(),
        ["version"] = Describe(state.Version),
        ["name"] = state.Name,
        ["createdMs"] = state.CreatedMs,
        ["value"] = Convert.ToHexStringLower(state.Value),
        ["fingerprints"] = Describe(state.Fingerprints),
        ["previous"] = state.Previous is { } p
            ? new JsonObject { ["version"] = Describe(p.Version), ["value"] = Convert.ToHexStringLower(p.Value), ["fingerprints"] = Describe(p.Fingerprints) }
            : null,
        ["burns"] = new JsonArray([.. state.Burns.Select(b => (JsonNode)new JsonObject
        {
            ["version"] = Describe(b.Version), ["burn"] = Describe(b.Burn), ["reason"] = b.Reason,
        })]),
        ["extensions"] = new JsonArray([.. state.Extensions.Select(e => (JsonNode)new JsonObject
        {
            ["type"] = e.Type, ["data"] = Convert.ToHexStringLower(e.Data),
        })]),
    };

    private static string Describe(Stamp stamp) => $"{stamp.Hlc.PhysicalMs}.{stamp.Hlc.Logical}@{Convert.ToHexStringLower(stamp.Origin)}";

    private static JsonNode? Describe(FingerprintSet? set) => set is null
        ? null
        : new JsonObject
        {
            ["variantSet"] = set.VariantSetVersion,
            ["entries"] = new JsonArray([.. set.Entries.Select(e => (JsonNode)JsonValue.Create(
                $"{e.Kind}:{e.Length}:{e.RollingHash:x16}:{Convert.ToHexStringLower(e.Hmac)}")!)]),
        };

    /// <summary>
    /// What each write command did before brief T16-S2b: one full load, the change to the
    /// database the command made, one save. Each returns false where the command refused (nothing saved).
    /// <para>
    /// Simplified for histories of sound records only (code review, DeepSeek B M-2): the commands'
    /// <c>ThrowIfUnreadable</c> calls are left out, so <see cref="Create"/> would write over an
    /// unreadable name and <see cref="Restore"/> returns false where <c>restore</c> names the file.
    /// The golden and the oracle never make a damaged record; a history that does needs those calls here.
    /// </para>
    /// </summary>
    public static class Legacy
    {
        private static bool Save(RecordVaultStore store, SecretsDb db)
        {
            store.SaveSecrets(db, Key);
            return true;
        }

        /// <summary><c>create</c> and <c>ingest</c>: refused for an existing name.</summary>
        public static bool Create(BareRecordVault vault, string name, string value)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            if (db.Secrets.ContainsKey(name))
                return false;
            db.Secrets[name] = new Secret(value, vault.Now, vault.Now);
            return Save(store, db);
        }

        /// <summary><c>add</c>: writes only when the value changed (or the name is new).</summary>
        public static bool Add(BareRecordVault vault, string name, string value)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            db.Secrets[name] = new Secret(value, vault.Now, vault.Now);
            return Save(store, db);
        }

        public static bool Burn(BareRecordVault vault, string name, string? reason)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            if (!db.Secrets.TryGetValue(name, out var existing) || existing.BurnedAt.HasValue)
                return false;
            db.Secrets[name] = existing with { BurnedAt = vault.Now, BurnReason = reason };
            return Save(store, db);
        }

        /// <summary><c>rotate</c> and <c>ingest --rotate</c>.</summary>
        public static bool Rotate(BareRecordVault vault, string name, string value)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            if (!db.Secrets.TryGetValue(name, out var existing))
                return false;
            db.Secrets[name] = existing with { Value = value, Modified = vault.Now, BurnedAt = null, BurnReason = null, Rotated = true };
            return Save(store, db);
        }

        public static bool Restore(BareRecordVault vault, string name)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            if (!db.Secrets.TryGetValue(name, out var existing) || existing.PreviousValue is null)
                return false;
            db.Secrets[name] = existing with
            {
                Value = existing.PreviousValue, Modified = vault.Now, BurnedAt = null, BurnReason = null, Rotated = true, Restored = true,
            };
            return Save(store, db);
        }

        public static bool Delete(BareRecordVault vault, string name)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            if (!db.Secrets.Remove(name))
                return false;
            return Save(store, db);
        }

        /// <summary><c>import</c>: every name that isn't live, in the export's order.</summary>
        public static bool Import(BareRecordVault vault, IReadOnlyDictionary<string, Secret> exported)
        {
            var store = vault.Store();
            var db = store.LoadSecrets(Key, TextWriter.Null);
            foreach (var (name, secret) in exported.OrderBy(kv => kv.Key))
            {
                if (!db.Secrets.ContainsKey(name))
                    db.Secrets[name] = secret;
            }
            return Save(store, db);
        }
    }

    /// <summary>The UTF-8 bytes of a value, for planting.</summary>
    public static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
}
