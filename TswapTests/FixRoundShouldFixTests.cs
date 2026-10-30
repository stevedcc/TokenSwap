using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>Fix round 1, C: the review's should-fix items.</summary>
public sealed class FixRoundShouldFixTests : IDisposable
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly byte[] _vaultKey;
    private DateTimeOffset _now = T0;

    public FixRoundShouldFixTests()
    {
        _m = new FleetMachine("shouldfix", _keys) { Clock = () => _now };
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private FleetMachine LaptopWithACopy()
    {
        var laptop = new FleetMachine("shouldfix-laptop", _keys) { Clock = () => _now };
        var copy = Path.Combine(laptop.Dir, "vault");
        CopyFolder(_m.VaultDir!, copy);
        File.WriteAllText(laptop.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { VaultDir = copy, OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));
        return laptop;
    }

    [Fact]
    public void VaultMerge_ChecksEveryRecordsStaleGuard_BeforeWritingTheKeyringOrConfig()
    {
        _m.Ok("v1", "ingest", "s");
        using var laptop = LaptopWithACopy();
        _now = T0.AddMinutes(5);
        laptop.Ok("v2\nv2\n", "add", "s");
        var otherStates = RecordVaultStore.ForFolder(laptop.VaultDir!, laptop.Config).LoadRecordStates(_vaultKey).States;

        var store = new RecordVaultStore(_m.Dir, clock: () => _now);
        var config = store.LoadConfig();
        store.LoadSecrets(_vaultKey);
        // Another process changes the record between this command's load and its write.
        _m.Ok("", "burn", "s", "meanwhile");
        var configBefore = File.ReadAllBytes(_m.ConfigPath);
        var keyringPath = Path.Combine(_m.VaultDir!, "keyring");
        var keyringBefore = File.ReadAllBytes(keyringPath);
        var beforeWriteRan = false;

        // What vault merge does in beforeWrite: back up and save the config with the keyring.
        Assert.Throws<TswapException>(() => store.MergeRecords(otherStates, _vaultKey, beforeWrite: () =>
        {
            beforeWriteRan = true;
            store.SaveConfig(config with { RngMode = RngMode.YubiKey });
        }));
        Assert.False(beforeWriteRan);
        // Fix round 3, item 8: the outcome, not only the seam flag.
        Assert.Equal(configBefore, File.ReadAllBytes(_m.ConfigPath));
        Assert.Equal(keyringBefore, File.ReadAllBytes(keyringPath));
    }

    [Fact]
    public void VaultMerge_SkipsAnUnreadableRecord_AndWarns()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("w1", "ingest", "t");
        using var laptop = LaptopWithACopy();
        _now = T0.AddMinutes(5);
        laptop.Ok("v2\nv2\n", "add", "s");
        laptop.Ok("w2\nw2\n", "add", "t");
        var damaged = RecordFile(_m, _vaultKey, "s");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..120]);
        var damagedBytes = File.ReadAllBytes(damaged);

        var (exit, _, err) = _m.Run("", "vault", "merge", laptop.VaultDir!);

        Assert.Equal(0, exit);
        Assert.Contains(Path.GetFileName(damaged), err);
        Assert.Equal(damagedBytes, File.ReadAllBytes(damaged));
        Assert.Equal("w2", _m.Get("t"));
    }

    [Fact]
    public void VaultMerge_OfItsOwnFolder_SpelledDifferently_IsRefused()
    {
        var spelled = Path.Combine(_m.VaultDir!, "records", "..") + Path.DirectorySeparatorChar;

        var (exit, _, err) = _m.Run("", "vault", "merge", spelled);

        Assert.NotEqual(0, exit);
        Assert.Contains("own folder", err);
    }

    [Fact]
    public void Import_KeepsTheOriginalBurnTime()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("", "burn", "s", "seen");
        var burnedAt = JsonDocument.Parse(_m.Ok("", "burned", "--json")).RootElement[0].GetProperty("burnedAt").GetDateTime();
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);
        _m.Ok("", "delete", "s");
        _now = T0.AddDays(3);

        _m.Ok("pass\n", "import", "--include-burned", export);

        var reimported = JsonDocument.Parse(_m.Ok("", "burned", "--json")).RootElement[0];
        Assert.Equal("outstanding", reimported.GetProperty("status").GetString());
        Assert.Equal(burnedAt, reimported.GetProperty("burnedAt").GetDateTime());
    }

    [Fact]
    public void BurnHistoryTruncation_DoesNotDependOnOrder_WhenBurnStampsTie()
    {
        // restore copies a burn's stamp onto a new version, so equal burn stamps happen.
        var origin = Enumerable.Repeat((byte)7, 16).ToArray();
        var burn = new Stamp(new Hlc(5000, 0), origin);
        var burns = Enumerable.Range(0, RecordMerge.MaxBurns + 4)
            .Select(i => new BurnEntry(new Stamp(new Hlc(100 + i, 0), origin), burn, $"b{i}"))
            .ToList();
        var id = new byte[32];
        var current = new Stamp(new Hlc(9000, 0), origin);
        SecretRecord Record(IEnumerable<BurnEntry> b) =>
            new(id, current, RecordType.Value, current, "s", 1, "v"u8.ToArray(), b.ToList());

        var forward = RecordMerge.Normalize(Record(burns));
        var backward = RecordMerge.Normalize(Record(Enumerable.Reverse(burns)));

        Assert.True(forward.SameState(backward));
    }

    [Fact]
    public void SaveConfig_KeepsTheHigherLastHlcOnDisk()
    {
        var stale = new RecordVaultStore(_m.Dir, clock: () => _now);
        var staleConfig = stale.LoadConfig();
        _now = T0.AddDays(1);
        _m.Ok("v", "ingest", "s"); // another process moves LastHlc on
        var onDisk = Hlc.TryParse(_m.Config.LastHlc)!.Value;

        stale.SaveConfig(staleConfig with { RngMode = RngMode.YubiKey });

        Assert.Equal(onDisk, Hlc.TryParse(_m.Config.LastHlc));
    }

    [Fact]
    public void WriteDurable_SweepsOrphanTempFilesOlderThanAnHour()
    {
        _m.Ok("v", "ingest", "s");
        var old = Path.Combine(_m.RecordsDir, new string('a', 64) + ".0123456789AB.tmp");
        var young = Path.Combine(_m.RecordsDir, new string('b', 64) + ".0123456789AB.tmp");
        File.WriteAllText(old, "orphan");
        File.WriteAllText(young, "in flight");
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddHours(-2));

        _m.Ok("w", "ingest", "t");

        Assert.False(File.Exists(old));
        Assert.True(File.Exists(young));
    }

    private static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var file in Directory.GetFiles(from))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (var dir in Directory.GetDirectories(from))
            CopyFolder(dir, Path.Combine(to, Path.GetFileName(dir)));
    }
}
