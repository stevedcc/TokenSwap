using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T14 item 4: every time tswap writes (created, modified, burned, approved, export and backup
/// times, the one-hour cutoffs) comes from one injected <see cref="TimeProvider"/>, set here to a
/// fixed instant that is not the system time. A commands' time is <see cref="CommandContext.Time"/>;
/// the store's (HLC stamps, backup names) and the file layer's (the orphan sweep) come from their own
/// constructor parameter, which the composition root fills with the same instance.
/// </summary>
public sealed class TimeProviderTests : IDisposable
{
    /// <summary>The fake clock's instant: <see cref="BrokerManualClock"/>'s start plus 123 ms.</summary>
    private static readonly DateTime T0 = new(2026, 10, 30, 12, 0, 0, 123, DateTimeKind.Utc);

    private const string T0BackupSuffix = ".bak-20261030T120000123Z";

    private readonly BrokerManualClock _clock = new();
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly List<string> _dirs = [];

    public TimeProviderTests()
    {
        _clock.Advance(TimeSpan.FromMilliseconds(123));
        Assert.Equal(T0, _clock.GetUtcNow().UtcDateTime);
        _m = new FleetMachine("time", _keys) { Time = _clock };
    }

    public void Dispose()
    {
        _m.Dispose();
        foreach (var dir in _dirs.Where(Directory.Exists))
            Directory.Delete(dir, true);
    }

    private string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-time-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        return dir;
    }

    private DateTime Later(TimeSpan by)
    {
        _clock.Advance(by);
        return _clock.GetUtcNow().UtcDateTime;
    }

    /// <summary>A classic vault's secrets, read with the machine's simulated YubiKey.</summary>
    private SecretsDb ClassicSecrets() =>
        new Storage(_m.Dir).LoadSecrets(new VaultUnlocker(_keys).Unlock(_m.Config, s => s[0]), TextWriter.Null);

    private static void AssertUtc(DateTime expected, DateTime? actual)
    {
        Assert.Equal(expected, actual);
        Assert.Equal(DateTimeKind.Utc, actual!.Value.Kind);
    }

    // ---------------------------------------------------------------- commands (CommandContext.Time)

    [Fact]
    public void Init_WritesCreated_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");

        AssertUtc(T0, _m.Config.Created);
    }

    [Fact]
    public void Create_WritesCreatedAndModified_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");
        var t1 = Later(TimeSpan.FromHours(1));

        _m.Ok("", "create", "db-pw");

        var secret = ClassicSecrets().Secrets["db-pw"];
        AssertUtc(t1, secret.Created);
        AssertUtc(t1, secret.Modified);
    }

    [Fact]
    public void Add_WritesCreatedAndModified_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");
        var t1 = Later(TimeSpan.FromHours(1));

        _m.Ok("typed-value\ntyped-value\n", "add", "api-key");

        var secret = ClassicSecrets().Secrets["api-key"];
        Assert.Equal("typed-value", secret.Value);
        AssertUtc(t1, secret.Created);
        AssertUtc(t1, secret.Modified);
    }

    [Fact]
    public void Ingest_WritesCreatedAndModified_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");
        var t1 = Later(TimeSpan.FromHours(1));

        _m.Ok("piped-value", "ingest", "token");

        var secret = ClassicSecrets().Secrets["token"];
        AssertUtc(t1, secret.Created);
        AssertUtc(t1, secret.Modified);
    }

    [Fact]
    public void Burn_WritesBurnedAt_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");
        _m.Ok("", "create", "db-pw");
        var t1 = Later(TimeSpan.FromHours(1));

        _m.Ok("", "burn", "db-pw", "seen in a log");

        var secret = ClassicSecrets().Secrets["db-pw"];
        AssertUtc(t1, secret.BurnedAt);
        AssertUtc(T0, secret.Created);
    }

    [Fact]
    public void Rotate_WritesModified_FromTheTimeProvider_AndKeepsCreated()
    {
        _m.Ok("", "init", "--keyring");
        _m.Ok("", "create", "db-pw");
        var t1 = Later(TimeSpan.FromHours(1));

        _m.Ok("", "rotate", "db-pw");

        var secret = ClassicSecrets().Secrets["db-pw"];
        AssertUtc(t1, secret.Modified);
        AssertUtc(T0, secret.Created);
    }

    [Fact]
    public void Export_WritesItsCreatedTimestamp_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");
        _m.Ok("", "create", "db-pw");
        var t1 = Later(TimeSpan.FromHours(1));
        var exportPath = _m.PathOf("export.json");

        _m.Ok("passphrase\npassphrase\n", "export", exportPath);

        var export = JsonSerializer.Deserialize(File.ReadAllText(exportPath), TswapJsonContext.Default.ExportFile)!;
        AssertUtc(t1, export.Created);
    }

    [Fact]
    public void SlotRequestApproveAccept_WriteTheirTimes_FromTheTimeProvider()
    {
        _m.Ok("", "init", "--keyring");
        using var requester = new FleetMachine("time-requester", SimulatedYubiKeyService.WithKeys(SerialB)) { Time = _clock };
        var requestFile = requester.PathOf("request.json");
        var approveFile = _m.PathOf("approve.json");

        var requested = Later(TimeSpan.FromHours(1));
        requester.Ok("", "slot", "request", requestFile);
        AssertUtc(requested, requester.Config.Created);

        var approved = Later(TimeSpan.FromHours(1));
        _m.Ok("", "slot", "approve", requestFile, approveFile);
        AssertUtc(approved, Assert.Single(_m.Config.ApprovedSlots!).Approved);

        // 'slot accept' writes no time of its own here: the accepted config keeps the request's Created.
        Later(TimeSpan.FromHours(1));
        requester.Ok("", "slot", "accept", approveFile);
        AssertUtc(requested, requester.Config.Created);
    }

    // ---------------------------------------------------------------- record store (HLC stamps)

    [Fact]
    public void RecordStore_CreateThenBurnAtTheSameInstant_StampsT0_TheBurnOnTheNextLogicalCounter()
    {
        var vaultKey = VaultKey(_m, InitRecordVault(_m));

        _m.Ok("", "create", "db-pw");
        _m.Ok("", "burn", "db-pw", "seen in a log");

        // Created comes from the command's time (CommandContext.Time), the stamps from the store's:
        // both are T0 to the millisecond. With the clock standing still every stamp keeps T0's
        // physical time and only the HLC's logical counter moves: the create's save takes (T0, 0)
        // for the version and (T0, 1) for the file's write stamp, the burn (T0, 2) for the burn and
        // (T0, 3) for its write stamp. Every displayed time is the physical part: T0.
        var record = ReadRecord(_m, vaultKey, "db-pw");
        var t0Ms = new DateTimeOffset(T0).ToUnixTimeMilliseconds();
        Assert.Equal(t0Ms, record.CreatedMs);
        Assert.Equal(new Hlc(t0Ms, 0), record.Version.Hlc);
        Assert.Equal(new Hlc(t0Ms, 2), Assert.Single(record.Burns).Burn.Hlc);
        Assert.Equal(new Hlc(t0Ms, 3), record.Write.Hlc);

        var secret = new RecordVaultStore(_m.Dir).LoadSecrets(vaultKey).Secrets["db-pw"];
        AssertUtc(T0, secret.Created);
        AssertUtc(T0, secret.Modified);
        AssertUtc(T0, secret.BurnedAt);
    }

    [Fact]
    public void Restore_WritesTheNewVersionsTime_FromTheTimeProvider()
    {
        var vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("old-pw", "ingest", "db-pw");
        Later(TimeSpan.FromHours(1));
        _m.Ok("new-pw", "ingest", "--rotate", "db-pw");
        var t2 = Later(TimeSpan.FromHours(1));

        _m.Ok("", "restore", "db-pw");

        // The record store keeps a version's time as its HLC stamp, taken from the store's clock.
        var secret = new RecordVaultStore(_m.Dir).LoadSecrets(vaultKey).Secrets["db-pw"];
        Assert.Equal("old-pw", secret.Value);
        AssertUtc(t2, secret.Modified);
        AssertUtc(T0, secret.Created);
    }

    // ---------------------------------------------------------------- backup names

    [Fact]
    public void StorageBackupConfig_NamesTheBackup_FromTheTimeProvider()
    {
        var dir = NewDir();
        File.WriteAllText(Path.Combine(dir, "config.json"), "{}");

        var backup = new Storage(dir, time: _clock).BackupConfig();

        Assert.Equal(Path.Combine(dir, "config.json") + T0BackupSuffix, backup);
        Assert.Equal("{}", File.ReadAllText(backup));
    }

    [Fact]
    public void RecordVaultStoreBackupConfig_NamesTheBackup_FromTheTimeProvider()
    {
        var dir = NewDir();
        File.WriteAllText(Path.Combine(dir, "config.json"), "{}");

        var backup = new RecordVaultStore(dir, time: _clock).BackupConfig();

        Assert.Equal(Path.Combine(dir, "config.json") + T0BackupSuffix, backup);
        Assert.Equal("{}", File.ReadAllText(backup));
    }

    // ---------------------------------------------------------------- one-hour cutoffs

    [Fact]
    public void DurableWrite_SweepsAnOrphanTempFile61MinutesOld_KeepsOne59MinutesOld()
    {
        var dir = NewDir();
        var young = Path.Combine(dir, "record.0123456789AB.tmp");
        var old = Path.Combine(dir, "record.0123456789AC.tmp");
        File.WriteAllText(young, "in flight");
        File.WriteAllText(old, "left by a crash");
        File.SetLastWriteTimeUtc(young, T0.AddMinutes(-59));
        File.SetLastWriteTimeUtc(old, T0.AddMinutes(-61));

        new DirectoryOwnerMatcher(time: _clock).WriteDurable(Path.Combine(dir, "record"), "new"u8);

        Assert.True(File.Exists(young), "a temp file 59 minutes old may belong to a write in flight: kept");
        Assert.False(File.Exists(old), "a temp file 61 minutes old is a crash's leftover: removed");
        Assert.Equal("new", File.ReadAllText(Path.Combine(dir, "record")));
    }

    [Fact]
    public void ThroughCliHost_TheCommandsAndTheStore_ReadTheOneTimeSeam()
    {
        var dir = NewDir();
        var testKey = new byte[32];
        testKey[0] = 0x42;
        var env = new Dictionary<string, string?>
        {
            ["TSWAP_CONFIG_DIR"] = dir,
            ["TSWAP_TEST_KEY"] = Convert.ToHexString(testKey),
            ["TSWAP_TEST_SUDO_BYPASS"] = "1",
        };
        (int Exit, string Out, string Err) Run(params string[] args)
        {
            var console = new FakeConsole("");
            var exit = CliHost.Run(args, console, name => env.GetValueOrDefault(name), isPrivileged: false,
                processPath: "/usr/local/bin/tswap", timeForTests: _clock);
            return (exit, console.OutText, console.ErrorText);
        }

        var init = Run("init", "--keyring");
        Assert.True(init.Exit == 0, init.Err);
        var created = Later(TimeSpan.FromHours(1));
        var create = Run("create", "db-pw");
        Assert.True(create.Exit == 0, create.Err);
        var migrated = Later(TimeSpan.FromHours(1));
        var migrate = Run("migrate", "--to-records");
        Assert.True(migrate.Exit == 0, migrate.Err);

        var stamp = "yyyyMMdd'T'HHmmssfff'Z'";
        var config = JsonSerializer.Deserialize(File.ReadAllText(Path.Combine(dir, "config.json")), TswapJsonContext.Default.Config)!;
        AssertUtc(T0, config.Created);
        // The store's backup of config.json and the command's move of secrets.json.enc, both at the migration's time.
        Assert.True(File.Exists(Path.Combine(dir, "config.json.bak-" + migrated.ToString(stamp))), migrate.Out);
        Assert.True(File.Exists(Path.Combine(dir, "secrets.json.enc.bak-" + migrated.ToString(stamp))), migrate.Out);
        var store = new RecordVaultStore(dir);
        var vaultKey = new VaultUnlocker(new TestKeyYubiKeyService(testKey), overrideKey: testKey).Unlock(store.LoadConfig(), s => s[0]);
        var secret = store.LoadSecrets(vaultKey).Secrets["db-pw"];
        AssertUtc(created, secret.Created);
    }
}
