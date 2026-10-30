using System.Security.Cryptography;
using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 6 (decision 8): <c>migrate --to-records [--vault-dir &lt;dir&gt;]</c>. The order
/// (write into a temp folder, re-read and compare, rename, switch config.json, then move
/// secrets.json.enc aside) leaves a working vault after a crash at any step. A plain XOR vault
/// becomes a keyring vault in the same run (K_v stays the derived master key; every enrolled
/// YubiKey gets its own slot, plus a recovery slot).
/// </summary>
public sealed class MigrateToRecordsTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _m;

    public MigrateToRecordsTests() => _m = new FleetMachine("migrate", _keys);

    public void Dispose() => _m.Dispose();

    private string DefaultVaultDir => Path.Combine(_m.Dir, "vault");

    private string[] TempFolders => Directory.GetDirectories(_m.Dir, "vault.tmp-*");

    private string[] SecretsBackups => Directory.GetFiles(_m.Dir, "secrets.json.enc.bak-*");

    /// <summary>50 secrets, every fifth one burned.</summary>
    private static Dictionary<string, Secret> FiftySecrets()
    {
        var secrets = new Dictionary<string, Secret>();
        var t = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        for (var i = 0; i < 50; i++)
        {
            var secret = new Secret($"value-{i}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}", t.AddHours(-i), t.AddMinutes(i));
            if (i % 5 == 0)
                secret = secret with { BurnedAt = t.AddDays(1).AddMinutes(i), BurnReason = $"leak {i}" };
            secrets[$"secret-{i:D2}"] = secret;
        }
        return secrets;
    }

    /// <summary>A plain (XOR) vault on keys A and B with 50 secrets; returns the master key and the secrets.</summary>
    private (byte[] MasterKey, Dictionary<string, Secret> Secrets) PlainVaultWithFiftySecrets()
    {
        _m.Ok("1\n2\n\n", "init");
        var masterKey = new VaultUnlocker(_keys).Unlock(_m.Config, serials => serials[0]);
        var secrets = FiftySecrets();
        new Storage(_m.Dir).SaveSecrets(new SecretsDb(new Dictionary<string, Secret>(secrets)), masterKey);
        return (masterKey, secrets);
    }

    private static void AssertSameSecrets(Dictionary<string, Secret> expected, SecretsDb actual)
    {
        Assert.Equal(expected.Keys.Order(), actual.Secrets.Keys.Order());
        foreach (var (name, secret) in expected)
        {
            var got = actual.Secrets[name];
            Assert.Equal(secret.Value, got.Value);
            Assert.Equal(secret.BurnedAt, got.BurnedAt);
            Assert.Equal(secret.BurnReason, got.BurnReason);
            Assert.Equal(secret.Modified, got.Modified);
        }
    }

    private SecretsDb ReadRecords(byte[] vaultKey)
    {
        var store = new RecordVaultStore(_m.Dir);
        store.LoadConfig();
        return store.LoadSecrets(vaultKey);
    }

    private Dictionary<string, byte[]> ConfigDirSnapshot() =>
        Directory.GetFiles(_m.Dir).ToDictionary(f => Path.GetFileName(f), File.ReadAllBytes);

    private void AssertUnchanged(Dictionary<string, byte[]> before)
    {
        Assert.Equal(before.Keys.Order(), ConfigDirSnapshot().Keys.Order());
        foreach (var (name, bytes) in before)
            Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(_m.Dir, name)));
        Assert.Empty(Directory.GetDirectories(_m.Dir));
    }

    [Fact]
    public void APlainXorVault_With50Secrets_Converts_AndReadsBackWithTheSameMasterKey()
    {
        var (masterKey, secrets) = PlainVaultWithFiftySecrets();

        var output = _m.Ok("1\n", "migrate", "--to-records");

        var config = _m.Config;
        Assert.Equal("records", config.Store);
        Assert.Equal(DefaultVaultDir, config.VaultDir);
        Assert.NotNull(config.OriginId);
        Assert.Null(config.Keyring);
        AssertSameSecrets(secrets, ReadRecords(masterKey));
        Assert.False(File.Exists(_m.SecretsPath));
        Assert.Single(SecretsBackups);
        Assert.Empty(TempFolders);
        Assert.Contains("Recovery Private Key", output);
        Assert.Equal(10, _m.Ok("", "burned").Split('\n').Count(l => l.Contains("leak ")));
    }

    [Fact]
    public void TheConvertedXorVault_OpensWithEachYubiKeyAlone_AndTheRecoveryKey_AndHasNoXorFieldsLeft()
    {
        var (masterKey, secrets) = PlainVaultWithFiftySecrets();
        var output = _m.Ok("1\n", "migrate", "--to-records");

        var config = _m.Config;
        Assert.Empty(config.YubiKeySerials);
        Assert.Equal("", config.RedundancyXor);
        Assert.Null(config.UnlockChallenge);
        Assert.Null(config.MasterKeySalt);
        Assert.DoesNotContain("RedundancyXor\": \"0", _m.ConfigText);

        var keyring = _m.Keyring;
        Assert.Equal(KeyringFormat.KeyringFormatVersion, keyring.FormatVersion);
        Assert.Equal(3, keyring.Slots.Count);
        Assert.Equal(new[] { SerialA, SerialB }, keyring.Slots.Where(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .Select(s => YubiKeySlotBlob.Decode(s.HwBlob!).Serial).Order());

        _keys.PluggedIn = [SerialA];
        Assert.Equal(secrets["secret-07"].Value, _m.Get("secret-07"));
        _keys.PluggedIn = [SerialB];
        Assert.Equal(secrets["secret-08"].Value, _m.Get("secret-08"));
        Assert.Equal(masterKey, RecoveryKeyUnlock.Unlock(keyring, Convert.FromBase64String(RecoveryKeyFrom(output))));
    }

    [Fact]
    public void AMissingYubiKey_RefusesTheRun_NamingIt_BeforeAnythingIsWritten()
    {
        PlainVaultWithFiftySecrets();
        _keys.PluggedIn = [SerialA];
        var before = ConfigDirSnapshot();
        _keys.Challenges.Clear();

        var (exit, _, err) = _m.Run("", "migrate", "--to-records");

        Assert.NotEqual(0, exit);
        Assert.Contains(SerialB.ToString(), err);
        AssertUnchanged(before);
        Assert.Empty(_keys.Challenges); // refused before any unlock or enrolment
    }

    [Fact]
    public void ATpmKeyringVault_With50Secrets_Converts_KeepingItsKeyring()
    {
        _m.Tpm = RandomNumberGenerator.GetBytes(32);
        var initOutput = _m.Ok("", "init", "--tpm");
        var before = _m.Keyring;
        var vaultKey = RecoveryKeyUnlock.Unlock(before, Convert.FromBase64String(RecoveryKeyFrom(initOutput)));
        var secrets = FiftySecrets();
        new Storage(_m.Dir).SaveSecrets(new SecretsDb(new Dictionary<string, Secret>(secrets)), vaultKey);
        var slotId = _m.Config.KeyringSlotId;

        _m.Ok("", "migrate", "--to-records");

        var config = _m.Config;
        Assert.Equal("records", config.Store);
        Assert.Equal(HardwareBackend.Tpm, config.Backend);
        Assert.Equal(slotId, config.KeyringSlotId);
        Assert.Equal(KeyringCodec.Encode(before), File.ReadAllBytes(Path.Combine(DefaultVaultDir, "keyring")));
        AssertSameSecrets(secrets, ReadRecords(vaultKey));
        Assert.Equal(secrets["secret-42"].Value, _m.Get("secret-42"));
        Assert.Single(SecretsBackups);
    }

    [Fact]
    public void AForcedMismatch_ChangesNothing()
    {
        PlainVaultWithFiftySecrets();
        var before = ConfigDirSnapshot();
        _m.MigrationSeams = new RecordMigrationSeams
        {
            TamperReadBack = db =>
            {
                db.Secrets["secret-03"] = db.Secrets["secret-03"] with { Value = "not what was written" };
                return db;
            },
        };

        var (exit, _, err) = _m.Run("1\n", "migrate", "--to-records");

        Assert.NotEqual(0, exit);
        Assert.Contains("secret-03", err);
        AssertUnchanged(before);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(4)]
    public void ACrashAfterAStep_LeavesAWorkingVault_AndARerunFinishesOrRefuses(int step)
    {
        var (_, secrets) = PlainVaultWithFiftySecrets();
        _m.MigrationSeams = new RecordMigrationSeams { AfterStep = s => { if (s == step) throw new IOException($"simulated crash after step {s}"); } };

        var (exit, _, _) = _m.Run("1\n", "migrate", "--to-records");
        Assert.NotEqual(0, exit);
        _m.MigrationSeams = null;

        // The vault still opens: classic before step 4, records after it.
        Assert.Equal(step == 4 ? "records" : null, _m.Config.Store);
        _keys.PluggedIn = [SerialA];
        Assert.Equal(secrets["secret-11"].Value, _m.Get("secret-11"));
        _keys.PluggedIn = [SerialA, SerialB];

        // Fix round 1 (A2): only a temp folder older than an hour counts as left by a crash.
        foreach (var temp in TempFolders)
            Directory.SetLastWriteTimeUtc(temp, DateTime.UtcNow.AddHours(-2));
        var rerun = _m.Run("1\n", "migrate", "--to-records");
        switch (step)
        {
            case 1:
                // The stale temp folder is removed (with a notice) and the conversion finishes.
                Assert.True(rerun.Exit == 0, rerun.Err);
                Assert.Contains("vault.tmp-", rerun.Out + rerun.Err);
                Assert.Equal("records", _m.Config.Store);
                Assert.Empty(TempFolders);
                break;
            case 3:
                // The vault folder is there but config.json still names the classic store: refused
                // (the folder is not empty), and the classic vault keeps working.
                Assert.NotEqual(0, rerun.Exit);
                Assert.Contains("not empty", rerun.Err);
                Assert.Null(_m.Config.Store);
                break;
            case 4:
                // Only the last step was missing: the re-run moves secrets.json.enc aside.
                Assert.True(rerun.Exit == 0, rerun.Err);
                Assert.False(File.Exists(_m.SecretsPath));
                Assert.Single(SecretsBackups);
                break;
        }
        _keys.PluggedIn = [SerialA];
        Assert.Equal(secrets["secret-12"].Value, _m.Get("secret-12"));
    }

    [Fact]
    public void AFileAppearingInTheTargetBeforeTheRename_IsNeverDeleted_AndNothingElseChanges()
    {
        // Fix round 1 (A2): the target is re-checked right before step 3; never a recursive delete.
        var (_, secrets) = PlainVaultWithFiftySecrets();
        var before = File.ReadAllBytes(_m.ConfigPath);
        Directory.CreateDirectory(DefaultVaultDir); // empty at the first check: accepted
        var planted = Path.Combine(DefaultVaultDir, "someone-elses-file");
        _m.MigrationSeams = new RecordMigrationSeams { BeforeStep = s => { if (s == 3) File.WriteAllText(planted, "keep me"); } };

        var (exit, _, err) = _m.Run("1\n", "migrate", "--to-records");

        Assert.NotEqual(0, exit);
        Assert.Contains("not empty", err);
        Assert.Equal("keep me", File.ReadAllText(planted));
        Assert.Empty(TempFolders);
        Assert.Equal(before, File.ReadAllBytes(_m.ConfigPath));
        _m.MigrationSeams = null;
        _keys.PluggedIn = [SerialA];
        Assert.Equal(secrets["secret-05"].Value, _m.Get("secret-05"));
    }

    [Fact]
    public void ARecentTempFolder_RefusesTheRun_AnotherMigrationMayBeRunning()
    {
        PlainVaultWithFiftySecrets();
        var young = DefaultVaultDir + ".tmp-0badc0de";
        Directory.CreateDirectory(young);
        File.WriteAllText(Path.Combine(young, "keyring"), "in progress");

        var (exit, _, err) = _m.Run("1\n", "migrate", "--to-records");

        Assert.NotEqual(0, exit);
        Assert.Contains("another migration may be running", err);
        Assert.True(File.Exists(Path.Combine(young, "keyring")));
        Assert.Null(_m.Config.Store);
    }

    [Fact]
    public void TheRecoveryKey_IsShownBeforeTheConfigSwitch_SoACrashCantLoseIt()
    {
        // Fix round 1 (A4): shown after step 2's verification and before step 4.
        var (masterKey, _) = PlainVaultWithFiftySecrets();
        _m.MigrationSeams = new RecordMigrationSeams { AfterStep = s => { if (s == 3) throw new IOException("simulated crash after step 3"); } };

        var (exit, stdout, _) = _m.Run("1\n", "migrate", "--to-records");

        Assert.NotEqual(0, exit);
        var keyring = KeyringCodec.Decode(File.ReadAllBytes(Path.Combine(DefaultVaultDir, "keyring")));
        Assert.Equal(masterKey, RecoveryKeyUnlock.Unlock(keyring, Convert.FromBase64String(RecoveryKeyFrom(stdout))));
    }

    [Fact]
    public void ARerunAfterACrashAfterStep4_DoesNotClaimARecoveryKey()
    {
        PlainVaultWithFiftySecrets();
        _m.MigrationSeams = new RecordMigrationSeams { AfterStep = s => { if (s == 4) throw new IOException("simulated crash after step 4"); } };
        var (_, firstOut, _) = _m.Run("1\n", "migrate", "--to-records");
        Assert.Contains("Recovery Private Key", firstOut);
        _m.MigrationSeams = null;

        var rerun = _m.Ok("1\n", "migrate", "--to-records");

        Assert.DoesNotContain("Recovery Private Key", rerun);
        Assert.DoesNotContain("recovery key", rerun.ToLowerInvariant());
    }

    [Fact]
    public void ANonEmptyTargetFolder_IsRefused()
    {
        PlainVaultWithFiftySecrets();
        var target = Path.Combine(_m.Dir, "shared");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "something"), "x");
        var before = File.ReadAllBytes(_m.ConfigPath);

        var (exit, _, err) = _m.Run("1\n", "migrate", "--to-records", "--vault-dir", target);

        Assert.NotEqual(0, exit);
        Assert.Contains("not empty", err);
        Assert.Equal(before, File.ReadAllBytes(_m.ConfigPath));
        Assert.True(File.Exists(_m.SecretsPath));
    }

    [Fact]
    public void AnEmptyTargetFolderElsewhere_IsUsed()
    {
        var (masterKey, secrets) = PlainVaultWithFiftySecrets();
        var target = Path.Combine(_m.Dir, "OneDrive", "tswap-vault");
        Directory.CreateDirectory(target);

        _m.Ok("1\n", "migrate", "--to-records", "--vault-dir", target);

        Assert.Equal(target, _m.Config.VaultDir);
        Assert.True(File.Exists(Path.Combine(target, "keyring")));
        AssertSameSecrets(secrets, ReadRecords(masterKey));
    }

    [Fact]
    public void RunningItTwice_Refuses_AlreadyARecordStore()
    {
        PlainVaultWithFiftySecrets();
        _m.Ok("1\n", "migrate", "--to-records");

        var (exit, _, err) = _m.Run("1\n", "migrate", "--to-records");

        Assert.NotEqual(0, exit);
        Assert.Contains("already a record store", err);
    }

    [Fact]
    public void WithoutSudo_IsRefused()
    {
        PlainVaultWithFiftySecrets();
        _m.Sudo = false;

        Assert.Contains("sudo", _m.Run("1\n", "migrate", "--to-records").Err);
        Assert.Null(_m.Config.Store);
    }
}

/// <summary>
/// Brief T6 decision 8, last bullet: another machine joins an existing shared vault folder with
/// <c>init --vault-dir</c> (a YubiKey or recovery slot opens it) or <c>slot accept --vault-dir</c>
/// (its new slot goes straight into the shared keyring).
/// </summary>
public sealed class JoinSharedVaultFolderTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _home;
    private readonly FleetMachine _laptop;
    private readonly string _shared;

    public JoinSharedVaultFolderTests()
    {
        _home = new FleetMachine("join-home", _keys);
        _laptop = new FleetMachine("join-laptop", _keys);
        _shared = Path.Combine(_home.Dir, "Sync", "tswap");
        _home.Ok("", "init", "--keyring");
        _home.Ok("shared-value", "ingest", "s");
        _home.Ok("", "migrate", "--to-records", "--vault-dir", _shared);
    }

    public void Dispose()
    {
        _home.Dispose();
        _laptop.Dispose();
    }

    [Fact]
    public void InitVaultDir_OnAnExistingFolder_PointsThisMachineAtIt()
    {
        _laptop.Ok("", "init", "--vault-dir", _shared);

        var config = _laptop.Config;
        Assert.Equal("records", config.Store);
        Assert.Equal(_shared, config.VaultDir);
        Assert.NotEqual(_home.Config.OriginId, config.OriginId);
        Assert.Equal("shared-value", _laptop.Get("s"));
        _laptop.Ok("laptop-value", "ingest", "t");
        Assert.Equal("laptop-value", _home.Get("t"));
    }

    [Fact]
    public void InitVaultDir_OnAFolderWithoutAKeyring_IsRefused()
    {
        var empty = Path.Combine(_laptop.Dir, "empty");
        Directory.CreateDirectory(empty);

        var (exit, _, err) = _laptop.Run("", "init", "--vault-dir", empty);

        Assert.NotEqual(0, exit);
        Assert.Contains("migrate --to-records", err);
        Assert.False(File.Exists(_laptop.ConfigPath));
    }

    [Fact]
    public void SlotAcceptVaultDir_WritesTheNewSlotIntoTheSharedKeyring()
    {
        _laptop.Tpm = RandomNumberGenerator.GetBytes(32);
        var request = Path.Combine(_laptop.Dir, "request.json");
        var approve = Path.Combine(_laptop.Dir, "approve.json");
        _laptop.Ok("", "slot", "request", "--tpm", request);
        _home.Ok("yes\n", "slot", "approve", request, approve);

        _laptop.Ok("", "slot", "accept", approve, "--vault-dir", _shared);

        var config = _laptop.Config;
        Assert.Equal("records", config.Store);
        Assert.Equal(_shared, config.VaultDir);
        Assert.Null(config.Keyring);
        // No receipt round trip needed: the home machine's keyring (the same file) has the slot.
        var laptopSlot = Convert.FromBase64String(config.KeyringSlotId!);
        Assert.Contains(_home.Keyring.Slots, s => s.SlotId.AsSpan().SequenceEqual(laptopSlot));
        _keys.PluggedIn = [];
        Assert.Equal("shared-value", _laptop.Get("s"));
    }
}

/// <summary>
/// Fix round 1, A5: the documented join flow for a TPM machine on a record-store vault:
/// <c>init --vault-dir</c>, then <c>slot request --tpm</c> on it (the pending-slot fields are machine
/// fields), <c>slot approve</c> on an enrolled machine, <c>slot accept</c>, <c>slot merge</c>.
/// </summary>
public sealed class JoinSharedVaultFolderWithTpmTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _home;
    private readonly FleetMachine _router;
    private readonly string _shared;

    public JoinSharedVaultFolderWithTpmTests()
    {
        _home = new FleetMachine("jointpm-home", _keys);
        _router = new FleetMachine("jointpm-router", _keys) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _shared = Path.Combine(_home.Dir, "Sync", "tswap");
        _home.Ok("", "init", "--keyring");
        _home.Ok("shared-value", "ingest", "s");
        _home.Ok("", "migrate", "--to-records", "--vault-dir", _shared);
    }

    public void Dispose()
    {
        _home.Dispose();
        _router.Dispose();
    }

    [Fact]
    public void InitVaultDir_ThenSlotRequestTpm_Approve_Accept_Merge_OpensWithTheTpm()
    {
        var joinOutput = _router.Ok("", "init", "--vault-dir", _shared);
        var request = _router.PathOf("request.json");
        var approve = _router.PathOf("approve.json");

        _router.Ok("yes\n", "slot", "request", "--tpm", request);
        Assert.Equal("records", _router.Config.Store);
        Assert.Equal(_shared, _router.Config.VaultDir);
        _home.Ok("", "slot", "approve", request, approve);
        _router.Ok("", "slot", "accept", approve);
        _home.Ok("", "slot", "merge", approve + ".receipt.json");

        var config = _router.Config;
        Assert.Equal("records", config.Store);
        Assert.Null(config.PendingSlotId);
        var slotId = Convert.FromBase64String(config.KeyringSlotId!);
        Assert.Contains(_home.Keyring.Slots, s => s.SlotId.AsSpan().SequenceEqual(slotId));
        _keys.PluggedIn = [];
        Assert.Equal("shared-value", _router.Get("s"));
        // The printed guidance names the flow that works.
        Assert.Contains("slot accept <approve-file>", joinOutput);
    }
}
