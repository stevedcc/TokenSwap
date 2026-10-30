using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 3 (decisions 3 and 4) through the store and the CLI: HLC stamps across commands,
/// sync tools' conflicted copies of a record, unreadable records failing closed, and the clean-up
/// of copies a decided conflict made redundant.
/// </summary>
public sealed class RecordConflictTests : IDisposable
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly FleetMachine _other;
    private readonly byte[] _vaultKey;
    private DateTimeOffset _now = T0;
    private DateTimeOffset _otherNow = T0;

    public RecordConflictTests()
    {
        _m = new FleetMachine("conflict-a", _keys) { Clock = () => _now };
        var recoveryKey = InitRecordVault(_m);
        _vaultKey = VaultKey(_m, recoveryKey);
        _other = new FleetMachine("conflict-b", _keys) { Clock = () => _otherNow };
    }

    public void Dispose()
    {
        _m.Dispose();
        _other.Dispose();
    }

    /// <summary>Points <see cref="_other"/> at a copy of the vault folder (another synced replica).</summary>
    private void OtherGetsACopyOfTheFolder()
    {
        var copy = Path.Combine(_other.Dir, "vault");
        CopyFolder(_m.VaultDir!, copy);
        File.WriteAllText(_other.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { VaultDir = copy, OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));
    }

    /// <summary>Points <see cref="_other"/> at the same vault folder (a network share, or a sync tool caught up).</summary>
    private void OtherSharesTheFolder() =>
        File.WriteAllText(_other.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));

    private string Rec(string name) => RecordFile(_m, _vaultKey, name);

    private string OtherRec(string name) => RecordFile(_other, _vaultKey, name);

    // ------------------------------------------------------------------ HLC across commands

    [Fact]
    public void Hlc_NeverDecreases_WithTheClockSetBackBetweenCommands()
    {
        _m.Ok("v1", "ingest", "s");
        var first = ReadRecord(_m, _vaultKey, "s");

        _now = T0.AddHours(-5);
        _m.Ok("", "burn", "s", "seen");
        var second = ReadRecord(_m, _vaultKey, "s");

        Assert.True(second.OutstandingBurn!.Burn.Hlc > first.Write.Hlc);
        Assert.True(second.Write.Hlc > second.OutstandingBurn.Burn.Hlc);
    }

    [Fact]
    public void Hlc_TwoWritesInTheSameMillisecond_GetDistinctIncreasingStamps()
    {
        _m.Ok("v1", "ingest", "a");
        _m.Ok("v2", "ingest", "b");

        var a = ReadRecord(_m, _vaultKey, "a").Version.Hlc;
        var b = ReadRecord(_m, _vaultKey, "b").Version.Hlc;
        Assert.Equal(T0.ToUnixTimeMilliseconds(), a.PhysicalMs);
        Assert.True(b > a);
    }

    [Fact]
    public void AWriteAfterSeeingARecordFromTheFuture_OrdersAfterIt()
    {
        OtherSharesTheFolder();
        _otherNow = T0.AddDays(3); // the other machine's clock runs three days ahead
        _other.Ok("v1", "ingest", "s");
        var future = ReadRecord(_m, _vaultKey, "s");

        _m.Ok("", "burn", "s", "seen here");

        var after = ReadRecord(_m, _vaultKey, "s");
        Assert.True(after.OutstandingBurn!.Burn.Hlc > future.Write.Hlc);
        Assert.True(after.Write.Hlc > future.Write.Hlc);
    }

    [Fact]
    public void AnAbsurdFutureStamp_IsWarnedAbout_AndNamesShowsFarFuture()
    {
        _m.Ok("v2", "ingest", "normal");
        OtherSharesTheFolder();
        _otherNow = DateTimeOffset.MaxValue;
        _other.Ok("v1", "ingest", "from-the-future");

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.Contains("far future", stdout.Split('\n').Single(l => l.Contains("from-the-future")));
        Assert.Contains("2027-01-15", stdout.Split('\n').Single(l => l.Contains("normal")));
        Assert.Contains(Path.GetFileName(Rec("from-the-future")), stderr);
        Assert.Contains("year ahead", stderr);
    }

    // ------------------------------------------------------------------ conflicted copies

    [Theory]
    [InlineData(" (conflicted copy 2026-10-30)", "Dropbox")]
    [InlineData(" (1)", "Dropbox")]
    [InlineData("-DESKTOP-ABC123", "OneDrive")]
    [InlineData(".sync-conflict-20261030-120000-ABCDEF", "Syncthing")]
    public void ARealConflictCopyName_IsResolvedByTheRules(string suffix, string tool)
    {
        _m.Ok("v1", "ingest", "s");
        OtherGetsACopyOfTheFolder();
        _otherNow = T0.AddMinutes(5);
        _other.Ok("v2\nv2\n", "add", "s"); // a newer value on the other replica
        File.Copy(OtherRec("s"), Rec("s") + suffix);

        Assert.Equal("v2", _m.Get("s"));
        var (_, names, err) = _m.Run("", "names");
        Assert.Single(names.Split('\n'), l => l.StartsWith("s "));
        Assert.Contains(tool, err);
        Assert.Contains(Path.GetFileName(Rec("s")), err);
    }

    [Fact]
    public void AnOlderConflictCopy_LosesToTheMainRecord()
    {
        OtherGetsACopyOfTheFolder();
        _other.Ok("old", "ingest", "s");
        _now = T0.AddMinutes(5);
        _m.Ok("new", "ingest", "s");
        File.Copy(OtherRec("s"), Rec("s") + " (1)");

        Assert.Equal("new", _m.Get("s"));
    }

    [Fact]
    public void AnUndecryptableConflictCopy_IsWarnedAbout_AndKept_EvenAfterAWrite()
    {
        _m.Ok("v1", "ingest", "s");
        var copy = Rec("s") + ".sync-conflict-20261030-120000-ABCDEF";
        File.WriteAllBytes(copy, File.ReadAllBytes(Rec("s"))[..100]);

        var (exit, _, err) = _m.Run("", "names");
        Assert.Equal(0, exit);
        Assert.Contains(Path.GetFileName(copy), err);
        Assert.Contains("Syncthing", err);

        _m.Ok("", "burn", "s", "seen");
        Assert.True(File.Exists(copy));
        Assert.Equal("v1", _m.Get("s"));
    }

    [Fact]
    public void RedundantCopies_AreRemovedOnlyOnTheNextWriteOfThatRecord()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("w", "ingest", "unrelated");
        OtherGetsACopyOfTheFolder();
        _otherNow = T0.AddMinutes(5);
        _other.Ok("v2\nv2\n", "add", "s");
        var copy = Rec("s") + " (conflicted copy 2026-10-30)";
        File.Copy(OtherRec("s"), copy);

        // Reads never delete; a write of another record doesn't touch this one's copy.
        _m.Get("s");
        _m.Ok("", "names");
        _m.Ok("", "burn", "unrelated", "x");
        Assert.True(File.Exists(copy));

        _now = T0.AddMinutes(10);
        _m.Ok("", "burn", "s", "seen");

        Assert.False(File.Exists(copy));
        var record = ReadRecord(_m, _vaultKey, "s");
        Assert.Equal("v2", System.Text.Encoding.UTF8.GetString(record.Value));
        Assert.Equal("seen", record.OutstandingBurn!.Reason);
    }

    [Fact]
    public void ARedundantCopyWhoseRemovalFails_IsAWarning_AndTheWriteSucceeds()
    {
        _m.Ok("v1", "ingest", "s");
        OtherGetsACopyOfTheFolder();
        _otherNow = T0.AddMinutes(5);
        _other.Ok("v2\nv2\n", "add", "s");
        var copy = Rec("s") + " (1)";
        File.Copy(OtherRec("s"), copy);

        var store = new RecordVaultStore(_m.Dir, clock: () => _now)
        {
            DeleteFile = path => throw new IOException($"The process cannot access the file '{path}' because it is being used by another process."),
        };
        var warnings = new StringWriter();
        store.LoadConfig();
        var db = store.LoadSecrets(_vaultKey, warnings);
        db.Secrets["s"] = db.Secrets["s"] with { BurnedAt = DateTime.UtcNow, BurnReason = "seen" };
        store.SaveSecrets(db, _vaultKey);

        Assert.Contains("could not remove", warnings.ToString());
        Assert.True(File.Exists(copy));
        Assert.Equal("seen", ReadRecord(_m, _vaultKey, "s").OutstandingBurn!.Reason);
    }

    // ------------------------------------------------------------------ unreadable main record

    [Fact]
    public void ATruncatedMainRecord_FailsClosed()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("w", "ingest", "other");
        var path = Rec("s");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
        // A good conflicted copy beside it changes nothing: the main record may be newer.
        OtherGetsACopyOfTheFolder();
        File.Copy(OtherRec("s"), path + " (1)");
        var truncated = File.ReadAllBytes(path);
        var fileName = Path.GetFileName(path);

        // The command that needs it stops, naming the file.
        var (getExit, _, getErr) = _m.Run("", "get", "s");
        Assert.NotEqual(0, getExit);
        Assert.Contains(fileName, getErr);
        var template = Path.Combine(_m.Dir, "t.yaml");
        File.WriteAllText(template, "a: \"\" # tswap: s\n");
        Assert.Contains(fileName, _m.Run("", "apply", template).Err);
        Assert.Contains(fileName, _m.Run("", "run", "true", "{{s}}").Err);

        // names warns and counts, and still lists the readable ones.
        var (namesExit, names, namesErr) = _m.Run("", "names");
        Assert.Equal(0, namesExit);
        Assert.Contains("other", names);
        Assert.Contains(fileName, namesErr);
        Assert.Contains("1 unreadable record", namesErr);

        // Never treated as absent: creating, ingesting or deleting it refuses.
        Assert.NotEqual(0, _m.Run("", "create", "s").Exit);
        Assert.NotEqual(0, _m.Run("x", "ingest", "s").Exit);
        Assert.NotEqual(0, _m.Run("", "delete", "s").Exit);
        Assert.NotEqual(0, _m.Run("", "burn", "s").Exit);

        // Other writes (a delete runs the tombstone pass over every record) leave it alone.
        _m.Ok("", "delete", "other");
        _m.Ok("", "create", "new-one");
        Assert.Equal(truncated, File.ReadAllBytes(path));
        Assert.True(File.Exists(path + " (1)"));
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
