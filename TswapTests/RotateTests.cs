using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 4 (decision 7, #8): <c>rotate &lt;name&gt; [length]</c> and
/// <c>ingest --rotate &lt;name&gt;</c> write a newer version of an existing secret; the secret
/// exists throughout, a burn of the old version becomes history, and <c>burned</c> reports it as
/// rotated. Sudo unless the winning version is burned (owner decision 2026-10-30).
/// </summary>
public sealed class RotateTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly byte[] _vaultKey;

    public RotateTests()
    {
        _m = new FleetMachine("rotate", _keys);
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private string[] RecordBytesSnapshot() => _m.RecordFiles.Select(f => Convert.ToHexString(File.ReadAllBytes(Path.Combine(_m.RecordsDir, f)))).ToArray();

    [Fact]
    public void Rotate_ABurnedSecret_WritesANewValue_BurnedListsItAsRotated_HistoryKept()
    {
        _m.Ok("old-value", "ingest", "api-token");
        _m.Ok("", "burn", "api-token", "pasted in chat");
        var before = ReadRecord(_m, _vaultKey, "api-token");

        var output = _m.Ok("", "rotate", "api-token", "48");

        Assert.Contains("rotated", output);
        Assert.DoesNotContain(_m.Get("api-token"), output);
        var after = ReadRecord(_m, _vaultKey, "api-token");
        Assert.Equal(48, Encoding.UTF8.GetString(after.Value).Length);
        Assert.True(after.Version.CompareTo(before.Version) > 0);
        Assert.Equal(RecordType.Value, after.Type);
        Assert.Null(after.OutstandingBurn);
        var history = Assert.Single(after.Burns);
        Assert.Equal("pasted in chat", history.Reason);
        Assert.Equal(before.Version, history.Version);

        Assert.DoesNotContain("[BURNED]", _m.Ok("", "names"));
        var burned = _m.Ok("", "burned");
        Assert.Contains("api-token", burned);
        Assert.Contains("pasted in chat", burned);
        Assert.Contains("rotated", burned.ToLowerInvariant());
        Assert.DoesNotContain("Burned Secrets (1)", burned);

        using var json = JsonDocument.Parse(_m.Ok("", "burned", "--json"));
        var entry = Assert.Single(json.RootElement.EnumerateArray());
        Assert.Equal("rotated", entry.GetProperty("status").GetString());
    }

    [Fact]
    public void IngestRotate_ReplacesTheValueFromStdin()
    {
        _m.Ok("old-value", "ingest", "db-pass");
        _m.Ok("", "burn", "db-pass", "seen");

        var output = _m.Ok("new-value", "ingest", "--rotate", "db-pass");

        Assert.DoesNotContain("new-value", output);
        Assert.Equal("new-value", _m.Get("db-pass"));
        Assert.Equal("seen", Assert.Single(ReadRecord(_m, _vaultKey, "db-pass").Burns).Reason);
    }

    [Fact]
    public void CreateAndIngest_OnAnExistingName_RefuseAndPointToRotate()
    {
        _m.Ok("v", "ingest", "taken");

        var create = _m.Run("", "create", "taken");
        var ingest = _m.Run("other", "ingest", "taken");

        Assert.NotEqual(0, create.Exit);
        Assert.Contains("rotate", create.Err);
        Assert.DoesNotContain("delete' first", create.Err);
        Assert.NotEqual(0, ingest.Exit);
        Assert.Contains("ingest --rotate", ingest.Err);
        Assert.Equal("v", _m.Get("taken"));
    }

    [Fact]
    public void WithoutSudo_RotatingABurnedSecretWorks_AnUnburnedOneRefuses_NothingWritten()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (Windows CI runs elevated; see SlotCommandTests)
        _m.Ok("v1", "ingest", "burned-one");
        _m.Ok("v2", "ingest", "clean-one");
        _m.Ok("", "burn", "burned-one", "seen");
        _m.Sudo = false;
        var before = RecordBytesSnapshot();
        var lastHlc = _m.Config.LastHlc;

        var refused = _m.Run("", "rotate", "clean-one");
        var refusedIngest = _m.Run("v3", "ingest", "--rotate", "clean-one");

        Assert.NotEqual(0, refused.Exit);
        Assert.Contains("requires", refused.Err);
        Assert.NotEqual(0, refusedIngest.Exit);
        Assert.Contains("requires", refusedIngest.Err);
        Assert.Equal(before, RecordBytesSnapshot());
        Assert.Equal(lastHlc, _m.Config.LastHlc);

        _m.Ok("", "rotate", "burned-one");
        _m.Sudo = true;
        Assert.NotEqual("v1", _m.Get("burned-one"));
        Assert.Equal("v2", _m.Get("clean-one"));
    }

    [Fact]
    public void WithSudo_BothBurnedAndUnburnedRotate()
    {
        _m.Ok("v1", "ingest", "burned-one");
        _m.Ok("v2", "ingest", "clean-one");
        _m.Ok("", "burn", "burned-one", "seen");

        _m.Ok("", "rotate", "burned-one");
        _m.Ok("v3", "ingest", "--rotate", "clean-one");

        Assert.NotEqual("v1", _m.Get("burned-one"));
        Assert.Equal("v3", _m.Get("clean-one"));
    }

    [Fact]
    public void Rotate_AMissingName_Refuses()
    {
        var rotate = _m.Run("", "rotate", "nope");
        var ingest = _m.Run("x", "ingest", "--rotate", "nope");

        Assert.NotEqual(0, rotate.Exit);
        Assert.Contains("not found", rotate.Err);
        Assert.NotEqual(0, ingest.Exit);
        Assert.Contains("not found", ingest.Err);
        Assert.Empty(_m.RecordFiles);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IngestRotate_WithTheSameValue_StillWritesANewVersion(bool burned)
    {
        // Fix round 1 (A7): a rotation always writes a new version; a burn of the old one is history.
        _m.Ok("same", "ingest", "s");
        if (burned)
            _m.Ok("", "burn", "s", "seen");
        var before = ReadRecord(_m, _vaultKey, "s");

        _m.Ok("same", "ingest", "--rotate", "s");

        var after = ReadRecord(_m, _vaultKey, "s");
        Assert.True(after.Version.CompareTo(before.Version) > 0);
        Assert.Null(after.OutstandingBurn);
        Assert.Equal(burned ? 1 : 0, after.Burns.Count);
        Assert.DoesNotContain("[BURNED]", _m.Ok("", "names"));
    }

    [Fact]
    public void ARotationThatHappensToDrawTheSameValue_StillWritesANewVersion()
    {
        // What 'rotate' hands the store: the existing secret marked as rotated.
        _m.Ok("same", "ingest", "s");
        _m.Ok("", "burn", "s", "seen");
        var before = ReadRecord(_m, _vaultKey, "s");
        var store = new RecordVaultStore(_m.Dir);
        store.LoadConfig();
        var db = store.LoadSecrets(_vaultKey);
        db.Secrets["s"] = db.Secrets["s"] with { BurnedAt = null, BurnReason = null, Rotated = true };

        store.SaveSecrets(db, _vaultKey);

        var after = ReadRecord(_m, _vaultKey, "s");
        Assert.True(after.Version.CompareTo(before.Version) > 0);
        Assert.Equal(RecordType.Value, after.Type);
    }

    [Fact]
    public void Rotate_ASecretBurnedTwice_KeepsBothIncidents()
    {
        _m.Ok("v1", "ingest", "s");
        _m.Ok("", "burn", "s", "first leak");
        _m.Ok("", "rotate", "s");
        _m.Ok("", "burn", "s", "second leak");
        _m.Ok("", "rotate", "s");

        var burned = _m.Ok("", "burned");
        Assert.Contains("first leak", burned);
        Assert.Contains("second leak", burned);
        Assert.Equal(2, ReadRecord(_m, _vaultKey, "s").Burns.Count);
    }
}

/// <summary>
/// Brief T6 decision 7 on the classic single-file store: <c>rotate</c> works for unburned secrets
/// (sudo); a burned secret is refused with a pointer to <c>migrate --to-records</c>, because the
/// classic format has one burn field and no history and #35 forbids overwriting an incident record.
/// </summary>
public sealed class RotateClassicStoreTests : IDisposable
{
    private readonly FleetMachine _m = new("rotate-classic", SimulatedYubiKeyService.WithKeys(SerialA));

    public RotateClassicStoreTests() => _m.Ok("", "init", "--keyring");

    public void Dispose() => _m.Dispose();

    [Fact]
    public void Rotate_AnUnburnedSecret_ReplacesItsValue()
    {
        _m.Ok("old", "ingest", "s");

        _m.Ok("", "rotate", "s", "20");
        _m.Ok("newer", "ingest", "--rotate", "s");

        Assert.Equal("newer", _m.Get("s"));
    }

    [Fact]
    public void Rotate_AnUnburnedSecret_WithoutSudo_Refuses()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (Windows CI runs elevated; see SlotCommandTests)
        _m.Ok("old", "ingest", "s");
        _m.Sudo = false;

        Assert.Contains("requires", _m.Run("", "rotate", "s").Err);
        _m.Sudo = true;
        Assert.Equal("old", _m.Get("s"));
    }

    [Fact]
    public void Rotate_ABurnedSecret_IsRefused_PointingToMigrate_AndTheIncidentIsKept()
    {
        _m.Ok("old", "ingest", "s");
        _m.Ok("", "burn", "s", "seen");
        var before = File.ReadAllBytes(_m.SecretsPath);

        var rotate = _m.Run("", "rotate", "s");
        var ingest = _m.Run("new", "ingest", "--rotate", "s");

        Assert.NotEqual(0, rotate.Exit);
        Assert.Contains("migrate --to-records", rotate.Err);
        Assert.NotEqual(0, ingest.Exit);
        Assert.Contains("migrate --to-records", ingest.Err);
        Assert.Equal(before, File.ReadAllBytes(_m.SecretsPath));
        Assert.Contains("seen", _m.Ok("", "burned"));
    }
}
