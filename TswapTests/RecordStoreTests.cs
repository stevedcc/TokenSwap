using System.Text;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 1 (decisions 1, 3, 6): the per-secret record store on one machine, through the
/// CLI. The composition root picks <see cref="RecordVaultStore"/> from <c>"Store": "records"</c>;
/// commands are unchanged.
/// </summary>
public sealed class RecordStoreTests : IDisposable
{
    private readonly FleetMachine _m = new("records", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly string _recoveryKey;
    private readonly byte[] _vaultKey;

    public RecordStoreTests()
    {
        _recoveryKey = InitRecordVault(_m);
        _vaultKey = VaultKey(_m, _recoveryKey);
    }

    public void Dispose() => _m.Dispose();

    [Fact]
    public void TheCompositionRoot_PicksTheRecordStore_FromTheStoreField()
    {
        Assert.IsType<RecordVaultStore>(VaultStores.Open(_m.Dir));

        using var classic = new FleetMachine("classic", SimulatedYubiKeyService.WithKeys(SerialA));
        classic.Ok("", "init", "--keyring");
        Assert.IsType<Storage>(VaultStores.Open(classic.Dir));
    }

    [Fact]
    public void CreateIngestGetApplyNames_RoundTripThroughRecords()
    {
        _m.Ok("", "create", "generated", "40");
        _m.Ok("piped-value", "ingest", "piped");

        Assert.Equal("piped-value", _m.Get("piped"));
        Assert.Equal(40, _m.Get("generated").Length);

        var template = Path.Combine(_m.Dir, "values.yaml");
        File.WriteAllText(template, "password: \"\" # tswap: piped\n");
        Assert.Contains("password: \"piped-value\"", _m.Ok("", "apply", template));

        var names = _m.Ok("", "names");
        Assert.Contains("generated", names);
        Assert.Contains("piped", names);
        Assert.False(File.Exists(_m.SecretsPath));
        Assert.Equal(2, _m.RecordFiles.Length);
    }

    [Fact]
    public void Burn_WritesABurnedRecord_NamesAndBurnedShowIt()
    {
        _m.Ok("value-1", "ingest", "token");
        _m.Ok("", "burn", "token", "seen in a log");

        var record = ReadRecord(_m, _vaultKey, "token");
        Assert.Equal(RecordType.Burned, record.Type);
        Assert.Equal("value-1", Encoding.UTF8.GetString(record.Value));
        Assert.Equal("seen in a log", record.OutstandingBurn!.Reason);
        Assert.Contains("token", _m.Ok("", "names").Split('\n').Single(l => l.Contains("[BURNED]")));
        Assert.Contains("seen in a log", _m.Ok("", "burned"));
        // A second burn is refused (#35), and the incident record is unchanged.
        Assert.NotEqual(0, _m.Run("", "burn", "token", "again").Exit);
        Assert.Equal("seen in a log", ReadRecord(_m, _vaultKey, "token").OutstandingBurn!.Reason);
    }

    [Fact]
    public void Delete_WritesATombstone_NotAnAbsentFile()
    {
        _m.Ok("value-1", "ingest", "doomed");
        var file = RecordFile(_m, _vaultKey, "doomed");
        var sizeBefore = new FileInfo(file).Length;

        _m.Ok("", "delete", "doomed");

        Assert.True(File.Exists(file));
        var record = ReadRecord(_m, _vaultKey, "doomed");
        Assert.Equal(RecordType.Tombstone, record.Type);
        Assert.Empty(record.Value);
        Assert.Equal(sizeBefore, new FileInfo(file).Length);
        Assert.Equal(1, _m.Run("", "get", "doomed").Exit);
        Assert.Contains("No secrets", _m.Ok("", "names"));
        // The name can be used again: a new value after the delete.
        _m.Ok("value-2", "ingest", "doomed");
        Assert.Equal("value-2", _m.Get("doomed"));
    }

    [Fact]
    public void OneFilePerSecret_NoPlaintextNameOrValueOnDisk()
    {
        _m.Ok("plain-value-marker", "ingest", "plain-name-marker");
        _m.Ok("other-value-marker", "ingest", "other-name-marker");
        _m.Ok("", "burn", "other-name-marker", "reason-marker");

        var files = _m.RecordFiles;
        Assert.Equal(2, files.Length);
        Assert.All(files, f => Assert.Matches("^[0-9a-f]{64}$", f));
        foreach (var path in Directory.GetFiles(_m.VaultDir!, "*", SearchOption.AllDirectories).Append(_m.ConfigPath))
        {
            var text = Encoding.Latin1.GetString(File.ReadAllBytes(path));
            foreach (var marker in new[] { "plain-name-marker", "plain-value-marker", "other-name-marker", "other-value-marker", "reason-marker" })
                Assert.DoesNotContain(marker, text);
            Assert.DoesNotContain("marker", Path.GetFileName(path));
        }
    }

    [Fact]
    public void ValuesInOneSizeBucket_GiveTheSameFileSize_OneBytePastIt_TheNextBucket()
    {
        // Inner payload for a one-letter name: 39 fixed + 1 (name) + 4 + value + 1 (burn count)
        // = 45 + value bytes, padded to 256-byte buckets.
        _m.Ok("x", "ingest", "a");
        _m.Ok(new string('y', 256 - 45), "ingest", "b");
        _m.Ok(new string('z', 256 - 45 + 1), "ingest", "c");

        long Size(string name) => new FileInfo(RecordFile(_m, _vaultKey, name)).Length;
        Assert.Equal(Size("a"), Size("b"));
        Assert.Equal(Size("b") + 256, Size("c"));
    }

    [Fact]
    public void EveryWrite_MovesTheClockForward_AndSavesLastHlc()
    {
        var now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
        _m.Clock = () => now;
        _m.Ok("v", "ingest", "s1");
        var first = ReadRecord(_m, _vaultKey, "s1");

        Assert.Equal(new Hlc(1_800_000_000_000, 0), first.Version.Hlc);
        Assert.True(first.Write.Hlc > first.Version.Hlc);
        Assert.Equal(first.Write.Hlc, Hlc.TryParse(_m.Config.LastHlc));
        Assert.Equal(Convert.FromBase64String(_m.Config.OriginId!), first.Write.Origin);
    }
}
