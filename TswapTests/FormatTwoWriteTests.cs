using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 9: every write of a format 2 record decodes that record whole (the only way to
/// read format 2), nothing else, and says so with the count-only warning. On a folder without the
/// marker it writes format 2, so older machines keep reading it; once the folder is marked it
/// converts that record to format 3 and leaves every other format 2 record as it is.
/// </summary>
public sealed class FormatTwoWriteTests : IDisposable
{
    private readonly FleetMachine _m = new("format-two-write", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _key;
    private readonly List<(string File, Stamp Version)> _values = [];

    public FormatTwoWriteTests()
    {
        _key = VaultKey(_m, InitFormatTwoVault(_m));
        _m.Ok("target-1", "ingest", "target");
        _m.Ok("target-2", "ingest", "--rotate", "target");
        _m.Ok("other-1", "ingest", "other");
        _m.Ok("gone-1", "ingest", "gone");
        _m.Ok("", "delete", "gone");
    }

    public void Dispose() => _m.Dispose();

    private string FileOf(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private byte FormatOf(string name) => File.ReadAllBytes(RecordFile(_m, _key, name))[4];

    private static string Warning(int count) =>
        $"Warning: {count} of the records read here were stored in the old record format 2, which tswap can only decrypt whole; the value " +
        $"versions not needed were wiped. Ask the user to run {ElevatedCommand.For("tswap", "vault reindex")} once to convert the vault.";

    public static TheoryData<string, string[]> Writes() => new()
    {
        { "", ["burn", "target", "seen"] },
        { "", ["rotate", "target"] },
        { "", ["delete", "target"] },
        { "", ["restore", "target"] },
        { "target-new\ntarget-new\n", ["add", "target"] },
        { "target-ingested", ["ingest", "--rotate", "target"] },
    };

    private (string Err, Dictionary<string, byte[]> Others) RunWatched(string stdin, string[] args)
    {
        var others = new[] { "other", "gone" }.ToDictionary(n => n, n => File.ReadAllBytes(RecordFile(_m, _key, n)));
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
        var (exit, _, err) = _m.Run(stdin, args);
        _m.StoreOpened = null;
        Assert.True(exit == 0, $"{string.Join(' ', args)}: {err}");
        return (err, others);
    }

    [Theory]
    [MemberData(nameof(Writes))]
    public void Write_OfAFormatTwoRecord_DecodesOnlyIt_WritesFormatTwo_AndWarns(string stdin, string[] args)
    {
        var (err, others) = RunWatched(stdin, args);

        Assert.NotEmpty(_values);
        Assert.All(_values, v => Assert.Equal(FileOf("target"), v.File));
        Assert.Equal(KeyringFormat.RecordFormatVersionV2, FormatOf("target"));
        Assert.Contains(Warning(1), err);
        foreach (var (name, bytes) in others)
            Assert.Equal(bytes, File.ReadAllBytes(RecordFile(_m, _key, name)));
    }

    [Theory]
    [MemberData(nameof(Writes))]
    public void Write_AfterTheMarker_ConvertsThatRecordOnly(string stdin, string[] args)
    {
        WriteMarker(_m);

        var (err, others) = RunWatched(stdin, args);

        Assert.All(_values, v => Assert.Equal(FileOf("target"), v.File));
        Assert.Equal(KeyringFormat.RecordFormatVersion, FormatOf("target"));
        Assert.Contains(Warning(1), err);
        foreach (var (name, bytes) in others)
        {
            Assert.Equal(bytes, File.ReadAllBytes(RecordFile(_m, _key, name)));
            Assert.Equal(KeyringFormat.RecordFormatVersionV2, FormatOf(name));
        }
        var written = ReadRecord(_m, _key, "target");
        if (written.Type != RecordType.Tombstone)
            Assert.Equal(Fingerprints(_key, written.Value), written.Fingerprints);
    }

    [Fact]
    public void Create_ExistingFormatTwoName_DecodesItToRefuse_AndWarns()
    {
        var before = File.ReadAllBytes(RecordFile(_m, _key, "target"));
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));

        var (exit, _, err) = _m.Run("", "create", "target");

        Assert.Equal(1, exit);
        Assert.Contains("Secret 'target' already exists", err);
        Assert.Contains(Warning(1), err);
        Assert.All(_values, v => Assert.Equal(FileOf("target"), v.File));
        Assert.NotEmpty(_values);
        Assert.Equal(before, File.ReadAllBytes(RecordFile(_m, _key, "target")));
    }

    /// <summary>The warning carries a count only: never the name of a live or deleted secret, a value or a hashed file name.</summary>
    [Fact]
    public void Warning_NamesNothing()
    {
        var (err, _) = RunWatched("", ["delete", "target"]);

        foreach (var leak in new[] { "target", "gone", FileOf("target"), FileOf("gone"), "target-2", "gone-1" })
            Assert.DoesNotContain(leak, err.Replace(Warning(1), "", StringComparison.Ordinal));
        Assert.Contains(Warning(1), err);
        Assert.DoesNotContain("target", Warning(1));
    }

    /// <summary>
    /// Code review (MiMo C I-1): import looks at every exported name the vault already holds, to skip
    /// it. A live format 2 one can only be read whole, so it is decoded (and counted in the warning)
    /// although nothing of it is written; it is skipped, never written over.
    /// </summary>
    [Fact]
    public void Import_SkippedFormatTwoName_IsDecodedToSkip_AndWarns_WritesNothingOfIt()
    {
        using var source = new FleetMachine("format-two-write-export", SimulatedYubiKeyService.WithKeys(SerialA));
        InitRecordVault(source);
        source.Ok("exported-target", "ingest", "target");
        source.Ok("exported-new", "ingest", "fresh");
        var export = _m.PathOf("export.json");
        source.Ok("pass\npass\n", "export", export);
        var target = File.ReadAllBytes(RecordFile(_m, _key, "target"));

        var (err, others) = RunWatched("pass\n", ["import", export]);

        Assert.Equal(target, File.ReadAllBytes(RecordFile(_m, _key, "target")));
        Assert.Equal("target-2", _m.Get("target"));
        Assert.Equal("exported-new", _m.Get("fresh"));
        Assert.NotEmpty(_values);
        Assert.All(_values, v => Assert.Equal(FileOf("target"), v.File));
        Assert.Contains(Warning(1), err);
        foreach (var (name, bytes) in others)
            Assert.Equal(bytes, File.ReadAllBytes(RecordFile(_m, _key, name)));
    }
}
