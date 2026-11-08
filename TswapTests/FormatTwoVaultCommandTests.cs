using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>Brief T16-S2 task 9: <c>get</c> and <c>apply</c> decrypt exactly the value versions they print or substitute.</summary>
public sealed class SelectiveValueCommandTests : IDisposable
{
    private readonly FleetMachine _m = new("selective-cmd", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly byte[] _key;

    public SelectiveValueCommandTests()
    {
        _key = VaultKey(_m, InitRecordVault(_m));
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
    }

    public void Dispose() => _m.Dispose();

    private string FileName(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private RecordMetadata Metadata(string name) =>
        Store(_m).LoadMetadata(_key, TextWriter.Null).Records.Single(r => r.Name == name);

    [Fact]
    public void Get_DecryptsOnlyItsCurrentValue()
    {
        _m.Ok("old-value", "ingest", "s");
        _m.Ok("new-value", "ingest", "--rotate", "s");
        _m.Ok("other-value", "ingest", "t");
        _values.Clear();

        var (exit, stdout, stderr) = _m.Run("", "get", "s");

        Assert.Equal(0, exit);
        Assert.Equal("new-value", stdout.Trim());
        Assert.Equal("", stderr);
        Assert.Equal([(FileName("s"), Metadata("s").Version)], _values);
    }

    [Fact]
    public void Apply_DecryptsOnlyItsMarkers()
    {
        _m.Ok("a-value", "ingest", "a");
        _m.Ok("b-old", "ingest", "b");
        _m.Ok("b-new", "ingest", "--rotate", "b");
        _m.Ok("c-value", "ingest", "c");
        _m.Ok("unrelated-value", "ingest", "unrelated");
        var file = _m.PathOf("t.yaml");
        File.WriteAllText(file, "x: \"\"  # tswap: a\ny: \"\"  # tswap: b:previous\nz: \"\"  # tswap: a\nw: \"filled\"  # tswap: c\n");
        _values.Clear();

        var (exit, stdout, stderr) = _m.Run("", "apply", file);

        Assert.Equal(0, exit);
        Assert.Equal("x: \"a-value\"  # tswap: a\ny: \"b-old\"  # tswap: b:previous\nz: \"a-value\"  # tswap: a\nw: \"filled\"  # tswap: c\n", stdout);
        Assert.Contains("already populated", stderr);
        Assert.Equal(
            new[] { (FileName("a"), Metadata("a").Version), (FileName("b"), Metadata("b").PreviousVersion!) }.Order(),
            _values.Order());
    }

    /// <summary>
    /// Code review (MiMo A I-1): a format 3 record whose conflicted copy is garbage is no format 2
    /// record: get decrypts only its current value and prints no format 2 warning.
    /// </summary>
    [Fact]
    public void Get_FormatThreeRecordWithAGarbageCopy_NoFormatTwoWarning_OneValue()
    {
        _m.Ok("old-value", "ingest", "s");
        _m.Ok("new-value", "ingest", "--rotate", "s");
        File.WriteAllBytes(RecordFile(_m, _key, "s") + " (1)", [1, 2, 3, 4, 3, 7, 7, 7, 7, 7]);
        _values.Clear();

        var (exit, stdout, stderr) = _m.Run("", "get", "s");

        Assert.Equal(0, exit);
        Assert.Equal("new-value", stdout.Trim());
        Assert.DoesNotContain("format 2", stderr);
        Assert.Contains("can't be used", stderr);
        Assert.Equal([(FileName("s"), Metadata("s").Version)], _values);
    }

    /// <summary>
    /// Code review (GLM A-2): get still takes a name only. "x:previous" is refused by the name check
    /// before the vault is opened, as before, so get never prints a previous value.
    /// </summary>
    [Fact]
    public void Get_PreviousToken_RefusedAsAnInvalidName()
    {
        _m.Ok("old-value", "ingest", "s");
        _m.Ok("new-value", "ingest", "--rotate", "s");
        _values.Clear();

        var (exit, stdout, stderr) = _m.Run("", "get", "s:previous");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains("Invalid secret name", stderr);
        Assert.Empty(_values);
    }

    [Fact]
    public void Apply_UnrelatedUnreadableRecord_NotReported()
    {
        _m.Ok("a-value", "ingest", "a");
        _m.Ok("d-value", "ingest", "d");
        var damaged = RecordFile(_m, _key, "d");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);
        var file = _m.PathOf("t.yaml");
        File.WriteAllText(file, "x: \"\"  # tswap: a\n");

        var (exit, stdout, stderr) = _m.Run("", "apply", file);

        Assert.Equal(0, exit);
        Assert.Equal("x: \"a-value\"  # tswap: a\n", stdout);
        Assert.Equal("", stderr);
        Assert.Contains(Path.GetFileName(damaged), _m.Run("", "names").Err); // control: the damage is there
    }
}

/// <summary>
/// Brief T16-S2 task 9: every reading command on a vault with format 2 records (owner decision 1:
/// "keep working with warning"). Each decodes only the format 2 records it needs, prints the format 2
/// warning once with their count (never a name, file name or value), and otherwise behaves as
/// before; a format 3 record on the same vault is never decrypted by the reading commands.
/// </summary>
public sealed class FormatTwoVaultCommandTests : IDisposable
{
    private static readonly string Fix = OperatingSystem.IsWindows()
        ? "`tswap vault reindex` (from an elevated command prompt)"
        : "`sudo tswap vault reindex`";

    private readonly FleetMachine _m = new("v2-cmd", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly byte[] _key;

    public FormatTwoVaultCommandTests()
    {
        _key = VaultKey(_m, InitFormatTwoVault(_m));
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
    }

    public void Dispose() => _m.Dispose();

    private string FileName(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private static string ReadWarning(int n) =>
        $"Warning: {n} record(s) are stored in the old record format 2, which keeps a secret's name and value in one " +
        "encrypted block, so tswap decrypted them whole to read their names and burn state and wiped the values without " +
        $"using them. Ask the user to run {Fix} once to convert the vault.";

    private static string UseWarning(int n) =>
        $"Warning: {n} of the records used here are stored in the old record format 2, which tswap can only decrypt " +
        $"whole; the value versions not used were wiped. Ask the user to run {Fix} once to convert the vault.";

    private static string[] Lines(string text) => text.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>Format 2: alpha, beta (burned), gamma (deleted); then the marker, and delta in format 3.</summary>
    private void Vault()
    {
        _m.Ok("alpha-value", "ingest", "alpha");
        _m.Ok("beta-value", "ingest", "beta");
        _m.Ok("", "burn", "beta", "seen");
        _m.Ok("gamma-value", "ingest", "gamma");
        _m.Ok("", "delete", "gamma");
        WriteMarker(_m);
        _m.Ok("delta-value", "ingest", "delta");
        Assert.Equal(3, Store(_m).LoadMetadata(_key, TextWriter.Null).NotFingerprinted);
        _values.Clear();
    }

    private void AssertOnlyFormatTwoDecrypted(params string[] names)
    {
        Assert.NotEmpty(_values);
        Assert.All(_values, v => Assert.Contains(v.File, names.Select(FileName)));
        Assert.DoesNotContain(_values, v => v.File == FileName("delta"));
    }

    [Theory]
    [InlineData("names")]
    [InlineData("list")]
    [InlineData("burned")]
    public void ReadingCommands_ListEverySecret_WarnOnceWithTheCount(string command)
    {
        Vault();

        var (exit, stdout, stderr) = _m.Run("", command);

        Assert.Equal(0, exit);
        if (command == "burned")
        {
            Assert.Contains("beta", stdout);
            Assert.DoesNotContain("alpha", stdout);
        }
        else
        {
            Assert.All(new[] { "alpha", "beta", "delta" }, n => Assert.Contains(n, stdout));
            Assert.DoesNotContain("gamma", stdout);
        }
        Assert.Equal([ReadWarning(3)], Lines(stderr));
        AssertOnlyFormatTwoDecrypted("alpha", "beta");
    }

    [Fact]
    public void Check_MarkerOnAFormatTwoRecord_ResolvesAndWarns()
    {
        Vault();
        var file = _m.PathOf("v.yaml");
        File.WriteAllText(file, "a: \"\"  # tswap: alpha\nd: \"\"  # tswap: delta\n");

        var (exit, stdout, stderr) = _m.Run("", "check", file);

        Assert.Equal(0, exit);
        Assert.Contains("✓ alpha (line 1)", stdout);
        Assert.Contains("✓ delta (line 2)", stdout);
        Assert.Equal([ReadWarning(1)], Lines(stderr));
        AssertOnlyFormatTwoDecrypted("alpha");
    }

    [Fact]
    public void Check_UnnamedUnreadableFormatTwoRecord_NoLongerStops()
    {
        Vault();
        var damaged = RecordFile(_m, _key, "beta");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);
        var file = _m.PathOf("v.yaml");
        File.WriteAllText(file, "d: \"\"  # tswap: delta\n");

        var (exit, stdout, stderr) = _m.Run("", "check", file);

        Assert.Equal(0, exit);
        Assert.Contains("✓ delta (line 1)", stdout);
        Assert.Equal("", stderr);
        Assert.Empty(_values);
    }

    [Fact]
    public void Get_FormatTwoRecord_ReturnsTheValueAndWarns()
    {
        Vault();

        var (exit, stdout, stderr) = _m.Run("", "get", "alpha");

        Assert.Equal(0, exit);
        Assert.Equal("alpha-value", stdout.Trim());
        Assert.Equal([UseWarning(1)], Lines(stderr));
        AssertOnlyFormatTwoDecrypted("alpha");
    }

    [Fact]
    public void Apply_FormatTwoRecord_FillsAndWarns()
    {
        Vault();
        var file = _m.PathOf("t.yaml");
        File.WriteAllText(file, "a: \"\"  # tswap: alpha\nd: \"\"  # tswap: delta\n");

        var (exit, stdout, stderr) = _m.Run("", "apply", file);

        Assert.Equal(0, exit);
        Assert.Equal("a: \"alpha-value\"  # tswap: alpha\nd: \"delta-value\"  # tswap: delta\n", stdout);
        Assert.Equal([UseWarning(1)], Lines(stderr));
        // Code review (GLM B-3, MiMo B-M1): exactly its two markers' records: alpha decoded whole (one
        // version), delta's current section; nothing of beta or gamma.
        Assert.Equal(new[] { FileName("alpha"), FileName("delta") }.Order(StringComparer.Ordinal),
            _values.Select(v => v.File).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void List_UnreadableFormatTwoRecord_Refuses_NamingTheFile()
    {
        Vault();
        var damaged = RecordFile(_m, _key, "alpha");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);

        var (exit, stdout, stderr) = _m.Run("", "list");

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("beta", stdout);
        Assert.Contains(Path.GetFileName(damaged), stderr);
        Assert.Contains("'list' covers every secret", stderr);
    }

    [Fact]
    public void Names_UnreadableFormatTwoRecord_Warns()
    {
        Vault();
        var damaged = RecordFile(_m, _key, "alpha");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.DoesNotContain("alpha", stdout);
        Assert.Contains("beta", stdout);
        Assert.Contains("delta", stdout);
        Assert.Contains(Path.GetFileName(damaged), stderr);
        Assert.Contains("1 unreadable record", stderr);
        // Code review (GLM B-2): the warning counts the records actually decrypted whole (beta and
        // gamma's tombstone), not the one that failed to decrypt.
        Assert.Contains(ReadWarning(2), Lines(stderr));
    }

    /// <summary>The format 2 counterpart of <c>RecordConflictTests.ATruncatedMainRecord_FailsClosed</c>.</summary>
    [Fact]
    public void ATruncatedFormatTwoMainRecord_GetAndApplyFailNamingTheFile()
    {
        Vault();
        var damaged = RecordFile(_m, _key, "alpha");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);
        var fileName = Path.GetFileName(damaged);
        var template = _m.PathOf("t.yaml");
        File.WriteAllText(template, "a: \"\"  # tswap: alpha\n");

        var (getExit, _, getErr) = _m.Run("", "get", "alpha");
        var (applyExit, _, applyErr) = _m.Run("", "apply", template);

        Assert.NotEqual(0, getExit);
        Assert.Contains(fileName, getErr);
        Assert.NotEqual(0, applyExit);
        Assert.Contains(fileName, applyErr);
    }

    // ------------------------------------------------------------------ code review

    /// <summary>
    /// Code review (MiMo A M-3): a command that decoded format 2 records and then fails still says so
    /// (owner decision 1), before its error.
    /// </summary>
    [Fact]
    public void List_RefusingAfterDecodingFormatTwoRecords_StillWarns()
    {
        Vault();
        var damaged = RecordFile(_m, _key, "delta"); // the format 3 one
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);

        var (exit, _, stderr) = _m.Run("", "list");

        Assert.NotEqual(0, exit);
        Assert.Contains("'list' covers every secret", stderr);
        Assert.Contains(ReadWarning(3), Lines(stderr));
    }

    [Fact]
    public void Apply_FailingAfterUsingAFormatTwoRecord_StillWarns()
    {
        Vault();
        var file = _m.PathOf("t.yaml");
        File.WriteAllText(file, "a: \"\"  # tswap: alpha\nm: \"\"  # tswap: missing\n");

        var (exit, stdout, stderr) = _m.Run("", "apply", file);

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains("not found", stderr);
        Assert.Contains(UseWarning(1), Lines(stderr));
    }

    /// <summary>
    /// Code review (GLM A-4, MiMo A M-2), the reason two records can never claim one name: the codec
    /// binds a record's name to its record id in format 2 as in format 3, and the store binds the id
    /// to the file. A planted format 2 record whose name belongs to another record is unreadable on the
    /// metadata path exactly as in the full load: names warns and lists the name once, list refuses.
    /// </summary>
    [Fact]
    public void AFormatTwoRecordClaimingAnotherName_IsUnreadable_NeverADuplicate()
    {
        Vault();
        var alpha = ReadRecordFormatTwo("alpha");
        var impostor = RecordFile(_m, _key, "impostor");
        var otherId = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), "impostor");
        File.WriteAllBytes(impostor, SecretRecordCodec.Encode(alpha with { RecordId = otherId }, _key, KeyringFormat.RecordFormatVersionV2));
        var full = Store(_m).LoadSecrets(_key, TextWriter.Null);
        Assert.Contains(Path.GetFileName(impostor), full.UnreadableFiles!);

        var (exit, stdout, stderr) = _m.Run("", "names");
        var list = _m.Run("", "list");

        Assert.Equal(0, exit);
        Assert.Single(Lines(stdout), l => l.StartsWith("alpha ", StringComparison.Ordinal));
        Assert.Contains("its record id does not belong to the name inside it", stderr);
        Assert.NotEqual(0, list.Exit);
        Assert.Contains(Path.GetFileName(impostor), list.Err);
    }

    private SecretRecord ReadRecordFormatTwo(string name) =>
        SecretRecordCodec.Decode(File.ReadAllBytes(RecordFile(_m, _key, name)), _key);
}
