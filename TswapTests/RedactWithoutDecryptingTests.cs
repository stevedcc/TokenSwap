using System.Text;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 7: <c>redact</c> and <c>tocomment</c> read metadata sections only and recognise
/// secrets by their fingerprints: no value is decrypted (the store's <c>ValueDecrypted</c> seam
/// stays empty while <c>RecordDecrypted</c> shows the metadata was read, so the proof can't pass on
/// a command that read nothing). A vault with records lacking fingerprints is refused before the
/// input file is opened.
/// </summary>
public sealed class RedactWithoutDecryptingTests : IDisposable
{
    private static readonly byte[] Origin = Enumerable.Repeat((byte)0x0C, 16).ToArray();
    private static readonly string Fix = OperatingSystem.IsWindows()
        ? "`tswap vault reindex` (from an elevated command prompt)"
        : "`sudo tswap vault reindex`";

    private readonly FleetMachine _m = new("redact-meta", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly List<string> _metadataRead = [];
    private byte[] _key = [];

    public RedactWithoutDecryptingTests()
    {
        _m.StoreOpened = store =>
        {
            store.ValueDecrypted = (file, version) => _values.Add((file, version));
            store.RecordDecrypted = _metadataRead.Add;
        };
    }

    public void Dispose() => _m.Dispose();

    private void InitFormatThree() => _key = VaultKey(_m, InitRecordVault(_m));

    private void InitFormatTwo() => _key = VaultKey(_m, InitFormatTwoVault(_m));

    private string Write(string name, string content)
    {
        var path = _m.PathOf(name);
        File.WriteAllText(path, content);
        return path;
    }

    private void ClearSeams()
    {
        _values.Clear();
        _metadataRead.Clear();
    }

    private static string B64(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private void Plant(string name, string value, Func<SecretRecord, SecretRecord> change)
    {
        Directory.CreateDirectory(_m.RecordsDir);
        var id = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), name);
        var version = new Stamp(new Hlc(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), 0), Origin);
        var record = new SecretRecord(id, version, RecordType.Value, version, name, 1, Encoding.UTF8.GetBytes(value), [])
        {
            Fingerprints = Fingerprints(_key, Encoding.UTF8.GetBytes(value)),
        };
        File.WriteAllBytes(RecordFile(_m, _key, name), SecretRecordCodec.Encode(change(record), _key, KeyringFormat.RecordFormatVersion));
    }

    /// <summary>The refusal as the CLI prints it (every TswapException is "❌ Error: …" on stderr).</summary>
    private string Refusal(string command, int count, bool tocomment = false) =>
        $"❌ Error: '{command}' recognises secrets by their fingerprints, and {count} record(s) in this vault have none yet (written by " +
        $"an older tswap, or the vault was never reindexed). Ask the user to run {Fix}. The file was not read{(tocomment ? " or changed" : "")}.";

    [Fact]
    public void Redact_DecryptsNoValue()
    {
        InitFormatThree();
        _m.Ok("old-db-value", "ingest", "db");
        _m.Ok("new-db-value", "ingest", "--rotate", "db");
        _m.Ok("api-token-77", "ingest", "api");
        var file = Write("log.txt", $"now new-db-value\nthen old-db-value\nencoded {B64("api-token-77")}\n");
        ClearSeams();

        var (exit, stdout, stderr) = _m.Run("", "redact", file);

        Assert.Equal(0, exit);
        Assert.Equal("now [REDACTED: db]\nthen [REDACTED: db:previous]\nencoded [REDACTED: api (base64)]\n", stdout);
        Assert.Equal("", stderr);
        Assert.Empty(_values);
        Assert.NotEmpty(_metadataRead);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ToComment_DecryptsNoValue(bool dryRun)
    {
        InitFormatThree();
        _m.Ok("old-db-value", "ingest", "db");
        _m.Ok("new-db-value", "ingest", "--rotate", "db");
        _m.Ok("api-token-77", "ingest", "api");
        var content = $"a: new-db-value\nb: \"old-db-value\"\nc: {B64("api-token-77")}\n";
        var file = Write("values.yaml", content);
        ClearSeams();

        var (exit, stdout, stderr) = dryRun ? _m.Run("", "tocomment", file, "--dry-run") : _m.Run("", "tocomment", file);

        Assert.Equal(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains($"  - c: [REDACTED: api (base64)]", stderr);
        Assert.Contains("  - b: \"[REDACTED: db:previous]\"", stderr);
        Assert.DoesNotContain("db-value", stderr);
        Assert.Equal(
            dryRun ? content : "a: \"\"  # tswap: db\nb: \"\"  # tswap: db:previous\nc: \"\"  # tswap: api\n",
            File.ReadAllText(file));
        Assert.Empty(_values);
        Assert.NotEmpty(_metadataRead);
    }

    [Fact]
    public void Redact_FormatTwoRecord_Refuses()
    {
        InitFormatTwo();
        _m.Ok("legacy-value-1", "ingest", "legacy");
        var file = Write("log.txt", "legacy-value-1\n");
        ClearSeams();

        var (exit, stdout, stderr) = _m.Run("", "redact", file);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains("1 record(s)", stderr);
        Assert.Contains(Fix, stderr);
        Assert.DoesNotContain("legacy", stderr);
        Assert.Empty(_values);
    }

    [Fact]
    public void ToComment_FormatTwoRecord_RefusesFileUnchanged()
    {
        InitFormatTwo();
        _m.Ok("legacy-value-1", "ingest", "legacy");
        var file = Write("values.yaml", "pw: legacy-value-1\n");
        ClearSeams();

        var (exit, stdout, stderr) = _m.Run("", "tocomment", file);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(Refusal("tocomment", 1, tocomment: true), stderr.Trim());
        Assert.Equal("pw: legacy-value-1\n", File.ReadAllText(file));
        Assert.Empty(_values);
    }

    [Fact]
    public void Redact_RecordWithoutFingerprints_Refuses()
    {
        InitFormatThree();
        _m.Ok("fine-value-1", "ingest", "fine");
        Plant("bare", "bare-value-1", r => r with { Fingerprints = null });
        var file = Write("log.txt", "bare-value-1 fine-value-1\n");
        ClearSeams();

        var (exit, stdout, stderr) = _m.Run("", "redact", file);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(Refusal("redact", 1), stderr.Trim());
        Assert.Empty(_values);
    }

    [Fact]
    public void Redact_OlderVariantSet_NotesAndMasks()
    {
        InitFormatThree();
        Plant("elder", "elder-value-42", r => r with { Fingerprints = r.Fingerprints! with { VariantSetVersion = 0 } });
        var file = Write("log.txt", "x elder-value-42 y\n");
        ClearSeams();

        var (exit, stdout, stderr) = _m.Run("", "redact", file);

        Assert.Equal(0, exit);
        Assert.Equal("x [REDACTED: elder] y\n", stdout);
        Assert.Equal(
            $"Note: 1 record(s) were fingerprinted by an older tswap and are matched with the fingerprints they have; {Fix} adds the newer variants.",
            stderr.Trim());
        Assert.DoesNotContain("elder", stderr);
        Assert.DoesNotContain(Path.GetFileName(RecordFile(_m, _key, "elder")), stderr);
        Assert.Empty(_values);
    }

    [Fact]
    public void Redact_AfterReindex_Masks()
    {
        InitFormatTwo();
        _m.Ok("legacy-value-1", "ingest", "legacy");
        var file = Write("log.txt", "x legacy-value-1\n");
        Assert.Equal(1, _m.Run("", "redact", file).Exit);

        _m.Ok("", "vault", "reindex");
        ClearSeams();
        var (exit, stdout, _) = _m.Run("", "redact", file);

        Assert.Equal(0, exit);
        Assert.Equal("x [REDACTED: legacy]\n", stdout);
        Assert.Empty(_values);
    }

    [Fact]
    public void Redact_Refusal_DoesNotOpenTheInput()
    {
        if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            return; // mode 000 can't stop an administrator from opening it
        InitFormatTwo();
        _m.Ok("legacy-value-1", "ingest", "legacy");
        var file = Write("log.txt", "legacy-value-1\n");
        File.SetUnixFileMode(file, UnixFileMode.None);
        try
        {
            var (exit, stdout, stderr) = _m.Run("", "redact", file);

            Assert.Equal(1, exit);
            Assert.Equal("", stdout);
            Assert.Equal(Refusal("redact", 1), stderr.Trim()); // no access error: the file was never opened
        }
        finally
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        // Control: on a fingerprinted vault the same file fails on opening it.
        _m.Ok("", "vault", "reindex");
        File.SetUnixFileMode(file, UnixFileMode.None);
        try
        {
            Assert.NotEqual(0, _m.Run("", "redact", file).Exit);
        }
        finally
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [Fact]
    public void Redact_BurnedSecret_StillMasked()
    {
        InitFormatThree();
        _m.Ok("first-value-9", "ingest", "pw");
        _m.Ok("", "burn", "pw", "seen");
        _m.Ok("second-value-9", "ingest", "--rotate", "pw"); // the previous version is burned
        _m.Ok("", "burn", "pw", "seen again");
        var file = Write("log.txt", "a second-value-9 b first-value-9\n");
        ClearSeams();

        var (exit, stdout, _) = _m.Run("", "redact", file);

        Assert.Equal(0, exit);
        Assert.Equal("a [REDACTED: pw] b [REDACTED: pw:previous]\n", stdout);
        Assert.Empty(_values);
    }

    [Fact]
    public void ToComment_BurnedSecret_StillReplaced()
    {
        InitFormatThree();
        _m.Ok("first-value-9", "ingest", "pw");
        _m.Ok("", "burn", "pw", "seen");
        _m.Ok("second-value-9", "ingest", "--rotate", "pw");
        _m.Ok("", "burn", "pw", "seen again");
        var file = Write("values.yaml", "a: second-value-9\nb: first-value-9\n");
        ClearSeams();

        Assert.Equal(0, _m.Run("", "tocomment", file).Exit);

        Assert.Equal("a: \"\"  # tswap: pw\nb: \"\"  # tswap: pw:previous\n", File.ReadAllText(file));
        Assert.Empty(_values);
    }

    [Fact]
    public void Redact_BurnedValueTies_AtCommandLevel()
    {
        InitFormatThree();
        // b-rotated's previous value X was burned; a-burned's current value X is burned. Today's quirk:
        // a name:previous entry counts as live, so it wins although "a-burned" sorts first by name.
        _m.Ok("shared-x-value", "ingest", "b-rotated");
        _m.Ok("", "burn", "b-rotated", "seen");
        _m.Ok("other-value-1", "ingest", "--rotate", "b-rotated");
        _m.Ok("shared-x-value", "ingest", "a-burned");
        _m.Ok("", "burn", "a-burned", "seen");
        // One value under a burned and a live name: the live one wins although the burned sorts first.
        _m.Ok("shared-y-value", "ingest", "c-burned");
        _m.Ok("", "burn", "c-burned", "seen");
        _m.Ok("shared-y-value", "ingest", "d-live");
        var file = Write("log.txt", "x=shared-x-value y=shared-y-value\n");
        ClearSeams();

        var (exit, stdout, _) = _m.Run("", "redact", file);

        Assert.Equal(0, exit);
        Assert.Equal("x=[REDACTED: b-rotated:previous] y=[REDACTED: d-live]\n", stdout);
        Assert.Empty(_values);
    }

    /// <summary>
    /// Difference 12 (owner-accepted): a record whose fingerprints describe another value is masked by
    /// its fingerprints and its stored value passes through; the command that uses the value still
    /// fails closed, naming the file.
    /// </summary>
    [Fact]
    public void Redact_FingerprintValueMismatch_MasksWhatTheFingerprintsDescribe()
    {
        InitFormatThree();
        Plant("liar", "stored-value-B", r => r with { Fingerprints = Fingerprints(_key, Encoding.UTF8.GetBytes("described-value-A")) });
        var file = Write("log.txt", "a=described-value-A b=stored-value-B\n");
        ClearSeams();

        var (exit, stdout, _) = _m.Run("", "redact", file);

        Assert.Equal(0, exit);
        Assert.Equal("a=[REDACTED: liar] b=stored-value-B\n", stdout);
        Assert.Empty(_values);
        var (getExit, _, getErr) = _m.Run("", "get", "liar");
        Assert.NotEqual(0, getExit);
        Assert.Contains(Path.GetFileName(RecordFile(_m, _key, "liar")), getErr);
    }
}
