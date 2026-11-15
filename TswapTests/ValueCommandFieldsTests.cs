using TswapCli.Commands;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Issue #311 task 7 (spec "Setting fields", "Writes", guard rail 1): <c>--field FIELD=VALUE</c> (repeatable),
/// <c>--fields JSON|@FILE</c> and <c>--by LABEL</c> on <c>create</c>, <c>ingest</c>, <c>ingest --rotate</c>, <c>add</c>
/// and <c>rotate</c>: the value and the fields in one record write, all or nothing.
/// </summary>
public sealed class ValueCommandFieldsTests : IDisposable
{
    private const string StoredValue = "Xq7-stored-secret-value-91";

    /// <summary>Every character <c>create</c>/<c>rotate</c> draws from: a field holding it contains any 1-character value they generate.</summary>
    private static readonly string AllGenerated = CreateCommand.Charset;

    private DateTimeOffset _now = new(2026, 11, 15, 16, 42, 7, TimeSpan.Zero);
    private readonly FleetMachine _m;
    private readonly byte[] _key;
    private int _recordsWritten;

    public ValueCommandFieldsTests()
    {
        _m = new FleetMachine("value-command-fields", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
        _m.StoreOpened = store => store.AfterRecordWritten = () => _recordsWritten++;
    }

    public void Dispose() => _m.Dispose();

    private (int Exit, string Out, string Err) Run(string stdin, params string[] args)
    {
        _now = _now.AddSeconds(1);
        _recordsWritten = 0;
        return _m.Run(stdin, args);
    }

    private string Ok(string stdin, params string[] args)
    {
        var (exit, stdout, stderr) = Run(stdin, args);
        Assert.True(exit == 0, $"'{string.Join(' ', args)}' failed: {stderr}\n{stdout}");
        return stdout;
    }

    private SecretRecord Record(string name) => ReadRecord(_m, _key, name);

    private FieldSet FieldsOf(string name) => Assert.IsType<FieldSet>(FieldsCodec.TryGet(Record(name).Extensions));

    private Dictionary<string, string> Live(string name) =>
        FieldsOf(name).Live.ToDictionary(e => e.Name, e => e.Value!, StringComparer.Ordinal);

    private byte[] FieldsBytes(string name) => Record(name).Extensions.Single(e => e.Type == FieldsExtension.Type).Data;

    private bool Exists(string name) => File.Exists(RecordFile(_m, _key, name));

    private byte[] Bytes(string name) => File.ReadAllBytes(RecordFile(_m, _key, name));

    /// <summary>
    /// The value and the fields came from one record write: the last command wrote exactly one record file, and
    /// in it each field change follows the value version and precedes the record's write stamp.
    /// </summary>
    private void AssertOneWrite(string name, params string[] fields)
    {
        Assert.Equal(1, _recordsWritten);
        var record = Record(name);
        var set = FieldsOf(name);
        foreach (var field in fields)
        {
            var changed = set.Get(field)!.Changed;
            Assert.True(changed.CompareTo(record.Version) > 0, $"{field} changed at {changed}, not after the version {record.Version}");
            Assert.True(record.Write.CompareTo(changed) > 0, $"{field} changed at {changed}, not before the write {record.Write}");
        }
    }

    // ------------------------------------------------------------------ each command writes value and fields in one write

    [Fact]
    public void Create_WithField_ValueAndFieldsInOneWrite()
    {
        var stdout = Ok("", "create", "grafana-admin", "24", "--field", "username=admin", "--field", "source=generated:tswap", "--by", "claude");

        Assert.Contains("✓ Secret 'grafana-admin' created (24 chars)", stdout);
        Assert.Contains("Fields of 'grafana-admin' updated (source, username).", stdout);
        Assert.Equal(24, _m.Get("grafana-admin").Length);
        Assert.Equal(new Dictionary<string, string> { ["source"] = "generated:tswap", ["username"] = "admin" }, Live("grafana-admin"));
        Assert.Equal("claude", FieldsOf("grafana-admin").Get("username")!.Who.By);
        Assert.Equal(Record("grafana-admin").Version, FieldsOf("grafana-admin").Since);
        AssertOneWrite("grafana-admin", "source", "username");
    }

    [Fact]
    public void Ingest_WithFieldsJson_ValueAndFieldsInOneWrite()
    {
        Ok("cf-token-value-0042", "ingest", "cloudflare-ddns", "--fields", """{"kind": "api-key", "source": "external:cloudflare"}""");

        Assert.Equal("cf-token-value-0042", _m.Get("cloudflare-ddns"));
        Assert.Equal(new Dictionary<string, string> { ["kind"] = "api-key", ["source"] = "external:cloudflare" }, Live("cloudflare-ddns"));
        AssertOneWrite("cloudflare-ddns", "kind", "source");
    }

    [Fact]
    public void Ingest_WithFieldsFile_Accepted()
    {
        var file = _m.PathOf("fields.json");
        File.WriteAllText(file, """{"url": "https://x.example", "username": "app"}""");

        Ok("file-token-value-0042", "ingest", "s", "--fields", "@" + file);

        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://x.example", ["username"] = "app" }, Live("s"));
    }

    [Fact]
    public void Add_WithField_ValueAndFieldsInOneWrite()
    {
        Ok("added-value-0042\nadded-value-0042\n", "add", "db", "--field", "host=db1", "--field", "port=5432");

        Assert.Equal("added-value-0042", _m.Get("db"));
        Assert.Equal(new Dictionary<string, string> { ["host"] = "db1", ["port"] = "5432" }, Live("db"));
        AssertOneWrite("db", "host", "port");
    }

    [Fact]
    public void Add_SameValue_WithField_WritesTheField()
    {
        Ok("same-value-0042\nsame-value-0042\n", "add", "db");
        var before = Record("db");

        var stdout = Ok("same-value-0042\nsame-value-0042\n", "add", "db", "--field", "host=db1");

        var after = Record("db");
        Assert.Equal(before.Version, after.Version);
        Assert.True(after.Write.CompareTo(before.Write) > 0);
        Assert.Equal(new Dictionary<string, string> { ["host"] = "db1" }, Live("db"));
        Assert.Contains("Fields of 'db' updated (host).", stdout);
        Assert.Equal("same-value-0042", _m.Get("db"));
    }

    [Fact]
    public void Rotate_WithField_NewValueAndFieldsInOneWrite_UnlistedFieldsKept()
    {
        Ok(StoredValue, "ingest", "s");
        Ok("", "field", "set", "s", "url=https://a.example", "username=old");
        var before = Record("s");

        Ok("", "rotate", "s", "--field", "username=new", "--by", "owner");

        var after = Record("s");
        Assert.True(after.Version.CompareTo(before.Version) > 0);
        Assert.NotEqual(StoredValue, _m.Get("s"));
        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://a.example", ["username"] = "new" }, Live("s"));
        Assert.Equal("owner", FieldsOf("s").Get("username")!.Who.By);
        AssertOneWrite("s", "username");
    }

    [Fact]
    public void IngestRotate_WithField_NewValueAndFieldsInOneWrite_UnlistedFieldsKept()
    {
        Ok(StoredValue, "ingest", "s");
        Ok("", "field", "set", "s", "url=https://a.example");

        Ok("rotated-value-0042", "ingest", "--rotate", "s", "--fields", """{"expires": "2027-01-31", "url": null}""");

        Assert.Equal("rotated-value-0042", _m.Get("s"));
        Assert.Equal(new Dictionary<string, string> { ["expires"] = "2027-01-31" }, Live("s"));
        Assert.True(FieldsOf("s").Get("url")!.Deleted);
        AssertOneWrite("s", "expires", "url");
    }

    // ------------------------------------------------------------------ guard rail 1, same write: nothing stored

    [Fact]
    public void Create_FieldWithSameWriteValue_Refused()
    {
        var (exit, stdout, stderr) = Run("", "create", "s", "1", "--field", "note=" + AllGenerated);

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.note' contains a stored secret value.", stderr);
        Assert.Equal("", stdout);
        Assert.False(Exists("s"));
    }

    [Fact]
    public void Ingest_FieldWithSameWriteValue_Refused()
    {
        var (exit, stdout, stderr) = Run("new-value-0042", "ingest", "s", "--field", "conn=postgres://app:new-value-0042@db/app");

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.conn' contains a stored secret value.", stderr);
        Assert.DoesNotContain("new-value-0042", stdout + stderr);
        Assert.False(Exists("s"));
    }

    [Fact]
    public void Add_FieldWithSameWriteValue_Refused()
    {
        var (exit, _, stderr) = Run("new-value-0042\nnew-value-0042\n", "add", "s", "--field", "conn=postgres://app:new-value-0042@db/app");

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.conn' contains a stored secret value.", stderr);
        Assert.DoesNotContain("new-value-0042", stderr);
        Assert.False(Exists("s"));
    }

    [Fact]
    public void Rotate_FieldWithSameWriteValue_Refused()
    {
        Ok(StoredValue, "ingest", "s");
        Ok("", "field", "set", "s", "url=https://a.example");
        var before = Bytes("s");

        var (exit, stdout, stderr) = Run("", "rotate", "s", "1", "--field", "note=" + AllGenerated);

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.note' contains a stored secret value.", stderr);
        Assert.Equal("", stdout);
        Assert.Equal(before, Bytes("s"));
        Assert.Equal(StoredValue, _m.Get("s"));
    }

    [Fact]
    public void IngestRotate_FieldWithSameWriteValue_Refused()
    {
        Ok(StoredValue, "ingest", "s");
        Ok("", "field", "set", "s", "url=https://a.example");
        var before = Bytes("s");

        var (exit, stdout, stderr) = Run("rotated-value-0042", "ingest", "--rotate", "s", "--field", "conn=postgres://app:rotated-value-0042@db/app");

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.conn' contains a stored secret value.", stderr);
        Assert.DoesNotContain("rotated-value-0042", stdout + stderr);
        Assert.Equal(before, Bytes("s"));
        Assert.Equal(StoredValue, _m.Get("s"));
        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://a.example" }, Live("s"));
    }

    /// <summary>The same write is checked in its NFC form too, as a field is stored.</summary>
    [Fact]
    public void Ingest_DecomposedValue_FieldWithItsComposedForm_Refused()
    {
        var (exit, _, stderr) = Run("café-secret-42", "ingest", "s", "--field", "note=café-secret-42");

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.note' contains a stored secret value.", stderr);
        Assert.False(Exists("s"));
    }

    // ------------------------------------------------------------------ all or nothing

    public static TheoryData<string[], string> BadFields => new()
    {
        { ["--field", "Bad=x"], "Refused field name 'Bad'" },
        { ["--field", "url=https://x.example", "--field", "kind=nonsense"], "Refused field 'kind'" },
        { ["--field", "url=https://x.example", "--field", $"conn=postgres://app:{StoredValue}@db"], "Refused: the value for 's.conn' contains a stored secret value." },
        { ["--fields", "{" + string.Join(", ", Enumerable.Range(0, FieldRules.MaxLiveFields + 1).Select(i => $"\"f{i}\": \"v {i}\"")) + "}"],
            "Refused: the fields of 's' are over a cap." },
    };

    [Theory]
    [MemberData(nameof(BadFields))]
    public void Create_BadField_NothingWritten(string[] fields, string message)
    {
        Ok(StoredValue, "ingest", "other");

        var (exit, stdout, stderr) = Run("", ["create", "s", .. fields]);

        Assert.Equal(1, exit);
        Assert.Contains(message, stderr);
        Assert.Equal("", stdout);
        Assert.False(Exists("s"));
        Assert.DoesNotContain(Ok("", "names").Split('\n'), l => l.StartsWith("s ", StringComparison.Ordinal));
        Assert.Contains(Ok("", "names").Split('\n'), l => l.StartsWith("other ", StringComparison.Ordinal));
    }

    [Fact]
    public void Create_RandomLookingField_WarnsAndWrites()
    {
        var (exit, _, stderr) = Run("", "create", "s", "--field", "note=QWxhZGRpbjpvcGVuIHNlc2FtZQ00");

        Assert.Equal(0, exit);
        Assert.Contains(FieldSecretCheck.RandomLookingWarning("s", "note"), stderr);
        Assert.Equal(new Dictionary<string, string> { ["note"] = "QWxhZGRpbjpvcGVuIHNlc2FtZQ00" }, Live("s"));
    }

    [Fact]
    public void FieldAndFields_Mixed_Refused()
    {
        var (exit, _, stderr) = Run("v-0042", "ingest", "s", "--field", "url=https://x.example", "--fields", """{"kind": "token"}""");

        Assert.Equal(1, exit);
        Assert.Contains("one form", stderr);
        Assert.False(Exists("s"));
    }

    [Theory]
    [InlineData("--field", """{"kind": "token"}""", "--field takes FIELD=VALUE")]
    [InlineData("--field", "@fields.json", "--field takes FIELD=VALUE")]
    [InlineData("--fields", "kind=token", "--fields takes one JSON object or @FILE")]
    public void WrongFormForTheFlag_Refused(string flag, string arg, string message)
    {
        var (exit, _, stderr) = Run("v-0042", "ingest", "s", flag, arg);

        Assert.Equal(1, exit);
        Assert.Contains(message, stderr);
        Assert.False(Exists("s"));
    }

    [Fact]
    public void By_WithoutFields_Refused()
    {
        var (exit, _, stderr) = Run("v-0042", "ingest", "s", "--by", "claude");

        Assert.Equal(1, exit);
        Assert.Contains("--by labels a field change", stderr);
        Assert.False(Exists("s"));
    }

    [Fact]
    public void Ingest_FieldsNeverFromStdin()
    {
        foreach (var source in new[] { "@-", "@/dev/stdin" })
        {
            var (exit, _, stderr) = Run("""{"username": "admin"}""", "ingest", "s", "--fields", source);
            Assert.Equal(1, exit);
            Assert.Contains("never from stdin", stderr);
            Assert.False(Exists("s"));
        }

        // stdin is the value, never fields: a JSON object piped in is stored as the secret.
        Ok("""{"username": "admin"}""", "ingest", "s");
        Assert.Equal("""{"username": "admin"}""", _m.Get("s"));
        Assert.Empty(FieldsOf("s").Entries);
    }

    [Fact]
    public void FieldWrite_OnVaultWithoutFingerprints_Refused_PlainWriteWorks()
    {
        using var old = new FleetMachine("value-fields-format2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(old, InitFormatTwoVault(old));
        old.Ok(StoredValue, "ingest", "s");

        var (exit, stdout, stderr) = old.Run("", "create", "t", "--field", "url=https://x.example");

        Assert.Equal(1, exit);
        Assert.Contains("'create' checks each value against the stored secrets by their fingerprints, and 1 record(s) in this vault have none yet", stderr);
        Assert.Contains("Nothing was written.", stderr);
        Assert.Equal("", stdout);
        Assert.False(File.Exists(RecordFile(old, key, "t")));

        old.Ok("", "create", "t");
        Assert.Equal(32, old.Get("t").Length);
    }

    // ------------------------------------------------------------------ value writes without fields keep them

    [Theory]
    [InlineData("burn")]
    [InlineData("restore")]
    [InlineData("rotate")]
    [InlineData("ingest --rotate")]
    public void ValueWrites_WithoutFields_KeepFields(string command)
    {
        Ok(StoredValue, "ingest", "s");
        Ok("second-value-0042", "ingest", "--rotate", "s");
        Ok("", "field", "set", "s", "url=https://a.example", "rotate=step 1\nstep 2", "--by", "owner");
        var before = FieldsBytes("s");
        var version = Record("s").Version;

        switch (command)
        {
            case "burn": Ok("", "burn", "s", "leaked"); break;
            case "restore": Ok("", "restore", "s"); break;
            case "rotate": Ok("", "rotate", "s"); break;
            default: Ok("third-value-0042", "ingest", "--rotate", "s"); break;
        }

        Assert.Equal(before, FieldsBytes("s"));
        if (command != "burn")
            Assert.True(Record("s").Version.CompareTo(version) > 0, $"{command} wrote no new version");
    }

    // ------------------------------------------------------------------ the new value in a field: a warning

    [Theory]
    [InlineData("add")]
    [InlineData("ingest")]
    [InlineData("ingest --rotate")]
    [InlineData("rotate")]
    public void ValueInAField_Warns(string command)
    {
        const string NewValue = "new-value-0042";
        if (command is "ingest --rotate" or "rotate")
            Ok(StoredValue, "ingest", "s");
        Ok("other-value-0042", "ingest", "other");
        Ok("", "field", "set", "other", "note=" + (command == "rotate" ? AllGenerated : $"uses {NewValue} somewhere"));

        // A field value with no character create/rotate draws from, so a 1-character rotation can't land in it.
        const string Field = "note=~ ~";
        var (exit, stdout, stderr) = command switch
        {
            "add" => Run($"{NewValue}\n{NewValue}\n", "add", "s", "--field", Field),
            "ingest" => Run(NewValue, "ingest", "s", "--field", Field),
            "ingest --rotate" => Run(NewValue, "ingest", "--rotate", "s", "--field", Field),
            _ => Run("", "rotate", "s", "1", "--field", Field),
        };

        Assert.True(exit == 0, stderr);
        Assert.Contains("Warning: the new value of 's' appears in other.note.", stderr);
        Assert.DoesNotContain(NewValue, stdout + stderr);
        Assert.Equal("~ ~", Live("s")["note"]);
    }

    [Fact]
    public void ValueInAField_FieldGivenInNfc_ValueInNfd_Warns()
    {
        Ok("other-value-0042", "ingest", "other");
        Ok("", "field", "set", "other", "note=uses café-secret-42 here");

        var (exit, _, stderr) = Run("café-secret-42", "ingest", "s", "--field", "kind=token");

        Assert.Equal(0, exit);
        Assert.Contains("Warning: the new value of 's' appears in other.note.", stderr);
    }
}
