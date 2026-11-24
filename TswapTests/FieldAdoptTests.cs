using TswapCore;
using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Issue #311 task 6b: <c>sudo tswap field adopt NAME FIELD --from SECRET</c> (spec "Commands", guard rail 1): SECRET's
/// current value becomes NAME's field FIELD and SECRET is deleted, in one commit; every refusal writes nothing.
/// </summary>
public sealed class FieldAdoptTests : IDisposable
{
    private const string Password = "Xq7-stored-password-value-91";
    private const string Username = "svc-backup";

    private DateTimeOffset _now = new(2026, 11, 15, 16, 42, 7, TimeSpan.Zero);
    private readonly FleetMachine _m;
    private readonly byte[] _key;

    public FieldAdoptTests()
    {
        _m = new FleetMachine("field-adopt", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private byte[] Bytes(string name) => File.ReadAllBytes(RecordFile(_m, _key, name));

    private FieldSet FieldsOf(string name) => Assert.IsType<FieldSet>(FieldsCodec.TryGet(ReadRecord(_m, _key, name).Extensions));

    private (int Exit, string Out, string Err) Adopt(string name, string field, string secret)
    {
        _now = _now.AddSeconds(1);
        return _m.Run("", "field", "adopt", name, field, "--from", secret);
    }

    /// <summary>A password secret <c>db</c> and a burned username secret <c>db-user</c>, as the burned usernames are today.</summary>
    private void PlantBurnedUsername(string secret = "db-user", string value = Username)
    {
        if (!File.Exists(RecordFile(_m, _key, "db")))
            _m.Ok(Password, "ingest", "db");
        _m.Ok(value, "ingest", secret);
        _m.Ok("", "burn", secret, "seen in a log");
    }

    /// <summary>Runs <paramref name="adopt"/> and checks it was refused with <paramref name="message"/>, writing nothing.</summary>
    private string AssertRefusedNothingWritten(string message, string name, string field, string secret)
    {
        var names = new[] { name, secret }.Where(n => File.Exists(RecordFile(_m, _key, n))).Distinct().ToList();
        var before = names.ToDictionary(n => n, Bytes);

        var (exit, stdout, stderr) = Adopt(name, field, secret);

        Assert.Equal(1, exit);
        Assert.Contains(message, stderr);
        Assert.Equal("", stdout);
        foreach (var n in names)
            Assert.Equal(before[n], Bytes(n));
        Assert.False(File.Exists(RecordFile(_m, _key, name)) && !before.ContainsKey(name), $"a record '{name}' was created");
        return stdout + stderr;
    }

    // ------------------------------------------------------------------ the adopt

    [Fact]
    public void FieldAdopt_WithoutSudo_Refused()
    {
        if (Environment.IsPrivilegedProcess)
            return; // the refusal can't happen in a privileged process (Windows CI runs elevated)
        PlantBurnedUsername();
        _m.Sudo = false;

        AssertRefusedNothingWritten("The 'field adopt' command requires", "db", "username", "db-user");
        _m.Sudo = true;
        Assert.Equal(Username, _m.Get("db-user"));
    }

    [Fact]
    public void FieldAdopt_BurnedUsername_BecomesField_SecretDeleted()
    {
        PlantBurnedUsername();
        var before = ReadRecord(_m, _key, "db");

        var (exit, stdout, stderr) = Adopt("db", "username", "db-user");

        Assert.True(exit == 0, stderr);
        Assert.Contains("'db-user'", stdout);
        Assert.Contains("'db.username'", stdout);
        Assert.DoesNotContain(Username, stdout + stderr); // never printed; field show shows it
        Assert.DoesNotContain("looks random", stderr);

        var field = FieldsOf("db").Get("username")!;
        Assert.Equal(Username, field.Value);
        Assert.False(field.Deleted);
        var after = ReadRecord(_m, _key, "db");
        var tombstone = ReadRecord(_m, _key, "db-user");
        Assert.Equal(RecordType.Tombstone, tombstone.Type);
        // One commit: a metadata-only write of NAME (same value version, one new write stamp, which the field's change
        // doesn't post-date) and the tombstone, stamped next to NAME's write from the same clock reading.
        Assert.Equal(before.Version, after.Version);
        Assert.True(after.Write.CompareTo(before.Write) > 0, $"write stamp {after.Write} not after {before.Write}");
        Assert.True(field.Changed.CompareTo(before.Write) > 0 && field.Changed.CompareTo(after.Write) <= 0,
            $"field stamp {field.Changed} not in this write ({before.Write}, {after.Write}]");
        Assert.All<Stamp>([field.Changed, after.Write, tombstone.Write], s => Assert.Equal(_now.ToUnixTimeMilliseconds(), s.Hlc.PhysicalMs));
        Assert.Equal(1, Math.Abs((long)after.Write.Hlc.Logical - tombstone.Write.Hlc.Logical));
        Assert.Equal(Password, _m.Get("db"));
        Assert.Equal("username = \"svc-backup\"\n", _m.Ok("", "field", "show", "db").ReplaceLineEndings("\n"));
        var (getExit, _, getErr) = _m.Run("", "get", "db-user");
        Assert.Equal(1, getExit);
        Assert.Contains("Secret 'db-user' not found", getErr);
    }

    [Fact]
    public void FieldAdopt_LiveSecret_Works()
    {
        _m.Ok(Password, "ingest", "db");
        _m.Ok(Username, "ingest", "db-user");

        var (exit, _, stderr) = Adopt("db", "username", "db-user");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Username, FieldsOf("db").Get("username")!.Value);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "db-user").Type);
    }

    [Fact]
    public void FieldAdopt_RandomLookingValue_NoWarning()
    {
        PlantBurnedUsername(value: "c3ZjLWJhY2t1cC11c2VyMDE");

        var (exit, _, stderr) = Adopt("db", "username", "db-user");

        Assert.True(exit == 0, stderr);
        Assert.Equal("", stderr);
    }

    [Fact]
    public void FieldAdopt_SecondSameValue_Works()
    {
        _m.Ok("another-password-0123456", "ingest", "b");
        PlantBurnedUsername("u1");
        Assert.Equal(0, Adopt("db", "username", "u1").Exit);

        // u1 is deleted now, and deleted values are not checked: a second burned copy of the same username adopts.
        _m.Ok(Username, "ingest", "u2");
        _m.Ok("", "burn", "u2");
        var (exit, _, stderr) = Adopt("b", "username", "u2");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Username, FieldsOf("db").Get("username")!.Value);
        Assert.Equal(Username, FieldsOf("b").Get("username")!.Value);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "u2").Type);
    }

    [Fact]
    public void FieldAdopt_DecomposedValue_StoredAsNfc()
    {
        PlantBurnedUsername(value: "José");

        Assert.Equal(0, Adopt("db", "username", "db-user").Exit);

        Assert.Equal("José", FieldsOf("db").Get("username")!.Value);
    }

    // ------------------------------------------------------------------ refusals, each writing nothing

    [Fact]
    public void FieldAdopt_SameLiveValueElsewhere_Refused()
    {
        _m.Ok("another-password-0123456", "ingest", "b");
        PlantBurnedUsername("u1");
        _m.Ok(Username, "ingest", "u2");

        AssertRefusedNothingWritten("Refused: the value for 'db.username' contains a stored secret value.", "db", "username", "u1");
        AssertRefusedNothingWritten("Refused: the value for 'b.username' contains a stored secret value.", "b", "username", "u2");
    }

    [Fact]
    public void FieldAdopt_SecretIsName_Refused()
    {
        _m.Ok(Username, "ingest", "db");

        AssertRefusedNothingWritten("'field adopt' needs two different secrets", "db", "username", "db");
    }

    [Fact]
    public void FieldAdopt_NameMissing_Refused()
    {
        _m.Ok(Username, "ingest", "db-user");

        AssertRefusedNothingWritten("No secret 'db'.", "db", "username", "db-user");
    }

    [Fact]
    public void FieldAdopt_NameDeleted_Refused()
    {
        PlantBurnedUsername();
        _m.Ok("", "delete", "db");

        AssertRefusedNothingWritten("No secret 'db'.", "db", "username", "db-user");
    }

    [Fact]
    public void FieldAdopt_SecretMissing_Refused()
    {
        _m.Ok(Password, "ingest", "db");

        AssertRefusedNothingWritten("No secret 'db-user'.", "db", "username", "db-user");
    }

    [Fact]
    public void FieldAdopt_FieldHasValue_Refused()
    {
        PlantBurnedUsername();
        _m.Ok("", "field", "set", "db", "username=someone-else");

        AssertRefusedNothingWritten("'db.username' has a value already; unset it first", "db", "username", "db-user");
        Assert.Equal("someone-else", FieldsOf("db").Get("username")!.Value);
    }

    [Fact]
    public void FieldAdopt_RemovedField_Adopts()
    {
        PlantBurnedUsername();
        _m.Ok("", "field", "set", "db", "username=someone-else");
        _m.Ok("", "field", "unset", "db", "username");

        Assert.Equal(0, Adopt("db", "username", "db-user").Exit);

        Assert.Equal(Username, FieldsOf("db").Get("username")!.Value);
    }

    [Fact]
    public void FieldAdopt_SecretHasFields_RefusedNamingThem()
    {
        PlantBurnedUsername();
        _m.Ok("", "field", "set", "db-user", "url=https://db.example", "host=db1");

        AssertRefusedNothingWritten("'db-user' has fields of its own (host, url); move them first", "db", "username", "db-user");
    }

    [Fact]
    public void FieldAdopt_InvalidValue_Refused()
    {
        PlantBurnedUsername(value: "line one\u0007");

        var shown = AssertRefusedNothingWritten("Refused field 'username':", "db", "username", "db-user");

        Assert.DoesNotContain("line one", shown);
    }

    // Review fix 1: a refused adopt leaves SECRET a secret, so its value must not reach either stream.
    [Theory]
    [InlineData("kind", "Refused field 'kind': the value of 'db-user' is not a known kind (use one of password,")]
    [InlineData("expires", "Refused field 'expires': the value of 'db-user' is not a date; use YYYY-MM-DD")]
    public void FieldAdopt_FormatRefusal_DoesNotShowValue(string field, string message)
    {
        PlantBurnedUsername();

        var shown = AssertRefusedNothingWritten(message, "db", field, "db-user");

        Assert.DoesNotContain(Username, shown);
        _m.Sudo = true;
        Assert.Equal(Username, _m.Get("db-user"));
    }

    // Review fix 3: the cap refusal comes at Commit, after both writes are staged: neither is written.
    [Fact]
    public void FieldAdopt_OverCap_RefusedAtCommit_NothingWritten()
    {
        PlantBurnedUsername();
        _m.Ok("", "field", "set", "db",
            "{" + string.Join(", ", Enumerable.Range(0, FieldRules.MaxLiveFields).Select(i => $"\"f{i}\": \"v {i}\"")) + "}");

        var shown = AssertRefusedNothingWritten("Refused: the fields of 'db' are over a cap.", "db", "username", "db-user");

        Assert.DoesNotContain(Username, shown);
        Assert.Equal(FieldRules.MaxLiveFields, FieldsOf("db").Live.Count());
        Assert.Equal(Username, _m.Get("db-user"));
        Assert.NotEqual(RecordType.Tombstone, ReadRecord(_m, _key, "db-user").Type);
    }

    [Fact]
    public void FieldAdopt_InvalidFieldName_Refused()
    {
        PlantBurnedUsername();

        AssertRefusedNothingWritten("Refused field name 'User'", "db", "User", "db-user");
    }

    [Fact]
    public void FieldAdopt_OnVaultWithoutFingerprints_Refused()
    {
        using var old = new FleetMachine("field-adopt-format2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(old, InitFormatTwoVault(old));
        old.Ok(Password, "ingest", "db");
        old.Ok(Username, "ingest", "db-user");
        var db = File.ReadAllBytes(RecordFile(old, key, "db"));
        var user = File.ReadAllBytes(RecordFile(old, key, "db-user"));

        var (exit, stdout, stderr) = old.Run("", "field", "adopt", "db", "username", "--from", "db-user");

        Assert.Equal(1, exit);
        Assert.Contains("'field adopt' checks each value against the stored secrets by their fingerprints, and 2 record(s) in this vault have none yet", stderr);
        Assert.Contains("vault reindex", stderr);
        Assert.Equal("", stdout);
        Assert.Equal(db, File.ReadAllBytes(RecordFile(old, key, "db")));
        Assert.Equal(user, File.ReadAllBytes(RecordFile(old, key, "db-user")));
    }

    // ------------------------------------------------------------------ several groups in one command (brief T56, #395)

    /// <summary>The password secrets <c>db</c> and <c>b</c>, and every one of <paramref name="holders"/> holding <see cref="Username"/>.</summary>
    private void PlantHolders(params string[] holders)
    {
        _m.Ok(Password, "ingest", "db");
        _m.Ok("another-password-0123456", "ingest", "b");
        foreach (var holder in holders)
            _m.Ok(Username, "ingest", holder);
    }

    private (int Exit, string Out, string Err) AdoptArgs(string args)
    {
        _now = _now.AddSeconds(1);
        return _m.Run("", ["field", .. args.Split(' ')]);
    }

    private Dictionary<string, byte[]> AllRecords() => _m.RecordFiles.ToDictionary(f => f, f => File.ReadAllBytes(Path.Combine(_m.RecordsDir, f)));

    /// <summary>
    /// Runs <paramref name="args"/> and checks it was refused with <paramref name="message"/>, no record changed or was
    /// added, and neither stream holds the value; returns stderr.
    /// </summary>
    private string AssertGroupsRefused(string message, string args)
    {
        var before = AllRecords();

        var (exit, stdout, stderr) = AdoptArgs(args);

        Assert.Equal(1, exit);
        Assert.Contains(message, stderr);
        Assert.Equal("", stdout);
        Assert.DoesNotContain(Username, stdout + stderr);
        var after = AllRecords();
        Assert.Equal(before.Keys.Order(StringComparer.Ordinal), after.Keys.Order(StringComparer.Ordinal));
        foreach (var (file, bytes) in before)
            Assert.Equal(bytes, after[file]);
        return stderr;
    }

    private static string HolderRefusal(string field, string holders) =>
        $"Refused: the value for 'db.{field}' contains a stored secret value. Fields are visible; a secret never goes in one. " +
        $"It contains the value of {holders}. If those hold the same setting (one username for two services, say), adopt " +
        "them in the same command, one NAME FIELD --from SECRET group each; otherwise change them first.";

    [Fact]
    public void FieldAdopt_TwoHoldersInOneCommand_BothAdopted()
    {
        PlantHolders("u1", "u2");

        var (exit, stdout, stderr) = AdoptArgs("adopt db username --from u1 b username --from u2");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Username, FieldsOf("db").Get("username")!.Value);
        Assert.Equal(Username, FieldsOf("b").Get("username")!.Value);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "u1").Type);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "u2").Type);
        Assert.Equal(
            [
                "✓ The value of 'u1' is now the field 'db.username' (visible; tswap field show db); secret 'u1' deleted.",
                "✓ The value of 'u2' is now the field 'b.username' (visible; tswap field show b); secret 'u2' deleted.",
            ],
            stdout.ReplaceLineEndings("\n").TrimEnd('\n').Split('\n'));
        Assert.DoesNotContain(Username, stdout + stderr);
        Assert.Equal(Password, _m.Get("db"));
    }

    [Fact]
    public void FieldAdopt_OneOtherHolder_RefusedNamingIt()
    {
        PlantHolders("u1", "u2");

        var stderr = AssertGroupsRefused("It contains the value of 'u2'. If those hold the same setting", "adopt db username --from u1");

        Assert.Contains(HolderRefusal("username", "'u2'"), stderr);
    }

    [Fact]
    public void FieldAdopt_TwoOtherHolders_RefusedNamingBothInOrder()
    {
        PlantHolders("u1", "u3", "u2");

        AssertGroupsRefused(HolderRefusal("username", "'u2', 'u3'"), "adopt db username --from u1");
    }

    [Fact]
    public void FieldAdopt_TwoGroups_ThirdHolderLeft_RefusedNamingOnlyIt()
    {
        PlantHolders("u1", "u2", "u3");

        AssertGroupsRefused(HolderRefusal("username", "'u3'"), "adopt db username --from u1 b username --from u2");
    }

    [Fact]
    public void FieldAdopt_PreviousValueHolder_RefusedNamingItsPreviousValue()
    {
        PlantHolders("u1", "u2");
        _m.Ok("", "burn", "u2", "rotating");
        _m.Ok("a-different-username", "ingest", "--rotate", "u2");

        AssertGroupsRefused(HolderRefusal("username", "'u2' (its previous value)"), "adopt db username --from u1");
    }

    [Fact]
    public void FieldAdopt_TwoFieldsOnOneName_OneFieldWrite()
    {
        PlantHolders("u1");
        _m.Ok("db.example", "ingest", "h1");

        var (exit, _, stderr) = AdoptArgs("adopt db username --from u1 db host --from h1");

        Assert.True(exit == 0, stderr);
        var fields = FieldsOf("db");
        var username = fields.Get("username")!;
        var host = fields.Get("host")!;
        Assert.Equal(Username, username.Value);
        Assert.Equal("db.example", host.Value);
        // One field write for db (a second SetFields on one name is refused by the writer): both edits in the order
        // given, stamped from the same clock reading, the record's write stamp not before the last of them.
        Assert.True(username.Changed.CompareTo(host.Changed) < 0, $"{username.Changed} not before {host.Changed}");
        Assert.Equal(username.Changed.Hlc.PhysicalMs, host.Changed.Hlc.PhysicalMs);
        Assert.True(host.Changed.CompareTo(ReadRecord(_m, _key, "db").Write) <= 0);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "u1").Type);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "h1").Type);
    }

    [Fact]
    public void FieldAdopt_SecondGroupNameMissing_NothingWritten()
    {
        PlantHolders("u1", "u2");

        AssertGroupsRefused("No secret 'nope'.", "adopt db username --from u1 nope username --from u2");

        Assert.NotEqual(RecordType.Tombstone, ReadRecord(_m, _key, "u1").Type);
    }

    [Fact]
    public void FieldAdopt_SecondGroupFormatRefusal_FirstGroupNotWritten()
    {
        PlantHolders("u1", "u2");

        AssertGroupsRefused("Refused field 'kind': the value of 'u2' is not a known kind", "adopt db username --from u1 b kind --from u2");

        Assert.Null(FieldsOf("db").Get("username"));
    }

    [Theory]
    [InlineData("u1", "adopt db username --from u1 b username --from u1", "'field adopt' names 'u1' twice after --from.")]
    [InlineData("u1 u2", "adopt db username --from u1 db username --from u2", "'field adopt' names 'db.username' twice.")]
    [InlineData("u1 u2", "adopt db username --from u1 u1 host --from u2",
        "'u1' is adopted (and deleted) in this command, so it can't receive a field in it too.")]
    public void FieldAdopt_GroupsThatClash_Refused(string holders, string args, string message)
    {
        PlantHolders(holders.Split(' '));

        AssertGroupsRefused(message, args);
    }

    [Fact]
    public void FieldAdopt_NamesDifferingInCase_AreTwoSecrets()
    {
        PlantHolders("u1", "U1");

        var (exit, _, stderr) = AdoptArgs("adopt db username --from u1 b username --from U1");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Username, FieldsOf("db").Get("username")!.Value);
        Assert.Equal(Username, FieldsOf("b").Get("username")!.Value);
    }

    [Fact]
    public void FieldAdopt_TwoGroupsWithoutSudo_Refused()
    {
        if (Environment.IsPrivilegedProcess)
            return; // the refusal can't happen in a privileged process (Windows CI runs elevated)
        PlantHolders("u1", "u2");
        _m.Sudo = false;

        AssertGroupsRefused("The 'field adopt' command requires", "adopt db username --from u1 b username --from u2");
    }

    [Theory]
    [InlineData("adopt db username")]
    [InlineData("adopt db username --from")]
    [InlineData("adopt db username db-user")]
    [InlineData("adopt db --from db-user")]
    [InlineData("adopt db username --from db-user extra")]
    [InlineData("adopt db username --from u1 b")]
    [InlineData("adopt db username --from u1 b username u2 x")]
    [InlineData("adopt db username --from u1 b username --from")]
    public void FieldAdopt_BadArguments_Usage(string args)
    {
        var (exit, _, stderr) = _m.Run("", ["field", .. args.Split(' ')]);

        Assert.Equal(1, exit);
        Assert.Contains("field adopt NAME FIELD --from SECRET", stderr);
    }
}
