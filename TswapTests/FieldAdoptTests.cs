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
    private void AssertRefusedNothingWritten(string message, string name, string field, string secret)
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
        Assert.Equal("username = \"svc-backup\"\n", _m.Ok("", "field", "show", "db"));
        Assert.Contains("db-user", _m.Run("", "get", "db-user").Err); // not found
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

        AssertRefusedNothingWritten("Refused field 'username':", "db", "username", "db-user");
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

    [Theory]
    [InlineData("adopt db username")]
    [InlineData("adopt db username --from")]
    [InlineData("adopt db username db-user")]
    [InlineData("adopt db --from db-user")]
    [InlineData("adopt db username --from db-user extra")]
    public void FieldAdopt_BadArguments_Usage(string args)
    {
        var (exit, _, stderr) = _m.Run("", ["field", .. args.Split(' ')]);

        Assert.Equal(1, exit);
        Assert.Contains("field adopt NAME FIELD --from SECRET", stderr);
    }
}
