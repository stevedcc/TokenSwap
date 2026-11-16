using System.Text;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Issue #311 task 4, spec guard rail 1: a field value holding a stored secret value is refused,
/// without naming the secret; the check reads fingerprints only. Every retained version of every
/// live secret is checked (burned and previous values included), deleted secrets' values are not,
/// and the value being written in the same call is checked too.
/// </summary>
public sealed class FieldSecretCheckTests : IDisposable
{
    private const string Expected =
        "Refused: the value for 'grafana.username' contains a stored secret value. Fields are visible; a secret never goes in one.";

    private static readonly FieldWho Claude = new("a1a1a1a1", "steve", Elevated: false, Terminal: false, By: "claude");

    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m;
    private readonly byte[] _key;
    private readonly FingerprintKeys _keys;

    public FieldSecretCheckTests()
    {
        _m = new FleetMachine("field-secret-check", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
        _keys = FingerprintKeys.Derive(_key);
    }

    public void Dispose()
    {
        _keys.Dispose();
        _m.Dispose();
    }

    private RecordVaultStore NewStore() => new(_m.Dir, time: new FuncTimeProvider(() => _now), warnings: TextWriter.Null);

    private VaultView View() => new(NewStore(), _key, TextWriter.Null);

    private FingerprintIndex Stored()
    {
        using var view = View();
        return view.BuildIndex(_keys);
    }

    private FingerprintIndex SameWrite(string value) =>
        FingerprintIndex.Build([("being-written", false, Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), _keys))], _keys);

    private string? Check(string value, FingerprintIndex? sameWrite = null) =>
        FieldSecretCheck.Refusal(Stored(), sameWrite, "grafana", "username", value);

    private void SetFields(string name, params FieldEdit[] edits)
    {
        _now = _now.AddSeconds(1);
        using var writer = new VaultWriter(NewStore(), _key, TextWriter.Null);
        writer.SetFields(name, edits, Claude);
        writer.Commit();
    }

    [Fact]
    public void Refused_WhenFieldContainsStoredValue()
    {
        _m.Ok("hunter2-stored-value", "ingest", "db");

        Assert.Equal(Expected, Check("hunter2-stored-value"));
        Assert.Equal(Expected, Check("user=hunter2-stored-value;host=x"));
        Assert.Equal(Expected, Check($"basic {Convert.ToBase64String(Encoding.UTF8.GetBytes("hunter2-stored-value"))}"));
        Assert.Null(Check("admin"));
    }

    [Fact]
    public void NotNamingTheSecret()
    {
        _m.Ok("value-of-the-distinctive-secret", "ingest", "distinctive-secret-name");

        var refusal = Check("value-of-the-distinctive-secret");

        Assert.Equal(Expected, refusal);
        Assert.DoesNotContain("distinctive", refusal);
    }

    [Fact]
    public void Refused_SameWriteValue()
    {
        _m.Ok("some-other-value", "ingest", "other");

        Assert.Null(Check("brand-new-value-77"));
        Assert.Equal(Expected, Check("brand-new-value-77", SameWrite("brand-new-value-77")));
        Assert.Equal(Expected, Check("prefix brand-new-value-77 suffix", SameWrite("brand-new-value-77")));
        Assert.Null(Check("admin", SameWrite("brand-new-value-77")));
    }

    [Fact]
    public void DeletedSecretValue_NotChecked()
    {
        _m.Ok("deleted-username-value", "ingest", "old-username");
        Assert.Equal(Expected, Check("deleted-username-value"));

        _m.Ok("", "delete", "old-username");

        Assert.Null(Check("deleted-username-value"));
    }

    [Fact]
    public void BurnedSecretValue_Checked()
    {
        _m.Ok("burned-username-value", "ingest", "burned-user");
        _m.Ok("", "burn", "burned-user", "seen in a log");
        using (var view = View())
            Assert.True(view.IsBurned("burned-user"));

        Assert.Equal(Expected, Check("burned-username-value"));
    }

    [Fact]
    public void PreviousVersion_Checked()
    {
        _m.Ok("first-value-before-rotation", "ingest", "db");
        _m.Ok("second-value-after-rotation", "ingest", "--rotate", "db");

        Assert.Equal(Expected, Check("first-value-before-rotation"));
        Assert.Equal(Expected, Check("second-value-after-rotation"));
    }

    /// <summary>
    /// Review Focus 1: the value is normalised (NFC) before the scan, as it would be stored, so a
    /// decomposed spelling of a stored value can't slip past the check.
    /// </summary>
    [Fact]
    public void FieldSecretCheck_NormalisesBeforeScanning()
    {
        const string composed = "café-stored-secret";
        const string decomposed = "café-stored-secret";
        _m.Ok(composed, "ingest", "db");

        Assert.Equal(Expected, Check(decomposed));
        Assert.Equal(Expected, FieldSecretCheck.Refusal(
            FingerprintIndex.Build([], _keys), SameWrite(composed), "grafana", "username", decomposed));
    }

    [Theory]
    [InlineData("dGhpcyBpcyBhIHRlc3QhIQ==", true)] // 24 characters of base64
    [InlineData("0123456789abcdef0123456789abcdef01234567", true)] // 40 hex digits
    [InlineData("AbCdEfGhIjKlMnOpQr_-", true)] // 20 characters of base64url
    [InlineData("https://grafana.example.com/login", false)]
    [InlineData("AbCdEfGhIjKlMnOpQrS", false)] // 19 characters
    [InlineData("dGhpcyBpcyBhIH Rlc3QhIQ==", false)] // a space
    [InlineData("admin", false)]
    public void LooksRandom(string value, bool expected) =>
        Assert.Equal(expected, FieldSecretCheck.LooksRandom(value));

    [Fact]
    public void RandomLookingWarning_Text() =>
        Assert.Equal(
            "Warning: the value for 'grafana.username' looks random. Fields are visible: if it is a secret, unset it and store it as a secret.",
            FieldSecretCheck.RandomLookingWarning("grafana", "username"));

    [Fact]
    public void FieldsContaining_NamesTheFieldsHoldingTheNewValue()
    {
        _m.Ok("v1", "ingest", "b-secret");
        _m.Ok("v2", "ingest", "a-secret");
        _m.Ok("v3", "ingest", "gone");
        SetFields("b-secret", new FieldEdit("url", "https://x/?u=new-value-99"), new FieldEdit("owner", "platform"));
        SetFields("a-secret", new FieldEdit("username", "new-value-99"), new FieldEdit("notes", "café new-value-99"));
        SetFields("gone", new FieldEdit("username", "new-value-99"));
        _m.Ok("", "delete", "gone");

        using var view = View();
        var found = FieldSecretCheck.FieldsContaining(view, SameWrite("new-value-99"));

        Assert.Equal(["a-secret.notes", "a-secret.username", "b-secret.url"], found);
        Assert.Empty(FieldSecretCheck.FieldsContaining(view, SameWrite("not-anywhere-0")));
    }

    /// <summary>
    /// A stored field value in decomposed form (as only an unchecked merge or import brings one: writes
    /// normalise) is scanned as NFC, as the new value's fingerprints are.
    /// </summary>
    [Fact]
    public void FieldsContaining_NormalisesFieldValues()
    {
        PlantField("s", "notes", "cafe\u0301-new");

        using var view = View();
        Assert.Equal("cafe\u0301-new", view.Fields("s")!.Get("notes")!.Value);

        Assert.Equal(["s.notes"], FieldSecretCheck.FieldsContaining(view, SameWrite("caf\u00e9-new")));
    }

    /// <summary>
    /// Review (task 4, Minor 1): a secret value is stored as given, not normalised, so one in decomposed
    /// form (NFD) must still be found in a field value given in the same form: the raw value is scanned
    /// as well as its NFC form.
    /// </summary>
    [Fact]
    public void Refused_WhenStoredSecretIsDecomposed()
    {
        const string decomposed = "cafe\u0301-decomposed-secret";
        _m.Ok(decomposed, "ingest", "db");

        Assert.Equal(Expected, Check(decomposed));
        Assert.Equal(Expected, Check($"x {decomposed} y"));
        Assert.Equal(Expected, FieldSecretCheck.Refusal(
            FingerprintIndex.Build([], _keys), SameWrite(decomposed), "grafana", "username", decomposed));
    }

    /// <summary>Review (task 4, Minor 1), the reverse: a decomposed new value is found in a field holding those exact characters.</summary>
    [Fact]
    public void FieldsContaining_FindsDecomposedValueInDecomposedField()
    {
        PlantField("s", "notes", "cafe\u0301-new");

        using var view = View();

        Assert.Equal(["s.notes"], FieldSecretCheck.FieldsContaining(view, SameWrite("cafe\u0301-new")));
    }

    /// <summary>
    /// Review (task 4, Minor 2): <see cref="FieldSecretCheck.FieldsContaining"/> works from the metadata
    /// the view already holds, as <see cref="VaultView.BuildIndex"/> does, instead of reloading it with
    /// <see cref="FormatTwoRecords.Skip"/> over a caller's <see cref="FormatTwoRecords.Decode"/> load.
    /// </summary>
    [Fact]
    public void FieldsContaining_KeepsTheViewsLoadedMetadata()
    {
        using var m2 = new FleetMachine("field-secret-check-f2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key2 = VaultKey(m2, InitFormatTwoVault(m2));
        m2.Ok("legacy-value", "ingest", "legacy");
        using var keys2 = FingerprintKeys.Derive(key2);
        using var view = new VaultView(Store(m2), key2, TextWriter.Null);
        var loaded = view.LoadAll(FormatTwoRecords.Decode);
        Assert.Equal(1, view.FormatTwoDecoded);

        Assert.Empty(FieldSecretCheck.FieldsContaining(view, FingerprintIndex.Build(
            [("new", false, Fingerprinter.Compute(Encoding.UTF8.GetBytes("legacy-value"), keys2))], keys2)));

        Assert.Same(loaded, view.LoadAll(FormatTwoRecords.Decode));
        Assert.Equal(1, view.FormatTwoDecoded);
    }

    /// <summary>
    /// Gives secret <paramref name="name"/> (created here) one field holding <paramref name="value"/>
    /// exactly as given, through the codec: writes normalise, so only an unchecked merge or import
    /// brings a decomposed value.
    /// </summary>
    private void PlantField(string name, string field, string value)
    {
        _m.Ok("v1", "ingest", name);
        SetFields(name, new FieldEdit("owner", "x"));
        var path = RecordFile(_m, _key, name);
        var record = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        var since = Assert.IsType<FieldSet>(FieldsCodec.TryGet(record.Extensions)).Since;
        var at = new Stamp(new Hlc(since.Hlc.PhysicalMs + 1, 0), since.Origin);
        record = record with
        {
            Extensions = FieldsCodec.With(record.Extensions, new FieldSet(since, [new FieldEntry(field, value, false, at, Claude, [])])),
        };
        File.WriteAllBytes(path, SecretRecordCodec.Encode(record, _key, KeyringFormat.RecordFormatVersion));
    }
}
