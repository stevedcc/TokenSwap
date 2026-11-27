using System.Text;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T63 (#412): the no-secret-in-a-field check finds a stored multi-line value whatever line breaks the field value
/// or the stored value has (<c>\r\n</c>, <c>\n</c> or a lone <c>\r</c>): the field value is scanned in its NFC form and as
/// given, each also with its line breaks written as LF, CRLF and CR. The fixture is <see cref="FieldSecretCheckTests"/>'.
/// </summary>
public sealed class FieldSecretCheckLineBreakTests : IDisposable
{
    private const string Expected =
        "Refused: the value for 'grafana.username' contains a stored secret value. Fields are visible; a secret never goes in one.";

    private const string CafeNfc = "café-line-one\r\ncafé-line-two";

    private static readonly FieldWho Claude = new("a1a1a1a1", "steve", Elevated: false, Terminal: false, By: "claude");

    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m;
    private readonly byte[] _key;
    private readonly FingerprintKeys _keys;

    public FieldSecretCheckLineBreakTests()
    {
        _m = new FleetMachine("field-secret-line-break", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
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

    private static (string Stored, string Checked, bool Refused) Row(int row) => row switch
    {
        1 => ("line-one-secret\r\nline-two-secret", "line-one-secret\nline-two-secret", true),
        2 => ("line-one-secret\r\nline-two-secret", "note: line-one-secret\nline-two-secret, see vault", true),
        3 => ("line-one-secret\r\nline-two-secret", "line-one-secret\nline-two-secreT", false),
        4 => ("line-one-secret\nline-two-secret", "line-one-secret\r\nline-two-secret", true),
        5 => ("line-one-secret\rline-two-secret", "line-one-secret\nline-two-secret", true),
        6 => (CafeNfc, CafeNfc.Normalize(NormalizationForm.FormD).Replace("\r\n", "\n"), true),
        _ => throw new ArgumentOutOfRangeException(nameof(row)),
    };

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public void Refusal_FindsAStoredValue_WhateverItsLineBreaks(int row)
    {
        var (stored, checkedValue, refused) = Row(row);
        _m.Ok(stored, "ingest", "pem");

        Assert.Equal(refused ? Expected : null, Check(checkedValue));
    }

    [Fact]
    public void Holders_FindAStoredValue_WhateverItsLineBreaks()
    {
        _m.Ok("line-one-secret\r\nline-two-secret", "ingest", "pem");

        Assert.Equal([new FieldSecretCheck.SecretHolder("pem", false)],
            FieldSecretCheck.Holders(Stored(), "line-one-secret\nline-two-secret"));
    }

    [Fact]
    public void FieldsContaining_FindsAFieldValue_WhateverItsLineBreaks()
    {
        _m.Ok("another-value-0123456", "ingest", "s");
        SetFields("s", new FieldEdit("note", "line-one-secret\nline-two-secret"));

        using var view = View();

        Assert.Equal(["s.note"], FieldSecretCheck.FieldsContaining(view, SameWrite("line-one-secret\r\nline-two-secret")));
    }
}
