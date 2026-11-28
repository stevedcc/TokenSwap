using System.Text;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T65 (#434): <c>redact</c> takes a lone <c>\r</c> as a line break, as T63 decided for the broker and the field
/// check: a stored value whose breaks are all one kind is found whatever mix of <c>\r\n</c>, <c>\n</c> and lone
/// <c>\r</c> the output has; and <c>run</c>'s own forms (<see cref="Redaction.Variants"/>) include the form with every
/// break as a lone <c>\r</c>.
/// </summary>
public class LoneCrRedactionTests
{
    internal static string V2(string eol) => "line-one-secret" + eol + "line-two-secret";

    internal static string V3(string e1, string e2) => "first-line-value" + e1 + "second-line-value" + e2 + "third-line-value";

    private static SecretsDb Db(string value) =>
        new(new Dictionary<string, Secret> { ["s"] = new(value, TestTime.Fixed, TestTime.Fixed, null, null) }) { KeepsPreviousValues = true };

    /// <summary>The rows of the brief's table: stored value, text, <c>redact</c>'s output.</summary>
    internal static readonly (string Stored, string Text, string Redacted)[] Rows =
    [
        (V2("\n"), "x " + V2("\r") + " y", "x [REDACTED: s] y"),
        (V2("\r\n"), "x " + V2("\r") + " y", "x [REDACTED: s] y"),
        (V2("\r"), "x " + V2("\n") + " y", "x [REDACTED: s] y"),
        (V2("\r"), "x " + V2("\r\n") + " y", "x [REDACTED: s] y"),
        (V3("\n", "\n"), "x " + V3("\r", "\r\n") + " y", "x [REDACTED: s] y"),
        (V3("\r", "\r"), "x " + V3("\n", "\r") + " y", "x [REDACTED: s] y"),
        (V2("\n"), "x " + V2("\r\r") + " y", "x " + V2("\r\r") + " y"),
        (V2("\n") + "\n", "x " + V2("\r") + "\r", "x [REDACTED: s]"),
    ];

    public static TheoryData<int> RowNumbers() => [.. Enumerable.Range(1, Rows.Length)];

    [Theory, MemberData(nameof(RowNumbers))]
    public void Redact_MasksAValue_PrintedWithALoneCr(int row)
    {
        var (stored, text, redacted) = Rows[row - 1];

        Assert.Equal(redacted, Redact.RedactContent(text, Db(stored)));
    }

    private static string Base64(string form) => Convert.ToBase64String(Encoding.UTF8.GetBytes(form));

    [Fact]
    public void Variants_HoldTheLoneCrForm()
    {
        var lf = Redaction.Variants(V2("\n"));
        var cr = Redaction.Variants(V2("\r"));

        Assert.Contains(V2("\r"), lf);
        Assert.Contains(Base64(V2("\r")), lf);
        Assert.Contains(V2("\n"), cr);
        Assert.Contains(V2("\r\n"), cr);
        Assert.Contains(Base64(V2("\n")), cr);
        Assert.Contains(Base64(V2("\r\n")), cr);
        Assert.Equal(lf.Count, lf.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(cr.Count, cr.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>A form and its encodings, as <c>Redaction.Variants</c> builds them.</summary>
    private static string[] Enc(string form)
    {
        var b64 = Base64(form);
        var b64Url = b64.Replace('+', '-').Replace('/', '_');
        return [form, b64, b64.TrimEnd('='), b64Url, b64Url.TrimEnd('=')];
    }

    public static TheoryData<string, string[]> TodaysForms() => new()
    {
        { V2("\n"), [V2("\n"), V2("\r\n"), V2("\r")] },
        { V2("\r\n"), [V2("\r\n"), V2("\n"), "line-one-secret\r\r\nline-two-secret", V2("\r")] },
    };

    [Theory, MemberData(nameof(TodaysForms))]
    public void Variants_OfAValueWithoutALoneCr_KeepTodaysForms(string value, string[] forms)
    {
        var expected = forms.SelectMany(Enc).Distinct(StringComparer.Ordinal).ToList();

        Assert.Equal(expected, Redaction.Variants(value));
    }
}
