using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #311, task 1: what a field name and value may be (<see cref="FieldRules"/>), the formats of
/// the well-known fields, and the per-secret caps.
/// </summary>
public sealed class FieldRulesTests
{
    private static readonly byte[] Origin = [.. Enumerable.Repeat((byte)0xA1, 16)];
    private static readonly FieldWho Who = new("a1a1a1a1", "steve", false, false, null);

    private static Stamp At(long ms) => new(new Hlc(ms, 0), Origin);

    [Theory]
    [InlineData("username")]
    [InlineData("a")]
    [InlineData("db_name-2")]
    [InlineData("0123456789012345678901234567890123456789012345678901234567890123")] // 64
    public void Validate_Name_Allowed(string name) =>
        Assert.Null(FieldRules.Validate(name, "x"));

    [Theory]
    [InlineData("Username")]
    [InlineData("a.b")]
    [InlineData("a b")]
    [InlineData("useré")]
    [InlineData("01234567890123456789012345678901234567890123456789012345678901234")] // 65
    [InlineData("")]
    public void Validate_Name_Refused(string name)
    {
        var message = FieldRules.Validate(name, "x");

        Assert.NotNull(message);
        Assert.Contains("field name", message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("line one\nline two")]
    [InlineData("café 中文 \U0001F600")]
    public void ValidateValue_Allowed(string value)
    {
        Assert.Null(FieldRules.ValidateValue(value));
        Assert.Null(FieldRules.Validate("note", value));
    }

    [Theory]
    [InlineData("a\u0000b", "U+0000")]
    [InlineData("a\tb", "U+0009")]
    [InlineData("a\rb", "U+000D")]
    [InlineData("a‎b", "U+200E")]
    [InlineData("a‮b", "U+202E")]
    [InlineData("a​b", "U+200B")]
    [InlineData("ab", "U+E000")]
    [InlineData("a\U000F0000b", "U+F0000")]
    public void ValidateValue_Refused_NamesCodePoint(string value, string codePoint)
    {
        var bare = FieldRules.ValidateValue(value);
        Assert.NotNull(bare);
        Assert.Contains(codePoint, bare);

        var named = FieldRules.Validate("note", value);
        Assert.NotNull(named);
        Assert.Contains(codePoint, named);
        Assert.Contains("'note'", named);
    }

    [Fact]
    public void ValidateValue_LoneSurrogates_Refused()
    {
        // Built in code: xUnit's attribute data turns a lone surrogate into U+FFFD before the test sees it.
        foreach (var (value, codePoint) in new[]
        {
            ("a" + '\uD800' + "b", "U+D800"),
            ("a" + '\uDC00', "U+DC00"),
            // A lone surrogate after another refused character: still a refusal naming it, never an exception.
            ("a\u0000" + '\uD800', "U+D800"),
            ("text \u202E more " + '\uDC00' + " end", "U+DC00"),
        })
        {
            Assert.Contains(codePoint, FieldRules.ValidateValue(value));
            Assert.Contains(codePoint, FieldRules.Validate("note", value));
        }
    }

    [Fact]
    public void NormaliseValue_ComposesToNfc()
    {
        Assert.Equal("café", FieldRules.NormaliseValue("café"));
        Assert.Equal("café", FieldRules.NormaliseValue("café"));
    }

    [Fact]
    public void NormaliseValue_LoneSurrogate_IsLeftForValidateToRefuse()
    {
        Assert.Equal("a\uD800", FieldRules.NormaliseValue("a\uD800"));
        Assert.Equal("a\u0000\uD800", FieldRules.NormaliseValue("a\u0000\uD800"));
        Assert.Contains("U+D800", FieldRules.ValidateValue("a\uD800"));
    }

    [Fact]
    public void ValidateValue_Length_CountsCharactersAfterNfc()
    {
        Assert.Null(FieldRules.ValidateValue(new string('a', 4096)));
        Assert.Contains("4096", FieldRules.ValidateValue(new string('a', 4097)));
        Assert.Contains("4096", FieldRules.Validate("note", new string('a', 4097)));

        // 4096 composed characters written decomposed (8192 UTF-16 units) are still 4096 after NFC.
        Assert.Null(FieldRules.ValidateValue(string.Concat(Enumerable.Repeat("é", 4096))));
        // 4096 emoji are 4096 characters, not 8192.
        Assert.Null(FieldRules.ValidateValue(string.Concat(Enumerable.Repeat("\U0001F600", 4096))));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("token")]
    [InlineData("api-key")]
    [InlineData("private-key")]
    [InlineData("certificate")]
    [InlineData("connection-string")]
    [InlineData("other")]
    public void Validate_Kind_Known(string kind) =>
        Assert.Null(FieldRules.Validate("kind", kind));

    [Theory]
    [InlineData("secret")]
    [InlineData("Password")]
    [InlineData("password ")]
    public void Validate_Kind_Unknown_Refused(string kind)
    {
        var message = FieldRules.Validate("kind", kind);

        Assert.NotNull(message);
        Assert.Contains("'kind'", message);
        Assert.Contains("connection-string", message);
    }

    [Fact]
    public void KnownKinds_AreTheSpecsSeven() =>
        Assert.Equal(["password", "token", "api-key", "private-key", "certificate", "connection-string", "other"], FieldRules.KnownKinds);

    [Theory]
    [InlineData("2027-01-31")]
    [InlineData("2027-01-31T13:10:51Z")]
    [InlineData("2028-02-29")]
    public void Validate_Expires_Allowed(string expires) =>
        Assert.Null(FieldRules.Validate("expires", expires));

    [Theory]
    [InlineData("2027-02-30")]
    [InlineData("2027-02-29")]
    [InlineData("31.01.2027")]
    [InlineData("2027-01-31T13:10:51+01:00")]
    [InlineData("2027-01-31T13:10:51")]
    [InlineData("2027-01-31T13:10Z")]
    [InlineData("2027-01-31 13:10:51Z")]
    [InlineData("2027-1-31")]
    [InlineData("٢٠٢٧-01-31")] // Arabic-Indic digits
    public void Validate_Expires_Refused(string expires)
    {
        var message = FieldRules.Validate("expires", expires);

        Assert.NotNull(message);
        Assert.Contains("'expires'", message);
        Assert.Contains("YYYY-MM-DD", message);
    }

    [Fact]
    public void Validate_OtherFields_TakeAnyValidValue()
    {
        Assert.Null(FieldRules.Validate("kinds", "secret"));
        Assert.Null(FieldRules.Validate("expiry", "31.01.2027"));
    }

    private static FieldEntry Live(int i, string value) => new($"f{i:D3}", value, false, At(10), Who, []);

    private static FieldEntry Marker(int i, params FieldChange[] history) => new($"gone{i:D3}", null, true, At(10), Who, history);

    [Fact]
    public void CheckCaps_FieldCount()
    {
        Assert.Null(FieldRules.CheckCaps(new FieldSet(At(1), [.. Enumerable.Range(0, 64).Select(i => Live(i, "v"))])));

        var message = FieldRules.CheckCaps(new FieldSet(At(1), [.. Enumerable.Range(0, 65).Select(i => Live(i, "v"))]));
        Assert.NotNull(message);
        Assert.Contains("65", message);
        Assert.Contains("64", message);
    }

    /// <summary>A set of 16 live fields whose encoding is exactly <paramref name="size"/> bytes.</summary>
    private static FieldSet OfEncodedSize(int size)
    {
        List<FieldEntry> entries = [.. Enumerable.Range(0, 15).Select(i => Live(i, new string('a', 4000)))];
        var withoutLast = FieldsCodec.Encode(new FieldSet(At(1), [.. entries, Live(15, "")])).Length;
        entries.Add(Live(15, new string('a', size - withoutLast)));
        var set = new FieldSet(At(1), entries);
        Assert.Equal(size, FieldsCodec.Encode(set).Length);
        return set;
    }

    [Fact]
    public void CheckCaps_EncodedSize()
    {
        Assert.Null(FieldRules.CheckCaps(OfEncodedSize(65536)));

        var message = FieldRules.CheckCaps(OfEncodedSize(65537));
        Assert.NotNull(message);
        Assert.Contains("65537", message);
        Assert.Contains("65536", message);
    }

    [Fact]
    public void CheckCaps_DeleteMarkers_CountBytesNotFields()
    {
        FieldEntry[] live = [.. Enumerable.Range(0, 64).Select(i => Live(i, new string('a', 900)))];
        FieldEntry[] smallMarkers = [.. Enumerable.Range(0, 10).Select(i => Marker(i))];
        FieldEntry[] heavyMarkers =
            [.. Enumerable.Range(0, 10).Select(i => Marker(i, new FieldChange(new string('b', 1000), At(5), Who)))];

        var withSmall = new FieldSet(At(1), [.. live, .. smallMarkers]);
        Assert.True(FieldsCodec.Encode(withSmall).Length <= 65536);
        Assert.Null(FieldRules.CheckCaps(withSmall));

        var withHeavy = new FieldSet(At(1), [.. live, .. heavyMarkers]);
        Assert.True(FieldsCodec.Encode(withHeavy).Length > 65536);
        var message = FieldRules.CheckCaps(withHeavy);
        Assert.NotNull(message);
        Assert.Contains("65536", message);
    }

    // ------------------------------------------------------------------ final wave: Escape, the value subject, format refusals

    /// <summary>Both final reviews: an astral character is one Unicode scalar, shown as one <c>U+XXXXX</c>, not two surrogates.</summary>
    [Theory]
    [InlineData("a\U0001F600b", "aU+1F600b")]
    [InlineData("\U000F0000", "U+F0000")]
    [InlineData("x\u202Ey\n", "xU+202EyU+000A")]
    [InlineData("plain-ascii_1", "plain-ascii_1")]
    public void Escape_PerScalar(string text, string escaped) => Assert.Equal(escaped, FieldRules.Escape(text));

    /// <summary>A lone surrogate (not a scalar) is still shown by its code unit. Not as InlineData: xUnit mangles lone surrogates there.</summary>
    [Fact]
    public void Escape_LoneSurrogates_ShownByCodeUnit()
    {
        Assert.Equal("aU+D800b", FieldRules.Escape("a\uD800b"));
        Assert.Equal("U+DC00U+D800", FieldRules.Escape("\uDC00\uD800"));
    }

    /// <summary>GLM final 1: a kind/expires refusal never shows the value given (it may be a secret pasted by mistake).</summary>
    [Theory]
    [InlineData("kind", "Refused field 'kind': the value given is not a known kind (use one of password,")]
    [InlineData("expires", "Refused field 'expires': the value given is not a date; use YYYY-MM-DD")]
    public void Validate_FormatRefusal_DoesNotShowTheValue(string name, string message)
    {
        const string value = "Xq7-pasted-secret-91";

        var refusal = FieldRules.Validate(name, value);

        Assert.NotNull(refusal);
        Assert.StartsWith(message, refusal);
        Assert.DoesNotContain(value, refusal);
    }

    /// <summary>MiMo final 2 / GLM final 2: the subject names what is checked, a field value or a <c>--by</c> label.</summary>
    [Fact]
    public void ValidateValue_Subject_NamesALabel()
    {
        Assert.Equal("The value contains U+001B (a control character); a field holds no control, format, surrogate or " +
            "private-use characters other than a line feed.", FieldRules.ValidateValue("a\u001bb"));
        Assert.Equal("The label contains U+001B (a control character); a label holds no control, format, surrogate or " +
            "private-use characters other than a line feed.", FieldRules.ValidateValue("a\u001bb", FieldRules.ValueSubject.Label));
    }
}
