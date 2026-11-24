using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using Xunit;
using MatchType = TswapCore.MatchType;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 1: <see cref="SecretVariants.For"/> is the one list of variants that both
/// redaction (<c>SecretProcessor.BuildMatchList</c>) and fingerprints are computed from, so a
/// fingerprint scan can never match a different set of strings than today's plaintext matcher.
/// </summary>
public class SecretVariantsTests
{
    /// <summary>Reaches the protected <c>BuildMatchList</c> without widening its visibility.</summary>
    private sealed class MatchListProbe : SecretProcessor
    {
        public static IReadOnlyList<(string Name, MatchType Type, string SearchText)> Build(SecretsDb db) =>
            BuildMatchList(db);

        protected override string GetReplacement(string secretName, MatchType matchType) => "";
    }

    [Fact]
    public void For_Abc_IsPlainAndBase64_WithoutBase64UrlEqualToBase64()
    {
        Assert.Equal([(VariantKind.Plain, "abc"), (VariantKind.Base64, "YWJj")], SecretVariants.For("abc"));
    }

    [Fact]
    public void For_ValueWithWhitespace_HasWhitespaceStrippedVariant()
    {
        Assert.Contains((VariantKind.WhitespaceStripped, "abc"), SecretVariants.For("a b\nc"));
    }

    [Fact]
    public void For_ValueWhoseBase64HasUrlUnsafeCharacters_HasBase64UrlVariant()
    {
        var variants = SecretVariants.For("??>");
        Assert.Contains((VariantKind.Base64, "Pz8+"), variants);
        Assert.Contains((VariantKind.Base64Url, "Pz8-"), variants);
    }

    [Fact]
    public void For_EmptyValue_IsEmpty()
    {
        Assert.Empty(SecretVariants.For(""));
    }

    [Fact]
    public void For_AllWhitespace_HasNoWhitespaceStrippedEntry()
    {
        const string value = " \n\t";
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        Assert.Equal([(VariantKind.Plain, value), (VariantKind.Base64, base64)], SecretVariants.For(value));
    }

    [Fact]
    public void CurrentSetVersion_IsTwo()
    {
        Assert.Equal(2, SecretVariants.CurrentSetVersion);
    }

    // ------------------------------------------------------------------ brief T54 Task 1: form variants

    public static TheoryData<string, (VariantKind, string)[]> FormRows => new()
    {
        { "abc", [(VariantKind.Plain, "abc"), (VariantKind.Base64, "YWJj")] },
        {
            "caf\u00e9",
            [
                (VariantKind.Plain, "caf\u00e9"), (VariantKind.Base64, "Y2Fmw6k="), (VariantKind.Base64Url, "Y2Fmw6k"),
                (VariantKind.NfdPlain, "cafe\u0301"), (VariantKind.NfdBase64, "Y2FmZcyB"),
            ]
        },
        {
            "cafe\u0301",
            [
                (VariantKind.Plain, "cafe\u0301"), (VariantKind.Base64, "Y2FmZcyB"),
                (VariantKind.NfcPlain, "caf\u00e9"), (VariantKind.NfcBase64, "Y2Fmw6k="), (VariantKind.NfcBase64Url, "Y2Fmw6k"),
            ]
        },
        {
            // U+0958 is a composition exclusion: NFC decomposes it, so the decomposed texts come in under the Nfc
            // kinds, and the NFD list adds nothing (its texts are already present).
            "\u0958x",
            [
                (VariantKind.Plain, "\u0958x"), (VariantKind.Base64, "4KWYeA=="), (VariantKind.Base64Url, "4KWYeA"),
                (VariantKind.NfcPlain, "\u0915\u093cx"), (VariantKind.NfcBase64, "4KSV4KS8eA=="), (VariantKind.NfcBase64Url, "4KSV4KS8eA"),
            ]
        },
        {
            "p\u00e4ss w\u00f6rd",
            [
                (VariantKind.Plain, "p\u00e4ss w\u00f6rd"), (VariantKind.WhitespaceStripped, "p\u00e4ssw\u00f6rd"),
                (VariantKind.Base64, "cMOkc3Mgd8O2cmQ="), (VariantKind.Base64Url, "cMOkc3Mgd8O2cmQ"),
                (VariantKind.NfdPlain, "pa\u0308ss wo\u0308rd"), (VariantKind.NfdWhitespaceStripped, "pa\u0308sswo\u0308rd"),
                (VariantKind.NfdBase64, "cGHMiHNzIHdvzIhyZA=="), (VariantKind.NfdBase64Url, "cGHMiHNzIHdvzIhyZA"),
            ]
        },
        {
            // A lone surrogate can't be normalised: the base kinds only.
            "x\uD800y",
            [(VariantKind.Plain, "x\uD800y"), (VariantKind.Base64, "eO+/vXk="), (VariantKind.Base64Url, "eO-_vXk")]
        },
    };

    [Theory]
    [MemberData(nameof(FormRows))]
    public void For_AddsTheNfcAndNfdForms(string value, (VariantKind, string)[] expected)
    {
        Assert.Equal(expected, SecretVariants.For(value));
    }

    [Fact]
    public void BaseKind_MapsEveryFormKindToItsBaseKind_AndLeavesOthers()
    {
        VariantKind[] bases = [VariantKind.Plain, VariantKind.WhitespaceStripped, VariantKind.Base64, VariantKind.Base64Url];
        VariantKind[] all =
        [
            VariantKind.Plain, VariantKind.WhitespaceStripped, VariantKind.Base64, VariantKind.Base64Url,
            VariantKind.NfcPlain, VariantKind.NfcWhitespaceStripped, VariantKind.NfcBase64, VariantKind.NfcBase64Url,
            VariantKind.NfdPlain, VariantKind.NfdWhitespaceStripped, VariantKind.NfdBase64, VariantKind.NfdBase64Url,
        ];
        Assert.Equal([.. bases, .. bases, .. bases], all.Select(k => k.BaseKind()));
        Assert.Equal((VariantKind)200, ((VariantKind)200).BaseKind());
        Assert.Equal((VariantKind)12, ((VariantKind)12).BaseKind());
    }

    [Fact]
    public void VariantKind_FormValues_ArePinned()
    {
        // The byte values are record format: appended, never renumbered.
        Assert.Equal(
            [4, 5, 6, 7, 8, 9, 10, 11],
            new[]
            {
                VariantKind.NfcPlain, VariantKind.NfcWhitespaceStripped, VariantKind.NfcBase64, VariantKind.NfcBase64Url,
                VariantKind.NfdPlain, VariantKind.NfdWhitespaceStripped, VariantKind.NfdBase64, VariantKind.NfdBase64Url,
            }.Select(k => (int)k));
    }

    private static FingerprintSet Set(string value, byte version)
    {
        using var keys = FingerprintKeys.Derive(new byte[32]);
        return Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys) with { VariantSetVersion = version };
    }

    [Fact]
    public void Compute_NonAsciiValue_HasItsFormEntries_AndVersionTwo()
    {
        using var keys = FingerprintKeys.Derive(new byte[32]);
        var computed = Fingerprinter.Compute(Encoding.UTF8.GetBytes("caf\u00e9"), keys);

        Assert.Equal(2, computed.VariantSetVersion);
        Assert.Equal(
            [VariantKind.Plain, VariantKind.Base64, VariantKind.Base64Url, VariantKind.NfdPlain, VariantKind.NfdBase64],
            computed.Entries.Select(e => e.Kind));
    }

    [Theory]
    [InlineData("caf\u00e9", 2, true)]
    [InlineData("abc", 1, true)]
    [InlineData("ab", 1, true)]
    [InlineData("??>", 1, true)]
    [InlineData("caf\u00e9", 1, false)]
    [InlineData("\U0001F600", 1, false)]
    [InlineData("", 1, true)]
    [InlineData("abc", 0, false)]
    public void IsCurrent_VersionTwo_OrAVersionOneSetThatProvesItsValueAscii(string value, byte version, bool expected)
    {
        Assert.Equal(expected, SecretVariants.IsCurrent(Set(value, version)));
    }

    [Fact]
    public void IsCurrent_VersionOneWithoutItsBase64Entry_IsNotCurrent()
    {
        var set = Set("abc", 1);
        var withoutBase64 = set with { Entries = [.. set.Entries.Where(e => e.Kind != VariantKind.Base64)] };

        Assert.True(SecretVariants.IsCurrent(set));
        Assert.False(SecretVariants.IsCurrent(withoutBase64));
    }

    /// <summary>
    /// The property the brief names: for one secret, the (MatchType, SearchText) pairs the redaction
    /// matcher builds are exactly the variants (Plain and WhitespaceStripped map to Plaintext). The
    /// matcher sorts its list, so both sides are compared in one canonical order. Since the matcher
    /// is now built from <see cref="SecretVariants"/>, both are also compared with
    /// <see cref="PinnedMatcherVariants"/>, the inclusion rules <c>BuildMatchList</c> had before
    /// task 1 (copied verbatim), so a change to the variants can't pass by changing both sides.
    /// </summary>
    [Fact]
    public void BuildMatchList_ForOneSecret_EqualsTheMappedVariants()
    {
        var random = new Random(16_01);
        List<string> values = ["\uD800", "line one\nline two\r\n\tline three", "a b", "??>", " ", "abc", "x\uDC00y"];
        const string alphabet = "abcXYZ019+/=-_ \n\r\t?>~é€😀";
        while (values.Count < 200)
        {
            var length = random.Next(0, 40);
            var chars = new char[length];
            for (var i = 0; i < length; i++)
                chars[i] = random.Next(10) == 0 ? (char)random.Next(0xD800, 0xE000) : alphabet[random.Next(alphabet.Length)];
            values.Add(new string(chars));
        }

        foreach (var value in values)
        {
            var db = new SecretsDb(new Dictionary<string, Secret>
            {
                ["s"] = new(value, TestTime.Fixed, TestTime.Fixed),
            });
            var fromMatcher = MatchListProbe.Build(db)
                .Select(e => (e.Type, e.SearchText))
                .Order(PairOrder.Instance)
                .ToList();
            var variants = SecretVariants.For(value);
            var fromVariants = variants
                .Select(v => (Map(v.Kind), v.Text))
                .Order(PairOrder.Instance)
                .ToList();
            var baseVariants = variants
                .Where(v => v.Kind.BaseKind() == v.Kind)
                .Select(v => (Map(v.Kind), v.Text))
                .Order(PairOrder.Instance)
                .ToList();
            var pinned = PinnedMatcherVariants(value).Order(PairOrder.Instance).ToList();
            Assert.Equal(pinned, baseVariants);
            Assert.Equal(PinnedFormVariants(value), variants.Where(v => v.Kind.BaseKind() != v.Kind));
            Assert.Equal(fromVariants, fromMatcher);
        }
    }

    /// <summary>The per-value body of <c>BuildMatchList</c> as it was before T16-S1 task 1.</summary>
    private static List<(MatchType Type, string Text)> PinnedMatcherVariants(string value)
    {
        List<(MatchType Type, string Text)> list = [];
        if (string.IsNullOrEmpty(value)) return list;
        list.Add((MatchType.Plaintext, value));
        var normalised = value.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "");
        if (normalised != value && !string.IsNullOrEmpty(normalised))
            list.Add((MatchType.Plaintext, normalised));
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        if (base64 != value)
            list.Add((MatchType.Base64, base64));
        var base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        if (base64Url != base64 && base64Url != value)
            list.Add((MatchType.Base64Url, base64Url));
        return list;
    }

    /// <summary>
    /// Brief T54 Task 1, written out apart from <see cref="SecretVariants.For"/>: unless the value holds a lone
    /// surrogate, the variants of its NFC form under the Nfc kinds, then those of its NFD form under the Nfd kinds,
    /// each form only when it differs from the value, and each text only when no earlier variant has it.
    /// </summary>
    private static List<(VariantKind Kind, string Text)> PinnedFormVariants(string value)
    {
        List<(VariantKind Kind, string Text)> forms = [];
        if (string.IsNullOrEmpty(value)) return forms;
        for (var i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1])) i++;
            else if (char.IsSurrogate(value[i])) return forms;
        }

        HashSet<string> seen = [.. PinnedKinds(value).Select(v => v.Text)];
        foreach (var (form, offset) in new[] { (value.Normalize(NormalizationForm.FormC), 4), (value.Normalize(NormalizationForm.FormD), 8) })
        {
            if (form == value) continue;
            foreach (var (kind, text) in PinnedKinds(form))
                if (seen.Add(text))
                    forms.Add(((VariantKind)((int)kind + offset), text));
        }
        return forms;
    }

    /// <summary>The base variants of one form with their kinds, by the rule <see cref="PinnedMatcherVariants"/> pins.</summary>
    private static List<(VariantKind Kind, string Text)> PinnedKinds(string form)
    {
        List<(VariantKind Kind, string Text)> list = [(VariantKind.Plain, form)];
        var stripped = form.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "");
        if (stripped != form && stripped.Length > 0)
            list.Add((VariantKind.WhitespaceStripped, stripped));
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(form));
        if (base64 != form)
            list.Add((VariantKind.Base64, base64));
        var base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        if (base64Url != base64 && base64Url != form)
            list.Add((VariantKind.Base64Url, base64Url));
        return list;
    }

    private static MatchType Map(VariantKind kind) => kind.BaseKind() switch
    {
        VariantKind.Plain or VariantKind.WhitespaceStripped => MatchType.Plaintext,
        VariantKind.Base64 => MatchType.Base64,
        VariantKind.Base64Url => MatchType.Base64Url,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private sealed class PairOrder : IComparer<(MatchType Type, string Text)>
    {
        public static readonly PairOrder Instance = new();

        public int Compare((MatchType Type, string Text) a, (MatchType Type, string Text) b)
        {
            var cmp = a.Type.CompareTo(b.Type);
            return cmp != 0 ? cmp : string.CompareOrdinal(a.Text, b.Text);
        }
    }
}
