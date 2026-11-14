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
    public void CurrentSetVersion_IsOne()
    {
        Assert.Equal(1, SecretVariants.CurrentSetVersion);
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
            var fromVariants = SecretVariants.For(value)
                .Select(v => (Map(v.Kind), v.Text))
                .Order(PairOrder.Instance)
                .ToList();
            var pinned = PinnedMatcherVariants(value).Order(PairOrder.Instance).ToList();
            Assert.Equal(pinned, fromVariants);
            Assert.Equal(fromVariants, fromMatcher);
        }
    }

    /// <summary>The per-value body of <c>BuildMatchList</c> as it was before T16-S1 task 1.</summary>
    private static List<(MatchType Type, string Text)> PinnedMatcherVariants(string value)
    {
        List<(MatchType Type, string Text)> list = [];
        if (string.IsNullOrEmpty(value)) return list;
        list.Add((MatchType.Plaintext, value));
        var normalized = value.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "");
        if (normalized != value && !string.IsNullOrEmpty(normalized))
            list.Add((MatchType.Plaintext, normalized));
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        if (base64 != value)
            list.Add((MatchType.Base64, base64));
        var base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        if (base64Url != base64 && base64Url != value)
            list.Add((MatchType.Base64Url, base64Url));
        return list;
    }

    private static MatchType Map(VariantKind kind) => kind switch
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
