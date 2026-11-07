using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 6: the fingerprint engine behind <c>redact</c> and <c>tocomment</c>
/// (<see cref="SecretMatcher"/>). It finds values from their fingerprints only, selects in today's
/// priority order over the original text, and differs from the plaintext engine
/// (<see cref="PlaintextRedactOracle"/>) exactly where the plan lists: no match inside text tswap
/// inserted (difference 2), tocomment's context from the original neighbours (3), and redact masks
/// multi-line values across lines (4).
/// </summary>
public class RedactEngineTests
{
    private static Secret S(string value, bool burned = false, string? previous = null, bool previousBurned = false) =>
        new(value, DateTime.UtcNow, DateTime.UtcNow, burned ? DateTime.UtcNow : null, burned ? "test" : null)
        {
            PreviousValue = previous,
            PreviousBurned = previousBurned,
        };

    private static SecretsDb Db(params (string Name, Secret Secret)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => s.Secret)) { KeepsPreviousValues = true };

    [Fact]
    public void Redact_SecretInsideAnInsertedLabel_NotReplaced()
    {
        var db = Db(("s1", S("abcdefgh")), ("s2", S("RED")));
        Assert.Equal("x [[REDACTED: s2]ACTED: s1] [REDACTED: s2]", PlaintextRedactOracle.RedactContent("x abcdefgh RED", db)); // today
        Assert.Equal("x [REDACTED: s1] [REDACTED: s2]", Redact.RedactContent("x abcdefgh RED", db));
    }

    /// <summary>
    /// Code review (MiMo A M-1), difference 2 "inside or across": a value that exists only across the
    /// edge of an inserted label (its "]" plus the original "x") was masked by the plaintext engine and
    /// is not now. The output holds nothing from the vault: every character comes from the input or
    /// from the label, so nothing is revealed that the reader can't build from them.
    /// </summary>
    [Fact]
    public void Redact_SecretAcrossAnInsertedLabel_NotReplaced()
    {
        var db = Db(("a", S("hello")), ("b", S("]x")));
        Assert.Equal("[REDACTED: a[REDACTED: b]", PlaintextRedactOracle.RedactContent("hellox", db)); // today
        Assert.Equal("[REDACTED: a]x", Redact.RedactContent("hellox", db));
    }

    [Fact]
    public void ToComment_SecretInsideAnInsertedMarker_NotReplaced()
    {
        var db = Db(("s1", S("abcdefgh")), ("s2", S("tswap")));
        Assert.NotEqual("k: \"\"  # tswap: s1", PlaintextRedactOracle.ToComment("k: abcdefgh", db).Content); // today: the marker is rewritten
        Assert.Equal("k: \"\"  # tswap: s1", Redact.ToComment("k: abcdefgh", db).Content);
    }

    [Fact]
    public void ToComment_AdjacentSecrets_UseOriginalNeighbours()
    {
        // "beta2." is followed by 'a' in the original line, so it is no separate value there; today it
        // was matched against the '"' of the marker inserted for "alpha12".
        var db = Db(("a", S("alpha12")), ("b", S("beta2.")));
        Assert.Equal("k: \"\"  # tswap: b\"\"  # tswap: a", PlaintextRedactOracle.ToComment("k: beta2.alpha12", db).Content);
        Assert.Equal("k: beta2.\"\"  # tswap: a", Redact.ToComment("k: beta2.alpha12", db).Content);
    }

    [Fact]
    public void Redact_MultiLineValue_MaskedAcrossLines()
    {
        const string pem = "-----BEGIN KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END KEY-----";
        var db = Db(("pem", S(pem)));
        var content = "key: |\n" + pem + "\nnext: 1\n";
        Assert.Equal(content, PlaintextRedactOracle.RedactContent(content, db)); // today: no line holds the whole value
        Assert.Equal("key: |\n[REDACTED: pem]\nnext: 1\n", Redact.RedactContent(content, db));
        Assert.Equal("key: |\n[REDACTED: pem]\nnext: 1\n", Redact.RedactContent(content.Replace("\n", "\r\n"), db));
    }

    [Fact]
    public void Label_MatchesTodaysLabels()
    {
        Assert.Equal("[REDACTED: db]", RedactProcessor.Label("db", VariantKind.Plain));
        Assert.Equal("[REDACTED: db]", RedactProcessor.Label("db", VariantKind.WhitespaceStripped));
        Assert.Equal("[REDACTED: db (base64)]", RedactProcessor.Label("db", VariantKind.Base64));
        Assert.Equal("[REDACTED: db (base64url)]", RedactProcessor.Label("db", VariantKind.Base64Url));
        Assert.Equal("[REDACTED: db:previous]", RedactProcessor.Label("db:previous", VariantKind.Plain));
        Assert.Equal("[REDACTED: db:previous]", RedactProcessor.Label("db:previous", VariantKind.WhitespaceStripped));
        Assert.Equal("[REDACTED: db:previous (base64)]", RedactProcessor.Label("db:previous", VariantKind.Base64));
        Assert.Equal("[REDACTED: db:previous (base64url)]", RedactProcessor.Label("db:previous", VariantKind.Base64Url));
    }

    /// <summary>
    /// The fingerprint engine against the plaintext oracle on a seeded random corpus. The corpus is
    /// constrained by differences 2-4 only: secrets come from an alphabet sharing no character with
    /// the inserted texts and are placed with a separator between any two (2, 3), and contain no CR
    /// or LF (4). Texts span lines, use CRLF, and hold astral-plane characters next to and inside
    /// secrets (difference 5 needs no exclusion: neither engine matches a split surrogate pair).
    /// The secrets include burned ones, previous values, equal values under two names and values
    /// that are prefixes of each other.
    /// </summary>
    [Fact]
    public void Engine_MatchesOracle_OnRandomCorpus()
    {
        var random = new Random(16_26);
        // No character of "[REDACTED: ", "]", " (base64)", " (base64url)", "\"\"  # tswap: ", ":previous"
        // or the names (lowercase k, m, n, v, x, y, z) is in this alphabet.
        string[] alphabet = [.. "FGHIJKLMNOQVWXYZ0123579!%&*+/=?@^_|~".Select(c => c.ToString()), "😀", "🔑", "é"];
        string[] separators = [" ", ", ", "\n", "\r\n", "; ", "😀", " 🔑 ", "\t"];
        string[] quotes = ["", "", "\"", "'"];
        string[] filler = ["key: ", "x=", "# note ", "zz", "\n", "\r\n", "   ", "😀", "k: \"\"  # tswap: mm\n", "--", "yy-", "{\"v\": "];
        var counts = new Dictionary<string, int> { ["redact-hits"] = 0, ["tocomment-hits"] = 0, ["previous"] = 0, ["burned"] = 0, ["astral"] = 0 };

        for (var round = 0; round < 250; round++)
        {
            string Value(int min, int max) => string.Concat(Enumerable.Range(0, random.Next(min, max)).Select(_ => alphabet[random.Next(alphabet.Length)]));
            var values = new List<string>();
            var secrets = new List<(string Name, Secret Secret)>();
            var count = random.Next(1, 7);
            for (var i = 0; i < count; i++)
            {
                var value = random.Next(5) switch
                {
                    0 when values.Count > 0 => values[random.Next(values.Count)],                       // equal values
                    1 when values.Count > 0 => values[random.Next(values.Count)] + Value(1, 4),         // a prefix of another
                    _ => Value(2, 12),
                };
                values.Add(value);
                string? previous = random.Next(3) == 0 ? (random.Next(2) == 0 && values.Count > 1 ? values[random.Next(values.Count)] : Value(2, 10)) : null;
                if (previous is not null) values.Add(previous);
                var burned = random.Next(3) == 0;
                secrets.Add(($"k{(char)('m' + i)}", S(value, burned, previous, previousBurned: previous is not null && random.Next(2) == 0)));
            }
            var db = Db([.. secrets]);
            var forms = values.SelectMany(v => SecretVariants.For(v).Select(x => x.Text)).ToList();

            var text = new StringBuilder();
            for (var part = random.Next(3, 14); part > 0; part--)
            {
                text.Append(filler[random.Next(filler.Length)]);
                if (random.Next(3) > 0)
                {
                    var quote = quotes[random.Next(quotes.Length)];
                    text.Append(separators[random.Next(separators.Length)])
                        .Append(quote).Append(forms[random.Next(forms.Count)]).Append(quote)
                        .Append(separators[random.Next(separators.Length)]);
                }
            }
            var content = text.ToString();

            var expected = PlaintextRedactOracle.RedactContent(content, db);
            Assert.True(expected == Redact.RedactContent(content, db), $"round {round}, redact:\n{content}");
            var (oracleContent, oracleChanges) = PlaintextRedactOracle.ToComment(content, db);
            var (engineContent, engineChanges) = Redact.ToComment(content, db);
            Assert.True(oracleContent == engineContent, $"round {round}, tocomment:\n{content}");
            Assert.Equal(oracleChanges, engineChanges);

            if (expected != content.Replace("\r\n", "\n")) counts["redact-hits"]++;
            if (oracleChanges.Count > 0) counts["tocomment-hits"]++;
            if (secrets.Any(s => s.Secret.PreviousValue is not null) && expected.Contains(":previous")) counts["previous"]++;
            if (secrets.Any(s => s.Secret.BurnedAt is not null)) counts["burned"]++;
            if (values.Any(v => v.Any(char.IsSurrogate)) && expected != content.Replace("\r\n", "\n")) counts["astral"]++;
        }

        Assert.All(counts, c => Assert.True(c.Value > 20, $"generator: {c.Key} = {c.Value}"));
    }
}
