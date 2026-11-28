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
/// multi-line values across lines (4). Two later engine-only differences in <c>tocomment</c> are not in
/// the oracle either: brief T20 adopts a YAML literal block scalar whose content is one stored value's
/// plain form, and brief T22 leaves a block-scalar content line holding an encoded form (base64,
/// base64url, whitespace-stripped) of a value unchanged (<see cref="ToCommentBlockScalarTests"/>). Brief T63 adds
/// a third: <c>tocomment</c> comments out a continuation line holding a value, where the oracle removes it. The fixed
/// seed produces no such line; if a seed or corpus change does, apply the owner-sanctioned T63 rule written in brief
/// T63 (Task 1, "Oracle") to <c>PlaintextRedactOracle</c>: a continuation candidate that holds a value is commented out
/// (or kept in block content), never removed.
/// </summary>
public class RedactEngineTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private static Secret S(string value, bool burned = false, string? previous = null, bool previousBurned = false) =>
        new(value, TestTime.Fixed, TestTime.Fixed, burned ? TestTime.Fixed : null, burned ? "test" : null)
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
        // Brief T30: 'a' has 8 characters (a shorter value is matched only as a whole word).
        var db = Db(("a", S("hello123")), ("b", S("]x")));
        Assert.Equal("[REDACTED: a[REDACTED: b]", PlaintextRedactOracle.RedactContent("hello123x", db)); // today
        Assert.Equal("[REDACTED: a]x", Redact.RedactContent("hello123x", db));
    }

    [Fact]
    public void ToComment_SecretInsideAnInsertedMarker_NotReplaced()
    {
        var db = Db(("s1", S("abcdefgh")), ("s2", S("tswap")));
        // Before T50: the oracle then matched "tswap" inside the inserted marker and rewrote it to
        // 'k: ""  # ""  # tswap: s2: s1'; since T50b it keeps a match holding inserted text as it is.
        Assert.Equal("k: \"\"  # tswap: s1", PlaintextRedactOracle.ToComment("k: abcdefgh", db).Content);
        var (content, changes) = Redact.ToComment("k: abcdefgh", db);
        Assert.Equal("k: \"\"  # tswap: s1", content);
        ToCommentRoundTrip.Check(changes, db); // brief T50b Task 2
    }

    [Fact]
    public void ToComment_AdjacentSecrets_UseOriginalNeighbours()
    {
        // "beta2." is followed by 'a' in the original line, so it is no separate value there. Before T50: the
        // oracle matched it against the '"' of the marker inserted for "alpha12" ('k: ""  # tswap: b""  # tswap: a')
        // and the engine gave 'k: beta2.""  # tswap: a'. Since T50b "alpha12" is no whole value either (rule (a):
        // the text before it ends in '.'), so neither engine changes the line.
        var db = Db(("a", S("alpha12")), ("b", S("beta2.")));
        Assert.Equal("k: beta2.alpha12", PlaintextRedactOracle.ToComment("k: beta2.alpha12", db).Content);
        var (content, changes) = Redact.ToComment("k: beta2.alpha12", db);
        Assert.Equal("k: beta2.alpha12", content);
        ToCommentRoundTrip.Check(changes, db); // brief T50b Task 2
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
    /// that are prefixes of each other. The corpus is not constrained by the T20 and T22 differences:
    /// it can in principle produce a block start (<c>key: |+</c> say) followed by a deeper line holding a
    /// value or an encoded form; the fixed seed produces no such case, and a seed that did would fail
    /// here by design, not by a fault in either engine.
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
        // Code review (GLM B-6, MiMo B-M5): each counter proves the case it names happened in an output.
        var counts = new Dictionary<string, int>
        {
            ["redact-hits"] = 0, ["tocomment-hits"] = 0, ["previous-masked"] = 0, ["burned-masked"] = 0,
            ["burned-vs-live-tie"] = 0, ["astral-value-masked"] = 0, ["astral-next-to-a-masked-value"] = 0,
        };

        for (var round = 0; round < 250; round++)
        {
            string Value(int min, int max) => string.Concat(Enumerable.Range(0, random.Next(min, max)).Select(_ => alphabet[random.Next(alphabet.Length)]));
            List<string> values = [];
            var secrets = new List<(string Name, Secret Secret)>();
            var count = random.Next(1, 7);
            for (var i = 0; i < count; i++)
            {
                var value = random.Next(5) switch
                {
                    0 when values.Count > 0 => values[random.Next(values.Count)],                       // equal values
                    1 when values.Count > 0 => values[random.Next(values.Count)] + Value(1, 4),         // a prefix of another
                    _ => Value(8, 16), // brief T30: the oracle matches anywhere, so it can only judge long values
                };
                values.Add(value);
                string? previous = random.Next(3) == 0 ? (random.Next(2) == 0 && values.Count > 1 ? values[random.Next(values.Count)] : Value(8, 14)) : null;
                if (previous is not null) values.Add(previous);
                var burned = random.Next(3) == 0;
                secrets.Add(($"k{(char)('m' + i)}", S(value, burned, previous, previousBurned: previous is not null && random.Next(2) == 0)));
            }
            var db = Db([.. secrets]);
            var forms = values.SelectMany(v => SecretVariants.For(v).Select(x => x.Text)).ToList();

            var text = new StringBuilder();
            List<string> nextToEmoji = []; // forms placed with an emoji directly before or after them
            for (var part = random.Next(3, 14); part > 0; part--)
            {
                text.Append(filler[random.Next(filler.Length)]);
                if (random.Next(3) > 0)
                {
                    var quote = quotes[random.Next(quotes.Length)];
                    var before = separators[random.Next(separators.Length)];
                    var form = forms[random.Next(forms.Count)];
                    var after = separators[random.Next(separators.Length)];
                    text.Append(before).Append(quote).Append(form).Append(quote).Append(after);
                    if (quote == "" && (char.IsLowSurrogate(before[^1]) || char.IsHighSurrogate(after[0])))
                        nextToEmoji.Add(form);
                }
            }
            var content = text.ToString();

            var expected = PlaintextRedactOracle.RedactContent(content, db);
            Assert.True(expected == Redact.RedactContent(content, db), $"round {round}, redact:\n{content}");
            var (oracleContent, oracleChanges) = PlaintextRedactOracle.ToComment(content, db);
            var (engineContent, engineChanges) = Redact.ToComment(content, db);
            Assert.True(oracleContent == engineContent, $"round {round}, tocomment:\n{content}");
            Assert.Equal(oracleChanges, engineChanges);

            bool Masked(string form) => content.Contains(form) && !expected.Contains(form);
            bool Labelled(string token) => expected.Contains($"[REDACTED: {token}]") || expected.Contains($"[REDACTED: {token} (");
            if (expected != content.Replace("\r\n", "\n")) counts["redact-hits"]++;
            // Brief T50b (owner decision 2): a round in which the engine found an occurrence, replaced or skipped
            // (the whole-value rule makes replacements rare here, most placements being followed by more text).
            var report = Redact.ToCommentReport(content, db);
            if (report.Changes.Count + report.Skipped.Count > 0) counts["tocomment-hits"]++;
            if (secrets.Any(s => s.Secret.PreviousValue is not null && Labelled(s.Name + ":previous"))) counts["previous-masked"]++;
            if (secrets.Any(s => s.Secret.BurnedAt is not null && Labelled(s.Name))) counts["burned-masked"]++;
            // A form held by a burned secret's current value and by a live token, present in the text:
            // the burn state decided the label.
            var burnedForms = secrets.Where(s => s.Secret.BurnedAt is not null)
                .SelectMany(s => SecretVariants.For(s.Secret.Value).Select(v => v.Text)).ToHashSet();
            var liveForms = secrets.Where(s => s.Secret.BurnedAt is null).SelectMany(s => SecretVariants.For(s.Secret.Value))
                .Concat(secrets.Where(s => s.Secret.PreviousValue is not null).SelectMany(s => SecretVariants.For(s.Secret.PreviousValue!)))
                .Select(v => v.Text).ToHashSet();
            if (burnedForms.Any(f => liveForms.Contains(f) && Masked(f))) counts["burned-vs-live-tie"]++;
            if (values.Any(v => v.Any(char.IsSurrogate) && Masked(v))) counts["astral-value-masked"]++;
            if (nextToEmoji.Any(Masked)) counts["astral-next-to-a-masked-value"]++;
        }

        output.WriteLine(string.Join(", ", counts.Select(c => $"{c.Key} = {c.Value}")));
        Assert.All(counts, c => Assert.True(c.Value > 20, $"generator: {c.Key} = {c.Value}"));
    }
}
