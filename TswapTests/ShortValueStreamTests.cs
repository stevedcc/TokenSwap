using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RedactingPty;
using TswapCli;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T30 (#314): <c>run</c>'s stream matching of short values (under 8 characters) as whole words only,
/// however the output is chunked. Through RedactingPty's real <see cref="StreamRedactor"/>, as
/// <see cref="FingerprintStreamMatcherTests"/> does. The window's edges count as boundaries; the right
/// edge is decided by the next window (the occurrence is held), and the pending point never splits a word
/// it can hold (<see cref="TokenBoundary.HoldOutsideWord"/>), so the next window starts on a word's start.
/// </summary>
public class ShortValueStreamTests(ITestOutputHelper output)
{
    private const string LongValue = "long-secret-value-1";

    private static FingerprintKeys NewKeys() => FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));

    private static FingerprintSet Set(string value, FingerprintKeys keys) =>
        Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys);

    private static RecordMetadata Record(string name, FingerprintSet? current, FingerprintSet? previous = null) =>
        new(RandomNumberGenerator.GetBytes(32), Stamp.Zero, RecordType.Value, Stamp.Zero, name, 0, [], current,
            previous is null ? null : Stamp.Zero, previous, []);

    private static VaultMetadata Vault(params RecordMetadata[] records) => new(records, 0, 0, []);

    /// <summary>
    /// Issue #343: a fresh matcher per run, so no run reuses the carried scan state another run left behind.
    /// </summary>
    private static string Redacted(Func<FingerprintStreamMatcher> newMatcher, IEnumerable<string> chunks)
    {
        using var matcher = newMatcher();
        var redactor = new StreamRedactor([], [matcher]);
        var sb = new StringBuilder();
        foreach (var chunk in chunks)
            sb.Append(redactor.ProcessChunk(chunk));
        return sb.Append(redactor.Flush()).ToString();
    }

    private static IEnumerable<string> Chunk(string text, int size)
    {
        for (var i = 0; i < text.Length; i += size)
            yield return text.Substring(i, Math.Min(size, text.Length - i));
    }

    /// <summary>Two chunks cut at every position, and one character at a time: each joined output is <paramref name="expected"/>.</summary>
    private static void AssertEveryCut(Func<FingerprintStreamMatcher> newMatcher, string text, string expected)
    {
        for (var cut = 0; cut <= text.Length; cut++)
            Assert.True(expected == Redacted(newMatcher, [text[..cut], text[cut..]]), $"cut at {cut}: {Redacted(newMatcher, [text[..cut], text[cut..]])}");
        Assert.Equal(expected, Redacted(newMatcher, Chunk(text, 1)));
    }

    private static List<FingerprintHit> Scan(FingerprintScanner scanner, string text)
    {
        List<FingerprintHit> hits = [];
        scanner.Scan(text, hits);
        return hits;
    }

    // ── the scanner ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Scanner_WholeToken_DropsShortHitsInsideWords()
    {
        using var keys = NewKeys();
        List<(string, bool, FingerprintSet)> sets = [("p", false, Set("465", keys)), ("long", false, Set(LongValue, keys))];
        const string text = "65465 465 x" + LongValue + "x";

        Assert.Equal(
            [new FingerprintHit("p", false, VariantKind.Plain, 6, 3), new FingerprintHit("long", false, VariantKind.Plain, 11, LongValue.Length)],
            Scan(FingerprintScanner.Build(sets, keys, ShortValueMatching.WholeToken), text));
        Assert.Equal(
            [new FingerprintHit("p", false, VariantKind.Plain, 2, 3), new FingerprintHit("p", false, VariantKind.Plain, 6, 3),
             new FingerprintHit("long", false, VariantKind.Plain, 11, LongValue.Length)],
            Scan(FingerprintScanner.Build(sets, keys), text));
    }

    [Fact]
    public void Scanner_WholeToken_ShortTwinOfALongValue_LongStillFound()
    {
        using var keys = NewKeys();
        // a-short's base64 is exactly b-long's value; a-short is first in tie order and rejected inside the word.
        var scanner = FingerprintScanner.Build(
            [("a-short", false, Set("1234567", keys)), ("b-long", false, Set("MTIzNDU2Nw==", keys))], keys, ShortValueMatching.WholeToken);

        Assert.Equal(new FingerprintHit("b-long", false, VariantKind.Plain, 1, 12), Assert.Single(Scan(scanner, "xMTIzNDU2Nw== ")));
    }

    // ── the matcher through the real redactor ────────────────────────────────────────

    [Theory]
    [InlineData("65465 1465 4650", "65465 1465 4650")]
    [InlineData("port=465", "port=[REDACTED: p]")]
    [InlineData("465 ok", "[REDACTED: p] ok")]
    [InlineData("port=4655\n", "port=4655\n")]
    [InlineData("{\"port\":\"465\"}", "{\"port\":\"[REDACTED: p]\"}")]
    public void Matcher_ShortValue_EveryCut(string input, string expected)
    {
        using var keys = NewKeys();
        FingerprintStreamMatcher NewMatcher() =>
            FingerprintStreamMatcher.For(Vault(Record("p", Set("465", keys)), Record("long", Set(LongValue, keys))), keys);

        AssertEveryCut(NewMatcher, input, expected);
    }

    [Fact]
    public void Matcher_LongJsonLine_EveryChunkSize_Unchanged()
    {
        using var keys = NewKeys();
        FingerprintStreamMatcher NewMatcher() =>
            FingerprintStreamMatcher.For(Vault(Record("p", Set("465", keys)), Record("long", Set(LongValue, keys))), keys);
        var line = "{\"n\":[" + string.Join(",", Enumerable.Repeat("65465", 1200)) + "]}";

        for (var size = 1; size <= 300; size++)
        {
            var redacted = Redacted(NewMatcher, Chunk(line, size));
            Assert.True(line == redacted, $"chunk size {size}");
        }
        using (JsonDocument.Parse(line)) { }
    }

    private static readonly Dictionary<string, string> WebForms = new(StringComparer.Ordinal)
    {
        ["web"] = "[REDACTED: user]",
        ["d2Vi"] = "[REDACTED: user]",
        ["a\"b"] = "[REDACTED: q]",
    };

    [Fact]
    public void Matcher_ShortForms_WholeTokenOnly()
    {
        using var keys = NewKeys();
        FingerprintStreamMatcher NewMatcher() => FingerprintStreamMatcher.For(Vault(), keys, WebForms);
        using var matcher = NewMatcher();

        Assert.True(matcher.MaxMatchLength >= 4);
        AssertEveryCut(NewMatcher,
            "web-ngx /home/webster user=web b64=d2Vi xd2Vi q=a\"b ok",
            "web-ngx /home/webster user=[REDACTED: user] b64=[REDACTED: user] xd2Vi q=[REDACTED: q] ok");
    }

    /// <summary>
    /// Amendment A2: the short forms' hold is quantised like the scanner's caps, so two matchers whose
    /// longest short forms differ but round up to the same multiple of 256 hold back the same amount of
    /// every text: the hold says nothing about a substituted value's length.
    /// </summary>
    [Fact]
    public void Matcher_ShortFormsHold_DependsOnTextOnly()
    {
        var rng = new Random(3030);
        using var keys = NewKeys();
        var a = FingerprintStreamMatcher.For(Vault(), keys, new Dictionary<string, string> { ["abc"] = "[REDACTED: a]" });
        var b = FingerprintStreamMatcher.For(Vault(), keys, new Dictionary<string, string>
        {
            ["xy"] = "[REDACTED: b]",
            [new string('z', 40)] = "[REDACTED: b]",
        });

        for (var i = 0; i < 500; i++)
        {
            var text = RandomString(rng, rng.Next(0, 700), Filler + Word);
            Assert.Equal(a.PendingFrom(text), b.PendingFrom(text));
        }
    }

    // ── random property ──────────────────────────────────────────────────────────────

    private const string Word = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string Filler = "abc xyz 019 +/= -_ .:\n\r\t";
    private const string ShortAlphabet = Word + "-_";

    private static string RandomString(Random rng, int length, string alphabet)
    {
        var chars = new char[length];
        for (var i = 0; i < length; i++)
            chars[i] = alphabet[rng.Next(alphabet.Length)];
        return new string(chars);
    }

    /// <summary>
    /// Property: for vaults of short values (1 to 7 characters of letters, digits, <c>-</c> and <c>_</c>) and
    /// long ones (each starting with <c>!</c>, so no short form starts where a long occurrence does), current
    /// and previous, plus short forms, on texts with no run of word characters longer than 200 and no astral
    /// character, the output chunked (every size 1 to 64, and 20 random cut lists) equals the one-chunk output.
    /// </summary>
    [Fact]
    public void Matcher_RandomText_ChunkedEqualsWhole()
    {
        var rng = new Random(30_314);
        string[] separators = [" ", ", ", "\n", "\r\n", "; ", "=", ":", "\"", "/", ".", "(", ")", "\t"];
        int labelled = 0, insideWord = 0;
        for (var round = 0; round < 60; round++)
        {
            using var keys = NewKeys();
            List<string> shortValues = [];
            List<string> longValues = [];
            List<RecordMetadata> records = [];
            for (var n = rng.Next(1, 5); n > 0; n--)
            {
                var current = rng.Next(3) == 0 ? "!" + RandomString(rng, rng.Next(8, 16), ShortAlphabet) : RandomString(rng, rng.Next(1, 8), ShortAlphabet);
                string? previous = rng.Next(3) == 0 ? RandomString(rng, rng.Next(1, 8), ShortAlphabet) : null;
                (current.StartsWith('!') ? longValues : shortValues).Add(current);
                if (previous is not null) shortValues.Add(previous);
                records.Add(Record($"v{records.Count}", Set(current, keys), previous is null ? null : Set(previous, keys)));
            }
            Dictionary<string, string> shortForms = new(StringComparer.Ordinal);
            for (var n = rng.Next(0, 3); n > 0; n--)
            {
                var value = RandomString(rng, rng.Next(1, 8), ShortAlphabet);
                shortValues.Add(value);
                foreach (var variant in Redaction.Variants(value))
                    shortForms.TryAdd(variant, $"[REDACTED: f{shortForms.Count}]");
            }
            FingerprintStreamMatcher NewMatcher() => FingerprintStreamMatcher.For(Vault([.. records]), keys, shortForms);

            List<string> pieces = [.. shortValues.SelectMany(v => SecretVariants.For(v).Select(x => x.Text)), .. longValues];
            var text = new StringBuilder();
            var run = 0; // the current run of word characters
            void Append(string s)
            {
                foreach (var c in s)
                {
                    run = TokenBoundary.IsWordChar(c) ? run + 1 : 0;
                    if (run > 200) { text.Append(' '); run = 1; }
                    text.Append(c);
                }
            }
            for (var part = rng.Next(5, 40); part > 0; part--)
            {
                switch (rng.Next(4))
                {
                    case 0: Append(separators[rng.Next(separators.Length)]); break;
                    case 1: Append(RandomString(rng, rng.Next(1, 12), ShortAlphabet)); break;
                    default: Append(pieces[rng.Next(pieces.Count)]); break;
                }
                if (rng.Next(2) == 0) Append(separators[rng.Next(separators.Length)]);
            }
            var content = text.ToString();

            var whole = Redacted(NewMatcher, [content]);
            for (var size = 1; size <= 64; size++)
                Assert.True(whole == Redacted(NewMatcher, Chunk(content, size)), $"round {round}, size {size}:\n{content}");
            for (var list = 0; list < 20; list++)
            {
                var cuts = Enumerable.Range(0, rng.Next(1, 8)).Select(_ => rng.Next(0, content.Length + 1)).Append(0).Append(content.Length)
                    .Distinct().Order().ToList();
                var chunks = cuts.Zip(cuts.Skip(1), (from, to) => content[from..to]).ToList();
                Assert.True(whole == Redacted(NewMatcher, chunks), $"round {round}, cuts {string.Join(",", cuts)}:\n{content}");
            }

            if (ShortLabelled(whole, records, shortForms)) labelled++;
            if (ShortInsideWord(whole, shortValues)) insideWord++;
        }

        output.WriteLine($"short-labelled = {labelled}, short-inside-a-word = {insideWord}");
        Assert.True(labelled > 20, $"generator: short-labelled = {labelled}");
        Assert.True(insideWord > 20, $"generator: short-inside-a-word = {insideWord}");
    }

    /// <summary>A short version's label (a vault record's or a short form's) in the output.</summary>
    private static bool ShortLabelled(string whole, List<RecordMetadata> records, Dictionary<string, string> shortForms) =>
        shortForms.Values.Any(whole.Contains)
        || records.Any(r => (r.PreviousFingerprints is { } p && TokenBoundary.IsShort(p) && whole.Contains($"[REDACTED: {r.Name}:previous]"))
                            || (r.Fingerprints is { } c && TokenBoundary.IsShort(c) && whole.Contains($"[REDACTED: {r.Name}]")));

    /// <summary>A short value's plain text still in the output with a word character next to it (labels left out).</summary>
    private static bool ShortInsideWord(string output, List<string> shortValues)
    {
        var whole = System.Text.RegularExpressions.Regex.Replace(output, @"\[REDACTED: [^\]]*\]", " ");
        return shortValues.Any(v =>
        {
            for (var i = whole.IndexOf(v, StringComparison.Ordinal); i >= 0; i = whole.IndexOf(v, i + 1, StringComparison.Ordinal))
                if (!TokenBoundary.IsDelimited(whole, i, v.Length))
                    return true;
            return false;
        });
    }

    // ── the pending point ────────────────────────────────────────────────────────────

    /// <summary>
    /// <see cref="FingerprintScannerTests.PendingFrom_IndependentOfValues"/> with a short value added and both
    /// scanners in whole-token mode: the hold still reads the text and quantised aggregates only.
    /// </summary>
    [Fact]
    public void PendingFrom_WholeToken_DependsOnTextOnly()
    {
        var rng = new Random(77);
        string Like(string template) => new([.. template.Select(c => char.IsLetterOrDigit(c) ? Word[rng.Next(Word.Length)] : c)]);
        string[] templates = ["single-line-token-0001", "with space 42", "multi\nline value\nhere", "crlf\r\nvalue", "p465"];
        for (var pair = 0; pair < 8; pair++)
        {
            using var keysA = NewKeys();
            using var keysB = NewKeys();
            var a = FingerprintScanner.Build(templates.Index().Select(p => ($"n{p.Index}", false, Set(p.Item, keysA))), keysA, ShortValueMatching.WholeToken);
            var b = FingerprintScanner.Build(templates.Index().Select(p => ($"m{p.Index}", false, Set(Like(p.Item), keysB))), keysB, ShortValueMatching.WholeToken);

            for (var i = 0; i < 250; i++)
            {
                var text = RandomString(rng, rng.Next(0, 600), Filler + Word);
                Assert.Equal(a.PendingFrom(text), b.PendingFrom(text));
            }
        }
    }

    [Fact]
    public void PendingFrom_WholeToken_NeverSplitsAWordItCanHold()
    {
        var rng = new Random(256);
        using var keys = NewKeys();
        var scanner = FingerprintScanner.Build(
            [("p", false, Set("465", keys)), ("t", false, Set("token-value-1", keys)), ("m", false, Set("two\nlines", keys))],
            keys, ShortValueMatching.WholeToken);

        for (var i = 0; i < 2000; i++)
        {
            var text = new StringBuilder();
            for (var part = rng.Next(1, 8); part > 0; part--)
                text.Append(RandomString(rng, rng.Next(0, rng.Next(2) == 0 ? 40 : 400), ShortAlphabet)).Append(Filler[rng.Next(Filler.Length)]);
            var t = rng.Next(2) == 0 ? text.ToString().TrimEnd() : text.ToString();
            var p = scanner.PendingFrom(t);
            if (p <= 0 || p >= t.Length || !TokenBoundary.IsWordChar(t[p - 1]) || !TokenBoundary.IsWordChar(t[p]))
                continue;
            var start = p - 1;
            while (start > 0 && TokenBoundary.IsWordChar(t[start - 1])) start--;
            Assert.True(p - start > TokenBoundary.WordHoldLimit, $"text {i}: pending {p} splits a word starting at {start}");
        }
    }
}
