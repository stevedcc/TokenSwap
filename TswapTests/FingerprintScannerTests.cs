using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using Xunit;

namespace TswapTests;

/// <summary>
/// <see cref="FingerprintScanner"/>: the stream scanner behind <c>run</c>'s vault-wide masking. It must
/// find exactly what <see cref="FingerprintIndex.Scan"/> finds (plus multi-line values printed through a
/// PTY, found on a view with <c>\r\n</c> folded to <c>\n</c>), and its <see cref="FingerprintScanner.PendingFrom"/>
/// must hold back every possible start of an occurrence that a later chunk could complete, while
/// depending on nothing but the text and quantised per-class aggregates.
/// </summary>
public class FingerprintScannerTests
{
    private static FingerprintKeys NewKeys() => FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));

    private static FingerprintSet Set(string value, FingerprintKeys keys) =>
        Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys);

    private static List<FingerprintHit> Scan(FingerprintScanner scanner, string text)
    {
        List<FingerprintHit> hits = [];
        scanner.Scan(text, hits);
        return hits;
    }

    /// <summary>A PTY's output translation (ONLCR): every <c>\n</c> becomes <c>\r\n</c>, a <c>\r</c> stays.</summary>
    private static string Onlcr(string text) => text.Replace("\n", "\r\n");

    private const string Word = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string Punctuation = "!#$%&()*,.:;<>?@[]^{|}~-_+/=";

    private static string RandomString(Random rng, int length, string alphabet)
    {
        var chars = new char[length];
        for (var i = 0; i < length; i++)
            chars[i] = alphabet[rng.Next(alphabet.Length)];
        return new string(chars);
    }

    /// <summary>A random secret: single-line, with spaces, multi-line (LF or CRLF), or PEM-like.</summary>
    private static string RandomValue(Random rng)
    {
        switch (rng.Next(6))
        {
            case 0: return RandomString(rng, rng.Next(8, 40), Word);
            case 1: return RandomString(rng, rng.Next(8, 40), Word + Punctuation);
            case 2: return RandomString(rng, rng.Next(3, 10), Word) + " " + RandomString(rng, rng.Next(3, 10), Word + Punctuation);
            case 3:
            case 4:
                var newline = rng.Next(2) == 0 ? "\n" : "\r\n";
                var lines = Enumerable.Range(0, rng.Next(2, 5)).Select(_ => RandomString(rng, rng.Next(1, 16), Word + " "));
                return string.Join(newline, lines);
            default:
                return "-----BEGIN KEY-----\n" + string.Join("\n", Enumerable.Range(0, rng.Next(1, 4)).Select(_ => RandomString(rng, 24, Word + "+/")))
                    + "\n-----END KEY-----";
        }
    }

    /// <summary>Every form a value is printed in that the scanner must find: its variants, and the ONLCR form of a multi-line one.</summary>
    private static IEnumerable<string> PrintedForms(string value)
    {
        foreach (var (_, text) in SecretVariants.For(value))
            yield return text;
        if (value.Contains('\n'))
            yield return Onlcr(value);
    }

    private static (List<(string Name, bool IsPrevious, FingerprintSet Set)> Sets, List<string> Values) RandomVault(Random rng, FingerprintKeys keys)
    {
        List<(string, bool, FingerprintSet)> sets = [];
        List<string> values = [];
        for (var n = rng.Next(1, 6); n > 0; n--)
        {
            var name = $"secret-{rng.Next(1000)}";
            var current = RandomValue(rng);
            sets.Add((name, false, Set(current, keys)));
            values.Add(current);
            if (rng.Next(3) == 0)
            {
                var previous = rng.Next(4) == 0 ? current : RandomValue(rng);
                sets.Add((name, true, Set(previous, keys)));
                values.Add(previous);
            }
        }
        return (sets, values);
    }

    private const string Filler = "abc xyz 019 +/= -_ .:\n\r\t";

    /// <summary>Filler with every printed form of every value planted; returns where each was planted.</summary>
    private static (string Text, List<(int Start, int End)> Planted) PlantedText(Random rng, List<string> values)
    {
        var text = new StringBuilder();
        List<(int, int)> planted = [];
        foreach (var form in values.SelectMany(PrintedForms).OrderBy(_ => rng.Next()))
        {
            text.Append(RandomString(rng, rng.Next(0, 6), Filler));
            planted.Add((text.Length, text.Length + form.Length));
            text.Append(form);
        }
        text.Append(RandomString(rng, rng.Next(0, 6), Filler));
        return (text.ToString(), planted);
    }

    // ── equality with FingerprintIndex ───────────────────────────────────────────────

    /// <summary>
    /// Property: on the raw text the scanner reports exactly FingerprintIndex's spans, each once, labelled
    /// by the first hit in tie order (name ordinal, current before previous, kind). Its only other hits
    /// are folded ones (a <c>\r\n</c> inside the span). Fails on any unsound pruning (a character missing
    /// from a class, a whitespace plain entry classed as whitespace-free).
    /// </summary>
    [Fact]
    public void Scan_RawHits_EqualFingerprintIndexScan()
    {
        var rng = new Random(1107);
        using var keys = NewKeys();
        for (var round = 0; round < 300; round++)
        {
            var (sets, values) = RandomVault(rng, keys);
            var (text, _) = PlantedText(rng, values);
            var scanner = FingerprintScanner.Build(sets, keys);
            var index = FingerprintIndex.Build(sets, keys);

            var expected = index.Scan(text).GroupBy(h => (h.Start, h.Length)).ToDictionary(g => g.Key, g => g.First());
            var actual = Scan(scanner, text);

            Assert.Equal(actual.Count, actual.Select(h => (h.Start, h.Length)).Distinct().Count());
            foreach (var (span, first) in expected)
                Assert.Equal(first, Assert.Single(actual, h => (h.Start, h.Length) == span));
            foreach (var extra in actual.Where(h => !expected.ContainsKey((h.Start, h.Length))))
                Assert.Contains("\r\n", text.Substring(extra.Start, extra.Length));
        }
    }

    // ── multi-line values through a PTY ──────────────────────────────────────────────

    [Fact]
    public void Scan_MultiLine_Onlcr_Found()
    {
        using var keys = NewKeys();
        const string value = "line-one\nline two\nline-three";
        var scanner = FingerprintScanner.Build([("pem", false, Set(value, keys))], keys);
        var text = "out: " + Onlcr(value) + " end";

        var hit = Assert.Single(Scan(scanner, text));

        Assert.Equal(new FingerprintHit("pem", false, VariantKind.Plain, 5, Onlcr(value).Length), hit);
    }

    [Fact]
    public void Scan_CrLfValue_OnlcrOutput_Found()
    {
        using var keys = NewKeys();
        const string value = "a1 x\r\nb2 y\r\nc3";
        var scanner = FingerprintScanner.Build([("crlf", false, Set(value, keys))], keys);
        var printed = Onlcr(value); // "a1 x\r\r\nb2 y\r\r\nc3"
        var text = "> " + printed + "\r\n";

        var hit = Assert.Single(Scan(scanner, text));

        Assert.Equal(new FingerprintHit("crlf", false, VariantKind.Plain, 2, printed.Length), hit);
    }

    [Fact]
    public void Scan_CrLfValue_PipeOutput_Found()
    {
        using var keys = NewKeys();
        const string value = "a1 x\r\nb2 y\r\nc3";
        var scanner = FingerprintScanner.Build([("crlf", false, Set(value, keys))], keys);

        var hit = Assert.Single(Scan(scanner, "> " + value + "\n"));

        Assert.Equal(new FingerprintHit("crlf", false, VariantKind.Plain, 2, value.Length), hit);
    }

    /// <summary>A documented gap: a CRLF value printed with LF only is not a stored variant.</summary>
    [Fact]
    public void Scan_CrLfValue_LfOutput_NotFound()
    {
        using var keys = NewKeys();
        const string value = "a1 x\r\nb2 y\r\nc3";
        var scanner = FingerprintScanner.Build([("crlf", false, Set(value, keys))], keys);

        Assert.Empty(Scan(scanner, "> " + value.Replace("\r\n", "\n") + "\n"));
    }

    [Fact]
    public void MaxRawLength_PemSized_IncludesFoldSlack()
    {
        using var keys = NewKeys();
        var rng = new Random(3300);
        // 3,300 characters, 51 of them line breaks (52 lines).
        var body = RandomString(rng, 3300 - 51, Word + "+/");
        var value = string.Join("\n", Enumerable.Range(0, 52).Select(i => body.Substring(i * 3249 / 52, (i + 1) * 3249 / 52 - i * 3249 / 52)));
        Assert.Equal(3300, value.Length);
        var full = Set(value, keys);
        // Only the plain and whitespace-stripped entries, so the base64 entry (4,400) doesn't hide the slack.
        var textual = full with { Entries = [.. full.Entries.Where(e => e.Kind is VariantKind.Plain or VariantKind.WhitespaceStripped)] };

        var scanner = FingerprintScanner.Build([("pem", false, textual)], keys);

        Assert.Equal(3300, FingerprintIndex.Build([("pem", false, textual)], keys).MaxLength);
        Assert.Equal(3300 + 51, scanner.MaxRawLength);
        Assert.Equal(4400, FingerprintScanner.Build([("pem", false, full)], keys).MaxRawLength);
        // And the PTY-printed form, 3,351 characters, is found.
        var printed = Onlcr(value);
        Assert.Equal(3351, printed.Length);
        Assert.Single(Scan(scanner, printed), h => h.Length == 3351);
    }

    // ── PendingFrom ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Property: for every planted occurrence (every printed form, the ONLCR ones with cuts between the
    /// folded <c>\r</c> and its <c>\n</c> included) and every cut inside it, the text up to the cut holds
    /// from no later than the occurrence's start.
    /// </summary>
    [Fact]
    public void PendingFrom_IsSound()
    {
        var rng = new Random(2026);
        using var keys = NewKeys();
        for (var round = 0; round < 150; round++)
        {
            var (sets, values) = RandomVault(rng, keys);
            var (text, planted) = PlantedText(rng, values);
            var scanner = FingerprintScanner.Build(sets, keys);

            foreach (var (start, end) in planted)
            {
                for (var cut = start + 1; cut < end; cut++)
                {
                    var pending = scanner.PendingFrom(text.AsSpan(0, cut));
                    Assert.True(pending <= start,
                        $"round {round}: an occurrence at [{start}, {end}) cut at {cut} is held only from {pending}");
                }
            }
        }
    }

    [Fact]
    public void PendingFrom_SingleLineVault_TrailingSpace_HoldsNothing()
    {
        using var keys = NewKeys();
        var scanner = FingerprintScanner.Build(
            [("a", false, Set("s3cr3t-Value-1", keys)), ("b", false, Set("another+secret/2", keys))], keys);

        const string line = "INFO request handled in 12 ms ";
        Assert.Equal(line.Length, scanner.PendingFrom(line));
    }

    [Fact]
    public void PendingFrom_SingleLineVault_HoldsOnlyTheTrailingWord()
    {
        using var keys = NewKeys();
        var scanner = FingerprintScanner.Build([("a", false, Set("s3cr3t-Value-1", keys))], keys);

        const string line = "INFO request handled in 12 ms partial";
        Assert.Equal(line.Length - "partial".Length, scanner.PendingFrom(line));
    }

    [Fact]
    public void PendingFrom_TrailingCr_HeldWhenFreeEntriesExist()
    {
        using var keys = NewKeys();
        const string text = "first line\r";
        var multiLine = FingerprintScanner.Build([("pem", false, Set("line one\nline two", keys))], keys);
        var singleLine = FingerprintScanner.Build([("tok", false, Set("token-value-123", keys))], keys);

        Assert.True(multiLine.PendingFrom(text) <= text.Length - 1);
        Assert.Equal(text.Length, singleLine.PendingFrom(text));
    }

    /// <summary>
    /// Two vaults with the same class and length profile but different values (and different keys):
    /// identical pending points on random texts. Fails if the hold depends on a hash, a bitset or an HMAC.
    /// </summary>
    [Fact]
    public void PendingFrom_IndependentOfValues()
    {
        var rng = new Random(77);
        string Like(string template) => new([.. template.Select(c => char.IsLetterOrDigit(c) ? Word[rng.Next(Word.Length)] : c)]);
        string[] templates = ["single-line-token-0001", "with space 42", "multi\nline value\nhere", "crlf\r\nvalue"];
        // Several independent pairs of keys, so a dependence on anything key- or value-derived shows.
        for (var pair = 0; pair < 8; pair++)
        {
            using var keysA = NewKeys();
            using var keysB = NewKeys();
            var a = FingerprintScanner.Build(templates.Index().Select(p => ($"n{p.Index}", false, Set(p.Item, keysA))), keysA);
            var b = FingerprintScanner.Build(templates.Index().Select(p => ($"m{p.Index}", false, Set(Like(p.Item), keysB))), keysB);

            for (var i = 0; i < 250; i++)
            {
                var text = RandomString(rng, rng.Next(0, 600), Filler + Word);
                Assert.Equal(a.PendingFrom(text), b.PendingFrom(text));
            }
        }
    }

    [Fact]
    public void PendingFrom_CapsQuantised()
    {
        using var keys = NewKeys();
        var rng = new Random(300);
        // Only the whitespace-free class matters for '.' (not in either base64 alphabet).
        var text = new string('.', 1000);

        var longest300 = FingerprintScanner.Build([("x", false, Set(RandomString(rng, 300, Word), keys))], keys);
        var longest200 = FingerprintScanner.Build([("x", false, Set(RandomString(rng, 200, Word), keys))], keys);

        Assert.Equal(1000 - 511, longest300.PendingFrom(text)); // a 300-character value holds as a 512 cap
        Assert.Equal(1000 - 255, longest200.PendingFrom(text)); // a 200-character value as a 256 cap
    }

    // ── duplicates, collisions ───────────────────────────────────────────────────────

    [Fact]
    public void Scan_DuplicateValues_OneHitPerSpanInTieOrder()
    {
        using var keys = NewKeys();
        const string value = "shared-value-123";
        var twoNames = FingerprintScanner.Build([("zeta", false, Set(value, keys)), ("alpha", false, Set(value, keys))], keys);
        Assert.Equal(new FingerprintHit("alpha", false, VariantKind.Plain, 3, value.Length), Assert.Single(Scan(twoNames, "-> " + value)));

        var currentIsPrevious = FingerprintScanner.Build([("db", true, Set(value, keys)), ("db", false, Set(value, keys))], keys);
        Assert.Equal(new FingerprintHit("db", false, VariantKind.Plain, 3, value.Length), Assert.Single(Scan(currentIsPrevious, "-> " + value)));
    }

    [Fact]
    public void Scan_RollingHashCollision_NoHitWithoutHmac()
    {
        using var keys = NewKeys();
        var real = Set("s3cr3t-value", keys);
        var plain = real.Entries[0];
        var wrongHmac = (byte[])plain.Hmac.Clone();
        wrongHmac[0] ^= 0x01;
        var forged = new FingerprintSet(real.VariantSetVersion, [plain with { Hmac = wrongHmac }]);

        Assert.Empty(Scan(FingerprintScanner.Build([("x", false, forged)], keys), "value: s3cr3t-value"));
        // Control: the genuine entry is found in the same text.
        Assert.Single(Scan(FingerprintScanner.Build([("x", false, real)], keys), "value: s3cr3t-value"), h => h.Kind == VariantKind.Plain);
    }

    /// <summary>
    /// A value of whitespace only has no whitespace-stripped variant (it would be empty), so its plain
    /// entry looks like a whitespace-free one; it is still found. (Held back it is not: PendingFrom can't
    /// tell such an entry from a whitespace-free one without values, so a trailing whitespace run is
    /// emitted; such a value printed across a chunk boundary is the residual limit.)
    /// </summary>
    [Fact]
    public void Scan_WhitespaceOnlyValue_Found()
    {
        using var keys = NewKeys();
        const string value = " \t \t";
        var sets = new List<(string, bool, FingerprintSet)> { ("blank", false, Set(value, keys)) };

        var hits = Scan(FingerprintScanner.Build(sets, keys), "a" + value + "b");

        Assert.Equal(FingerprintIndex.Build(sets, keys).Scan("a" + value + "b").Where(h => h.Kind == VariantKind.Plain), hits.Where(h => h.Kind == VariantKind.Plain));
        Assert.Single(hits, h => h.Kind == VariantKind.Plain);
    }

    /// <summary>
    /// A whitespace-only value with line breaks, printed through a PTY (each <c>\n</c> as <c>\r\n</c>), is
    /// found too: its raw run is folded locally.
    /// </summary>
    [Fact]
    public void Scan_WhitespaceOnlyValue_ThroughPty_Found()
    {
        using var keys = NewKeys();
        const string value = " \n\t\n ";
        var scanner = FingerprintScanner.Build([("blank", false, Set(value, keys))], keys);
        var printed = Onlcr(value);

        Assert.Equal(new FingerprintHit("blank", false, VariantKind.Plain, 1, printed.Length), Assert.Single(Scan(scanner, "a" + printed + "b"), h => h.Kind == VariantKind.Plain));
        Assert.True(scanner.MaxRawLength >= printed.Length);
    }

    /// <summary>
    /// A pinned gap: a whitespace-only value split across two reads is not held back (PendingFrom can't
    /// tell its entry from a whitespace-free one, and holding every chunk's trailing whitespace would
    /// hold every line end), so neither window sees it whole.
    /// </summary>
    [Fact]
    public void PendingFrom_WhitespaceOnlyValue_TrailingWhitespaceNotHeld()
    {
        using var keys = NewKeys();
        var scanner = FingerprintScanner.Build([("blank", false, Set("   ", keys))], keys);

        Assert.Equal("hello ".Length, scanner.PendingFrom("hello "));
    }

    /// <summary>An entry of a kind this build doesn't know may still be folded: its raw span gets a slack of L.</summary>
    [Fact]
    public void MaxRawLength_UnknownKind_AllowsFoldSlack()
    {
        using var keys = NewKeys();
        var plain = Set("future-kind-value", keys).Entries[0];
        var unknown = new FingerprintSet(SecretVariants.CurrentSetVersion, [plain with { Kind = (VariantKind)9 }]);

        Assert.Equal(2 * plain.Length, FingerprintScanner.Build([("x", false, unknown)], keys).MaxRawLength);
    }

    /// <summary>
    /// The same periodic window scanned twice with one state (the second call finds the window starting
    /// with its own end): the hits are a fresh scan's, since a carried hit depends only on the text.
    /// </summary>
    [Fact]
    public void Scan_CarriedState_SameWindowTwice_PeriodicText_SameHits()
    {
        using var keys = NewKeys();
        var scanner = FingerprintScanner.Build([("p", false, Set("abab-secret", keys)), ("q", false, Set("line a\nline b", keys))], keys);
        var window = string.Concat(Enumerable.Repeat("abab-secret line a\nline b ", 40));
        var state = new FingerprintScanner.ScanState();
        var expected = Scan(scanner, window);

        for (var i = 0; i < 3; i++)
        {
            List<FingerprintHit> hits = [];
            scanner.Scan(window, hits, state);
            scanner.PendingFrom(window, state);
            Assert.Equal(expected, hits);
        }
    }

    /// <summary>
    /// Stage 2's case (a value with bytes 61 62 FF decodes to "ab\uFFFD"): UTF-8 encodes a lone high
    /// surrogate as U+FFFD's bytes, so the window "ab\uD83D" that cuts the pair of "ab😀" has the same
    /// HMAC. With the rolling-hash collision forced on top, it is still no hit
    /// (<see cref="FingerprintIndex.SplitsASurrogatePair"/>).
    /// </summary>
    [Fact]
    public void Scan_WindowSplittingASurrogatePair_NoHit()
    {
        using var keys = NewKeys();
        const string window = "ab\uD83D";
        var value = Set(Encoding.UTF8.GetString([0x61, 0x62, 0xFF]), keys).Entries[0];
        Assert.Equal(Fingerprinter.Hmac(window, keys), value.Hmac);
        var forged = value with { RollingHash = RollingHash.Of(window, keys.RollingBase) };
        var scanner = FingerprintScanner.Build([("binary-secret", false, new FingerprintSet(SecretVariants.CurrentSetVersion, [forged]))], keys);

        Assert.Empty(Scan(scanner, "ab\U0001F600"));
        // Control: the genuine entry confirms the text it really describes.
        Assert.Equal([new FingerprintHit("binary-secret", false, VariantKind.Plain, 0, 3)],
            Scan(FingerprintScanner.Build([("binary-secret", false, new FingerprintSet(SecretVariants.CurrentSetVersion, [value]))], keys), "ab\uFFFD"));
    }

    // ── carried state across chunks ──────────────────────────────────────────────────

    /// <summary>
    /// Property: a scan that carries its state from the previous window (as the stream matcher does)
    /// reports exactly the hits of a fresh scan of the same window, for windows that continue the
    /// previous one from its pending point, from another point (more or less held), or not at all.
    /// Fails if carried state is used without checking that the new window really continues it.
    /// </summary>
    [Fact]
    public void Scan_CarriedState_SameHitsAsFreshScan()
    {
        var rng = new Random(5150);
        using var keys = NewKeys();
        for (var round = 0; round < 120; round++)
        {
            var (sets, values) = RandomVault(rng, keys);
            var (text, _) = PlantedText(rng, values);
            if (rng.Next(2) == 0)
                text = Onlcr(text);
            var scanner = FingerprintScanner.Build(sets, keys);
            var state = new FingerprintScanner.ScanState();
            var window = "";
            for (var consumed = 0; consumed < text.Length || window.Length > 0;)
            {
                var size = rng.Next(1, 40);
                window += text.Substring(consumed, Math.Min(size, text.Length - consumed));
                consumed = Math.Min(text.Length, consumed + size);

                List<FingerprintHit> carried = [];
                scanner.Scan(window, carried, state);
                var pending = scanner.PendingFrom(window, state);
                Assert.Equal(Scan(scanner, window), carried);
                Assert.Equal(scanner.PendingFrom(window), pending);

                // Hold from the pending point, or (sometimes) from another one, or start afresh.
                var hold = rng.Next(5) switch
                {
                    0 => rng.Next(0, window.Length + 1),
                    1 => window.Length,
                    _ => pending,
                };
                window = consumed >= text.Length ? "" : window[hold..];
                if (rng.Next(30) == 0)
                    window = RandomString(rng, rng.Next(0, 20), Filler); // unrelated text
            }
        }
    }

    /// <summary>
    /// The stream matcher (which carries state) through the real redactor gives the output a stateless
    /// scan gives, for every chunk size 1..N, on a corpus with multi-line values through ONLCR.
    /// </summary>
    [Fact]
    public void Matcher_CarriedState_SameOutputForEveryChunkSize()
    {
        var rng = new Random(77077);
        using var keys = NewKeys();
        for (var round = 0; round < 6; round++)
        {
            var (sets, values) = RandomVault(rng, keys);
            var (text, _) = PlantedText(rng, values);
            text = Onlcr(text) + text;
            var records = sets.GroupBy(s => s.Name).Select(g => new TswapCore.Keyring.RecordMetadata(
                RandomNumberGenerator.GetBytes(32), TswapCore.Keyring.Stamp.Zero, TswapCore.Keyring.RecordType.Value,
                TswapCore.Keyring.Stamp.Zero, g.Key, 0, [], g.FirstOrDefault(s => !s.IsPrevious).Set,
                g.Any(s => s.IsPrevious) ? TswapCore.Keyring.Stamp.Zero : null, g.FirstOrDefault(s => s.IsPrevious).Set, [])).ToList();
            var carrying = TswapCli.FingerprintStreamMatcher.For(new VaultMetadata(records, 0, 0, []), keys);
            var stateless = new StatelessMatcher(FingerprintScanner.Build(
                records.SelectMany(r => r.RetainedVersions().Where(v => v.Fingerprints is not null).Select(v => (r.Name, v.IsPrevious, v.Fingerprints!))), keys));

            for (var size = 1; size <= 64; size++)
                Assert.Equal(Redact(stateless, text, size), Redact(carrying, text, size));
        }
    }

    private static string Redact(RedactingPty.IStreamMatcher matcher, string text, int size)
    {
        var redactor = new RedactingPty.StreamRedactor([], [matcher]);
        var sb = new StringBuilder();
        for (var i = 0; i < text.Length; i += size)
            sb.Append(redactor.ProcessChunk(text.Substring(i, Math.Min(size, text.Length - i))));
        return sb.Append(redactor.Flush()).ToString();
    }

    /// <summary>The matcher as it was before state was carried: a fresh scan of every window.</summary>
    private sealed class StatelessMatcher(FingerprintScanner scanner) : RedactingPty.IStreamMatcher
    {
        public int MaxMatchLength { get; } = Math.Max(1, scanner.MaxRawLength);

        public void FindMatches(ReadOnlySpan<char> window, ICollection<RedactingPty.StreamMatch> matches)
        {
            List<FingerprintHit> hits = [];
            scanner.Scan(window, hits);
            foreach (var h in hits)
                matches.Add(new RedactingPty.StreamMatch(h.Start, h.Length, h.IsPrevious ? $"[REDACTED: {h.Name}:previous]" : $"[REDACTED: {h.Name}]"));
        }

        public int PendingFrom(ReadOnlySpan<char> window) => scanner.PendingFrom(window);
    }

    [Fact]
    public void Scan_EmptyIndex_NothingFoundNothingHeld()
    {
        using var keys = NewKeys();
        var scanner = FingerprintScanner.Build([("empty", false, Set("", keys))], keys);

        Assert.Equal(0, scanner.MaxRawLength);
        Assert.Empty(Scan(scanner, "anything at all\r\n"));
        Assert.Equal(16, scanner.PendingFrom("anything at all\r"));
    }
}
