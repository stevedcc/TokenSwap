using System.Security.Cryptography;
using System.Text;
using TswapCore.Fingerprints;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 2: <see cref="FingerprintIndex.Scan"/> finds every variant of every indexed
/// value in a text, confirming each rolling-hash candidate on the HMAC, and returns every hit
/// (overlap resolution is Stages 2 and 3's job).
/// </summary>
public class FingerprintIndexTests
{
    private static FingerprintSet Set(string value, FingerprintKeys keys) =>
        Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys);

    [Fact]
    public void Scan_FindsEachVariantKind()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        const string value = "?? ab>";
        var variants = SecretVariants.For(value).ToDictionary(v => v.Kind, v => v.Text);
        Assert.Equal(4, variants.Count);
        var index = FingerprintIndex.Build([("tok", false, Set(value, keys))], keys);

        foreach (var (kind, text) in variants)
        {
            var haystack = "prefix [" + text + "] suffix";
            var hits = index.Scan(haystack);
            var hit = Assert.Single(hits, h => h.Kind == kind);
            Assert.Equal(new FingerprintHit("tok", false, kind, 8, text.Length), hit);
            Assert.Equal(text, haystack.Substring(hit.Start, hit.Length));
        }
    }

    [Fact]
    public void Scan_PreviousValue_IsFlagged()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var index = FingerprintIndex.Build(
            [("db", false, Set("new-value-123", keys)), ("db", true, Set("old-value-456", keys))], keys);

        var hits = index.Scan("a=old-value-456 b=new-value-123");

        Assert.Equal(
            [new FingerprintHit("db", true, VariantKind.Plain, 2, 13), new FingerprintHit("db", false, VariantKind.Plain, 18, 13)],
            hits);
    }

    [Fact]
    public void Scan_RollingCollisionWithoutHmacMatch_IsNoHit()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var real = Set("s3cr3t-value", keys);
        var plain = real.Entries[0];
        var wrongHmac = (byte[])plain.Hmac.Clone();
        wrongHmac[0] ^= 0x01;
        var forged = new FingerprintSet(real.VariantSetVersion, [plain with { Hmac = wrongHmac }]);
        var index = FingerprintIndex.Build([("x", false, forged)], keys);

        Assert.Empty(index.Scan("value: s3cr3t-value"));
        // Control: the genuine entry is found in the same text.
        Assert.Single(FingerprintIndex.Build([("x", false, real)], keys).Scan("value: s3cr3t-value"), h => h.Kind == VariantKind.Plain);
    }

    [Fact]
    public void Scan_OverlappingSecrets_ReturnsAllHits()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var index = FingerprintIndex.Build([("long", false, Set("abcdef", keys)), ("short", false, Set("cde", keys))], keys);

        var hits = index.Scan("xxabcdefxx").Where(h => h.Kind == VariantKind.Plain).ToList();

        Assert.Equal(
            [new FingerprintHit("long", false, VariantKind.Plain, 2, 6), new FingerprintHit("short", false, VariantKind.Plain, 4, 3)],
            hits);
    }

    [Fact]
    public void Scan_OrdersByStartThenLongestThenName()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var index = FingerprintIndex.Build(
            [("b", false, Set("abc", keys)), ("a", false, Set("abc", keys)), ("c", false, Set("abcd", keys)), ("d", false, Set("cd", keys))],
            keys);

        var hits = index.Scan("abcd").Select(h => (h.Name, h.Start, h.Length)).ToList();

        Assert.Equal([("c", 0, 4), ("a", 0, 3), ("b", 0, 3), ("d", 2, 2)], hits);
    }

    [Fact]
    public void Scan_PemSizedSecret()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var random = new Random(4_200);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\n";
        var value = "-----BEGIN PRIVATE KEY-----\n"
            + new string(Enumerable.Range(0, 4200 - 54).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray())
            + "\n-----END PRIVATE KEY-----";
        Assert.Equal(4200, value.Length);
        var index = FingerprintIndex.Build([("pem", false, Set(value, keys))], keys);

        Assert.True(index.MaxLength >= 4200);
        var hit = Assert.Single(index.Scan("key: |\n" + value + "\nnext: 1"), h => h.Kind == VariantKind.Plain);
        Assert.Equal(7, hit.Start);
        Assert.Equal(4200, hit.Length);
    }

    [Fact]
    public void Scan_EmptyValueAndShortText_FindNothing()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var index = FingerprintIndex.Build([("empty", false, Set("", keys)), ("long", false, Set("abcdefgh", keys))], keys);
        Assert.Empty(index.Scan(""));
        Assert.Empty(index.Scan("abc"));
        Assert.Equal(12, index.MaxLength); // base64 of "abcdefgh"
    }

    [Fact]
    public void Scan_ForgedRollingHashCollisionAcrossASurrogatePair_NoHit()
    {
        // UTF-8 encodes a lone high surrogate as U+FFFD's bytes, so the HMAC of "ab\uD83D" equals
        // the HMAC of "ab\uFFFD". Force the rolling-hash collision on top: an entry with the rolling
        // hash of the window that cuts the pair of "ab😀" and the HMAC of "ab\uFFFD".
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        const string window = "ab\uD83D";
        Assert.Equal(Fingerprinter.Hmac(window, keys), Fingerprinter.Hmac("ab\uFFFD", keys));
        var forged = new FingerprintEntry(VariantKind.Plain, 3, RollingHash.Of(window, keys.RollingBase), Fingerprinter.Hmac("ab\uFFFD", keys));
        var index = FingerprintIndex.Build([("binary-secret", false, new FingerprintSet(SecretVariants.CurrentSetVersion, [forged]))], keys);

        Assert.Empty(index.Scan("ab\U0001F600"));
        // Control: the same entry confirms the text it really describes.
        var control = FingerprintIndex.Build(
            [("binary-secret", false, new FingerprintSet(SecretVariants.CurrentSetVersion,
                [forged with { RollingHash = RollingHash.Of("ab\uFFFD", keys.RollingBase) }]))], keys);
        Assert.Equal([new FingerprintHit("binary-secret", false, VariantKind.Plain, 0, 3)], control.Scan("ab\uFFFD"));
    }

    [Fact]
    public void Scan_ValueWithAnEmoji_StillMatched()
    {
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        const string value = "\U0001F600pa\U0001F511ss\U0001F600";
        var index = FingerprintIndex.Build([("emoji", false, Set(value, keys))], keys);

        var hits = index.Scan("x=" + value + "\U0001F600;").Where(h => h.Kind == VariantKind.Plain).ToList();

        Assert.Equal([new FingerprintHit("emoji", false, VariantKind.Plain, 2, value.Length)], hits);
    }

    [Fact]
    public void SplitsASurrogatePair_Edges()
    {
        // A [Fact], not a [Theory]: xUnit's theory data serialisation turns a lone surrogate into U+FFFD.
        Assert.True(FingerprintIndex.SplitsASurrogatePair("\uDE00ab"));      // starts on a lone low surrogate
        Assert.True(FingerprintIndex.SplitsASurrogatePair("ab\uD83D"));      // ends on a lone high surrogate
        Assert.False(FingerprintIndex.SplitsASurrogatePair("a\uD83D\uDE00b")); // a whole pair inside
        Assert.False(FingerprintIndex.SplitsASurrogatePair("\uD83D\uDE00"));  // exactly a whole pair
        Assert.False(FingerprintIndex.SplitsASurrogatePair("abc"));           // no surrogates
        Assert.False(FingerprintIndex.SplitsASurrogatePair(""));
    }
}
