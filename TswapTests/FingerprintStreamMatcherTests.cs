using System.Security.Cryptography;
using System.Text;
using RedactingPty;
using TswapCli;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// <see cref="FingerprintStreamMatcher"/> through RedactingPty's real <see cref="StreamRedactor"/>: every
/// fingerprinted value version of the vault (current, previous, burned) is masked as <c>run</c> labels its
/// own tokens, <c>[REDACTED: name]</c> or <c>[REDACTED: name:previous]</c>, however the output is chunked.
/// </summary>
public class FingerprintStreamMatcherTests
{
    private static FingerprintKeys NewKeys() => FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));

    private static FingerprintSet Set(string value, FingerprintKeys keys) =>
        Fingerprinter.Compute(Encoding.UTF8.GetBytes(value), keys);

    private static RecordMetadata Record(string name, RecordType type, FingerprintSet? current, FingerprintSet? previous = null) =>
        new(RandomNumberGenerator.GetBytes(32), Stamp.Zero, type, Stamp.Zero, name, 0, [], current,
            previous is null ? null : Stamp.Zero, previous, []);

    private static VaultMetadata Vault(params RecordMetadata[] records) => new(records, 0, 0, []);

    private static List<string> Pieces(IStreamMatcher matcher, IEnumerable<string> chunks)
    {
        var redactor = new StreamRedactor([], [matcher]);
        List<string> pieces = [.. chunks.Select(redactor.ProcessChunk)];
        pieces.Add(redactor.Flush());
        return pieces;
    }

    private static IEnumerable<string> Chunk(string text, int size)
    {
        for (var i = 0; i < text.Length; i += size)
            yield return text.Substring(i, Math.Min(size, text.Length - i));
    }

    [Fact]
    public void Matcher_OtherSecret_AcrossChunks_Masked()
    {
        using var keys = NewKeys();
        const string value = "p@ss-W0rd-xyz";
        var matcher = FingerprintStreamMatcher.For(Vault(Record("db", RecordType.Value, Set(value, keys))), keys);
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        var text = $"conn={value} b64={base64} ok";

        for (var cut = 0; cut <= text.Length; cut++)
        {
            var pieces = Pieces(matcher, [text[..cut], text[cut..]]);
            Assert.Equal("conn=[REDACTED: db] b64=[REDACTED: db] ok", string.Concat(pieces));
        }
    }

    [Fact]
    public void Matcher_PreviousValue_LabelledPrevious()
    {
        using var keys = NewKeys();
        var matcher = FingerprintStreamMatcher.For(
            Vault(Record("db", RecordType.Value, Set("new-value-123", keys), Set("old-value-456", keys))), keys);

        Assert.Equal("a=[REDACTED: db:previous] b=[REDACTED: db]", string.Concat(Pieces(matcher, ["a=old-value-456 b=new-value-123"])));
    }

    [Fact]
    public void Matcher_BurnedValue_StillMasked()
    {
        using var keys = NewKeys();
        var matcher = FingerprintStreamMatcher.For(
            Vault(Record("leaked", RecordType.Burned, Set("burned-value-789", keys)),
                  Record("gone", RecordType.Tombstone, null)), keys);

        Assert.Equal("x [REDACTED: leaked] y", string.Concat(Pieces(matcher, ["x burned-value-789 y"])));
    }

    [Fact]
    public void Matcher_TwoThreads_SameResults()
    {
        using var keys = NewKeys();
        var matcher = FingerprintStreamMatcher.For(
            Vault(Record("a", RecordType.Value, Set("alpha-secret-1", keys)),
                  Record("b", RecordType.Value, Set("line one\nline two", keys))), keys);
        var textA = string.Concat(Enumerable.Range(0, 400).Select(i => $"row {i} alpha-secret-1 end\n"));
        var textB = string.Concat(Enumerable.Range(0, 400).Select(i => $"row {i} line one\r\nline two end\n"));
        var expectedA = string.Concat(Pieces(matcher, Chunk(textA, 97)));
        var expectedB = string.Concat(Pieces(matcher, Chunk(textB, 89)));
        Assert.DoesNotContain("alpha-secret-1", expectedA);
        Assert.DoesNotContain("line one", expectedB);

        // FallbackPty drains stdout and stderr on two threads with one matcher.
        var results = Enumerable.Range(0, 8).AsParallel().WithDegreeOfParallelism(4)
            .Select(i => i % 2 == 0 ? string.Concat(Pieces(matcher, Chunk(textA, 97))) : string.Concat(Pieces(matcher, Chunk(textB, 89))))
            .ToList();

        Assert.All(results.Where((_, i) => i % 2 == 0), r => Assert.Equal(expectedA, r));
        Assert.All(results.Where((_, i) => i % 2 == 1), r => Assert.Equal(expectedB, r));
    }

    [Fact]
    public void Matcher_EmptyIndex_MaxMatchLengthOne()
    {
        using var keys = NewKeys();
        var matcher = FingerprintStreamMatcher.For(Vault(), keys);

        Assert.Equal(1, matcher.MaxMatchLength);
        var redactor = new StreamRedactor([], [matcher]);
        Assert.Equal("plain output\r", redactor.ProcessChunk("plain output\r"));
        Assert.False(redactor.HasHeld);
    }

    /// <summary>
    /// A multi-line secret through a PTY (ONLCR), the chunk ending on the <c>\r</c> of one of its line
    /// breaks: nothing of it may be emitted before the <c>\n</c> arrives.
    /// </summary>
    [Fact]
    public void Matcher_ChunkSplitInsideCrLf_StillMasked()
    {
        using var keys = NewKeys();
        const string value = "-----BEGIN KEY-----\nMIIBOgIBAAJBAK\n-----END KEY-----";
        var matcher = FingerprintStreamMatcher.For(Vault(Record("pem", RecordType.Value, Set(value, keys))), keys);
        var printed = "key: " + value.Replace("\n", "\r\n") + "\r\n";
        var cut = printed.IndexOf('\r') + 1; // after the first "\r", before its "\n"

        var pieces = Pieces(matcher, [printed[..cut], printed[cut..]]);

        Assert.Equal("key: [REDACTED: pem]\r\n", string.Concat(pieces));
        Assert.DoesNotContain("BEGIN", pieces[0]);
        Assert.DoesNotContain('\r', pieces[0]);
    }
}
