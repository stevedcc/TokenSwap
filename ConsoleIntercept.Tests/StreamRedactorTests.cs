using Xunit;

namespace ConsoleIntercept.Tests;

/// <summary>
/// Unit tests for <see cref="StreamRedactor"/>.
/// These test the chunk-boundary sliding-window logic directly with synthetic chunks,
/// without needing a real PTY or subprocess.
/// </summary>
public class StreamRedactorTests
{
    private static List<StreamReplacement> Secrets(params (string name, string value)[] pairs)
        => pairs.Select(p => new StreamReplacement(p.value, $"[REDACTED: {p.name}]")).ToList();

    private static string Process(List<StreamReplacement> replacements, params string[] chunks)
    {
        var r = new StreamRedactor(replacements);
        var sb = new System.Text.StringBuilder();
        foreach (var chunk in chunks)
            sb.Append(r.ProcessChunk(chunk));
        sb.Append(r.Flush());
        return sb.ToString();
    }

    [Fact]
    public void SingleChunk_SecretRedacted()
    {
        var result = Process(Secrets(("pw", "hunter2")), "password is hunter2 ok");
        Assert.DoesNotContain("hunter2", result);
        Assert.Contains("[REDACTED: pw]", result);
    }

    [Fact]
    public void SecretSplitAcrossTwoChunks_Redacted()
    {
        // "hunter2" (7 chars) split after "hunte" — overlap must be >= 6 to catch this
        var result = Process(Secrets(("pw", "hunter2")), "password is hunte", "r2 ok");
        Assert.DoesNotContain("hunter2", result);
        Assert.Contains("[REDACTED: pw]", result);
    }

    [Fact]
    public void SecretSplitAfterFirstChar_Redacted()
    {
        // Worst case: only the first character of the secret lands in the first chunk
        var result = Process(Secrets(("pw", "hunter2")), "prefix h", "unter2 suffix");
        Assert.DoesNotContain("hunter2", result);
        Assert.Contains("[REDACTED: pw]", result);
    }

    [Fact]
    public void SecretEntirelyInTail_Redacted()
    {
        // Secret is entirely within the retained tail of a single chunk
        // Chunk is shorter than overlap so all of it is held as tail, flushed at the end
        var result = Process(Secrets(("pw", "hunter2")), "hunter2");
        Assert.DoesNotContain("hunter2", result);
        Assert.Contains("[REDACTED: pw]", result);
    }

    [Fact]
    public void SecretSpansThreeChunks_Redacted()
    {
        // Each chunk delivers part of the secret; overlap carries it across all boundaries
        var result = Process(Secrets(("pw", "hunter2")), "hun", "ter", "2");
        Assert.DoesNotContain("hunter2", result);
        Assert.Contains("[REDACTED: pw]", result);
    }

    [Fact]
    public void NoSecrets_OutputUnchanged()
    {
        var result = Process(Secrets(), "hello world");
        Assert.Equal("hello world", result);
    }

    [Fact]
    public void MultipleSecrets_AllRedacted()
    {
        var secrets = Secrets(("token", "AAABBB"), ("key", "CCCDDD"));
        var result = Process(secrets, "tok=AAAB", "BB key=CCC", "DDD done");
        Assert.DoesNotContain("AAABBB", result);
        Assert.DoesNotContain("CCCDDD", result);
        Assert.Contains("[REDACTED: token]", result);
        Assert.Contains("[REDACTED: key]", result);
    }

    [Fact]
    public void SurroundingTextPreserved()
    {
        var result = Process(Secrets(("pw", "hunter2")), "before hunte", "r2 after");
        Assert.Contains("before", result);
        Assert.Contains("after", result);
        Assert.DoesNotContain("hunter2", result);
    }

    [Fact]
    public void LongPaddingBeforeSecret_Redacted()
    {
        // Simulates a realistic read-buffer scenario: lots of padding forces the secret
        // to start near the end of one chunk and finish at the start of the next.
        var secret = "SECRETVAL";
        var secrets = Secrets(("s", secret));
        // 4090 x's + first 5 chars of secret in chunk 1; remaining 4 chars in chunk 2
        var chunk1 = new string('x', 4090) + secret[..5];
        var chunk2 = secret[5..] + " done";
        var result = Process(secrets, chunk1, chunk2);
        Assert.DoesNotContain(secret, result);
        Assert.Contains("[REDACTED: s]", result);
    }

    [Fact]
    public void NullReplacementList_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => new StreamRedactor(null!));
    }

    [Fact]
    public void NullReplacementEntry_ThrowsArgument()
    {
        var replacements = new List<StreamReplacement> { null! };
        Assert.Throws<ArgumentException>(() => new StreamRedactor(replacements));
    }

    [Fact]
    public void NullFindOrReplace_ThrowsArgument()
    {
        Assert.Throws<ArgumentException>(
            () => new StreamRedactor([new StreamReplacement(null!, "x")]));
        Assert.Throws<ArgumentException>(
            () => new StreamRedactor([new StreamReplacement("x", null!)]));
    }

    [Fact]
    public void EmptyFind_IsAllowedAndInert()
    {
        // Empty Find is explicitly permitted (documented as the inert entry) and must
        // never match anything.
        var result = Process([new StreamReplacement("", "[X]")], "hello world");
        Assert.Equal("hello world", result);
    }

    [Fact]
    public void NullChunk_ThrowsArgumentNull()
    {
        var r = new StreamRedactor([new StreamReplacement("secret", "[X]")]);
        Assert.Throws<ArgumentNullException>(() => r.ProcessChunk(null!));
    }

    [Fact]
    public void UnsortedReplacements_LongerFindStillWins()
    {
        // The constructor re-sorts longest-Find-first, so passing the shorter
        // prefix-sharing value first must not clobber the longer one.
        var replacements = new List<StreamReplacement>
        {
            new("super", "[REDACTED: short]"),
            new("superSecret", "[REDACTED: long]"),
        };
        var result = Process(replacements, "val=superSecret end");
        Assert.Contains("[REDACTED: long]", result);
        Assert.DoesNotContain("superSecret", result);
        Assert.DoesNotContain("[REDACTED: short]", result);
    }
}
