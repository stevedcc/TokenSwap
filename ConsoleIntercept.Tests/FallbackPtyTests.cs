using System.Text;
using ConsoleIntercept;
using Xunit;

namespace ConsoleIntercept.Tests;

/// <summary>
/// Tests for the FallbackPty drain plumbing (byte decode → StreamRedactor → re-encode)
/// using in-memory streams, without spawning a subprocess. Exercised via
/// InternalsVisibleTo since Drain is an implementation detail of FallbackPty.
/// </summary>
public class FallbackPtyTests
{
    private static string Drain(string input, IReadOnlyList<StreamReplacement> replacements)
    {
        var source = new MemoryStream(Encoding.UTF8.GetBytes(input));
        var dest = new MemoryStream();
        FallbackPty.Drain(source, dest, replacements, Encoding.UTF8, writeLock: null);
        return Encoding.UTF8.GetString(dest.ToArray());
    }

    [Fact]
    public void Drain_ReplacesSecretInOutput()
    {
        var result = Drain("password is hunter2 ok",
            [new StreamReplacement("hunter2", "[REDACTED: pw]")]);
        Assert.Equal("password is [REDACTED: pw] ok", result);
    }

    [Fact]
    public void Drain_SecretStraddlingReadBufferBoundary_Replaced()
    {
        // Drain reads in 4096-byte chunks; place the secret across the 4096 boundary.
        var input = new string('x', 4090) + "hunter2" + " end";
        var result = Drain(input, [new StreamReplacement("hunter2", "[REDACTED: pw]")]);
        Assert.DoesNotContain("hunter2", result);
        Assert.Contains("[REDACTED: pw] end", result);
        Assert.StartsWith(new string('x', 4090), result);
    }

    [Fact]
    public void Drain_NoReplacements_OutputUnchanged()
    {
        var result = Drain("plain output, nothing sensitive", []);
        Assert.Equal("plain output, nothing sensitive", result);
    }

    [Fact]
    public void Drain_MultiByteUtf8AcrossBufferBoundary_Preserved()
    {
        // A multi-byte UTF-8 character spanning the 4096-byte read boundary must survive
        // the decode/re-encode round trip (Decoder carries partial sequences between reads).
        var input = new string('x', 4095) + "é after-boundary hunter2";
        var result = Drain(input, [new StreamReplacement("hunter2", "[REDACTED: pw]")]);
        Assert.Contains("é after-boundary [REDACTED: pw]", result);
    }
}
