using System.Text;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T13 item 5: redaction of very short secrets (1, 2 and 3 bytes, and one non-ASCII byte) and
/// of overlapping forms, the same cases for <see cref="BrokerRedactor"/> (routes) and
/// <see cref="BrokerTemplateOutput"/> (templates). The forms each secret must have are pinned here
/// by hand, so dropping a claimed form fails a test; every input is also fed split at every chunk
/// boundary and one byte at a time.
/// </summary>
public class BrokerShortSecretRedactionTests
{
    /// <summary>
    /// One secret: the forms pinned by hand (Latin-1 text, one char per byte), and hand-built
    /// overlaps with their exact redacted output.
    /// </summary>
    public sealed record Case(byte[] Secret, string[] Pinned, (string Input, string Expected)[] Overlaps);

    private const string R = "[REDACTED]";

    private static readonly Dictionary<string, Case> Cases = new()
    {
        // "1" (0x31): raw; hex "31" (upper = lower); base64 "MQ==" and "MQ" (base64url is the same).
        // Too short for an aligned core, a spaced hex form or a wrapped form; percent, form and
        // JSON encoding all give "1".
        ["1"] = new("1"u8.ToArray(),
            ["1", "31", "MQ==", "MQ"],
            [("311", R + R), ("MQ1", R + R), ("MQ=", R + "="), ("MQ==1", R + R)]),

        // "11": raw; hex "3131"; "31 31" (od/xxd -g1); base64 "MTE=" and "MTE".
        ["11"] = new("11"u8.ToArray(),
            ["11", "3131", "31 31", "MTE=", "MTE"],
            [("31311", R + "1"), ("1131", R + "31"), ("3111", "3" + R + "1"), ("31 3131", R + "31"), ("MTE=11", R + R)]),

        // "a1": raw; hex "6131"; "61 31"; base64 "YTE=" and "YTE".
        ["a1"] = new("a1"u8.ToArray(),
            ["a1", "6131", "61 31", "YTE=", "YTE"],
            [("a6131", "a" + R), ("6a1", "6" + R), ("61 31 31", R + " 31"), ("6131a1", R + R), ("YTE=a1", R + R)]),

        // "1/z" (31 2F 7A): raw; hex upper and lower; spaced upper and lower; base64 "MS96" (no
        // padding; base64url the same); percent "1%2Fz" (also form encoding) and its lower-case
        // escape; JSON with "\/".
        ["1/z"] = new("1/z"u8.ToArray(),
            ["1/z", "312F7A", "312f7a", "31 2F 7A", "31 2f 7a", "MS96", "1%2Fz", "1%2fz", "1\\/z"],
            [("31/z", "3" + R), ("312F7A/z", R + "/z"), ("1%2F1/z", "1%2F" + R), ("1\\/z/z", R + "/z"), ("MS961/z", R + R)]),

        // One non-ASCII byte (0xE9, not valid UTF-8 alone): only the forms the redactor claims for
        // it, raw, hex upper and lower, base64 "6Q==" and "6Q". (Its percent and JSON forms are
        // built from U+FFFD; BROKER.md documents that limitation.)
        ["E9"] = new([0xE9],
            ["é", "E9", "e9", "6Q==", "6Q"],
            [("E9e9", R + R), ("6Q=", R + "="), ("éE9", R + R), ("6Q==é", R + R), ("EE9", "E" + R)]),
    };

    public static TheoryData<string> Labels => [.. Cases.Keys];

    private static byte[] L(string s) => Encoding.Latin1.GetBytes(s);

    private static IReadOnlyList<byte[]> FormsOf(byte[] secret)
    {
        var redactor = BrokerRedactor.ForSecret(secret, null);
        return [.. redactor.Forms.Select(f => f.ToArray())];
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public void ForSecret_ClaimsEveryPinnedForm(string label)
    {
        var c = Cases[label];
        var forms = FormsOf(c.Secret).Select(f => Convert.ToHexString(f)).ToHashSet();

        foreach (var pinned in c.Pinned)
            Assert.True(forms.Contains(Convert.ToHexString(L(pinned))), $"secret {label}: the form \"{pinned}\" is missing from ForSecret(...).Forms");
    }

    /// <summary>Every input for a case: each pinned form alone, side by side, overlapping, all together, and every form in Forms.</summary>
    private static List<string> Inputs(Case c)
    {
        var inputs = new List<string>(c.Pinned);
        foreach (var a in c.Pinned)
            foreach (var b in c.Pinned)
            {
                inputs.Add(a + b);
                inputs.Add("x" + a + "-" + b + "y");
                for (var k = 1; k < Math.Min(a.Length, b.Length); k++)
                    if (a.EndsWith(b[..k], StringComparison.Ordinal))
                        inputs.Add(a + b[k..]); // a's tail is b's head
            }
        inputs.Add(string.Concat(c.Pinned));
        inputs.AddRange(c.Overlaps.Select(o => o.Input));
        inputs.AddRange(FormsOf(c.Secret).Select(f => Encoding.Latin1.GetString(f)));
        return inputs;
    }

    /// <summary>The input whole, split in two at every boundary, and one byte at a time.</summary>
    private static IEnumerable<byte[][]> Chunkings(byte[] input)
    {
        yield return [input];
        for (var i = 1; i < input.Length; i++)
            yield return [input[..i], input[i..]];
        yield return [.. input.Select(b => new[] { b })];
    }

    private static string ThroughRedactor(byte[] secret, byte[][] chunks)
    {
        var redactor = BrokerRedactor.ForSecret(secret, null);
        var output = new MemoryStream();
        foreach (var chunk in chunks)
            redactor.Process(chunk, output);
        redactor.Flush(output);
        redactor.Clear();
        return Encoding.Latin1.GetString(output.ToArray());
    }

    private static async Task<string> ThroughTemplateOutput(byte[] secret, byte[][] chunks)
    {
        var output = new MemoryStream();
        var outputter = new BrokerTemplateOutput([secret.ToArray()], 1 << 20, (_, data) =>
        {
            output.Write(data.Span);
            return ValueTask.CompletedTask;
        });
        foreach (var chunk in chunks)
            await outputter.WriteAsync(BrokerOutputKind.Stdout, chunk);
        await outputter.CompleteAsync();
        return Encoding.Latin1.GetString(output.ToArray());
    }

    /// <summary>No complete pinned form, and no complete form from Forms either, is left in the output.</summary>
    private static void NoPinnedFormSurvives(Case c, string label, string input, string output)
    {
        foreach (var form in c.Pinned.Concat(FormsOf(c.Secret).Select(f => Encoding.Latin1.GetString(f))))
            Assert.False(output.Contains(form, StringComparison.Ordinal),
                $"secret {label}: input \"{input}\" left the complete form \"{form}\" in \"{output}\"");
    }

    [Fact]
    public void TheReplacement_HoldsNoForm()
    {
        // Otherwise "no form survives" could never pass; checked once for every case.
        foreach (var (label, c) in Cases)
            foreach (var form in c.Pinned.Concat(FormsOf(c.Secret).Select(f => Encoding.Latin1.GetString(f))))
                Assert.False(R.Contains(form, StringComparison.Ordinal), $"secret {label}: {form}");
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public void Redactor_LeavesNoCompletePinnedForm_InAnyInput_AtAnyChunking(string label)
    {
        var c = Cases[label];
        foreach (var input in Inputs(c))
            foreach (var chunks in Chunkings(L(input)))
                NoPinnedFormSurvives(c, label, input, ThroughRedactor(c.Secret, chunks));
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public async Task TemplateOutput_LeavesNoCompletePinnedForm_InAnyInput_AtAnyChunking(string label)
    {
        var c = Cases[label];
        foreach (var input in Inputs(c))
            foreach (var chunks in Chunkings(L(input)))
                NoPinnedFormSurvives(c, label, input, await ThroughTemplateOutput(c.Secret, chunks));
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public void Redactor_EachPinnedFormAlone_BecomesOneRedaction(string label)
    {
        var c = Cases[label];
        foreach (var pinned in c.Pinned)
            foreach (var chunks in Chunkings(L(pinned)))
                Assert.Equal(R, ThroughRedactor(c.Secret, chunks));
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public async Task TemplateOutput_EachPinnedFormAlone_BecomesOneRedaction(string label)
    {
        var c = Cases[label];
        foreach (var pinned in c.Pinned)
            foreach (var chunks in Chunkings(L(pinned)))
                Assert.Equal(R, await ThroughTemplateOutput(c.Secret, chunks));
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public void Redactor_HandBuiltOverlaps_GiveTheExactOutput_AtAnyChunking(string label)
    {
        var c = Cases[label];
        foreach (var (input, expected) in c.Overlaps)
            foreach (var chunks in Chunkings(L(input)))
                Assert.Equal(expected, ThroughRedactor(c.Secret, chunks));
    }

    [Theory]
    [MemberData(nameof(Labels))]
    public async Task TemplateOutput_HandBuiltOverlaps_GiveTheExactOutput_AtAnyChunking(string label)
    {
        var c = Cases[label];
        foreach (var (input, expected) in c.Overlaps)
            foreach (var chunks in Chunkings(L(input)))
                Assert.Equal(expected, await ThroughTemplateOutput(c.Secret, chunks));
    }

    [Fact]
    public async Task TheHexOnlyInput3131_ForSecret11_IsRedacted_ByBoth()
    {
        // The brief's named case: "11"'s hex form alone, which only the hex forms catch.
        var secret = "11"u8.ToArray();
        foreach (var chunks in Chunkings(L("3131")))
        {
            Assert.Equal(R, ThroughRedactor(secret, chunks));
            Assert.Equal(R, await ThroughTemplateOutput(secret, chunks));
        }
    }
}
