using System.Text;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T63 (#417): the broker's redactors (<see cref="BrokerRedactor"/> and <see cref="BrokerTemplateOutput"/>) match
/// each line break of a form (<c>\r\n</c>, <c>\n</c> or a lone <c>\r</c>) with any line break in the output, in any mix,
/// and the window stays "longest form − 1" because every form's CRLF spelling is listed as a form.
/// </summary>
public sealed class BrokerLineEndingRedactionTests
{
    private static string V2(string eol) => "line-one-secret" + eol + "line-two-secret";

    private static string V3(string e1, string e2) => "first-line-value" + e1 + "second-line-value" + e2 + "third-line-value";

    private const string CafeNfc = "café-line-one\r\ncafé-line-two";

    private static readonly string Ascii120 = string.Concat(Enumerable.Repeat("abcdefghij", 12));

    private static string Wrapped(string text, int width, string eol) =>
        string.Join(eol, text.Chunk(width).Select(static c => new string(c)));

    /// <summary>Row: the stored value and the text printed between <c>x </c> and <c> y</c>; null output: unchanged.</summary>
    private static (string Stored, string Printed, bool Masked) Row(int row) => row switch
    {
        1 => (V2("\r\n"), V2("\n"), true),
        2 => (V2("\n"), V2("\r\n"), true),
        3 => (V3("\r\n", "\r\n"), V3("\r\n", "\n"), true),
        4 => (V3("\n", "\n"), V3("\n", "\r\n"), true),
        5 => (V2("\r\n"), V2("\r"), true),
        6 => (V2("\r"), V2("\n"), true),
        7 => (V3("\n", "\n"), V3("\r", "\r\n"), true),
        8 => (V2("\n"), V2("\n\n"), false),
        9 => (CafeNfc, CafeNfc.Normalize(NormalizationForm.FormD).Replace("\r\n", "\n"), true),
        10 => (Ascii120, Wrapped(Convert.ToBase64String(Encoding.ASCII.GetBytes(Ascii120)), 64, "\r\n"), true),
        _ => throw new ArgumentOutOfRangeException(nameof(row)),
    };

    private static readonly int[] Rows = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    private static byte[] U(string text) => Encoding.UTF8.GetBytes(text);

    private static (byte[] Input, byte[] Expected) Case(int row)
    {
        var (_, printed, masked) = Row(row);
        var input = U("x " + printed + " y");
        return (input, masked ? U("x [REDACTED] y") : input);
    }

    private static byte[] ThroughRedactor(string stored, IEnumerable<byte[]> chunks)
    {
        var redactor = BrokerRedactor.ForSecret(U(stored), null);
        var output = new MemoryStream();
        foreach (var chunk in chunks)
            redactor.Process(chunk, output);
        redactor.Flush(output);
        return output.ToArray();
    }

    private static async Task<(byte[] Stdout, byte[] Stderr)> ThroughTemplateOutput(string stored,
        IEnumerable<(BrokerOutputKind Kind, byte[] Chunk)> chunks)
    {
        var stdout = new MemoryStream();
        var stderr = new MemoryStream();
        var outputter = new BrokerTemplateOutput([U(stored)], 1 << 20, (kind, data) =>
        {
            (kind == BrokerOutputKind.Stdout ? stdout : stderr).Write(data.Span);
            return ValueTask.CompletedTask;
        });
        foreach (var (kind, chunk) in chunks)
            await outputter.WriteAsync(kind, chunk);
        await outputter.CompleteAsync();
        return (stdout.ToArray(), stderr.ToArray());
    }

    private static IEnumerable<byte[]> OneBytePerChunk(byte[] input) => input.Select(static b => new[] { b });

    [UnixTheory("the broker is Unix only")]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public void Redactor_MasksAValue_PrintedWithOtherLineBreaks(int row)
    {
        var stored = Row(row).Stored;
        var (input, expected) = Case(row);

        Assert.Equal(expected, ThroughRedactor(stored, [input]));
        for (var split = 1; split < input.Length; split++)
            Assert.True(expected.AsSpan().SequenceEqual(ThroughRedactor(stored, [input[..split], input[split..]])),
                $"row {row}: split at byte {split} gave another output");
        Assert.Equal(expected, ThroughRedactor(stored, OneBytePerChunk(input)));
    }

    [UnixTheory("the broker is Unix only")]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public async Task TemplateOutput_MasksAValue_PrintedWithOtherLineBreaks(int row)
    {
        var stored = Row(row).Stored;
        var (input, expected) = Case(row);

        var whole = await ThroughTemplateOutput(stored, [(BrokerOutputKind.Stdout, input)]);
        var bytewise = await ThroughTemplateOutput(stored, OneBytePerChunk(input).Select(static c => (BrokerOutputKind.Stdout, c)));

        Assert.Equal(expected, whole.Stdout);
        Assert.Empty(whole.Stderr);
        Assert.Equal(expected, bytewise.Stdout);
        Assert.Empty(bytewise.Stderr);
    }

    /// <summary>Every break (<c>\r\n</c>, a lone <c>\r</c>, a bare <c>\n</c>) written as <c>\r\n</c>.</summary>
    private static byte[] CrLfSpelling(byte[] form)
    {
        List<byte> spelled = [];
        for (var i = 0; i < form.Length; i++)
        {
            if (form[i] == (byte)'\r' && i + 1 < form.Length && form[i + 1] == (byte)'\n')
                i++;
            else if (form[i] is not ((byte)'\r' or (byte)'\n'))
            {
                spelled.Add(form[i]);
                continue;
            }
            spelled.Add((byte)'\r');
            spelled.Add((byte)'\n');
        }
        return [.. spelled];
    }

    [UnixFact("the broker is Unix only")]
    public void Forms_LongestFormMinusOne_CoversEveryMatch()
    {
        foreach (var stored in Rows.Select(static r => Row(r).Stored).Distinct(StringComparer.Ordinal))
        {
            var redactor = BrokerRedactor.ForSecret(U(stored), null);
            var forms = redactor.Forms;

            Assert.Equal(forms.Max(static f => f.Length) - 1, redactor.Window);
            foreach (var form in forms)
            {
                Assert.True(BrokerRedactor.MaxMatchLength(form) - 1 <= redactor.Window,
                    $"a form of {form.Length} bytes can match more than the window holds");
                var crlf = CrLfSpelling(form);
                if (crlf.Length != form.Length)
                    Assert.True(forms.Any(f => f.AsSpan().SequenceEqual(crlf)),
                        $"a form of {form.Length} bytes with a one-byte break has no CRLF spelling of {crlf.Length} bytes in Forms");
            }
        }

        var row10 = BrokerRedactor.ForSecret(U(Ascii120), null).Forms;
        var wrapped64CrLf = U(Wrapped(Convert.ToBase64String(U(Ascii120)), 64, "\r\n"));
        Assert.Equal(164, wrapped64CrLf.Length);
        Assert.Contains(row10, f => f.AsSpan().SequenceEqual(wrapped64CrLf));
    }

    [UnixFact("the broker is Unix only")]
    public void Forms_OfAValueWithNoLineBreak_HoldNoLineBreak()
    {
        var forms = BrokerRedactor.FormsOf(U("s3cr3t-Value_+/=é"), null);

        Assert.NotEmpty(forms);
        Assert.All(forms, static f => Assert.False(f.Contains((byte)'\r') || f.Contains((byte)'\n'), "a form holds a line break"));
    }

    /// <summary>
    /// DeepSeek's brief review (M-2): a value ending in a line break, printed as the last bytes of the output with a
    /// <c>\r</c>: at the end (<see cref="BrokerRedactor.Flush"/>, <see cref="BrokerTemplateOutput.CompleteAsync"/>) that
    /// <c>\r</c> is a lone CR, a line break, never a match cut short.
    /// </summary>
    [UnixFact("the broker is Unix only")]
    public async Task ValueEndingInALineBreak_PrintedLastWithALoneCr_Masked()
    {
        const string stored = "line-one-secret\n";
        var input = U("x line-one-secret\r");
        var expected = U("x [REDACTED]");

        Assert.Equal(expected, ThroughRedactor(stored, [input]));
        Assert.Equal(expected, ThroughRedactor(stored, OneBytePerChunk(input)));
        Assert.Equal(expected, (await ThroughTemplateOutput(stored, [(BrokerOutputKind.Stdout, input)])).Stdout);
        Assert.Equal(expected, (await ThroughTemplateOutput(stored, OneBytePerChunk(input).Select(static c => (BrokerOutputKind.Stdout, c)))).Stdout);
    }

    [UnixFact("the broker is Unix only")]
    public async Task TemplateOutput_MatchStartingOnStdout_ReplacedOnStdout()
    {
        var (input, _) = Case(1);
        var half = input.Length / 2;

        var (stdout, stderr) = await ThroughTemplateOutput(Row(1).Stored,
            [(BrokerOutputKind.Stdout, input[..half]), (BrokerOutputKind.Stderr, input[half..])]);

        Assert.Equal(U("x [REDACTED]"), stdout);
        Assert.Equal(U(" y"), stderr);
    }
}
