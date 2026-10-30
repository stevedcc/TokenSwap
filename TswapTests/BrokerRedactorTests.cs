using System.Text;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>Brief T8 item 4 (decision 8): the streaming redactor on its own.</summary>
public class BrokerRedactorTests
{
    private const string Secret = "s3cr3t-Value_+/=é";

    private static string Run(BrokerRedactor redactor, params string[] chunks)
    {
        var output = new MemoryStream();
        foreach (var chunk in chunks)
            redactor.Process(Encoding.Latin1.GetBytes(chunk), output);
        redactor.Flush(output);
        return Encoding.Latin1.GetString(output.ToArray());
    }

    public static TheoryData<string> Forms()
    {
        var data = new TheoryData<string>();
        foreach (var form in BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), "x-access-token").Forms)
            data.Add(Encoding.Latin1.GetString(form));
        return data;
    }

    [Fact]
    public void Forms_CoverEveryEncodingTheBriefLists()
    {
        var bytes = Encoding.UTF8.GetBytes(Secret);
        var forms = BrokerRedactor.ForSecret(bytes, "x-access-token").Forms.Select(f => Encoding.Latin1.GetString(f)).ToHashSet();

        Assert.Contains(Encoding.Latin1.GetString(bytes), forms);                         // raw
        Assert.Contains(Convert.ToBase64String(bytes), forms);                            // base64, padded
        Assert.Contains(Convert.ToBase64String(bytes).TrimEnd('='), forms);               // unpadded
        Assert.Contains(Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'), forms); // base64url
        Assert.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes("x-access-token:" + Secret)), forms); // basic composite
        Assert.Contains(Convert.ToHexString(bytes), forms);                               // hex upper
        Assert.Contains(Convert.ToHexString(bytes).ToLowerInvariant(), forms);            // hex lower
        Assert.Contains(Uri.EscapeDataString(Secret), forms);                             // percent
        Assert.Contains(Uri.EscapeDataString(Secret).Replace("%C3%A9", "%c3%a9").Replace("%2B", "%2b").Replace("%2F", "%2f").Replace("%3D", "%3d"), forms);
        Assert.Contains(System.Text.Json.JsonEncodedText.Encode(Secret).Value, forms);   // JSON-escaped
        Assert.Contains(forms, f => f.Contains("\\/") && f.StartsWith("s3cr3t-Value_", StringComparison.Ordinal)); // '/' escaped as \/
    }

    [Theory]
    [MemberData(nameof(Forms))]
    public void EveryForm_IsRedacted_WholeAndSplitAcrossChunks(string form)
    {
        var redactor = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), "x-access-token");
        var whole = Run(redactor, "before " + form + " after");
        Assert.Equal("before [REDACTED] after", whole);

        for (var split = 1; split < form.Length; split++)
        {
            var r = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), "x-access-token");
            var output = new MemoryStream();
            r.Process(Encoding.Latin1.GetBytes("a" + form[..split]), output);
            r.Process(Encoding.Latin1.GetBytes(form[split..] + "b"), output);
            r.Flush(output);
            Assert.Equal("a[REDACTED]b", Encoding.Latin1.GetString(output.ToArray()));
        }
    }

    [Fact]
    public void Base64AtAnyAlignment_InsideALongerBase64Stream_IsRedacted()
    {
        var secret = Encoding.UTF8.GetBytes("a-long-enough-secret-value-123");
        foreach (var prefix in new[] { "", "x", "xy" })
        {
            var stream = Convert.ToBase64String(Encoding.UTF8.GetBytes(prefix).Concat(secret).Concat("tail"u8.ToArray()).ToArray());
            var r = BrokerRedactor.ForSecret(secret, null);
            var output = new MemoryStream();
            r.Process(Encoding.ASCII.GetBytes(stream), output);
            r.Flush(output);
            Assert.Contains("[REDACTED]", Encoding.ASCII.GetString(output.ToArray()));
        }
    }

    [Fact]
    public void OneByteChunks_AreRedacted_AndOtherBytesPassUnchanged()
    {
        var redactor = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), null);
        var text = "x" + Secret + "y" + Secret + Secret + "z\u0000ÿ";
        var output = new MemoryStream();
        foreach (var b in Encoding.UTF8.GetBytes(text))
            redactor.Process([b], output);
        redactor.Flush(output);

        Assert.Equal("x[REDACTED]y[REDACTED][REDACTED]z\u0000ÿ", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void Window_IsLongestFormMinusOne_AndProcessNeverHoldsMore()
    {
        var redactor = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), "x-access-token");
        Assert.Equal(redactor.Forms.Max(f => f.Length) - 1, redactor.Window);

        var output = new MemoryStream();
        var chunk = new byte[1 << 20];
        Array.Fill(chunk, (byte)'q');
        redactor.Process(chunk, output);
        Assert.True(output.Length >= chunk.Length - redactor.Window); // all but the window went out at once
        redactor.Flush(output);
        Assert.Equal(chunk.Length, output.Length);
    }

    [Fact]
    public void Contains_FindsAFormInAHeaderValue()
    {
        var redactor = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), null);
        Assert.True(redactor.Contains("token=" + Convert.ToHexString(Encoding.UTF8.GetBytes(Secret)).ToLowerInvariant()));
        Assert.False(redactor.Contains("nothing here"));
    }

    [Fact]
    public void Clear_ZeroesTheForms()
    {
        var redactor = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), null);
        var forms = redactor.Forms.ToList();
        redactor.Clear();
        Assert.All(forms, f => Assert.All(f, b => Assert.Equal(0, b)));
    }
}
