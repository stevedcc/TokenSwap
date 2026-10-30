using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TswapCore.Broker;

/// <summary>
/// The streaming redactor (brief T8 decision 8). Every response body passes through it before it
/// reaches the client, and every response header value is checked with <see cref="Contains"/>.
/// <para>
/// <b>Best effort:</b> a hostile upstream can obfuscate a value past any window. The guarantee is
/// that the broker never emits a <i>known form</i> of the value (<see cref="Forms"/>), and only ever
/// sends the value to that route's upstream, over TLS, inside the route's path and method envelope.
/// </para>
/// <para>
/// It holds a sliding window of (longest form − 1) bytes between chunks, flushed at the end; it
/// never buffers the body. Matches are leftmost, longest form first, and replaced by
/// <c>[REDACTED]</c>.
/// </para>
/// </summary>
public sealed class BrokerRedactor
{
    public static readonly byte[] Replacement = "[REDACTED]"u8.ToArray();

    /// <summary>A derived base64 core shorter than this is not used (it would redact ordinary text).</summary>
    private const int MinAlignedCoreLength = 8;

    private readonly byte[][] _forms;       // longest first
    private readonly bool[] _firstByte = new bool[256];
    private readonly byte[] _carry;
    private int _carryLength;

    private BrokerRedactor(byte[][] forms)
    {
        _forms = forms;
        foreach (var f in forms)
            _firstByte[f[0]] = true;
        Window = forms.Length == 0 ? 0 : forms[0].Length - 1;
        _carry = new byte[Window];
    }

    /// <summary>The byte patterns redacted, longest first.</summary>
    public IReadOnlyList<byte[]> Forms => _forms;

    /// <summary>The bytes held back between chunks: the longest form's length minus one.</summary>
    public int Window { get; }

    /// <summary>
    /// The forms of <paramref name="secret"/> (decision 8): the raw value; base64 with and without
    /// padding, and base64url (also at the two other byte alignments, as found inside a longer
    /// base64 stream); for a <c>basic</c> route (<paramref name="basicUser"/>) the exact
    /// <c>base64(user:secret)</c> the broker sent and <c>user:secret</c>; hex, upper and lower case;
    /// percent-encoded (upper and lower hex, and form encoding); JSON-escaped (default, relaxed and
    /// minimal escaping, each also with <c>\/</c>); the value's base64 wrapped at 76 (LF and CRLF)
    /// and 64 columns, hex with spaces between bytes, and hex wrapped at 60 (T9 fix round 1).
    /// <c>tswap run</c>'s redaction covers the raw value, which is included.
    /// </summary>
    public static BrokerRedactor ForSecret(ReadOnlySpan<byte> secret, string? basicUser)
    {
        var forms = new List<byte[]>();
        void Add(byte[] form)
        {
            if (form.Length > 0 && !forms.Any(f => f.AsSpan().SequenceEqual(form)))
                forms.Add(form);
        }
        void AddText(string text) => Add(Encoding.UTF8.GetBytes(text));
        void AddWrapped(string text, int width, string eol)
        {
            if (text.Length > width)
                AddText(string.Join(eol, text.Chunk(width).Select(c => new string(c))));
        }
        void AddBase64(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            var url = b64.Replace('+', '-').Replace('/', '_');
            AddText(b64);
            AddText(b64.TrimEnd('='));
            AddText(url);
            AddText(url.TrimEnd('='));
        }

        var raw = secret.ToArray();
        Add(raw);
        AddBase64(raw);

        // The value inside a longer base64 stream: at each byte alignment k, the characters that
        // depend only on the value's bytes.
        for (var k = 0; k < 3; k++)
        {
            var padded = new byte[k + raw.Length];
            raw.CopyTo(padded, k);
            var encoded = Convert.ToBase64String(padded);
            var start = (8 * k + 5) / 6;
            var end = 8 * (k + raw.Length) / 6;
            if (end - start < MinAlignedCoreLength)
                continue;
            var core = encoded[start..end];
            AddText(core);
            AddText(core.Replace('+', '-').Replace('/', '_'));
        }

        if (basicUser != null)
        {
            var composite = Encoding.ASCII.GetBytes(basicUser + ":").Concat(raw).ToArray();
            Add(composite);
            AddBase64(composite);
        }

        var hex = Convert.ToHexString(raw);
        AddText(hex);
        AddText(hex.ToLowerInvariant());

        // T9 fix round 1 (MiMo I3): the shapes common tools print the value alone in. Base64
        // wrapped at 76 columns (GNU base64, MIME with CRLF) and at 64 (openssl base64); hex with a
        // space between bytes (od -An -tx1, xxd -g1, within one line) and plain hex wrapped at 60
        // (xxd -p). A value inside a longer wrapped stream, or split over xxd's or od's lines
        // with offsets and an ASCII column between, is not covered (BROKER.md says so).
        var b64Plain = Convert.ToBase64String(raw);
        AddWrapped(b64Plain, 76, "\n");
        AddWrapped(b64Plain, 76, "\r\n");
        AddWrapped(b64Plain, 64, "\n");
        var lowerHex = hex.ToLowerInvariant();
        if (raw.Length > 1)
        {
            AddText(string.Join(' ', Enumerable.Range(0, raw.Length).Select(i => lowerHex.Substring(2 * i, 2))));
            AddText(string.Join(' ', Enumerable.Range(0, raw.Length).Select(i => hex.Substring(2 * i, 2))));
        }
        AddWrapped(lowerHex, 60, "\n");

        var value = Encoding.UTF8.GetString(raw);
        var percent = Uri.EscapeDataString(value);
        AddText(percent);
        AddText(LowerHexEscapes(percent));
        var form = WebUtility.UrlEncode(value);
        AddText(form);
        AddText(LowerHexEscapes(form));

        foreach (var json in new[]
                 {
                     JsonEncodedText.Encode(value).Value,
                     JsonEncodedText.Encode(value, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).Value,
                     MinimalJsonEscape(value),
                 })
        {
            AddText(json);
            AddText(json.Replace("/", "\\/"));
        }

        return new BrokerRedactor([.. forms.OrderByDescending(f => f.Length)]);
    }

    private static string LowerHexEscapes(string s) =>
        Regex.Replace(s, "%[0-9A-F]{2}", m => m.Value.ToLowerInvariant(), RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static string MinimalJsonEscape(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case < ' ': sb.Append("\\u").Append(((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture)); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    /// <summary>True when <paramref name="headerValue"/> (as its Latin-1 wire bytes) contains a form.</summary>
    public bool Contains(string headerValue)
    {
        var bytes = Encoding.Latin1.GetBytes(headerValue);
        var utf8 = Encoding.UTF8.GetBytes(headerValue);
        return IndexOfForm(bytes) >= 0 || IndexOfForm(utf8) >= 0;
    }

    private int IndexOfForm(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
            if (_firstByte[data[i]] && MatchAt(data, i) > 0)
                return i;
        return -1;
    }

    /// <summary>The length of the longest form at <paramref name="i"/> that fits in <paramref name="data"/>, or 0.</summary>
    private int MatchAt(ReadOnlySpan<byte> data, int i)
    {
        foreach (var form in _forms)
            if (i + form.Length <= data.Length && data.Slice(i, form.Length).SequenceEqual(form))
                return form.Length;
        return 0;
    }

    /// <summary>Redacts <paramref name="input"/> into <paramref name="output"/>, holding back at most <see cref="Window"/> bytes.</summary>
    public void Process(ReadOnlySpan<byte> input, Stream output)
    {
        if (input.IsEmpty)
            return;
        var data = new byte[_carryLength + input.Length];
        _carry.AsSpan(0, _carryLength).CopyTo(data);
        input.CopyTo(data.AsSpan(_carryLength));
        var safeEnd = data.Length - Window; // a match starting before this fits in data
        var i = 0;
        var emitted = 0;
        while (i < safeEnd)
        {
            var length = _firstByte[data[i]] ? MatchAt(data, i) : 0;
            if (length > 0)
            {
                output.Write(data, emitted, i - emitted);
                output.Write(Replacement);
                i += length;
                emitted = i;
            }
            else
            {
                i++;
            }
        }
        if (i < emitted)
            i = emitted;
        output.Write(data, emitted, Math.Max(i, emitted) - emitted);
        _carryLength = data.Length - Math.Max(i, emitted);
        data.AsSpan(data.Length - _carryLength).CopyTo(_carry);
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>Redacts and writes the held-back bytes (the end of the body).</summary>
    public void Flush(Stream output)
    {
        ReadOnlySpan<byte> data = _carry.AsSpan(0, _carryLength);
        var i = 0;
        var emitted = 0;
        while (i < data.Length)
        {
            var length = _firstByte[data[i]] ? MatchAt(data, i) : 0;
            if (length > 0)
            {
                output.Write(data[emitted..i]);
                output.Write(Replacement);
                i += length;
                emitted = i;
            }
            else
            {
                i++;
            }
        }
        output.Write(data[emitted..]);
        CryptographicOperations.ZeroMemory(_carry);
        _carryLength = 0;
    }

    /// <summary>Zeroes the forms and the window (the end of the request).</summary>
    public void Clear()
    {
        foreach (var form in _forms)
            CryptographicOperations.ZeroMemory(form);
        CryptographicOperations.ZeroMemory(_carry);
        _carryLength = 0;
    }
}
