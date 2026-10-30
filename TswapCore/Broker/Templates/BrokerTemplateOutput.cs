using System.Security.Cryptography;

namespace TswapCore.Broker.Templates;

/// <summary>
/// A template's output on its way to the caller (brief T9 decision 6): stdout and stderr go through
/// <b>one</b> redactor state, in the order they were read, so a secret split across the two streams
/// is still caught; then they are counted against <c>max_output_bytes</c>.
/// <list type="bullet">
/// <item>Redaction comes first, on bytes: every known form of every secret the template used (the
/// forms of T8's <see cref="BrokerRedactor"/>), longest first, replaced by <c>[REDACTED]</c>; a
/// replacement goes to the stream the match started in.</item>
/// <item>Then the cut: output beyond the limit is read and discarded (the child keeps running), and
/// the held-back window is dropped at the cut, never flushed, so no fragment of a secret that the
/// cut separated from its end can leak.</item>
/// </list>
/// Nothing is buffered beyond the window (longest form − 1 bytes).
/// </summary>
public sealed class BrokerTemplateOutput
{
    private readonly byte[][] _forms;
    private readonly bool[] _firstByte = new bool[256];
    private readonly int _window;
    private readonly long _max;
    private readonly Func<BrokerOutputKind, ReadOnlyMemory<byte>, ValueTask> _emit;
    private byte[] _carry = [];
    private BrokerOutputKind[] _carryKinds = [];

    /// <param name="secrets">Copies of the secrets; this zeroes them once their forms are built.</param>
    public BrokerTemplateOutput(IEnumerable<byte[]> secrets, long maxBytes, Func<BrokerOutputKind, ReadOnlyMemory<byte>, ValueTask> emit)
    {
        var forms = new List<byte[]>();
        foreach (var secret in secrets)
        {
            if (secret.Length == 0)
                continue;
            var redactor = BrokerRedactor.ForSecret(secret, null);
            foreach (var form in redactor.Forms)
                if (!forms.Any(f => f.AsSpan().SequenceEqual(form)))
                    forms.Add(form.ToArray());
            redactor.Clear();
            CryptographicOperations.ZeroMemory(secret); // fix round 1 (GLM 7, MiMo M1): the caller's copy too
        }
        _forms = [.. forms.OrderByDescending(f => f.Length)];
        foreach (var f in _forms)
            _firstByte[f[0]] = true;
        _window = _forms.Length == 0 ? 0 : _forms[0].Length - 1;
        _max = maxBytes;
        _emit = emit;
    }

    /// <summary>Bytes the child wrote (both streams).</summary>
    public long BytesIn { get; private set; }

    /// <summary>Bytes passed on (after redaction, at most the limit).</summary>
    public long BytesOut { get; private set; }

    /// <summary>True when output was cut at the limit.</summary>
    public bool Truncated { get; private set; }

    /// <summary>Takes a chunk the child wrote to <paramref name="kind"/>.</summary>
    public async ValueTask WriteAsync(BrokerOutputKind kind, ReadOnlyMemory<byte> chunk)
    {
        BytesIn += chunk.Length;
        if (Truncated || chunk.IsEmpty)
            return; // read and discarded
        var data = new byte[_carry.Length + chunk.Length];
        var kinds = new BrokerOutputKind[data.Length];
        _carry.CopyTo(data, 0);
        _carryKinds.CopyTo(kinds, 0);
        chunk.Span.CopyTo(data.AsSpan(_carry.Length));
        kinds.AsSpan(_carry.Length).Fill(kind);
        CryptographicOperations.ZeroMemory(_carry);

        var safeEnd = data.Length - _window; // a match starting before this fits in data
        var i = 0;
        var emitted = 0;
        while (i < safeEnd && !Truncated)
        {
            var length = _firstByte[data[i]] ? MatchAt(data, i) : 0;
            if (length == 0)
            {
                i++;
                continue;
            }
            await EmitRunsAsync(data, kinds, emitted, i).ConfigureAwait(false);
            await EmitAsync(kinds[i], BrokerRedactor.Replacement).ConfigureAwait(false);
            i += length;
            emitted = i;
        }
        var keepFrom = Math.Max(Math.Max(i, emitted), safeEnd < 0 ? 0 : Math.Min(safeEnd, data.Length));
        if (!Truncated)
            await EmitRunsAsync(data, kinds, emitted, keepFrom).ConfigureAwait(false);
        if (Truncated)
        {
            // The cut: the held-back window is dropped, never flushed.
            _carry = [];
            _carryKinds = [];
        }
        else
        {
            _carry = data[keepFrom..];
            _carryKinds = kinds[keepFrom..];
        }
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>The end of the output: the held-back window is redacted and passed on (unless the output was cut).</summary>
    public async ValueTask CompleteAsync()
    {
        if (!Truncated)
        {
            var data = _carry;
            var i = 0;
            var emitted = 0;
            while (i < data.Length && !Truncated)
            {
                var length = _firstByte[data[i]] ? MatchAt(data, i) : 0;
                if (length == 0)
                {
                    i++;
                    continue;
                }
                await EmitRunsAsync(data, _carryKinds, emitted, i).ConfigureAwait(false);
                await EmitAsync(_carryKinds[i], BrokerRedactor.Replacement).ConfigureAwait(false);
                i += length;
                emitted = i;
            }
            if (!Truncated)
                await EmitRunsAsync(data, _carryKinds, emitted, data.Length).ConfigureAwait(false);
        }
        Clear();
    }

    /// <summary>Zeroes the forms and the window.</summary>
    public void Clear()
    {
        foreach (var f in _forms)
            CryptographicOperations.ZeroMemory(f);
        CryptographicOperations.ZeroMemory(_carry);
        _carry = [];
        _carryKinds = [];
    }

    private int MatchAt(ReadOnlySpan<byte> data, int i)
    {
        foreach (var form in _forms)
            if (i + form.Length <= data.Length && data.Slice(i, form.Length).SequenceEqual(form))
                return form.Length;
        return 0;
    }

    /// <summary>Passes on data[from..to), split where the stream changes.</summary>
    private async ValueTask EmitRunsAsync(byte[] data, BrokerOutputKind[] kinds, int from, int to)
    {
        var start = from;
        for (var j = from; j <= to && !Truncated; j++)
        {
            if (j < to && kinds[j] == kinds[start])
                continue;
            if (j > start)
                await EmitAsync(kinds[start], data.AsMemory(start, j - start)).ConfigureAwait(false);
            start = j;
        }
    }

    /// <summary>Counts and passes on <paramref name="bytes"/>, cutting at the limit.</summary>
    private async ValueTask EmitAsync(BrokerOutputKind kind, ReadOnlyMemory<byte> bytes)
    {
        if (Truncated || bytes.IsEmpty)
            return;
        var room = _max - BytesOut;
        if (bytes.Length > room)
        {
            Truncated = true;
            bytes = bytes[..(int)Math.Max(0, room)];
        }
        if (bytes.IsEmpty)
            return;
        BytesOut += bytes.Length;
        // A copy: the caller's buffer is zeroed after this call.
        await _emit(kind, bytes.ToArray()).ConfigureAwait(false);
    }
}
