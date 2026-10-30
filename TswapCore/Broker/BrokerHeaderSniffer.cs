using System.Buffers;
using System.IO.Pipelines;
using System.Text;

namespace TswapCore.Broker;

/// <summary>
/// Kestrel rewrites a request's <c>Connection</c> header to <c>keep-alive</c> or <c>close</c>, so the
/// header names a client lists there (decision 6: dropped, never forwarded) are not visible in
/// <c>Request.Headers</c>. This reader sits between the socket and Kestrel, passes every byte through
/// unchanged, and copies the first request's header block (up to <see cref="MaxCapture"/> bytes) so
/// <see cref="TakeConnectionNamedHeaders"/> can read the raw <c>Connection</c> lines. The broker answers
/// every request with <c>Connection: close</c>, so the first request is the only one on a connection.
/// </summary>
public sealed class BrokerHeaderSniffer : PipeReader
{
    /// <summary>More than Kestrel's request line plus header limits; Kestrel refuses a bigger header block anyway.</summary>
    public const int MaxCapture = 64 * 1024;

    private readonly PipeReader _inner;
    private readonly MemoryStream _capture = new();
    private ReadOnlySequence<byte> _last;
    private long _consumed;   // absolute offset of _last's start
    private bool _complete;   // header block captured (or limit reached)

    public BrokerHeaderSniffer(PipeReader inner) => _inner = inner;

    /// <summary>True once the first header block ended (or the capture limit was reached).</summary>
    public bool HeadersSeen => _complete;

    /// <summary>
    /// The header names the first request's raw <c>Connection</c> lines list (lower case), excluding
    /// close and keep-alive. The captured header block (which holds the client's own header values)
    /// is zeroed afterwards; later calls return an empty set.
    /// </summary>
    public IReadOnlySet<string> TakeConnectionNamedHeaders()
    {
        var block = _capture.ToArray();
        try
        {
            return ParseConnectionTokens(block);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(block);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_capture.GetBuffer());
            _capture.SetLength(0);
            _complete = true;
        }
    }
    internal long CapturedLength => _capture.Length;
    internal byte[] CaptureBufferForTests => _capture.GetBuffer();

    public override async ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        var result = await _inner.ReadAsync(cancellationToken).ConfigureAwait(false);
        Observe(result.Buffer);
        return result;
    }

    public override bool TryRead(out ReadResult result)
    {
        if (!_inner.TryRead(out result))
            return false;
        Observe(result.Buffer);
        return true;
    }

    public override void AdvanceTo(SequencePosition consumed)
    {
        _consumed += _last.Slice(_last.Start, consumed).Length;
        _inner.AdvanceTo(consumed);
    }

    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
    {
        _consumed += _last.Slice(_last.Start, consumed).Length;
        _inner.AdvanceTo(consumed, examined);
    }

    public override void CancelPendingRead() => _inner.CancelPendingRead();

    public override void Complete(Exception? exception = null) => _inner.Complete(exception);

    public override ValueTask CompleteAsync(Exception? exception = null) => _inner.CompleteAsync(exception);

    private void Observe(ReadOnlySequence<byte> buffer)
    {
        _last = buffer;
        if (_complete)
            return;
        // Copy the bytes of this buffer that lie beyond what has been captured already.
        var end = _consumed + buffer.Length;
        if (end > _capture.Length)
        {
            var skip = _capture.Length - _consumed;
            var take = Math.Min(end - _capture.Length, MaxCapture - _capture.Length);
            if (skip >= 0 && take > 0)
                foreach (var segment in buffer.Slice(skip, take))
                    _capture.Write(segment.Span);
        }
        if (_capture.Length >= MaxCapture || HeaderEnd(_capture.GetBuffer().AsSpan(0, (int)_capture.Length)) >= 0)
            _complete = true;
    }

    private static int HeaderEnd(ReadOnlySpan<byte> bytes) => bytes.IndexOf("\r\n\r\n"u8);

    /// <summary>The header names listed by raw <c>Connection</c> header lines in <paramref name="headerBlock"/> (lower case).</summary>
    public static IReadOnlySet<string> ParseConnectionTokens(byte[] headerBlock)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var end = HeaderEnd(headerBlock);
        var text = Encoding.Latin1.GetString(headerBlock, 0, end < 0 ? headerBlock.Length : end);
        var lines = text.Split("\r\n");
        foreach (var line in lines.Skip(1)) // the request line first
        {
            var colon = line.IndexOf(':');
            if (colon <= 0 || !line[..colon].Trim().Equals("Connection", StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var token in line[(colon + 1)..].Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                if (!token.Equals("close", StringComparison.OrdinalIgnoreCase) && !token.Equals("keep-alive", StringComparison.OrdinalIgnoreCase))
                    names.Add(token.ToLowerInvariant());
        }
        return names;
    }
}

/// <summary>A connection's transport with its input replaced by a <see cref="BrokerHeaderSniffer"/>.</summary>
internal sealed class SniffedDuplexPipe(IDuplexPipe inner, BrokerHeaderSniffer input) : IDuplexPipe
{
    public PipeReader Input => input;
    public PipeWriter Output => inner.Output;
}
