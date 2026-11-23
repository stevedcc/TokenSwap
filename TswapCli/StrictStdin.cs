using System.Text;
using TswapCore;

namespace TswapCli;

/// <summary>
/// Brief T48: the one reader of redirected stdin (<see cref="SystemConsole.In"/> and its piped <c>ReadLine</c>), for
/// the life of the process. UTF-8 on every OS, never the console's code page: a leading UTF-8 BOM is dropped, a UTF-16
/// or UTF-32 BOM switches to that encoding (Windows PowerShell 5.1 sends UTF-16 when <c>$OutputEncoding</c> is
/// Unicode), and input that is not valid in the encoding in force is refused with <see cref="InvalidInput"/>, never
/// stored with U+FFFD. A U+FEFF after the first character is data and is kept.
/// </summary>
/// <remarks>
/// <c>agent serve</c> never reads stdin through this reader: after <c>ProcessDetach</c> the agent's own protocol owns
/// fd 0 (<c>AgentCommand</c>'s <c>Console.OpenStandardInput()</c>).
/// </remarks>
internal static class StrictStdin
{
    /// <summary>The refusal: one fixed text on every OS, naming no byte or character of the input.</summary>
    internal const string InvalidInput =
        "stdin is not valid UTF-8 (tswap reads piped input as UTF-8). Nothing was changed. In Windows PowerShell 5.1, run $OutputEncoding = [System.Text.UTF8Encoding]::new($false) first, or use PowerShell 7.";

    private static readonly Lazy<TextReader> SharedReader = new(() => Create(Console.OpenStandardInput()));

    /// <summary>The process's one reader of redirected stdin, created on first use.</summary>
    internal static TextReader Shared => SharedReader.Value;

    /// <summary>
    /// A strict reader over <paramref name="stream"/>. Nothing is read until the first read; then the leading bytes are
    /// peeked (one at a time, only as many as a byte order mark could need) to choose the encoding.
    /// </summary>
    internal static TextReader Create(Stream stream) => new BomPeekingReader(stream);

    // The byte order marks, the 4-byte ones first (A15): FF FE 00 00 is UTF-32LE, not UTF-16LE then a NUL.
    private static readonly (byte[] Bom, Func<Encoding> Encoding)[] Boms =
    [
        ([0xFF, 0xFE, 0x00, 0x00], () => new UTF32Encoding(bigEndian: false, byteOrderMark: false, throwOnInvalidCharacters: true)),
        ([0x00, 0x00, 0xFE, 0xFF], () => new UTF32Encoding(bigEndian: true, byteOrderMark: false, throwOnInvalidCharacters: true)),
        ([0xEF, 0xBB, 0xBF], () => new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)),
        ([0xFF, 0xFE], () => new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true)),
        ([0xFE, 0xFF], () => new UnicodeEncoding(bigEndian: true, byteOrderMark: false, throwOnInvalidBytes: true)),
    ];

    /// <summary>
    /// Reads the leading bytes while they are still a proper prefix of some BOM (so a pipe that delivers one line at a
    /// time is never waited on for more than a BOM needs), then returns the encoding and the bytes after the BOM.
    /// </summary>
    private static (Encoding Encoding, byte[] AfterBom) PeekBom(Stream stream)
    {
        List<byte> head = [];
        while (Boms.Any(b => b.Bom.Length > head.Count && b.Bom.AsSpan().StartsWith(head.ToArray())))
        {
            var next = stream.ReadByte();
            if (next < 0)
                break;
            head.Add((byte)next);
        }
        var bytes = head.ToArray();
        foreach (var (bom, encoding) in Boms)
            if (bytes.AsSpan().StartsWith(bom))
                return (Strict(encoding()), bytes[bom.Length..]);
        return (Strict(new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)), bytes);
    }

    /// <summary><paramref name="encoding"/> whose decoder refuses with <see cref="InvalidInput"/> (no inner exception).</summary>
    private static Encoding Strict(Encoding encoding)
    {
        var strict = (Encoding)encoding.Clone();
        strict.DecoderFallback = RefusingDecoderFallback.Instance;
        return strict;
    }

    /// <summary>
    /// A3: the refusal is thrown by the decoding itself, so <c>Read</c>, <c>ReadLine</c>, <c>ReadBlock</c>,
    /// <c>ReadToEnd</c> and the end-of-stream flush are all covered; .NET's <see cref="DecoderFallbackException"/>
    /// would name the bytes.
    /// </summary>
    private sealed class RefusingDecoderFallback : DecoderFallback
    {
        public static readonly RefusingDecoderFallback Instance = new();

        public override int MaxCharCount => 0;

        public override DecoderFallbackBuffer CreateFallbackBuffer() => new Buffer();

        private sealed class Buffer : DecoderFallbackBuffer
        {
            public override bool Fallback(byte[] bytesUnknown, int index) => throw new TswapException(InvalidInput);
            public override char GetNextChar() => '\0';
            public override bool MovePrevious() => false;
            public override int Remaining => 0;
        }
    }

    /// <summary>The peeked bytes, then the rest of the stream.</summary>
    private sealed class ReplayStream(byte[] head, Stream rest) : Stream
    {
        private int _position;

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_position < head.Length)
            {
                var n = Math.Min(buffer.Length, head.Length - _position);
                head.AsSpan(_position, n).CopyTo(buffer);
                _position += n;
                return n;
            }
            return rest.Read(buffer);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                rest.Dispose();
            base.Dispose(disposing);
        }
    }

    /// <summary>Chooses the encoding at the first read, then reads through a strict <see cref="StreamReader"/>.</summary>
    private sealed class BomPeekingReader(Stream stream) : TextReader
    {
        private StreamReader? _inner;

        private StreamReader Inner
        {
            get
            {
                if (_inner is null)
                {
                    var (encoding, rest) = PeekBom(stream);
                    // A2: no detection of its own: StreamReader's swaps in Encoding.UTF8/Unicode/UTF32, which replace.
                    _inner = new StreamReader(new ReplayStream(rest, stream), encoding, detectEncodingFromByteOrderMarks: false);
                }
                return _inner;
            }
        }

        public override int Peek() => Inner.Peek();
        public override int Read() => Inner.Read();
        public override int Read(char[] buffer, int index, int count) => Inner.Read(buffer, index, count);
        public override int Read(Span<char> buffer) => Inner.Read(buffer);
        public override int ReadBlock(char[] buffer, int index, int count) => Inner.ReadBlock(buffer, index, count);
        public override int ReadBlock(Span<char> buffer) => Inner.ReadBlock(buffer);
        public override string? ReadLine() => Inner.ReadLine();
        public override string ReadToEnd() => Inner.ReadToEnd();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_inner is not null)
                    _inner.Dispose();
                else
                    stream.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
