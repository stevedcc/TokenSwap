using System.Text;
using System.Text.RegularExpressions;
using TswapCli;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T48: redirected stdin is read through one strict reader (<see cref="StrictStdin"/>): UTF-8 unless a UTF-16 or
/// UTF-32 byte order mark says otherwise, a leading UTF-8 BOM dropped, and invalid input refused with one fixed
/// message that names no byte of the input, never replaced with U+FFFD.
/// </summary>
public sealed partial class StdinUtf8ReaderTests
{
    private const string Refusal =
        "stdin is not valid UTF-8 (tswap reads piped input as UTF-8). Nothing was changed. In Windows PowerShell 5.1, run $OutputEncoding = [System.Text.UTF8Encoding]::new($false) first, or use PowerShell 7.";

    /// <summary>A10: hex fragments of the refused rows' bytes, none of which the message may contain.</summary>
    private static readonly string[] HexFragments = ["C3", "FF", "F0", "9F", "98", "D8", "3D"];

    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];

    private static string ReadAll(byte[] bytes, bool oneBytePerRead = false)
    {
        Stream stream = oneBytePerRead ? new OneBytePerReadStream(bytes) : new MemoryStream(bytes);
        using var reader = StrictStdin.Create(stream);
        return reader.ReadToEnd();
    }

    private static void AssertRefused(byte[] bytes, bool oneBytePerRead = false)
    {
        var ex = Assert.Throws<TswapException>(() => ReadAll(bytes, oneBytePerRead));
        Assert.Equal(Refusal, ex.Message);
        Assert.Equal(1, ex.ExitCode);
        Assert.Null(ex.InnerException); // A3: DecoderFallbackException's message names the bytes
        foreach (var hex in HexFragments)
            Assert.DoesNotContain(hex, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    public static TheoryData<string> NonAsciiCases()
    {
        var data = new TheoryData<string>();
        foreach (var c in EvilValues.Cases.Where(c => c.Value.Any(ch => ch > '\x7F')))
            data.Add(c.Name);
        return data;
    }

    [Theory]
    [MemberData(nameof(NonAsciiCases))]
    public void Utf8OfEveryNonAsciiCorpusValue_IsReadExactly(string caseName)
    {
        var value = EvilValues.Get(caseName).Value;
        Assert.Equal(value, ReadAll(Encoding.UTF8.GetBytes(value)));
    }

    [Fact]
    public void NonAsciiCorpus_IsNotEmpty() => Assert.True(NonAsciiCases().Count >= 10);

    [Fact]
    public void LeadingUtf8Bom_IsDropped() =>
        Assert.Equal("café-value", ReadAll([.. Utf8Bom, .. Encoding.UTF8.GetBytes("café-value")]));

    [Fact]
    public void LeadingUtf8Bom_OneBytePerRead_IsDropped() =>
        Assert.Equal("café-value", ReadAll([.. Utf8Bom, .. Encoding.UTF8.GetBytes("café-value")], oneBytePerRead: true));

    [Fact]
    public void ByteOrderMarkInside_IsKept() =>
        Assert.Equal("abcdefg﻿hijklmno", ReadAll(Encoding.UTF8.GetBytes("abcdefg﻿hijklmno")));

    [Fact]
    public void Utf16LeBom_SwitchesToUtf16Le() =>
        Assert.Equal("café-value", ReadAll([0xFF, 0xFE, .. Encoding.Unicode.GetBytes("café-value")]));

    [Fact]
    public void Utf16BeBom_SwitchesToUtf16Be() =>
        Assert.Equal("café-value", ReadAll([0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes("café-value")]));

    /// <summary>A15: fails when the 2-byte UTF-16LE BOM is checked before the 4-byte UTF-32LE one.</summary>
    [Fact]
    public void Utf32LeBom_SwitchesToUtf32Le() =>
        Assert.Equal("café-value", ReadAll([0xFF, 0xFE, 0x00, 0x00, .. new UTF32Encoding(false, false).GetBytes("café-value")]));

    [Fact]
    public void Utf32BeBom_SwitchesToUtf32Be() =>
        Assert.Equal("café-value", ReadAll([0x00, 0x00, 0xFE, 0xFF, .. new UTF32Encoding(true, false).GetBytes("café-value")]));

    [Fact]
    public void OneBytePerRead_FourByteSequence_IsReadExactly() =>
        Assert.Equal("abc\U0001F600def-value", ReadAll(Encoding.UTF8.GetBytes("abc\U0001F600def-value"), oneBytePerRead: true));

    [Fact]
    public void InvalidContinuation_IsRefused() => AssertRefused([0x63, 0x61, 0x66, 0xC3, 0x28]);

    [Fact]
    public void ByteNeverValidInUtf8_IsRefused() => AssertRefused([0x61, 0xFF, 0x62]);

    [Fact]
    public void TruncatedFourByteSequenceAtTheEnd_IsRefused() => AssertRefused([0x61, 0xF0, 0x9F, 0x98]);

    [Fact]
    public void Utf8BomThenInvalidContinuation_IsRefused() => AssertRefused([.. Utf8Bom, 0x63, 0x61, 0x66, 0xC3, 0x28]);

    [Fact]
    public void Utf16LeLoneHighSurrogate_IsRefused() => AssertRefused([0xFF, 0xFE, 0x61, 0x00, 0x3D, 0xD8, 0x62, 0x00]);

    [Fact]
    public void InvalidContinuation_ReadLine_IsRefused()
    {
        using var reader = StrictStdin.Create(new MemoryStream([0x63, 0x61, 0x66, 0xC3, 0x28, 0x0A]));
        var ex = Assert.Throws<TswapException>(() => reader.ReadLine());
        Assert.Equal(Refusal, ex.Message);
    }

    [Fact]
    public void Lines_AreReadOneAtATime()
    {
        using var reader = StrictStdin.Create(new MemoryStream(Encoding.UTF8.GetBytes("1\ncafé\n")));
        Assert.Equal("1", reader.ReadLine());
        Assert.Equal("café", reader.ReadLine());
        Assert.Null(reader.ReadLine());
    }

    /// <summary>Creating the reader reads nothing: the BOM is peeked at the first read, not before.</summary>
    [Fact]
    public void Create_ReadsNothingUntilTheFirstRead()
    {
        var stream = new OneBytePerReadStream(Encoding.UTF8.GetBytes("x"));
        using var reader = StrictStdin.Create(stream);
        Assert.Equal(0, stream.Reads);
        Assert.Equal('x', reader.Read());
    }

    // --- Source guard (A1, A16) ---

    /// <summary>Static <c>System.Console</c> input, not preceded by '.' or a word character.</summary>
    [GeneratedRegex(@"(?<![.\w])Console\.(ReadLine|Read|In)\b")]
    private static partial Regex BareConsoleInput();

    [GeneratedRegex(@"\bSystem\.Console\.(ReadLine|Read|In)\b")]
    private static partial Regex QualifiedConsoleInput();

    /// <summary>The two <c>CommandContext</c> prompts: there <c>Console</c> is its <see cref="IConsole"/> property.</summary>
    private const string CommandContextPrompt = "var input = Console.ReadLine()?.Trim();";

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "TokenSwap.slnx")))
                return dir.FullName;
        throw new InvalidOperationException("TokenSwap.slnx not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void Source_StdinIsReadOnlyThroughTheConsoleSeam()
    {
        var cli = Path.Combine(RepoRoot(), "TswapCli");
        var files = Directory.EnumerateFiles(cli, "*.cs", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(cli, f).Replace('\\', '/'))
            .Where(f => !f.Split('/').Any(part => part is "bin" or "obj"))
            .Where(f => f is not ("SystemConsole.cs" or "StrictStdin.cs"))
            .ToList();
        Assert.Contains("CommandContext.cs", files);
        Assert.Contains("Commands/AgentCommand.cs", files);

        List<string> offenders = [];
        var allowedPrompts = 0;
        foreach (var file in files)
        {
            var lineNumber = 0;
            foreach (var line in File.ReadLines(Path.Combine(cli, file)))
            {
                lineNumber++;
                if (QualifiedConsoleInput().IsMatch(line))
                    offenders.Add($"{file}:{lineNumber}: {line.Trim()}");
                else if (BareConsoleInput().IsMatch(line))
                {
                    if (file == "CommandContext.cs" && line.Trim() == CommandContextPrompt)
                        allowedPrompts++;
                    else
                        offenders.Add($"{file}:{lineNumber}: {line.Trim()}");
                }
            }
        }

        Assert.True(offenders.Count == 0, "static System.Console input outside the seam:\n" + string.Join("\n", offenders));
        Assert.Equal(2, allowedPrompts);
    }

    /// <summary>A stream that hands out one byte per <see cref="Read(byte[], int, int)"/>.</summary>
    private sealed class OneBytePerReadStream(byte[] bytes) : Stream
    {
        private int _position;

        public int Reads { get; private set; }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            Reads++;
            if (buffer.Length == 0 || _position == bytes.Length)
                return 0;
            buffer[0] = bytes[_position++];
            return 1;
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
    }
}
