using System.Buffers;
using System.Buffers.Binary;

namespace TswapCore.Broker.SshAgent;

/// <summary>A message (or key, or payload) that doesn't parse as <c>docs/ssh-agent-wire.md</c> says.</summary>
public sealed class SshWireException(string message) : Exception(message);

/// <summary>
/// Reads the SSH data types of RFC 4251 §5 from one bounded buffer (wire doc section 1). Every
/// read checks the bytes left first; nothing here allocates more than the bytes it was handed.
/// </summary>
public ref struct SshReader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;
    private int _pos;

    public readonly int Remaining => _data.Length - _pos;

    public readonly bool AtEnd => _pos == _data.Length;

    public byte ReadByte()
    {
        if (Remaining < 1)
            throw new SshWireException("truncated (byte)");
        return _data[_pos++];
    }

    public uint ReadUInt32()
    {
        if (Remaining < 4)
            throw new SshWireException("truncated (uint32)");
        var value = BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(_pos, 4));
        _pos += 4;
        return value;
    }

    /// <summary>A <c>string</c>: its bytes, a slice of the buffer (no copy).</summary>
    public ReadOnlySpan<byte> ReadString()
    {
        var length = ReadUInt32();
        if (length > (uint)Remaining)
            throw new SshWireException("string longer than the bytes left");
        var value = _data.Slice(_pos, (int)length);
        _pos += (int)length;
        return value;
    }

    /// <summary>A <c>string</c> that must equal <paramref name="expected"/> (ordinal bytes).</summary>
    public bool ReadStringEquals(ReadOnlySpan<byte> expected) => ReadString().SequenceEqual(expected);

    /// <summary>
    /// A positive <c>mpint</c> (wire doc section 1): refused when negative or not minimal, or longer
    /// than <paramref name="maxBytes"/> significant bytes. Returns the magnitude, big-endian, without
    /// the sign byte (empty for zero).
    /// </summary>
    public ReadOnlySpan<byte> ReadPositiveMpint(int maxBytes = 2048)
    {
        var raw = ReadString();
        if (raw.Length == 0)
            return raw;
        if ((raw[0] & 0x80) != 0)
            throw new SshWireException("negative mpint");
        if (raw[0] == 0)
        {
            if (raw.Length == 1 || (raw[1] & 0x80) == 0)
                throw new SshWireException("mpint with an unnecessary leading zero");
            raw = raw[1..];
        }
        if (raw.Length > maxBytes)
            throw new SshWireException("mpint too long");
        return raw;
    }

    /// <summary>Throws unless every byte was read (no trailing bytes).</summary>
    public readonly void EnsureEnd()
    {
        if (!AtEnd)
            throw new SshWireException("trailing bytes");
    }
}

/// <summary>Writes the SSH data types of RFC 4251 §5.</summary>
public sealed class SshWriter
{
    private readonly ArrayBufferWriter<byte> _buffer = new(256);

    public SshWriter Byte(byte value)
    {
        _buffer.GetSpan(1)[0] = value;
        _buffer.Advance(1);
        return this;
    }

    public SshWriter UInt32(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.GetSpan(4), value);
        _buffer.Advance(4);
        return this;
    }

    public SshWriter String(ReadOnlySpan<byte> value)
    {
        UInt32((uint)value.Length);
        _buffer.Write(value);
        return this;
    }

    public SshWriter String(string ascii) => String(System.Text.Encoding.UTF8.GetBytes(ascii));

    /// <summary>A positive mpint from a big-endian magnitude (leading zeros stripped, a sign byte added when needed).</summary>
    public SshWriter PositiveMpint(ReadOnlySpan<byte> magnitude)
    {
        var start = 0;
        while (start < magnitude.Length && magnitude[start] == 0)
            start++;
        var digits = magnitude[start..];
        if (digits.Length > 0 && (digits[0] & 0x80) != 0)
        {
            UInt32((uint)digits.Length + 1);
            Byte(0);
            _buffer.Write(digits);
        }
        else
        {
            String(digits);
        }
        return this;
    }

    /// <summary>Raw bytes, no length prefix.</summary>
    public SshWriter Raw(ReadOnlySpan<byte> value)
    {
        _buffer.Write(value);
        return this;
    }

    public int Length => _buffer.WrittenCount;

    public byte[] ToArray() => _buffer.WrittenSpan.ToArray();

    /// <summary>Zeroes what was written (for buffers that held private key material).</summary>
    public void Clear()
    {
        // ArrayBufferWriter.Clear zeroes the written part of its buffer (unlike ResetWrittenCount).
        _buffer.Clear();
    }
}
