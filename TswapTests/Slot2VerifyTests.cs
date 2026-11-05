using System.Security.Cryptography;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 2: <see cref="Slot2Verify.ExpectedResponse"/>, the answer a slot programmed with
/// HMAC_LT64 gives. The rule is Yubico's (yubikey-personalization, <c>ykpersonalize.1.adoc</c>, <c>hmac-lt64</c>):
/// "Whatever is in the last byte of the challenge is used as end of input marker (backtracking from end of
/// payload)": the trailing bytes equal to the frame's last byte are stripped before the HMAC. The edge cases below
/// follow that text (citation in the task 2 report).
/// </summary>
public sealed class Slot2VerifyTests
{
    private static readonly byte[] Key = Convert.FromHexString("00112233445566778899aabbccddeeff00112233");

    private static byte[] Frame(ReadOnlySpan<byte> start, byte fill)
    {
        var frame = new byte[64];
        frame.AsSpan().Fill(fill);
        start.CopyTo(frame);
        return frame;
    }

    [Fact]
    public void Slot2Verify_StripsZeroPadding() =>
        Assert.Equal(HMACSHA1.HashData(Key, "abc"u8), Slot2Verify.ExpectedResponse(Key, Frame("abc"u8, 0x00)));

    [Fact]
    public void Slot2Verify_StripsTrailingRepeatsOfLastByte() =>
        // "ab" + 62 × 'b': every trailing 'b' is the end marker, including the one that was part of "ab".
        Assert.Equal(HMACSHA1.HashData(Key, "a"u8), Slot2Verify.ExpectedResponse(Key, Frame("ab"u8, 0x62)));

    [Fact]
    public void Slot2Verify_LastByteOccursOnce_StripsOnlyIt()
    {
        // 63 × 'a' then 'b': the marker is the single last byte; the 63 bytes before it are the input.
        var frame = Frame([], 0x61);
        frame[63] = 0x62;

        Assert.Equal(HMACSHA1.HashData(Key, frame.AsSpan(0, 63)), Slot2Verify.ExpectedResponse(Key, frame));
    }

    [Fact]
    public void Slot2Verify_AllEqualFrame_HashesTheEmptyInput() =>
        // Backtracking from the end never meets another byte: no input is left.
        Assert.Equal(HMACSHA1.HashData(Key, ReadOnlySpan<byte>.Empty), Slot2Verify.ExpectedResponse(Key, Frame([], 0x00)));

    [Fact]
    public void Slot2Verify_RejectsAFrameThatIsNot64Bytes() =>
        Assert.Throws<ArgumentException>(() => Slot2Verify.ExpectedResponse(Key, new byte[63]));

    [Fact]
    public void Slot2Verify_RejectsAKeyThatIsNot20Bytes() =>
        Assert.Throws<ArgumentException>(() => Slot2Verify.ExpectedResponse(new byte[16], new byte[64]));
}
