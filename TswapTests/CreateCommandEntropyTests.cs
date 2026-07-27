using TswapCli.Commands;
using Xunit;

namespace TswapTests;

/// <summary>
/// Unit tests for CreateCommand's YubiKey-entropy rejection-sampling helpers
/// (<see cref="CreateCommand.DeriveYubiKeyChars"/> and <see cref="CreateCommand.RejectionSampleChars"/>),
/// exercised directly against fixed key material rather than through a fake YubiKey/CommandContext.
/// The system-RNG path (RandomNumberGenerator.GetItems) is covered separately in
/// CommandTests.cs via the "create"/"get" command pair.
/// </summary>
public class CreateCommandEntropyTests
{
    private static readonly byte[] FixedIkm =
        Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");

    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(256)] // large enough to plausibly stress the rejection loop / exhaustion path
    [InlineData(1000)]
    public void DeriveYubiKeyChars_ProducesRequestedLengthWithinCharset(int length)
    {
        var chars = CreateCommand.DeriveYubiKeyChars(FixedIkm, length);

        Assert.Equal(length, chars.Length);
        Assert.All(chars, c => Assert.Contains(c, CreateCommand.Charset));
    }

    [Fact]
    public void DeriveYubiKeyChars_IsDeterministicGivenFixedInputs()
    {
        // Not a claim about production behavior (the real `challenge` is fresh RNG on every
        // `create` call) - this just confirms the derivation itself has no hidden randomness
        // (e.g. no accidental use of the ambient RNG instead of the HKDF-derived buffer).
        var first = CreateCommand.DeriveYubiKeyChars(FixedIkm, 300);
        var second = CreateCommand.DeriveYubiKeyChars(FixedIkm, 300);

        Assert.Equal(first, second);
    }

    [Fact]
    public void DeriveYubiKeyChars_DifferentIkmProducesDifferentOutput()
    {
        var otherIkm = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

        var a = CreateCommand.DeriveYubiKeyChars(FixedIkm, 64);
        var b = CreateCommand.DeriveYubiKeyChars(otherIkm, 64);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveYubiKeyChars_ZeroLengthReturnsEmpty()
    {
        var chars = CreateCommand.DeriveYubiKeyChars(FixedIkm, 0);

        Assert.Empty(chars);
    }

    // Largest multiple of Charset.Length that still fits in a byte - mirrors CreateCommand's
    // private RejectionCeiling computation so these tests aren't hardcoded to one charset size.
    private static readonly int RejectionCeiling = (256 / CreateCommand.Charset.Length) * CreateCommand.Charset.Length;

    [Fact]
    public void RejectionSampleChars_SkipsBytesAtOrAboveCeiling()
    {
        // Bytes >= RejectionCeiling must be skipped entirely rather than reintroducing modulo
        // bias; bytes within range map via `byte % Charset.Length`.
        byte[] source = [(byte)RejectionCeiling, 255, 0, (byte)(CreateCommand.Charset.Length - 1), (byte)CreateCommand.Charset.Length];
        var destination = new char[3];

        var filled = CreateCommand.RejectionSampleChars(source, destination, 0);

        Assert.Equal(3, filled);
        Assert.Equal(CreateCommand.Charset[0], destination[0]);
        Assert.Equal(CreateCommand.Charset[^1], destination[1]);
        Assert.Equal(CreateCommand.Charset[0], destination[2]); // Charset.Length % Charset.Length == 0
    }

    [Fact]
    public void RejectionSampleChars_StopsAtDestinationBoundsEvenWithMoreSourceBytes()
    {
        byte[] source = [0, 1, 2, 3, 4];
        var destination = new char[2];

        var filled = CreateCommand.RejectionSampleChars(source, destination, 0);

        Assert.Equal(2, filled);
    }

    [Fact]
    public void RejectionSampleChars_AllRejectedLeavesFillUnchanged()
    {
        byte[] source = [(byte)RejectionCeiling, (byte)(RejectionCeiling + 5), 255, (byte)(RejectionCeiling + 1)];
        var destination = new char[4];

        var filled = CreateCommand.RejectionSampleChars(source, destination, 1);

        Assert.Equal(1, filled); // nothing accepted, so fill count is unchanged from startIndex
    }

    [Fact]
    public void RejectionSampleChars_ContinuesFillingFromStartIndex()
    {
        var destination = new char[4];
        var firstFill = CreateCommand.RejectionSampleChars([0, 1], destination, 0);
        var secondFill = CreateCommand.RejectionSampleChars([2, 3], destination, firstFill);

        Assert.Equal(4, secondFill);
        Assert.Equal(CreateCommand.Charset[0], destination[0]);
        Assert.Equal(CreateCommand.Charset[1], destination[1]);
        Assert.Equal(CreateCommand.Charset[2], destination[2]);
        Assert.Equal(CreateCommand.Charset[3], destination[3]);
    }
}
