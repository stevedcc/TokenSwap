using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Fix round 1, A1: only an authenticated record's stamps move this machine's clock. A planted
/// file with a well-formed header and a far-future stamp but no valid payload must not push
/// <c>LastHlc</c> (and so every later write) anywhere.
/// </summary>
public sealed class UnauthenticatedHlcTests : IDisposable
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m = new("hlc-junk", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => Now };
    private readonly byte[] _vaultKey;

    public UnauthenticatedHlcTests()
    {
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("v", "ingest", "existing");
    }

    public void Dispose() => _m.Dispose();

    /// <summary>A file with a valid magic/version header, a far-future write stamp and junk after it.</summary>
    private static byte[] JunkWithFutureHeader()
    {
        var bytes = new byte[SecretRecordCodec.HeaderSize + 300];
        RandomNumberGenerator.Fill(bytes);
        "TSR1"u8.CopyTo(bytes);
        bytes[4] = KeyringFormat.RecordFormatVersion;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(37, 8), 9_000_000_000_000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(65, 4), 300);
        return bytes;
    }

    [Theory]
    [InlineData("")]
    [InlineData(" (1)")]
    public void AJunkRecordWithAFutureHeader_DoesNotMoveTheClock(string suffix)
    {
        var junkName = suffix == "" ? new string('a', 64) : Path.GetFileName(RecordFile(_m, _vaultKey, "existing")) + suffix;
        File.WriteAllBytes(Path.Combine(_m.RecordsDir, junkName), JunkWithFutureHeader());
        var lastBefore = Hlc.TryParse(_m.Config.LastHlc)!.Value;

        _m.Ok("w", "ingest", "fresh");

        var fresh = ReadRecord(_m, _vaultKey, "fresh");
        Assert.Equal(Now.ToUnixTimeMilliseconds(), fresh.Version.Hlc.PhysicalMs);
        Assert.True(Hlc.TryParse(_m.Config.LastHlc)!.Value.PhysicalMs < 9_000_000_000_000);
        Assert.True(Hlc.TryParse(_m.Config.LastHlc)!.Value > lastBefore);
    }

    [Fact]
    public void HlcNext_AtTheTopOfTheRange_IsATswapException()
    {
        var ex = Assert.Throws<TswapException>(() => Hlc.Next(new Hlc(long.MaxValue, uint.MaxValue), 0));
        Assert.Contains("clock", ex.Message);
    }
}
