using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T4 item 1: the one-key YubiKey slot primitive. <see cref="YubiKeySlotBlob"/> (the slot's
/// parameters in its v3 hardware blob, decision 2) and <see cref="YubiKeySlotKek"/> (decision 1:
/// <c>KEK_slot = HKDF-SHA256(ikm: HMAC-SHA1 response, salt: slot salt, info:
/// "tswap/yubikey-slot/v1" || slotId)</c>).
/// </summary>
public class YubiKeySlotTests
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private static readonly byte[] Challenge = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Salt = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] SlotId = Enumerable.Range(200, 16).Select(i => (byte)i).ToArray();

    private static YubiKeySlotBlob Blob(int serial = SerialA, byte[]? challenge = null, byte[]? salt = null) =>
        new(serial, challenge ?? Challenge, salt ?? Salt, YubiKeyTouchPolicy.Required);

    private static byte[] Kek(SimulatedYubiKeyService keys, YubiKeySlotBlob blob, byte[]? slotId = null) =>
        YubiKeySlotKek.Recover(keys, blob, slotId ?? SlotId);

    // --- KEK derivation ---

    [Fact]
    public void Kek_IsDeterministicForTheSameKeyChallengeSaltAndSlotId()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);

        var first = Kek(keys, Blob());
        var second = Kek(keys, Blob());

        Assert.Equal(32, first.Length);
        Assert.Equal(first, second);
    }

    [Fact]
    public void Kek_IsTheSpecifiedHkdfOfTheKeysResponseToTheBlobsChallenge()
    {
        // Pins decision 1's exact construction, so a later change to it cannot slip through as
        // "still deterministic": HKDF-SHA256(response, salt, "tswap/yubikey-slot/v1" || slotId).
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var paddedChallenge = new byte[64];
        System.Text.Encoding.UTF8.GetBytes(Convert.ToHexString(Challenge)).CopyTo(paddedChallenge, 0);
        var response = HMACSHA1.HashData(SimulatedYubiKeyService.SecretFor(SerialA), paddedChallenge);
        var expected = HKDF.DeriveKey(HashAlgorithmName.SHA256, response, 32, Salt,
            [.. "tswap/yubikey-slot/v1"u8.ToArray(), .. SlotId]);

        Assert.Equal(expected, Kek(keys, Blob()));
        Assert.Equal([(SerialA, Convert.ToHexString(Challenge))], keys.Challenges);
    }

    [Fact]
    public void Kek_DiffersByKey()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);

        Assert.NotEqual(Kek(keys, Blob(SerialA)), Kek(keys, Blob(SerialB)));
    }

    [Fact]
    public void Kek_DiffersByChallenge()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var otherChallenge = (byte[])Challenge.Clone();
        otherChallenge[0] ^= 1;

        Assert.NotEqual(Kek(keys, Blob()), Kek(keys, Blob(challenge: otherChallenge)));
    }

    [Fact]
    public void Kek_DiffersBySalt()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var otherSalt = (byte[])Salt.Clone();
        otherSalt[^1] ^= 1;

        Assert.NotEqual(Kek(keys, Blob()), Kek(keys, Blob(salt: otherSalt)));
    }

    [Fact]
    public void Kek_DiffersBySlotId()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var otherSlotId = (byte[])SlotId.Clone();
        otherSlotId[5] ^= 1;

        Assert.NotEqual(Kek(keys, Blob()), Kek(keys, Blob(), otherSlotId));
    }

    /// <summary>Hands out its responses and keeps them, so the test can see they were zeroed.</summary>
    private sealed class KeepingYubiKeys : IYubiKeyService
    {
        public List<byte[]> Responses { get; } = [];
        public bool IsSimulated => false;
        public IReadOnlyList<int> ListSerials() => [SerialA];
        public byte[] Challenge(int serial, string challenge)
        {
            var response = RandomNumberGenerator.GetBytes(20);
            Responses.Add(response);
            return response;
        }
        public bool? DetectTouchRequirement(int serial) => true;
    }

    [Fact]
    public void Recover_ZeroesTheResponseBytesAfterUse()
    {
        var keys = new KeepingYubiKeys();

        YubiKeySlotKek.Recover(keys, Blob(), SlotId);

        var response = Assert.Single(keys.Responses);
        Assert.All(response, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Derive_RejectsAResponseThatIsNotAnHmacSha1()
    {
        var ex = Assert.Throws<TswapException>(() => YubiKeySlotKek.Derive(new byte[16], Salt, SlotId));
        Assert.Contains("20", ex.Message);
    }

    // --- Blob encoding ---

    [Fact]
    public void Create_GivesFreshRandomChallengeAndSaltOfThirtyTwoBytes()
    {
        var a = YubiKeySlotBlob.Create(SerialA, requiresTouch: true);
        var b = YubiKeySlotBlob.Create(SerialA, requiresTouch: true);

        Assert.Equal(32, a.Challenge.Length);
        Assert.Equal(32, a.Salt.Length);
        Assert.NotEqual(a.Challenge, b.Challenge);
        Assert.NotEqual(a.Salt, b.Salt);
        Assert.NotEqual(a.Challenge, a.Salt);
    }

    [Theory]
    [InlineData(true, YubiKeyTouchPolicy.Required)]
    [InlineData(false, YubiKeyTouchPolicy.NotRequired)]
    [InlineData(null, YubiKeyTouchPolicy.Unknown)]
    public void Create_RecordsTheTouchPolicy(bool? requiresTouch, YubiKeyTouchPolicy expected)
    {
        var blob = YubiKeySlotBlob.Create(SerialA, requiresTouch);

        Assert.Equal(expected, blob.Touch);
        Assert.Equal(requiresTouch, blob.RequiresTouch);
    }

    [Theory]
    [InlineData(YubiKeyTouchPolicy.Required)]
    [InlineData(YubiKeyTouchPolicy.NotRequired)]
    [InlineData(YubiKeyTouchPolicy.Unknown)]
    public void Blob_RoundTrips(YubiKeyTouchPolicy touch)
    {
        var blob = new YubiKeySlotBlob(SerialB, Challenge, Salt, touch);

        var decoded = YubiKeySlotBlob.Decode(blob.Encode());

        Assert.Equal(SerialB, decoded.Serial);
        Assert.Equal(Challenge, decoded.Challenge);
        Assert.Equal(Salt, decoded.Salt);
        Assert.Equal(touch, decoded.Touch);
    }

    [Fact]
    public void Blob_HasItsOwnMagicAndVersionByteThenTheFixedFields()
    {
        var bytes = Blob(SerialB).Encode();

        Assert.Equal(4 + 1 + 4 + 32 + 32 + 1, bytes.Length);
        Assert.Equal("TSYK"u8.ToArray(), bytes[..4]);
        Assert.Equal(1, bytes[4]);
        Assert.Equal(SerialB, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(5, 4)));
        Assert.Equal(Challenge, bytes[9..41]);
        Assert.Equal(Salt, bytes[41..73]);
        Assert.Equal((byte)YubiKeyTouchPolicy.Required, bytes[73]);
        Assert.True(YubiKeySlotBlob.IsYubiKeyBlob(bytes));
    }

    [Fact]
    public void IsYubiKeyBlob_IsFalseForOtherBackendsBlobsAndNoBlob()
    {
        var (_, tpmBlob) = new SimulatedHardwareService(HardwareBackend.Tpm, new byte[32]).Enroll();

        Assert.False(YubiKeySlotBlob.IsYubiKeyBlob(tpmBlob));
        Assert.False(YubiKeySlotBlob.IsYubiKeyBlob(null));
        Assert.False(YubiKeySlotBlob.IsYubiKeyBlob([]));
        Assert.False(YubiKeySlotBlob.IsYubiKeyBlob("TSY"u8.ToArray()));
    }

    [Fact]
    public void Decode_UnknownVersion_IsRejected()
    {
        var bytes = Blob().Encode();
        bytes[4] = 2;

        var ex = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
        Assert.Contains("version 2", ex.Message);
        Assert.Contains("newer tswap", ex.Message);
    }

    [Fact]
    public void Decode_VersionZero_IsRejected()
    {
        var bytes = Blob().Encode();
        bytes[4] = 0;

        Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(40)]
    [InlineData(73)]
    public void Decode_Truncated_IsRejected(int length)
    {
        var bytes = Blob().Encode()[..length];

        var ex = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
        Assert.Contains("YubiKey slot blob", ex.Message);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    public void Decode_TrailingBytes_AreRejected(int extra)
    {
        byte[] bytes = [.. Blob().Encode(), .. new byte[extra]];

        var ex = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
        Assert.Contains("trailing", ex.Message);
    }

    [Fact]
    public void Decode_WrongMagic_IsRejected()
    {
        var bytes = Blob().Encode();
        bytes[0] = (byte)'X';

        Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
    }

    [Fact]
    public void Decode_UnknownTouchPolicy_IsRejected()
    {
        var bytes = Blob().Encode();
        bytes[^1] = 7;

        var ex = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
        Assert.Contains("touch", ex.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void Decode_NonPositiveSerial_IsRejected(int serial)
    {
        var bytes = Blob().Encode();
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(5, 4), serial);

        Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes));
    }

    [Fact]
    public void Constructor_RejectsWrongSizedChallengeOrSalt()
    {
        Assert.Throws<ArgumentException>(() => new YubiKeySlotBlob(SerialA, new byte[31], Salt, YubiKeyTouchPolicy.Required));
        Assert.Throws<ArgumentException>(() => new YubiKeySlotBlob(SerialA, Challenge, new byte[33], YubiKeyTouchPolicy.Required));
    }

    [Fact]
    public void BlobFitsTheKeyringsHwBlobColumn_AndSurvivesAKeyringRoundTrip()
    {
        var hwBlob = Blob().Encode();
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, new byte[16], 1,
            [new Slot(SlotId, new byte[32], new byte[60], SlotKind.Machine, hwBlob)]);

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Equal(Blob().Serial, YubiKeySlotBlob.Decode(decoded.Slots[0].HwBlob!).Serial);
    }
}
