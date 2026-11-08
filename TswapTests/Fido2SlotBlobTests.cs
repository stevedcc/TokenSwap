using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 1: the FIDO2 slot blob (<c>TSYK</c> version 3), the WebAuthn PRF transform, Yubico's
/// AAGUID list and the slot's display name.
/// </summary>
public class Fido2SlotBlobTests
{
    private const int OwnersSerial = 33060005;

    /// <summary>YubiKey 5 NFC / 5C NFC, firmware 5.7 (the owner's key).</summary>
    private static readonly Guid OwnersAaguid = Guid.Parse("d7781e5d-e353-46aa-afe2-3ca49f13332a");

    private static readonly byte[] FixedPrfInput = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] FixedCredentialId = Enumerable.Range(0xA0, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] TswapRpIdBytes = "tswap.crawford.dev"u8.ToArray();

    private static Fido2SlotBlob FixedBlob() =>
        new(OwnersSerial, OwnersAaguid, FixedPrfInput, Fido2SlotBlob.TswapRpId, FixedCredentialId, requiresPassword: true);

    /// <summary>
    /// The layout written out by hand, independent of <see cref="Fido2SlotBlob.Encode"/>, so the refusal
    /// tests can build blobs the encoder would never write.
    /// </summary>
    private static byte[] Raw(
        byte version = 3, byte flags = 0x01, byte prfVersion = 1, int serial = OwnersSerial,
        byte[]? rpId = null, int? credentialIdLength = null, byte[]? credentialId = null)
    {
        rpId ??= TswapRpIdBytes;
        credentialId ??= FixedCredentialId;
        List<byte> bytes = [];
        bytes.AddRange("TSYK"u8.ToArray());
        bytes.Add(version);
        bytes.Add(flags);
        bytes.Add(prfVersion);
        var serialBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(serialBytes, serial);
        bytes.AddRange(serialBytes);
        bytes.AddRange(OwnersAaguid.ToByteArray(bigEndian: true));
        bytes.AddRange(FixedPrfInput);
        bytes.Add((byte)rpId.Length);
        bytes.AddRange(rpId);
        var lengthBytes = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(lengthBytes, (ushort)(credentialIdLength ?? credentialId.Length));
        bytes.AddRange(lengthBytes);
        bytes.AddRange(credentialId);
        return [.. bytes];
    }

    private static void AssertMalformed(byte[] bytes)
    {
        var ex = Assert.Throws<TswapException>(() => Fido2SlotBlob.Decode(bytes));
        Assert.StartsWith("Malformed FIDO2 slot blob: ", ex.Message);
        Assert.EndsWith(". Restore config.json from backup.", ex.Message);
        var (blob, kind, error) = Fido2SlotBlob.Parse(bytes);
        Assert.Null(blob);
        Assert.Equal(SlotPasswordKind.Corrupt, kind);
        Assert.Equal(ex.Message, error);
    }

    private static void AssertNeedsNewer(byte[] bytes, string expected)
    {
        var ex = Assert.Throws<TswapException>(() => Fido2SlotBlob.Decode(bytes));
        Assert.Equal(expected, ex.Message);
        var (blob, kind, error) = Fido2SlotBlob.Parse(bytes);
        Assert.Null(blob);
        Assert.Equal(SlotPasswordKind.NeedsNewerTswap, kind);
        Assert.Equal(expected, error);
    }

    // --- round trip and layout ---

    [Theory]
    [InlineData(33060005, true, 16)]
    [InlineData(33060005, false, 64)]
    [InlineData(null, true, 1023)]
    [InlineData(null, false, 16)]
    public void Fido2Blob_RoundTrips(int? serial, bool requiresPassword, int credentialIdLength)
    {
        var credentialId = RandomNumberGenerator.GetBytes(credentialIdLength);
        var original = Fido2SlotBlob.Create(serial, OwnersAaguid, credentialId, requiresPassword);

        var decoded = Fido2SlotBlob.Decode(original.Encode());

        Assert.Equal(serial, decoded.Serial);
        Assert.Equal(OwnersAaguid, decoded.Aaguid);
        Assert.Equal(original.PrfInput, decoded.PrfInput);
        Assert.Equal(32, decoded.PrfInput.Length);
        Assert.Equal(Fido2SlotBlob.TswapRpId, decoded.RpId);
        Assert.Equal(credentialId, decoded.CredentialId);
        Assert.Equal(requiresPassword, decoded.RequiresPassword);
        Assert.Equal(1, decoded.PrfVersion);
    }

    [Fact]
    public void Fido2Blob_Create_DrawsAFreshPrfInputAndUsesTswapsRpId()
    {
        var first = Fido2SlotBlob.Create(OwnersSerial, OwnersAaguid, FixedCredentialId, requiresPassword: false);
        var second = Fido2SlotBlob.Create(OwnersSerial, OwnersAaguid, FixedCredentialId, requiresPassword: false);

        Assert.Equal("tswap.crawford.dev", Fido2SlotBlob.TswapRpId);
        Assert.Equal(Fido2SlotBlob.TswapRpId, first.RpId);
        Assert.NotEqual(first.PrfInput, second.PrfInput);
    }

    [Fact]
    public void Fido2Blob_LayoutIsPinned()
    {
        // "TSYK" || 03 || flags 01 || PRF version 01 || serial 33060005 LE || AAGUID (RFC 4122 order) ||
        // PRF input 00..1F || rpId length 18 || "tswap.crawford.dev" || credential id length 16 LE || A0..AF.
        // Worked out by hand (Python's struct and uuid), not by the encoder.
        const string expected =
            "5453594B" + "03" + "01" + "01" + "A574F801" +
            "D7781E5DE35346AAAFE23CA49F13332A" +
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "12" + "74737761702E63726177666F72642E646576" +
            "1000" + "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";

        Assert.Equal(expected, Convert.ToHexString(FixedBlob().Encode()));
        Assert.Equal(expected, Convert.ToHexString(Raw()));

        // Password-free (flags 00), so the flags byte and the PRF version byte differ: with flags 01 a swap
        // of the two would go unseen (it did, in the break-it-once check).
        var passwordFree = new Fido2SlotBlob(
            OwnersSerial, OwnersAaguid, FixedPrfInput, Fido2SlotBlob.TswapRpId, FixedCredentialId, requiresPassword: false);
        Assert.Equal(expected[..10] + "00" + expected[12..], Convert.ToHexString(passwordFree.Encode()));
    }

    [Fact]
    public void Fido2Blob_UnknownSerialIsWrittenAsZero()
    {
        var blob = new Fido2SlotBlob(null, OwnersAaguid, FixedPrfInput, Fido2SlotBlob.TswapRpId, FixedCredentialId, requiresPassword: false);

        var bytes = blob.Encode();

        Assert.Equal(0, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(7, 4)));
        Assert.Equal(0x00, bytes[5]);
    }

    // --- strict decoding ---

    [Theory]
    [InlineData(4)]  // magic only
    [InlineData(5)]  // no flags
    [InlineData(6)]  // no PRF version
    [InlineData(7)]  // no serial
    [InlineData(11)] // no AAGUID
    [InlineData(27)] // no PRF input
    [InlineData(59)] // no rpId length
    [InlineData(60)] // no rpId
    [InlineData(78)] // no credential id length
    [InlineData(79)] // half a credential id length
    [InlineData(80)] // no credential id
    [InlineData(95)] // one byte of the credential id missing
    public void Fido2Blob_Decode_RefusesATruncatedBlob(int length)
    {
        AssertMalformed(Raw().AsSpan(0, length).ToArray());
    }

    [Fact]
    public void Fido2Blob_Decode_RefusesTrailingBytes() => AssertMalformed([.. Raw(), 0x00]);

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(1024)]
    public void Fido2Blob_Decode_RefusesACredentialIdLengthOutOfRange(int length)
    {
        AssertMalformed(Raw(credentialId: new byte[length]));
    }

    [Fact]
    public void Fido2Blob_Decode_RefusesAnEmptyRpId() => AssertMalformed(Raw(rpId: []));

    [Fact]
    public void Fido2Blob_Decode_RefusesAnotherRpId() => AssertMalformed(Raw(rpId: "evil.example.com"u8.ToArray()));

    [Fact]
    public void Fido2Blob_Decode_RefusesANegativeSerial() => AssertMalformed(Raw(serial: -1));

    [Fact]
    public void Fido2Blob_Decode_RefusesPrfVersionZero() => AssertMalformed(Raw(prfVersion: 0));

    [Theory]
    [InlineData(0x02, "needs a newer tswap (FIDO2 slot flags 0x02); upgrade tswap.")]
    [InlineData(0x81, "needs a newer tswap (FIDO2 slot flags 0x81); upgrade tswap.")]
    public void Fido2Blob_Decode_UnknownFlagBitsNeedANewerTswap(byte flags, string expected)
    {
        AssertNeedsNewer(Raw(flags: flags), expected);
    }

    [Fact]
    public void Fido2Blob_Decode_PrfVersionTwoNeedsANewerTswap()
    {
        AssertNeedsNewer(Raw(prfVersion: 2), "needs a newer tswap (FIDO2 slot PRF version 2); upgrade tswap.");
    }

    [Fact]
    public void Fido2Blob_NeedsNewerText_NamesWhatIsNew()
    {
        Assert.Equal("needs a newer tswap (FIDO2 slot flags 0x02); upgrade tswap.",
            Fido2SlotBlob.NeedsNewerText("FIDO2 slot flags 0x02"));
    }

    [Fact]
    public void Fido2Blob_Parse_ReportsThePasswordKind()
    {
        Assert.Equal(SlotPasswordKind.Password, Fido2SlotBlob.Parse(Raw(flags: 0x01)).Kind);
        Assert.Equal(SlotPasswordKind.None, Fido2SlotBlob.Parse(Raw(flags: 0x00)).Kind);
    }

    [Fact]
    public void Fido2Blob_V020ParserSaysNeedsNewer()
    {
        // YubiKeySlotBlob.Parse is byte-for-byte v0.2.0's (`git diff v0.2.0 -- TswapCore/Keyring/YubiKeySlotBlob.cs`
        // shows comment changes only). This pins what a v0.2.x tswap answers for a FIDO2 slot; a change to
        // Parse breaks the pin's premise, because released v0.2.x builds keep the old code.
        var fido2 = FixedBlob().Encode();

        var (blob, kind, error) = YubiKeySlotBlob.Parse(fido2);

        Assert.Null(blob);
        Assert.Equal(SlotPasswordKind.NeedsNewerTswap, kind);
        Assert.Equal(SlotPassword.NeedsNewerTswapText(3), error);
    }

    [Fact]
    public void Fido2Blob_Parse_RefusesWrongMagic()
    {
        byte[] bytes = [.. "TSTP"u8.ToArray(), .. Raw()[4..]];

        AssertMalformed(bytes);
        Assert.Equal("Malformed FIDO2 slot blob: wrong magic. Restore config.json from backup.", Fido2SlotBlob.Parse(bytes).Error);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Fido2Blob_Parse_RefusesAnOtpVersionAsCorrupt(byte version)
    {
        var bytes = Raw(version: version);

        AssertMalformed(bytes);
        Assert.Equal(
            $"Malformed FIDO2 slot blob: version {version} is not a FIDO2 slot's. Restore config.json from backup.",
            Fido2SlotBlob.Parse(bytes).Error);
    }

    [Fact]
    public void Fido2Blob_Parse_VersionFourNeedsANewerTswap() =>
        AssertNeedsNewer(Raw(version: 4), SlotPassword.NeedsNewerTswapText(4));

    // --- constructor and Create guards ---

    [Fact]
    public void Fido2Blob_Constructor_RefusesAnotherRpId()
    {
        var ex = Assert.Throws<ArgumentException>(() => new Fido2SlotBlob(
            OwnersSerial, OwnersAaguid, FixedPrfInput, "evil.example.com", FixedCredentialId, requiresPassword: false));
        Assert.Equal("rpId", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Fido2Blob_Constructor_RefusesASerialThatIsNotPositive(int serial)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new Fido2SlotBlob(
            serial, OwnersAaguid, FixedPrfInput, Fido2SlotBlob.TswapRpId, FixedCredentialId, requiresPassword: false));
        Assert.Equal("serial", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Fido2Blob_Create_RefusesASerialThatIsNotPositive(int serial)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            Fido2SlotBlob.Create(serial, OwnersAaguid, FixedCredentialId, requiresPassword: false));
        Assert.Equal("serial", ex.ParamName);
    }

    [Fact]
    public void Fido2Blob_Constructor_RefusesAPrfInputOf31Bytes()
    {
        var ex = Assert.Throws<ArgumentException>(() => new Fido2SlotBlob(
            OwnersSerial, OwnersAaguid, new byte[31], Fido2SlotBlob.TswapRpId, FixedCredentialId, requiresPassword: false));
        Assert.Equal("prfInput", ex.ParamName);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(1024)]
    public void Fido2Blob_Constructor_RefusesACredentialIdOutOfRange(int length)
    {
        var ex = Assert.Throws<ArgumentException>(() => new Fido2SlotBlob(
            OwnersSerial, OwnersAaguid, FixedPrfInput, Fido2SlotBlob.TswapRpId, new byte[length], requiresPassword: false));
        Assert.Equal("credentialId", ex.ParamName);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(1024)]
    public void Fido2Blob_Create_RefusesACredentialIdOutOfRange(int length)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Fido2SlotBlob.Create(OwnersSerial, OwnersAaguid, new byte[length], requiresPassword: false));
        Assert.Equal("credentialId", ex.ParamName);
    }

    [Fact]
    public void Fido2Blob_RpIdBytesAreTheUtf8OfTheRpId()
    {
        // The encoder and Parse use a u8 literal beside the string constant; this keeps the two equal.
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes(Fido2SlotBlob.TswapRpId), Fido2SlotBlob.TswapRpIdUtf8.ToArray());
    }

    // --- the PRF transform ---

    [Fact]
    public void Fido2Prf_MatchesTheSpikeVector()
    {
        // The spike's known vector (design/yubikey-sdk at 1e3d56b, spikes/yubikey-sdk.Tests/PrfTests.cs):
        // SHA-256("WebAuthn PRF" || 0x00 || "tswap-yk-spike-salt-v1"), written out here as hex.
        Assert.Equal(
            "94EC57CBFCDB8EF8CE252CB7D9B0DAA0DFDC8A0059FA289979AF0FEA66E639A3",
            Convert.ToHexString(Fido2Prf.Salt("tswap-yk-spike-salt-v1"u8)));
    }

    [Fact]
    public void Fido2Prf_SaltIsThirtyTwoBytes() => Assert.Equal(32, Fido2Prf.Salt(FixedPrfInput).Length);

    // --- Yubico's AAGUIDs and the display name ---

    [Theory]
    [InlineData("d7781e5d-e353-46aa-afe2-3ca49f13332a", "YubiKey 5 NFC or 5C NFC")]                    // the owner's key
    [InlineData("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5, 5C, 5 Nano or 5C Nano")]
    [InlineData("a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa", "Security Key NFC by Yubico")]
    [InlineData("24083bcb-3034-4867-99de-a3b52e1d426a", "Security Key NFC by Yubico - Enterprise Edition")]
    [InlineData("d8522d9f-575b-4866-88a9-ba99fa02f35b", "YubiKey Bio - FIDO Edition")]
    [InlineData("ba0a9266-40d8-4048-9786-d710b5474752", "YubiKey Bio - Multi-protocol Edition")]
    [InlineData("fcc0118f-cd45-435b-8da1-9782b2da0715", "YubiKey 5 NFC FIPS or 5C NFC FIPS")]
    [InlineData("85203421-48f9-4355-9bc8-8a53846e5083", "YubiKey 5Ci FIPS")]
    [InlineData("1ac71f64-468d-4fe0-bef1-0e5f2f551f18", "YubiKey 5 NFC or 5C NFC (enterprise profile)")]
    public void YubicoAaguids_KnowsTheOwnersKeyAndTheSeries(string aaguid, string model)
    {
        var guid = Guid.Parse(aaguid);

        Assert.True(YubicoAaguids.IsYubico(guid));
        Assert.Equal(model, YubicoAaguids.ModelName(guid));
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000")] // attestation "none" zeroes the AAGUID
    [InlineData("42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3")] // Google Titan Security Key v2 (not Yubico)
    public void YubicoAaguids_RefusesOtherAaguids(string aaguid)
    {
        var guid = Guid.Parse(aaguid);

        Assert.False(YubicoAaguids.IsYubico(guid));
        Assert.Null(YubicoAaguids.ModelName(guid));
    }

    [Fact]
    public void YubicoAaguids_ListsEachOfTheArticles70AaguidsOnce()
    {
        // The article's two tables hold 70 distinct AAGUIDs (retrieved 2026-11-06). A duplicate line would
        // otherwise overwrite another silently when the lookup is built.
        var aaguids = YubicoAaguids.Entries.Select(entry => Guid.Parse(entry.Aaguid)).ToList();

        Assert.Equal(70, aaguids.Count);
        Assert.Equal(aaguids.Count, aaguids.Distinct().Count());
    }

    [Fact]
    public void DisplayName_SerialModelFallback()
    {
        var unknown = Guid.Parse("42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3");

        Assert.Equal("YubiKey 33060005", Fido2SlotBlob.DisplayName(OwnersSerial, OwnersAaguid));
        Assert.Equal("YubiKey 5 NFC or 5C NFC", Fido2SlotBlob.DisplayName(null, OwnersAaguid));
        Assert.Equal("the YubiKey this slot was made with", Fido2SlotBlob.DisplayName(null, unknown));
    }
}
