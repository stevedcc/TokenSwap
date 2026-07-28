using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the request/approve wire format (issue #121): JSON encoding (see
/// <see cref="SlotRequestFile"/>'s doc comment for why JSON rather than fixed-binary), with
/// explicit version checks on both this format's own version and the embedded
/// <see cref="KeyringFormat.KeyringFormatVersion"/> — this module's established bar after two
/// prior version-check gaps (#146, #148).
/// </summary>
public class SlotEnrollmentFileCodecTests
{
    [Fact]
    public void RequestFile_RoundTrips()
    {
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var publicKey = SlotKeyPair.Generate().PublicKey;
        var file = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion, Convert.ToBase64String(slotId), Convert.ToBase64String(publicKey));

        var json = SlotEnrollmentFileCodec.SerializeRequest(file);
        var decoded = SlotEnrollmentFileCodec.DeserializeRequest(json);

        Assert.Equal(file, decoded);
    }

    [Fact]
    public void RequestFile_ContainsDocumentedFieldNames()
    {
        // Not a byte-pinned golden test (this format is deliberately JSON, not fixed-binary —
        // see SlotRequestFile's doc comment) but the field names are still a documented contract
        // a reviewer or future reader should be able to see stay stable.
        var file = new SlotRequestFile(1, "c2xvdA==", "cHVia2V5");
        var json = SlotEnrollmentFileCodec.SerializeRequest(file);

        Assert.Contains("\"FormatVersion\"", json);
        Assert.Contains("\"SlotId\"", json);
        Assert.Contains("\"PublicKey\"", json);
    }

    [Fact]
    public void RequestFile_UnsupportedFormatVersion_ThrowsCleanTswapException()
    {
        var json = """{"FormatVersion":999,"SlotId":"AAAA","PublicKey":"AAAA"}""";

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeRequest(json));
        Assert.Contains("Unsupported slot request file format version", ex.Message);
    }

    [Fact]
    public void RequestFile_InvalidJson_ThrowsCleanTswapException()
    {
        Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeRequest("not json at all"));
    }

    [Fact]
    public void RequestFile_NullJson_ThrowsCleanTswapException()
    {
        Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeRequest("null"));
    }

    private static SlotApproveFile MakeApproveFile() => new(
        SlotApproveFile.CurrentFormatVersion,
        KeyringFormat.KeyringFormatVersion,
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize)),
        1,
        new List<SlotDto>
        {
            new(Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
                Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
                Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)),
                SlotKind.Machine),
        },
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
        Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
        Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)));

    [Fact]
    public void ApproveFile_RoundTrips()
    {
        // Compared field-by-field (rather than via record Equals) because ExistingSlots is a
        // List<SlotDto>, and List<T> has no structural Equals of its own — the record-generated
        // Equals would compare list references, not contents, and always report "different" for
        // a freshly-deserialized list even when every element matches.
        var file = MakeApproveFile();

        var json = SlotEnrollmentFileCodec.SerializeApprove(file);
        var decoded = SlotEnrollmentFileCodec.DeserializeApprove(json);

        Assert.Equal(file.FormatVersion, decoded.FormatVersion);
        Assert.Equal(file.KeyringFormatVersion, decoded.KeyringFormatVersion);
        Assert.Equal(file.VaultId, decoded.VaultId);
        Assert.Equal(file.K, decoded.K);
        Assert.Equal(file.ExistingSlots, decoded.ExistingSlots);
        Assert.Equal(file.NewSlotId, decoded.NewSlotId);
        Assert.Equal(file.NewSlotPublicKey, decoded.NewSlotPublicKey);
        Assert.Equal(file.NewSlotEphemeralPublicKey, decoded.NewSlotEphemeralPublicKey);
        Assert.Equal(file.NewSlotWrapped, decoded.NewSlotWrapped);
    }

    [Fact]
    public void ApproveFile_UnsupportedFormatVersion_ThrowsCleanTswapException()
    {
        var file = MakeApproveFile() with { FormatVersion = 999 };
        var json = SlotEnrollmentFileCodec.SerializeApprove(file);

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove(json));
        Assert.Contains("Unsupported slot approve file format version", ex.Message);
    }

    [Fact]
    public void ApproveFile_UnsupportedKeyringFormatVersion_ThrowsCleanTswapException()
    {
        // The version-check-gap class this module has hit before (#146, #148): the embedded
        // keyring format version must be checked explicitly, not just this file's own version.
        var file = MakeApproveFile() with { KeyringFormatVersion = 255 };
        var json = SlotEnrollmentFileCodec.SerializeApprove(file);

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove(json));
        Assert.Contains("Unsupported keyring format version", ex.Message);
    }

    [Fact]
    public void ApproveFile_InvalidJson_ThrowsCleanTswapException()
    {
        Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove("{ not json"));
    }

    [Fact]
    public void DecodeFixed_WrongLength_ThrowsCleanTswapException()
    {
        var tooShort = Convert.ToBase64String(new byte[4]);

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DecodeFixed(tooShort, 16, "test field"));
        Assert.Contains("test field", ex.Message);
        Assert.Contains("16 bytes", ex.Message);
    }

    [Fact]
    public void DecodeFixed_InvalidBase64_ThrowsCleanTswapException()
    {
        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DecodeFixed("not-base64!!!", 16, "test field"));
        Assert.Contains("test field", ex.Message);
        Assert.Contains("base64", ex.Message);
    }

    [Fact]
    public void DecodeVariable_InvalidBase64_ThrowsCleanTswapException()
    {
        Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DecodeVariable("not-base64!!!", "test field"));
    }
}
