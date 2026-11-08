using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 2 row 2: a FIDO2 slot is never requested or approved (its credential is made on a machine that
/// can open the vault, by <c>slot add --fido2</c>), so a request or approve file carrying one is refused.
/// </summary>
public class SlotEnrollmentFileTests
{
    private const string Fido2Refused =
        "A FIDO2 slot isn't requested or approved; add it with 'tswap slot add --fido2' on a machine that can open the vault.";

    [Fact]
    public void RequestFile_Fido2Blob_Refused()
    {
        var file = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            HwBlob: Convert.ToBase64String(Fido2TestSlots.Blob().Encode()));

        var ex = Assert.Throws<TswapException>(() =>
            SlotEnrollmentFileCodec.DeserializeRequest(SlotEnrollmentFileCodec.SerializeRequest(file)));

        Assert.Equal(Fido2Refused, ex.Message);
    }

    [Fact]
    public void ApproveFile_Fido2Blob_Refused()
    {
        var file = new SlotApproveFile(SlotApproveFile.CurrentFormatVersion, KeyringFormat.KeyringFormatVersion,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize)), 1, [],
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(92)),
            NewSlotHwBlob: Convert.ToBase64String(Fido2TestSlots.Blob().Encode()));

        var ex = Assert.Throws<TswapException>(() =>
            SlotEnrollmentFileCodec.DeserializeApprove(SlotEnrollmentFileCodec.SerializeApprove(file)));

        Assert.Equal(Fido2Refused, ex.Message);
    }

    // Final review (task 2 deferred minor): a damaged FIDO2 (TSYK v3) blob in a request file gets the FIDO2 parser's
    // corrupt text, not the OTP parser's "needs a newer tswap".
    [Fact]
    public void RequestFile_CorruptFido2Blob_GetsTheFido2CorruptText()
    {
        var encoded = Fido2TestSlots.Blob().Encode();
        var file = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            HwBlob: Convert.ToBase64String(encoded[..20]));

        var ex = Assert.Throws<TswapException>(() =>
            SlotEnrollmentFileCodec.DeserializeRequest(SlotEnrollmentFileCodec.SerializeRequest(file)));

        Assert.StartsWith("Malformed FIDO2 slot blob", ex.Message);
        Assert.DoesNotContain("newer tswap", ex.Message);
    }

    // A FIDO2 blob with flag bits this build doesn't know is still a FIDO2 slot: the FIDO2 refusal.
    [Fact]
    public void RequestFile_NewerFido2Blob_GetsTheFido2Refusal()
    {
        var encoded = Fido2TestSlots.Blob().Encode();
        encoded[5] |= 0x80; // an unknown flag bit
        var file = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            HwBlob: Convert.ToBase64String(encoded));

        var ex = Assert.Throws<TswapException>(() =>
            SlotEnrollmentFileCodec.DeserializeRequest(SlotEnrollmentFileCodec.SerializeRequest(file)));

        Assert.Equal(Fido2Refused, ex.Message);
    }

    /// <summary>An OTP request still passes (the control for the refusal above).</summary>
    [Fact]
    public void RequestFile_OtpBlob_StillAccepted()
    {
        var file = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            HwBlob: Convert.ToBase64String(YubiKeySlotBlob.Create(11111111, requiresTouch: true).Encode()));

        var decoded = SlotEnrollmentFileCodec.DeserializeRequest(SlotEnrollmentFileCodec.SerializeRequest(file));

        Assert.Equal(file.HwBlob, decoded.HwBlob);
    }
}
