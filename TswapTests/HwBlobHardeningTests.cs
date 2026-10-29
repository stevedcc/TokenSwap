using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Hardening after the T2 security review: a crafted approve file must never carry a slot
/// hwBlob that <see cref="KeyringCodec.Encode"/> would refuse (a version 2 keyring, a recovery
/// slot) or an absurdly large one, and must fail with a clean <see cref="TswapException"/>, not a
/// raw <see cref="ArgumentException"/>; and <see cref="KeyringCodec.Decode"/> must reject bytes
/// left over after the last slot.
/// </summary>
public class HwBlobHardeningTests
{
    private static SlotDto Slot(SlotKind kind, byte[]? hwBlob) => new(
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
        Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)),
        kind,
        hwBlob == null ? null : Convert.ToBase64String(hwBlob));

    private static string ApproveJson(byte keyringVersion, params SlotDto[] slots) =>
        SlotEnrollmentFileCodec.SerializeApprove(new SlotApproveFile(
            SlotApproveFile.CurrentFormatVersion,
            keyringVersion,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize)),
            1,
            [.. slots],
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize)),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            Convert.ToBase64String(SlotKeyPair.Generate().PublicKey),
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(48))));

    [Fact]
    public void ApproveFile_Version2KeyringSlotWithAHwBlob_IsACleanTswapException()
    {
        var json = ApproveJson(2, Slot(SlotKind.Machine, [1, 2, 3]));

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove(json));
        Assert.Contains("Malformed slot approve file", ex.Message);
        Assert.Contains("version 2", ex.Message);
    }

    [Fact]
    public void ApproveFile_RecoverySlotWithAHwBlob_IsACleanTswapException()
    {
        var json = ApproveJson(3, Slot(SlotKind.Machine, [1, 2, 3]), Slot(SlotKind.Recovery, [4]));

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove(json));
        Assert.Contains("Malformed slot approve file", ex.Message);
        Assert.Contains("recovery slot", ex.Message);
    }

    [Fact]
    public void ApproveFile_OversizedHwBlob_IsACleanTswapException()
    {
        var json = ApproveJson(3, Slot(SlotKind.Machine, new byte[KeyringFormat.MaxHwBlobSize + 1]));

        var ex = Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove(json));
        Assert.Contains("Malformed slot approve file", ex.Message);
        Assert.Contains($"{KeyringFormat.MaxHwBlobSize}", ex.Message);
    }

    [Fact]
    public void ApproveFile_HwBlobNotBase64_IsACleanTswapException()
    {
        var json = ApproveJson(3, Slot(SlotKind.Machine, null) with { HwBlob = "not base64!!" });

        Assert.Throws<TswapException>(() => SlotEnrollmentFileCodec.DeserializeApprove(json));
    }

    [Fact]
    public void ApproveFile_ValidVersion3MachineSlotHwBlobAtTheLimit_IsAccepted()
    {
        var json = ApproveJson(3, Slot(SlotKind.Machine, new byte[KeyringFormat.MaxHwBlobSize]), Slot(SlotKind.Recovery, null));

        var file = SlotEnrollmentFileCodec.DeserializeApprove(json);

        Assert.Equal(2, file.ExistingSlots.Count);
    }

    [Fact]
    public void MaxHwBlobSize_IsWellAboveTheLargestRealBlob()
    {
        // Largest real blob: the Secure Enclave's, ~430 bytes of dataRepresentation + a 4-byte
        // prefix + a 125-byte ECIES package (65 + 12 + 32 + 16) = ~560 bytes. The Windows PCP
        // bundle is ~310 (4 + ~48-byte key name + 256-byte RSA-2048 ciphertext), the Linux TPM
        // sealed public + private ~300.
        Assert.Equal(4096, KeyringFormat.MaxHwBlobSize);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void Decode_ValidKeyringWithOneExtraByte_IsMalformed(byte version)
    {
        var bytes = KeyringCodec.Encode(new Keyring(version, RandomNumberGenerator.GetBytes(16), 1,
            [new Slot(RandomNumberGenerator.GetBytes(16), SlotKeyPair.Generate().PublicKey, [1, 2], SlotKind.Machine)]));
        Assert.NotNull(KeyringCodec.Decode(bytes)); // the untouched bytes decode

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode([.. bytes, 0x00]));
        Assert.Contains("Malformed keyring", ex.Message);
        Assert.Contains("trailing", ex.Message);
    }
}
