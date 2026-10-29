using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Keyring format version 3 (issue #154, brief T2 decision 3): the hardware backend's blob moves
/// into the machine slot as <see cref="Slot.HwBlob"/>, so it is versioned by
/// <see cref="Keyring.FormatVersion"/>, which every slot's AEAD binds. Version 2 keyrings (YubiKey
/// and recovery slots only, no hwBlob column) keep decoding; see also
/// <see cref="KeyringV2FixtureTests"/>.
/// </summary>
public class KeyringFormatV3Tests
{
    private static readonly byte[] VaultId = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
    private static readonly byte[] SlotId = Convert.FromHexString("101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] PublicKey =
        Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] SlotId2 = Convert.FromHexString("303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] PublicKey2 =
        Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");

    [Fact]
    public void CurrentVersionIs3()
    {
        Assert.Equal(3, KeyringFormat.KeyringFormatVersion);
    }

    [Fact]
    public void Encode_Version3_MatchesGoldenBytesExactly()
    {
        var keyring = new Keyring(3, VaultId, 1,
        [
            new Slot(SlotId, PublicKey, Convert.FromHexString("aabbccdd"), SlotKind.Machine, HwBlob: Convert.FromHexString("c0ffee")),
            new Slot(SlotId2, PublicKey2, Convert.FromHexString("0102"), SlotKind.Recovery),
        ]);

        var bytes = KeyringCodec.Encode(keyring);

        const string expectedHex =
            "03" +                                                                 // formatVersion
            "000102030405060708090a0b0c0d0e0f" +                                   // vaultId (16)
            "01" +                                                                 // k
            "02000000" +                                                           // slotCount = 2 (LE)
            "101112131415161718191a1b1c1d1e1f" +                                   // slot 1: slotId
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +   //   publicKey
            "04000000" + "aabbccdd" +                                              //   wrapped
            "00" +                                                                 //   kind = Machine
            "03000000" + "c0ffee" +                                                //   hwBlob (version 3)
            "303132333435363738393a3b3c3d3e3f" +                                   // slot 2: slotId
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +   //   publicKey
            "02000000" + "0102" +                                                  //   wrapped
            "01" +                                                                 //   kind = Recovery
            "00000000";                                                            //   hwBlob: none

        Assert.Equal(expectedHex, Convert.ToHexStringLower(bytes));
    }

    [Fact]
    public void EncodeDecode_Version3_RoundTripsAHwBlobSlotAndAYubiKeySlot()
    {
        var hwBlob = RandomNumberGenerator.GetBytes(300);
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1,
        [
            new Slot(SlotId, PublicKey, [1, 2, 3], SlotKind.Machine, hwBlob),   // a TPM machine slot
            new Slot(SlotId2, PublicKey2, [4, 5], SlotKind.Machine),           // a YubiKey machine slot
            new Slot(RandomNumberGenerator.GetBytes(16), PublicKey, [6], SlotKind.Recovery),
        ]);

        var decoded = KeyringCodec.Decode(KeyringCodec.Encode(keyring));

        Assert.Equal(3, decoded.FormatVersion);
        Assert.Equal(VaultId, decoded.VaultId);
        Assert.Equal(3, decoded.Slots.Count);
        Assert.Equal(hwBlob, decoded.Slots[0].HwBlob);
        Assert.Equal(new byte[] { 1, 2, 3 }, decoded.Slots[0].Wrapped);
        Assert.Null(decoded.Slots[1].HwBlob);
        Assert.Equal(SlotId2, decoded.Slots[1].SlotId);
        Assert.Equal(new byte[] { 4, 5 }, decoded.Slots[1].Wrapped);
        Assert.Equal([SlotKind.Machine, SlotKind.Machine, SlotKind.Recovery], decoded.Slots.Select(s => s.Kind));
        Assert.Null(decoded.Slots[2].HwBlob);
    }

    [Fact]
    public void Version2_StillEncodesWithoutTheHwBlobColumn_AndRoundTrips()
    {
        var keyring = new Keyring(2, VaultId, 1, [new Slot(SlotId, PublicKey, [9, 9], SlotKind.Machine)]);

        var bytes = KeyringCodec.Encode(keyring);
        var decoded = KeyringCodec.Decode(bytes);

        Assert.Equal(1 + 16 + 1 + 4 + 16 + 32 + 4 + 2 + 1, bytes.Length);
        Assert.Equal(2, decoded.FormatVersion);
        Assert.Null(decoded.Slots[0].HwBlob);
    }

    [Fact]
    public void Encode_Version2WithAHwBlob_IsAProgrammerError()
    {
        // A version 2 keyring has no place for a hwBlob; silently dropping it would lose the
        // only copy of a TPM/Secure Enclave slot's sealed key.
        var keyring = new Keyring(2, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Machine, HwBlob: [7])]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Encode_RecoverySlotWithAHwBlob_IsAProgrammerError()
    {
        var keyring = new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Recovery, HwBlob: [7])]);

        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(keyring));
    }

    [Fact]
    public void Encode_UnknownVersion_IsAProgrammerError()
    {
        Assert.Throws<ArgumentException>(() => KeyringCodec.Encode(new Keyring(4, VaultId, 1, [])));
    }

    [Fact]
    public void Decode_Version4_SaysTheVaultWasCreatedByANewerTswap()
    {
        var bytes = KeyringCodec.Encode(new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1])]));
        bytes[0] = 4;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(bytes));

        Assert.Contains("Unsupported keyring format version: 4", ex.Message);
        Assert.Contains("newer", ex.Message);
    }

    [Fact]
    public void Decode_RecoverySlotCarryingAHwBlob_IsMalformed()
    {
        var bytes = KeyringCodec.Encode(new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Recovery)]));
        // Rewrite the trailing hwBlob length (0) to 1 and append one byte.
        bytes[^4] = 1;
        bytes = [.. bytes, 0x42];

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(bytes));
        Assert.Contains("Malformed keyring", ex.Message);
    }

    [Fact]
    public void Decode_TruncatedHwBlobLength_IsMalformed()
    {
        var bytes = KeyringCodec.Encode(new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Machine, [5, 6])]));

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(bytes[..^4]));
        Assert.Contains("Malformed keyring", ex.Message);
    }

    [Fact]
    public void Decode_HugeHwBlobLengthPrefix_IsMalformedNotAnOverflow()
    {
        var bytes = KeyringCodec.Encode(new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Machine, [5, 6])]));
        // hwBlobLength sits just before the last 2 bytes.
        bytes[^6] = 0xFF; bytes[^5] = 0xFF; bytes[^4] = 0xFF; bytes[^3] = 0xFF;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(bytes));
        Assert.Contains("Malformed keyring", ex.Message);
    }

    [Fact]
    public void TamperingWithTheVersionByte_FailsAuthentication()
    {
        // A real version 3 keyring vault (YubiKey slot, test-mode KEK = the override key),
        // relabelled as version 2 the way an attacker would: re-encoded as a well-formed version
        // 2 keyring, so the parser has nothing to object to. What stops it is the AEAD: the slot
        // was wrapped with formatVersion 3 in its associated data. (A bare 3 -> 2 byte flip is
        // now rejected earlier, as trailing bytes; see the next test.)
        var kekSlot = RandomNumberGenerator.GetBytes(32);
        var (config, _, _) = TswapCli.Commands.InitCommand.BuildKeyringConfig(
            kekSlot, [1, 2], new string('0', 40), null, RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), RandomNumberGenerator.GetBytes(32), includeRecovery: false);
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        Assert.Equal(3, keyring.FormatVersion);
        var relabelled = KeyringCodec.Encode(keyring with { FormatVersion = 2 });
        Assert.Equal(2, relabelled[0]);
        var tampered = config with { Keyring = Convert.ToBase64String(relabelled) };
        var unlocker = new VaultUnlocker(new TestKeyYubiKeyService(kekSlot), overrideKey: kekSlot);

        Assert.NotNull(unlocker.Unlock(config, _ => 0)); // the untampered vault opens
        var ex = Assert.Throws<TswapException>(() => unlocker.Unlock(tampered, _ => 0));
        Assert.Contains("authentication", ex.Message);
    }

    [Fact]
    public void FlippingOnlyTheVersionByte_3To2_IsRejectedAsMalformed()
    {
        var bytes = KeyringCodec.Encode(new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Machine)]));
        bytes[0] = 2;

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(bytes));
        Assert.Contains("Malformed keyring", ex.Message);
    }

    [Fact]
    public void Decode_Version3_UnknownSlotKind_StillThrows()
    {
        var bytes = KeyringCodec.Encode(new Keyring(3, VaultId, 1, [new Slot(SlotId, PublicKey, [1], SlotKind.Machine)]));
        bytes[^5] = 0xFF; // kind sits just before the 4-byte hwBlob length (0)

        var ex = Assert.Throws<TswapException>(() => KeyringCodec.Decode(bytes));
        Assert.Contains("unknown slot kind", ex.Message);
    }

    [Fact]
    public void Version3_FlippedByteInsideTheWrappedPayload_FailsAuthentication()
    {
        var kekSlot = RandomNumberGenerator.GetBytes(32);
        var (config, _, _) = TswapCli.Commands.InitCommand.BuildKeyringConfig(
            kekSlot, [1, 2], new string('0', 40), null, RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), RandomNumberGenerator.GetBytes(32), includeRecovery: false);
        var bytes = Convert.FromBase64String(config.Keyring!);
        bytes[^6] ^= 0xFF; // last wrapped byte: before kind(1) + hwBlobLength(4)
        var unlocker = new VaultUnlocker(new TestKeyYubiKeyService(kekSlot), overrideKey: kekSlot);

        var ex = Assert.Throws<TswapException>(() => unlocker.Unlock(config with { Keyring = Convert.ToBase64String(bytes) }, _ => 0));
        Assert.Contains("authentication", ex.Message);
    }
}
