using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #261, owner decision of 2026-11-07: <c>tswap slots</c> notes, after the table, when this machine's own
/// Linux TPM slot was sealed under the RSA-2048 primary (a header-less package or <c>TSTP 0x01</c>), so every unlock
/// is slower than it needs to be. Re-enrolling in place is issue #264. Nothing for an ECC slot, for another machine's
/// slot, or off Linux (a Windows TPM slot has no primary to choose).
/// </summary>
public class SlotsRsaPrimaryNoteTests
{
    private static byte[] LegacyPackage() => [40, 0, 0, 0, .. RandomNumberGenerator.GetBytes(60)];

    private static string Note(byte[] slotId) =>
        $"Note: this machine's TPM slot ({Convert.ToHexStringLower(slotId)[..8]}) was made before tswap 0.3.0 and uses an " +
        "RSA-2048 key, so each unlock takes seconds longer than it needs to. A TPM slot made by tswap 0.3.0 or later uses " +
        "ECC P-256 and unlocks several times faster; re-enrolling a slot in place isn't supported yet (issue #264).";

    /// <summary>A TPM keyring vault whose machine slots carry <paramref name="hwBlobs"/>; the first is this machine's.</summary>
    private static (Config Config, List<Slot> Slots) Vault(HardwareBackend? backend, params byte[][] hwBlobs)
    {
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        List<Slot> slots = [];
        foreach (var hwBlob in hwBlobs)
        {
            var pair = SlotKeyPair.Generate();
            slots.Add(MachineSlotWrap.Wrap(vaultKey, pair.PrivateKey, pair.PublicKey, RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize),
                RandomNumberGenerator.GetBytes(32), KeyringFormat.KeyringFormatVersion, vaultId, 1) with { HwBlob = hwBlob });
        }
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, vaultId, 1, slots);
        var config = new Config([], "", DateTime.UtcNow, RequiresTouch: false, RngMode: RngMode.System, Backend: backend,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(keyring)), KeyringSlotId: Convert.ToBase64String(slots[0].SlotId));
        return (config, slots);
    }

    private static string[] Lines(string text) => text.ReplaceLineEndings("\n").Split('\n');

    public static TheoryData<string, byte[]> RsaBlobs() => new()
    {
        { "legacy header-less package", LegacyPackage() },
        { "TSTP 0x01", TpmSlotBlob.Wrap(LegacyPackage(), TpmSlotBlob.Password) },
    };

    [Theory]
    [MemberData(nameof(RsaBlobs))]
    public void OwnRsaSlot_OnLinux_GetsTheNote(string what, byte[] own)
    {
        var (config, slots) = Vault(HardwareBackend.Tpm, own, LegacyPackage());

        var lines = Lines(SlotsCommand.Format(config, os: OSPlatform.Linux));

        // Exactly the text, once: the slot's short id is its only variable part (no blob bytes, no secret).
        Assert.Equal(1, lines.Count(l => l == Note(slots[0].SlotId)));
        Assert.Single(lines, l => l.StartsWith("Note: this machine's TPM slot", StringComparison.Ordinal));
        Assert.True(lines.ToList().IndexOf(Note(slots[0].SlotId)) > lines.ToList().FindLastIndex(l => l.StartsWith(Convert.ToHexStringLower(slots[1].SlotId)[..8])),
            $"{what}: the note follows the table");
    }

    [Theory]
    [InlineData(TpmSlotBlob.EccPrimary)]
    [InlineData(TpmSlotBlob.EccPrimary | TpmSlotBlob.Password)]
    public void OwnEccSlot_NoNote_EvenWithAnotherMachinesRsaSlot(byte flags)
    {
        var (config, _) = Vault(HardwareBackend.Tpm, TpmSlotBlob.Wrap(LegacyPackage(), flags), LegacyPackage(),
            TpmSlotBlob.Wrap(LegacyPackage(), TpmSlotBlob.Password));

        Assert.DoesNotContain("RSA-2048", SlotsCommand.Format(config, os: OSPlatform.Linux));
    }

    [Theory]
    [InlineData("Windows")]
    [InlineData("OSX")]
    public void OwnRsaSlot_OffLinux_NoNote(string os)
    {
        var (config, _) = Vault(HardwareBackend.Tpm, LegacyPackage());

        Assert.DoesNotContain("RSA-2048", SlotsCommand.Format(config, os: OSPlatform.Create(os)));
    }

    [Fact]
    public void VaultNotOnTheTpmBackend_NoNote()
    {
        // The unlock reads a TPM blob only for a TPM vault: a YubiKey vault's machine slot is never "this machine's TPM slot".
        var (config, _) = Vault(backend: null, LegacyPackage());

        Assert.DoesNotContain("RSA-2048", SlotsCommand.Format(config, os: OSPlatform.Linux));
    }

    [Fact]
    public void OwnSlotIsAYubiKeySlot_NoNote()
    {
        // A YubiKey v1 blob classifies as password-free and has no ECC bit, but it is no TPM slot; another machine's
        // RSA TPM slot in the keyring gets no note either.
        var (config, _) = Vault(HardwareBackend.Tpm, YubiKeySlotBlob.Create(11111111, requiresTouch: true).Encode(), LegacyPackage());

        Assert.DoesNotContain("RSA-2048", SlotsCommand.Format(config, os: OSPlatform.Linux));
    }

    [Fact]
    public void OwnSlotCorruptOrFromANewerTswap_NoNote()
    {
        foreach (var flags in new byte[] { 0x00, 0x04 })
        {
            byte[] blob = [.. "TSTP"u8, 1, flags, .. LegacyPackage()];
            var (config, _) = Vault(HardwareBackend.Tpm, blob);

            Assert.DoesNotContain("RSA-2048", SlotsCommand.Format(config, os: OSPlatform.Linux));
        }
    }

    [Theory]
    [InlineData("Linux", true)]
    [InlineData("Windows", false)]
    public void SlotsCommand_UsesTheContextsOs(string os, bool noted)
    {
        using var m = new FleetMachine("rsa-note") { Tpm = RandomNumberGenerator.GetBytes(32), Os = OSPlatform.Create(os) };
        m.Ok("", "init", "--tpm", "--no-password");
        var ownId = MakeOwnSlotRsa(m);

        var stdout = m.Ok("", "slots");

        Assert.Equal(noted, Lines(stdout).Contains(Note(ownId)));
    }

    /// <summary>Strips this machine's slot header, leaving the bare package, as v0.2.0 wrote a password-free slot; returns the slot id.</summary>
    private static byte[] MakeOwnSlotRsa(FleetMachine m)
    {
        var store = new RecordVaultStore(m.Dir);
        var config = store.LoadConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var ownId = Convert.FromBase64String(config.KeyringSlotId!);
        var slots = keyring.Slots.Select(s =>
            s.SlotId.AsSpan().SequenceEqual(ownId) ? s with { HwBlob = TpmSlotBlob.Split(s.HwBlob!).Package } : s).ToList();
        // Straight into the vault folder's keyring file: a save would (rightly) refuse a changed slot.
        File.WriteAllBytes(Path.Combine(m.VaultDir!, RecordVaultStore.KeyringFileName), KeyringCodec.Encode(keyring with { Slots = slots }));
        return ownId;
    }
}
