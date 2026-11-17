using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T36 (#350): <c>tswap slots</c> names each hardware slot by its own data, so every machine lists one keyring's
/// slots with the same kinds, and only the slot this machine's <c>config.json</c> names (as the unlock finds it) says
/// "this machine's" or "this Mac's". The full row texts are spelt out here once, to pin the wording.
/// </summary>
public class SlotsKindLabelTests
{
    // xUnit makes a new instance per test, so every test draws the same bytes whatever the order (brief T36, A5).
    private readonly Random _rng = new(HardwareSlotKindTests.Seed);

    private const string WindowsMadeOn = "TPM (Windows), sealed to the TPM of the machine it was made on";
    private const string MacMadeOn = "Secure Enclave, sealed to the Mac it was made on (touch setting recorded only there)";
    private const string LinuxEccOwn = "TPM (Linux, ECC P-256), sealed to this machine's TPM";
    private const string LinuxEccMadeOn = "TPM (Linux, ECC P-256), sealed to the TPM of the machine it was made on";
    private const string LinuxRsaMadeOn = "TPM (Linux, RSA-2048), sealed to the TPM of the machine it was made on";
    private const string NotRecorded = "hardware-sealed (kind not recorded)";

    private const string NewNote =
        "Note: this keyring has more than one machine slot. The row that says \"this machine's TPM\" or \"this Mac's " +
        "Secure Enclave\" is the slot this machine's config.json names as its own; the other rows show what their slot " +
        "data records (slots carry no machine name yet).";

    private const string OldNote =
        "\nNote: this keyring has more than one machine slot. Slot data alone (no\n" +
        "per-slot label yet) can't tell you which one is this machine's own without an\n" +
        "actual hardware unlock, which this listing deliberately doesn't attempt.";

    private byte[] Bytes(int count)
    {
        var bytes = new byte[count];
        _rng.NextBytes(bytes);
        return bytes;
    }

    private byte[] WindowsPackage() => HardwareSlotKindTests.WindowsPackage(_rng);
    private byte[] LinuxPackage() => HardwareSlotKindTests.LinuxPackage(_rng);
    private byte[] SecureEnclavePackage() => HardwareSlotKindTests.SecureEnclavePackage(_rng);
    private byte[] Unrecognised() => HardwareSlotKindTests.Unrecognised(_rng);

    /// <summary>
    /// A keyring vault whose machine slots carry <paramref name="blobs"/>; <paramref name="ownIndex"/> null leaves
    /// <see cref="Config.KeyringSlotId"/> unset, otherwise it names that slot (brief T36, A6).
    /// </summary>
    private (Config Config, List<Slot> Slots) Vault(HardwareBackend? backend, int? ownIndex, bool requiresTouch, params byte[][] blobs)
    {
        var vaultKey = Bytes(32);
        var vaultId = Bytes(KeyringFormat.VaultIdSize);
        List<Slot> slots = [];
        foreach (var blob in blobs)
        {
            var pair = SlotKeyPair.Generate();
            slots.Add(MachineSlotWrap.Wrap(vaultKey, pair.PrivateKey, pair.PublicKey, Bytes(KeyringFormat.SlotIdSize),
                Bytes(32), KeyringFormat.KeyringFormatVersion, vaultId, 1) with { HwBlob = blob });
        }
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, vaultId, 1, slots);
        var config = new Config([], "", TestTime.Fixed, RequiresTouch: requiresTouch, RngMode: RngMode.System, Backend: backend,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(keyring)));
        return (Own(config, slots, backend, ownIndex, requiresTouch), slots);
    }

    /// <summary>The same keyring as listed by another machine: its backend, its own slot, its touch setting.</summary>
    private static Config Own(Config config, List<Slot> slots, HardwareBackend? backend, int? ownIndex, bool requiresTouch) =>
        config with
        {
            Backend = backend,
            RequiresTouch = requiresTouch,
            KeyringSlotId = ownIndex is { } i ? Convert.ToBase64String(slots[i].SlotId) : null,
        };

    private static string Id8(Slot slot) => Convert.ToHexStringLower(slot.SlotId)[..8];

    private static List<string> Rows(string text) =>
        text.ReplaceLineEndings("\n").Split('\n').Where(l => Regex.IsMatch(l, @"^[0-9a-f]{8}\s+machine\s")).ToList();

    private static string Row(string text, Slot slot) => Assert.Single(Rows(text), r => r.StartsWith(Id8(slot), StringComparison.Ordinal));

    private static void AssertRowEndsWith(string text, Slot slot, string expected) => Assert.EndsWith(expected, Row(text, slot));

    /// <summary>Brief T36, A2: the PROTECTION column up to its first <c>", "</c> outside parentheses.</summary>
    private static string KindOf(string row)
    {
        var protection = row[24..];
        var depth = 0;
        for (var i = 0; i < protection.Length - 1; i++)
        {
            depth += protection[i] switch { '(' => 1, ')' => -1, _ => 0 };
            if (depth == 0 && protection[i] == ',' && protection[i + 1] == ' ')
                return protection[..i];
        }
        return protection;
    }

    /// <summary>The issue's keyring: Windows password, Mac password, Linux ECC, Linux ECC password.</summary>
    private (Config Config, List<Slot> Slots) IssuesKeyring() =>
        Vault(HardwareBackend.Tpm, 2, false,
            TpmSlotBlob.Wrap(WindowsPackage(), TpmSlotBlob.Password),
            SecureEnclaveSlotBlob.Wrap(SecureEnclavePackage()),
            TpmSlotBlob.Wrap(LinuxPackage(), TpmSlotBlob.EccPrimary),
            TpmSlotBlob.Wrap(LinuxPackage(), TpmSlotBlob.EccPrimary | TpmSlotBlob.Password));

    private static string OnLinux(Config config, List<Slot> slots) =>
        SlotsCommand.Format(Own(config, slots, HardwareBackend.Tpm, 2, false), os: OSPlatform.Linux);

    private static string OnTheMac(Config config, List<Slot> slots) =>
        SlotsCommand.Format(Own(config, slots, HardwareBackend.SecureEnclave, 1, false), os: OSPlatform.OSX);

    private static string OnWindows(Config config, List<Slot> slots) =>
        SlotsCommand.Format(Own(config, slots, HardwareBackend.Tpm, 0, false), os: OSPlatform.Windows);

    [Fact]
    public void IssuesKeyring_OnLinux_EachSlotByItsOwnKind()
    {
        var (config, slots) = IssuesKeyring();

        var text = OnLinux(config, slots);

        AssertRowEndsWith(text, slots[0], WindowsMadeOn + ", vault password");
        AssertRowEndsWith(text, slots[1], MacMadeOn + ", vault password");
        AssertRowEndsWith(text, slots[2], LinuxEccOwn + ", no password");
        AssertRowEndsWith(text, slots[3], LinuxEccMadeOn + ", vault password");
        Assert.Single(Rows(text), r => r.Contains("this machine's TPM,", StringComparison.Ordinal));
    }

    [Fact]
    public void IssuesKeyring_OnTheMac()
    {
        var (config, slots) = IssuesKeyring();

        var text = OnTheMac(config, slots);

        AssertRowEndsWith(text, slots[1], "Secure Enclave, no touch required, sealed to this Mac's Secure Enclave, vault password");
        AssertRowEndsWith(text, slots[0], WindowsMadeOn + ", vault password");
        AssertRowEndsWith(text, slots[2], LinuxEccMadeOn + ", no password");
        AssertRowEndsWith(text, slots[3], LinuxEccMadeOn + ", vault password");
        Assert.DoesNotContain(Rows(text), r => r.Contains("this machine's", StringComparison.Ordinal));
    }

    [Fact]
    public void IssuesKeyring_OnWindows()
    {
        var (config, slots) = IssuesKeyring();

        var text = OnWindows(config, slots);

        AssertRowEndsWith(text, slots[0], "TPM (Windows), sealed to this machine's TPM, vault password");
        AssertRowEndsWith(text, slots[1], MacMadeOn + ", vault password");
        AssertRowEndsWith(text, slots[2], LinuxEccMadeOn + ", no password");
        AssertRowEndsWith(text, slots[3], LinuxEccMadeOn + ", vault password");
    }

    [Fact]
    public void IssuesKeyring_EveryMachineNamesTheSameKinds()
    {
        var (config, slots) = IssuesKeyring();
        string[] listings = [OnLinux(config, slots), OnTheMac(config, slots), OnWindows(config, slots)];
        string[] expected = ["TPM (Windows)", "Secure Enclave", "TPM (Linux, ECC P-256)", "TPM (Linux, ECC P-256)"];

        for (var i = 0; i < slots.Count; i++)
        {
            var slot = slots[i];
            Assert.All(listings, listing => Assert.Equal(expected[i], KindOf(Row(listing, slot))));
        }
    }

    [Fact]
    public void HeaderlessSlots_ByTheirShape()
    {
        var (config, slots) = Vault(null, 0, false,
            WindowsPackage(), LinuxPackage(), SecureEnclavePackage(), Unrecognised(),
            TpmSlotBlob.Wrap(Unrecognised(), TpmSlotBlob.Password));

        var text = SlotsCommand.Format(config, os: OSPlatform.Linux);

        AssertRowEndsWith(text, slots[0], WindowsMadeOn + ", no password");
        AssertRowEndsWith(text, slots[1], LinuxRsaMadeOn + ", no password");
        AssertRowEndsWith(text, slots[2], MacMadeOn + ", no password");
        AssertRowEndsWith(text, slots[3], NotRecorded + ", no password");
        AssertRowEndsWith(text, slots[4], "TPM (platform not recorded), sealed to the TPM of the machine it was made on, vault password");
        Assert.DoesNotContain(Rows(text), r => r.Contains("this machine's", StringComparison.Ordinal) || r.Contains("this Mac's", StringComparison.Ordinal));
    }

    [Fact]
    public void OwnSlotWithAnUnrecognisedPackage_TakesThisMachinesBackend()
    {
        var (tpm, tpmSlots) = Vault(HardwareBackend.Tpm, 0, false, Unrecognised(), Unrecognised());
        var (mac, macSlots) = Vault(HardwareBackend.SecureEnclave, 0, true, Unrecognised(), Unrecognised());

        var tpmText = SlotsCommand.Format(tpm, os: OSPlatform.Linux);
        var macText = SlotsCommand.Format(mac, os: OSPlatform.OSX);

        AssertRowEndsWith(tpmText, tpmSlots[0], "TPM, sealed to this machine's TPM, no password");
        AssertRowEndsWith(tpmText, tpmSlots[1], NotRecorded + ", no password");
        AssertRowEndsWith(macText, macSlots[0], "Secure Enclave, touch required (Touch ID or password), sealed to this Mac's Secure Enclave, no password");
        AssertRowEndsWith(macText, macSlots[1], NotRecorded + ", no password");
    }

    [Fact]
    public void OwnSlotWhoseDataSaysTheOtherChip_IsNotThisMachines()
    {
        var (tpm, tpmSlots) = Vault(HardwareBackend.Tpm, 0, false, SecureEnclaveSlotBlob.Wrap(SecureEnclavePackage()), LinuxPackage());
        var (mac, macSlots) = Vault(HardwareBackend.SecureEnclave, 0, false, WindowsPackage(), LinuxPackage());

        var tpmText = SlotsCommand.Format(tpm, os: OSPlatform.Linux);
        var macText = SlotsCommand.Format(mac, os: OSPlatform.OSX);

        AssertRowEndsWith(tpmText, tpmSlots[0], MacMadeOn + ", vault password");
        Assert.DoesNotContain(Rows(tpmText), r => r.Contains("this machine's", StringComparison.Ordinal));
        AssertRowEndsWith(macText, macSlots[0], WindowsMadeOn + ", no password");
        Assert.DoesNotContain(Rows(macText), r => r.Contains("this Mac's", StringComparison.Ordinal));
    }

    [Fact]
    public void KeyringSlotIdNotBase64_NoOwnRow_NoThrow()
    {
        var (config, _) = Vault(HardwareBackend.Tpm, 0, false, TpmSlotBlob.Wrap(LinuxPackage(), TpmSlotBlob.EccPrimary), LinuxPackage());
        config = config with { KeyringSlotId = "not base64!" };

        var text = SlotsCommand.Format(config, os: OSPlatform.Linux);

        Assert.Equal(2, Rows(text).Count);
        Assert.DoesNotContain(Rows(text), r => r.Contains("this machine's", StringComparison.Ordinal));
    }

    [Fact]
    public void KeyringSlotIdUnset_TheFirstMachineSlotIsThisMachines()
    {
        var (config, slots) = Vault(HardwareBackend.Tpm, null, false,
            TpmSlotBlob.Wrap(LinuxPackage(), TpmSlotBlob.EccPrimary), WindowsPackage());

        var text = SlotsCommand.Format(config, os: OSPlatform.Linux);

        AssertRowEndsWith(text, slots[0], LinuxEccOwn + ", no password");
        AssertRowEndsWith(text, slots[1], WindowsMadeOn + ", no password");
    }

    [Fact]
    public void MultiSlotNote_OwnSlotCorrupt_KeepsTheOldNote()
    {
        // Round-2 review (GLM Minor 2): the new note points at a row that says "this machine's TPM"; an own slot that
        // is corrupt or needs a newer tswap prints its mark instead, so the old note stays.
        foreach (var flags in new byte[] { 0x00, 0x04 })
        {
            var (config, _) = Vault(HardwareBackend.Tpm, 0, false, [.. "TSTP"u8, 1, flags, .. Unrecognised()], LinuxPackage());

            var text = SlotsCommand.Format(config, os: OSPlatform.Linux).ReplaceLineEndings("\n");

            Assert.Contains(OldNote, text);
            Assert.DoesNotContain(Rows(text), r => r.Contains("this machine's", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void MultiSlotNote_NamesTheOwnRow_WhenThereIsOne()
    {
        var (config, slots) = IssuesKeyring();
        var (headerless, _) = Vault(null, 0, false,
            WindowsPackage(), LinuxPackage(), SecureEnclavePackage(), Unrecognised(),
            TpmSlotBlob.Wrap(Unrecognised(), TpmSlotBlob.Password));

        var linux = OnLinux(config, slots).ReplaceLineEndings("\n");
        var noOwnRow = SlotsCommand.Format(headerless, os: OSPlatform.Linux).ReplaceLineEndings("\n");

        Assert.Contains(NewNote, linux.Replace('\n', ' '));
        Assert.DoesNotContain("can't tell you which one", linux.Replace('\n', ' '));
        Assert.Contains(OldNote, noOwnRow);
    }
}
