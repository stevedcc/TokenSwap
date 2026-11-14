using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 8: the guided <c>init</c> offers each plugged-in YubiKey as an OTP slot and a FIDO2 slot (listed
/// through the FIDO2 service, matched to the OTP keys by serial), in each OS's order: Linux OTP then FIDO2, macOS
/// FIDO2 first (no Input Monitoring needed), Windows one FIDO2 entry after the TPM and the OTP keys (its dialog picks
/// the key). A key with no OTP interface (the Security Key series) is offered as FIDO2 only, and every OS says what each
/// slot type needs elsewhere. The OS is the context's (<see cref="TswapCli.CommandContext.Os"/>), so each OS's list is
/// checked on any OS.
/// </summary>
public sealed class GuidedInitFido2Tests : IDisposable
{
    private const int Serial = 11111111;
    private const string Pin = FakeFido2Keys.DefaultPin;
    private const string Password = "correct horse battery staple";

    /// <summary>Security Key NFC by Yubico (<see cref="YubicoAaguids"/>): FIDO2 only, no OTP interface, no serial.</summary>
    private static readonly Guid SecurityKeyAaguid = Guid.Parse("149a2021-8ef6-4133-96b8-81f8d5b7f1f5");

    private const string LinuxOtp = "YubiKey 11111111, OTP slot (no PIN)";
    private const string Fido2Entry = "YubiKey 11111111, FIDO2 slot (PIN + touch)";
    private const string MacFido2Entry = "YubiKey 11111111, FIDO2 slot (PIN + touch; preferred on a Mac: no Input Monitoring needed)";
    private const string MacOtp = "YubiKey 11111111, OTP slot (no PIN; needs Input Monitoring for the terminal)";
    private const string WindowsFido2Entry = "a security key's FIDO2 slot (Windows' dialog: pick the key, PIN, touch)";

    private readonly List<FleetMachine> _machines = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
    }

    private FleetMachine Machine(OSPlatform os, params int[] otpSerials)
    {
        var m = new FleetMachine("guided-fido2", SimulatedYubiKeyService.WithKeys(otpSerials))
        {
            Fido2Keys = new FakeFido2Keys { CanList = os != OSPlatform.Windows },
            Terminal = new FakeTerminal(),
            Os = os,
            ChipOverride = () => new MachineChip(null, "not in this test"),
        };
        _machines.Add(m);
        return m;
    }

    /// <summary>The numbered entries of the guided list ("  1. …"), without their numbers.</summary>
    private static List<string> Entries(string stdout)
    {
        var lines = stdout.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var start = lines.IndexOf("This machine has:");
        Assert.True(start >= 0, stdout);
        List<string> entries = [];
        for (var i = start + 1; i < lines.Count && lines[i].StartsWith("  ", StringComparison.Ordinal); i++)
        {
            var line = lines[i].Trim();
            var dot = line.IndexOf(". ", StringComparison.Ordinal);
            if (dot > 0 && int.TryParse(line[..dot], out var number) && number == entries.Count + 1)
                entries.Add(line[(dot + 2)..]);
        }
        return entries;
    }

    public static TheoryData<string> Oses => ["linux", "macos", "windows"];

    private static OSPlatform Os(string name) => name switch
    {
        "linux" => OSPlatform.Linux,
        "macos" => OSPlatform.OSX,
        _ => OSPlatform.Windows,
    };

    [Theory]
    [MemberData(nameof(Oses))]
    public void GuidedInit_OffersFido2PerKey_PerOsOrder(string os)
    {
        var m = Machine(Os(os), Serial);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        if (os == "windows")
        {
            m.ChipOverride = null;
            m.Tpm = RandomNumberGenerator.GetBytes(32);
        }

        // Enter, then the end of input at the pick prompt: the list is shown and nothing is written.
        var (exit, stdout, _) = m.RunOnTerminal("\n", "init", "--no-password");

        Assert.Equal(1, exit);
        Assert.False(File.Exists(m.ConfigPath));
        List<string> expected = os switch
        {
            "linux" => [LinuxOtp, Fido2Entry],
            "macos" => [MacFido2Entry, MacOtp],
            _ => ["TPM", LinuxOtp, WindowsFido2Entry],
        };
        Assert.Equal(expected, Entries(stdout));
        Assert.DoesNotContain(m.Fido2Keys.Calls, c => c.Op != FakeFido2Op.Find);
    }

    [Fact]
    public void GuidedInit_FidoOnlyKey_OfferedAsFido2Only()
    {
        var m = Machine(OSPlatform.Linux);
        var key = m.Fido2Keys!.AddKey(null, SecurityKeyAaguid);
        m.Terminal!.Enqueue(Pin, Pin);

        // Enter, pick 1, recovery (default yes), other machines no.
        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(["Security Key NFC by Yubico, FIDO2 slot (PIN + touch)"], Entries(stdout));
        Assert.DoesNotContain("(no YubiKey plugged in)", stdout);
        Assert.Equal(HardwareBackend.YubiKey, m.Config.Backend);
        var keyring = m.Keyring;
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));
        var blob = Assert.IsType<YubiKeySlotKind.Fido2>(YubiKeySlotKinds.Classify(keyring.Slots[0].HwBlob)).Blob;
        Assert.Null(blob.Serial);
        Assert.True(m.Fido2Keys.Holds(key, blob.CredentialId));
        Assert.Contains("Security Key NFC by Yubico, FIDO2: no password", stdout);

        // It opens the vault: the PIN at the terminal, a touch.
        m.Terminal.Enqueue(Pin);
        var (namesExit, _, namesErr) = m.Run("", "names");
        Assert.True(namesExit == 0, namesErr);
    }

    [Fact]
    public void GuidedInit_BothSlotsForOneKey_GivesTwoSlots()
    {
        var m = Machine(OSPlatform.Linux, Serial);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Terminal!.Enqueue(Pin, Pin);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        var machineSlots = m.Keyring.Slots.Where(s => s.Kind == SlotKind.Machine).Select(s => YubiKeySlotKinds.Classify(s.HwBlob)).ToList();
        Assert.Equal(2, machineSlots.Count);
        Assert.Equal(Serial, Assert.Single(machineSlots.OfType<YubiKeySlotKind.Otp>()).Blob.Serial);
        Assert.Equal(Serial, Assert.Single(machineSlots.OfType<YubiKeySlotKind.Fido2>()).Blob.Serial);
        Assert.Contains($"YubiKey {Serial}, OTP: no password", stdout);
        Assert.Contains($"YubiKey {Serial}, FIDO2: no password", stdout);

        // Each opens the vault on its own: the OTP slot with no PIN, then the FIDO2 slot with the OTP key's slot 2 gone.
        m.Fido2Keys.Calls.Clear();
        m.Ok("", "names");
        Assert.Empty(m.Fido2Keys.Calls);
        m.Keys.ProgramSlot2(Serial, true); // a new secret: the OTP slot no longer opens
        m.Terminal.Enqueue(Pin);
        var (namesExit, _, namesErr) = m.Run("", "names");
        Assert.True(namesExit == 0, namesErr);
        Assert.Equal(1, m.Fido2Keys.Calls.Count(c => c.Op == FakeFido2Op.GetHmacSecret));
    }

    [Fact]
    public void GuidedInit_Fido2PasswordSlot_NeedsThePassword()
    {
        var m = Machine(OSPlatform.Linux);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Terminal!.Enqueue(Pin, Pin);

        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1\n{Password}\n{Password}\n\nn\n", "init", "--password");

        Assert.True(exit == 0, stderr + stdout);
        var blob = Assert.IsType<YubiKeySlotKind.Fido2>(YubiKeySlotKinds.Classify(m.Keyring.Slots[0].HwBlob)).Blob;
        Assert.True(blob.RequiresPassword);
        Assert.Contains($"YubiKey {Serial}, FIDO2: password", stdout);
        m.Terminal.Enqueue(Pin);
        var (namesExit, _, namesErr) = m.RunOnTerminal($"{Password}\n", "names");
        Assert.True(namesExit == 0, namesErr);
    }

    [Theory]
    [MemberData(nameof(Oses))]
    public void GuidedInit_ShowsMultiOsNote(string os)
    {
        var m = Machine(Os(os), Serial);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);

        var (_, stdout, _) = m.RunOnTerminal("\n", "init", "--no-password");

        Assert.Contains(GuidedInit.MultiOsNote, stdout);
        Assert.Equal(
            "Using a key on other machines too? An OTP slot needs Input Monitoring for the terminal on a Mac and Yubico's udev " +
            "rule on Linux. A FIDO2 slot needs no Input Monitoring on a Mac and, on Linux, no extra rule on current systemd " +
            "distributions (otherwise the key maker's udev rule); it asks for the key's FIDO2 PIN and a touch on every unlock, and a " +
            "FIDO2 slot enrolled on one OS opens the vault on the others. Pick both for one key to give it two slots; either " +
            "opens the vault.",
            GuidedInit.MultiOsNote);
    }

    // Final review (carry-forward 3): the note is about FIDO2 slots, so it is shown only when one is offered.
    [Fact]
    public void GuidedInit_MultiOsNote_NotShownWithoutAFido2Entry()
    {
        var m = Machine(OSPlatform.Linux, Serial); // an OTP key, no FIDO2 key listed

        var (_, stdout, _) = m.RunOnTerminal("\n", "init", "--no-password");

        Assert.Contains(LinuxOtp, Entries(stdout));
        Assert.DoesNotContain(GuidedInit.MultiOsNote, stdout);
    }

    [Fact]
    public void GuidedInit_MultiOsNote_NotShownWithAFido2ListingProblem()
    {
        var m = Machine(OSPlatform.Linux, Serial);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Fido2Keys.FailNext(FakeFido2Op.Find, TswapCore.Vault.Fido2.Fido2Failure.Busy);

        var (_, stdout, _) = m.RunOnTerminal("\n", "init", "--no-password");

        Assert.Contains("  FIDO2 keys: ", stdout);
        Assert.DoesNotContain(GuidedInit.MultiOsNote, stdout);
    }

    [Fact]
    public void GuidedInit_Fido2KeyWithoutPin_OffersOneFirst()
    {
        var m = Machine(OSPlatform.Linux);
        var key = m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid, pin: null);
        // The offer, the new PIN twice, then the PIN for each of the two key operations.
        m.Terminal!.Enqueue("yes", Pin, Pin, Pin, Pin);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(Pin, key.Pin);
        Assert.Contains($"YubiKey {Serial} has no FIDO2 PIN; a FIDO2 slot needs one. Set a FIDO2 PIN on it now? (yes/no): ", m.Terminal.Text);
        Assert.IsType<YubiKeySlotKind.Fido2>(YubiKeySlotKinds.Classify(m.Keyring.Slots[0].HwBlob));
    }

    [Fact]
    public void GuidedInit_Fido2KeyLeftOut_CarriesOnWithTheOtpSlot()
    {
        // A FIDO2 enrolment that fails (a wrong PIN) gets the same carry-on offer as a key tswap can't reach.
        var m = Machine(OSPlatform.Linux, Serial);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Terminal!.Enqueue("000000");

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2\n\ny\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains($"Carry on without YubiKey {Serial}, FIDO2? (y/N): ", stdout);
        var machine = Assert.Single(m.Keyring.Slots, s => s.Kind == SlotKind.Machine);
        Assert.IsType<YubiKeySlotKind.Otp>(YubiKeySlotKinds.Classify(machine.HwBlob));
    }

    // Final review: a FIDO2 listing problem is said on its own line, without "(no YubiKey plugged in)" beside it.
    [Fact]
    public void GuidedInit_Fido2ListingProblem_NoNoYubiKeyLine()
    {
        var m = Machine(OSPlatform.Linux);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Fido2Keys.FailNext(FakeFido2Op.Find, TswapCore.Vault.Fido2.Fido2Failure.Busy);

        var (_, stdout, _) = m.RunOnTerminal("\n", "init", "--no-password");

        Assert.Contains("  FIDO2 keys: ", stdout);
        Assert.DoesNotContain("(no YubiKey plugged in)", stdout);
    }

    // Final review: stopping after a make-credential says the key may keep an unused credential, and that it is
    // harmless; a stop before any credential was made doesn't.
    [Fact]
    public void GuidedInit_StopAfterMakeCredential_SaysAnUnusedCredentialMayStay()
    {
        var m = Machine(OSPlatform.Linux);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Fido2Keys.FailNext(FakeFido2Op.GetHmacSecret, TswapCore.Vault.Fido2.Fido2Failure.TimedOut, afterPin: true);
        m.Terminal!.Enqueue(Pin, Pin);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Stopped without YubiKey {Serial}, FIDO2. No config or vault was written. {GuidedInit.UnusedCredentialNote}", stdout + stderr);
    }

    [Fact]
    public void GuidedInit_StopBeforeMakeCredential_SaysNothingAboutCredentials()
    {
        var m = Machine(OSPlatform.Linux);
        m.Fido2Keys!.AddKey(Serial, Fido2TestSlots.Aaguid);
        m.Terminal!.Enqueue("000000"); // a wrong PIN: make-credential refused

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Stopped without YubiKey {Serial}, FIDO2. No config or vault was written.", stdout + stderr);
        Assert.DoesNotContain(GuidedInit.UnusedCredentialNote, stdout + stderr);
    }

    [Fact]
    public void UnusedCredentialNote_SaysItIsHarmless() =>
        Assert.Equal("A key used in this run may keep an unused FIDO2 credential: harmless (non-discoverable: most keys, YubiKeys included, store nothing for it).",
            GuidedInit.UnusedCredentialNote);
}
