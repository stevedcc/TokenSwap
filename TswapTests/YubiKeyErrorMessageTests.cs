using System.Runtime.InteropServices;
using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 5: a YubiKey failure reaches the user with the text <see cref="SdkYubiKeyService"/> gave
/// it (an empty slot 2 points to <c>tswap yubikey setup</c>, a busy key says busy), at unlock and at enrolment; the
/// outer layers don't swallow or re-word it. Everything runs through <see cref="CliRunner"/> over
/// <see cref="SdkYubiKeyService"/> and <see cref="FakeOtpKeys"/>.
/// </summary>
public sealed class YubiKeyErrorMessageTests : IDisposable
{
    private const int SerialA = 61111111;
    private const int SerialB = 62222222;
    private const string SetupHint = "tswap yubikey setup";

    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-errors-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static SdkYubiKeyService Service(FakeOtpKeys fake, OSPlatform? os = null) =>
        new(fake, os ?? YubiKeyAccessTexts.CurrentOs());

    private (int Exit, string Out, string Err) Run(SdkYubiKeyService keys, string stdin, bool terminal, params string[] args) =>
        Run(keys, new FakeConsole(stdin) { IsInputRedirected = !terminal }, () => new MachineChip(null, "no chip in this test"), args);

    private (int Exit, string Out, string Err) Run(
        SdkYubiKeyService keys, FakeConsole console, Func<MachineChip> chip, params string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var ctx = new CommandContext(console, env, () => VaultStores.Open(_dir, warnings: console.Error), keys,
            new VaultUnlocker(keys), testKey: null, sudoBypass: true)
        {
            ChipProbe = chip,
        };
        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    private static void Hide(FakeOtpKeys fake, int serial, KeyboardInterfaceState probe)
    {
        fake.Keys.RemoveAll(k => k.Serial == serial);
        fake.WithHiddenKey(serial);
        fake.Interfaces.Add(probe);
    }

    /// <summary>A vault with one slot on <see cref="SerialA"/> (and the recovery slot), made over a working fake.</summary>
    private void MakeVault(FakeOtpKeys fake)
    {
        var (exit, _, err) = Run(Service(fake), "", false, "init", "--yubikey");
        Assert.True(exit == 0, err);
    }

    [Fact]
    public void Unlock_Slot2Empty_PointsToSetup()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA);
        MakeVault(fake);
        fake.Slot2Empty.Add(SerialA);

        var (exit, _, err) = Run(Service(fake), "", false, "names");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA}", err);
        Assert.Contains(SetupHint, err);
    }

    [Fact]
    public void Unlock_KeyBusy_SaysBusy()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA);
        MakeVault(fake);
        fake.Busy.Add(SerialA);

        var (exit, _, err) = Run(Service(fake), "", false, "names");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA} is busy", err);
        Assert.DoesNotContain("No YubiKey detected", err);
    }

    [Fact]
    public void GuidedInit_HiddenKeyOnMac_ShowsExplanationAndOffersChip()
    {
        var fake = new FakeOtpKeys().WithHiddenKey(SerialA);
        var keys = Service(fake, OSPlatform.OSX);
        var console = new FakeConsole("\n1\ny\n") { IsInputRedirected = false };

        Run(keys, console, () => new MachineChip(HardwareBackend.SecureEnclave, null), "init");

        var text = console.OutText;
        Assert.Contains("YubiKeys: " + YubiKeyAccessTexts.ExplainHidden(SerialA, OSPlatform.OSX), text);
        Assert.Contains("Input Monitoring", text);
        Assert.Contains("1. Secure Enclave", text);
    }

    [Fact]
    public void Enrol_Slot2Empty_PointsToSetup()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA);
        MakeVault(fake);
        fake.WithKey(SerialB);
        fake.Slot2Empty.Add(SerialB);

        var before = File.ReadAllBytes(Path.Combine(_dir, "vault", "keyring"));

        var (exit, _, err) = Run(Service(fake), "", false, "slot", "add", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialB}", err);
        Assert.Contains(SetupHint, err);
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_dir, "vault", "keyring")));
    }

    [Fact]
    public void Unlock_OneKeyBusyAnotherSlot2Empty_NamesBoth()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA);
        MakeVault(fake);
        fake.WithKey(SerialB);
        var (addExit, _, addErr) = Run(Service(fake), "", false, "slot", "add", "--yubikey");
        Assert.True(addExit == 0, addErr);
        fake.Busy.Add(SerialA);
        fake.Slot2Empty.Add(SerialB);

        var (exit, _, err) = Run(Service(fake), "", false, "names");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA} is busy", err);
        Assert.Contains($"YubiKey {SerialB}", err);
        Assert.Contains(SetupHint, err);
    }

    private const int SerialC = 63333333;

    [Fact]
    public void Unlock_BusyHiddenKeyAndUnrelatedReachableKey_SaysBusy()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA);
        MakeVault(fake);
        fake.WithKey(SerialB);
        var (addExit, _, addErr) = Run(Service(fake), "", false, "slot", "add", "--yubikey");
        Assert.True(addExit == 0, addErr);
        fake.Keys.RemoveAll(k => k.Serial == SerialB);
        Hide(fake, SerialA, KeyboardInterfaceState.Busy);
        fake.WithKey(SerialC);

        var (exit, _, err) = Run(Service(fake), "", false, "names");

        Assert.NotEqual(0, exit);
        Assert.Contains("No plugged-in YubiKey matches", err);
        Assert.Contains(SdkYubiKeyService.ProbeBusyMessage, err);
    }

    [Fact]
    public void Enrol_BusyHiddenNewKeyAndEnrolledReachableKey_SaysBusy()
    {
        var fake = new FakeOtpKeys().WithKey(SerialB);
        MakeVault(fake);
        Hide(fake, SerialA, KeyboardInterfaceState.Busy);

        var (exit, _, err) = Run(Service(fake), "", false, "slot", "add", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("already has a working slot", err);
        Assert.Contains(SdkYubiKeyService.ProbeBusyMessage, err);
    }

    [Fact]
    public void Setup_SerialOfBusyHiddenKey_SaysBusy()
    {
        var fake = new FakeOtpKeys().WithKey(SerialB);
        Hide(fake, SerialA, KeyboardInterfaceState.Busy);

        var (exit, _, err) = Run(Service(fake), "", false, "yubikey", "setup", "--touch", "--serial", $"{SerialA}");

        Assert.NotEqual(0, exit);
        Assert.Contains(SdkYubiKeyService.ProbeBusyMessage, err);
        Assert.Empty(fake.Programs);
    }
}
