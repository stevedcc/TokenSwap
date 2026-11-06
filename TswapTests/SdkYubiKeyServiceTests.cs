using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Vault;
using Xunit;
using Yubico.PlatformInterop;
using Yubico.YubiKey;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 2: <see cref="SdkYubiKeyService"/> over the device seam (<see cref="FakeOtpKeys"/>).
/// What the user sees for each state of the keys: listed, hidden from the keyboard interface, without a serial, busy,
/// slot 2 empty; and the exact challenge bytes the key receives.
/// </summary>
public sealed class SdkYubiKeyServiceTests
{
    private static SdkYubiKeyService Service(IOtpKeys keys, OSPlatform? os = null, TextWriter? verbose = null) =>
        new(keys, os ?? OSPlatform.Linux, verbose);

    // ── ListSerials ────────────────────────────────────────────────────────────

    [Fact]
    public void ListSerials_ReturnsKeyboardReachableSerials()
    {
        var keys = new FakeOtpKeys().WithKey(33060005).WithKey(12345678);

        Assert.Equal([33060005, 12345678], Service(keys).ListSerials());
    }

    [Fact]
    public void ListSerials_NoKeys_ReturnsEmpty() =>
        Assert.Empty(Service(new FakeOtpKeys()).ListSerials());

    [Fact]
    public void ListSerials_NoKeyboardReachableKey_ExplainsPerOs_MacOS()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.OSX).ListSerials());

        Assert.Contains("Input Monitoring", ex.Message);
        Assert.Contains("YubiKey 33060005", ex.Message);
    }

    [Fact]
    public void ListSerials_NoKeyboardReachableKey_ExplainsPerOs_Linux()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).ListSerials());

        Assert.Contains("YubiKey 33060005", ex.Message);
        Assert.Contains("OTP interface", ex.Message);
        Assert.Contains("udev rule", ex.Message);
        Assert.Contains("ykpers", ex.Message);
        Assert.Contains("yubikey-personalization", ex.Message);
        Assert.Contains("administrator", ex.Message);
        Assert.Contains("no smart-card fallback", ex.Message);
        Assert.Contains("TPM", ex.Message);
        Assert.Contains("another machine", ex.Message);
    }

    [Fact]
    public void ListSerials_NoKeyboardReachableKey_ExplainsPerOs_Windows()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Windows).ListSerials());

        Assert.Contains("YubiKey 33060005: its OTP interface can't be reached", ex.Message);
        Assert.DoesNotContain("Input Monitoring", ex.Message);
        Assert.DoesNotContain("udev", ex.Message);
    }

    /// <summary>
    /// Final review item 6 (p2-I-1): the SDK's listing itself fails as busy (another program mid-command): the busy
    /// kind and text, never "no YubiKey".
    /// </summary>
    [Fact]
    public void ListSerials_KeyBusy_SaysBusy()
    {
        var keys = new FakeOtpKeys { FindFails = OtpFailure.Busy }.WithKey(33060005);

        var ex = Assert.Throws<YubiKeyDeviceException>(() => Service(keys).ListSerials());

        Assert.Equal(OtpFailure.Busy, ex.Kind);
        Assert.Equal("A YubiKey is busy (another tswap or app is using it); try again.", ex.Message);
        Assert.DoesNotContain("No YubiKey", ex.Message);
    }

    /// <summary>Final review item 6 (p2-M-1): the fake's busy key fails a program call too, as its doc says.</summary>
    [Fact]
    public void ProgramSlot2_KeyBusy_SaysBusyAndProgramsNothing()
    {
        var keys = new FakeOtpKeys().WithKey(33060005);
        keys.Slot2Empty.Add(33060005);
        keys.Busy.Add(33060005);

        var ex = Assert.Throws<YubiKeyDeviceException>(() => Service(keys).ProgramSlot2(33060005, requireTouch: true));

        Assert.Equal(OtpFailure.Busy, ex.Kind);
        Assert.Equal("YubiKey 33060005 is busy (another tswap or app is using it); try again.", ex.Message);
        Assert.Contains(33060005, keys.Slot2Empty); // nothing was programmed
    }

    [Fact]
    public void ListSerials_OneReachableOneHidden_ReturnsTheReachableOne()
    {
        // Mixed keys: the per-OS explanation is only for when none is reachable.
        var keys = new FakeOtpKeys().WithHiddenKey(11111111).WithKey(22222222);

        Assert.Equal([22222222], Service(keys).ListSerials());
    }

    [Fact]
    public void ListSerials_OnlyKeyHasNoSerial_SaysSerialUnreadable()
    {
        var keys = new FakeOtpKeys().WithKey(null);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).ListSerials());

        Assert.Contains("serial", ex.Message);
        Assert.Contains("can't be read", ex.Message);
        Assert.DoesNotContain("No YubiKey", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ListSerials_SerialLessKeyBesideAnother_ListsTheOther()
    {
        var keys = new FakeOtpKeys().WithKey(null).WithKey(33060005);

        Assert.Equal([33060005], Service(keys).ListSerials());
    }

    // ── FindKeys ───────────────────────────────────────────────────────────────

    [Fact]
    public void FindKeys_ReportsHiddenAndReachable()
    {
        var keys = new FakeOtpKeys().WithKey(33060005, "HidKeyboard, HidFido").WithHiddenKey(12345678, "HidFido");

        var found = Service(keys).FindKeys();

        Assert.Equal(
            [new YubiKeyInfo(33060005, true, "HidKeyboard, HidFido"), new YubiKeyInfo(12345678, false, "HidFido")],
            found);
    }

    // ── Challenge ──────────────────────────────────────────────────────────────

    [Fact]
    public void Challenge_SendsYkmanBytes_ShortString_ZeroPadded()
    {
        var keys = new FakeOtpKeys().WithKey(1);

        Service(keys).Challenge(1, "abc");

        var sent = Assert.Single(keys.Challenges).Challenge;
        Assert.Equal(64, sent.Length);
        Assert.Equal(new byte[] { 0x61, 0x62, 0x63 }, sent[..3]);
        Assert.All(sent[3..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void Challenge_SendsYkmanBytes_LongString_Truncated()
    {
        var keys = new FakeOtpKeys().WithKey(1);
        var text = new string('x', 36) + new string('y', 64);

        Service(keys).Challenge(1, text);

        var sent = Assert.Single(keys.Challenges).Challenge;
        Assert.Equal(Encoding.ASCII.GetBytes(text)[..64], sent);
    }

    [Fact]
    public void Challenge_SendsYkmanBytes_MultiByteCutInHalf()
    {
        var keys = new FakeOtpKeys().WithKey(1);
        var text = "a" + string.Concat(Enumerable.Repeat("é", 32)); // 65 UTF-8 bytes

        Service(keys).Challenge(1, text);

        var sent = Assert.Single(keys.Challenges).Challenge;
        Assert.Equal(64, sent.Length);
        Assert.Equal(0x61, sent[0]);
        for (var i = 0; i < 31; i++)
        {
            Assert.Equal(0xC3, sent[1 + 2 * i]);
            Assert.Equal(0xA9, sent[2 + 2 * i]);
        }
        Assert.Equal(0xC3, sent[63]); // the 32nd é, cut in half (byte truncation, as ykman got it)
    }

    [Fact]
    public void Challenge_ReturnsTheKeysResponse()
    {
        var keys = new FakeOtpKeys().WithKey(7);
        var frame = new byte[64];
        "abc"u8.CopyTo(frame);

        Assert.Equal(HMACSHA1.HashData(FakeOtpKeys.SecretFor(7), frame), Service(keys).Challenge(7, "abc"));
    }

    [Fact]
    public void Challenge_KeyNotReachable_ExplainsPerOs()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);

        var mac = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.OSX).Challenge(33060005, "abc"));
        var linux = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).Challenge(33060005, "abc"));

        Assert.Contains("Input Monitoring", mac.Message);
        Assert.Contains("udev rule", linux.Message);
        Assert.Empty(keys.Challenges); // never challenged a key it knows it can't reach
    }

    [Fact]
    public void Challenge_SerialAbsent_SaysNotPluggedIn()
    {
        var keys = new FakeOtpKeys().WithKey(11111111);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(33060005, "abc"));

        Assert.Contains("YubiKey 33060005 is not plugged in", ex.Message);
        Assert.DoesNotContain("udev", ex.Message);
        Assert.Empty(keys.Challenges);
    }

    [Fact]
    public void Challenge_SerialAbsent_AddsPerOsTextWhenHiddenSerialUnknown()
    {
        // The slot's key may be the hidden one whose serial can't be read.
        var keys = new FakeOtpKeys().WithHiddenKey(null);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).Challenge(33060005, "abc"));

        Assert.Contains("YubiKey 33060005 is not plugged in", ex.Message);
        Assert.Contains("udev rule", ex.Message);
        Assert.Contains("A YubiKey", ex.Message);
    }

    [Fact]
    public void Challenge_SerialAbsent_HiddenKeyWithKnownSerial_NoPerOsText()
    {
        // A hidden key whose serial is known is not the one asked for: no reason to explain it.
        var keys = new FakeOtpKeys().WithHiddenKey(11111111);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).Challenge(33060005, "abc"));

        Assert.Contains("YubiKey 33060005 is not plugged in", ex.Message);
        Assert.DoesNotContain("udev", ex.Message);
    }

    [Fact]
    public void ChallengeReportingTouch_TouchRequested_ReportsTrue()
    {
        var keys = new FakeOtpKeys().WithKey(5);
        keys.AsksForTouch.Add(5);

        Assert.True(Service(keys).ChallengeReportingTouch(5, "abc").AskedForTouch);
    }

    [Fact]
    public void ChallengeReportingTouch_NoTouch_ReportsFalse()
    {
        var keys = new FakeOtpKeys().WithKey(5);

        Assert.False(Service(keys).ChallengeReportingTouch(5, "abc").AskedForTouch);
    }

    [Fact]
    public void Challenge_KeyBusy_SaysBusy()
    {
        var keys = new FakeOtpKeys().WithKey(33060005);
        keys.Busy.Add(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(33060005, "abc"));

        Assert.Contains("33060005", ex.Message);
        Assert.Contains("busy", ex.Message);
        Assert.DoesNotContain("No YubiKey", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Challenge_Slot2Empty_PointsToSetup()
    {
        var keys = new FakeOtpKeys().WithKey(33060005);
        keys.Slot2Empty.Add(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(33060005, "abc"));

        Assert.Equal("Slot 2 of YubiKey 33060005 isn't set up for challenge-response; run `tswap yubikey setup`.", ex.Message);
    }

    [Fact]
    public void Challenge_OtherFailure_PassesTheSdkMessageThroughWithSerial()
    {
        var keys = new ThrowingOtpKeys(9, new OtpKeysException(OtpFailure.Other, 9, "Timed out waiting for user interaction."));

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(9, "abc"));

        Assert.Contains("YubiKey 9", ex.Message);
        Assert.Contains("Timed out waiting for user interaction.", ex.Message);
    }

    [Fact]
    public void DetectTouchRequirement_ReturnsNull() =>
        Assert.Null(Service(new FakeOtpKeys().WithKey(1)).DetectTouchRequirement(1));

    [Fact]
    public void Verbose_PrintsSerialAndTick()
    {
        var verbose = new StringWriter();

        Service(new FakeOtpKeys().WithKey(33060005), verbose: verbose).Challenge(33060005, "abc");

        Assert.Equal("YubiKey (serial: 33060005)... ✓" + Environment.NewLine, verbose.ToString());
    }

    [Fact]
    public void IsSimulated_IsFalse() => Assert.False(Service(new FakeOtpKeys()).IsSimulated);

    // ── Slot 2 state and programming ──────────────────────────────────────────

    [Fact]
    public void GetSlot2State_ReportsTheKeysState()
    {
        var keys = new FakeOtpKeys().WithKey(1).WithKey(2);
        keys.Slot2Empty.Add(2);

        Assert.Equal(Slot2State.Configured, Service(keys).GetSlot2State(1));
        Assert.Equal(Slot2State.Empty, Service(keys).GetSlot2State(2));
    }

    [Fact]
    public void GetSlot2State_SerialAbsent_SaysNotPluggedIn()
    {
        var ex = Assert.ThrowsAny<TswapException>(() => Service(new FakeOtpKeys()).GetSlot2State(33060005));

        Assert.Contains("YubiKey 33060005 is not plugged in", ex.Message);
    }

    [Fact]
    public void ProgramSlot2_Success_ProgramsThatSerialWithTheTouchFlag()
    {
        var keys = new FakeOtpKeys().WithKey(1).WithKey(2);

        Service(keys).ProgramSlot2(2, requireTouch: true);

        Assert.Equal([(2, true)], keys.Programs);
    }

    [Theory]
    [InlineData(OtpFailure.ProgramFailed)]
    [InlineData(OtpFailure.VerifyWrong)]
    [InlineData(OtpFailure.VerifyNoAnswer)]
    public void SdkService_ProgramSlot2_PassesKindThrough(OtpFailure kind)
    {
        var keys = new FakeOtpKeys().WithKey(33060005);
        keys.ProgramOutcome[33060005] = kind;

        var ex = Assert.Throws<YubiKeyProgramException>(() => Service(keys).ProgramSlot2(33060005, requireTouch: false));

        Assert.Equal(kind, ex.Kind);
        Assert.Equal(33060005, ex.Serial);
        Assert.IsAssignableFrom<TswapException>(ex);
    }

    [Fact]
    public void ProgramSlot2_KeyNotReachable_ExplainsPerOs_AndNeverPrograms()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.OSX).ProgramSlot2(33060005, true));

        Assert.Contains("Input Monitoring", ex.Message);
        Assert.Empty(keys.Programs);
    }

    [Fact]
    public void TestKeyService_ProgramSlot2_Refuses()
    {
        var service = new TestKeyYubiKeyService(new byte[32]);

        var ex = Assert.ThrowsAny<TswapException>(() => service.ProgramSlot2(TestKeyYubiKeyService.Serial1, requireTouch: true));

        Assert.Equal("Test mode (TSWAP_TEST_KEY) can't program a YubiKey.", ex.Message);
    }

    [Fact]
    public void TestKeyService_FindKeysAndSlot2State()
    {
        var service = new TestKeyYubiKeyService(new byte[32]);

        Assert.Equal([new YubiKeyInfo(TestKeyYubiKeyService.Serial1, true, "HidKeyboard")], service.FindKeys());
        Assert.Equal(Slot2State.Configured, service.GetSlot2State(TestKeyYubiKeyService.Serial1));
    }

    // ── The SDK's exceptions ───────────────────────────────────────────────────

    /// <summary>
    /// One row per mapped SDK exception, built the way the SDK (Yubico.NET.SDK 1.18.1) throws it; the message texts
    /// are copied from its ExceptionMessages.resx (source lines in the task 2 report).
    /// </summary>
    public static TheoryData<Exception, OtpFailure> SdkExceptions => new()
    {
        // KeyboardTransform.WaitFor: no acknowledgement or no answer within ~1 s: another process mid-command, or a
        // slot 2 that isn't an HMAC challenge-response (static password, Yubico OTP) → no answer, both causes named.
        { new KeyboardConnectionException("The YubiKey did not acknowledge a write to the keyboard interface within the alloted time."), OtpFailure.NoAnswer },
        // KeyboardFrameReader.AddStatusReport at session open: the status report shows a command in progress → busy.
        { new MalformedYubiKeyResponseException("The status report must be the first and only report returned by the YubiKey."), OtpFailure.Busy },
        // KeyboardTransform.WaitFor: the touch wasn't given in time → passed through.
        { new KeyboardConnectionException("Timed out waiting for user interaction."), OtpFailure.Other },
        { new KeyboardConnectionException("Tried writing a keyboard report and unexpectedly recieved no reply."), OtpFailure.Other },
        // LinuxHidFeatureReportConnection: the hidraw node can't be opened (no udev rule) → not reachable.
        { new PlatformApiException("Could not open HID node on Linux."), OtpFailure.NotReachable },
        { new PlatformApiException("A HIDRAW operation failed."), OtpFailure.Other },
        // MacOSHidFeatureReportConnection: IOHIDDeviceOpen refused (Input Monitoring) → not reachable;
        // kIOReturnExclusiveAccess (another app holds the key) → busy.
        { new PlatformApiException("IOHIDDeviceOpen", unchecked((int)0xE00002E2), "Can't open IOKit device."), OtpFailure.NotReachable },
        { new PlatformApiException("IOHIDDeviceOpen", unchecked((int)0xE00002C5), "Can't open IOKit device."), OtpFailure.Busy },
        { new PlatformApiException("Can't open IOKit device."), OtpFailure.NotReachable },
        // HidDDevice.OpenHandleWithAccess (Windows): access denied → not reachable.
        { new UnauthorizedAccessException("Access is denied."), OtpFailure.NotReachable },
        // ConnectionFactory.CreateConnection: no interface the OTP application can use → not reachable.
        { new InvalidOperationException("No suitable interface present. Unable to establish connection to YubiKey."), OtpFailure.NotReachable },
        { new InvalidOperationException("YubiKey Operation Failed [Conditions of use not satisfied]"), OtpFailure.Other },
        { new MalformedYubiKeyResponseException("bad"), OtpFailure.Other },
    };

    [Theory]
    [MemberData(nameof(SdkExceptions))]
    public void Classify_MapsSdkExceptions(Exception sdkException, OtpFailure expected) =>
        Assert.Equal(expected, YubicoOtpKeys.Classify(sdkException));

    /// <summary>
    /// Final review item 4 (p1-I1): the probe's open failure is classified like a challenge's: macOS's exclusive-access
    /// refusal is a busy key, any other open failure an interface tswap can't open.
    /// </summary>
    public static TheoryData<Exception, string> ProbeOpenFailures => new()
    {
        { new PlatformApiException("IOHIDDeviceOpen", unchecked((int)0xE00002C5), "Can't open IOKit device."), nameof(KeyboardInterfaceState.Busy) },
        { new PlatformApiException("IOHIDDeviceOpen", unchecked((int)0xE00002E2), "Can't open IOKit device."), nameof(KeyboardInterfaceState.Unopenable) },
        { new PlatformApiException("Can't open IOKit device."), nameof(KeyboardInterfaceState.Unopenable) },
        { new PlatformApiException("Could not open HID node on Linux."), nameof(KeyboardInterfaceState.Unopenable) },
        { new UnauthorizedAccessException("Access is denied."), nameof(KeyboardInterfaceState.Unopenable) },
    };

    [Theory]
    [MemberData(nameof(ProbeOpenFailures))]
    public void ProbeStateFor_OpenFailure(Exception openFailure, string expected) =>
        Assert.Equal(expected, YubicoOtpKeys.ProbeStateFor(openFailure).ToString()); // the enum is internal

    // ── Task 4 review fix round, item 2: the failure's kind travels with its text ──

    [Fact]
    public void Challenge_KeyBusy_CarriesTheBusyKind()
    {
        var fake = new FakeOtpKeys().WithKey(33060005);
        fake.Busy.Add(33060005);
        var service = new SdkYubiKeyService(fake, OSPlatform.Linux);

        var e = Assert.Throws<YubiKeyDeviceException>(() => service.Challenge(33060005, "c"));

        Assert.Equal(OtpFailure.Busy, e.Kind);
        Assert.Equal(33060005, e.Serial);
        Assert.Equal("YubiKey 33060005 is busy (another tswap or app is using it); try again.", e.Message);
    }

    [Fact]
    public void Challenge_Slot2Empty_CarriesItsKind()
    {
        var fake = new FakeOtpKeys().WithKey(33060005);
        fake.Slot2Empty.Add(33060005);
        var service = new SdkYubiKeyService(fake, OSPlatform.Linux);

        var e = Assert.Throws<YubiKeyDeviceException>(() => service.Challenge(33060005, "c"));

        Assert.Equal(OtpFailure.Slot2Empty, e.Kind);
    }

    [Fact]
    public void Challenge_NotPluggedIn_CarriesItsKind()
    {
        var service = new SdkYubiKeyService(new FakeOtpKeys().WithKey(1), OSPlatform.Linux);

        var e = Assert.Throws<YubiKeyDeviceException>(() => service.Challenge(33060005, "c"));

        Assert.Equal(OtpFailure.NotPluggedIn, e.Kind);
        Assert.StartsWith("YubiKey 33060005 is not plugged in.", e.Message);
    }

    [Fact]
    public void Challenge_HiddenKey_ProbeSeesBusy_CarriesTheBusyKind()
    {
        var fake = new FakeOtpKeys().WithHiddenKey(33060005);
        fake.Interfaces.Add(KeyboardInterfaceState.Busy);
        var service = new SdkYubiKeyService(fake, OSPlatform.Linux);

        var e = Assert.Throws<YubiKeyDeviceException>(() => service.Challenge(33060005, "c"));

        Assert.Equal(OtpFailure.Busy, e.Kind);
    }

    [Fact]
    public void Challenge_HiddenKey_CarriesNotReachable()
    {
        var fake = new FakeOtpKeys().WithHiddenKey(33060005);
        fake.Interfaces.Add(KeyboardInterfaceState.Unopenable);
        var service = new SdkYubiKeyService(fake, OSPlatform.Linux);

        var e = Assert.Throws<YubiKeyDeviceException>(() => service.Challenge(33060005, "c"));

        Assert.Equal(OtpFailure.NotReachable, e.Kind);
    }

    // ── Slot2Settings (pure; task 4 pins the cited values) ─────────────────────

    [Fact]
    public void Slot2Settings_TouchFollowsTheFlag()
    {
        Assert.Equal(new Slot2Programming(HmacSha1: true, SmallChallenge: true, Touch: true, KeyLength: 20), YubicoOtpKeys.Slot2Settings(true));
        Assert.Equal(new Slot2Programming(HmacSha1: true, SmallChallenge: true, Touch: false, KeyLength: 20), YubicoOtpKeys.Slot2Settings(false));
    }

    // ── Fix round 1: a key that isn't keyboard-reachable is probed (read-only) ──

    private const string UncertainStart = "tswap can't reach YubiKey 33060005's OTP interface. If another tswap or app is using it, try again when it's done; otherwise: ";

    [Fact]
    public void ListSerials_HiddenKey_ProbeSeesBusyInterface_SaysBusy()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);
        keys.Interfaces.Add(KeyboardInterfaceState.Busy);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).ListSerials());

        Assert.Equal("YubiKey 33060005 is busy (another tswap or app is waiting for a touch); try again when it's done.", ex.Message);
    }

    /// <summary>Final review item 5: several hidden keys and a busy interface: each readable serial is named.</summary>
    [Fact]
    public void ListSerials_TwoHiddenKeys_ProbeSeesBusy_NamesEachSerial()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005).WithHiddenKey(33060006).WithHiddenKey(null);
        keys.Interfaces.Add(KeyboardInterfaceState.Busy);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).ListSerials());

        Assert.Equal("YubiKey 33060005 or YubiKey 33060006 is busy (another tswap or app is waiting for a touch); try again when it's done.", ex.Message);
    }

    /// <summary>Final review item 5: a hidden key without a readable serial keeps the generic sentence.</summary>
    [Fact]
    public void ListSerials_HiddenKeyWithoutSerial_ProbeSeesBusy_SaysAYubiKeyIsBusy()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(null);
        keys.Interfaces.Add(KeyboardInterfaceState.Busy);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).ListSerials());

        Assert.Equal("A YubiKey is busy (another tswap or app is waiting for a touch); try again when it's done.", ex.Message);
    }

    [Fact]
    public void ListSerials_HiddenKey_ProbeCantOpen_ExplainsPerOsOnly()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);
        keys.Interfaces.Add(KeyboardInterfaceState.Unopenable);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.OSX).ListSerials());

        Assert.StartsWith("YubiKey 33060005: macOS is blocking", ex.Message);
        Assert.DoesNotContain("try again", ex.Message);
    }

    [Fact]
    public void ListSerials_HiddenKey_NoKeyboardInterfaceListed_ExplainsPerOsOnly()
    {
        // Linux without the udev rule: the SDK can't read the node's vendor id, so no Yubico keyboard interface is listed.
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).ListSerials());

        Assert.StartsWith("YubiKey 33060005: its OTP interface can't be reached", ex.Message);
        Assert.DoesNotContain("try again", ex.Message);
    }

    [Theory]
    [InlineData(nameof(KeyboardInterfaceState.Idle))]
    [InlineData(nameof(KeyboardInterfaceState.Unreadable))]
    public void ListSerials_HiddenKey_ProbeInconclusive_PutsUncertaintyFirst(string state)
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);
        keys.Interfaces.Add(Enum.Parse<KeyboardInterfaceState>(state));

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).ListSerials());

        Assert.StartsWith(UncertainStart + "YubiKey 33060005: its OTP interface can't be reached", ex.Message);
        Assert.Contains("udev rule", ex.Message);
    }

    [Fact]
    public void ListSerials_HiddenKey_ProbeFails_PutsUncertaintyFirst()
    {
        var keys = new FakeOtpKeys { ProbeFails = true }.WithHiddenKey(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).ListSerials());

        Assert.StartsWith(UncertainStart, ex.Message);
    }

    [Fact]
    public void Challenge_KeyNotReachable_ProbeSeesBusyInterface_SaysBusy()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);
        keys.Interfaces.Add(KeyboardInterfaceState.Busy);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(33060005, "abc"));

        Assert.Equal("YubiKey 33060005 is busy (another tswap or app is waiting for a touch); try again when it's done.", ex.Message);
        Assert.Empty(keys.Challenges);
    }

    [Fact]
    public void Challenge_KeyNotReachable_ProbeInconclusive_PutsUncertaintyFirst()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(33060005);
        keys.Interfaces.Add(KeyboardInterfaceState.Idle);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.OSX).Challenge(33060005, "abc"));

        Assert.StartsWith(UncertainStart + "YubiKey 33060005: macOS is blocking", ex.Message);
    }

    [Fact]
    public void Challenge_KeyNotReachable_IdleInterfaceBelongsToAnotherKey_ExplainsPerOsOnly()
    {
        // One idle keyboard interface, and one keyboard-reachable key to own it: nothing unaccounted for.
        var keys = new FakeOtpKeys().WithKey(11111111).WithHiddenKey(33060005);
        keys.Interfaces.Add(KeyboardInterfaceState.Idle);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).Challenge(33060005, "abc"));

        Assert.StartsWith("YubiKey 33060005: its OTP interface can't be reached", ex.Message);
        Assert.DoesNotContain("try again", ex.Message);
    }

    [Fact]
    public void Challenge_SerialAbsent_HiddenSerialUnknown_ProbeSeesBusy_SaysBusy()
    {
        var keys = new FakeOtpKeys().WithHiddenKey(null);
        keys.Interfaces.Add(KeyboardInterfaceState.Busy);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(33060005, "abc"));

        Assert.Contains("YubiKey 33060005 is not plugged in", ex.Message);
        Assert.Contains("A YubiKey is busy (another tswap or app is waiting for a touch)", ex.Message);
    }

    [Fact]
    public void Challenge_SerialAbsent_ReachableKeyWithoutSerial_SaysSoToo()
    {
        var keys = new FakeOtpKeys().WithKey(null);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(33060005, "abc"));

        Assert.Contains("YubiKey 33060005 is not plugged in", ex.Message);
        Assert.Contains("A YubiKey whose serial can't be read is plugged in", ex.Message);
    }

    [Fact]
    public void Challenge_NoAnswer_NamesBothCauses()
    {
        var keys = new ThrowingOtpKeys(9, new OtpKeysException(OtpFailure.NoAnswer, 9, "The YubiKey did not acknowledge a write to the keyboard interface within the alloted time."));

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys).Challenge(9, "abc"));

        Assert.Contains("YubiKey 9 didn't answer", ex.Message);
        Assert.Contains("slot 2 may not be set up for HMAC challenge-response (run `tswap yubikey setup`)", ex.Message);
        Assert.Contains("another tswap or app is using it", ex.Message);
        Assert.DoesNotContain("is busy", ex.Message);
    }

    /// <summary>The keyboard interface's status byte (the report's last byte): touch 0x20, read 0x40, sequence 0x1F.</summary>
    [Theory]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0x00 }, false)]
    [InlineData(new byte[] { 5, 4, 3, 2, 1, 0, 0, 0x00 }, false)]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0x20 }, true)]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0x40 }, true)]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0x01 }, true)]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0x2A }, true)]
    public void StatusShowsBusy_ReadsTheLastByte(byte[] report, bool busy) =>
        Assert.Equal(busy, YubicoOtpKeys.StatusShowsBusy(report));

    [Fact]
    public void StatusShowsBusy_EmptyReport_IsNotBusy() => Assert.False(YubicoOtpKeys.StatusShowsBusy([]));

    [Fact]
    public void Simulated_HiddenKey_ChallengeExplainsHidden()
    {
        var sim = SimulatedYubiKeyService.WithKeys(33060005);
        sim.Hidden.Add(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => sim.Challenge(33060005, "abc"));

        Assert.Contains("YubiKey 33060005", ex.Message);
        Assert.Contains("OTP interface", ex.Message);
        Assert.Empty(sim.Challenges);
    }

    [Fact]
    public void Simulated_BusyKey_ChallengeSaysBusy()
    {
        var sim = SimulatedYubiKeyService.WithKeys(33060005);
        sim.Busy.Add(33060005);

        var ex = Assert.ThrowsAny<TswapException>(() => sim.Challenge(33060005, "abc"));

        Assert.Contains("33060005", ex.Message);
        Assert.Contains("busy", ex.Message);
    }

    [Fact]
    public void Challenge_KeyTurnsUnreachableAfterLookup_UsesTheProbe()
    {
        // Race: listed as reachable by the look-up, then the seam's own listing misses its keyboard interface (it
        // turned busy). The NotReachable from the seam goes through the probe like the look-up's own case.
        var keys = new ThrowingOtpKeys(33060005, new OtpKeysException(OtpFailure.NotReachable, 33060005, "found over HidFido only"),
            [KeyboardInterfaceState.Busy]);

        var ex = Assert.ThrowsAny<TswapException>(() => Service(keys, OSPlatform.Linux).Challenge(33060005, "abc"));

        Assert.Equal("YubiKey 33060005 is busy (another tswap or app is waiting for a touch); try again when it's done.", ex.Message);
    }

    /// <summary>One reachable key whose every operation fails with one exception.</summary>
    private sealed class ThrowingOtpKeys(int keySerial, OtpKeysException failure, IReadOnlyList<KeyboardInterfaceState>? interfaces = null) : IOtpKeys
    {
        public IReadOnlyList<OtpKeyInfo> Find() => [new OtpKeyInfo(keySerial, true, "HidKeyboard")];
        public OtpChallengeResult Challenge(int serial, ReadOnlySpan<byte> challenge64, Action onTouchRequested) => throw failure;
        public Slot2State Slot2(int serial) => throw failure;
        public void ProgramSlot2(int serial, bool requireTouch) => throw failure;
        public IReadOnlyList<KeyboardInterfaceState> ProbeKeyboardInterfaces() => interfaces ?? [];
    }
}
