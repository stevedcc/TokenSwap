using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Yubico.PlatformInterop;
using Yubico.YubiKey;
using Yubico.YubiKey.Otp;

namespace TswapCore.Vault;

/// <summary>
/// What <see cref="YubicoOtpKeys.ProgramSlot2WithKey"/> sends for slot 2: HMAC-SHA1 challenge-response with
/// HMAC_LT64 on (<c>UseSmallChallenge</c>), touch per flag (<c>UseButton</c>), a 20-byte key: the settings of
/// <c>ykman otp chalresp</c> (yubikey-manager 5.9.2, <c>yubikit/yubiotp.py</c> <c>HmacSha1SlotConfiguration</c>).
/// </summary>
internal sealed record Slot2Programming(bool HmacSha1, bool SmallChallenge, bool Touch, int KeyLength);

/// <summary>
/// The real <see cref="IOtpKeys"/>: Yubico's .NET SDK (<c>Yubico.YubiKey</c> 1.18.1). Calls
/// <see cref="YubicoSdk.EnsureInitialized"/> before any SDK call. A key is used only over the keyboard interface: the
/// SDK would otherwise fall back to the smart-card interface, where a USB key refuses HMAC challenge-response
/// (spike: "Conditions of use not satisfied"). The SDK's exceptions become <see cref="OtpKeysException"/>s through
/// <see cref="Classify"/>; slot 2's state comes from the OTP status the session reads when it opens.
/// </summary>
internal sealed class YubicoOtpKeys : IOtpKeys
{
    /// <summary>The verify challenge after programming: a short string, zero-padded to 64 bytes like tswap's own.</summary>
    private static ReadOnlySpan<byte> VerifyChallenge => "tswap yubikey setup verify v1"u8;

    public IReadOnlyList<OtpKeyInfo> Find()
    {
        YubicoSdk.EnsureInitialized();
        try
        {
            return YubiKeyDevice.FindAll()
                .Select(d => new OtpKeyInfo(d.SerialNumber, d.AvailableTransports.HasFlag(Transport.HidKeyboard), d.AvailableTransports.ToString()))
                .ToList();
        }
        catch (Exception e)
        {
            throw new OtpKeysException(Classify(e), null, e.Message);
        }
    }

    public OtpChallengeResult Challenge(int serial, ReadOnlySpan<byte> challenge64, Action onTouchRequested)
    {
        if (challenge64.Length != 64)
            throw new ArgumentException("The challenge frame is 64 bytes", nameof(challenge64));
        var frame = challenge64.ToArray();
        try
        {
            using var otp = OpenSlot2(serial);
            return Calculate(otp, frame, onTouchRequested);
        }
        catch (Exception e) when (e is not OtpKeysException)
        {
            throw new OtpKeysException(Classify(e), serial, e.Message);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
        }
    }

    /// <summary>
    /// <c>OtpSession.IsLongPressConfigured</c>: the status bit "configuration 2 is valid" (SDK
    /// <c>ReadStatusResponse</c>, <c>LongPressValidMask</c> 0x02; yubikey-manager <c>CFGSTATE.SLOT2_VALID</c>), set for
    /// any configuration (challenge-response, OTP, static password), so <see cref="Slot2State.Empty"/> means empty.
    /// </summary>
    public Slot2State Slot2(int serial)
    {
        try
        {
            using var otp = new OtpSession(KeyboardDevice(serial));
            return otp.IsLongPressConfigured ? Slot2State.Configured : Slot2State.Empty;
        }
        catch (Exception e) when (e is not OtpKeysException)
        {
            throw new OtpKeysException(Classify(e), serial, e.Message);
        }
    }

    /// <summary>The slot secret is drawn here (host RNG), handed to <see cref="ProgramSlot2WithKey"/>, and zeroed here.</summary>
    public void ProgramSlot2(int serial, bool requireTouch)
    {
        var key = new byte[Slot2Settings(requireTouch).KeyLength];
        try
        {
            RandomNumberGenerator.Fill(key);
            ProgramSlot2WithKey(serial, key, requireTouch);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Programs slot 2 with <paramref name="key20"/> per <see cref="Slot2Settings"/>, then proves it: a verify
    /// challenge must answer <see cref="Slot2Verify.ExpectedResponse"/> (compared in constant time) and ask for a touch
    /// exactly when <paramref name="requireTouch"/>. Never zeroes <paramref name="key20"/> (the caller owns it); zeroes
    /// the buffers it allocates. Failures before anything is written keep their own kind; then
    /// <see cref="OtpFailure.ProgramFailed"/>, <see cref="OtpFailure.VerifyNoAnswer"/>, <see cref="OtpFailure.VerifyWrong"/>.
    /// </summary>
    internal void ProgramSlot2WithKey(int serial, byte[] key20, bool requireTouch)
    {
        var settings = Slot2Settings(requireTouch);
        if (key20.Length != settings.KeyLength)
            throw new ArgumentException($"The slot key is {settings.KeyLength} bytes", nameof(key20));
        if (!settings.HmacSha1)
            throw new InvalidOperationException("tswap programs slot 2 for HMAC-SHA1 only");

        OtpSession otp;
        try
        {
            otp = new OtpSession(KeyboardDevice(serial));
        }
        catch (Exception e) when (e is not OtpKeysException)
        {
            throw new OtpKeysException(Classify(e), serial, e.Message);
        }

        using (otp)
        {
            try
            {
                otp.ConfigureChallengeResponse(Slot.LongPress)
                    .UseHmacSha1()
                    .UseKey(key20)
                    .UseSmallChallenge(settings.SmallChallenge)
                    .UseButton(settings.Touch)
                    .Execute();
            }
            catch (Exception e)
            {
                throw new OtpKeysException(OtpFailure.ProgramFailed, serial, e.Message);
            }

            var frame = new byte[64];
            VerifyChallenge.CopyTo(frame);
            byte[]? expected = null;
            byte[]? response = null;
            try
            {
                expected = Slot2Verify.ExpectedResponse(key20, frame);
                using var touchSeen = new ManualResetEventSlim();
                OtpChallengeResult result;
                try
                {
                    result = Calculate(otp, frame, touchSeen.Set);
                }
                catch (Exception e)
                {
                    throw new OtpKeysException(OtpFailure.VerifyNoAnswer, serial, e.Message);
                }
                response = result.Response;
                if (!CryptographicOperations.FixedTimeEquals(response, expected))
                    throw new OtpKeysException(OtpFailure.VerifyWrong, serial, "the answer differs from the programmed key's");
                // The SDK reports the touch on a thread-pool task (CalculateChallengeResponse: Task.Run(_touchNotify)),
                // which can still be queued when the answer arrives: wait for it before calling the touch setting wrong.
                var touched = result.TouchRequested || (requireTouch && touchSeen.Wait(TouchReportGrace));
                if (touched != requireTouch)
                    throw new OtpKeysException(OtpFailure.VerifyWrong, serial,
                        requireTouch ? "it answered without asking for a touch" : "it asked for a touch that wasn't asked for");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(frame);
                if (expected is not null)
                    CryptographicOperations.ZeroMemory(expected);
                if (response is not null)
                    CryptographicOperations.ZeroMemory(response);
            }
        }
    }

    private static readonly TimeSpan TouchReportGrace = TimeSpan.FromSeconds(2);

    /// <summary>
    /// The settings <see cref="ProgramSlot2WithKey"/> follows. Each maps to one SDK call:
    /// <c>UseHmacSha1</c> (CHAL_HMAC + CHAL_RESP), <c>UseSmallChallenge</c> (HMAC_LT64), <c>UseButton</c>
    /// (CHAL_BTN_TRIG), <c>UseKey</c> (20 bytes). The SDK's operations also set SERIAL_API_VISIBLE and ALLOW_UPDATE by
    /// default (<c>OperationBase</c>), as ykman's <c>SlotConfiguration</c> does.
    /// </summary>
    internal static Slot2Programming Slot2Settings(bool requireTouch) =>
        new(HmacSha1: true, SmallChallenge: true, Touch: requireTouch, KeyLength: ConfigureChallengeResponseKeySize);

    private const int ConfigureChallengeResponseKeySize = Yubico.YubiKey.Otp.Operations.ConfigureChallengeResponse.HmacSha1KeySize;

    // The SDK's messages (Yubico.NET.SDK 1.18.1, Resources/ExceptionMessages.resx of each assembly). The SDK ships no
    // satellite resource assemblies, so these are the texts it throws on every system.
    private const string KeyboardTimeoutMessage = "The YubiKey did not acknowledge a write to the keyboard interface within the alloted time.";
    private const string LinuxHidOpenFailedMessage = "Could not open HID node on Linux.";
    private const string IOKitCannotOpenDeviceMessage = "Can't open IOKit device.";
    private const string NoSuitableInterfaceMessage = "No suitable interface present. Unable to establish connection to YubiKey.";

    /// <summary>kIOReturnExclusiveAccess, as <c>PlatformApiException</c> prints the code of a failed IOHIDDeviceOpen.</summary>
    private const string MacExclusiveAccess = "IOHIDDeviceOpen = 0xE00002C5.";

    /// <summary>
    /// The SDK's exceptions as <see cref="OtpFailure"/>s (the table with the SDK source lines is in the stage 1 task 2
    /// report). Anything unmapped is <see cref="OtpFailure.Other"/>, its message passed through.
    /// </summary>
    internal static OtpFailure Classify(Exception e) => e switch
    {
        // KeyboardTransform.WaitFor: the key didn't take the command within ~1 s (busy with another process's
        // command, such as a challenge waiting for its touch). ykman's equivalent: "Timeout waiting for YubiKey to
        // become ready to receive".
        KeyboardConnectionException { Message: KeyboardTimeoutMessage } => OtpFailure.Busy,
        PlatformApiException p when p.Message.Contains(IOKitCannotOpenDeviceMessage, StringComparison.Ordinal)
            && p.Message.Contains(MacExclusiveAccess, StringComparison.Ordinal) => OtpFailure.Busy,
        PlatformApiException { Message: LinuxHidOpenFailedMessage } => OtpFailure.NotReachable,
        PlatformApiException p when p.Message.Contains(IOKitCannotOpenDeviceMessage, StringComparison.Ordinal) => OtpFailure.NotReachable,
        UnauthorizedAccessException => OtpFailure.NotReachable,
        InvalidOperationException { Message: NoSuitableInterfaceMessage } => OtpFailure.NotReachable,
        _ => OtpFailure.Other,
    };

    /// <summary>The key with this serial, refused unless the SDK sees it over the keyboard interface.</summary>
    private static IYubiKeyDevice KeyboardDevice(int serial)
    {
        YubicoSdk.EnsureInitialized();
        var device = YubiKeyDevice.FindAll().FirstOrDefault(d => d.SerialNumber == serial)
            ?? throw new OtpKeysException(OtpFailure.Other, serial, "it is not plugged in");
        if (!device.AvailableTransports.HasFlag(Transport.HidKeyboard))
            throw new OtpKeysException(OtpFailure.NotReachable, serial, $"found over {device.AvailableTransports} only");
        return device;
    }

    /// <summary>An OTP session on the key whose slot 2 holds a configuration; <see cref="OtpFailure.Slot2Empty"/> otherwise.</summary>
    private static OtpSession OpenSlot2(int serial)
    {
        var otp = new OtpSession(KeyboardDevice(serial));
        if (otp.IsLongPressConfigured)
            return otp;
        otp.Dispose();
        throw new OtpKeysException(OtpFailure.Slot2Empty, serial, "slot 2 is empty");
    }

    /// <summary>
    /// HMAC-SHA1 on slot 2 (<c>UseYubiOtp(false)</c>) with the 64-byte frame as it is. The response is copied out and
    /// the SDK's own buffer cleared.
    /// </summary>
    private static OtpChallengeResult Calculate(OtpSession otp, byte[] frame, Action onTouchRequested)
    {
        var touched = 0;
        var data = otp.CalculateChallengeResponse(Slot.LongPress)
            .UseYubiOtp(false)
            .UseChallenge(frame)
            .UseTouchNotifier(() =>
            {
                Volatile.Write(ref touched, 1);
                onTouchRequested();
            })
            .GetDataBytes();
        var response = data.ToArray();
        MemoryMarshal.AsMemory(data).Span.Clear();
        return new OtpChallengeResult(response, Volatile.Read(ref touched) == 1);
    }
}
