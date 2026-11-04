using System.Diagnostics;
using System.Text;
using Yubico.YubiKey.Otp;

namespace YkSpike;

/// <summary>Read-only OTP checks: slot 2's state and one HMAC-SHA1 challenge-response. Never configures a slot.</summary>
public static class Otp
{
    /// <summary>The spike's own challenge: UTF-8 of this text, zero-padded to 64 bytes (never tswap's).</summary>
    public const string ChallengeText = "tswap-yk-spike-challenge-v1";

    public static byte[] ChallengeBytes()
    {
        var bytes = new byte[64];
        Encoding.UTF8.GetBytes(ChallengeText).CopyTo(bytes, 0);
        return bytes;
    }

    public static void Status(int? serial)
    {
        var device = Devices.Pick(serial);
        using var otp = new OtpSession(device);
        Report.Line("slot2_configured", otp.IsLongPressConfigured);
        Report.Line("slot1_configured", otp.IsShortPressConfigured);
        Report.Line("slot2_touch", "unknown (the SDK exposes no touch flag for a configured slot)");
    }

    public static void Challenge(int? serial)
    {
        var device = Devices.Pick(serial);
        Report.Line("challenge_hex", Convert.ToHexStringLower(ChallengeBytes()));
        // Which transport the SDK picks for OTP (KeyboardConnection = HID keyboard, SmartCardConnection = CCID).
        using (var probe = device.Connect(Yubico.YubiKey.YubiKeyApplication.Otp))
            Report.Line("otp_connection", probe.GetType().Name);
        var touched = false;
        var watch = Stopwatch.StartNew();
        using var otp = new OtpSession(device);
        var response = otp.CalculateChallengeResponse(Slot.LongPress)
            .UseYubiOtp(false)
            .UseChallenge(ChallengeBytes())
            .UseTouchNotifier(() =>
            {
                touched = true;
                Console.Error.WriteLine("(touch your YubiKey)");
            })
            .GetDataBytes();
        Report.Line("touch_notified", touched);
        Report.Line("ms", watch.ElapsedMilliseconds);
        Report.Line("response_bytes", response.Length);
        Report.Line("response_h", Report.Hash16(response.Span));
    }
}
