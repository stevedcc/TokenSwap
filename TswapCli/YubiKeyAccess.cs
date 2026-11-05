using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>
/// Explains a YubiKey whose OTP interface the operating system blocks. On macOS ykman fails
/// with <see cref="OtpBlockedLine"/> until the terminal has Input Monitoring.
/// </summary>
public static class YubiKeyAccess
{
    public const string OtpBlockedLine = "The connection type required for this command is not supported/enabled on the YubiKey.";

    /// <summary>The explanation for a blocked OTP interface, or null when the error is something else.</summary>
    public static string? ExplainBlocked(string errorMessage, int serial, OSPlatform os)
    {
        if (!errorMessage.Contains(OtpBlockedLine, StringComparison.Ordinal))
            return null;
        if (os == OSPlatform.OSX)
            return $"YubiKey {serial}: macOS is blocking access to this key's OTP interface (Input Monitoring for the app running tswap). Use the Secure Enclave or another key, or allow it in System Settings → Privacy & Security → Input Monitoring.";
        if (os == OSPlatform.Linux)
            return $"YubiKey {serial}: its OTP interface can't be reached (check that the YubiKey udev rule gives you access to its hidraw device).";
        return $"YubiKey {serial}: its OTP interface can't be reached.";
    }
}
