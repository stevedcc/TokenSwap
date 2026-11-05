using System.Runtime.InteropServices;

namespace TswapCore.Vault;

/// <summary>
/// What tswap says about a YubiKey whose OTP interface the operating system hides or refuses (the key is seen over
/// FIDO or smart card only). Moved here from <c>TswapCli/YubiKeyAccess.cs</c> (stage 1 task 3 deletes that copy and
/// its ykman-text trigger) and extended with the spike's findings: on Linux, no smart-card fallback for this slot type.
/// </summary>
internal static class YubiKeyAccessTexts
{
    /// <summary>"YubiKey N", or "A YubiKey" for a key whose serial can't be read.</summary>
    public static string Name(int? serial) => serial is { } s ? $"YubiKey {s}" : "A YubiKey";

    /// <summary>The per-OS explanation for a key whose OTP interface can't be reached.</summary>
    public static string ExplainHidden(int? serial, OSPlatform os)
    {
        var name = Name(serial);
        if (os == OSPlatform.OSX)
            return $"{name}: macOS is blocking access to this key's OTP interface (Input Monitoring for the app running tswap). Use the Secure Enclave or another key, or allow it in System Settings → Privacy & Security → Input Monitoring.";
        if (os == OSPlatform.Linux)
            return $"{name}: its OTP interface can't be reached. It needs the YubiKey udev rule (often installed by the ykpers or yubikey-personalization package, which needs an administrator), and there is no smart-card fallback for this slot type. Without the rule, use a TPM slot or another machine.";
        return $"{name}: its OTP interface can't be reached.";
    }

    /// <summary>The OS tswap runs on, for <see cref="ExplainHidden"/> (any other OS gets the generic wording).</summary>
    public static OSPlatform CurrentOs() =>
        OperatingSystem.IsMacOS() ? OSPlatform.OSX
        : OperatingSystem.IsLinux() ? OSPlatform.Linux
        : OperatingSystem.IsWindows() ? OSPlatform.Windows
        : OSPlatform.Create("OTHER");
}
