using TswapCore;

namespace TswapCli;

/// <summary>
/// The hardware chip this machine can offer to <c>init</c>: <paramref name="Backend"/> is
/// <see cref="HardwareBackend.SecureEnclave"/> or <see cref="HardwareBackend.Tpm"/> when usable, else null.
/// <paramref name="UnavailableReason"/> is a one-line reason when the OS has such a chip but it can't be
/// used (e.g. a missing library), else null.
/// </summary>
public sealed record MachineChip(HardwareBackend? Backend, string? UnavailableReason);

/// <summary>Asks the OS which chip is usable, without creating or touching any key.</summary>
public static class ChipProbe
{
    public static MachineChip Detect()
    {
        try
        {
            if (OperatingSystem.IsMacOS())
                return FromSecureEnclaveProbe(ProbeSecureEnclave());
            if (OperatingSystem.IsLinux())
                return FromProbe(HardwareBackend.Tpm, ProbeLinuxTpm());
            if (OperatingSystem.IsWindows())
                return FromProbe(HardwareBackend.Tpm, ProbeWindowsTpm());
            return new MachineChip(null, null);
        }
        catch (Exception ex)
        {
            // A probe that throws (e.g. TswapException for a missing dylib) means "not usable", with its reason.
            return new MachineChip(null, ex.Message);
        }
    }

    /// <summary>A probe that can say why not: usable, or unavailable with its reason.</summary>
    internal static MachineChip FromProbe(HardwareBackend backend, (bool Available, string? Reason) probe)
        => probe.Available ? new MachineChip(backend, null) : new MachineChip(null, probe.Reason);

    internal const string SecureEnclaveUnavailableReason =
        "the Secure Enclave isn't available on this Mac (Intel Macs without a T2 chip have none)";

    /// <summary>The Secure Enclave's probe answers only yes or no, so a no gets the likely reason.</summary>
    internal static MachineChip FromSecureEnclaveProbe(bool available)
        => FromProbe(HardwareBackend.SecureEnclave, (available, available ? null : SecureEnclaveUnavailableReason));

    [System.Runtime.Versioning.SupportedOSPlatform("macos")]
    private static bool ProbeSecureEnclave() => HardwareServices.SecureEnclaveAvailable();

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static (bool Available, string? Reason) ProbeLinuxTpm() => HardwareServices.LinuxTpmProbe();

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (bool Available, string? Reason) ProbeWindowsTpm() => HardwareServices.WindowsTpmProbe();
}
