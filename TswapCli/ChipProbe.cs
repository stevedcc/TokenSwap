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
                return Probe(HardwareBackend.SecureEnclave, ProbeSecureEnclave);
            if (OperatingSystem.IsLinux())
                return Probe(HardwareBackend.Tpm, ProbeLinuxTpm);
            if (OperatingSystem.IsWindows())
                return Probe(HardwareBackend.Tpm, ProbeWindowsTpm);
            return new MachineChip(null, null);
        }
        catch (Exception ex)
        {
            // A probe that throws (e.g. TswapException for a missing dylib) means "not usable", with its reason.
            return new MachineChip(null, ex.Message);
        }
    }

    private static MachineChip Probe(HardwareBackend backend, Func<bool> isAvailable)
        => isAvailable() ? new MachineChip(backend, null) : new MachineChip(null, null);

    [System.Runtime.Versioning.SupportedOSPlatform("macos")]
    private static bool ProbeSecureEnclave() => HardwareServices.SecureEnclaveAvailable();

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static bool ProbeLinuxTpm() => HardwareServices.LinuxTpmAvailable();

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool ProbeWindowsTpm() => HardwareServices.WindowsTpmAvailable();
}
