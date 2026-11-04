using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>Guided init, task 1: which chip this machine can offer to <c>init</c>.</summary>
public class ChipProbeTests
{
    [Fact]
    public void FleetMachine_WithASecureEnclave_OffersIt()
    {
        using var m = new FleetMachine("chip") { SecureEnclave = RandomNumberGenerator.GetBytes(32) };
        Assert.Equal(new MachineChip(HardwareBackend.SecureEnclave, null), m.Context(new FakeConsole(""), ["init"]).ChipProbe());
    }

    [Fact]
    public void FleetMachine_WithATpm_OffersIt()
    {
        using var m = new FleetMachine("chip") { Tpm = RandomNumberGenerator.GetBytes(32) };
        Assert.Equal(new MachineChip(HardwareBackend.Tpm, null), m.Context(new FakeConsole(""), ["init"]).ChipProbe());
    }

    [Fact]
    public void FleetMachine_WithNoChip_OffersNone()
    {
        using var m = new FleetMachine("chip");
        Assert.Equal(new MachineChip(null, null), m.Context(new FakeConsole(""), ["init"]).ChipProbe());
    }

    [Fact]
    public void LinuxTpmProbe_ReportsWhyNot()
    {
        Assert.Equal((true, (string?)null), TswapCore.Vault.Interop.Tpm2ToolsInterop.ProbeOutcome(0, ""));
        Assert.Equal((false, (string?)"no TPM found or no access to it (tpm2_getcap failed: ERROR:tcti:src/tss2-tcti/tcti-device.c:452:Tss2_Tcti_Device_Init() Failed to open device file /dev/tpmrm0: Permission denied)"),
            TswapCore.Vault.Interop.Tpm2ToolsInterop.ProbeOutcome(1,
                "\nERROR:tcti:src/tss2-tcti/tcti-device.c:452:Tss2_Tcti_Device_Init() Failed to open device file /dev/tpmrm0: Permission denied\nERROR: Could not load tcti, got: \"device\"\n"));
        Assert.Equal((false, (string?)"no TPM found or no access to it (tpm2_getcap failed with exit code 2)"),
            TswapCore.Vault.Interop.Tpm2ToolsInterop.ProbeOutcome(2, "  \n"));
        Assert.Equal((false, (string?)"tpm2-tools is not installed"),
            TswapCore.Vault.Interop.Tpm2ToolsInterop.ProbeOutcome(new TswapException("tpm2-tools is not installed")));
    }

    [Fact]
    public void ChipProbe_CarriesTheProbesReason()
    {
        Assert.Equal(new MachineChip(HardwareBackend.Tpm, null), ChipProbe.FromProbe(HardwareBackend.Tpm, (true, null)));
        Assert.Equal(new MachineChip(null, "no access"), ChipProbe.FromProbe(HardwareBackend.Tpm, (false, "no access")));
    }

    [Fact]
    public void Detect_OnLinux_NeverOffersASecureEnclave()
    {
        if (!OperatingSystem.IsLinux()) return;
        Assert.NotEqual(HardwareBackend.SecureEnclave, ChipProbe.Detect().Backend);
    }
}
