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
    public void Detect_OnLinux_NeverOffersASecureEnclave()
    {
        if (!OperatingSystem.IsLinux()) return;
        Assert.NotEqual(HardwareBackend.SecureEnclave, ChipProbe.Detect().Backend);
    }
}
