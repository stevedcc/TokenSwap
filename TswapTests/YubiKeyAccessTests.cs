using System.Runtime.InteropServices;
using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>Guided init, task 2: explaining a YubiKey whose OTP interface the OS blocks.</summary>
public class YubiKeyAccessTests
{
    [Fact]
    public void ExplainBlocked_OnMacOS_NamesInputMonitoring() =>
        Assert.Contains("Input Monitoring", YubiKeyAccess.ExplainBlocked("ykman failed: WARNING: Failed opening device\nERROR: " + YubiKeyAccess.OtpBlockedLine, 33060005, OSPlatform.OSX));

    [Fact]
    public void ExplainBlocked_OnLinux_NamesTheUdevRule() =>
        Assert.Contains("udev rule", YubiKeyAccess.ExplainBlocked("ERROR: " + YubiKeyAccess.OtpBlockedLine, 1, OSPlatform.Linux));

    [Fact]
    public void ExplainBlocked_OtherErrors_AreNotExplained() =>
        Assert.Null(YubiKeyAccess.ExplainBlocked("ykman failed: device 1 not found", 1, OSPlatform.OSX));
}
