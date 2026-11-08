using System.Runtime.InteropServices;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>Guided init, task 2 (re-pointed at <see cref="YubiKeyAccessTexts"/>, stage 1 task 3): explaining a YubiKey whose OTP interface the OS blocks.</summary>
public class YubiKeyAccessTests
{
    [Fact]
    public void ExplainHidden_OnMacOS_NamesInputMonitoring() =>
        Assert.Contains("Input Monitoring", YubiKeyAccessTexts.ExplainHidden(33060005, OSPlatform.OSX));

    [Fact]
    public void ExplainHidden_OnLinux_NamesTheUdevRule() =>
        Assert.Contains("udev rule", YubiKeyAccessTexts.ExplainHidden(1, OSPlatform.Linux));

    [Fact]
    public void ExplainHidden_NamesTheKey() =>
        Assert.StartsWith("YubiKey 1:", YubiKeyAccessTexts.ExplainHidden(1, OSPlatform.Windows));
}
