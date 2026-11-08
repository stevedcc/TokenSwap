using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 1: <see cref="PcscStrategy.Describe"/> reads the PC/SC loader's strategy only in a
/// published (NativeAOT) Linux build, where <c>tswap_pcsc</c> is linked in. The JIT test host has no such library, so
/// it must answer without calling the import (a call would throw <see cref="DllNotFoundException"/>). The published
/// answers ("system library", "stand-in") are checked by <c>package.sh --smoke</c> from task 4 on.
/// </summary>
public sealed class PcscStrategyTests
{
    [Fact]
    public void Describe_InTheTestHost_NeverCallsTheLoader()
    {
        var expected = OperatingSystem.IsLinux() ? "unknown (not a published build)" : "not used";

        Assert.Equal(expected, PcscStrategy.Describe());
    }
}
