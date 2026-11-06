using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, tasks 4 and 5: the composition root's FIDO2 service. Yubico's SDK on Linux and macOS, <c>webauthn.dll</c>
/// on Windows (keys can't be listed there); none in test mode (<c>TSWAP_TEST_KEY</c>: a test sets
/// <see cref="CommandContext.Fido2"/> itself). Constructing it touches no key and calls nothing in <c>webauthn.dll</c>.
/// </summary>
public class CliHostFido2WiringTests
{
    [Fact]
    public void Fido2_TestMode_IsNone() =>
        Assert.Null(CliHost.Fido2Service(testKey: new byte[32]));

    [Fact]
    public void Fido2_LinuxAndMacOS_IsYubicosSdk()
    {
        var service = CliHost.Fido2Service(testKey: null);

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            Assert.NotNull(service);
            Assert.True(service.CanList);
        }
        else if (OperatingSystem.IsWindows())
        {
            Assert.NotNull(service);
            Assert.False(service.CanList);
        }
        else
        {
            Assert.Null(service);
        }
    }
}
