using TswapCli;
using TswapCore;
using Xunit;

namespace TswapTests;

public class SecurityWarningsTests
{
    [Fact]
    public void WarnIfNoTouch_YubiKeyWithoutTouch_Warns()
    {
        var console = new FakeConsole();
        var config = new Config([1, 2], "aabb", DateTime.UtcNow, RequiresTouch: false);

        SecurityWarnings.WarnIfNoTouch(console, config);

        Assert.Contains("YubiKey", console.ErrorText);
    }

    [Fact]
    public void WarnIfNoTouch_NonYubiKeyBackend_NeverWarns()
    {
        // TPM/Secure Enclave vaults have no YubiKeys at all; the YubiKey-specific wording
        // ("your YubiKeys", "tswap migrate") would be actively misleading for them, and
        // each backend already prints its own presence caveats at init time.
        var console = new FakeConsole();
        var tpmConfig = new Config([], "", DateTime.UtcNow, RequiresTouch: false, Backend: HardwareBackend.Tpm);

        SecurityWarnings.WarnIfNoTouch(console, tpmConfig);

        Assert.Equal("", console.ErrorText);
    }
}
