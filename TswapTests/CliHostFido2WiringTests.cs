using TswapCli;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
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

    /// <summary>
    /// Brief T19, item 3 (renamed from <c>Fido2_LinuxAndMacOS_IsYubicosSdk</c>: the wiring changed on purpose): Linux
    /// and macOS get <see cref="CompositeFido2Keys"/> (Yubico's SDK plus libfido2), and building it loads nothing;
    /// Windows is unchanged (<c>webauthn.dll</c>, keys can't be listed).
    /// </summary>
    [Fact]
    public void Fido2_LinuxAndMacOS_IsTheCompositeAndLoadsNothing()
    {
        var loads = 0;
        var keys = CliHost.Fido2Keys(testKey: null, loadOther: () =>
        {
            loads++;
            return new Libfido2LoadResult(Libfido2Status.NotInstalled, null);
        });
        var service = CliHost.Fido2Service(testKey: null);

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            Assert.IsType<CompositeFido2Keys>(keys);
            Assert.Equal(0, loads);
            Assert.NotNull(service);
            Assert.True(service.CanList);
            Assert.Equal(0, loads);
        }
        else if (OperatingSystem.IsWindows())
        {
            Assert.IsType<WebAuthnFido2Keys>(keys);
            Assert.NotNull(service);
            Assert.False(service.CanList);
        }
        else
        {
            Assert.Null(keys);
            Assert.Null(service);
        }
    }

    [Fact]
    public void Fido2Keys_TestMode_IsNone() => Assert.Null(CliHost.Fido2Keys(testKey: new byte[32]));

#if DEBUG
    /// <summary>
    /// Brief T19, owner check C5: a Debug build with <c>TSWAP_TEST_LIBFIDO2_ABSENT=1</c> plays "libfido2 isn't installed"
    /// (the loader is never called), so the owner can see the "needs libfido2" texts with a Token2 plugged in.
    /// </summary>
    [Fact]
    public void Libfido2Absent_TestSwitch_PlaysNotInstalled()
    {
        var absent = CliHost.Libfido2ForTests(name => name == "TSWAP_TEST_LIBFIDO2_ABSENT" ? "1" : null);

        Assert.NotNull(absent);
        Assert.Equal(new Libfido2LoadResult(Libfido2Status.NotInstalled, null), absent());
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            Assert.Equal(Libfido2Status.NotInstalled, CliHost.Fido2Keys(testKey: null, loadOther: absent)!.OtherBrands);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0")]
    [InlineData("yes")]
    public void Libfido2Absent_TestSwitch_OffUnlessExactlyOne(string? value) =>
        Assert.Null(CliHost.Libfido2ForTests(name => name == "TSWAP_TEST_LIBFIDO2_ABSENT" ? value : null));
#endif
}
