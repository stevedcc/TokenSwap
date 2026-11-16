using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// The enrolment seam (issue #151, brief T2 decision 1, option (b)): a sibling
/// <see cref="IHardwareEnrolmentService"/> next to the pure unlock seam
/// <see cref="IHardwareKeyService"/>. The wrap/seal backends (Secure Enclave, Linux TPM,
/// Windows TPM) implement it; YubiKey deliberately does not, because it derives
/// <c>KEK_slot</c> from an interactive challenge rather than wrapping a generated one.
/// These checks are type-level only and need no hardware; the hardware-gated suites
/// (<c>Category=Tpm</c>, <c>TpmWindows</c>, <c>SecureEnclave</c>) prove Enrol then Unlock
/// round-trips on real devices.
/// </summary>
public class HardwareEnrolmentSeamTests
{
    [Theory]
    [InlineData(typeof(LinuxTpmHardwareService))]
    [InlineData(typeof(WindowsTpmHardwareService))]
    [InlineData(typeof(SecureEnclaveHardwareService))]
    public void WrapBackends_ImplementBothUnlockAndEnrolmentSeams(Type backend)
    {
        Assert.True(typeof(IHardwareEnrolmentService).IsAssignableFrom(backend),
            $"{backend.Name} must implement IHardwareEnrolmentService");
        Assert.True(typeof(IHardwareKeyService).IsAssignableFrom(backend),
            $"{backend.Name} must still implement IHardwareKeyService");
    }

    [Fact]
    public void YubiKey_DoesNotImplementEnrolmentSeam()
    {
        // Decision 1: YubiKey's KEK_slot stays derived in InitCommand and passed in; no console
        // I/O moves behind an interface.
        Assert.False(typeof(IHardwareEnrolmentService).IsAssignableFrom(typeof(YubiKeyHardwareService)));
    }

    [Fact]
    public void YubiKeyService_RefusesAPasswordItCantUse()
    {
        // Review T17 p1 MiMo M9: a legacy pair slot or classic vault never has the vault password; a route
        // that hands this service one is a bug, and must fail loudly instead of unlocking without it.
        var service = new YubiKeyHardwareService(SimulatedYubiKeyService.WithKeys(), overrideKey: new byte[32]);

        Assert.Throws<ArgumentException>(() => service.Unlock(new Config([], "", TestTime.Fixed), serials => serials[0],
            () => throw new InvalidOperationException("never called")));
        Assert.Equal(new byte[32], service.Unlock(new Config([], "", TestTime.Fixed), serials => serials[0], password: null));
    }

    [Fact]
    public void HardwareEnrolment_CarriesOnlyTheKekAndTheBackendBlob_NotAConfig()
    {
        // The backend returns its own field (the blob) and never builds a whole Config.
        var properties = typeof(HardwareEnrolment).GetProperties().Select(p => (p.Name, p.PropertyType)).ToList();

        Assert.Equal([("KekSlot", typeof(byte[])), ("HwBlob", typeof(byte[]))], properties);
        Assert.DoesNotContain(typeof(IHardwareEnrolmentService).GetMethods(), m => m.ReturnType == typeof(Config));
    }
}
