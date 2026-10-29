using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// The enrollment seam (issue #151, brief T2 decision 1, option (b)): a sibling
/// <see cref="IHardwareEnrollmentService"/> next to the pure unlock seam
/// <see cref="IHardwareKeyService"/>. The wrap/seal backends (Secure Enclave, Linux TPM,
/// Windows TPM) implement it; YubiKey deliberately does not, because it derives
/// <c>KEK_slot</c> from an interactive challenge rather than wrapping a generated one.
/// These checks are type-level only and need no hardware; the hardware-gated suites
/// (<c>Category=Tpm</c>, <c>TpmWindows</c>, <c>SecureEnclave</c>) prove Enroll then Unlock
/// round-trips on real devices.
/// </summary>
public class HardwareEnrollmentSeamTests
{
    [Theory]
    [InlineData(typeof(LinuxTpmHardwareService))]
    [InlineData(typeof(WindowsTpmHardwareService))]
    [InlineData(typeof(SecureEnclaveHardwareService))]
    public void WrapBackends_ImplementBothUnlockAndEnrollmentSeams(Type backend)
    {
        Assert.True(typeof(IHardwareEnrollmentService).IsAssignableFrom(backend),
            $"{backend.Name} must implement IHardwareEnrollmentService");
        Assert.True(typeof(IHardwareKeyService).IsAssignableFrom(backend),
            $"{backend.Name} must still implement IHardwareKeyService");
    }

    [Fact]
    public void YubiKey_DoesNotImplementEnrollmentSeam()
    {
        // Decision 1: YubiKey's KEK_slot stays derived in InitCommand and passed in; no console
        // I/O moves behind an interface.
        Assert.False(typeof(IHardwareEnrollmentService).IsAssignableFrom(typeof(YubiKeyHardwareService)));
    }

    [Fact]
    public void HardwareEnrollment_CarriesOnlyTheKekAndTheBackendBlob_NotAConfig()
    {
        // The backend returns its own field (the blob) and never builds a whole Config.
        var properties = typeof(HardwareEnrollment).GetProperties().Select(p => (p.Name, p.PropertyType)).ToList();

        Assert.Equal([("KekSlot", typeof(byte[])), ("HwBlob", typeof(byte[]))], properties);
        Assert.DoesNotContain(typeof(IHardwareEnrollmentService).GetMethods(), m => m.ReturnType == typeof(Config));
    }
}
