using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// The simulated wrap/unwrap hardware backend (issue #153): it lets the TPM and Secure Enclave
/// enrollment and keyring paths run in CI without hardware. It proves plumbing only (dispatch,
/// config shape, round trips, error paths), never the hardware root-of-trust property; the
/// trait-gated hardware suites stay as they are.
/// </summary>
public class SimulatedHardwareServiceTests
{
    private static readonly byte[] MachineA =
        Convert.FromHexString("A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");
    private static readonly byte[] MachineB =
        Convert.FromHexString("B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2");

    private static int NoSelection(IReadOnlyList<int> serials)
        => throw new InvalidOperationException("chooseSerial must not be called for a single-device backend");

    private static Config SingleSlotConfig(HardwareBackend backend, byte[] blob) => backend switch
    {
        HardwareBackend.Tpm => new Config([], "", DateTime.UtcNow, Backend: backend, TpmSealedKey: Convert.ToBase64String(blob)),
        HardwareBackend.SecureEnclave => new Config([], "", DateTime.UtcNow, Backend: backend, SecureEnclaveWrappedKey: Convert.ToBase64String(blob)),
        _ => throw new ArgumentOutOfRangeException(nameof(backend)),
    };

    [Theory]
    [InlineData(HardwareBackend.Tpm)]
    [InlineData(HardwareBackend.SecureEnclave)]
    public void EnrollThenUnlock_OnTheSameMachine_RecoversTheSameKek(HardwareBackend backend)
    {
        var machine = new SimulatedHardwareService(backend, MachineA);

        var (kekSlot, hwBlob) = machine.Enroll();
        var recovered = machine.Unlock(SingleSlotConfig(backend, hwBlob), NoSelection);

        Assert.Equal(32, kekSlot.Length);
        Assert.Equal(kekSlot, recovered);
        Assert.NotEqual(kekSlot, hwBlob);
    }

    [Fact]
    public void Enroll_TwiceGivesIndependentKeys()
    {
        var machine = new SimulatedHardwareService(HardwareBackend.Tpm, MachineA);

        Assert.NotEqual(machine.Enroll().KekSlot, machine.Enroll().KekSlot);
    }

    [Theory]
    [InlineData(HardwareBackend.Tpm, "tpm")]
    [InlineData(HardwareBackend.SecureEnclave, "secure-enclave")]
    public void BlobFromAnotherMachine_FailsWithTheBackendsNormalError(HardwareBackend backend, string name)
    {
        var (_, hwBlob) = new SimulatedHardwareService(backend, MachineA).Enroll();
        var otherMachine = new SimulatedHardwareService(backend, MachineB);

        // Exactly TswapException, the error type the real backends raise for a failed
        // unseal/unwrap, never an AuthenticationTagMismatchException/CryptographicException
        // escaping from AES.
        var ex = Assert.Throws<TswapException>(() => otherMachine.Unlock(SingleSlotConfig(backend, hwBlob), NoSelection));
        Assert.Contains($"'{name}' operation failed", ex.Message);
        Assert.Contains("different machine", ex.Message);
    }

    [Fact]
    public void Unlock_MissingBlob_ThrowsClearError()
    {
        var machine = new SimulatedHardwareService(HardwareBackend.Tpm, MachineA);

        var ex = Assert.Throws<TswapException>(
            () => machine.Unlock(new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm), NoSelection));
        Assert.Contains("Config is corrupted", ex.Message);
    }

    [Fact]
    public void Unlock_TruncatedBlob_ThrowsClearErrorNotAnAesException()
    {
        var machine = new SimulatedHardwareService(HardwareBackend.Tpm, MachineA);

        var ex = Assert.Throws<TswapException>(
            () => machine.Unlock(SingleSlotConfig(HardwareBackend.Tpm, [1, 2, 3]), NoSelection));
        Assert.Contains("Config is corrupted", ex.Message);
    }

    [Fact]
    public void IsSimulated_OnBothSeams()
    {
        var machine = new SimulatedHardwareService(HardwareBackend.Tpm, MachineA);

        Assert.True(((IHardwareKeyService)machine).IsSimulated);
        Assert.True(((IHardwareEnrollmentService)machine).IsSimulated);
        Assert.Equal(HardwareBackend.Tpm, machine.Backend);
    }

    [Fact]
    public void Constructor_RejectsAMachineKeyThatIsNot32Bytes()
    {
        Assert.Throws<ArgumentException>(() => new SimulatedHardwareService(HardwareBackend.Tpm, new byte[16]));
    }

    // --- Selection at the composition root (TswapCli.HardwareServices) ---

    [Fact]
    public void UnlockBackends_WithoutTestKey_ContainsNoSimulatedBackend()
    {
        var backends = HardwareServices.UnlockBackends(testKey: null);

        Assert.DoesNotContain(backends, b => b.IsSimulated);
    }

    [Fact]
    public void UnlockBackends_WithTestKey_RegistersSimulatedTpmAndSecureEnclave()
    {
        var backends = HardwareServices.UnlockBackends(MachineA);

        Assert.All(backends, b => Assert.True(b.IsSimulated));
        Assert.Equal([HardwareBackend.Tpm, HardwareBackend.SecureEnclave], backends.Select(b => b.Backend).Order().ToList());
    }

    [Fact]
    public void Enrollment_WithTestKey_IsSimulatedAndKeyedByTheTestKey()
    {
        var enrollment = HardwareServices.Enrollment(HardwareBackend.Tpm, MachineA);
        var (kekSlot, hwBlob) = enrollment.Enroll();

        Assert.True(enrollment.IsSimulated);
        // Keyed by the test key: the same machine key unlocks it, another does not.
        Assert.Equal(kekSlot, new SimulatedHardwareService(HardwareBackend.Tpm, MachineA)
            .Unlock(SingleSlotConfig(HardwareBackend.Tpm, hwBlob), NoSelection));
        Assert.Throws<TswapException>(() => new SimulatedHardwareService(HardwareBackend.Tpm, MachineB)
            .Unlock(SingleSlotConfig(HardwareBackend.Tpm, hwBlob), NoSelection));
    }

    [Fact]
    public void Enrollment_WithoutTestKey_IsNeverSimulated()
    {
        // Constructing a real service touches no hardware (only Enroll/Unlock do).
        if (OperatingSystem.IsMacOS())
        {
            Assert.False(HardwareServices.Enrollment(HardwareBackend.SecureEnclave, testKey: null).IsSimulated);
            Assert.Throws<TswapException>(() => HardwareServices.Enrollment(HardwareBackend.Tpm, testKey: null));
        }
        else
        {
            Assert.False(HardwareServices.Enrollment(HardwareBackend.Tpm, testKey: null).IsSimulated);
            Assert.Throws<TswapException>(() => HardwareServices.Enrollment(HardwareBackend.SecureEnclave, testKey: null));
        }
    }

    [Fact]
    public void ReadTestKey_InThisDebugBuild_ReadsTheVariable()
    {
        // Control for ReleaseBuildGateTests: in the Debug build the tests run against, the
        // variable is honoured, so a null from the Release build means the gate, not a typo.
        var key = RandomNumberGenerator.GetBytes(32);

        var read = HardwareServices.ReadTestKey(name => name == "TSWAP_TEST_KEY" ? Convert.ToHexString(key) : null);

        Assert.Equal(key, read);
    }

    [Fact]
    public void ReadTestKey_Unset_IsNull()
    {
        Assert.Null(HardwareServices.ReadTestKey(_ => null));
    }
}
