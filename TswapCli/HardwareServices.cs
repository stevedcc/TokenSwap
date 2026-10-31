using TswapCore;
using TswapCore.Vault;

namespace TswapCli;

/// <summary>
/// Chooses the hardware services for this process: real backends, or simulated ones in test
/// mode. Test mode exists only in Debug builds with <c>TSWAP_TEST_KEY</c> set:
/// <see cref="ReadTestKey"/> compiles to "always null" in Release, and every other method here
/// selects a simulated service only for a non-null test key. So a Release binary has no path to
/// <see cref="TestKeyYubiKeyService"/> or <see cref="SimulatedHardwareService"/>, whatever the
/// environment says (<c>ReleaseBuildGateTests</c> proves it against a real Release build).
/// </summary>
internal static class HardwareServices
{
    public const string TestKeyVariable = "TSWAP_TEST_KEY";

    /// <summary>
    /// The hex-encoded 32-byte test key from <c>TSWAP_TEST_KEY</c>, or null. Debug builds only:
    /// in Release this always returns null.
    /// </summary>
    public static byte[]? ReadTestKey(Func<string, string?> getEnvironmentVariable)
    {
#if DEBUG
        var testKeyHex = getEnvironmentVariable(TestKeyVariable);
        if (testKeyHex is null)
            return null;
        var testKey = Convert.FromHexString(testKeyHex);
        if (testKey.Length != 32)
            throw new TswapException("TSWAP_TEST_KEY must be exactly 32 bytes (64 hex chars)");
        return testKey;
#else
        _ = getEnvironmentVariable;
        return null;
#endif
    }

    /// <summary>
    /// The non-YubiKey unlock backends to register with <see cref="VaultUnlocker"/> (the YubiKey
    /// backend is always registered by <see cref="VaultUnlocker"/> itself). In test mode a
    /// simulated TPM and Secure Enclave keyed by <paramref name="testKey"/>; otherwise the real
    /// backend for this OS. The Secure Enclave comes from <see cref="SecureEnclave"/>, so it runs
    /// as the vault folder's owner (<paramref name="ownerScope"/>, brief T12).
    /// </summary>
    public static IReadOnlyList<IHardwareKeyService> UnlockBackends(byte[]? testKey, VaultOwnerScope ownerScope)
    {
        if (testKey is not null)
            return
            [
                new SimulatedHardwareService(HardwareBackend.Tpm, testKey),
                SecureEnclave(testKey, ownerScope),
            ];

        List<IHardwareKeyService> backends = [];
        if (OperatingSystem.IsMacOS()) backends.Add(SecureEnclave(testKey, ownerScope));
        if (OperatingSystem.IsLinux()) backends.Add(new LinuxTpmHardwareService());
        if (OperatingSystem.IsWindows()) backends.Add(new WindowsTpmHardwareService());
        return backends;
    }

    /// <summary>
    /// The enrollment service for <paramref name="backend"/> (<c>init --tpm</c> /
    /// <c>--secure-enclave</c>): simulated in test mode, else the real one for this OS. Throws
    /// <see cref="TswapException"/> when this OS has no such hardware.
    /// <paramref name="requirePresence"/> (brief T11) is false only for a Secure Enclave enrolled
    /// with <c>--no-touch</c>; it defaults to presence required, so a caller that forgets it gets
    /// the safe key, and any other backend without presence throws. The Secure Enclave comes from
    /// <see cref="SecureEnclave"/>, so its key is created as the vault folder's owner
    /// (<paramref name="ownerScope"/>, brief T12).
    /// </summary>
    public static IHardwareEnrollmentService Enrollment(HardwareBackend backend, byte[]? testKey, VaultOwnerScope ownerScope, bool requirePresence = true)
    {
        if (!requirePresence && backend != HardwareBackend.SecureEnclave)
            throw new ArgumentException(
                $"Only a Secure Enclave enrolment can choose no presence, not '{backend.DisplayName()}'", nameof(requirePresence));

        switch (backend)
        {
            case HardwareBackend.SecureEnclave:
                return SecureEnclave(testKey, ownerScope, requirePresence);
            case HardwareBackend.Tpm when testKey is not null:
                return new SimulatedHardwareService(backend, testKey);
            case HardwareBackend.Tpm:
                if (OperatingSystem.IsLinux()) return new LinuxTpmHardwareService();
                if (OperatingSystem.IsWindows()) return new WindowsTpmHardwareService();
                throw new TswapException("--tpm is only supported on Windows and Linux.");
            default:
                throw new ArgumentOutOfRangeException(nameof(backend), backend,
                    "YubiKey derives KEK_slot in InitCommand; it has no enrollment service");
        }
    }

    /// <summary>
    /// Brief T12 decision 3: the one place a Secure Enclave service is built (simulated in test mode,
    /// else the real one, macOS only), always wrapped in
    /// <see cref="OwnerScopedHardwareService"/>, so under sudo its calls run as the vault folder's
    /// owner and macOS asks that user for Touch ID, not root. <c>SecureEnclaveFactoryScanTests</c>
    /// fails if the service is built anywhere else.
    /// </summary>
    private static OwnerScopedHardwareService SecureEnclave(byte[]? testKey, VaultOwnerScope ownerScope, bool requirePresence = true)
    {
        if (testKey is not null)
            return OwnerScopedHardwareService.Wrap(new SimulatedHardwareService(HardwareBackend.SecureEnclave, testKey, requirePresence), ownerScope);
        if (!OperatingSystem.IsMacOS())
            throw new TswapException("--secure-enclave is only supported on macOS.");
        return OwnerScopedHardwareService.Wrap(new SecureEnclaveHardwareService(requirePresence), ownerScope);
    }
}
