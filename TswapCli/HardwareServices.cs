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
        if (testKeyHex == null)
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
    /// backend for this OS.
    /// </summary>
    public static IReadOnlyList<IHardwareKeyService> UnlockBackends(byte[]? testKey)
    {
        if (testKey != null)
            return
            [
                new SimulatedHardwareService(HardwareBackend.Tpm, testKey),
                new SimulatedHardwareService(HardwareBackend.SecureEnclave, testKey),
            ];

        var backends = new List<IHardwareKeyService>();
        if (OperatingSystem.IsMacOS()) backends.Add(new SecureEnclaveHardwareService());
        if (OperatingSystem.IsLinux()) backends.Add(new LinuxTpmHardwareService());
        if (OperatingSystem.IsWindows()) backends.Add(new WindowsTpmHardwareService());
        return backends;
    }

    /// <summary>
    /// The enrollment service for <paramref name="backend"/> (<c>init --tpm</c> /
    /// <c>--secure-enclave</c>): simulated in test mode, else the real one for this OS. Throws
    /// <see cref="TswapException"/> when this OS has no such hardware.
    /// </summary>
    public static IHardwareEnrollmentService Enrollment(HardwareBackend backend, byte[]? testKey)
    {
        if (testKey != null && backend is HardwareBackend.Tpm or HardwareBackend.SecureEnclave)
            return new SimulatedHardwareService(backend, testKey);

        switch (backend)
        {
            case HardwareBackend.SecureEnclave:
                if (OperatingSystem.IsMacOS()) return new SecureEnclaveHardwareService();
                throw new TswapException("--secure-enclave is only supported on macOS.");
            case HardwareBackend.Tpm:
                if (OperatingSystem.IsLinux()) return new LinuxTpmHardwareService();
                if (OperatingSystem.IsWindows()) return new WindowsTpmHardwareService();
                throw new TswapException("--tpm is only supported on Windows and Linux.");
            default:
                throw new ArgumentOutOfRangeException(nameof(backend), backend,
                    "YubiKey derives KEK_slot in InitCommand; it has no enrollment service");
        }
    }
}
