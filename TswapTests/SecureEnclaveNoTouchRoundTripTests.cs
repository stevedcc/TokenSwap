using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T11 item 2: the Secure Enclave round trip CI can run. The presence prompt was the only
/// reason the Secure Enclave tests are manual (<see cref="SecureEnclaveHardwareServiceTests"/>,
/// <c>Category=SecureEnclave</c>); a key made with <c>requirePresence: false</c> unwraps without
/// one, so this class is in the default and <c>--unit</c> runs.
///
/// <para>It runs on macOS when <c>tswap_se_available()</c> is true. GitHub's macOS runners are
/// virtual machines and may have no Secure Enclave, so otherwise each test writes why to the test
/// output and returns, unless <c>CI_REQUIRE_SE=1</c> (as <c>CI_REQUIRE_BWRAP</c>): then it fails.
/// Every unwrap is bounded: a presence flag lost on the way would make the runner wait for a
/// Touch ID prompt nobody answers, and that must fail the test, not hang the job.</para>
/// </summary>
public class SecureEnclaveNoTouchRoundTripTests(ITestOutputHelper output)
{
    private static readonly TimeSpan UnwrapTimeout = TimeSpan.FromSeconds(30);

    // 65-byte ephemeral public key || 12-byte nonce || ciphertext || 16-byte tag.
    private const int EciesOverhead = 65 + 12 + 16;

    private bool CanRun()
    {
        string problem;
        if (!OperatingSystem.IsMacOS())
            problem = "the Secure Enclave exists only on macOS";
        else if (!AppleSecureEnclaveInterop.IsAvailable())
        {
            output.WriteLine("Secure Enclave available: false");
            problem = "tswap_se_available() is false on this Mac (no Secure Enclave, e.g. a virtual machine)";
        }
        else
        {
            output.WriteLine("Secure Enclave available: true");
            return true;
        }

        if (Environment.GetEnvironmentVariable("CI_REQUIRE_SE") == "1")
            Assert.Fail($"CI_REQUIRE_SE=1 but the Secure Enclave round trip can't run: {problem}");
        output.WriteLine($"SKIPPED: the Secure Enclave round trip can't run here: {problem}");
        return false;
    }

    /// <summary>Runs <paramref name="unwrap"/> with a timeout; a timeout fails the test.</summary>
    private static T Bounded<T>(Func<T> unwrap)
    {
        var task = Task.Run(unwrap);
        if (!task.Wait(UnwrapTimeout))
            Assert.Fail($"The Secure Enclave unwrap didn't return within {UnwrapTimeout.TotalSeconds} s: " +
                        "it is probably waiting for a presence prompt, so requirePresence: false was lost on the way.");
        return task.GetAwaiter().GetResult();
    }

    [Fact]
    public void ANoTouchKey_RoundTrips_AndATamperedPackageFails()
    {
        if (!CanRun() || !OperatingSystem.IsMacOS())
            return;
        NoTouchRoundTrip();
    }

    [SupportedOSPlatform("macos")]
    private static void NoTouchRoundTrip()
    {
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var key = RandomNumberGenerator.GetBytes(32);

        var wrapped = service.Wrap(key);
        var recovered = Bounded(() => service.Unwrap(wrapped));

        Assert.Equal(key, recovered);

        var tampered = (byte[])wrapped.Clone();
        tampered[^1] ^= 0x01; // the GCM tag
        var ex = Bounded(() => Assert.Throws<TswapException>(() => service.Unwrap(tampered)));
        Assert.Contains("Could not unlock with the Secure Enclave", ex.Message);
    }

    [Fact]
    public void ATouchKey_Wraps_WithoutUnwrapping()
    {
        // Creating a presence-gated key doesn't prompt; only using it does. This runs
        // tswap_se_wrap_v2's 1 branch and its access-control guard on hardware.
        if (!CanRun() || !OperatingSystem.IsMacOS())
            return;

        var key = RandomNumberGenerator.GetBytes(32);

        var wrapped = new SecureEnclaveHardwareService(requirePresence: true).Wrap(key);

        // 4-byte little-endian blob length || the key's dataRepresentation || the ECIES package.
        var blobLen = BinaryPrimitives.ReadInt32LittleEndian(wrapped);
        Assert.InRange(blobLen, 1, 2048);
        Assert.Equal(4 + blobLen + EciesOverhead + key.Length, wrapped.Length);
    }
}
