using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T17 task 13: the Secure Enclave password slot on a real Enclave, with keys made without presence,
/// so nothing prompts. Like <see cref="SecureEnclaveNoTouchRoundTripTests"/> this class is in the default and
/// <c>--unit</c> runs: it runs on macOS when <c>tswap_se_available()</c> is true (GitHub's macOS runner has a
/// Secure Enclave, and CI builds the shim there, so this is also what proves <c>tswap_se_wrap_v3</c> and
/// <c>tswap_se_unwrap_v2</c> compile and behave). Elsewhere each test writes why to the output and returns,
/// unless <c>CI_REQUIRE_SE=1</c>: then it fails. Every Enclave call is bounded: a call that waits for a dialog
/// nobody answers fails the test instead of hanging the job. The Touch ID + password case is manual
/// (<see cref="SecureEnclavePasswordHardwareTests"/>).
/// </summary>
public class SecureEnclavePasswordRoundTripTests(ITestOutputHelper output)
{
    private static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(30);

    private bool CanRun()
    {
        string problem;
        if (!OperatingSystem.IsMacOS())
            problem = "the Secure Enclave exists only on macOS";
        else if (!AppleSecureEnclaveInterop.IsAvailable())
            problem = "tswap_se_available() is false on this Mac (no Secure Enclave, e.g. a virtual machine)";
        else
            return true;

        if (Environment.GetEnvironmentVariable("CI_REQUIRE_SE") == "1")
            Assert.Fail($"CI_REQUIRE_SE=1 but the Secure Enclave password round trip can't run: {problem}");
        output.WriteLine($"SKIPPED: the Secure Enclave password round trip can't run here: {problem}");
        return false;
    }

    /// <summary>Runs <paramref name="call"/> with a timeout; a timeout fails the test (it must answer, not wait for a dialog).</summary>
    private T Bounded<T>(string what, Func<T> call)
    {
        var watch = Stopwatch.StartNew();
        var task = Task.Run(call);
        if (!((IAsyncResult)task).AsyncWaitHandle.WaitOne(CallTimeout))
            Assert.Fail($"{what} didn't return within {CallTimeout.TotalSeconds} s: it is probably waiting for a dialog.");
        output.WriteLine($"{what}: answered in {watch.ElapsedMilliseconds} ms");
        return task.GetAwaiter().GetResult();
    }

    private static StretchedPassword Password() => StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));

    private static StretchedPassword FlipLastBit(StretchedPassword p)
    {
        var bytes = new byte[StretchedPassword.Size];
        p.CopyTo(bytes);
        bytes[^1] ^= 0x01;
        try
        {
            return StretchedPassword.FromBytes(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Fact]
    public void RealEnclave_PasswordSlot_RoundTrips()
    {
        if (!CanRun() || !OperatingSystem.IsMacOS())
            return;
        RoundTrip();
    }

    [SupportedOSPlatform("macos")]
    private void RoundTrip()
    {
        using var password = Password();
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (kek, hwBlob) = Bounded("wrap_v3", () => service.Enroll(password));
        Assert.True(SecureEnclaveSlotBlob.HasHeader(hwBlob));

        var config = new Config([], "", TestTime.Fixed, Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(hwBlob));
        var recovered = Bounded("unwrap_v2", () => service.Unlock(config, _ => 0, () => password.Clone()));

        Assert.Equal(kek, recovered);
    }

    [Fact]
    public void RealEnclave_WrongPassword_Refused()
    {
        if (!CanRun() || !OperatingSystem.IsMacOS())
            return;
        WrongPasswords();
    }

    [SupportedOSPlatform("macos")]
    private void WrongPasswords()
    {
        using var password = Password();
        using var other = Password();
        using var flipped = FlipLastBit(password);
        var key = RandomNumberGenerator.GetBytes(32);
        var package = Bounded("wrap_v3", () => AppleSecureEnclaveInterop.WrapWithPassword(key, requirePresence: false, password));

        foreach (var (label, wrong) in new[] { ("another password", other), ("the last bit flipped", flipped) })
        {
            var ex = Bounded($"unwrap_v2 with {label}", () =>
                Assert.Throws<VaultPasswordRefusedException>(() => AppleSecureEnclaveInterop.UnwrapWithPassword(package, wrong)));
            Assert.Equal(VaultPasswordMessages.WrongPasswordSecureEnclave, ex.Message); // the shim's -7
        }

        // No rate limit: the right password still works after the failures (the owner's spike).
        Assert.Equal(key, Bounded("unwrap_v2 with the right password", () => AppleSecureEnclaveInterop.UnwrapWithPassword(package, password)));
    }

    [Fact]
    public void RealEnclave_NoCredential_RefusedWithoutDialog()
    {
        // The new unwrap refuses a credential that is not 32 bytes with -6, before touching the Enclave.
        if (!CanRun() || !OperatingSystem.IsMacOS())
            return;
        NoCredential();
    }

    [SupportedOSPlatform("macos")]
    private void NoCredential()
    {
        using var password = Password();
        var package = Bounded("wrap_v3", () => AppleSecureEnclaveInterop.WrapWithPassword(RandomNumberGenerator.GetBytes(32), requirePresence: false, password));

        var rc = Bounded("unwrap_v2 with an empty credential", () => AppleSecureEnclaveInterop.UnwrapV2ReturnCode(package, credential: []));

        Assert.Equal(SecureEnclaveReturnCodes.CredentialLength, rc);
    }

    /// <summary>What "at once" means for a refusal that must not wait for a dialog: well under <see cref="CallTimeout"/>.</summary>
    private static readonly TimeSpan PromptRefusal = TimeSpan.FromSeconds(5);

    [Fact]
    public void RealEnclave_StrippedHeader_Refused()
    {
        // Ruling 3 with the controller's rulings for the Secure Enclave: without its TSSE header the slot looks
        // password-free and gets today's generic text. CI run 41619549912: through the interactive tswap_se_unwrap
        // the key waited for an application-password dialog until the 30 s bound. The slot is recorded as made
        // without presence (config.json's RequiresTouch false, as init --no-touch writes it), so the unwrap allows
        // no interaction (tswap_se_unwrap_no_interaction) and must refuse at once.
        if (!CanRun() || !OperatingSystem.IsMacOS())
            return;
        StrippedHeader();
    }

    [SupportedOSPlatform("macos")]
    private void StrippedHeader()
    {
        using var password = Password();
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (_, hwBlob) = Bounded("wrap_v3", () => service.Enroll(password));
        var (_, package) = SecureEnclaveSlotBlob.Split(hwBlob);
        var config = new Config([], "", TestTime.Fixed, Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(package), RequiresTouch: false);

        var watch = Stopwatch.StartNew();
        var ex = Bounded("the no-interaction unwrap of a stripped password slot", () =>
            Record.Exception(() => service.Unlock(config, _ => 0, password: null)));
        watch.Stop();

        var refused = Assert.IsAssignableFrom<TswapException>(ex);
        Assert.StartsWith("Could not unlock with the Secure Enclave.", refused.Message);
        Assert.True(watch.Elapsed < PromptRefusal, $"refused after {watch.Elapsed.TotalSeconds:F1} s, not at once");
    }
}
