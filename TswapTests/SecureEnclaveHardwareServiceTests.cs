using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Secure Enclave backend tests. Trait-gated (<c>Category=SecureEnclave</c>) and excluded
/// from the default and <c>--unit</c> runs because they need a real Mac with a physical
/// Secure Enclave and will prompt for biometry/presence. Run them explicitly on a Mac:
/// <code>
///   ./runtests.sh --secure-enclave
///   # or: dotnet test ./TswapTests/TswapTests.csproj --filter Category=SecureEnclave
/// </code>
/// Each <c>Wrap</c> call creates a fresh Secure Enclave key (see
/// <c>AppleSecureEnclaveInterop</c>), so every test that calls <c>Unwrap</c> prompts for
/// Touch ID / presence separately.
/// </summary>
[SupportedOSPlatform("macos")]
[Trait("Category", "SecureEnclave")]
public class SecureEnclaveHardwareServiceTests
{
    [Fact]
    public void WrapUnwrap_RoundTripsKey()
    {
        // The core primitive: a key wrapped to the Enclave must unwrap back to itself,
        // and the wrapped form must not be the plaintext.
        var svc = new SecureEnclaveHardwareService();
        var key = RandomNumberGenerator.GetBytes(32);

        var wrapped = svc.Wrap(key);
        var recovered = svc.Unwrap(wrapped);

        Assert.Equal(key, recovered);
        Assert.NotEqual(key, wrapped);
    }

    [Fact]
    public void Unlock_RecoversVaultKeyFromSlot()
    {
        var svc = new SecureEnclaveHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = svc.Wrap(vaultKey);

        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(wrapped));

        var recovered = svc.Unlock(config, _ => throw new InvalidOperationException("chooseSerial should not be called for Secure Enclave"));

        Assert.Equal(vaultKey, recovered);
    }

    [Fact]
    public void Unlock_MissingWrappedKey_ThrowsClearError()
    {
        var svc = new SecureEnclaveHardwareService();
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave);

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("secure-enclave", ex.Message);
    }

    [Fact]
    public void Unlock_InvalidBase64_ThrowsClearError()
    {
        var svc = new SecureEnclaveHardwareService();
        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: "not valid base64!!");

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("base64", ex.Message);
    }

    [Fact]
    public void Unlock_WrongLengthKey_ThrowsClearError()
    {
        // Unwrap is a generic primitive (round-trips whatever was wrapped, per
        // WrapUnwrap_RoundTripsKey), so a 16-byte payload round-trips fine at that layer.
        // Unlock specifically promises a 32-byte vault key, so it must reject this.
        var svc = new SecureEnclaveHardwareService();
        var wrapped = svc.Wrap(RandomNumberGenerator.GetBytes(16));
        var config = new Config([], "", DateTime.UtcNow,
            Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(wrapped));

        var ex = Assert.Throws<TswapException>(() => svc.Unlock(config, _ => 0));
        Assert.Contains("32-byte", ex.Message);
    }

    [Fact]
    public void Unwrap_HugeLengthPrefix_ThrowsClearErrorInsteadOfOverflowing()
    {
        // A blobLen near int.MaxValue makes the naive "4 + blobLen > wrapped.Length" bounds
        // check overflow (wraps to negative, so the comparison passes when it shouldn't),
        // reaching `new byte[blobLen]` with an ~2GB size. The fix uses a subtraction-based
        // check instead; this proves it rejects cleanly rather than attempting that allocation.
        var svc = new SecureEnclaveHardwareService();
        var corrupted = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(corrupted, int.MaxValue - 1);

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(corrupted));
        Assert.Contains("length prefix", ex.Message);
    }

    [Fact]
    public void Unwrap_TruncatedCiphertext_ThrowsDistinctMalformedError()
    {
        // Uses a *real* Secure Enclave blob (from a real Wrap call) but truncates the
        // ciphertext package down to nothing usable. Proves tswap_se_unwrap's rc=-3 gets its
        // own "malformed" message rather than being collapsed into the generic "wrong machine
        // or presence cancelled" one — those are different problems, so they need different
        // messages. Reconstituting the SE key from a valid blob doesn't itself prompt (only the
        // key-agreement step does, which this never reaches — the length guard fails first).
        var svc = new SecureEnclaveHardwareService();
        var wrapped = svc.Wrap(RandomNumberGenerator.GetBytes(32));
        var blobLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(wrapped);

        var truncated = new byte[4 + blobLen + 1]; // 1 byte of "ciphertext" — nowhere near the 93-byte minimum
        wrapped.AsSpan(0, 4 + blobLen).CopyTo(truncated);

        var ex = Assert.Throws<TswapException>(() => svc.Unwrap(truncated));
        Assert.Contains("malformed", ex.Message);
    }

    [Fact(Skip = "Manual: requires denying/cancelling the Touch ID prompt to assert the failure path.")]
    public void Unwrap_RequiresUserPresence()
    {
        // The Swift shim (TswapSecureEnclave.swift) creates every key with
        // [.privateKeyUsage, .userPresence] access control, so key agreement always prompts
        // for biometry/passcode. Manually verified: cancelling the prompt makes Unwrap throw
        // TswapException ("...verification failed or was cancelled"), not hang or crash. This
        // documents that invariant; verifying the *denial* path needs a human to cancel the
        // system prompt, so it stays manual rather than a CI-run fact.
    }
}
