using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Unit tests for the XOR-share unlock logic, using a scripted IYubiKeyService.
/// This logic previously lived inline in Program.cs and had no direct coverage.
/// </summary>
public class VaultUnlockerTests
{
    private sealed class FakeYubiKeys : IYubiKeyService
    {
        public List<int> Connected = [];
        public Dictionary<int, byte[]> Responses = [];
        public List<(int Serial, string Challenge)> ChallengeLog = [];

        public bool IsSimulated => true;
        public IReadOnlyList<int> ListSerials() => Connected;
        public bool? DetectTouchRequirement(int serial) => null;

        public byte[] Challenge(int serial, string challenge)
        {
            ChallengeLog.Add((serial, challenge));
            return Responses[serial];
        }
    }

    private static int NoSelection(IReadOnlyList<int> serials)
        => throw new Exception("selection callback must not be called");

    private static (FakeYubiKeys Yubi, Config Config, byte[] K1, byte[] K2) MakeVault()
    {
        var k1 = RandomNumberGenerator.GetBytes(20);
        var k2 = RandomNumberGenerator.GetBytes(20);
        var config = new Config(
            [11111111, 22222222],
            Convert.ToHexString(Crypto.XorBytes(k1, k2)),
            DateTime.UtcNow,
            UnlockChallenge: "aabbcc");
        var yubi = new FakeYubiKeys { Responses = { [11111111] = k1, [22222222] = k2 } };
        return (yubi, config, k1, k2);
    }

    [Fact]
    public void Unlock_EitherKeyProducesSameMasterKey()
    {
        // The core redundancy property: unlocking with key #1 alone or key #2 alone
        // must derive the identical master key via the XOR share.
        var (yubi, config, _, _) = MakeVault();

        yubi.Connected = [11111111];
        var keyViaFirst = new VaultUnlocker(yubi).Unlock(config, NoSelection);

        yubi.Connected = [22222222];
        var keyViaSecond = new VaultUnlocker(yubi).Unlock(config, NoSelection);

        Assert.Equal(keyViaFirst, keyViaSecond);
        Assert.Equal(32, keyViaFirst.Length);
    }

    [Fact]
    public void Unlock_UsesConfiguredChallenge()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [11111111];

        new VaultUnlocker(yubi).Unlock(config, NoSelection);

        Assert.Equal((11111111, "aabbcc"), Assert.Single(yubi.ChallengeLog));
    }

    [Fact]
    public void Unlock_LegacyConfigWithoutChallenge_UsesFixedChallenge()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [11111111];
        var legacyConfig = config with { UnlockChallenge = null };

        new VaultUnlocker(yubi).Unlock(legacyConfig, NoSelection);

        Assert.Equal("tswap-unlock", yubi.ChallengeLog.Single().Challenge);
    }

    [Fact]
    public void Unlock_UnauthorizedSerial_Throws()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [33333333];

        var ex = Assert.Throws<TswapException>(() => new VaultUnlocker(yubi).Unlock(config, NoSelection));
        Assert.Contains("not authorized", ex.Message);
    }

    [Fact]
    public void Unlock_NoKeysConnected_Throws()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [];

        var ex = Assert.Throws<TswapException>(() => new VaultUnlocker(yubi).Unlock(config, NoSelection));
        Assert.Contains("No YubiKey detected", ex.Message);
    }

    [Fact]
    public void Unlock_MultipleKeysConnected_UsesSelectionCallback()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [11111111, 22222222];

        IReadOnlyList<int>? offered = null;
        var key = new VaultUnlocker(yubi).Unlock(config, serials => { offered = serials; return 22222222; });

        Assert.Equal([11111111, 22222222], offered);
        Assert.Equal(22222222, yubi.ChallengeLog.Single().Serial);
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void Unlock_OverrideKey_BypassesHardwareEntirely()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = []; // would throw if hardware were consulted
        var overrideKey = RandomNumberGenerator.GetBytes(32);

        var key = new VaultUnlocker(yubi, overrideKey).Unlock(config, NoSelection);

        Assert.Same(overrideKey, key);
        Assert.Empty(yubi.ChallengeLog);
    }

    [Fact]
    public void Unlock_CorruptedConfigSerialCount_ThrowsUserFacingError()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [11111111];
        var corrupted = config with { YubiKeySerials = [11111111] }; // only one serial

        var ex = Assert.Throws<TswapException>(() => new VaultUnlocker(yubi).Unlock(corrupted, NoSelection));
        Assert.Contains("expected exactly 2 YubiKey serials", ex.Message);
    }

    [Fact]
    public void Unlock_SelectionCallbackReturnsUnconnectedSerial_Throws()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [11111111, 22222222];

        var ex = Assert.Throws<TswapException>(
            () => new VaultUnlocker(yubi).Unlock(config, _ => 55555555));
        Assert.Contains("not among the connected keys", ex.Message);
    }

    [Fact]
    public void SelectConnectedSerial_RequiredSerialMissing_Throws()
    {
        var (yubi, _, _, _) = MakeVault();
        yubi.Connected = [11111111];

        var ex = Assert.Throws<TswapException>(
            () => new VaultUnlocker(yubi).SelectConnectedSerial(NoSelection, requiredSerial: 99999999));
        Assert.Contains("not found", ex.Message);
    }

    // --- Hardware-backend dispatch ---

    // Minimal stand-in for a future TPM/Secure-Enclave backend: returns a fixed key so a
    // test can prove VaultUnlocker routed to it (and not to the YubiKey backend).
    private sealed class FakeBackend(HardwareBackend backend, byte[] key) : IHardwareKeyService
    {
        public int UnlockCalls;
        public HardwareBackend Backend => backend;
        public bool IsSimulated => true;
        public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
        {
            UnlockCalls++;
            return key;
        }
    }

    [Fact]
    public void Unlock_ExplicitYubiKeyBackend_MatchesNullBackend()
    {
        // Backend == null (legacy) and Backend == YubiKey must take the identical path.
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = [11111111];

        var viaNull = new VaultUnlocker(yubi).Unlock(config, NoSelection);
        var viaExplicit = new VaultUnlocker(yubi).Unlock(config with { Backend = HardwareBackend.YubiKey }, NoSelection);

        Assert.Equal(viaNull, viaExplicit);
    }

    [Fact]
    public void Unlock_UnsupportedBackend_ThrowsClearError()
    {
        var (yubi, config, _, _) = MakeVault();
        var tpmConfig = config with { Backend = HardwareBackend.Tpm };

        var ex = Assert.Throws<TswapException>(
            () => new VaultUnlocker(yubi).Unlock(tpmConfig, NoSelection));
        Assert.Contains("tpm", ex.Message);
        Assert.Contains("does not support", ex.Message);
    }

    [Fact]
    public void Unlock_RegisteredBackend_IsDispatchedToInsteadOfYubiKey()
    {
        var (yubi, config, _, _) = MakeVault();
        yubi.Connected = []; // YubiKey backend would throw if it were consulted
        var tpmKey = RandomNumberGenerator.GetBytes(32);
        var tpm = new FakeBackend(HardwareBackend.SecureEnclave, tpmKey);

        var unlocker = new VaultUnlocker(yubi, additionalBackends: [tpm]);
        var key = unlocker.Unlock(config with { Backend = HardwareBackend.SecureEnclave }, NoSelection);

        Assert.Same(tpmKey, key);
        Assert.Equal(1, tpm.UnlockCalls);
        Assert.Empty(yubi.ChallengeLog);
    }
}
