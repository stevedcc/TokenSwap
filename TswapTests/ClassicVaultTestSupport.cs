using System.Security.Cryptography;
using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 (ruling 4): <c>init</c> can no longer create a classic single-file vault, but
/// classic vaults still exist (migration and export read them), so tests write one directly, as
/// tswap 0.1's <c>init</c> did: <c>config.json</c> with the two-YubiKey XOR fields, and
/// <c>secrets.json.enc</c> under the derived master key.
/// </summary>
internal static class ClassicVaultTestSupport
{
    /// <summary>
    /// A two-YubiKey XOR vault on <paramref name="serial1"/> and <paramref name="serial2"/> of
    /// <paramref name="keys"/> (both must answer), holding <paramref name="secrets"/>; returns the
    /// master key. The touch posture is recorded and acknowledged as init recorded it.
    /// </summary>
    public static byte[] CreateXorVault(string dir, IYubiKeyService keys, int serial1, int serial2, IDictionary<string, Secret>? secrets = null)
    {
        var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var answer1 = keys.ChallengeReportingTouch(serial1, challenge);
        var answer2 = keys.ChallengeReportingTouch(serial2, challenge);
        var touch1 = answer1.AskedForTouch ?? keys.DetectTouchRequirement(serial1);
        var touch2 = answer2.AskedForTouch ?? keys.DetectTouchRequirement(serial2);
        var salt = RandomNumberGenerator.GetBytes(32);
        var config = new Config(
            [serial1, serial2],
            Convert.ToHexString(Crypto.XorBytes(answer1.Response, answer2.Response)),
            TestTime.Fixed,
            touch1.HasValue && touch2.HasValue ? touch1.Value && touch2.Value : null,
            RngMode.System,
            challenge,
            MasterKeySalt: Convert.ToBase64String(salt));
        config = SecurityWarnings.Acknowledge(config);
        var key = Crypto.DeriveKey(answer1.Response, answer2.Response, salt);
        var store = new Storage(dir);
        store.SaveConfig(config);
        store.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>(secrets ?? new Dictionary<string, Secret>())), key);
        return key;
    }

    /// <summary><see cref="CreateXorVault(string, IYubiKeyService, int, int, IDictionary{string, Secret}?)"/> on a fleet machine's own keys.</summary>
    public static byte[] CreateXorVault(FleetMachine machine, int serial1 = RecordVaultTestSupport.SerialA, int serial2 = RecordVaultTestSupport.SerialB,
        IDictionary<string, Secret>? secrets = null) =>
        CreateXorVault(machine.Dir, machine.Keys, serial1, serial2, secrets);

    /// <summary>
    /// A classic vault as test-mode <c>init</c> made it (TSWAP_TEST_KEY): the synthetic serials, a
    /// zero XOR share, and the secrets encrypted under the test key itself (test-mode unlock returns
    /// it without a challenge).
    /// </summary>
    public static void CreateTestModeVault(string dir, byte[] testKey, IDictionary<string, Secret>? secrets = null)
    {
        var config = new Config(
            [TestKeyYubiKeyService.Serial1, TestKeyYubiKeyService.Serial2],
            new string('0', 40),
            TestTime.Fixed,
            null,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        var store = new Storage(dir);
        store.SaveConfig(config);
        store.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>(secrets ?? new Dictionary<string, Secret>())), testKey);
    }

    /// <summary>
    /// A classic keyring vault as tswap 0.1's <c>init --keyring</c> / <c>--tpm</c> /
    /// <c>--secure-enclave</c> made it: <c>config.json</c> carrying the keyring itself, and an empty
    /// <c>secrets.json.enc</c> under <c>K_v</c>. Made by today's <c>init</c> (with
    /// <paramref name="initFlags"/>, a recovery slot required) and folded back into the single-file
    /// layout: the keyring moves into config.json and the vault folder goes. Returns <c>K_v</c> and
    /// init's output.
    /// </summary>
    public static (byte[] VaultKey, string InitOutput) CreateKeyringVault(FleetMachine machine, params ReadOnlySpan<string> initFlags)
    {
        var output = machine.Ok("", ["init", .. initFlags]);
        return (FoldIntoClassicKeyringVault(machine.Dir, output), output);
    }

    /// <summary>
    /// Turns the record vault <c>init</c> just made in <paramref name="configDir"/> into the classic
    /// single-file keyring layout (see <see cref="CreateKeyringVault"/>); returns <c>K_v</c>, opened
    /// with the recovery key printed in <paramref name="initOutput"/>.
    /// </summary>
    public static byte[] FoldIntoClassicKeyringVault(string configDir, string initOutput)
    {
        var configPath = Path.Combine(configDir, "config.json");
        var config = JsonSerializer.Deserialize(File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        var keyringBytes = File.ReadAllBytes(Path.Combine(config.VaultDir!, RecordVaultStore.KeyringFileName));
        var classic = config with
        {
            Keyring = Convert.ToBase64String(keyringBytes),
            Store = null,
            VaultDir = null,
            OriginId = null,
            LastHlc = null,
        };
        Directory.Delete(config.VaultDir!, true);
        File.WriteAllText(configPath, JsonSerializer.Serialize(classic, TswapJsonContext.Default.Config));
        var vaultKey = RecoveryKeyUnlock.Unlock(KeyringCodec.Decode(keyringBytes), Convert.FromBase64String(RecordVaultTestSupport.RecoveryKeyFrom(initOutput)));
        new Storage(configDir).SaveSecrets(new SecretsDb([]), vaultKey);
        return vaultKey;
    }
}
