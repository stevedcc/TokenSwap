using System.Security.Cryptography;
using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T4 item 4 (decision 5): <c>slot add --yubikey</c> unlocks this machine's vault by any
/// slot, enrolls a plugged-in YubiKey that has no slot yet as a one-key slot, appends it to this
/// machine's keyring and backs up <c>config.json</c> first. "Machines" are config dirs; the
/// TPM is <see cref="SimulatedHardwareService"/>, the keys <see cref="SimulatedYubiKeyService"/>.
/// </summary>
public class SlotAddYubiKeyTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private static readonly byte[] RouterTpm = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] LaptopTpm = RandomNumberGenerator.GetBytes(32);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-slot-add-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);

    public SlotAddYubiKeyTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    /// <summary>
    /// A context on this test's "machine". <paramref name="tpm"/> is its simulated TPM (also the
    /// test key, so <c>init --tpm</c> enrolls with it), or null for a machine with no TPM backend.
    /// </summary>
    private CommandContext Context(FakeConsole console, string[] args, byte[]? tpm = null, bool sudo = true)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var unlocker = new VaultUnlocker(_keys, overrideKey: null,
            additionalBackends: tpm == null ? null : [new SimulatedHardwareService(HardwareBackend.Tpm, tpm)]);
        return new CommandContext(console, env, new Storage(_dir), _keys, unlocker, TestKey: tpm, SudoBypass: sudo);
    }

    private (int Exit, string Out, string Err) Run(string stdin, byte[]? tpm, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var exit = CliRunner.Run(Context(console, args, tpm), args);
        return (exit, console.OutText, console.ErrorText);
    }

    private string ConfigPath => Path.Combine(_dir, "config.json");

    private Config LoadConfig() => JsonSerializer.Deserialize(File.ReadAllText(ConfigPath), TswapJsonContext.Default.Config)!;

    private static Keyring DecodeKeyring(Config config) => KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

    private string GetSecret(string name, byte[]? tpm = null)
    {
        var (exit, stdout, stderr) = Run("", tpm, "get", name);
        Assert.True(exit == 0, stderr);
        return stdout.Trim();
    }

    private void YubiKeyVaultWithKeyA()
    {
        _keys.PluggedIn = [SerialA];
        Assert.Equal(0, Run("", null, "init", "--keyring").Exit);
        Assert.Equal(0, Run("s3cret\ns3cret\n", null, "add", "db-password").Exit);
    }

    [Fact]
    public void YubiKeyVault_AddKeyB_EitherKeyAloneUnlocks()
    {
        YubiKeyVaultWithKeyA();
        _keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = Run("", null, "slot", "add", "--yubikey");

        Assert.True(exit == 0, stderr);
        var keyring = DecodeKeyring(LoadConfig());
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery, SlotKind.Machine], keyring.Slots.Select(s => s.Kind));
        var added = keyring.Slots[2];
        Assert.Equal(SerialB, YubiKeySlotBlob.Decode(added.HwBlob!).Serial);
        Assert.Contains($"fingerprint: {SlotFingerprint.Compute(added.PublicKey)}", stdout);

        _keys.PluggedIn = [SerialA];
        Assert.Equal("s3cret", GetSecret("db-password"));
        _keys.PluggedIn = [SerialB];
        Assert.Equal("s3cret", GetSecret("db-password"));
    }

    [Fact]
    public void AddingKeyAAgain_IsRefused_AndConfigIsUntouched()
    {
        YubiKeyVaultWithKeyA();
        var before = File.ReadAllText(ConfigPath);
        _keys.PluggedIn = [SerialA];

        var (exit, _, stderr) = Run("", null, "slot", "add", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("already has a slot", stderr);
        Assert.Contains(SerialA.ToString(), stderr);
        Assert.Equal(before, File.ReadAllText(ConfigPath));
        Assert.Empty(Directory.GetFiles(_dir, "config.json.bak-*"));
    }

    [Fact]
    public void BothKeysPluggedIn_OnlyTheKeyWithoutASlotIsOffered()
    {
        // No stdin: a prompt would pick the first key (A, already enrolled) and fail.
        YubiKeyVaultWithKeyA();
        _keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = Run("", null, "slot", "add", "--yubikey");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("Multiple YubiKeys detected", stdout);
        Assert.Equal(SerialB, YubiKeySlotBlob.Decode(DecodeKeyring(LoadConfig()).Slots[^1].HwBlob!).Serial);
    }

    [Fact]
    public void TpmVault_AddKeyA_KeyAUnlocksWithTheTpmUnavailable()
    {
        Assert.Equal(0, Run("", RouterTpm, "init", "--tpm").Exit);
        Assert.Equal(0, Run("router-pw\nrouter-pw\n", RouterTpm, "add", "router").Exit);
        _keys.PluggedIn = [SerialA];

        var (exit, _, stderr) = Run("", RouterTpm, "slot", "add", "--yubikey");
        Assert.True(exit == 0, stderr);
        Assert.Equal(HardwareBackend.Tpm, LoadConfig().Backend);

        // Still through the TPM on the router itself (no YubiKey challenge needed).
        _keys.Challenges.Clear();
        Assert.Equal("router-pw", GetSecret("router", RouterTpm));
        Assert.Empty(_keys.Challenges);

        // No TPM backend at all, then another machine's TPM: key A opens it.
        Assert.Equal("router-pw", GetSecret("router", tpm: null));
        Assert.Equal("router-pw", GetSecret("router", LaptopTpm));

        // And without key A, the laptop gets the actionable error.
        _keys.PluggedIn = [];
        var (getExit, getOut, getErr) = Run("", LaptopTpm, "get", "router");
        Assert.NotEqual(0, getExit);
        Assert.DoesNotContain("router-pw", getOut);
        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", getErr);
    }

    [Fact]
    public void WithoutSudo_IsRefusedBeforeAnyUnlockOrWrite()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (see SlotCommandTests)

        YubiKeyVaultWithKeyA();
        var before = File.ReadAllText(ConfigPath);
        _keys.PluggedIn = [SerialA, SerialB];
        _keys.Challenges.Clear();
        var console = new FakeConsole();
        string[] args = ["slot", "add", "--yubikey"];

        var exit = CliRunner.Run(Context(console, args, sudo: false), args);

        Assert.NotEqual(0, exit);
        Assert.Contains("slot add", console.ErrorText);
        Assert.Contains("requires", console.ErrorText);
        Assert.Empty(_keys.Challenges);
        Assert.Equal(before, File.ReadAllText(ConfigPath));
    }

    [Fact]
    public void ConfigJsonIsBackedUpBeforeTheWrite()
    {
        YubiKeyVaultWithKeyA();
        var before = File.ReadAllText(ConfigPath);
        _keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = Run("", null, "slot", "add", "--yubikey");

        Assert.True(exit == 0, stderr);
        var backup = Assert.Single(Directory.GetFiles(_dir, "config.json.bak-*"));
        Assert.Equal(before, File.ReadAllText(backup));
        Assert.NotEqual(before, File.ReadAllText(ConfigPath));
        Assert.Contains(backup, stdout);
    }

    [Fact]
    public void SlotsListsEachYubiKeySlotWithItsSerial()
    {
        Assert.Equal(0, Run("", RouterTpm, "init", "--tpm").Exit);
        _keys.PluggedIn = [SerialA];
        Assert.Equal(0, Run("", RouterTpm, "slot", "add", "--yubikey").Exit);

        var (_, stdout, _) = Run("", RouterTpm, "slots");

        var machineRows = stdout.Split('\n').Where(l => l.Contains("  machine  ")).ToList();
        Assert.Equal(2, machineRows.Count);
        Assert.Contains("TPM", machineRows[0]);
        Assert.DoesNotContain("YubiKey", machineRows[0]);
        Assert.Contains($"YubiKey {SerialA}, touch required", machineRows[1]);
    }

    [Fact]
    public void PlainVault_IsRefused()
    {
        var testKey = RandomNumberGenerator.GetBytes(32);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        string[] init = ["init"];
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = init };
        Assert.Equal(0, CliRunner.Run(new CommandContext(new FakeConsole(), env, new Storage(_dir), yubiKeys,
            new VaultUnlocker(yubiKeys, overrideKey: testKey), testKey, SudoBypass: true), init));

        var (exit, _, stderr) = Run("", null, "slot", "add", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("no keyring", stderr);
    }

    [Fact]
    public void Version2Keyring_IsRefusedWithAnActionableMessage()
    {
        File.WriteAllText(ConfigPath, KeyringV2FixtureTests.FixtureConfigJson);
        File.WriteAllBytes(Path.Combine(_dir, "secrets.json.enc"), Convert.FromBase64String(KeyringV2FixtureTests.FixtureSecretsFileBase64));
        var testKey = Convert.FromHexString(KeyringV2FixtureTests.FixtureTestKeyHex);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var console = new FakeConsole();
        string[] args = ["slot", "add", "--yubikey"];
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };

        var exit = CliRunner.Run(new CommandContext(console, env, new Storage(_dir), yubiKeys,
            new VaultUnlocker(yubiKeys, overrideKey: testKey), testKey, SudoBypass: true), args);

        Assert.NotEqual(0, exit);
        Assert.Contains("format version 2", console.ErrorText);
        Assert.Equal(KeyringV2FixtureTests.FixtureConfigJson, File.ReadAllText(ConfigPath));
    }

    [Theory]
    [InlineData("slot", "add")]
    [InlineData("slot", "add", "--tpm")]
    [InlineData("slot", "add", "--yubikey", "extra")]
    public void WrongArguments_AreAUsageError(params string[] args)
    {
        var (exit, _, stderr) = Run("", null, args);

        Assert.Equal(1, exit);
        Assert.Contains("slot add --yubikey", stderr);
    }
}
