using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T4 item 3 (decision 4): <c>init --keyring</c> enrolls <b>one</b> plugged-in YubiKey as a
/// one-key slot (plus the recovery slot unless <c>--no-recovery</c>), with no pair fields in
/// config. Runs outside test mode against <see cref="SimulatedYubiKeyService"/>, so the slot's
/// <c>KEK_slot</c> really comes from the key's HMAC response.
/// </summary>
public class InitKeyringOneKeyTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-init-onekey-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);

    public InitKeyringOneKeyTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    private (int Exit, string Out, string Err) Run(string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var ctx = new CommandContext(console, env, new Storage(_dir), _keys, new VaultUnlocker(_keys), TestKey: null, SudoBypass: true);
        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    private Config LoadConfig() =>
        JsonSerializer.Deserialize(File.ReadAllText(Path.Combine(_dir, "config.json")), TswapJsonContext.Default.Config)!;

    private static Keyring DecodeKeyring(Config config) => KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

    private byte[] Unlock() => new VaultUnlocker(_keys).Unlock(LoadConfig(), s => s[0]);

    [Fact]
    public void OneKeyPluggedIn_OneYubiKeySlotPlusRecovery_NoPairFieldsInConfig()
    {
        _keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = Run("", "init", "--keyring");

        Assert.True(exit == 0, stderr);
        var config = LoadConfig();
        Assert.Empty(config.YubiKeySerials);
        Assert.Equal("", config.RedundancyXor);
        Assert.Null(config.UnlockChallenge);
        Assert.Null(config.MasterKeySalt);
        Assert.Null(config.Backend); // YubiKey
        Assert.True(config.RequiresTouch);
        Assert.DoesNotContain("XOR", stdout);

        var keyring = DecodeKeyring(config);
        Assert.Equal(3, keyring.FormatVersion);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));
        var machine = keyring.Slots[0];
        Assert.Equal(config.KeyringSlotId, Convert.ToBase64String(machine.SlotId));
        var blob = YubiKeySlotBlob.Decode(machine.HwBlob!);
        Assert.Equal(SerialA, blob.Serial);
        Assert.Equal(YubiKeyTouchPolicy.Required, blob.Touch);
        Assert.Contains(SerialA.ToString(), stdout);

        // The key was challenged once, with the slot's own challenge.
        Assert.Equal([(SerialA, blob.ChallengeString)], _keys.Challenges);
    }

    [Fact]
    public void OneKey_CreateApplyRoundTrip_AndAnotherKeyDoesNotOpenIt()
    {
        _keys.PluggedIn = [SerialA];
        Assert.Equal(0, Run("", "init", "--keyring").Exit);

        var (createExit, _, createErr) = Run("", "create", "db-password", "24");
        Assert.True(createExit == 0, createErr);
        var valuesFile = Path.Combine(_dir, "values.yaml");
        File.WriteAllText(valuesFile, "db:\n  password: \"\"  # tswap: db-password\n");
        var (applyExit, applyOut, applyErr) = Run("", "apply", valuesFile);
        Assert.True(applyExit == 0, applyErr);

        var stored = new Storage(_dir).LoadSecrets(Unlock(), TextWriter.Null).Secrets["db-password"].Value;
        Assert.Equal(24, stored.Length);
        Assert.Contains($"password: \"{stored}\"  # tswap: db-password", applyOut);

        _keys.PluggedIn = [SerialB];
        var (getExit, getOut, getErr) = Run("", "apply", valuesFile);
        Assert.NotEqual(0, getExit);
        Assert.DoesNotContain(stored, getOut);
        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", getErr);
    }

    [Fact]
    public void TwoKeysPluggedIn_ChooseSerialDecides_StillOneSlot()
    {
        _keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = Run("2\n", "init", "--keyring", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains("Multiple YubiKeys detected", stdout);
        var keyring = DecodeKeyring(LoadConfig());
        var machine = Assert.Single(keyring.Slots);
        Assert.Equal(SerialB, YubiKeySlotBlob.Decode(machine.HwBlob!).Serial);
        Assert.Equal([SerialB], _keys.Challenges.Select(c => c.Serial));

        _keys.PluggedIn = [SerialB];
        var vaultKey = Unlock();
        _keys.PluggedIn = [SerialA];
        Assert.Throws<TswapException>(() => Unlock());
        Assert.Equal(32, vaultKey.Length);
    }

    [Fact]
    public void TheRecoveryKeyRecoversKv()
    {
        _keys.PluggedIn = [SerialA];
        var (_, stdout, _) = Run("", "init", "--keyring");
        var lines = stdout.Split('\n').Select(l => l.Trim()).ToList();
        var recoveryPrivateKey = Convert.FromBase64String(lines[lines.IndexOf("Recovery Private Key (base64):") + 1]);

        var keyring = DecodeKeyring(LoadConfig());
        var recovery = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        var viaRecovery = RecoverySlotWrap.Unwrap(recovery.Wrapped, recovery.PublicKey, recoveryPrivateKey,
            keyring.FormatVersion, keyring.VaultId, keyring.K, recovery.SlotId);

        Assert.Equal(Unlock(), viaRecovery);
    }

    [Fact]
    public void NoKeyPluggedIn_FailsAndWritesNothing()
    {
        _keys.PluggedIn = [];

        var (exit, _, stderr) = Run("", "init", "--keyring");

        Assert.NotEqual(0, exit);
        Assert.Contains("No YubiKey detected", stderr);
        Assert.False(File.Exists(Path.Combine(_dir, "config.json")));
    }

    [Fact]
    public void Reinit_BacksUpTheOldConfigAndVault()
    {
        _keys.PluggedIn = [SerialA];
        Assert.Equal(0, Run("", "init", "--keyring").Exit);
        var oldConfig = File.ReadAllText(Path.Combine(_dir, "config.json"));

        Assert.Equal(0, Run("yes\n", "init", "--keyring").Exit);

        var backup = Assert.Single(Directory.GetFiles(_dir, "config.json.bak-*"));
        Assert.Equal(oldConfig, File.ReadAllText(backup));
        Assert.Single(Directory.GetFiles(_dir, "secrets.json.enc.bak-*"));
    }
}
