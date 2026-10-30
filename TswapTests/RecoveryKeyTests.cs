using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T5 item 4 (decision 3, issue #187): the recovery private key unlocks. It is read only
/// from stdin (<c>--recovery-key-stdin</c> for <c>slot add</c>, <c>slot approve</c> and
/// <c>slot merge</c>; always for the new <c>recover</c>), a bad key gets one actionable error and
/// writes nothing, and a key on argv is never accepted.
/// </summary>
public class RecoveryKeyTests : IDisposable
{
    private const int SerialA = 11111111;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly List<FleetMachine> _machines = [];
    private readonly FleetMachine _router;
    private string _recoveryKey = "";

    public RecoveryKeyTests()
    {
        _keys.PluggedIn = [];
        _router = Machine("router", tpm: RandomNumberGenerator.GetBytes(32));
    }

    public void Dispose()
    {
        foreach (var m in _machines) m.Dispose();
    }

    private FleetMachine Machine(string name, byte[]? tpm = null, byte[]? secureEnclave = null)
    {
        var m = new FleetMachine(name, _keys) { Tpm = tpm, SecureEnclave = secureEnclave };
        _machines.Add(m);
        return m;
    }

    private static string RecoveryKeyFrom(string initOutput)
    {
        var lines = initOutput.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        return lines[lines.IndexOf("Recovery Private Key (base64):") + 1];
    }

    private void RouterVault()
    {
        _recoveryKey = RecoveryKeyFrom(_router.Ok("", "init", "--tpm"));
        _router.Ok("router-pw\nrouter-pw\n", "add", "router");
    }

    private string Stdin => _recoveryKey + "\n";

    // --- route C: a YubiKey slot for the router's vault, made on the desktop ---

    [Fact]
    public void RouteC_SlotAddOnACopyWithTheRecoveryKey_MergedBack_RouterOpensWithTheKey()
    {
        RouterVault();
        var desktop = Machine("desktop");
        _router.CopyVaultTo(desktop);
        _keys.PluggedIn = [SerialA];

        desktop.Ok(Stdin, "slot", "add", "--yubikey", "--recovery-key-stdin");

        Assert.Equal(3, desktop.Keyring.Slots.Count);
        _keys.PluggedIn = [];
        _router.Ok("", "slot", "merge", desktop.ConfigPath, "--yes");
        Assert.Equal(desktop.Keyring.Slots.Select(s => s.SlotId), _router.Keyring.Slots.Select(s => s.SlotId));

        var tpm = _router.Tpm;
        _router.Tpm = null;
        _keys.PluggedIn = [SerialA];
        Assert.Equal("router-pw", _router.Get("router")); // the YubiKey alone
        _keys.PluggedIn = [];
        _router.Tpm = tpm;
        Assert.Equal("router-pw", _router.Get("router")); // the TPM still
    }

    // --- recover ---

    // T7 fix round 1 (GLM minor 5): recover explains the new key's touch posture before it records
    // the acknowledgement (before the config is written), and records it for that slot.
    [Fact]
    public void RecoverYubiKey_ExplainsTheTouchPosture_BeforeWritingTheAcknowledgement()
    {
        RouterVault();
        _router.Tpm = null;
        _keys.SetTouch(SerialA, false);
        _keys.PluggedIn = [SerialA];

        var (exit, text) = _router.RunInterleaved(Stdin, "recover", "--yubikey");

        Assert.True(exit == 0, text);
        var explained = text.IndexOf("any process running as you can unlock the vault while the key is plugged in", StringComparison.Ordinal);
        Assert.True(explained >= 0, text);
        Assert.True(explained < text.IndexOf("Previous config backed up to", StringComparison.Ordinal), text);
        Assert.True(explained < text.IndexOf("✓ Recovered", StringComparison.Ordinal), text);
        var newSlot = Convert.ToBase64String(_router.Keyring.Slots[2].SlotId);
        Assert.Equal("no-touch", _router.Config.AcknowledgedTouch![newSlot]);
    }

    [Fact]
    public void RecoverYubiKey_WithTheTpmLost_TheSecretsReadBack_AndTheRecoverySlotStays()
    {
        RouterVault();
        _router.Tpm = null; // the TPM is gone
        _keys.PluggedIn = [SerialA];
        var before = _router.ConfigText;

        var stdout = _router.Ok(Stdin, "recover", "--yubikey");

        Assert.Equal("router-pw", _router.Get("router"));
        var kinds = _router.Keyring.Slots.Select(s => s.Kind).ToList();
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery, SlotKind.Machine], kinds);
        Assert.Equal(SerialA, YubiKeySlotBlob.Decode(_router.Keyring.Slots[2].HwBlob!).Serial);
        Assert.Equal(before, File.ReadAllText(Assert.Single(_router.Backups)));
        Assert.Contains(SlotFingerprint.Compute(_router.Keyring.Slots[2].PublicKey), stdout);
        Assert.DoesNotContain(_recoveryKey, stdout);
    }

    [Fact]
    public void RecoverTpm_AfterTheTpmWasCleared_TheNewTpmOpensTheVault()
    {
        RouterVault();
        _router.Tpm = RandomNumberGenerator.GetBytes(32); // cleared: a new TPM key

        _router.Ok(Stdin, "recover", "--tpm");

        Assert.Equal("router-pw", _router.Get("router"));
        var config = _router.Config;
        Assert.Equal(HardwareBackend.Tpm, config.Backend);
        Assert.Equal(Convert.ToBase64String(_router.Keyring.Slots[^1].SlotId), config.KeyringSlotId);
        Assert.Contains(SlotKind.Recovery, _router.Keyring.Slots.Select(s => s.Kind));
        Assert.Empty(_keys.Challenges);
    }

    [Fact]
    public void RecoverSecureEnclave_OnAMacWithACopy_OpensWithTheSecureEnclave()
    {
        RouterVault();
        var mac = Machine("mac", secureEnclave: RandomNumberGenerator.GetBytes(32));
        _router.CopyVaultTo(mac);

        mac.Ok(Stdin, "recover", "--secure-enclave", "--with-touch", "--recovery-key-stdin");

        Assert.Equal(HardwareBackend.SecureEnclave, mac.Config.Backend);
        Assert.Equal("router-pw", mac.Get("router"));
    }

    // --- bad input ---

    public static TheoryData<string> Commands() =>
    [
        "recover --yubikey",
        "slot add --yubikey --recovery-key-stdin",
        "slot approve {request} {approve} --recovery-key-stdin",
        "slot merge {receipt} --recovery-key-stdin --yes",
    ];

    private string[] Args(string command, FleetMachine joiner) => command
        .Replace("{request}", joiner.PathOf("request.json"))
        .Replace("{approve}", joiner.PathOf("approve.json"))
        .Replace("{receipt}", joiner.PathOf("approve.json.receipt.json"))
        .Split(' ');

    /// <summary>A joiner with a request (and, for merge, a receipt) ready, so each command can run.</summary>
    private FleetMachine JoinerWithReceipt()
    {
        var joiner = Machine("joiner", tpm: RandomNumberGenerator.GetBytes(32));
        joiner.Ok("", "slot", "request", "--tpm", joiner.PathOf("request.json"));
        _router.Ok("", "slot", "approve", joiner.PathOf("request.json"), joiner.PathOf("approve.json"));
        joiner.Ok("", "slot", "accept", joiner.PathOf("approve.json"));
        File.Delete(joiner.PathOf("approve.json")); // approve must write it again to count
        return joiner;
    }

    [Theory]
    [MemberData(nameof(Commands))]
    public void WrongTruncatedEmptyOrGarbageKeys_AreRefusedAlike_AndNothingIsWritten(string command)
    {
        RouterVault();
        var joiner = JoinerWithReceipt();
        _router.Tpm = null; // only the recovery key could open it
        _keys.PluggedIn = [SerialA];
        _keys.Challenges.Clear();
        var before = _router.ConfigText;
        var backups = _router.Backups;
        var anotherVaultsKey = RecoveryKeyFrom(Machine("other", tpm: RandomNumberGenerator.GetBytes(32)).Ok("", "init", "--tpm"));

        string[] inputs =
        [
            anotherVaultsKey + "\n",                                  // wrong
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), // wrong, random
            _recoveryKey[..^4] + "\n",                                 // truncated
            "",                                                        // empty
            "not base64 at all!\n",                                    // malformed
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)), // too long
        ];
        var errors = new List<string>();
        foreach (var input in inputs)
        {
            var (exit, stdout, stderr) = _router.Run(input, Args(command, joiner));
            Assert.NotEqual(0, exit);
            Assert.Equal(before, _router.ConfigText);
            Assert.Equal(backups, _router.Backups);
            Assert.False(File.Exists(joiner.PathOf("approve.json")));
            Assert.DoesNotContain(_recoveryKey, stdout + stderr);
            errors.Add(stderr);
        }

        Assert.Single(errors.Distinct()); // no oracle: one message for every bad key
        Assert.Contains("recovery key", errors[0]);
        Assert.Contains("--recovery-key-stdin", errors[0]); // actionable
        Assert.Empty(_keys.Challenges); // nothing enrolled
    }

    [Theory]
    [InlineData("recover", "--yubikey", "--recovery-key", "{key}")]
    [InlineData("recover", "--yubikey", "--recovery-key-stdin={key}")]
    [InlineData("recover", "--yubikey", "{key}")]
    [InlineData("slot", "add", "--yubikey", "--recovery-key", "{key}")]
    [InlineData("slot", "add", "--yubikey", "--recovery-key-stdin", "{key}")]
    [InlineData("slot", "merge", "x.json", "--recovery-key", "{key}")]
    public void AKeyOnArgv_IsNotAccepted_AndNothingIsWritten(params string[] template)
    {
        RouterVault();
        _router.Tpm = null;
        _keys.PluggedIn = [SerialA];
        var before = _router.ConfigText;
        var args = template.Select(a => a.Replace("{key}", _recoveryKey)).ToArray();

        var (exit, stdout, stderr) = _router.Run("", args);

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        Assert.DoesNotContain(_recoveryKey, stdout + stderr);
        Assert.Equal(before, _router.ConfigText);
        Assert.Empty(_router.Backups);
    }

    [Fact]
    public void AKeyInTheEnvironment_IsIgnored()
    {
        RouterVault();
        _router.Tpm = null;
        _keys.PluggedIn = [SerialA];
        var before = _router.ConfigText;
        Environment.SetEnvironmentVariable("TSWAP_RECOVERY_KEY", _recoveryKey);
        try
        {
            var (exit, _, stderr) = _router.Run("", "recover", "--yubikey");

            Assert.NotEqual(0, exit);
            Assert.Contains("recovery key", stderr);
            Assert.Equal(before, _router.ConfigText);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TSWAP_RECOVERY_KEY", null);
        }
    }

    [Fact]
    public void StdinOnATerminal_IsRefused_TheKeyMustBePiped()
    {
        RouterVault();
        _keys.PluggedIn = [SerialA];
        var before = _router.ConfigText;

        var (exit, _, stderr) = _router.RunOnTerminal(Stdin, "recover", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("pipe", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    // --- approve and merge with the recovery key ---

    [Fact]
    public void ApproveAndMerge_WithTheRecoveryKey_WhileTheTpmIsUnavailable()
    {
        RouterVault();
        var desktop = Machine("desktop");
        var tpm = _router.Tpm;
        _router.Tpm = null;
        _keys.PluggedIn = [SerialA];
        desktop.Ok("", "slot", "request", desktop.PathOf("request.json"));

        _router.Ok(Stdin, "slot", "approve", desktop.PathOf("request.json"), desktop.PathOf("approve.json"), "--recovery-key-stdin");
        desktop.Ok("", "slot", "accept", desktop.PathOf("approve.json"));
        _router.Ok(Stdin, "slot", "merge", desktop.PathOf("approve.json.receipt.json"), "--recovery-key-stdin");

        Assert.Null(_router.Config.ApprovedSlots); // approved by this machine, so merged silently
        Assert.Equal("router-pw", _router.Get("router")); // with the desktop's key
        _keys.PluggedIn = [];
        _router.Tpm = tpm;
        Assert.Equal("router-pw", _router.Get("router"));
    }

    // --- refusals before the key is read ---

    [Fact]
    public void Recover_OnAVaultWithoutARecoverySlot_IsRefused()
    {
        _router.Ok("", "init", "--tpm", "--no-recovery");
        var before = _router.ConfigText;
        _keys.PluggedIn = [SerialA];

        var (exit, _, stderr) = _router.Run("anything\n", "recover", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("no recovery slot", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    [Fact]
    public void Recover_OnAVersion2Keyring_IsRefusedWithTheExistingMessage()
    {
        File.WriteAllText(_router.ConfigPath, KeyringV2FixtureTests.FixtureConfigJson);

        var (exit, _, stderr) = _router.Run("anything\n", "recover", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("format version 2", stderr);
        Assert.Equal(KeyringV2FixtureTests.FixtureConfigJson, _router.ConfigText);
    }

    [Fact]
    public void Recover_WithoutSudo_IsRefused()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (see SlotCommandTests)

        RouterVault();
        _router.Sudo = false;
        _keys.PluggedIn = [SerialA];
        var before = _router.ConfigText;

        var (exit, _, stderr) = _router.Run(Stdin, "recover", "--yubikey");

        Assert.NotEqual(0, exit);
        Assert.Contains("recover", stderr);
        Assert.Contains("requires", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    [Theory]
    [InlineData("recover")]
    [InlineData("recover", "--yubikey", "--tpm")]
    [InlineData("recover", "--keyring")]
    public void RecoverWithoutExactlyOneDevice_IsAUsageError(params string[] args)
    {
        RouterVault();

        var (exit, _, stderr) = _router.Run(Stdin, args);

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
    }

    [Fact]
    public void InitsRecoveryWarning_NamesRecoverAndTheStdinFlag()
    {
        var stdout = _router.Ok("", "init", "--tpm");

        Assert.Contains("sudo tswap recover --yubikey", stdout);
        Assert.Contains("--recovery-key-stdin", stdout);
    }
}
