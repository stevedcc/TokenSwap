using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 6: <c>init --fido2</c> makes a keyring vault whose machine slot is a FIDO2 slot (plus the recovery
/// slot unless <c>--no-recovery</c>), with <c>Backend = YubiKey</c> written out. The key is <see cref="FakeFido2Keys"/>
/// through the real <see cref="Fido2Service"/>, the controlling terminal a <see cref="FakeTerminal"/>.
/// </summary>
public class InitFido2Tests : IDisposable
{
    private const int SerialA = 33060005;
    private const int SerialB = 33060006;
    private const string Pin = FakeFido2Keys.DefaultPin;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "tswap-init-fido2-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SimulatedYubiKeyService _otp = SimulatedYubiKeyService.WithKeys();
    private readonly FakeFido2Keys _fido2 = new();
    private FakeTerminal? _terminal = new();

    public InitFido2Tests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    private string Dir(string machine = "a") => Path.Combine(_root, machine);

    private (int Exit, string Out, string Err) Run(string dir, string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
        var ctx = new CommandContext(console, env, VaultStores.Open(dir), _otp, new VaultUnlocker(_otp), TestKey: null, SudoBypass: true)
        {
            Fido2 = new Fido2Service(_fido2),
            Terminal = () => _terminal?.Open(),
        };
        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    private static Config LoadConfig(string dir) => VaultStores.Open(dir).LoadConfig();

    private static Keyring DecodeKeyring(Config config) => KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

    private static Fido2SlotBlob Fido2Blob(Slot slot) =>
        Assert.IsType<YubiKeySlotKind.Fido2>(YubiKeySlotKinds.Classify(slot.HwBlob)).Blob;

    [Fact]
    public void InitFido2_WritesBackendYubiKey_AndAFido2Slot()
    {
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, stdout, stderr) = Run(Dir(), "", "init", "--fido2");

        Assert.True(exit == 0, stderr);
        var config = LoadConfig(Dir());
        Assert.Equal(HardwareBackend.YubiKey, config.Backend);
        // Written out, not left null: tswap 0.2.x then reads the slot as one it needs a newer tswap for.
        using (var raw = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(Dir(), "config.json"))))
            Assert.Equal("yubikey", raw.RootElement.GetProperty("Backend").GetString());
        Assert.Empty(config.YubiKeySerials);
        var keyring = DecodeKeyring(config);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));
        var machine = keyring.Slots[0];
        Assert.Equal(config.KeyringSlotId, Convert.ToBase64String(machine.SlotId));
        var blob = Fido2Blob(machine);
        Assert.Equal(SerialA, blob.Serial);
        Assert.True(_fido2.Holds(key, blob.CredentialId));

        // The FIDO2 slot and the recovery slot wrap the same vault key.
        var lines = stdout.ReplaceLineEndings("\n").Split('\n').ToList();
        var recoveryKey = Convert.FromBase64String(lines[lines.IndexOf("Recovery Private Key (base64):") + 1]);
        var vaultKey = RecoveryKeyUnlock.Unlock(keyring, recoveryKey);
        var kek = Fido2SlotKek.Derive(_fido2.UvOutput(blob.CredentialId, blob.PrfInput), blob.PrfInput, machine.SlotId);
        var payload = SlotPayloadWrap.Unwrap(machine.Wrapped, kek, keyring.FormatVersion, keyring.VaultId, keyring.K, machine.SlotId);
        Assert.Equal(vaultKey, SlotSecretPayload.Decode(payload).VaultKey);

        Assert.Equal([FakeFido2Op.MakeCredential, FakeFido2Op.GetHmacSecret], _fido2.Calls.Select(c => c.Op).Where(op => op != FakeFido2Op.Find));
        Assert.Contains(Fido2SlotEnrollment.ResetWarning($"YubiKey {SerialA}"), stdout);
        Assert.DoesNotContain(Fido2SlotEnrollment.MultiOsHint, stdout + stderr);
    }

    [Fact]
    public void InitFido2_NoRecovery_OneSlot()
    {
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run(Dir(), "", "init", "--fido2", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Equal([SlotKind.Machine], DecodeKeyring(LoadConfig(Dir())).Slots.Select(s => s.Kind));
    }

    [Fact]
    public void InitFido2_SeveralKeys_AsksOrUsesSerial()
    {
        var a = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(SerialB, Fido2TestSlots.Aaguid);

        _terminal = new FakeTerminal(Pin, Pin);
        var (exit, _, stderr) = Run(Dir("a"), "", "init", "--fido2", "--serial", SerialB.ToString());
        Assert.True(exit == 0, stderr);
        Assert.Equal(SerialB, Fido2Blob(DecodeKeyring(LoadConfig(Dir("a"))).Slots[0]).Serial);
        Assert.Equal(b.Ref, _fido2.Calls.Single(c => c.Op == FakeFido2Op.MakeCredential).Key);
        Assert.All(_terminal.Reads, r => Assert.True(r.Secret));

        _fido2.Calls.Clear();
        _terminal = new FakeTerminal("1", Pin, Pin);
        (exit, _, stderr) = Run(Dir("b"), "", "init", "--fido2");
        Assert.True(exit == 0, stderr);
        Assert.Equal(SerialA, Fido2Blob(DecodeKeyring(LoadConfig(Dir("b"))).Slots[0]).Serial);
        Assert.Equal(a.Ref, _fido2.Calls.Single(c => c.Op == FakeFido2Op.MakeCredential).Key);
        Assert.Contains($"2. YubiKey {SerialB}", _terminal.Reads[0].Prompt);
    }

    [Theory]
    [InlineData("--yubikey")]
    [InlineData("--tpm")]
    [InlineData("--secure-enclave")]
    public void InitFido2_WithYubiKeyFlag_Refused(string other)
    {
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        string[] args = other == "--secure-enclave" ? ["init", "--fido2", other, "--with-touch"] : ["init", "--fido2", other];

        var (exit, _, stderr) = Run(Dir(), "", args);

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        Assert.Contains("mutually exclusive", stderr);
        Assert.Empty(_fido2.Calls);
        Assert.False(File.Exists(Path.Combine(Dir(), "config.json")));
    }

    [Fact]
    public void InitSerialWithoutFido2_IsAUsageError()
    {
        var (exit, _, stderr) = Run(Dir(), "", "init", "--yubikey", "--serial", "1");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        Assert.Contains("--serial", stderr);
        Assert.False(File.Exists(Path.Combine(Dir(), "config.json")));
    }

    [Fact]
    public void InitFido2_NoTerminal_RefusedBeforeAnyKeyCall()
    {
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = null;

        var (exit, _, stderr) = Run(Dir(), "", "init", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2Texts.NoTerminal, stderr);
        Assert.Empty(_fido2.Calls);
        Assert.False(Directory.Exists(Path.Combine(Dir(), "vault")));
    }

    [Fact]
    public void InitFido2_Windows_DialogPicks_SerialRefused()
    {
        _fido2.CanList = false;
        _fido2.Picked = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);

        var (refused, _, refusal) = Run(Dir("a"), "", "init", "--fido2", "--serial", SerialA.ToString());
        Assert.NotEqual(0, refused);
        Assert.Contains("on Windows, Windows' dialog picks the key", refusal);
        Assert.Empty(_fido2.Calls);

        var (exit, stdout, stderr) = Run(Dir("b"), "", "init", "--fido2");
        Assert.True(exit == 0, stderr);
        Assert.Contains(Fido2SlotEnrollment.WindowsDialogLine, stdout);
        Assert.Empty(_terminal!.Reads);
        // Windows doesn't say which key answered: no serial, the model's AAGUID.
        var blob = Fido2Blob(DecodeKeyring(LoadConfig(Dir("b"))).Slots[0]);
        Assert.Null(blob.Serial);
        Assert.Equal(Fido2TestSlots.Aaguid, blob.Aaguid);
    }

    [Fact]
    public void InitFido2_InterruptedAfterMakeCredential_WritesNothing()
    {
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _fido2.FailNext(FakeFido2Op.GetHmacSecret, Fido2Failure.TimedOut, afterPin: true);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run(Dir(), "", "init", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2SlotEnrollment.RetrySafeText, stderr);
        Assert.False(File.Exists(Path.Combine(Dir(), "config.json")));
        Assert.False(Directory.Exists(Path.Combine(Dir(), "vault")));
    }

    [Fact]
    public void InitFido2_RandomSlotIdPerVault()
    {
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin, Pin, Pin);
        Assert.Equal(0, Run(Dir("a"), "", "init", "--fido2").Exit);
        Assert.Equal(0, Run(Dir("b"), "", "init", "--fido2").Exit);

        var first = DecodeKeyring(LoadConfig(Dir("a"))).Slots[0];
        var second = DecodeKeyring(LoadConfig(Dir("b"))).Slots[0];
        Assert.False(CryptographicOperations.FixedTimeEquals(first.SlotId, second.SlotId));
        Assert.NotEqual(Fido2Blob(first).CredentialId, Fido2Blob(second).CredentialId);
    }
}
