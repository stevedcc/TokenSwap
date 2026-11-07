using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 6: <c>slot add --fido2</c> on a YubiKey OTP vault, with the FIDO2 key played by
/// <see cref="FakeFido2Keys"/> (through the real <see cref="Fido2Service"/>) and the controlling terminal by
/// <see cref="FakeTerminal"/>. The vault opens with the simulated OTP key, or with the recovery key on stdin.
/// </summary>
public class SlotAddFido2Tests : IDisposable
{
    private const int OtpSerial = 11111111;
    private const int SerialA = 33060005;
    private const int SerialB = 33060006;
    private const string Pin = FakeFido2Keys.DefaultPin;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-slot-add-fido2-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SimulatedYubiKeyService _otp = SimulatedYubiKeyService.WithKeys(OtpSerial);
    private readonly FakeFido2Keys _fido2 = new();
    private FakeTerminal? _terminal = new();
    private byte[] _recoveryKey = [];

    public SlotAddFido2Tests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    private bool _sudoBypass = true;

    private CommandContext Context(FakeConsole console, string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var unlocker = new VaultUnlocker(_otp, overrideKey: null);
        return new CommandContext(console, env, VaultStores.Open(_dir), _otp, unlocker, TestKey: null, SudoBypass: _sudoBypass)
        {
            Fido2 = new Fido2Service(_fido2),
            Terminal = () => _terminal?.Open(),
        };
    }

    private (int Exit, string Out, string Err) Run(string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var exit = CliRunner.Run(Context(console, args), args);
        return (exit, console.OutText, console.ErrorText);
    }

    /// <summary>A YubiKey OTP vault (key <see cref="OtpSerial"/> and the recovery slot) holding one secret.</summary>
    private void OtpVault()
    {
        var (exit, stdout, stderr) = Run("", "init", "--yubikey");
        Assert.True(exit == 0, stderr);
        var lines = stdout.ReplaceLineEndings("\n").Split('\n').ToList();
        _recoveryKey = Convert.FromBase64String(lines[lines.IndexOf("Recovery Private Key (base64):") + 1]);
        Assert.Equal(0, Run("s3cret\ns3cret\n", "add", "db-password").Exit);
    }

    private Keyring Keyring() => KeyringCodec.Decode(Convert.FromBase64String(VaultStores.Open(_dir).LoadConfig().Keyring!));

    private byte[] VaultKey() => RecoveryKeyUnlock.Unlock(Keyring(), _recoveryKey);

    private (Slot Slot, Fido2SlotBlob Blob) Fido2Slot() => Keyring().Slots
        .Select(s => (Slot: s, Kind: YubiKeySlotKinds.Classify(s.HwBlob)))
        .Where(x => x.Kind is YubiKeySlotKind.Fido2)
        .Select(x => (x.Slot, ((YubiKeySlotKind.Fido2)x.Kind).Blob))
        .Single();

    /// <summary>The vault key the slot's wrap gives under <paramref name="kek"/>, or null when the KEK doesn't open it.</summary>
    private static byte[]? Unwrap(Keyring keyring, Slot slot, byte[] kek)
    {
        try
        {
            var payload = SlotPayloadWrap.Unwrap(slot.Wrapped, kek, keyring.FormatVersion, keyring.VaultId, keyring.K, slot.SlotId);
            return SlotSecretPayload.Decode(payload).VaultKey;
        }
        catch (Exception e) when (e is CryptographicException or TswapException)
        {
            return null;
        }
    }

    /// <summary>Every file under the config folder (the vault folder included), with its bytes, sorted by path.</summary>
    private List<KeyValuePair<string, string>> Snapshot() => [.. Directory
        .GetFiles(_dir, "*", SearchOption.AllDirectories)
        .Select(f => KeyValuePair.Create(Path.GetRelativePath(_dir, f), Convert.ToHexString(File.ReadAllBytes(f))))
        .OrderBy(kv => kv.Key, StringComparer.Ordinal)];

    private List<FakeFido2Op> Ops() => [.. _fido2.Calls.Select(c => c.Op)];

    private static string PinPrompt(int serial) => $"FIDO2 PIN for YubiKey {serial}: ";

    [Fact]
    public void SlotAddFido2_AddsASlotThatOpensTheVault()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        var keyring = Keyring();
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery, SlotKind.Machine], keyring.Slots.Select(s => s.Kind));
        var (slot, blob) = Fido2Slot();
        Assert.Equal(keyring.Slots[2].SlotId, slot.SlotId);
        Assert.Equal(SerialA, blob.Serial);
        Assert.False(blob.RequiresPassword);
        var output = _fido2.UvOutput(blob.CredentialId, blob.PrfInput);
        Assert.Equal(VaultKey(), Unwrap(keyring, slot, Fido2SlotKek.Derive(output, blob.PrfInput, slot.SlotId)));
        Assert.Contains($"YubiKey {SerialA}", stdout);
        Assert.Contains($"fingerprint: {SlotFingerprint.Compute(slot.PublicKey)}", stdout);
        Assert.Single(Directory.GetFiles(_dir, "config.json.bak-*"));
        // The OTP key still opens the vault as before.
        Assert.Equal("s3cret", Run("", "get", "db-password").Out.Trim());
    }

    [Fact]
    public void SlotAddFido2_TwoPinTouches_ThenWrite()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        var before = Snapshot();
        var onDiskAtEachKeyCall = new List<(FakeFido2Op Op, bool Unchanged)>();
        _fido2.OnCall = call => onDiskAtEachKeyCall.Add((call.Op, Snapshot().SequenceEqual(before)));

        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");

        // Nothing on disk changed until the second key call was made (the write comes after it).
        Assert.All(onDiskAtEachKeyCall, call => Assert.True(call.Unchanged, $"the vault changed before {call.Op}"));
        Assert.True(exit == 0, stderr);
        Assert.Equal([FakeFido2Op.MakeCredential, FakeFido2Op.GetHmacSecret], Ops().Where(op => op != FakeFido2Op.Find));
        Assert.NotEqual(before, Snapshot());
        // Each operation: a PIN at the terminal and a touch.
        Assert.Equal([(true, PinPrompt(SerialA)), (true, PinPrompt(SerialA))], _terminal.Reads);
        // The touch line is a notice: stderr (final review, task 7 ruling).
        Assert.Equal(2, CountOf(stderr, Fido2SlotEnrollment.TouchLine));
        Assert.DoesNotContain(Fido2SlotEnrollment.TouchLine, stdout);
        Assert.Equal(2, _fido2.DevicePinCalls.Count);
    }

    [Fact]
    public void SlotAddFido2_TouchLineAfterEachPinPrompt()
    {
        // FIDO2 plan, task 8 (carry-forward 5): on Linux and macOS the PIN prompt comes first, then the touch line.
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        var console = new FakeConsole("");
        List<int> touchLinesAtEachRead = [];
        _terminal.OnRead = () => touchLinesAtEachRead.Add(CountOf(console.ErrorText, Fido2SlotEnrollment.TouchLine));
        string[] args = ["slot", "add", "--fido2"];

        var exit = CliRunner.Run(Context(console, args), args);

        Assert.True(exit == 0, console.ErrorText);
        Assert.Equal([0, 1], touchLinesAtEachRead);
        Assert.Equal(2, CountOf(console.ErrorText, Fido2SlotEnrollment.TouchLine));
    }

    [Fact]
    public void SlotAddFido2_CancelledPin_NoTouchLine()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal("");

        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2Texts.Cancelled($"YubiKey {SerialA}"), stderr);
        Assert.DoesNotContain(Fido2SlotEnrollment.TouchLine, stdout + stderr);
    }

    [Fact]
    public void SlotAddFido2_NoTerminal_RefusedBeforeAnyKeyCall()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = null;
        var before = Snapshot();
        _otp.Challenges.Clear();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2Texts.NoTerminal, stderr);
        Assert.Empty(_fido2.Calls);
        Assert.Empty(_otp.Challenges); // refused before the vault was unlocked
        Assert.Equal(before, Snapshot());
    }

    // Final review (pins): Windows (no listing) without a terminal refuses before any key call or unlock too.
    [Fact]
    public void SlotAddFido2_Windows_NoTerminal_RefusedBeforeAnyKeyCall()
    {
        OtpVault();
        _fido2.CanList = false;
        _fido2.Picked = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = null;
        var before = Snapshot();
        _otp.Challenges.Clear();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2Texts.NoTerminal, stderr);
        Assert.Empty(_fido2.Calls);
        Assert.Empty(_otp.Challenges);
        Assert.Equal(before, Snapshot());
    }

    // The PIN is never shown: not on stdout, stderr or the terminal; the new PIN of a key without one is read as a
    // secret; and every terminal the command opened was closed again.
    [Fact]
    public void SlotAddFido2_PinNeverShown_SetPinReadsSecret_TerminalClosed()
    {
        const string pin = "Qx7-pin-9Zr";
        OtpVault();
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid, pin: null);
        _terminal = new FakeTerminal("yes", pin, pin, pin, pin);

        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        Assert.Equal(pin, key.Pin);
        Assert.DoesNotContain(pin, stdout + stderr + _terminal.Text);
        Assert.False(_terminal.Reads[0].Secret); // the yes/no question
        Assert.All(_terminal.Reads.Skip(1), r => Assert.True(r.Secret, r.Prompt)); // the new PIN twice, then the PINs
        Assert.True(_terminal.Opens > 0);
        Assert.Equal(_terminal.Opens, _terminal.Disposals);
    }

    // With two FIDO2 slots in the vault, a third enrolment's exclude list carries both credentials.
    [Fact]
    public void SlotAddFido2_ThirdEnrolment_ExcludesBothSlots()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        Assert.Equal(0, Run("", "slot", "add", "--fido2", "--serial", SerialA.ToString()).Exit);
        _fido2.AddKey(SerialB, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        Assert.Equal(0, Run("", "slot", "add", "--fido2", "--serial", SerialB.ToString()).Exit);
        var enrolled = Keyring().Slots
            .Select(s => YubiKeySlotKinds.Classify(s.HwBlob)).OfType<YubiKeySlotKind.Fido2>().Select(f => f.Blob.CredentialId).ToList();
        Assert.Equal(2, enrolled.Count);
        _fido2.AddKey(33060007, Fido2TestSlots.Aaguid);
        _fido2.Calls.Clear();
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2", "--serial", "33060007");

        Assert.True(exit == 0, stderr);
        var excluded = _fido2.Calls.Single(c => c.Op == FakeFido2Op.MakeCredential).CredentialIds;
        Assert.Equal(enrolled.Select(Convert.ToHexString).Order(), excluded.Select(Convert.ToHexString).Order());
    }

    // Final review (MiMo p6a): the no-terminal and --serial-on-Windows refusals come before the sudo check, as in init.
    [Fact]
    public void SlotAddFido2_NoTerminal_RefusedBeforeTheSudoCheck()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = null;
        _sudoBypass = false;

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2Texts.NoTerminal, stderr);
        Assert.DoesNotContain("requires", stderr);
    }

    [Fact]
    public void SlotAddFido2_Windows_SerialRefusedBeforeTheSudoCheck()
    {
        OtpVault();
        _fido2.CanList = false;
        _fido2.Picked = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _sudoBypass = false;

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2", "--serial", SerialA.ToString());

        Assert.NotEqual(0, exit);
        Assert.Contains("on Windows, Windows' dialog picks the key", stderr);
        Assert.DoesNotContain("requires", stderr);
    }

    // Final review (MiMo p6a): the second key operation's failure keeps its type and kind, with the device failure
    // inside, when the retry-safe text is added.
    [Fact]
    public void Enroll_SecondOperationFails_KeepsTheFido2ExceptionAndItsCause()
    {
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _fido2.FailNext(FakeFido2Op.GetHmacSecret, Fido2Failure.TimedOut, afterPin: true);
        _terminal = new FakeTerminal(Pin, Pin);
        var ctx = Context(new FakeConsole(""), ["slot", "add", "--fido2"]);
        var key = Assert.Single(ctx.Fido2!.ListYubiKeys());

        var e = Assert.Throws<Fido2Exception>(() =>
            Fido2SlotEnrollment.Enroll(ctx, key, RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize), [], null));

        Assert.Equal(Fido2Failure.TimedOut, e.Kind);
        Assert.Equal(SerialA, e.Serial);
        Assert.EndsWith(" " + Fido2SlotEnrollment.RetrySafeText, e.Message);
        var cause = Assert.IsType<Fido2Exception>(e.InnerException);
        Assert.Equal(Fido2Texts.TimedOut($"YubiKey {SerialA}"), cause.Message);
    }

    [Fact]
    public void RetrySafeText_IsYubiKeysOwn() =>
        Assert.Equal("No slot was added and nothing was written. The key may keep an unused credential (a YubiKey stores " +
                     "nothing for it: its ID is the wrapped key), so running this again is safe.",
            Fido2SlotEnrollment.RetrySafeText);

    // Final review (MiMo p6a): a new PIN longer than CTAP2's 63 bytes is asked again before anything is sent.
    [Fact]
    public void SlotAddFido2_NewPinOver63Bytes_AskedAgain()
    {
        OtpVault();
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid, pin: null);
        var tooLong = new string('7', 64);
        _terminal = new FakeTerminal("yes", tooLong, "4321", "4321", "4321", "4321");

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        Assert.Equal("4321", key.Pin);
        Assert.Contains(TswapCli.Fido2PinPrompt.TooLongText, _terminal.Reads[2].Prompt);
        Assert.Single(_fido2.Calls, c => c.Op == FakeFido2Op.SetPin);
    }

    [Fact]
    public void SlotAddFido2_UnlockFails_NoKeyCall()
    {
        OtpVault();
        _otp.PluggedIn = []; // no other way in: no OTP key, no recovery key, no agent
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        var before = Snapshot();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", stderr);
        // Before the unlock only silent calls (the listing, and the duplicate probe when the vault has FIDO2 slots):
        // no PIN, no touch, no credential made.
        Assert.All(Ops(), op => Assert.True(op is FakeFido2Op.Find or FakeFido2Op.FindHolder, $"{op} before the unlock"));
        Assert.Empty(_fido2.DevicePinCalls);
        Assert.Empty(_terminal.Reads);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void SlotAddFido2_VaultWithoutKeyring_NamesInitFido2()
    {
        File.WriteAllText(Path.Combine(_dir, "config.json"), System.Text.Json.JsonSerializer.Serialize(
            new Config([], "", DateTime.UtcNow), TswapJsonContext.Default.Config));

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains("This vault has no keyring", stderr);
        Assert.Contains("'tswap init --fido2'", stderr);
        Assert.Empty(_fido2.Calls);
    }

    [Fact]
    public void SlotAddFido2_NoPin_OffersToSetOne()
    {
        OtpVault();
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid, pin: null);
        // yes; a mismatch (asked again); the new PIN twice; then the PIN for each of the two key operations.
        _terminal = new FakeTerminal("yes", "1111", "2222", "4321", "4321", "4321", "4321");

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        Assert.Equal("4321", key.Pin);
        Assert.Equal([FakeFido2Op.SetPin, FakeFido2Op.MakeCredential, FakeFido2Op.GetHmacSecret], Ops().Where(op => op != FakeFido2Op.Find));
        Assert.Equal(3, _fido2.PinBuffers.Count); // one new PIN (typed twice alike), then one PIN per operation
        var prompts = _terminal.Reads.Select(r => r.Prompt).ToList();
        Assert.Contains("no FIDO2 PIN", prompts[0]);
        Assert.False(_terminal.Reads[0].Secret);
        Assert.Contains("New FIDO2 PIN", prompts[1]);
        Assert.Contains("differ", prompts[3]); // the mismatch is said, and the new PIN asked again
        Assert.Contains("New FIDO2 PIN", prompts[3]);
        Assert.Equal(PinPrompt(SerialA), prompts[5]);
        Assert.Equal(PinPrompt(SerialA), prompts[6]);
        Assert.NotNull(Fido2Slot().Blob);
    }

    [Fact]
    public void SlotAddFido2_NoPin_DeclinedWritesNothing()
    {
        OtpVault();
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid, pin: null);
        _terminal = new FakeTerminal("no");
        var before = Snapshot();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains("No slot was added", stderr);
        Assert.Null(key.Pin);
        Assert.DoesNotContain(FakeFido2Op.SetPin, Ops());
        Assert.DoesNotContain(FakeFido2Op.MakeCredential, Ops());
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void SlotAddFido2_SeveralKeys_UsesSerialOrAsks()
    {
        OtpVault();
        var a = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(SerialB, Fido2TestSlots.Aaguid);

        // --serial picks the key without a question.
        _terminal = new FakeTerminal(Pin, Pin);
        var (exit, _, stderr) = Run("", "slot", "add", "--fido2", "--serial", SerialB.ToString());
        Assert.True(exit == 0, stderr);
        Assert.Equal(b.Ref, _fido2.Calls.Single(c => c.Op == FakeFido2Op.MakeCredential).Key);
        Assert.All(_terminal.Reads, r => Assert.True(r.Secret)); // only PINs were asked

        // Without it, the terminal asks which.
        _fido2.Calls.Clear();
        _terminal = new FakeTerminal("1", Pin, Pin);
        (exit, _, stderr) = Run("", "slot", "add", "--fido2");
        Assert.True(exit == 0, stderr);
        Assert.Equal(a.Ref, _fido2.Calls.Single(c => c.Op == FakeFido2Op.MakeCredential).Key);
        var question = _terminal.Reads[0];
        Assert.False(question.Secret);
        Assert.Contains($"1. YubiKey {SerialA}", question.Prompt);
        Assert.Contains($"2. YubiKey {SerialB}", question.Prompt);

        // A serial that isn't plugged in is refused before any PIN.
        _fido2.Calls.Clear();
        _terminal = new FakeTerminal(Pin, Pin);
        (exit, _, stderr) = Run("", "slot", "add", "--fido2", "--serial", "44444444");
        Assert.NotEqual(0, exit);
        Assert.Contains("44444444", stderr);
        Assert.Empty(_terminal.Reads);
        Assert.DoesNotContain(FakeFido2Op.MakeCredential, Ops());
    }

    [Fact]
    public void SlotAddFido2_KeyWithASlotAlready_Refused()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        Assert.Equal(0, Run("", "slot", "add", "--fido2").Exit);
        var before = Snapshot();
        _fido2.Calls.Clear();
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA}: this key already has a FIDO2 slot in this vault", stderr);
        Assert.Contains("`tswap slots`", stderr);
        Assert.Contains(FakeFido2Op.FindHolder, Ops());
        Assert.DoesNotContain(FakeFido2Op.MakeCredential, Ops());
        Assert.Empty(_terminal.Reads); // found by the silent probe, before any PIN
        Assert.Equal(before, Snapshot());
    }

    // Final review (carry-forward 2): where keys can be listed, a key that already holds one of this vault's FIDO2
    // credentials is refused by the silent probe before the vault is unlocked: no PIN, no touch, no unlock.
    [Fact]
    public void SlotAddFido2_KeyWithASlotAlready_RefusedBeforeUnlock()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        Assert.Equal(0, Run("", "slot", "add", "--fido2").Exit);
        var before = Snapshot();
        _fido2.Calls.Clear();
        _fido2.DevicePinCalls.Clear();
        _otp.Challenges.Clear();
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA}: this key already has a FIDO2 slot in this vault", stderr);
        Assert.Empty(_otp.Challenges); // the vault was not unlocked
        Assert.Empty(_terminal.Reads); // no PIN read
        Assert.Empty(_fido2.DevicePinCalls);
        Assert.All(Ops(), op => Assert.True(op is FakeFido2Op.Find or FakeFido2Op.FindHolder, $"{op} before the refusal"));
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void SlotAddFido2_SerialLessKey_DuplicateRefused()
    {
        OtpVault();
        _fido2.AddKey(serial: null, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");
        Assert.True(exit == 0, stderr);
        Assert.Null(Fido2Slot().Blob.Serial);
        Assert.Contains(Fido2TestSlots.ModelName, stdout);
        var before = Snapshot();
        _terminal = new FakeTerminal(Pin, Pin);

        (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains($"{Fido2TestSlots.ModelName}: this key already has a FIDO2 slot in this vault", stderr);
        Assert.Empty(_terminal.Reads);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void SlotAddFido2_KekIsDerivedFromOpenOutput()
    {
        OtpVault();
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        var keyring = Keyring();
        var (slot, blob) = Fido2Slot();
        // The second key call asked for exactly the new credential: the assertion whose output is the KEK's input.
        var made = _fido2.Calls.Single(c => c.Op == FakeFido2Op.MakeCredential);
        var asked = _fido2.Calls.Single(c => c.Op == FakeFido2Op.GetHmacSecret);
        Assert.Equal(key.Ref, asked.Key);
        Assert.Equal(blob.CredentialId, Assert.Single(asked.CredentialIds));
        Assert.Empty(made.CredentialIds); // no FIDO2 slot yet: an empty exclude list
        var uv = _fido2.UvOutput(blob.CredentialId, blob.PrfInput);
        Assert.Equal(VaultKey(), Unwrap(keyring, slot, Fido2SlotKek.Derive(uv, blob.PrfInput, slot.SlotId)));
        // Not the output without user verification, nor another slot id: the composition is exact.
        Assert.Null(Unwrap(keyring, slot, Fido2SlotKek.Derive(_fido2.NonUvOutput(blob.CredentialId, blob.PrfInput), blob.PrfInput, slot.SlotId)));
        Assert.Null(Unwrap(keyring, slot, Fido2SlotKek.Derive(uv, blob.PrfInput, keyring.Slots[0].SlotId)));
        // The output the service handed back was zeroed after the derivation.
        Assert.All(_fido2.LastOutput!, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SlotAddFido2_RecoveryKeyStdin_PinFromTty()
    {
        OtpVault();
        _otp.PluggedIn = []; // only the recovery key opens the vault
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, _, stderr) = Run(Convert.ToBase64String(_recoveryKey) + "\n", "slot", "add", "--fido2", "--recovery-key-stdin");

        Assert.True(exit == 0, stderr);
        Assert.Equal([(true, PinPrompt(SerialA)), (true, PinPrompt(SerialA))], _terminal.Reads);
        var (slot, blob) = Fido2Slot();
        var output = _fido2.UvOutput(blob.CredentialId, blob.PrfInput);
        Assert.Equal(VaultKey(), Unwrap(Keyring(), slot, Fido2SlotKek.Derive(output, blob.PrfInput, slot.SlotId)));
    }

    [Fact]
    public void SlotAddFido2_InterruptedAfterMakeCredential_WritesNothingSaysRetrySafe()
    {
        OtpVault();
        var key = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _fido2.FailNext(FakeFido2Op.GetHmacSecret, Fido2Failure.Cancelled, afterPin: true);
        _terminal = new FakeTerminal(Pin, Pin);
        var before = Snapshot();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains(Fido2Texts.Cancelled($"YubiKey {SerialA}"), stderr);
        Assert.Contains(Fido2SlotEnrollment.RetrySafeText, stderr);
        Assert.Equal(before, Snapshot());
        Assert.Equal([FakeFido2Op.MakeCredential, FakeFido2Op.GetHmacSecret], Ops().Where(op => op != FakeFido2Op.Find));

        // Running it again is safe: the unused credential is no slot of this vault, so nothing refuses the key.
        _terminal = new FakeTerminal(Pin, Pin);
        var (again, _, againErr) = Run("", "slot", "add", "--fido2");
        Assert.True(again == 0, againErr);
        Assert.True(_fido2.Holds(key, Fido2Slot().Blob.CredentialId));
    }

    [Fact]
    public void SlotAddFido2_Windows_LeavesPinCreationToTheDialog()
    {
        OtpVault();
        _fido2.CanList = false;
        _fido2.Picked = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid, pin: null);
        _terminal = new FakeTerminal();

        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        Assert.Contains(Fido2SlotEnrollment.WindowsDialogLine, stdout);
        Assert.Contains("create one", Fido2SlotEnrollment.WindowsDialogLine);
        Assert.Empty(_terminal.Reads); // no set-PIN question, no PIN prompt: Windows' dialog asks
        Assert.Equal([FakeFido2Op.MakeCredential, FakeFido2Op.GetHmacSecret], Ops());
        Assert.All(_fido2.Calls, c => Assert.Null(c.Key));
        Assert.Equal(2, CountOf(stderr, Fido2SlotEnrollment.WindowsTouchLine));
        Assert.DoesNotContain(Fido2SlotEnrollment.WindowsTouchLine, stdout);
        Assert.DoesNotContain(Fido2SlotEnrollment.TouchLine, stdout + stderr);
        var (slot, blob) = Fido2Slot();
        var output = _fido2.UvOutput(blob.CredentialId, blob.PrfInput);
        Assert.Equal(VaultKey(), Unwrap(Keyring(), slot, Fido2SlotKek.Derive(output, blob.PrfInput, slot.SlotId)));
    }

    [Fact]
    public void SlotAddFido2_Windows_SerialRefused()
    {
        OtpVault();
        _fido2.CanList = false;
        _fido2.Picked = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        var before = Snapshot();
        _otp.Challenges.Clear();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2", "--serial", SerialA.ToString());

        Assert.NotEqual(0, exit);
        Assert.Contains("on Windows, Windows' dialog picks the key", stderr);
        Assert.Empty(_fido2.Calls);
        Assert.Empty(_otp.Challenges);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void SlotAddFido2_Windows_DuplicateRefusedByExcludeList()
    {
        OtpVault();
        _fido2.CanList = false;
        _fido2.Picked = _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        Assert.Equal(0, Run("", "slot", "add", "--fido2").Exit);
        var first = Fido2Slot().Blob;
        var before = Snapshot();
        _fido2.Calls.Clear();

        var (exit, _, stderr) = Run("", "slot", "add", "--fido2");

        Assert.NotEqual(0, exit);
        Assert.Contains("this key already has a FIDO2 slot in this vault", stderr);
        var made = Assert.Single(_fido2.Calls);
        Assert.Equal(FakeFido2Op.MakeCredential, made.Op);
        Assert.Equal(first.CredentialId, Assert.Single(made.CredentialIds));
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void SlotAddFido2_WithPassword_UsesV2Kek()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);
        const string password = "a long vault password";

        var (exit, _, stderr) = Run($"{password}\n{password}\n", "slot", "add", "--fido2", "--password");

        Assert.True(exit == 0, stderr);
        var keyring = Keyring();
        var (slot, blob) = Fido2Slot();
        Assert.True(blob.RequiresPassword);
        var file = ((RecordVaultStore)VaultStores.Open(_dir)).ReadVaultPassword(keyring.VaultId)!;
        using var stretched = VaultPasswordKdf.Stretch(password, file.Salt, file.Params);
        var output = _fido2.UvOutput(blob.CredentialId, blob.PrfInput);
        Assert.Equal(VaultKey(), Unwrap(keyring, slot, Fido2SlotKek.DeriveV2(output, stretched, blob.PrfInput, slot.SlotId)));
        Assert.Null(Unwrap(keyring, slot, Fido2SlotKek.Derive(output, blob.PrfInput, slot.SlotId)));
    }

    [Fact]
    public void SlotAddFido2_SaysAResetKillsTheSlot()
    {
        OtpVault();
        _fido2.AddKey(SerialA, Fido2TestSlots.Aaguid);
        _terminal = new FakeTerminal(Pin, Pin);

        var (exit, stdout, stderr) = Run("", "slot", "add", "--fido2");

        Assert.True(exit == 0, stderr);
        var warning = Fido2SlotEnrollment.ResetWarning($"YubiKey {SerialA}");
        Assert.Contains(warning, stdout);
        Assert.Contains("FIDO2 reset", warning);
        Assert.Contains("deletes", warning);
        Assert.Contains("tswap slot add --fido2", warning);
        // A FIDO2 enrolment gets no OTP hint.
        Assert.DoesNotContain(Fido2SlotEnrollment.MultiOsHint, stdout + stderr);
    }

    [Fact]
    public void SlotAddFido2_SerialWithYubiKeyFlag_IsAUsageError()
    {
        OtpVault();
        var (exit, _, stderr) = Run("", "slot", "add", "--yubikey", "--serial", "1");
        Assert.NotEqual(0, exit);
        Assert.Contains("slot add --yubikey|--fido2", stderr);
        Assert.Empty(_fido2.Calls);
    }

    [Fact]
    public void OtpEnrolment_EndsWithMultiOsHint()
    {
        var hint = Fido2SlotEnrollment.MultiOsHint;
        Assert.Contains("Input Monitoring", hint);
        Assert.Contains("Mac", hint);
        Assert.Contains("udev rule", hint);
        Assert.Contains("Linux", hint);
        Assert.Contains("tswap slot add --fido2", hint);

        // init --yubikey: the enrolment's notes on stderr end with the hint.
        var (exit, _, stderr) = Run("", "init", "--yubikey");
        Assert.True(exit == 0, stderr);
        Assert.Equal(hint, LastLine(stderr));

        // slot add --yubikey likewise.
        var second = SimulatedYubiKeyService.WithKeys(OtpSerial, 22222222); // the vault's key and a new one, both plugged in
        var console = new FakeConsole();
        string[] args = ["slot", "add", "--yubikey"];
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var ctx = new CommandContext(console, env, VaultStores.Open(_dir), second, new VaultUnlocker(second, overrideKey: null), null, true);
        Assert.True(CliRunner.Run(ctx, args) == 0, console.ErrorText);
        Assert.Equal(hint, LastLine(console.ErrorText));
    }

    private static string LastLine(string text) =>
        text.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries)[^1];

    private static int CountOf(string text, string part)
    {
        var count = 0;
        for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
}
