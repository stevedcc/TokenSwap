using System.Security.Cryptography;
using System.Text;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 2 rows 5 and 6: the unlocker's classification keeps FIDO2 slots apart from the OTP slots. Task 7:
/// the fourth, last pass that tries them (PIN and touch), with the FIDO2 key played by <see cref="FakeFido2Keys"/>
/// through the real <see cref="Fido2Service"/>, simulated TPMs and simulated OTP keys.
/// </summary>
public class VaultUnlockerFido2Tests
{
    private const int OtpSerial = 11111111;

    [Fact]
    public void Classify_Fido2NotAnOtpCandidate()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(OtpSerial), OtpSerial);
        var fido2Blob = Fido2TestSlots.Blob(requiresPassword: true);
        var fido2 = slots.AddFido2(fido2Blob);
        slots.AddRecovery();

        var plan = VaultUnlocker.Classify(slots.Config(own: otp), slots.Keyring, excludeSerial: null);

        var candidate = Assert.Single(plan.YubiKeyCandidates);
        Assert.Equal(otp.SlotId, candidate.Slot.SlotId);
        Assert.Equal(1, plan.YubiKeySlotCount);
        Assert.Empty(plan.PasswordSerials);
        Assert.Equal("", plan.SetAsideSuffix); // not "needs a newer tswap"
        var (slot, blob) = Assert.Single(plan.Fido2Candidates);
        Assert.Equal(fido2.SlotId, slot.SlotId);
        Assert.Equal(fido2Blob.CredentialId, blob.CredentialId);
        Assert.Equal(fido2Blob.PrfInput, blob.PrfInput);
        Assert.True(blob.RequiresPassword);
    }

    /// <summary>The excluded key's OTP slots are left out; its FIDO2 slot stays a candidate (task 7 relies on it).</summary>
    [Fact]
    public void Classify_ExcludeSerial_KeepsThatKeysFido2Slot()
    {
        var slots = new Fido2TestSlots();
        var otp = slots.AddOtp(SimulatedYubiKeyService.WithKeys(Fido2TestSlots.Fido2Serial), Fido2TestSlots.Fido2Serial);
        var fido2 = slots.AddFido2(Fido2TestSlots.Blob(Fido2TestSlots.Fido2Serial));

        var plan = VaultUnlocker.Classify(slots.Config(own: otp), slots.Keyring, excludeSerial: Fido2TestSlots.Fido2Serial);

        Assert.Empty(plan.YubiKeyCandidates);
        Assert.Equal(fido2.SlotId, Assert.Single(plan.Fido2Candidates).Slot.SlotId);
    }

    /// <summary>A vault made by <c>init --fido2</c>: its own slot is a FIDO2 slot, so there is no own backend path.</summary>
    [Fact]
    public void InitFido2Vault_HasNoOwnBackendPath()
    {
        var slots = new Fido2TestSlots();
        var fido2 = slots.AddFido2(Fido2TestSlots.Blob());
        slots.AddRecovery();

        var plan = VaultUnlocker.Classify(slots.Config(HardwareBackend.YubiKey, own: fido2), slots.Keyring, excludeSerial: null);

        Assert.False(plan.OwnPath);
        Assert.Equal(fido2.SlotId, Assert.Single(plan.Fido2Candidates).Slot.SlotId);
        Assert.Equal("", plan.SetAsideSuffix);
    }

    // ------------------------------------------------------------------ task 7: pass 4

    private const int KeyA = 33060005;
    private const int KeyB = 33060006;
    private const string Pin = FakeFido2Keys.DefaultPin;

    private static readonly byte[] MachineKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] OtherMachineKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] Password = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] WrongPassword = RandomNumberGenerator.GetBytes(32);

    /// <summary>YubiKey 5Ci (<see cref="YubicoAaguids"/>), for a second model.</summary>
    private static readonly Guid Aaguid5Ci = Guid.Parse("c5ef55ff-ad9a-4b9f-b580-adebafe026d0");

    private readonly FakeFido2Keys _fido2 = new();

    /// <summary>Everything that happened, in order: the fake's operations, "prompt", "pin" and "notice: ...".</summary>
    private readonly List<string> _log = [];

    private readonly List<Fido2PinRequest> _pinRequests = [];

    public VaultUnlockerFido2Tests() => _fido2.OnCall = call => _log.Add(call.Op.ToString());

    /// <summary>A keyring whose slots really open with the simulated TPM, OTP keys and the fake FIDO2 keys.</summary>
    private sealed class Vault
    {
        public byte[] VaultKey { get; } = RandomNumberGenerator.GetBytes(32);
        public byte[] VaultId { get; } = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        public List<Slot> Slots { get; } = [];

        /// <summary>A TPM slot of <paramref name="machineKey"/>; <paramref name="opens"/> false wraps it under another KEK.</summary>
        public byte[] AddTpm(byte[] machineKey, bool password, bool opens = true)
        {
            using var stretched = password ? StretchedPassword.FromBytes(Password) : null;
            var (kek, hwBlob) = new SimulatedHardwareService(HardwareBackend.Tpm, machineKey).Enroll(stretched);
            return Add(opens ? kek : RandomNumberGenerator.GetBytes(32), hwBlob);
        }

        public byte[] AddOtp(IYubiKeyService keys, int serial, bool password)
        {
            var blob = YubiKeySlotBlob.Create(serial, requiresTouch: true);
            if (password)
                blob = blob.WithPassword();
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            using var stretched = StretchedPassword.FromBytes(Password);
            return Add(YubiKeySlotKek.Recover(keys, blob, slotId, stretched.Clone), blob.Encode(), slotId);
        }

        /// <summary>
        /// A FIDO2 slot on <paramref name="key"/> (a credential made on it), with the global constraints' KEK:
        /// <c>Fido2SlotKek.Derive(output, blob.PrfInput, slotId)</c>, or <c>DeriveV2</c> with <see cref="Password"/>.
        /// <paramref name="opens"/> false wraps it under another KEK (the key answers, the slot doesn't unwrap).
        /// </summary>
        public (byte[] SlotId, Fido2SlotBlob Blob) AddFido2(FakeFido2Keys fido2, FakeFido2Keys.Key key, bool password = false, bool opens = true)
        {
            var blob = Fido2SlotBlob.Create(key.Serial, key.Aaguid, fido2.AddCredential(key), password);
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var output = fido2.UvOutput(blob.CredentialId, blob.PrfInput);
            using var stretched = StretchedPassword.FromBytes(Password);
            var kek = password
                ? Fido2SlotKek.DeriveV2(output, stretched, blob.PrfInput, slotId)
                : Fido2SlotKek.Derive(output, blob.PrfInput, slotId);
            Add(opens ? kek : RandomNumberGenerator.GetBytes(32), blob.Encode(), slotId);
            return (slotId, blob);
        }

        public byte[] Add(byte[] kek, byte[] hwBlob, byte[]? slotId = null)
        {
            slotId ??= RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var pair = SlotKeyPair.Generate();
            Slots.Add(MachineSlotWrap.Wrap(VaultKey, pair.PrivateKey, pair.PublicKey, slotId, kek,
                KeyringFormat.KeyringFormatVersion, VaultId, 1) with { HwBlob = hwBlob });
            return slotId;
        }

        public Keyring Keyring => new(KeyringFormat.KeyringFormatVersion, VaultId, 1, [.. Slots]);

        public Config Config(HardwareBackend? backend, byte[]? own) => new(
            [], "", DateTime.UtcNow, RequiresTouch: true, RngMode: RngMode.System, Backend: backend,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(Keyring)),
            KeyringSlotId: own is null ? null : Convert.ToBase64String(own));
    }

    private VaultUnlocker Unlocker(IYubiKeyService? keys = null) =>
        new(keys ?? SimulatedYubiKeyService.WithKeys(), overrideKey: null,
            additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey)],
            fido2: new Fido2Service(_fido2));

    private Fido2Pin PinAnswer(string pin = Pin) => request =>
    {
        _log.Add("pin");
        _pinRequests.Add(request);
        return Encoding.UTF8.GetBytes(pin);
    };

    private VaultPasswordProvider Prompt(byte[] password) => () =>
    {
        _log.Add("prompt");
        return StretchedPassword.FromBytes(password);
    };

    private UnlockSources Sources(VaultPasswordProvider? prompt = null, Fido2Pin? pin = null, bool noTerminal = false) =>
        new(null, prompt) { Fido2Pin = noTerminal ? null : pin ?? PinAnswer(), Fido2Notice = text => _log.Add("notice: " + text) };

    private static byte[] Unlock(VaultUnlocker unlocker, Config config, UnlockSources sources) =>
        unlocker.Unlock(config, YubiKeySelection.Unattended, sources);

    private int Count(FakeFido2Op op) => _fido2.Calls.Count(c => c.Op == op);

    private int Prompts => _log.Count(l => l == "prompt");

    [Fact]
    public void Unlock_Fido2Last_AfterPasswordPass()
    {
        var vault = new Vault();
        var own = vault.AddTpm(MachineKey, password: true);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));

        // The right password: the TPM slot opens it in pass 3, and the FIDO2 key is never touched.
        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources(Prompt(Password)));
        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(["prompt"], _log);
        Assert.Empty(_fido2.Calls);

        // A wrong one: the TPM refuses it, and only then pass 4 asks for the FIDO2 PIN (a password-free slot).
        _log.Clear();
        key = Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources(Prompt(WrongPassword)));
        Assert.Equal(vault.VaultKey, key);
        Assert.Equal("prompt", _log[0]);
        Assert.True(_log.IndexOf("prompt") < _log.IndexOf("pin"));
        Assert.Equal(1, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>A vault made by <c>init --fido2</c>: its only machine slot is a FIDO2 slot.</summary>
    [Fact]
    public void Unlock_Fido2Only_Opens()
    {
        var vault = new Vault();
        var (own, _) = vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources());

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal([nameof(FakeFido2Op.FindHolder), nameof(FakeFido2Op.GetHmacSecret), "pin", "notice: " + Fido2Texts.TouchLine], _log);
        Assert.Equal($"YubiKey {KeyA}", Assert.Single(_pinRequests).KeyName);
        // The output is zeroed once the KEK is derived.
        Assert.All(_fido2.LastOutput!, b => Assert.Equal(0, b));
    }

    // Final review: a vault whose only usable ways in are FIDO2 slots asks a running agent before spending a PIN and a
    // touch (exit (a)), as pass 2 does.
    [Fact]
    public void Unlock_Fido2Only_AgentFirst_NoPinNoKeyCall()
    {
        var vault = new Vault();
        var (own, _) = vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid), password: true);
        var asked = 0;
        var sources = new UnlockSources(() => { asked++; return vault.VaultKey.ToArray(); }, Prompt(Password))
        {
            Fido2Pin = PinAnswer(),
            Fido2Notice = text => _log.Add("notice: " + text),
        };

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), sources);

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(1, asked);
        Assert.Empty(_pinRequests);
        Assert.Empty(_fido2.Calls);
        Assert.Equal(0, Prompts);
    }

    [Fact]
    public void Unlock_Fido2Only_AgentFails_SaidWithTheFido2Failure()
    {
        var vault = new Vault();
        var (own, _) = vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid), password: true);
        var sources = new UnlockSources(() => throw new AgentUnlockFailedException("the agent's key said no."), Prompt(Password))
        {
            Fido2Pin = PinAnswer("000000"),
            Fido2Notice = text => _log.Add("notice: " + text),
        };

        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), sources));

        Assert.Contains(Fido2Texts.PinWrong($"YubiKey {KeyA}", 7), ex.Message);
        Assert.Contains(VaultPasswordMessages.AgentAlsoFailed("the agent's key said no."), ex.Message);
    }

    // Goal 4 still holds: a vault without password slots never contacts an agent.
    [Fact]
    public void Unlock_Fido2Only_NoPasswordSlot_NeverAsksTheAgent()
    {
        var vault = new Vault();
        var (own, _) = vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));
        var sources = new UnlockSources(() => throw new InvalidOperationException("the agent was asked"), null)
        {
            Fido2Pin = PinAnswer(),
            Fido2Notice = text => _log.Add("notice: " + text),
        };

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), sources);

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(1, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>One vault-password prompt in the run: pass 3 asks it for the TPM slot, pass 4 reuses it.</summary>
    [Fact]
    public void Unlock_Fido2PasswordSlot_ReusesTypedPassword()
    {
        var vault = new Vault();
        // The TPM accepts the password (no refusal), but its slot doesn't unwrap: pass 3 fails without refuting it.
        var own = vault.AddTpm(MachineKey, password: true, opens: false);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid), password: true);

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources(Prompt(Password)));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(1, Prompts);
        Assert.Equal(1, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>Review Focus 1.</summary>
    [Fact]
    public void Unlock_Fido2WrongPin_ShowsRetriesAndStops()
    {
        var otp = SimulatedYubiKeyService.WithKeys(11111111);
        var vault = new Vault();
        vault.AddOtp(otp, 11111111, password: false);
        otp.PluggedIn = [];
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(KeyB, Fido2TestSlots.Aaguid);
        vault.AddFido2(_fido2, a);
        vault.AddFido2(_fido2, b);

        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlock(Unlocker(otp), vault.Config(HardwareBackend.YubiKey, null), Sources(pin: PinAnswer("000000"))));

        Assert.Contains(Fido2Texts.PinWrong($"YubiKey {KeyA}", 7), ex.Message);
        Assert.Contains("7 tries left", ex.Message);
        Assert.Contains("plug it in again", ex.Message);
        Assert.Contains(Fido2Texts.OtherSlotNotTried, ex.Message);
        // The OTP slot's failure stays in the combined message.
        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", ex.Message);
        Assert.Equal(1, Count(FakeFido2Op.GetHmacSecret));
        Assert.Single(_pinRequests);
        Assert.Equal(8, b.Retries);
    }

    /// <summary>Review Focus 2.</summary>
    [Fact]
    public void Unlock_Fido2KeyAbsent_NoPinPrompt()
    {
        var vault = new Vault();
        var own = vault.AddTpm(OtherMachineKey, password: false);
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        vault.AddFido2(_fido2, a);
        a.PluggedIn = false;

        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources()));

        Assert.Contains($"The FIDO2 slot of YubiKey {KeyA}: plug it in.", ex.Message);
        Assert.Contains(VaultUnlocker.ForeignHardwareSlotHint, ex.Message);
        Assert.Empty(_pinRequests);
        Assert.Equal(0, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>Review Focus 3: on Linux/macOS and on Windows (no dialog), no key call at all.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Unlock_Fido2OnlyNoTerminal_RefusesWithoutDialog(bool canList)
    {
        var vault = new Vault();
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var (own, _) = vault.AddFido2(_fido2, a);
        _fido2.CanList = canList;
        _fido2.Picked = a;

        var ex = Assert.Throws<VaultPasswordUnavailableException>(() =>
            Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources(noTerminal: true)));

        Assert.Equal(Fido2Texts.NoTerminal, ex.Message);
        Assert.Contains("needs a person at a terminal", ex.Message);
        Assert.Empty(_fido2.Calls);
    }

    /// <summary>Review Focus 5.</summary>
    [Fact]
    public void Unlock_Fido2CredentialGone_NamesReset()
    {
        var vault = new Vault();
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var (own, _) = vault.AddFido2(_fido2, a);
        _fido2.Reset(a);
        a.Pin = Pin;

        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources()));

        Assert.Contains($"YubiKey {KeyA} is plugged in but no longer holds this slot's credential: a FIDO2 reset deleted it", ex.Message);
        Assert.Contains("tswap slot add --fido2", ex.Message);
        Assert.Empty(_pinRequests);
        Assert.Equal(0, Count(FakeFido2Op.GetHmacSecret));
    }

    [Fact]
    public void Unlock_Fido2_ProbesSilentlyBeforePin()
    {
        var vault = new Vault();
        _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(KeyB, Fido2TestSlots.Aaguid);
        var (own, _) = vault.AddFido2(_fido2, b);

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources());

        Assert.Equal(vault.VaultKey, key);
        Assert.True(_log.IndexOf(nameof(FakeFido2Op.FindHolder)) < _log.IndexOf("pin"));
        var assertion = Assert.Single(_fido2.Calls, c => c.Op == FakeFido2Op.GetHmacSecret);
        Assert.Equal(b.Ref, assertion.Key);
        Assert.Equal($"YubiKey {KeyB}", Assert.Single(_pinRequests).KeyName);
    }

    [Fact]
    public void Unlock_Fido2OnWindows_TriedOnlyAfterOthersFail()
    {
        var otp = SimulatedYubiKeyService.WithKeys(11111111);
        var vault = new Vault();
        vault.AddOtp(otp, 11111111, password: false);
        var a = _fido2.AddKey(null, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(null, Aaguid5Ci);
        var (_, blobA) = vault.AddFido2(_fido2, a);
        var (_, blobB) = vault.AddFido2(_fido2, b);
        _fido2.CanList = false;
        _fido2.Picked = a;
        var config = vault.Config(HardwareBackend.YubiKey, null);

        // The OTP key opens it: no ceremony.
        Assert.Equal(vault.VaultKey, Unlock(Unlocker(otp), config, Sources()));
        Assert.Empty(_fido2.Calls);

        // The OTP key gone: one ceremony, every FIDO2 slot in its allow list, no probe.
        otp.PluggedIn = [];
        Assert.Equal(vault.VaultKey, Unlock(Unlocker(otp), config, Sources()));
        var assertion = Assert.Single(_fido2.Calls);
        Assert.Equal(FakeFido2Op.GetHmacSecret, assertion.Op);
        Assert.Null(assertion.Key);
        Assert.Equal([blobA.CredentialId, blobB.CredentialId], assertion.CredentialIds);
        Assert.Contains("notice: " + Fido2Texts.WindowsTouchLine, _log);
    }

    /// <summary>Agent start and broker unlock (the password proof) never ask for a FIDO2 PIN.</summary>
    [Fact]
    public void UnlockWithPasswordSlots_IgnoresFido2()
    {
        var vault = new Vault();
        var own = vault.AddTpm(MachineKey, password: true);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid), password: true);
        using var password = StretchedPassword.FromBytes(Password);

        Assert.Equal(vault.VaultKey, Unlocker().UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, password));

        var fido2Only = new Vault();
        var (fido2Own, _) = fido2Only.AddFido2(_fido2, _fido2.AddKey(KeyB, Fido2TestSlots.Aaguid), password: true);
        var ex = Assert.Throws<TswapException>(() =>
            Unlocker().UnlockWithPasswordSlots(fido2Only.Config(HardwareBackend.YubiKey, fido2Own), YubiKeySelection.Unattended, password));
        Assert.Equal(VaultUnlocker.NoPasswordSlotHereText, ex.Message);
        Assert.Empty(_fido2.Calls);
    }

    [Fact]
    public void Unlock_Fido2PasswordSlotOnly_AsksOnceAtPass4()
    {
        var vault = new Vault();
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var (own, _) = vault.AddFido2(_fido2, a, password: true);
        var config = vault.Config(HardwareBackend.YubiKey, own);

        Assert.Equal(vault.VaultKey, Unlock(Unlocker(), config, Sources(Prompt(Password))));
        Assert.Equal([nameof(FakeFido2Op.FindHolder), "prompt", nameof(FakeFido2Op.GetHmacSecret), "pin", "notice: " + Fido2Texts.TouchLine], _log);

        // The key absent: no password prompt, no PIN.
        _log.Clear();
        _pinRequests.Clear();
        a.PluggedIn = false;
        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), config, Sources(Prompt(Password))));
        Assert.Contains($"The FIDO2 slot of YubiKey {KeyA}: plug it in.", ex.Message);
        Assert.Equal(0, Prompts);
        Assert.Empty(_pinRequests);
    }

    /// <summary>
    /// The CLI: stdin piped (here it carries nothing a PIN could come from), the controlling terminal answers the PIN.
    /// Also the KEK composition from enrolment through unlock: the slot <c>slot add --fido2</c> made opens the vault.
    /// </summary>
    [Fact]
    public void Unlock_RedirectedStdinWithTty_AsksPinFromTty()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-unlock-fido2-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            var otp = SimulatedYubiKeyService.WithKeys(11111111);
            var service = new Fido2Service(_fido2);
            FakeTerminal terminal = new();
            (int Exit, string Out, string Err) Run(string stdin, params string[] args)
            {
                var console = new FakeConsole(stdin);
                Assert.True(console.IsInputRedirected);
                var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
                var ctx = new CommandContext(console, env, VaultStores.Open(dir), otp, new VaultUnlocker(otp, overrideKey: null, fido2: service),
                    TestKey: null, SudoBypass: true)
                {
                    Fido2 = service,
                    Terminal = terminal.Open,
                };
                var exit = CliRunner.Run(ctx, args);
                return (exit, console.OutText, console.ErrorText);
            }

            Assert.Equal(0, Run("", "init", "--yubikey").Exit);
            Assert.Equal(0, Run("s3cret\ns3cret\n", "add", "db-password").Exit);
            _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
            terminal.Enqueue(Pin, Pin);
            var (addExit, addOut, addErr) = Run("", "slot", "add", "--fido2");
            Assert.True(addExit == 0, addErr + addOut);

            otp.PluggedIn = [];
            _fido2.Calls.Clear();
            terminal.Enqueue(Pin);
            var (exit, stdout, stderr) = Run("not a pin\n", "get", "db-password");

            Assert.True(exit == 0, stderr);
            Assert.Equal("s3cret", stdout.Trim());
            Assert.Equal($"FIDO2 PIN for YubiKey {KeyA}: ", terminal.Reads[^1].Prompt[^$"FIDO2 PIN for YubiKey {KeyA}: ".Length..]);
            Assert.True(terminal.Reads[^1].Secret);
            Assert.Contains(Fido2Texts.TouchLine, stderr);
            Assert.DoesNotContain(Fido2Texts.TouchLine, stdout);
            Assert.Equal(1, _fido2.Calls.Count(c => c.Op == FakeFido2Op.GetHmacSecret));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    /// <summary>
    /// Controller ruling A (task 7): a TPM password slot refused the typed password in pass 3 (a definite answer), so
    /// pass 4 leaves the FIDO2 password slots out: no probe, no PIN, no touch.
    /// </summary>
    [Fact]
    public void Unlock_PasswordRefusedByTpm_SkipsFido2PasswordSlots()
    {
        var vault = new Vault();
        var own = vault.AddTpm(MachineKey, password: true);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid), password: true);

        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources(Prompt(WrongPassword))));

        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, ex.Message);
        Assert.Contains($"The FIDO2 slot of YubiKey {KeyA} was left out: the vault password didn't match.", ex.Message);
        Assert.Equal(1, Prompts);
        Assert.Empty(_fido2.Calls);
        Assert.Empty(_pinRequests);
    }

    /// <summary>
    /// Ruling A on Windows: a TPM password slot refused the password in pass 3, so the one ceremony's allow list holds
    /// only the password-free FIDO2 slot's credential; that slot opens.
    /// </summary>
    [Fact]
    public void Unlock_Windows_PasswordAskedBeforeDialog_RefusedOneDropsPasswordSlots()
    {
        var vault = new Vault();
        var own = vault.AddTpm(MachineKey, password: true);
        var a = _fido2.AddKey(null, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(null, Aaguid5Ci);
        vault.AddFido2(_fido2, a, password: true);
        var (_, free) = vault.AddFido2(_fido2, b);
        _fido2.CanList = false;
        _fido2.Picked = b;

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources(Prompt(WrongPassword)));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(1, Prompts);
        Assert.True(_log.IndexOf("prompt") < _log.IndexOf(nameof(FakeFido2Op.GetHmacSecret)));
        Assert.Equal([free.CredentialId], Assert.Single(_fido2.Calls).CredentialIds);
    }

    /// <summary>Windows, no other password slot: the password is asked before the dialog, and the slot it mixes opens.</summary>
    [Fact]
    public void Unlock_Windows_Fido2PasswordSlot_PasswordAskedBeforeDialog()
    {
        var vault = new Vault();
        var a = _fido2.AddKey(null, Fido2TestSlots.Aaguid);
        var (own, blob) = vault.AddFido2(_fido2, a, password: true);
        _fido2.CanList = false;
        _fido2.Picked = a;

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources(Prompt(Password)));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(["prompt", "notice: " + Fido2Texts.WindowsTouchLine, nameof(FakeFido2Op.GetHmacSecret)], _log);
        Assert.Equal([blob.CredentialId], Assert.Single(_fido2.Calls).CredentialIds);
    }

    /// <summary>
    /// Ruling A: nothing refuted the password (no TPM or Secure Enclave password slot), so the FIDO2 password slot is
    /// tried; the key's PIN was right (no PIN try lost), the unwrap fails, and the message names the vault password.
    /// </summary>
    [Fact]
    public void Unlock_UnrefutedWrongPassword_SaysPasswordMayBeWrong()
    {
        var vault = new Vault();
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var (own, _) = vault.AddFido2(_fido2, a, password: true);

        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources(Prompt(WrongPassword))));

        Assert.Contains(Fido2Texts.UnwrapFailed($"YubiKey {KeyA}", requiresPassword: true), ex.Message);
        Assert.Contains("the vault password may be wrong", ex.Message);
        Assert.Equal(8, a.Retries);
        Assert.Equal(1, Prompts);
    }

    [Fact]
    public void Unlock_Windows_SecondKeysSlotOpens()
    {
        var vault = new Vault();
        var a = _fido2.AddKey(null, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(null, Aaguid5Ci);
        var (own, blobA) = vault.AddFido2(_fido2, a);
        var (_, blobB) = vault.AddFido2(_fido2, b);
        _fido2.CanList = false;
        _fido2.Picked = b;

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources());

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal([blobA.CredentialId, blobB.CredentialId], Assert.Single(_fido2.Calls).CredentialIds);
    }

    [Fact]
    public void Unlock_Fido2PasswordSlotOnly_NoPasswordAvailable()
    {
        var vault = new Vault();
        var (own, _) = vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid), password: true);
        var config = vault.Config(HardwareBackend.YubiKey, own);

        // No prompt source at all.
        var ex = Assert.Throws<VaultPasswordUnavailableException>(() => Unlock(Unlocker(), config, Sources()));
        Assert.Contains(VaultPasswordMessages.NoTerminal, ex.Message);
        // A prompt that can't get one (no vault-password file).
        ex = Assert.Throws<VaultPasswordUnavailableException>(() => Unlock(Unlocker(), config,
            Sources(() => throw new VaultPasswordUnavailableException(VaultPasswordMessages.MissingFile))));
        Assert.Contains(VaultPasswordMessages.MissingFile, ex.Message);

        Assert.Empty(_pinRequests);
        Assert.Equal(0, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>
    /// A key whose remembered slot needs the password keeps its password-free slot back (task 4b); with no password
    /// source that deferred slot opens before pass 4, so no PIN is asked.
    /// </summary>
    [Fact]
    public void Unlock_DeferredOtpSlotOpens_NoPinAsked()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-unlock-fido2-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            const int serial = 11111111;
            var otp = SimulatedYubiKeyService.WithKeys(serial);
            var vault = new Vault();
            var passwordSlot = vault.AddOtp(otp, serial, password: true);
            vault.AddOtp(otp, serial, password: false);
            vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));
            var remembered = new RememberedYubiKeySlots(dir, DirectoryOwnerMatcher.Default);
            remembered.Remember(vault.VaultId, serial, passwordSlot);

            var key = Unlock(Unlocker(otp), vault.Config(HardwareBackend.YubiKey, null),
                new UnlockSources(null, null) { Remembered = remembered, Fido2Pin = PinAnswer() });

            Assert.Equal(vault.VaultKey, key);
            Assert.Empty(_fido2.Calls);
            Assert.Empty(_pinRequests);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Unlock_MixedNoTerminal_NamesFido2Skipped()
    {
        var vault = new Vault();
        var own = vault.AddTpm(OtherMachineKey, password: false);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));

        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources(noTerminal: true)));

        Assert.Contains(VaultUnlocker.ForeignHardwareSlotHint, ex.Message);
        Assert.Contains(Fido2Texts.NoTerminal, ex.Message);
        Assert.Empty(_fido2.Calls);
    }

    /// <summary>Review Focus 6: a Security Key or Bio reports no serial; it is found by its credential and named by model.</summary>
    [Fact]
    public void Unlock_SerialLessKey_Opens()
    {
        var vault = new Vault();
        var key5Ci = _fido2.AddKey(null, Aaguid5Ci);
        var (own, blob) = vault.AddFido2(_fido2, key5Ci);
        Assert.Null(blob.Serial);

        var key = Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources());

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal("YubiKey 5Ci", Assert.Single(_pinRequests).KeyName);
    }

    [Fact]
    public void Unlock_SecondFido2SlotNotTriedAfterOne_SaysWhy()
    {
        var vault = new Vault();
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        var b = _fido2.AddKey(KeyB, Fido2TestSlots.Aaguid);
        var (own, _) = vault.AddFido2(_fido2, a, opens: false);
        vault.AddFido2(_fido2, b);

        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources()));

        Assert.Contains(Fido2Texts.UnwrapFailed($"YubiKey {KeyA}", requiresPassword: false), ex.Message);
        Assert.Contains(Fido2Texts.OtherSlotNotTried, ex.Message);
        Assert.Equal(1, Count(FakeFido2Op.GetHmacSecret));
        Assert.Single(_pinRequests);
    }

    /// <summary><see cref="YubiKeySelection.ExcludeSerial"/> (re-enrolling a key's OTP slot) leaves its FIDO2 slot in.</summary>
    [Fact]
    public void UnlockExcluding_KeepsTheSameKeysFido2Slots()
    {
        var otp = SimulatedYubiKeyService.WithKeys(KeyA);
        var vault = new Vault();
        vault.AddOtp(otp, KeyA, password: false);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));
        otp.Challenges.Clear(); // making the OTP slot challenged the key

        var key = Unlocker(otp).Unlock(vault.Config(HardwareBackend.YubiKey, null),
            YubiKeySelection.Unattended with { ExcludeSerial = KeyA }, Sources());

        Assert.Equal(vault.VaultKey, key);
        Assert.Empty(otp.Challenges);
        Assert.Equal(1, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>Carry-forward 2: a busy key makes the silent probe fail; the error names it and no PIN is asked.</summary>
    [Fact]
    public void Unlock_Fido2ProbeBusy_NamesKeyNoPin()
    {
        var vault = new Vault();
        var (own, _) = vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));
        _fido2.FailNext(FakeFido2Op.FindHolder, Fido2Failure.Busy);

        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), vault.Config(HardwareBackend.YubiKey, own), Sources()));

        Assert.Contains(Fido2Texts.Busy($"YubiKey {KeyA}"), ex.Message);
        Assert.Empty(_pinRequests);
        Assert.Equal(0, Count(FakeFido2Op.GetHmacSecret));
    }

    /// <summary>
    /// Carry-forward 1: the own slot is a password-free TPM slot that fails here and the other slots are only FIDO2
    /// (no OTP slot): the FIDO2 slot is still tried, and opens.
    /// </summary>
    [Fact]
    public void Unlock_OwnTpmFails_OnlyFido2Besides_Fido2Opens()
    {
        var vault = new Vault();
        var own = vault.AddTpm(OtherMachineKey, password: false);
        vault.AddFido2(_fido2, _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid));

        Assert.Equal(vault.VaultKey, Unlock(Unlocker(), vault.Config(HardwareBackend.Tpm, own), Sources()));
    }

    /// <summary>Carry-forward 1: the own slot is set aside (needs a newer tswap); the FIDO2 slot opens the vault.</summary>
    [Fact]
    public void Unlock_OwnSlotSetAside_Fido2Opens()
    {
        var vault = new Vault();
        var own = vault.AddTpm(MachineKey, password: true);
        var i = vault.Slots.FindIndex(s => s.SlotId.AsSpan().SequenceEqual(own));
        var newer = (byte[])vault.Slots[i].HwBlob!.Clone();
        newer[4] = 99; // an unknown TSTP header version
        vault.Slots[i] = vault.Slots[i] with { HwBlob = newer };
        var a = _fido2.AddKey(KeyA, Fido2TestSlots.Aaguid);
        vault.AddFido2(_fido2, a);
        var config = vault.Config(HardwareBackend.Tpm, own);
        Assert.Equal(SlotPasswordKind.NeedsNewerTswap, VaultUnlocker.OwnSlotPassword(config).Kind);

        Assert.Equal(vault.VaultKey, Unlock(Unlocker(), config, Sources()));

        // The key unplugged: both reasons are named.
        a.PluggedIn = false;
        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(), config, Sources()));
        Assert.Contains("This machine's slot of this vault can't be used.", ex.Message);
        Assert.Contains("needs a newer tswap", ex.Message);
        Assert.Contains($"The FIDO2 slot of YubiKey {KeyA}: plug it in.", ex.Message);
    }
}
