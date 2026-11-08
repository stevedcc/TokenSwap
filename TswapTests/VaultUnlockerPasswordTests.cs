using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 3, ruling 13: <see cref="VaultUnlocker"/> unlocks in three passes. Pass 1 tries every
/// password-free candidate; pass 2 asks the agent (<see cref="UnlockSources.AskAgent"/>) only when pass 1
/// opened nothing and a password candidate is reachable; pass 3 calls <see cref="UnlockSources.Prompt"/>
/// once and tries the password candidates. Slots that need a newer tswap or are corrupt are set aside
/// before any pass (ruling 3). Simulated TPM, simulated Secure Enclave and simulated YubiKeys.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class VaultUnlockerPasswordTests
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private const string NoTerminalText =
        "This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.";
    private const string WrongPasswordText = "Wrong vault password (or this slot's key changed).";
    private const string StrippedHeaderText =
        "This slot's hardware object needs a password, but its blob doesn't say so: restore config.json from backup, or upgrade tswap.";

    private static readonly byte[] MachineKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] OtherMachineKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] Password = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] WrongPassword = RandomNumberGenerator.GetBytes(32);

    private static string Id8(byte[] slotId) => Convert.ToHexString(slotId).ToLowerInvariant()[..8];

    private sealed class VaultBuilder
    {
        public byte[] VaultKey { get; } = RandomNumberGenerator.GetBytes(32);
        public byte[] VaultId { get; } = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        public List<Slot> Slots { get; } = [];

        public byte[] AddTpmSlot(byte[] machineKey, bool password, HardwareBackend backend = HardwareBackend.Tpm)
        {
            using var stretched = password ? StretchedPassword.FromBytes(Password) : null;
            var (kek, hwBlob) = new SimulatedHardwareService(backend, machineKey).Enroll(stretched);
            return AddSlot(kek, hwBlob);
        }

        public byte[] AddYubiKeySlot(IYubiKeyService keys, int serial, bool password)
        {
            var blob = YubiKeySlotBlob.Create(serial, requiresTouch: true);
            if (password)
                blob = blob.WithPassword();
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            using var stretched = StretchedPassword.FromBytes(Password);
            var kek = YubiKeySlotKek.Recover(keys, blob, slotId, stretched.Clone);
            AddSlot(kek, blob.Encode(), slotId);
            return slotId;
        }

        public byte[] AddSlot(byte[] kek, byte[] hwBlob, byte[]? slotId = null)
        {
            slotId ??= RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var pair = SlotKeyPair.Generate();
            Slots.Add(MachineSlotWrap.Wrap(VaultKey, pair.PrivateKey, pair.PublicKey, slotId, kek,
                KeyringFormat.KeyringFormatVersion, VaultId, 1) with { HwBlob = hwBlob });
            return slotId;
        }

        public void ReplaceBlob(byte[] slotId, byte[] hwBlob)
        {
            var i = Slots.FindIndex(s => s.SlotId.AsSpan().SequenceEqual(slotId));
            Slots[i] = Slots[i] with { HwBlob = hwBlob };
        }

        public Config Config(HardwareBackend? backend, byte[]? ownSlotId) => new(
            [], "", DateTime.UtcNow, RequiresTouch: true, RngMode: RngMode.System, Backend: backend,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1, Slots))),
            KeyringSlotId: ownSlotId is null ? null : Convert.ToBase64String(ownSlotId));
    }

    private static VaultUnlocker Unlocker(IYubiKeyService keys, HardwareBackend backend = HardwareBackend.Tpm) =>
        new(keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(backend, MachineKey)]);

    private static Func<byte[]?> AgentMustNotBeCalled => () => throw new InvalidOperationException("the agent must not be asked");

    private static VaultPasswordProvider PromptMustNotBeCalled => () => throw new InvalidOperationException("the prompt must not be called");

    private static UnlockSources NeitherSource => new(AgentMustNotBeCalled, PromptMustNotBeCalled);

    private static byte[] Unlock(VaultUnlocker unlocker, Config config, UnlockSources sources) =>
        unlocker.Unlock(config, YubiKeySelection.Unattended, sources);

    private static VaultPasswordProvider Prompt(byte[] bytes, List<string>? log = null) => () =>
    {
        log?.Add("prompt");
        return StretchedPassword.FromBytes(bytes);
    };

    // ------------------------------------------------------------------ the password slot itself

    [Fact]
    public void PasswordSlot_PromptCalledOnce_UnlockSucceeds()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        var calls = new List<string>();

        var key = Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own),
            new UnlockSources(() => { calls.Add("agent"); return null; }, Prompt(Password, calls)));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(["agent", "prompt"], calls);
    }

    [Fact]
    public void PasswordSlot_SecureEnclave_PromptCalledOnce_UnlockSucceeds()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true, HardwareBackend.SecureEnclave);
        Assert.True(SecureEnclaveSlotBlob.HasHeader(vault.Slots[0].HwBlob));
        var prompts = 0;

        var key = Unlock(Unlocker(SimulatedYubiKeyService.WithKeys(), HardwareBackend.SecureEnclave),
            vault.Config(HardwareBackend.SecureEnclave, own),
            new UnlockSources(null, () => { prompts++; return StretchedPassword.FromBytes(Password); }));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(1, prompts);
    }

    [Fact]
    public void PasswordSlot_WrongPassword_FailsWithRuling18Text()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);

        var ex = Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()),
            vault.Config(HardwareBackend.Tpm, own), new UnlockSources(null, Prompt(WrongPassword))));

        // Ruling 18's text, not the "another machine" hint.
        Assert.Equal(WrongPasswordText, ex.Message);
        Assert.DoesNotContain(VaultUnlocker.ForeignHardwareSlotHint, ex.Message);
    }

    [Fact]
    public void PasswordYubiKeySlot_WrongPassword_FailsWithRuling18Text()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        vault.AddYubiKeySlot(keys, SerialA, password: true);

        var ex = Assert.Throws<TswapException>(() => Unlock(new VaultUnlocker(keys),
            vault.Config(null, null), new UnlockSources(null, Prompt(WrongPassword))));

        Assert.Contains(WrongPasswordText, ex.Message);
        Assert.Contains(SerialA.ToString(), ex.Message);
    }

    [Fact]
    public void PasswordSlot_NoSources_ThrowsVaultPasswordUnavailable()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);

        var ex = Assert.Throws<VaultPasswordUnavailableException>(() =>
            Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own), UnlockSources.None));

        Assert.Equal(NoTerminalText, ex.Message);
        // The existing overloads (no sources) pass UnlockSources.None.
        Assert.Throws<VaultPasswordUnavailableException>(() =>
            Unlocker(SimulatedYubiKeyService.WithKeys()).Unlock(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended));
    }

    [Fact]
    public void ProvidedPassword_IsDisposedAfterUnlock()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        StretchedPassword? handedOut = null;

        Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own),
            new UnlockSources(null, () => handedOut = StretchedPassword.FromBytes(Password)));

        Assert.NotNull(handedOut);
        Assert.Throws<ObjectDisposedException>(() => handedOut!.CopyTo(new byte[32]));
    }

    [Fact]
    public void WrongPassword_TpmAndYubiKeySlots_TheServicesCloneIsFreedToo()
    {
        // Review T17 p4 MiMo I3: on the failure path the clone handed to the service is freed as well as the
        // original (ruling 13's per-service finally), not only on success.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var tpmVault = new VaultBuilder();
        var own = tpmVault.AddTpmSlot(MachineKey, password: true);
        var ykVault = new VaultBuilder();
        ykVault.AddYubiKeySlot(keys, SerialA, password: true);
        var frees = 0;
        StretchedPassword.BeforeFreeObserver = _ => Interlocked.Increment(ref frees);
        try
        {
            Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()),
                tpmVault.Config(HardwareBackend.Tpm, own), new UnlockSources(null, Prompt(WrongPassword))));
            Assert.Equal(2, frees); // the TPM service's clone and the original

            frees = 0;
            Assert.ThrowsAny<TswapException>(() => Unlock(new VaultUnlocker(keys),
                ykVault.Config(null, null), new UnlockSources(null, Prompt(WrongPassword))));
            Assert.Equal(2, frees); // the YubiKey candidate's clone and the original
        }
        finally
        {
            StretchedPassword.BeforeFreeObserver = null;
        }
    }

#pragma warning disable CA1416 // the Secure Enclave service runs against the fake shim here
    [Fact]
    public void WrongPassword_SecureEnclaveService_FreesWhatTheProviderGave()
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = TswapCore.Vault.Interop.AppleSecureEnclaveInterop.UseShim(shim);
        using var right = StretchedPassword.FromBytes(Password);
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (_, hwBlob) = service.Enroll(right);
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(hwBlob));
        var given = new List<StretchedPassword>();
        var frees = 0;
        StretchedPassword.BeforeFreeObserver = _ => Interlocked.Increment(ref frees);
        try
        {
            Assert.Throws<VaultPasswordRefusedException>(() => service.Unlock(config, _ => 0, () =>
            {
                var p = StretchedPassword.FromBytes(WrongPassword);
                given.Add(p);
                return p;
            }));
        }
        finally
        {
            StretchedPassword.BeforeFreeObserver = null;
        }

        Assert.Equal(1, frees);
        Assert.Throws<ObjectDisposedException>(() => Assert.Single(given).CopyTo(new byte[32]));
    }
#pragma warning restore CA1416

    [Fact]
    public void ProvidedPassword_IsDisposedAfterAFailedUnlock()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        StretchedPassword? handedOut = null;

        Assert.ThrowsAny<TswapException>(() => Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()),
            vault.Config(HardwareBackend.Tpm, own), new UnlockSources(null, () => handedOut = StretchedPassword.FromBytes(WrongPassword))));

        Assert.Throws<ObjectDisposedException>(() => handedOut!.CopyTo(new byte[32]));
    }

    [Fact]
    public void Prompt_CalledOnce_AcrossSeveralPasswordCandidates()
    {
        // Two password YubiKey slots; A's slot was made with another HMAC secret, so it fails, and B opens.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        var reprogrammedA = new SimulatedYubiKeyService(new Dictionary<int, byte[]> { [SerialA] = RandomNumberGenerator.GetBytes(20) });
        var vault = new VaultBuilder();
        vault.AddYubiKeySlot(reprogrammedA, SerialA, password: true);
        vault.AddYubiKeySlot(keys, SerialB, password: true);
        keys.Challenges.Clear();
        keys.PluggedIn = [SerialA, SerialB];
        var prompts = 0;
        var frees = 0;

        byte[] key;
        StretchedPassword.BeforeFreeObserver = _ => frees++;
        try
        {
            key = Unlock(new VaultUnlocker(keys), vault.Config(null, null),
                new UnlockSources(null, () => { prompts++; return StretchedPassword.FromBytes(Password); }));
        }
        finally
        {
            StretchedPassword.BeforeFreeObserver = null;
        }

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(1, prompts);
        Assert.Equal([SerialA, SerialB], keys.Challenges.Select(c => c.Serial));
        // One clone per candidate tried (A, B), each disposed by the service, plus the original.
        Assert.Equal(3, frees);
    }

    // ------------------------------------------------------------------ Goal 4 and Review focus 2

    [Fact]
    public void NoPasswordVault_NoSourceEverCalled()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: false);
        vault.AddYubiKeySlot(keys, SerialA, password: false);

        Assert.Equal(vault.VaultKey, Unlock(Unlocker(keys), vault.Config(HardwareBackend.Tpm, own), NeitherSource));

        // ...and through the YubiKey slot when the TPM is another machine's.
        var elsewhere = new VaultUnlocker(keys, null, [new SimulatedHardwareService(HardwareBackend.Tpm, OtherMachineKey)]);
        Assert.Equal(vault.VaultKey, Unlock(elsewhere, vault.Config(HardwareBackend.Tpm, own), NeitherSource));
    }

    [Fact]
    public void MixedVault_NoPasswordYubiKeyFirst_ProviderAndAgentNeverCalled()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        vault.AddYubiKeySlot(keys, SerialA, password: false);
        keys.Challenges.Clear();
        var hardwareCalls = new List<string>();

        byte[] key;
        using (SimulatedHardwareService.ObserveCalls((backend, call) => hardwareCalls.Add($"{backend.DisplayName} {call}")))
            key = Unlock(Unlocker(keys), vault.Config(HardwareBackend.Tpm, own), NeitherSource);

        Assert.Equal(vault.VaultKey, key);
        Assert.Empty(hardwareCalls); // the password TPM slot was never tried
        Assert.Equal([SerialA], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void MixedVault_NoPasswordKeyUnplugged_AgentThenPrompt()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        vault.AddYubiKeySlot(keys, SerialA, password: false);
        keys.PluggedIn = [];
        var calls = new List<string>();

        var key = Unlock(Unlocker(keys), vault.Config(HardwareBackend.Tpm, own),
            new UnlockSources(() => { calls.Add("agent"); return null; }, Prompt(Password, calls)));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal(["agent", "prompt"], calls);
    }

    // ------------------------------------------------------------------ the proof: password slots only

    [Fact]
    public void PasswordSlotsOnly_MixedVault_OpensThroughThePasswordSlot()
    {
        // The proof of 'agent start' and 'broker unlock': the password-free YubiKey slot would open the vault,
        // but only this machine's password slot may be used.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        vault.AddYubiKeySlot(keys, SerialA, password: false);
        keys.Challenges.Clear();
        var hardwareCalls = new List<string>();
        using var stretched = StretchedPassword.FromBytes(Password);

        byte[] key;
        using (SimulatedHardwareService.ObserveCalls((backend, call) => hardwareCalls.Add($"{backend.DisplayName} {call}")))
            key = Unlocker(keys).UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, stretched);

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal([$"{HardwareBackend.Tpm.DisplayName} Unlock"], hardwareCalls);
        Assert.Empty(keys.Challenges);
        // The caller's password is still usable: the unlocker only disposed its clones.
        var copy = new byte[StretchedPassword.Size];
        stretched.CopyTo(copy);
        Assert.Equal(Password, copy);
    }

    [Fact]
    public void PasswordSlotsOnly_MixedVault_WrongPassword_Refused()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        vault.AddYubiKeySlot(keys, SerialA, password: false);
        keys.Challenges.Clear();
        using var wrong = StretchedPassword.FromBytes(WrongPassword);

        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlocker(keys).UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, wrong));

        Assert.Contains(WrongPasswordText, ex.Message);
        Assert.Empty(keys.Challenges);
    }

    [Fact]
    public void PasswordSlotsOnly_WrongPassword_WithASetAsideSlot_KeepsTheRefusedType()
    {
        // Review T17 p1 MiMo I2: the set-aside suffix must not turn a refused password into a plain error.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        var corrupt = vault.AddYubiKeySlot(keys, SerialA, password: true);
        var blob = (byte[])vault.Slots[1].HwBlob!.Clone();
        blob[^1] = 0x00;
        vault.ReplaceBlob(corrupt, blob);
        using var wrong = StretchedPassword.FromBytes(WrongPassword);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() =>
            Unlocker(keys).UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, wrong));

        Assert.StartsWith(WrongPasswordText, ex.Message);
        Assert.EndsWith($"Skipped slot(s) {Id8(corrupt)}: their slot blob is corrupt; restore config.json from backup.", ex.Message);
        Assert.Equal(VaultPasswordRefusal.WrongPassword, ex.Reason); // kept through the set-aside suffix
    }

    [Fact]
    public void PasswordSlotsOnly_PasswordYubiKeyBesideAPasswordFreeTpm_UsesTheYubiKey()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: false);
        vault.AddYubiKeySlot(keys, SerialA, password: true);
        keys.Challenges.Clear();
        var hardwareCalls = new List<string>();
        using var stretched = StretchedPassword.FromBytes(Password);

        byte[] key;
        using (SimulatedHardwareService.ObserveCalls((_, call) => hardwareCalls.Add(call)))
            key = Unlocker(keys).UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, stretched);

        Assert.Equal(vault.VaultKey, key);
        Assert.Empty(hardwareCalls); // the password-free TPM slot was never tried
        Assert.Equal([SerialA], keys.Challenges.Select(c => c.Serial));

        using var wrong = StretchedPassword.FromBytes(WrongPassword);
        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlocker(keys).UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, wrong));
        Assert.Contains(WrongPasswordText, ex.Message);
    }

    [Fact]
    public void PasswordSlotsOnly_NoPasswordSlotHere_Refuses_TouchingNothing()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: false);
        vault.AddYubiKeySlot(keys, SerialA, password: false);
        keys.Challenges.Clear();
        var hardwareCalls = new List<string>();
        using var stretched = StretchedPassword.FromBytes(Password);

        TswapException ex;
        using (SimulatedHardwareService.ObserveCalls((_, call) => hardwareCalls.Add(call)))
            ex = Assert.ThrowsAny<TswapException>(() =>
                Unlocker(keys).UnlockWithPasswordSlots(vault.Config(HardwareBackend.Tpm, own), YubiKeySelection.Unattended, stretched));

        Assert.Equal(VaultUnlocker.NoPasswordSlotHereText, ex.Message);
        Assert.Empty(hardwareCalls);
        Assert.Empty(keys.Challenges);
    }

    [Fact]
    public void AgentKey_UsedWithoutTouchingPasswordSlots()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        var hardwareCalls = new List<string>();

        byte[] key;
        using (SimulatedHardwareService.ObserveCalls((_, call) => hardwareCalls.Add(call)))
            key = Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own),
                new UnlockSources(() => (byte[])vault.VaultKey.Clone(), PromptMustNotBeCalled));

        Assert.Equal(vault.VaultKey, key);
        Assert.Empty(hardwareCalls);
    }

    [Fact]
    public void NoReachableCandidate_TodaysMessage_NoSourceCalled()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        vault.AddYubiKeySlot(keys, SerialA, password: true);
        keys.PluggedIn = [];

        var ex = Assert.Throws<TswapException>(() => Unlock(new VaultUnlocker(keys), vault.Config(null, null), NeitherSource));

        Assert.StartsWith("No plugged-in YubiKey matches a slot of this vault. ", ex.Message);
        Assert.Contains($"serial(s) {SerialA}", ex.Message);
    }

    [Fact]
    public void PasswordFreeVault_UnlockFails_NoSourceCalled()
    {
        // A copied config: the TPM slot is another machine's. Today's message, no source called.
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(OtherMachineKey, password: false);

        var ex = Assert.Throws<TswapException>(() =>
            Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own), NeitherSource));

        Assert.EndsWith(VaultUnlocker.ForeignHardwareSlotHint, ex.Message);
        Assert.Contains("made on a different machine", ex.Message);
    }

    // ------------------------------------------------------------------ combined errors

    [Fact]
    public void AllPassesFail_MessageCombinesAsToday()
    {
        // Pass 1: the own TPM slot (no password) is another machine's, and key A (no password) was
        // reprogrammed. Pass 3: key B's password slot gets the wrong password.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        var reprogrammedA = new SimulatedYubiKeyService(new Dictionary<int, byte[]> { [SerialA] = RandomNumberGenerator.GetBytes(20) });
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(OtherMachineKey, password: false);
        vault.AddYubiKeySlot(reprogrammedA, SerialA, password: false);
        vault.AddYubiKeySlot(keys, SerialB, password: true);

        var ex = Assert.Throws<TswapException>(() => Unlock(Unlocker(keys), vault.Config(HardwareBackend.Tpm, own),
            new UnlockSources(() => null, Prompt(WrongPassword))));

        Assert.Contains($"YubiKey {SerialA} did not open any of its slots", ex.Message);           // YubiKey pass 1
        Assert.Contains("(The vault's own backend failed too: ", ex.Message);                     // ownFailure
        Assert.Contains(VaultUnlocker.ForeignHardwareSlotHint, ex.Message);                       // own backend + hint
        Assert.Contains(WrongPasswordText, ex.Message);                                           // pass 3
        Assert.True(ex.Message.IndexOf(WrongPasswordText, StringComparison.Ordinal) >
                    ex.Message.IndexOf(VaultUnlocker.ForeignHardwareSlotHint, StringComparison.Ordinal),
            "the pass 3 failure follows the pass 1 failure");
    }

    [Fact]
    public void Pass1Failure_HiddenWhenPass3Succeeds()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        var reprogrammedA = new SimulatedYubiKeyService(new Dictionary<int, byte[]> { [SerialA] = RandomNumberGenerator.GetBytes(20) });
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(OtherMachineKey, password: false);
        vault.AddYubiKeySlot(reprogrammedA, SerialA, password: false);
        vault.AddYubiKeySlot(keys, SerialB, password: true);
        keys.Challenges.Clear();

        var key = Unlock(Unlocker(keys), vault.Config(HardwareBackend.Tpm, own), new UnlockSources(() => null, Prompt(Password)));

        Assert.Equal(vault.VaultKey, key);
        Assert.Equal([SerialA, SerialB], keys.Challenges.Select(c => c.Serial)); // pass 1 really failed first
    }

    [Fact]
    public void AgentFailedAndPromptFailed_MessageNamesBoth()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);

        var ex = Assert.Throws<TswapException>(() => Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()),
            vault.Config(HardwareBackend.Tpm, own),
            new UnlockSources(() => throw new AgentUnlockFailedException("the agent's TPM said no."), Prompt(WrongPassword))));

        Assert.Equal($"{WrongPasswordText} The tswap agent could not unlock either: the agent's TPM said no.", ex.Message);
    }

    [Fact]
    public void AgentKeyCheckRefusal_PassesThrough()
    {
        // ruling 9: a key that fails keyCheck is refused by AskAgent itself (a plain TswapException).
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);

        var ex = Assert.Throws<TswapException>(() => Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()),
            vault.Config(HardwareBackend.Tpm, own),
            new UnlockSources(() => throw new TswapException("returned a key that doesn't open this vault"), PromptMustNotBeCalled)));

        Assert.Equal("returned a key that doesn't open this vault", ex.Message);
    }

    // ------------------------------------------------------------------ CouldNeedPassword

    [Fact]
    public void CouldNeedPassword_TruthTable()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);

        var tpmPassword = new VaultBuilder();
        var own1 = tpmPassword.AddTpmSlot(MachineKey, password: true);
        Assert.True(VaultUnlocker.CouldNeedPassword(tpmPassword.Config(HardwareBackend.Tpm, own1), []));

        var tpmLegacy = new VaultBuilder();
        var own2 = tpmLegacy.AddTpmSlot(MachineKey, password: false);
        Assert.False(VaultUnlocker.CouldNeedPassword(tpmLegacy.Config(HardwareBackend.Tpm, own2), [SerialA]));

        var yubiKeyPassword = new VaultBuilder();
        yubiKeyPassword.AddYubiKeySlot(keys, SerialA, password: true);
        Assert.True(VaultUnlocker.CouldNeedPassword(yubiKeyPassword.Config(null, null), [SerialA]));
        Assert.False(VaultUnlocker.CouldNeedPassword(yubiKeyPassword.Config(null, null), [SerialB]));
        Assert.False(VaultUnlocker.CouldNeedPassword(yubiKeyPassword.Config(null, null), []));

        var mixed = new VaultBuilder();
        mixed.AddYubiKeySlot(keys, SerialA, password: false);
        mixed.AddYubiKeySlot(keys, SerialB, password: true);
        Assert.True(VaultUnlocker.CouldNeedPassword(mixed.Config(null, null), [SerialA, SerialB]));

        var passwordFree = new VaultBuilder();
        var own3 = passwordFree.AddTpmSlot(MachineKey, password: false);
        passwordFree.AddYubiKeySlot(keys, SerialA, password: false);
        Assert.False(VaultUnlocker.CouldNeedPassword(passwordFree.Config(HardwareBackend.Tpm, own3), [SerialA, SerialB]));

        // Review T17 p4 MiMo M3: a corrupt or needs-newer-tswap slot is set aside, never counted as a password slot
        // (ruling 3), so a vault whose only "password" slots are such slots never asks for the password.
        var corruptOwn = new VaultBuilder();
        var own4 = corruptOwn.AddTpmSlot(MachineKey, password: true);
        var tstp = (byte[])corruptOwn.Slots[0].HwBlob!.Clone();
        tstp[5] = 0x00; // a TSTP header without the password flag: corrupt
        corruptOwn.ReplaceBlob(own4, tstp);
        Assert.False(VaultUnlocker.CouldNeedPassword(corruptOwn.Config(HardwareBackend.Tpm, own4), []));

        var newerYubiKey = new VaultBuilder();
        var newer = newerYubiKey.AddYubiKeySlot(keys, SerialA, password: true);
        var tsyk = (byte[])newerYubiKey.Slots[0].HwBlob!.Clone();
        tsyk[^1] = 0x03; // a flag this tswap doesn't know: needs a newer tswap
        newerYubiKey.ReplaceBlob(newer, tsyk);
        Assert.False(VaultUnlocker.CouldNeedPassword(newerYubiKey.Config(null, null), [SerialA]));
    }

    // ------------------------------------------------------------------ set-aside slots (ruling 3)

    [Fact]
    public void StrippedHeader_SaysRestoreOrUpgrade()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        vault.ReplaceBlob(own, TpmSlotBlob.Split(vault.Slots[0].HwBlob!).Package);

        var ex = Assert.ThrowsAny<TswapException>(() =>
            Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own), NeitherSource));

        Assert.Equal(StrippedHeaderText, ex.Message);
    }

    [Fact]
    public void UnknownHeaderVersion_RefusedAtClassification_NoPrompt_SaysNewerTswap()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        var blob = (byte[])vault.Slots[0].HwBlob!.Clone();
        blob[4] = 2;
        vault.ReplaceBlob(own, blob);
        var hardwareCalls = new List<string>();

        TswapException ex;
        using (SimulatedHardwareService.ObserveCalls((_, call) => hardwareCalls.Add(call)))
            ex = Assert.Throws<TswapException>(() =>
                Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own), NeitherSource));

        Assert.EndsWith($"Slot {Id8(own)}: needs a newer tswap (blob version 2 or unknown flags); upgrade tswap.", ex.Message);
        Assert.Empty(hardwareCalls);
    }

    [Fact]
    public void Messages_CallerPrefixesSlotId()
    {
        // The unlocker prefixes the NeedsNewerTswap text with the slot id; Split/Decode texts carry none.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        var vault = new VaultBuilder();
        var newer = vault.AddYubiKeySlot(keys, SerialB, password: true);
        var blob = (byte[])vault.Slots[0].HwBlob!.Clone();
        blob[^1] = 0x03;
        vault.ReplaceBlob(newer, blob);
        vault.AddYubiKeySlot(keys, SerialA, password: false);
        keys.PluggedIn = [];

        var split = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(blob));
        Assert.StartsWith("needs a newer tswap", split.Message);

        var ex = Assert.Throws<TswapException>(() => Unlock(new VaultUnlocker(keys), vault.Config(null, null), NeitherSource));
        Assert.EndsWith($"Slot {Id8(newer)}: needs a newer tswap (blob version 2 or unknown flags); upgrade tswap.", ex.Message);
    }

    [Fact]
    public void CorruptSlot_BesideGoodPasswordFreeSlot_StillUnlocks()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        var vault = new VaultBuilder();
        var corrupt = vault.AddYubiKeySlot(keys, SerialB, password: true);
        var blob = (byte[])vault.Slots[0].HwBlob!.Clone();
        blob[^1] = 0x00;
        vault.ReplaceBlob(corrupt, blob);
        vault.AddYubiKeySlot(keys, SerialA, password: false);

        Assert.Equal(vault.VaultKey, Unlock(new VaultUnlocker(keys), vault.Config(null, null), NeitherSource));
    }

    [Fact]
    public void CorruptSlot_Alone_NamedInTheError()
    {
        var vault = new VaultBuilder();
        var own = vault.AddTpmSlot(MachineKey, password: true);
        var blob = (byte[])vault.Slots[0].HwBlob!.Clone();
        blob[5] = 0x00;
        vault.ReplaceBlob(own, blob);

        var ex = Assert.Throws<TswapException>(() =>
            Unlock(Unlocker(SimulatedYubiKeyService.WithKeys()), vault.Config(HardwareBackend.Tpm, own), NeitherSource));

        Assert.Contains($"Skipped slot(s) {Id8(own)}: their slot blob is corrupt; restore config.json from backup.", ex.Message);
    }

    [Fact]
    public void CorruptYubiKeySlot_Alone_NamedWithTheGeneralisedText()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new VaultBuilder();
        var corrupt = vault.AddYubiKeySlot(keys, SerialA, password: true);
        var blob = (byte[])vault.Slots[0].HwBlob!.Clone();
        blob[^1] = 0x00;
        vault.ReplaceBlob(corrupt, blob);

        var ex = Assert.Throws<TswapException>(() => Unlock(new VaultUnlocker(keys), vault.Config(null, null), NeitherSource));

        Assert.EndsWith($"Skipped slot(s) {Id8(corrupt)}: their slot blob is corrupt; restore config.json from backup.", ex.Message);
    }

    // ------------------------------------------------------------------ the services

    [Fact]
    public void SimulatedEnroll_WithPassword_WrapsWithTheBackendsHeader()
    {
        using var stretched = StretchedPassword.FromBytes(Password);
        var (_, tpmBlob) = new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey).Enroll(stretched);
        var (_, seBlob) = new SimulatedHardwareService(HardwareBackend.SecureEnclave, MachineKey).Enroll(stretched);
        var (_, plainBlob) = new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey).Enroll(null);

        Assert.True(TpmSlotBlob.HasHeader(tpmBlob));
        Assert.True(SecureEnclaveSlotBlob.HasHeader(seBlob));
        // Issue #261: a simulated TPM slot has the Linux layout, so the password-free one has a TSTP header too,
        // with only the ECC-primary bit.
        Assert.Equal([.. "TSTP"u8, 1, TpmSlotBlob.EccPrimary], plainBlob[..6]);
        // The package is a password-free one plus the simulated "object needs a password" marker.
        Assert.Equal(TpmSlotBlob.Split(plainBlob).Package.Length + 1, TpmSlotBlob.Split(tpmBlob).Package.Length);
    }

    [Fact]
    public void UnlockHardware_PassesThePasswordToTheBackend()
    {
        // slot accept's path: KEK_slot straight from the hardware, with the password.
        using var stretched = StretchedPassword.FromBytes(Password);
        var (kek, blob) = new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey).Enroll(stretched);
        var config = new Config([], "", DateTime.UtcNow, RequiresTouch: true, RngMode: RngMode.System, Backend: HardwareBackend.Tpm,
            PendingSlotId: Convert.ToBase64String(new byte[16]), PendingSlotHwBlob: Convert.ToBase64String(blob));

        var recovered = Unlocker(SimulatedYubiKeyService.WithKeys())
            .UnlockHardware(config, YubiKeySelection.Unattended, () => StretchedPassword.FromBytes(Password));

        Assert.Equal(kek, recovered);
    }

    [Fact]
    public void LinuxTpm_UnsplitPasswordBlob_RefusedBeforeTpm2Tools()
    {
        if (!OperatingSystem.IsLinux())
            return;
        // Brief T17 task 8 replaced task 3's NotImplementedException placeholder: an unsplit TSTP blob is
        // still refused before tpm2-tools is touched, now with ruling 3's legacy-parser text
        // (Tpm2ArgvTests.UnsplitTstpBlob_SaysNewerTswap pins it in full).
        var tstp = TpmSlotBlob.Wrap([5, 0, 0, 0, 1, 2, 3, 4, 5, 6], TpmSlotBlob.Password);
#pragma warning disable CA1416 // guarded by the IsLinux return above; the analyzer doesn't follow it into the lambda
        var ex = Assert.Throws<TswapException>(() => TswapCore.Vault.Interop.Tpm2ToolsInterop.Unseal(tstp, eccPrimary: false));
#pragma warning restore CA1416
        Assert.Equal(VaultPasswordMessages.LegacyParserNeedsNewerTswap(1), ex.Message);
    }
}
