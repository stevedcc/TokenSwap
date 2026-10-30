using System.Security.Cryptography;
using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T4 item 2 (decision 3): <see cref="VaultUnlocker"/> tries the vault's own backend first,
/// then every one-key YubiKey slot (a slot whose hwBlob is a <see cref="YubiKeySlotBlob"/>) whose
/// key is plugged in. Keyrings are built here the way the enrollment code builds them, with
/// <see cref="SimulatedYubiKeyService"/> answering real per-key HMAC-SHA1 challenges.
/// </summary>
public class YubiKeySlotUnlockTests
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;
    private const int SerialC = 33333333;

    private static readonly byte[] MachineKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] OtherMachineKey = RandomNumberGenerator.GetBytes(32);

    private static int NoSelection(IReadOnlyList<int> serials) =>
        throw new InvalidOperationException($"chooseSerial must not be called (got {string.Join(", ", serials)})");

    private sealed class KeyringBuilder
    {
        public byte[] VaultKey { get; } = RandomNumberGenerator.GetBytes(32);
        public byte[] VaultId { get; } = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        public List<Slot> Slots { get; } = [];

        public byte[] AddYubiKeySlot(IYubiKeyService keys, int serial)
        {
            var blob = YubiKeySlotBlob.Create(serial, requiresTouch: true);
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var kek = YubiKeySlotKek.Recover(keys, blob, slotId);
            AddMachineSlot(slotId, kek, blob.Encode());
            return slotId;
        }

        public byte[] AddTpmSlot(byte[] machineKey)
        {
            var (kek, hwBlob) = new SimulatedHardwareService(HardwareBackend.Tpm, machineKey).Enroll();
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            AddMachineSlot(slotId, kek, hwBlob);
            return slotId;
        }

        private void AddMachineSlot(byte[] slotId, byte[] kek, byte[] hwBlob)
        {
            var pair = SlotKeyPair.Generate();
            Slots.Add(MachineSlotWrap.Wrap(VaultKey, pair.PrivateKey, pair.PublicKey, slotId, kek,
                KeyringFormat.KeyringFormatVersion, VaultId, 1) with { HwBlob = hwBlob });
        }

        public Config Config(HardwareBackend? backend = null, byte[]? ownSlotId = null) => new(
            [], "", DateTime.UtcNow, RequiresTouch: true, RngMode: RngMode.System, Backend: backend,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(new Keyring(KeyringFormat.KeyringFormatVersion, VaultId, 1, Slots))),
            KeyringSlotId: ownSlotId == null ? null : Convert.ToBase64String(ownSlotId));
    }

    private static (SimulatedYubiKeyService Keys, KeyringBuilder Vault, Config Config) TwoKeyVault()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB, SerialC);
        var vault = new KeyringBuilder();
        var slotA = vault.AddYubiKeySlot(keys, SerialA);
        vault.AddYubiKeySlot(keys, SerialB);
        keys.Challenges.Clear();
        // KeyringSlotId names A's slot (this "machine" enrolled A); B's slot must still open the
        // vault on its own: a YubiKey slot needs no KeyringSlotId.
        return (keys, vault, vault.Config(ownSlotId: slotA));
    }

    [Fact]
    public void TwoYubiKeySlots_OnlyAPluggedIn_Unlocks()
    {
        var (keys, vault, config) = TwoKeyVault();
        keys.PluggedIn = [SerialA];

        Assert.Equal(vault.VaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([SerialA], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void TwoYubiKeySlots_OnlyBPluggedIn_Unlocks()
    {
        var (keys, vault, config) = TwoKeyVault();
        keys.PluggedIn = [SerialB];

        Assert.Equal(vault.VaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([SerialB], keys.Challenges.Select(c => c.Serial));
    }

    [Theory]
    [InlineData(SerialA)]
    [InlineData(SerialB)]
    public void TwoYubiKeySlots_BothPluggedIn_ChooseSerialDecides(int chosen)
    {
        var (keys, vault, config) = TwoKeyVault();
        keys.PluggedIn = [SerialA, SerialB];
        IReadOnlyList<int>? offered = null;

        var unlocked = new VaultUnlocker(keys).Unlock(config, serials => { offered = serials; return chosen; });

        Assert.Equal(vault.VaultKey, unlocked);
        Assert.Equal([SerialA, SerialB], offered);
        Assert.Equal([chosen], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void TwoYubiKeySlots_AnUnenrolledKeyAlsoPluggedIn_IsNotOffered()
    {
        var (keys, vault, config) = TwoKeyVault();
        keys.PluggedIn = [SerialC, SerialB];

        Assert.Equal(vault.VaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([SerialB], keys.Challenges.Select(c => c.Serial));
    }

    [Theory]
    [InlineData(SerialC)]
    [InlineData]
    public void TwoYubiKeySlots_NeitherPluggedIn_ActionableErrorListingTheSlotSerials(params int[] pluggedIn)
    {
        var (keys, _, config) = TwoKeyVault();
        keys.PluggedIn = [.. pluggedIn];

        var ex = Assert.Throws<TswapException>(() => new VaultUnlocker(keys).Unlock(config, NoSelection));

        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", ex.Message);
        Assert.Contains(SerialA.ToString(), ex.Message);
        Assert.Contains(SerialB.ToString(), ex.Message);
        Assert.Empty(keys.Challenges);
    }

    [Fact]
    public void SameKeyInTwoSlots_TheFirstSlotThatAuthenticatesWins()
    {
        // Key A has two slots (e.g. one enrolled on the router, one through slot request). The
        // first one's wrapped bytes are damaged; unlock goes on to the second.
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new KeyringBuilder();
        vault.AddYubiKeySlot(keys, SerialA);
        vault.AddYubiKeySlot(keys, SerialA);
        var damaged = vault.Slots[0].Wrapped.ToArray();
        damaged[^1] ^= 0xFF;
        vault.Slots[0] = vault.Slots[0] with { Wrapped = damaged };
        keys.Challenges.Clear();

        Assert.Equal(vault.VaultKey, new VaultUnlocker(keys).Unlock(vault.Config(), NoSelection));
        Assert.Equal(2, keys.Challenges.Count);
    }

    [Fact]
    public void ChosenKeyOpensNoSlot_FailsWithATswapExceptionNamingTheKey()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new KeyringBuilder();
        vault.AddYubiKeySlot(keys, SerialA);
        var damaged = vault.Slots[0].Wrapped.ToArray();
        damaged[^1] ^= 0xFF;
        vault.Slots[0] = vault.Slots[0] with { Wrapped = damaged };

        var ex = Assert.Throws<TswapException>(() => new VaultUnlocker(keys).Unlock(vault.Config(), NoSelection));

        Assert.Contains(SerialA.ToString(), ex.Message);
    }

    // --- A TPM vault with a YubiKey slot ---

    private static (SimulatedYubiKeyService Keys, KeyringBuilder Vault, Config Config) TpmVaultWithYubiKeySlot()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var vault = new KeyringBuilder();
        var tpmSlot = vault.AddTpmSlot(MachineKey);
        vault.AddYubiKeySlot(keys, SerialA);
        keys.Challenges.Clear();
        return (keys, vault, vault.Config(HardwareBackend.Tpm, ownSlotId: tpmSlot));
    }

    [Fact]
    public void TpmVaultWithYubiKeySlot_TpmAvailable_UnlocksThroughTheTpm()
    {
        var (keys, vault, config) = TpmVaultWithYubiKeySlot();
        var unlocker = new VaultUnlocker(keys, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey)]);

        Assert.Equal(vault.VaultKey, unlocker.Unlock(config, NoSelection));
        Assert.Empty(keys.Challenges);
    }

    [Fact]
    public void TpmVaultWithYubiKeySlot_NoTpmBackendInThisBuild_UnlocksThroughTheYubiKey()
    {
        var (keys, vault, config) = TpmVaultWithYubiKeySlot();

        Assert.Equal(vault.VaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([SerialA], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void TpmVaultWithYubiKeySlot_OnAnotherMachinesTpm_UnlocksThroughTheYubiKey()
    {
        // The vault files copied to a laptop: its TPM cannot unseal the router's blob, but the
        // owner's YubiKey opens its own slot.
        var (keys, vault, config) = TpmVaultWithYubiKeySlot();
        var unlocker = new VaultUnlocker(keys, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, OtherMachineKey)]);

        Assert.Equal(vault.VaultKey, unlocker.Unlock(config, NoSelection));
        Assert.Equal([SerialA], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void TpmVaultWithYubiKeySlot_NeitherAvailable_ErrorNamesTheSlotSerialAndTheTpmFailure()
    {
        var (keys, _, config) = TpmVaultWithYubiKeySlot();
        keys.PluggedIn = [];
        var unlocker = new VaultUnlocker(keys, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, OtherMachineKey)]);

        var ex = Assert.Throws<TswapException>(() => unlocker.Unlock(config, NoSelection));

        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", ex.Message);
        Assert.Contains(SerialA.ToString(), ex.Message);
        Assert.Contains("different machine", ex.Message); // the TPM's own error, kept
    }

    [Fact]
    public void TpmVaultWithoutYubiKeySlots_KeepsItsOwnErrorUnchanged()
    {
        var vault = new KeyringBuilder();
        var tpmSlot = vault.AddTpmSlot(MachineKey);
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);
        var unlocker = new VaultUnlocker(keys, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, OtherMachineKey)]);

        var ex = Assert.Throws<TswapException>(() => unlocker.Unlock(vault.Config(HardwareBackend.Tpm, tpmSlot), NoSelection));

        Assert.StartsWith("Simulated 'tpm' operation failed", ex.Message);
        Assert.Empty(keys.Challenges);
    }

    // --- Legacy pair keyring plus a one-key slot ---

    private static (SimulatedYubiKeyService Keys, Config Config, byte[] VaultKey) PairFixtureWithSlotForC()
    {
        var keys = SimulatedYubiKeyService.WithKeys(KeyringV3PairFixtureTests.SerialA, KeyringV3PairFixtureTests.SerialB, SerialC);
        var fixture = KeyringV3PairFixtureTests.FixtureConfig();
        keys.PluggedIn = [KeyringV3PairFixtureTests.SerialA];
        var vaultKey = new VaultUnlocker(keys).Unlock(fixture, NoSelection);

        var keyring = KeyringCodec.Decode(Convert.FromBase64String(fixture.Keyring!));
        var blob = YubiKeySlotBlob.Create(SerialC, requiresTouch: true);
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var pair = SlotKeyPair.Generate();
        keys.PluggedIn = [SerialC];
        var slot = MachineSlotWrap.Wrap(vaultKey, pair.PrivateKey, pair.PublicKey, slotId,
            YubiKeySlotKek.Recover(keys, blob, slotId), keyring.FormatVersion, keyring.VaultId, keyring.K) with { HwBlob = blob.Encode() };
        var extended = keyring with { Slots = [.. keyring.Slots, slot] };
        keys.Challenges.Clear();
        return (keys, fixture with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(extended)) }, vaultKey);
    }

    [Fact]
    public void PairKeyringWithAOneKeySlot_PairKeyUnlocksThroughThePairPath()
    {
        var (keys, config, vaultKey) = PairFixtureWithSlotForC();
        keys.PluggedIn = [KeyringV3PairFixtureTests.SerialB];

        Assert.Equal(vaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([(KeyringV3PairFixtureTests.SerialB, config.UnlockChallenge!)], keys.Challenges);
    }

    [Fact]
    public void PairKeyringWithAOneKeySlot_TheNewKeyAloneUnlocks()
    {
        var (keys, config, vaultKey) = PairFixtureWithSlotForC();
        keys.PluggedIn = [SerialC];

        Assert.Equal(vaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([SerialC], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void PairKeyringWithoutOneKeySlots_UnenrolledKeyKeepsThePairError()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialC);

        var ex = Assert.Throws<TswapException>(() =>
            new VaultUnlocker(keys).Unlock(KeyringV3PairFixtureTests.FixtureConfig(), NoSelection));

        Assert.Equal($"YubiKey {SerialC} not authorized. Expected: {KeyringV3PairFixtureTests.SerialA}, {KeyringV3PairFixtureTests.SerialB}", ex.Message);
    }

    [Fact]
    public void LegacyV2Fixture_StillUnlocksInTestMode()
    {
        var testKey = Convert.FromHexString(KeyringV2FixtureTests.FixtureTestKeyHex);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var config = JsonSerializer.Deserialize(KeyringV2FixtureTests.FixtureConfigJson, TswapJsonContext.Default.Config)!;
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var recovery = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        var viaRecovery = RecoverySlotWrap.Unwrap(recovery.Wrapped, recovery.PublicKey,
            Convert.FromBase64String(KeyringV2FixtureTests.FixtureRecoveryPrivateKey),
            keyring.FormatVersion, keyring.VaultId, keyring.K, recovery.SlotId);

        Assert.Equal(viaRecovery, new VaultUnlocker(yubiKeys, overrideKey: testKey).Unlock(config, NoSelection));
    }
}
