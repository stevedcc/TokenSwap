using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Follow-ups from the external security review of brief T4: (1) enrollment challenges the key
/// twice and refuses one that answers differently; (2) a corrupt YubiKey blob in one slot does
/// not stop another slot from unlocking; (3) <c>slot add --yubikey</c> refuses a version 2
/// keyring before sudo and before any unlock.
/// </summary>
public class T4ReviewFollowUpTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-t4-followup-" + Guid.NewGuid().ToString("N")[..8]);

    public T4ReviewFollowUpTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    private (int Exit, string Out, string Err) Run(IYubiKeyService keys, string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var exit = CliRunner.Run(new CommandContext(console, env, new Storage(_dir), keys, new VaultUnlocker(keys), TestKey: null, SudoBypass: true), args);
        return (exit, console.OutText, console.ErrorText);
    }

    // --- 1. Enrollment double challenge ---

    /// <summary>One plugged-in key whose response to the same challenge alternates between two values.</summary>
    private sealed class AlternatingYubiKey(int serial) : IYubiKeyService
    {
        private int _calls;
        public bool IsSimulated => false;
        public IReadOnlyList<int> ListSerials() => [serial];
        public byte[] Challenge(int s, string challenge)
        {
            var response = HMACSHA1.HashData(SimulatedYubiKeyService.SecretFor(s), System.Text.Encoding.UTF8.GetBytes(challenge));
            if (_calls++ % 2 == 1)
                response[0] ^= 1;
            return response;
        }
        public bool? DetectTouchRequirement(int s) => false;
    }

    private void AssertRefusedAsInconsistent(int exit, string stderr)
    {
        Assert.NotEqual(0, exit);
        Assert.Contains("answered the same challenge differently", stderr);
    }

    [Fact]
    public void InitKeyring_KeyWithInconsistentResponses_IsRefusedAndNothingIsWritten()
    {
        var (exit, _, stderr) = Run(new AlternatingYubiKey(SerialA), "", "init", "--keyring");

        AssertRefusedAsInconsistent(exit, stderr);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public void SlotRequest_KeyWithInconsistentResponses_IsRefusedAndNothingIsWritten()
    {
        var requestFile = Path.Combine(_dir, "request.json");

        var (exit, _, stderr) = Run(new AlternatingYubiKey(SerialA), "", "slot", "request", requestFile);

        AssertRefusedAsInconsistent(exit, stderr);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    /// <summary>Key A answers consistently (it unlocks the vault); key B alternates.</summary>
    private sealed class GoodAAlternatingB : IYubiKeyService
    {
        private readonly SimulatedYubiKeyService _good = SimulatedYubiKeyService.WithKeys(SerialA);
        private readonly AlternatingYubiKey _bad = new(SerialB);
        public bool IsSimulated => false;
        public IReadOnlyList<int> ListSerials() => [SerialA, SerialB];
        public byte[] Challenge(int serial, string challenge) =>
            serial == SerialA ? _good.Challenge(serial, challenge) : _bad.Challenge(serial, challenge);
        public bool? DetectTouchRequirement(int serial) => true;
    }

    [Fact]
    public void SlotAdd_KeyWithInconsistentResponses_IsRefusedAndConfigIsUntouched()
    {
        var keyA = SimulatedYubiKeyService.WithKeys(SerialA);
        Assert.Equal(0, Run(keyA, "", "init", "--keyring").Exit);
        var configPath = Path.Combine(_dir, "config.json");
        var before = File.ReadAllText(configPath);

        var (exit, _, stderr) = Run(new GoodAAlternatingB(), "", "slot", "add", "--yubikey");

        AssertRefusedAsInconsistent(exit, stderr);
        Assert.Equal(before, File.ReadAllText(configPath));
        Assert.Empty(Directory.GetFiles(_dir, "config.json.bak-*"));
    }

    [Fact]
    public void Enroll_ChallengesTheKeyTwiceWithTheSameChallenge()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA);

        Assert.Equal(0, Run(keys, "", "init", "--keyring").Exit);

        Assert.Equal(2, keys.Challenges.Count);
        Assert.Equal(keys.Challenges[0], keys.Challenges[1]);
    }

    // --- 2. A corrupt blob does not block the fallback ---

    private static (SimulatedYubiKeyService Keys, byte[] VaultKey, Config Config, byte[] CorruptSlotId) VaultWithCorruptSlotForBAndGoodSlotForA()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        var slots = new List<Slot>();
        foreach (var serial in new[] { SerialB, SerialA }) // B's slot first, so it is met first
        {
            var blob = YubiKeySlotBlob.Create(serial, requiresTouch: true);
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var pair = SlotKeyPair.Generate();
            slots.Add(MachineSlotWrap.Wrap(vaultKey, pair.PrivateKey, pair.PublicKey, slotId,
                YubiKeySlotKek.Recover(keys, blob, slotId), KeyringFormat.KeyringFormatVersion, vaultId, 1) with { HwBlob = blob.Encode() });
        }
        // Corrupt B's blob: right magic, one trailing byte, so it fails strict decoding.
        slots[0] = slots[0] with { HwBlob = [.. slots[0].HwBlob!, 0] };
        keys.Challenges.Clear();
        var config = new Config([], "", DateTime.UtcNow, RequiresTouch: true,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(new Keyring(KeyringFormat.KeyringFormatVersion, vaultId, 1, slots))));
        return (keys, vaultKey, config, slots[0].SlotId);
    }

    private static int NoSelection(IReadOnlyList<int> serials) => throw new InvalidOperationException("no prompt expected");

    [Fact]
    public void CorruptBlobInAnUnpluggedKeysSlot_DoesNotStopAPluggedInKeysSlot()
    {
        var (keys, vaultKey, config, _) = VaultWithCorruptSlotForBAndGoodSlotForA();
        keys.PluggedIn = [SerialA];

        Assert.Equal(vaultKey, new VaultUnlocker(keys).Unlock(config, NoSelection));
        Assert.Equal([SerialA], keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void CorruptBlob_WhenNothingElseUnlocks_TheErrorNamesTheCorruptSlot()
    {
        var (keys, _, config, corruptSlotId) = VaultWithCorruptSlotForBAndGoodSlotForA();
        keys.PluggedIn = [SerialB];

        var ex = Assert.Throws<TswapException>(() => new VaultUnlocker(keys).Unlock(config, NoSelection));

        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", ex.Message);
        Assert.Contains(Convert.ToHexString(corruptSlotId).ToLowerInvariant()[..8], ex.Message);
        Assert.Contains("corrupt", ex.Message);
    }

    // --- 3. slot add refuses a version 2 keyring before sudo and unlock ---

    private sealed class UntouchableYubiKeys : IYubiKeyService
    {
        public bool IsSimulated => false;
        public IReadOnlyList<int> ListSerials() => throw new InvalidOperationException("must not touch the YubiKey");
        public byte[] Challenge(int serial, string challenge) => throw new InvalidOperationException("must not touch the YubiKey");
        public bool? DetectTouchRequirement(int serial) => throw new InvalidOperationException("must not touch the YubiKey");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SlotAdd_Version2Keyring_IsRefusedBeforeSudoAndBeforeAnyUnlock(bool sudoBypass)
    {
        File.WriteAllText(Path.Combine(_dir, "config.json"), KeyringV2FixtureTests.FixtureConfigJson);
        var keys = new UntouchableYubiKeys();
        var console = new FakeConsole();
        string[] args = ["slot", "add", "--yubikey"];
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        // No override key: an unlock would have to go through the untouchable service.
        var ctx = new CommandContext(console, env, new Storage(_dir), keys, new VaultUnlocker(keys), TestKey: null, SudoBypass: sudoBypass);

        var exit = CliRunner.Run(ctx, args);

        Assert.NotEqual(0, exit);
        Assert.Contains("format version 2", console.ErrorText);
        Assert.DoesNotContain("must not touch", console.ErrorText);
        Assert.DoesNotContain("requires sudo", console.ErrorText);
        Assert.Equal(KeyringV2FixtureTests.FixtureConfigJson, File.ReadAllText(Path.Combine(_dir, "config.json")));
    }
}
