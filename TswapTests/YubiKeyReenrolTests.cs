using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCli;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 4b: <c>slot add --yubikey</c> re-enrols a key whose one-key slots no longer open (after
/// <c>yubikey setup --replace</c>), unlocking through another way in; the old slots are kept, and this machine remembers
/// (<c>yubikey-slots.json</c>) the slot each key last opened with, so unlock tries it first. The migrate guide's touch
/// upgrade uses this flow. Everything runs in process against <see cref="SimulatedYubiKeyService"/>: reprogramming a
/// simulated key gives it a fresh secret, so its old slots answer wrongly. In the static-seam collection because the
/// agent tests watch <see cref="AgentUnlock.AskedObserver"/>.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed partial class YubiKeyReenrolTests : IDisposable
{
    private const int SerialA = 51111111;
    private const int SerialB = 52222222;
    private const int SerialT = 53333333;
    private const int PairA = KeyringV3PairFixtureTests.SerialA;
    private const int PairB = KeyringV3PairFixtureTests.SerialB;
    private const string Password = "correct horse battery staple";
    private const string WrongPassword = "incorrect horse";

    private readonly List<FleetMachine> _machines = [];
    private readonly List<AgentServer> _agents = [];
    private string _recoveryKey = "";

    public void Dispose()
    {
        foreach (var agent in _agents)
            agent.DisposeAsync().AsTask().GetAwaiter().GetResult();
        AgentUnlock.AskedObserver = null;
        foreach (var m in _machines)
            m.Dispose();
    }

    // ── vaults ────────────────────────────────────────────────────────────────

    private FleetMachine Machine(params int[] serials)
    {
        var m = new FleetMachine("reenrol", SimulatedYubiKeyService.WithKeys(serials));
        _machines.Add(m);
        return m;
    }

    /// <summary>
    /// A classic two-key XOR vault on A and B converted with <c>migrate --to-records</c> (one one-key slot per key and a
    /// recovery slot), holding the secret <c>db</c>. The call log is cleared.
    /// </summary>
    private FleetMachine ConvertedTwoKeyVault()
    {
        var m = Machine(SerialA, SerialB);
        ClassicVaultTestSupport.CreateXorVault(m, SerialA, SerialB);
        m.Keys.PluggedIn = [SerialA, SerialB];
        _recoveryKey = RecordVaultTestSupport.RecoveryKeyFrom(m.Ok("", "migrate", "--to-records"));
        m.Ok("s3cret\ns3cret\n", "add", "db");
        Assert.Equal([SerialA, SerialB], OneKeySlots(m).Select(s => s.Blob.Serial));
        Assert.Contains(m.Keyring.Slots, s => s.Kind == SlotKind.Recovery);
        m.Keys.Challenges.Clear();
        return m;
    }

    /// <summary>What <c>yubikey setup --replace</c> does to the key: a fresh secret in slot 2.</summary>
    private static void Reprogram(FleetMachine m, int serial, bool touch = true)
    {
        m.Keys.ProgramSlot2(serial, touch);
        m.Keys.Programmed.Clear();
    }

    private static List<(Slot Slot, YubiKeySlotBlob Blob)> OneKeySlots(FleetMachine m) =>
        m.Keyring.Slots.Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .Select(s => (s, YubiKeySlotBlob.Decode(s.HwBlob!))).ToList();

    private static List<(Slot Slot, YubiKeySlotBlob Blob)> SlotsOf(FleetMachine m, int serial) =>
        OneKeySlots(m).Where(s => s.Blob.Serial == serial).ToList();

    private static List<string> ChallengesOf(FleetMachine m, int serial) =>
        m.Keys.Challenges.Where(c => c.Serial == serial).Select(c => c.Challenge).ToList();

    private static string HintPath(FleetMachine m) => Path.Combine(m.Dir, RememberedYubiKeySlots.FileName);

    private static string KeyringPath(FleetMachine m) => Path.Combine(m.VaultDir!, RecordVaultStore.KeyringFileName);

    private static (int Exit, string Out, string Err) SlotAdd(FleetMachine m, params string[] extra) =>
        m.Run("", ["slot", "add", "--yubikey", .. extra]);

    private static string ReenrolledLine(int serial) => $"YubiKey {serial} re-enrolled as a new slot (fingerprint ";

    private const string KeptText =
        "its old slot(s) no longer open and are kept (`tswap slots` lists them as other slots of this key).";

    private static string TouchCount(int check) => $"{check} for the check, plus 2 if the key is re-enrolled";

    private static string WorkingSlot(int serial) => $"YubiKey {serial} already has a working slot";

    private const string MistypedLine = "if you mistyped the vault password, stop now (Ctrl-C)";

    private const string OtherSlotMark = "another slot of this key (not the one it last opened with)";

    // ── re-enrolment ──────────────────────────────────────────────────────────

    [Fact]
    public void SlotAdd_LiveKey_StillRefused()
    {
        var m = ConvertedTwoKeyVault();
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains(WorkingSlot(SerialA), stderr);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
        Assert.DoesNotContain(ReenrolledLine(SerialA), stdout + stderr);
    }

    [Fact]
    public void SlotAdd_ReprogrammedKey_ReenrolsWithAnotherKey()
    {
        var m = ConvertedTwoKeyVault();
        var oldA = Assert.Single(SlotsOf(m, SerialA));
        var b = Assert.Single(SlotsOf(m, SerialB));
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        var slotsOfA = SlotsOf(m, SerialA);
        Assert.Equal(2, slotsOfA.Count);
        Assert.Equal(oldA.Slot.SlotId, slotsOfA[0].Slot.SlotId); // the old slot is kept
        var newA = slotsOfA[1];
        Assert.Contains(ReenrolledLine(SerialA) + SlotFingerprint.Compute(newA.Slot.PublicKey) + "); " + KeptText, stdout);
        Assert.Contains(TouchCount(1), stdout);
        // The call log: A's old slot once (the check), the new slot twice (the enrolment); the unlock went through B.
        Assert.Equal([oldA.Blob.ChallengeString, newA.Blob.ChallengeString, newA.Blob.ChallengeString], ChallengesOf(m, SerialA));
        Assert.Equal([b.Blob.ChallengeString], ChallengesOf(m, SerialB));
        Assert.Equal(1 + 2, ChallengesOf(m, SerialA).Count); // the touch count announced

        m.Keys.PluggedIn = [SerialA];
        Assert.Equal("s3cret", m.Get("db"));
        m.Keys.PluggedIn = [SerialB];
        Assert.Equal("s3cret", m.Get("db"));
    }

    [Fact]
    public void SlotAdd_ReprogrammedKey_WithTpmSlot_Reenrols()
    {
        var m = Machine(SerialA);
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        m.Ok("", "init", "--tpm");
        m.Ok("router-pw\nrouter-pw\n", "add", "db");
        m.Keys.PluggedIn = [SerialA];
        m.Ok("", "slot", "add", "--yubikey");
        Reprogram(m, SerialA);
        m.Keys.Challenges.Clear();

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialA), stdout);
        Assert.Equal(2, SlotsOf(m, SerialA).Count);
        var tpm = m.Tpm;
        m.Tpm = null;
        Assert.Equal("router-pw", m.Get("db")); // the new slot alone
        m.Tpm = tpm;
    }

    [Fact]
    public void SlotAdd_ReprogrammedKey_NoOtherWayIn_RefusesAndNamesWays()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains(TouchCount(1), stdout);
        Assert.Contains($"YubiKey {SerialA}'s slot(s) in this vault no longer open", stderr);
        foreach (var way in new[] { "another enrolled YubiKey", "a legacy pair slot whose two keys are plugged in and don't include this key",
                     "this machine's TPM or Secure Enclave slot", "a running `tswap agent`", "--recovery-key-stdin" })
            Assert.Contains(way, stderr);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
        Assert.Single(ChallengesOf(m, SerialA)); // the check only: nothing was enrolled
    }

    [Fact]
    public void SlotAdd_ReprogrammedKey_NoOtherWayIn_WithRecoveryKeyStdin_Reenrols()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = m.Run(_recoveryKey + "\n", "slot", "add", "--yubikey", "--recovery-key-stdin");
        AssertNotEchoed(stdout + stderr, _recoveryKey);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialA), stdout);
        Assert.Equal("s3cret", m.Get("db"));
    }

    [Fact]
    public void SlotAdd_Reenrol_WithPairSlotBothKeysPlugged_Reenrols()
    {
        var m = ConvertedPairVault(SerialT);
        // The pair's keys have one-key slots too (the guide's first step), and T has its own.
        m.Keys.PluggedIn = [PairA];
        m.Ok("", "slot", "add", "--yubikey");
        m.Keys.PluggedIn = [PairB, PairA];
        m.Ok("", "slot", "add", "--yubikey");
        m.Keys.PluggedIn = [SerialT, PairA];
        m.Ok("", "slot", "add", "--yubikey");
        var pair = m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine && s.HwBlob is null);
        Reprogram(m, SerialT);
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialT, PairA, PairB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialT), stdout);
        // The unlock went through the pair slot (its own challenge), with one of the pair's keys.
        var pairChallenge = m.Config.UnlockChallenge!;
        Assert.Single(m.Keys.Challenges, c => c.Challenge == pairChallenge);
        Assert.DoesNotContain(m.Keys.Challenges, c => c.Serial != SerialT && c.Challenge != pairChallenge);
        Assert.Equal(pair.Wrapped, m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine && s.HwBlob is null).Wrapped);
        m.Keys.PluggedIn = [SerialT];
        Assert.Equal(KeyringV3PairFixtureTests.FixtureSecretValue, m.Get(KeyringV3PairFixtureTests.FixtureSecretName));
    }

    [Fact]
    public void SlotAdd_Reenrol_WithAgent_Reenrols()
    {
        // A's slot without the password, B's with it; an agent holding the vault key runs.
        var m = Machine(SerialA, SerialB);
        m.Keys.PluggedIn = [SerialA];
        var recovery = RecordVaultTestSupport.RecoveryKeyFrom(m.Ok("", "init", "--yubikey", "--no-password"));
        m.Ok("s3cret\ns3cret\n", "add", "db");
        m.Keys.PluggedIn = [SerialA, SerialB];
        m.Ok(Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password");
        var vaultKey = RecordVaultTestSupport.VaultKey(m, recovery);
        var agentCalls = 0;
        FakeAgent(m, () =>
        {
            Interlocked.Increment(ref agentCalls);
            return vaultKey.ToArray();
        });
        Reprogram(m, SerialA);
        m.Keys.Challenges.Clear();

        var (exit, stdout, stderr) = SlotAdd(m, "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialA), stdout);
        Assert.Equal(1, agentCalls);
        Assert.Empty(ChallengesOf(m, SerialB)); // the agent opened it, not B
        m.Keys.PluggedIn = [SerialA];
        Assert.Equal("s3cret", m.Get("db"));
    }

    [Fact]
    public void SlotAdd_Slot2Empty_PointsToSetup()
    {
        var m = ConvertedTwoKeyVault();
        m.Keys.Slot2States[SerialA] = Slot2State.Empty;
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains($"Slot 2 of YubiKey {SerialA} isn't set up for challenge-response", stderr);
        Assert.Contains("tswap yubikey setup", stderr);
        Assert.Empty(m.Keys.Challenges);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
    }

    // ── the liveness check ────────────────────────────────────────────────────

    [Fact]
    public void SlotAdd_LivenessBusy_AbortsWithoutWrite()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        m.Keys.Busy.Add(SerialA);
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA} is busy (another tswap or app is using it); try again.", stderr);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
        Assert.Empty(ChallengesOf(m, SerialB)); // no unlock was tried
    }

    [Fact]
    public void SlotAdd_LivenessTouchTimeout_AbortsWithoutWrite()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        m.Keys.NotAnswering.Add(SerialA);
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains($"Timed out waiting for YubiKey {SerialA}", stderr);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
        Assert.Empty(ChallengesOf(m, SerialB));
    }

    [Fact]
    public void SlotAdd_LivenessMixed_OpensWins()
    {
        // A has a slot that times out (first in keyring order) and one that opens: the working slot wins.
        var m = ConvertedTwoKeyVault();
        var keyring = m.Keyring;
        var real = keyring.Slots.Single(s => s.HwBlob is not null && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob) && YubiKeySlotBlob.Decode(s.HwBlob).Serial == SerialA);
        var dead = real with { SlotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize), HwBlob = YubiKeySlotBlob.Create(SerialA, true).Encode() };
        File.WriteAllBytes(KeyringPath(m), KeyringCodec.Encode(keyring with { Slots = [dead, .. keyring.Slots] }));
        File.Delete(HintPath(m)); // keyring order
        var challenges = 0;
        m.Keys.OnChallenge = s =>
        {
            if (s != SerialA)
                return;
            if (challenges++ == 0)
                m.Keys.NotAnswering.Add(SerialA);
            else
                m.Keys.NotAnswering.Remove(SerialA);
        };
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains(WorkingSlot(SerialA), stderr);
        Assert.DoesNotContain("Timed out", stderr);
        Assert.Equal(2, challenges);
    }

    [Fact]
    public void SlotAdd_Liveness_TriesRememberedSlotFirst()
    {
        var m = ReenrolledA();
        var newA = SlotsOf(m, SerialA)[1];
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.Contains(WorkingSlot(SerialA), stderr);
        Assert.Equal([newA.Blob.ChallengeString], ChallengesOf(m, SerialA)); // the remembered slot, and it opened
    }

    [Fact]
    public void SlotAdd_LegacyPairSlotsOnly_FirstEnrolment_NoPairLabelled()
    {
        var m = ConvertedPairVault();
        var pair = m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine && s.HwBlob is null);
        m.Keys.PluggedIn = [PairA, PairB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains($"YubiKey {PairA} added as its own slot", stdout);
        Assert.DoesNotContain(ReenrolledLine(PairA), stdout);
        Assert.Equal([PairA], OneKeySlots(m).Select(s => s.Blob.Serial));
        var pairNow = m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine && s.HwBlob is null);
        Assert.Equal(pair.SlotId, pairNow.SlotId);
        Assert.Equal(pair.Wrapped, pairNow.Wrapped);
        var slots = m.Ok("", "slots");
        Assert.DoesNotContain(OtherSlotMark, slots);
    }

    [Fact]
    public void SlotAdd_SecondCycle_ThreeSlots_NewestOpensWithOneChallenge()
    {
        var m = ReenrolledA();
        Reprogram(m, SerialA);
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(TouchCount(2), stdout);
        var slotsOfA = SlotsOf(m, SerialA);
        Assert.Equal(3, slotsOfA.Count);
        // The check: the remembered (second) slot first, then the first; then the enrolment of the third, twice.
        Assert.Equal([slotsOfA[1].Blob.ChallengeString, slotsOfA[0].Blob.ChallengeString,
            slotsOfA[2].Blob.ChallengeString, slotsOfA[2].Blob.ChallengeString], ChallengesOf(m, SerialA));

        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA];
        Assert.Equal("s3cret", m.Get("db"));
        Assert.Equal([slotsOfA[2].Blob.ChallengeString], ChallengesOf(m, SerialA));
    }

    [Fact]
    public void SlotAdd_Reenrol_OneWrite_FailureBeforeWriteLeavesKeyringIdentical()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        var keyringBefore = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        var hintBefore = File.ReadAllBytes(HintPath(m));
        // The enrolment's second challenge (A's third: check, first enrolment challenge, second) times out.
        var challenges = 0;
        m.Keys.OnChallenge = s =>
        {
            if (s == SerialA && ++challenges == 3)
                m.Keys.NotAnswering.Add(SerialA);
        };
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain(ReenrolledLine(SerialA), stdout);
        Assert.Equal(keyringBefore, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
        // The unlock through B remembered B's slot (as every unlock does); A's entry wasn't touched.
        var vaultId = m.Keyring.VaultId;
        var remembered = new RememberedYubiKeySlots(m.Dir, DirectoryOwnerMatcher.Default).ForVault(vaultId);
        var before = JsonSerializer.Deserialize(hintBefore, TswapJsonContext.Default.RememberedYubiKeySlotsFile)!;
        Assert.Equal(before.Slots.Single(e => e.Serial == SerialA).SlotId, Convert.ToBase64String(remembered[SerialA]));
    }

    [Fact]
    public void SlotAdd_Reenrol_OutputHasNoKeyMaterial()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        AssertNoKeyMaterial(stdout + stderr);
        // tswap's slot fingerprint is the short grouped form, below both thresholds.
        Assert.Matches(@"\(fingerprint [0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}\)", stdout);
    }

    [Fact]
    public void SlotAdd_Reenrol_UnderSudo_RememberedFileKeepsOwner()
    {
        if (OperatingSystem.IsWindows())
            return; // the owner switch is Unix's (DirectoryOwnerMatcher never switches on Windows)
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        File.Delete(HintPath(m));
        var root = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0);
        m.Ownership = new DirectoryOwnerMatcher(root);
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        // Written as the config folder's owner (uid 1000 in the fake), never as root, mode 0600: the hint and the keyring.
        var folderOwner = root.GetOwner(m.Dir)!.Value;
        Assert.NotEqual(0u, folderOwner.Uid);
        Assert.Contains(root.Switches, s => s.Path == Path.GetFullPath(HintPath(m)) && s.Uid == folderOwner.Uid && s.Gid == folderOwner.Gid);
        Assert.Contains(root.Switches, s => s.Path == Path.GetFullPath(KeyringPath(m)) && s.Uid == folderOwner.Uid && s.Gid == folderOwner.Gid);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(HintPath(m)));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(KeyringPath(m)));
        m.Ownership = null;
        Assert.Equal(SlotsOf(m, SerialA)[1].Slot.SlotId, Remembered(m)[SerialA]);
    }

    [Fact]
    public void SlotAdd_Reenrol_HintWriteFails_StillSucceeds()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        File.Delete(HintPath(m));
        Directory.CreateDirectory(HintPath(m)); // a folder where the file goes: every write of it fails
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = SlotAdd(m);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialA), stdout);
        Assert.Contains($"couldn't remember YubiKey {SerialA}'s new slot on this machine", stdout + stderr);
        Assert.Equal(2, SlotsOf(m, SerialA).Count);
    }

    // ── the vault password ────────────────────────────────────────────────────

    [Fact]
    public void SlotAdd_Reenrol_WrongPasswordViaChip_AbortsWithoutWrite()
    {
        // The vault opens through the TPM (no password); A's slot has the password; the new slot gets it too.
        var m = Machine(SerialA);
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        m.Ok("", "init", "--tpm", "--no-password");
        m.Keys.PluggedIn = [SerialA];
        m.Ok(Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password");
        Reprogram(m, SerialA);
        File.Delete(HintPath(m));
        m.Keys.Challenges.Clear();
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();

        var (exit, stdout, stderr) = m.RunOnTerminal(WrongPassword + "\n", "slot", "add", "--yubikey", "--password");
        AssertNotEchoed(stdout + stderr, WrongPassword);

        Assert.NotEqual(0, exit);
        Assert.Contains("the vault password didn't match", stderr);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
        Assert.False(File.Exists(HintPath(m)));
        Assert.Single(ChallengesOf(m, SerialA)); // the check; nothing was enrolled
        Assert.DoesNotContain(ReenrolledLine(SerialA), stdout);
    }

    [Fact]
    public void SlotAdd_PasswordSlot_AsksOnceBeforeChallenges()
    {
        // A and B both have password slots; A is reprogrammed; the new slot gets the password too.
        var m = PasswordVaultOnAAndB(bPassword: true);
        Reprogram(m, SerialA);
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];
        var console = new FakeConsole("1\n" + Password + "\n") { IsInputRedirected = false, Interleaved = true };
        string? atFirstChallenge = null;
        m.Keys.OnChallenge = _ => atFirstChallenge ??= console.OutText;
        string[] args = ["slot", "add", "--yubikey", "--password"];

        var exit = CliRunner.Run(m.Context(console, args), args);

        var text = console.OutText;
        Assert.True(exit == 0, text);
        Assert.Equal(1, Regex.Count(text, Regex.Escape(TerminalPasswordProvider.PromptText)));
        AssertNotEchoed(text, Password);
        Assert.NotNull(atFirstChallenge);
        var prompt = atFirstChallenge.IndexOf(TerminalPasswordProvider.PromptText, StringComparison.Ordinal);
        var count = atFirstChallenge.IndexOf(TouchCount(1), StringComparison.Ordinal);
        Assert.True(prompt >= 0 && count > prompt, atFirstChallenge); // the prompt, then the touch count, then the challenges
        Assert.Contains(ReenrolledLine(SerialA), text);
        Assert.True(SlotsOf(m, SerialA)[1].Blob.RequiresPassword); // the new slot got the password
        Assert.DoesNotContain(MistypedLine, text); // the unlock through B's password slot proved it

        m.Keys.PluggedIn = [SerialA];
        var (getExit, getOut, getErr) = m.RunOnTerminal(Password + "\n", "get", "db");
        Assert.True(getExit == 0, getErr);
        Assert.Equal("s3cret", getOut.Trim());
    }

    [Theory]
    [InlineData("--no-password")]
    [InlineData("--password")]
    public void SlotAdd_PasswordSlot_MistypedPassword_Aborts(string flag)
    {
        // A's slot has the password, B's doesn't. A isn't reprogrammed: the mistyped password makes it look dead.
        // Final review (owner decision): one mistyped password stops the command, whatever the new slot gets.
        var m = PasswordVaultOnAAndB(bPassword: false);
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];
        var passwordFile = Path.Combine(m.VaultDir!, RecordVaultStore.VaultPasswordFileName);
        var keyringBefore = File.ReadAllBytes(KeyringPath(m));
        var configBefore = File.ReadAllBytes(m.ConfigPath);
        var passwordFileBefore = File.ReadAllBytes(passwordFile);
        var checkChallenges = SlotsOf(m, SerialA).Count;

        var (exit, stdout, stderr) = m.RunOnTerminal("1\n" + WrongPassword + "\n", "slot", "add", "--yubikey", flag);
        AssertNotEchoed(stdout + stderr, WrongPassword);

        Assert.NotEqual(0, exit);
        Assert.Contains(
            $"YubiKey {SerialA} isn't enrolled again: the vault password didn't match this vault's (checked against the " +
            "vault's password verifier), so tswap can't tell whether its slot(s) that need the password still open the vault. " +
            "Nothing was changed.", stderr);
        Assert.DoesNotContain(MistypedLine, stdout + stderr);
        Assert.DoesNotContain(ReenrolledLine(SerialA), stdout + stderr);
        Assert.Equal(keyringBefore, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(configBefore, File.ReadAllBytes(m.ConfigPath));
        Assert.Equal(passwordFileBefore, File.ReadAllBytes(passwordFile));
        Assert.Equal(checkChallenges, ChallengesOf(m, SerialA).Count); // the check only: no enrolment challenge
        Assert.Empty(m.Keys.Programmed);
    }

    /// <summary>
    /// Fix round, item 7: the agent opens the vault but never proves the typed password (or this key's slots). A's
    /// password slot with a mistyped password looks dead; the agent opens the vault (the only way in without the
    /// password); the new slot is to get the password, so the verifier is applied and the re-enrolment aborts.
    /// </summary>
    [Fact]
    public void SlotAdd_PasswordSlot_AgentDoesNotProveThePassword()
    {
        var m = PasswordVaultOnAAndB(bPassword: true, recovery: true);
        var vaultKey = RecordVaultTestSupport.VaultKey(m, _recoveryKey);
        var agentCalls = 0;
        FakeAgent(m, () =>
        {
            Interlocked.Increment(ref agentCalls);
            return vaultKey.ToArray();
        });
        var before = File.ReadAllBytes(KeyringPath(m));
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = m.RunOnTerminal("1\n" + WrongPassword + "\n", "slot", "add", "--yubikey", "--password");
        AssertNotEchoed(stdout + stderr, WrongPassword);

        Assert.NotEqual(0, exit);
        Assert.Contains("the vault password didn't match", stderr);
        Assert.Equal(1, agentCalls); // asked once, for the unlock only
        Assert.Empty(ChallengesOf(m, SerialB)); // the agent opened it
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.DoesNotContain(ReenrolledLine(SerialA), stdout);
    }

    /// <summary>
    /// Fix round, item 2: a slot of this key needs the vault password but the vault-password file is gone: refused with
    /// the missing-file text before any challenge, whatever the new slot gets (a freshly salted password would make the
    /// live slot look dead and write a second vault-password file).
    /// </summary>
    [Theory]
    [InlineData("--password")]
    [InlineData("--no-password")]
    public void SlotAdd_KeySlotNeedsPassword_NoVaultPasswordFile_Refused(string flag)
    {
        var m = PasswordVaultOnAAndB(bPassword: false);
        File.Delete(Path.Combine(m.VaultDir!, RecordVaultStore.VaultPasswordFileName));
        var before = File.ReadAllBytes(KeyringPath(m));
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = m.RunOnTerminal("1\n" + Password + "\n" + Password + "\n", "slot", "add", "--yubikey", flag);

        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordMessages.MissingFile, stderr);
        Assert.Empty(m.Keys.Challenges);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.False(File.Exists(Path.Combine(m.VaultDir!, RecordVaultStore.VaultPasswordFileName)));
    }

    /// <summary>
    /// Fix round, item 3: the unlock's own prompt can't run (no terminal), so nothing was typed: the refusal doesn't say
    /// the password may have been mistyped.
    /// </summary>
    [Fact]
    public void SlotAdd_Reenrol_NoTerminalForUnlockPrompt_DoesNotSayMistyped()
    {
        var m = VaultAPasswordFreeBPassword();
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = SlotAdd(m, "--no-password");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialA}'s slot(s) in this vault no longer open", stderr);
        Assert.DoesNotContain("may have been mistyped", stderr);
    }

    /// <summary>
    /// Fix round, item 5 (controller ruling): with --recovery-key-stdin, the vault password is the line after the
    /// recovery key, as for a first enrolment. The vault opens with the recovery key, so the typed password is checked
    /// against the verifier: a wrong one aborts without a write, the right one re-enrols with the password.
    /// </summary>
    [Fact]
    public void SlotAdd_Reenrol_RecoveryKeyStdin_WithPassword_VerifierDecides()
    {
        var m = VaultAPasswordFreeBPassword();
        Reprogram(m, SerialA);
        var before = File.ReadAllBytes(KeyringPath(m));
        m.Keys.PluggedIn = [SerialA];

        var (wrongExit, wrongOut, wrongErr) = m.Run(_recoveryKey + "\n" + WrongPassword + "\n",
            "slot", "add", "--yubikey", "--password", "--recovery-key-stdin");
        AssertNotEchoed(wrongOut + wrongErr, _recoveryKey, WrongPassword);

        Assert.NotEqual(0, wrongExit);
        Assert.Contains("the vault password didn't match", wrongErr);
        Assert.DoesNotContain(ReenrolledLine(SerialA), wrongOut);
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));

        var (exit, stdout, stderr) = m.Run(_recoveryKey + "\n" + Password + "\n",
            "slot", "add", "--yubikey", "--password", "--recovery-key-stdin");
        AssertNotEchoed(stdout + stderr, _recoveryKey, Password);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialA), stdout);
        Assert.True(SlotsOf(m, SerialA)[^1].Blob.RequiresPassword);
    }

    /// <summary>A record vault on A (no password, with recovery: <c>_recoveryKey</c>) and B (a password slot), holding <c>db</c>.</summary>
    private FleetMachine VaultAPasswordFreeBPassword()
    {
        var m = Machine(SerialA, SerialB);
        m.Keys.PluggedIn = [SerialA];
        _recoveryKey = RecordVaultTestSupport.RecoveryKeyFrom(m.Ok("", "init", "--yubikey", "--no-password"));
        m.Ok("s3cret\ns3cret\n", "add", "db");
        m.Keys.PluggedIn = [SerialA, SerialB];
        m.Ok(Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password");
        Assert.Equal([SerialA, SerialB], OneKeySlots(m).Select(s => s.Blob.Serial));
        m.Keys.Challenges.Clear();
        return m;
    }

    [Fact]
    public void SlotAdd_PasswordSlot_OnlyPasswordWayIn_MistypedPassword_SaysSo()
    {
        // A and B both have password slots, no recovery; A is reprogrammed and the password mistyped: B's slot fails too.
        var m = PasswordVaultOnAAndB(bPassword: true);
        Reprogram(m, SerialA);
        var before = File.ReadAllBytes(KeyringPath(m));
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = m.RunOnTerminal("1\n" + WrongPassword + "\n", "slot", "add", "--yubikey", "--no-password");
        AssertNotEchoed(stdout + stderr, WrongPassword);

        Assert.NotEqual(0, exit);
        Assert.Contains("the vault password may have been mistyped", stderr);
        Assert.Equal(1, Regex.Count(stdout + stderr, Regex.Escape(TerminalPasswordProvider.PromptText)));
        Assert.Equal(before, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(backupsBefore, m.Backups.Order()); // no new backup: nothing was written
    }

    /// <summary>
    /// A record vault on A (a password slot; a recovery slot only with <paramref name="recovery"/>, its key in
    /// <c>_recoveryKey</c>) and B (a password slot or not), holding <c>db</c>.
    /// </summary>
    private FleetMachine PasswordVaultOnAAndB(bool bPassword, bool recovery = false)
    {
        var m = Machine(SerialA, SerialB);
        m.Keys.PluggedIn = [SerialA];
        var init = m.Ok(Password + "\n" + Password + "\n", ["init", "--yubikey", "--password", .. recovery ? Array.Empty<string>() : ["--no-recovery"]]);
        if (recovery)
            _recoveryKey = RecordVaultTestSupport.RecoveryKeyFrom(init);
        var (addExit, _, addErr) = m.RunOnTerminal("s3cret\ns3cret\n" + Password + "\n", "add", "db");
        Assert.True(addExit == 0, addErr);
        m.Keys.PluggedIn = [SerialA, SerialB];
        var (exit, _, err) = m.RunOnTerminal(Password + "\n" + (bPassword ? Password + "\n" : ""),
            "slot", "add", "--yubikey", bPassword ? "--password" : "--no-password");
        Assert.True(exit == 0, err);
        Assert.Equal([SerialA, SerialB], OneKeySlots(m).Select(s => s.Blob.Serial));
        return m;
    }

    // ── unlock and the remembered slot ───────────────────────────────────────

    /// <summary><see cref="ConvertedTwoKeyVault"/> with A reprogrammed and re-enrolled (through B).</summary>
    private FleetMachine ReenrolledA()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];
        var (exit, stdout, stderr) = SlotAdd(m);
        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(2, SlotsOf(m, SerialA).Count);
        m.Keys.Challenges.Clear();
        return m;
    }

    private static IReadOnlyDictionary<int, byte[]> Remembered(FleetMachine m) =>
        new RememberedYubiKeySlots(m.Dir, DirectoryOwnerMatcher.Default).ForVault(m.Keyring.VaultId);

    [Fact]
    public void Unlock_TriesRememberedSlotFirst()
    {
        var m = ReenrolledA();
        var newA = SlotsOf(m, SerialA)[1];
        m.Keys.PluggedIn = [SerialA];

        Assert.Equal("s3cret", m.Get("db"));

        Assert.Equal([newA.Blob.ChallengeString], ChallengesOf(m, SerialA));
    }

    /// <summary>
    /// Fix round, item 1: re-enrolled with the vault password over a password-free slot (the documented path on a
    /// converted XOR vault): the old password-free slot is not challenged first; the unlock costs one challenge of A.
    /// </summary>
    [Fact]
    public void Unlock_ReenrolledWithPasswordOverPasswordFreeSlot_OneChallenge()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];
        var (addExit, addOut, addErr) = m.RunOnTerminal("1\n" + Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password");
        Assert.True(addExit == 0, addErr + addOut);
        var newA = SlotsOf(m, SerialA)[^1];
        Assert.True(newA.Blob.RequiresPassword);
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal("s3cret", stdout.Trim());
        Assert.Equal([newA.Blob.ChallengeString], ChallengesOf(m, SerialA));
    }

    /// <summary>
    /// Fix round, item 1: the password-free slots kept out of the first pass stay reachable. A's remembered slot is a
    /// password slot (stale: it no longer opens), its password-free slot works, and there is no terminal for the
    /// password: the password-free slot is tried last and opens.
    /// </summary>
    [Fact]
    public void Unlock_RememberedPasswordSlotStale_NoTerminal_PasswordFreeSlotStillOpens()
    {
        var (m, slotsOfA) = StaleRememberedPasswordSlotOfA();

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal("s3cret", stdout.Trim());
        Assert.Equal([slotsOfA[1].Blob.ChallengeString], ChallengesOf(m, SerialA));
        Assert.Equal(slotsOfA[1].Slot.SlotId, Remembered(m)[SerialA]);
    }

    /// <summary>
    /// A with a password slot (dead after a reprogram) and, re-enrolled without the password, a live password-free
    /// slot; the hint names the dead password slot (stale), so the password-free one is deferred. Only A plugged in.
    /// </summary>
    private (FleetMachine M, List<(Slot Slot, YubiKeySlotBlob Blob)> SlotsOfA) StaleRememberedPasswordSlotOfA(bool recovery = false)
    {
        var m = PasswordVaultOnAAndB(bPassword: false, recovery: recovery);
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];
        var (addExit, addOut, addErr) = m.RunOnTerminal("1\n" + Password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(addExit == 0, addErr + addOut);
        var slotsOfA = SlotsOf(m, SerialA);
        Assert.True(slotsOfA[0].Blob.RequiresPassword);
        Assert.False(slotsOfA[1].Blob.RequiresPassword);
        new RememberedYubiKeySlots(m.Dir, DirectoryOwnerMatcher.Default).Remember(m.Keyring.VaultId, SerialA, slotsOfA[0].Slot.SlotId);
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA];
        return (m, slotsOfA);
    }

    /// <summary>
    /// Fix round 2, item 2a: at a terminal with a stale hint, the password pass runs and fails (the remembered password
    /// slot is dead), then the deferred password-free slot opens, and the hint moves to it.
    /// </summary>
    [Fact]
    public void Unlock_RememberedPasswordSlotStale_AtTerminal_PasswordPassFails_DeferredSlotOpens()
    {
        var (m, slotsOfA) = StaleRememberedPasswordSlotOfA();

        var (exit, stdout, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal("s3cret", stdout.Trim());
        Assert.Equal([slotsOfA[0].Blob.ChallengeString, slotsOfA[1].Blob.ChallengeString], ChallengesOf(m, SerialA));
        Assert.Equal(slotsOfA[1].Slot.SlotId, Remembered(m)[SerialA]);
    }

    /// <summary>
    /// Fix round 2, item 2b: an unlock with no prompt source at all (no agent, no password provider) still tries the
    /// deferred password-free slot.
    /// </summary>
    [Fact]
    public void Unlock_RememberedPasswordSlotStale_NoPromptSource_DeferredSlotOpens()
    {
        var (m, slotsOfA) = StaleRememberedPasswordSlotOfA(recovery: true);
        var config = VaultStores.Open(m.Dir).LoadConfig();
        var remembered = new RememberedYubiKeySlots(m.Dir, DirectoryOwnerMatcher.Default);

        var key = new VaultUnlocker(m.Keys).Unlock(config, YubiKeySelection.Unattended, new UnlockSources(null, null) { Remembered = remembered });

        Assert.Equal(RecordVaultTestSupport.VaultKey(m, _recoveryKey), key);
        Assert.Equal([slotsOfA[1].Blob.ChallengeString], ChallengesOf(m, SerialA));
        Assert.Equal(slotsOfA[1].Slot.SlotId, Remembered(m)[SerialA]);
    }

    /// <summary>
    /// Final review item 2 (p6-I2): the deferred password-free slot's failure isn't discarded. A's remembered slot needs
    /// the password, its password-free slot is deferred, A is busy and there is no terminal: the error names the busy
    /// key, not only the missing terminal.
    /// </summary>
    [Fact]
    public void Unlock_DeferredSlotKeyBusy_NoTerminal_ErrorNamesBusyKey()
    {
        var (m, _) = StaleRememberedPasswordSlotOfA();
        m.Keys.Busy.Add(SerialA);

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("s3cret", stdout);
        Assert.Contains(VaultPasswordMessages.NoTerminal, stderr);
        Assert.Contains($"YubiKey {SerialA} is busy (another tswap or app is using it); try again.", stderr);
    }

    /// <summary>
    /// Final review item 2 (p6-I2), the same with no prompt source at all (no agent, no password provider): the
    /// deferred slot's busy text is part of the error.
    /// </summary>
    [Fact]
    public void Unlock_DeferredSlotKeyBusy_NoPromptSource_ErrorNamesBusyKey()
    {
        var (m, _) = StaleRememberedPasswordSlotOfA();
        m.Keys.Busy.Add(SerialA);
        var config = VaultStores.Open(m.Dir).LoadConfig();
        var remembered = new RememberedYubiKeySlots(m.Dir, DirectoryOwnerMatcher.Default);

        var ex = Assert.ThrowsAny<TswapException>(() =>
            new VaultUnlocker(m.Keys).Unlock(config, YubiKeySelection.Unattended, new UnlockSources(null, null) { Remembered = remembered }));

        Assert.Contains(VaultPasswordMessages.NoTerminal, ex.Message);
        Assert.Contains($"YubiKey {SerialA} is busy (another tswap or app is using it); try again.", ex.Message);
    }

    /// <summary>
    /// Final review items 2 and 3 (p6-I2, p6-M2): A's slots are all dead (its remembered one needs the password, its
    /// password-free one is deferred), B's password-free slot is dead, a wrong password is typed. Pass 1 tries B only
    /// (A has no password-free slot left there, so no "A opened none of its slots" line for a key never challenged in
    /// it); the deferred slot's failure is part of the combined error.
    /// </summary>
    [Fact]
    public void Unlock_AllDead_CombinedErrorHasDeferredFailure_NoSpuriousPass1Line()
    {
        var (m, slotsOfA) = StaleRememberedPasswordSlotOfA();
        m.Keys.PluggedIn = [SerialA, SerialB];
        Reprogram(m, SerialA);
        Reprogram(m, SerialB);
        m.Keys.Challenges.Clear();

        var (exit, _, stderr) = m.RunOnTerminal(WrongPassword + "\n", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains($"YubiKey {SerialB} did not open any of its slots in this vault", stderr); // pass 1: B alone
        Assert.Contains($"YubiKey {SerialA}: {VaultPasswordMessages.WrongPasswordKdf}", stderr); // pass 3
        Assert.Contains($"YubiKey {SerialA} did not open any of its slots in this vault", stderr); // the deferred slot
        Assert.DoesNotContain($"{SerialA} opened none of its slots", stderr);
        Assert.Equal([slotsOfA[0].Blob.ChallengeString, slotsOfA[1].Blob.ChallengeString], ChallengesOf(m, SerialA));
    }

    /// <summary>
    /// Fix round 2, item 1a: B's remembered slot is a dead password slot and its password-free slot is live, so the
    /// unlock uses the mistyped password (its password pass fails), then opens through B's deferred password-free slot.
    /// The unlock using the password is no proof of it: the verifier aborts A's re-enrolment with the password, and
    /// nothing is written.
    /// </summary>
    [Fact]
    public void SlotAdd_Reenrol_PasswordUsedByUnlockButNotProven_MistypedAborts()
    {
        var m = Machine(SerialA, SerialB);
        m.Keys.PluggedIn = [SerialA];
        m.Ok("", "init", "--yubikey", "--no-password");
        m.Ok("s3cret\ns3cret\n", "add", "db");
        m.Keys.PluggedIn = [SerialA, SerialB];
        m.Ok(Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password"); // B's password slot and the file
        Reprogram(m, SerialB);
        m.Keys.PluggedIn = [SerialB, SerialA];
        var (bExit, bOut, bErr) = m.RunOnTerminal("1\n" + Password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(bExit == 0, bErr + bOut);
        var slotsOfB = SlotsOf(m, SerialB);
        Assert.True(slotsOfB[0].Blob.RequiresPassword);
        Assert.False(slotsOfB[1].Blob.RequiresPassword);
        new RememberedYubiKeySlots(m.Dir, DirectoryOwnerMatcher.Default).Remember(m.Keyring.VaultId, SerialB, slotsOfB[0].Slot.SlotId);
        Reprogram(m, SerialA);
        var passwordFile = Path.Combine(m.VaultDir!, RecordVaultStore.VaultPasswordFileName);
        var keyringBefore = File.ReadAllBytes(KeyringPath(m));
        var passwordFileBefore = File.ReadAllBytes(passwordFile);
        var backupsBefore = m.Backups.Order().ToArray();
        m.Keys.Challenges.Clear();
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = m.RunOnTerminal("1\n" + WrongPassword + "\n", "slot", "add", "--yubikey", "--password");
        AssertNotEchoed(stdout + stderr, WrongPassword);

        Assert.NotEqual(0, exit);
        Assert.Contains("the vault password didn't match", stderr);
        Assert.DoesNotContain(ReenrolledLine(SerialA), stdout);
        // The unlock went the way this test is about: B's dead password slot, then its deferred password-free slot.
        Assert.Equal([slotsOfB[0].Blob.ChallengeString, slotsOfB[1].Blob.ChallengeString], ChallengesOf(m, SerialB));
        Assert.Single(SlotsOf(m, SerialA)); // no new slot
        Assert.Equal(keyringBefore, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(passwordFileBefore, File.ReadAllBytes(passwordFile));
        Assert.Equal(backupsBefore, m.Backups.Order());
    }

    /// <summary>
    /// Fix round 2, item 1b: the right password, typed for A's dead password slot; the new slot without the password;
    /// the unlock through B's password-free slot (it never uses the password): no mistyped line.
    /// </summary>
    [Fact]
    public void SlotAdd_Reenrol_CorrectPassword_UnlockWithoutIt_NoMistypedLine()
    {
        var m = PasswordVaultOnAAndB(bPassword: false);
        Reprogram(m, SerialA);
        m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = m.RunOnTerminal("1\n" + Password + "\n", "slot", "add", "--yubikey", "--no-password");
        AssertNotEchoed(stdout + stderr, Password);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(ReenrolledLine(SerialA), stdout);
        Assert.DoesNotContain(MistypedLine, stdout + stderr);
    }

    /// <summary>Fix round 2, item 3: the one-key keyring vault's touch note uses the flow, with the elevated recover fallback.</summary>
    [Fact]
    public void MigrateKeyringNote_UsesReenrolFlowAndElevatedRecoverFallback()
    {
        var m = Machine(SerialA);
        m.Keys.PluggedIn = [SerialA];
        m.Ok("", "init", "--yubikey");

        var output = m.Ok("", "migrate");

        Assert.Contains("tswap yubikey setup --replace --touch --serial N", output);
        Assert.Contains(ElevatedCommand.Line("tswap", "slot add --yubikey") + "   # enrols the reprogrammed key again", output);
        Assert.Contains("tswap names   # with only that key plugged in", output);
        Assert.Contains("Only if no other way in is left: pipe the recovery key into " + ElevatedCommand.Line("tswap", "recover --yubikey"), output);
    }

    [Fact]
    public void Unlock_FirstSlotOfSerialDead_StillOpens()
    {
        var m = ReenrolledA();
        File.Delete(HintPath(m)); // nothing remembered: keyring order, the dead slot first
        var slotsOfA = SlotsOf(m, SerialA);
        m.Keys.PluggedIn = [SerialA];

        Assert.Equal("s3cret", m.Get("db"));

        Assert.Equal([slotsOfA[0].Blob.ChallengeString, slotsOfA[1].Blob.ChallengeString], ChallengesOf(m, SerialA));
        Assert.Equal(slotsOfA[1].Slot.SlotId, Remembered(m)[SerialA]); // remembered after the unlock
        m.Keys.Challenges.Clear();
        Assert.Equal("s3cret", m.Get("db"));
        Assert.Single(ChallengesOf(m, SerialA));
    }

    [Fact]
    public void Unlock_TouchTimeoutOnFirstSlot_Stops()
    {
        var m = ReenrolledA();
        File.Delete(HintPath(m));
        m.Keys.NotAnswering.Add(SerialA);
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains($"Timed out waiting for YubiKey {SerialA}", stderr);
        Assert.Single(ChallengesOf(m, SerialA)); // stopped at the first slot
    }

    [Fact]
    public void Merge_DoesNotChangeRememberedSlot()
    {
        var m = ConvertedTwoKeyVault();
        Reprogram(m, SerialA);
        var copy = Machine(SerialA, SerialB);
        copy.Keys = m.Keys;
        m.CopyVaultTo(copy);
        // The copy re-enrols A (its own new slot, remembered on that machine), then this machine does.
        m.Keys.PluggedIn = [SerialA, SerialB];
        Assert.Equal(0, SlotAdd(copy).Exit);
        Assert.Equal(0, SlotAdd(m).Exit);
        var hint = File.ReadAllText(HintPath(m));
        var mine = Remembered(m)[SerialA];
        m.Keys.PluggedIn = [SerialA];

        m.Ok("", "vault", "merge", copy.VaultDir!, "--yes");

        Assert.Equal(3, SlotsOf(m, SerialA).Count); // the copy's slot came in
        Assert.Equal(hint, File.ReadAllText(HintPath(m)));
        Assert.Equal(mine, Remembered(m)[SerialA]);
    }

    [Fact]
    public void Slots_MarksOtherSlotOfKey()
    {
        var m = ReenrolledA();
        var slotsOfA = SlotsOf(m, SerialA);
        var b = Assert.Single(SlotsOf(m, SerialB));

        var output = m.Ok("", "slots");

        var rows = output.Split('\n');
        string Row(Slot slot) => Assert.Single(rows, r => r.StartsWith(Convert.ToHexStringLower(slot.SlotId)[..8], StringComparison.Ordinal));
        Assert.Contains(OtherSlotMark, Row(slotsOfA[0].Slot));
        Assert.DoesNotContain(OtherSlotMark, Row(slotsOfA[1].Slot));
        Assert.DoesNotContain(OtherSlotMark, Row(b.Slot));
        Assert.Equal(1, Regex.Count(output, Regex.Escape(OtherSlotMark)));

        File.Delete(HintPath(m)); // nothing remembered: nothing marked
        Assert.DoesNotContain(OtherSlotMark, m.Ok("", "slots"));
    }

    [Theory]
    [InlineData("unreadable")]
    [InlineData("malformed")]
    [InlineData("root-owned")]
    public void RememberedSlot_UnreadableMalformedOrRootOwned_UnlockStillWorks(string kind)
    {
        var m = ReenrolledA();
        var slotsOfA = SlotsOf(m, SerialA);
        var path = HintPath(m);
        switch (kind)
        {
            case "unreadable":
                if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
                    return; // a mode can't make a file unreadable there
                File.SetUnixFileMode(path, UnixFileMode.None);
                break;
            case "malformed":
                File.WriteAllText(path, "{ not json");
                break;
            case "root-owned":
                if (OperatingSystem.IsWindows())
                    return; // owners are Unix's here
                var fake = new FileOwnershipTests.FakeOwnership(privileged: false, euid: 1000, dirUid: 1000, dirGid: 1000);
                fake.Owners[Path.GetFullPath(path)] = (0, 0);
                m.Ownership = new DirectoryOwnerMatcher(fake);
                break;
        }
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal("s3cret", stdout.Trim());
        // The hint was ignored: keyring order, the dead slot first.
        Assert.Equal([slotsOfA[0].Blob.ChallengeString, slotsOfA[1].Blob.ChallengeString], ChallengesOf(m, SerialA));
        if (kind == "unreadable") // fix round, item 6: the hint was rewritten at 0600, so it works again
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            Assert.Equal(slotsOfA[1].Slot.SlotId, Remembered(m)[SerialA]);
        }
    }

    [Fact]
    public void Unlock_HintWriteFails_UnlockStillSucceeds()
    {
        var m = ReenrolledA();
        File.Delete(HintPath(m));
        Directory.CreateDirectory(HintPath(m)); // a folder where the file goes: the write really fails
        m.Keys.PluggedIn = [SerialA];

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal("s3cret", stdout.Trim());
        Assert.True(Directory.Exists(HintPath(m)));
    }

    [Fact]
    public void SetupThenSlotAdd_SecondKeyStillOpensBetweenSteps()
    {
        var m = ConvertedTwoKeyVault();
        m.Keys.PluggedIn = [SerialA, SerialB];
        var (setupExit, _, setupErr) = m.RunOnTerminal($"{SerialA}\n", "yubikey", "setup", "--replace", "--touch", "--serial", $"{SerialA}");
        Assert.True(setupExit == 0, setupErr);
        Assert.Equal([(SerialA, true)], m.Keys.Programmed);

        m.Keys.PluggedIn = [SerialB];
        Assert.Equal("s3cret", m.Get("db")); // B alone, between the two steps

        m.Keys.PluggedIn = [SerialA, SerialB];
        Assert.Equal(0, SlotAdd(m).Exit);
        m.Keys.PluggedIn = [SerialA];
        Assert.Equal("s3cret", m.Get("db"));
    }

    // ── the migrate guide ─────────────────────────────────────────────────────

    /// <summary>A classic two-key XOR vault on A and B whose keys need no touch (so the guide offers the touch upgrade).</summary>
    private FleetMachine ClassicNoTouchVault()
    {
        var m = Machine(SerialA, SerialB);
        m.Keys.SetTouch(SerialA, false);
        m.Keys.SetTouch(SerialB, false);
        ClassicVaultTestSupport.CreateXorVault(m, SerialA, SerialB,
            new Dictionary<string, Secret> { ["db"] = new("s3cret", DateTime.UtcNow, DateTime.UtcNow) });
        return m;
    }

    /// <summary>The legacy pair-keyring fixture (classic, single-file) on a fleet machine, its keys needing no touch.</summary>
    private FleetMachine LegacyPairVault(params int[] extraSerials)
    {
        var m = Machine([PairA, PairB, .. extraSerials]);
        File.WriteAllText(m.ConfigPath, JsonSerializer.Serialize(
            KeyringV3PairFixtureTests.FixtureConfig() with { RequiresTouch = false }, TswapJsonContext.Default.Config));
        File.WriteAllBytes(m.SecretsPath, Convert.FromBase64String(KeyringV3PairFixtureTests.FixtureSecretsFileBase64));
        return m;
    }

    /// <summary><see cref="LegacyPairVault"/> converted with <c>migrate --to-records</c> (the pair slot is kept as it is).</summary>
    private FleetMachine ConvertedPairVault(params int[] extraSerials)
    {
        var m = LegacyPairVault(extraSerials);
        m.Keys.PluggedIn = [PairA];
        m.Ok("", "migrate", "--to-records");
        Assert.Empty(OneKeySlots(m));
        m.Keys.Challenges.Clear();
        return m;
    }

    private static string Guide(FleetMachine m)
    {
        var (exit, stdout, stderr) = m.Run("yes\n", "migrate");
        Assert.True(exit == 0, stderr);
        Assert.Contains("RE-INITIALIZATION GUIDE", stdout);
        return stdout[stdout.IndexOf("RE-INITIALIZATION GUIDE", StringComparison.Ordinal)..];
    }

    [Fact]
    public void MigrateGuide_UsesReenrolFlow()
    {
        var guide = Guide(ClassicNoTouchVault());

        Assert.Contains("migrate --to-records", guide);
        Assert.Contains($"yubikey setup --replace --touch --serial {SerialA}", guide);
        Assert.Contains($"yubikey setup --replace --touch --serial {SerialB}", guide);
        Assert.Contains("slot add --yubikey", guide);
        Assert.Contains("tswap names", guide);
        Assert.Contains("one key at a time", guide);
        Assert.DoesNotContain("tswap init", guide);
        var recoverLines = guide.Split('\n').Where(l => Regex.IsMatch(l, @"\brecover\b")).ToList();
        var fallback = Assert.Single(recoverLines);
        Assert.Contains("only if no other way in is left", fallback, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MigrateGuide_FlowWorksEndToEnd()
    {
        var m = ClassicNoTouchVault();
        m.Keys.PluggedIn = [SerialA, SerialB];

        RunGuide(m, Guide(m), [SerialA, SerialB]);

        foreach (var serial in new[] { SerialA, SerialB })
        {
            m.Keys.PluggedIn = [serial];
            Assert.Equal("s3cret", m.Get("db"));
            Assert.True(SlotsOf(m, serial)[^1].Blob.RequiresTouch == true);
        }
    }

    [Fact]
    public void MigrateGuide_LegacyPairKeyring_FlowWorksEndToEnd()
    {
        var m = LegacyPairVault();
        m.Keys.PluggedIn = [PairA, PairB];
        var guide = Guide(m);
        Assert.Contains("first enrolment", guide);

        RunGuide(m, guide, [PairA, PairB]);

        foreach (var serial in new[] { PairA, PairB })
        {
            m.Keys.PluggedIn = [serial];
            Assert.Equal(KeyringV3PairFixtureTests.FixtureSecretValue, m.Get(KeyringV3PairFixtureTests.FixtureSecretName));
            Assert.True(SlotsOf(m, serial)[^1].Blob.RequiresTouch == true);
        }
    }

    /// <summary>
    /// Runs the commands of the printed guide, in order, as the user would: the lines that are commands (starting with
    /// <c>tswap</c> or <c>sudo tswap</c>; a trailing <c># comment</c> and the Windows elevation note dropped). The
    /// test plays the keys: a <c>yubikey setup --serial N</c> line makes N the key in hand (its serial typed at the
    /// prompt); <c>slot add</c> runs with the key in hand first and the other key plugged in; <c>names</c> runs with
    /// only the key in hand. Before any setup line, both keys are plugged in.
    /// </summary>
    private void RunGuide(FleetMachine m, string guide, int[] serials)
    {
        int? inHand = null;
        var commands = guide.Split('\n').Select(l => l.Trim())
            .Select(l => l.Contains(" #", StringComparison.Ordinal) ? l[..l.IndexOf(" #", StringComparison.Ordinal)].Trim() : l)
            .Select(l => l.Replace(ElevatedCommand.WindowsNote, "", StringComparison.Ordinal).Trim())
            .Where(l => l.StartsWith("tswap ", StringComparison.Ordinal) || l.StartsWith("sudo tswap ", StringComparison.Ordinal))
            .ToList();
        Assert.NotEmpty(commands);
        foreach (var line in commands)
        {
            var args = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).SkipWhile(w => w is "sudo").Skip(1)
                .Select(a => a.StartsWith("~/", StringComparison.Ordinal) ? Path.Combine(m.Dir, a[2..]) : a).ToArray();
            (int Exit, string Out, string Err) result;
            switch (args)
            {
                case ["export", ..]:
                    result = m.Run("pp\npp\n", args);
                    break;
                case ["yubikey", "setup", .., "--serial", var n]:
                    inHand = int.Parse(n);
                    m.Keys.PluggedIn = [inHand.Value, .. serials.Where(s => s != inHand)];
                    result = m.RunOnTerminal(n + "\n", args);
                    break;
                case ["names", ..]:
                    m.Keys.PluggedIn = [inHand!.Value];
                    result = m.Run("", args);
                    break;
                default:
                    m.Keys.PluggedIn = inHand is { } k ? [k, .. serials.Where(s => s != k)] : [.. serials];
                    result = m.Run("", args);
                    break;
            }
            Assert.True(result.Exit == 0, $"'{line}' failed: {result.Err}\n{result.Out}");
        }
        Assert.Contains(commands, c => c.Contains("names"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private AgentServer FakeAgent(FleetMachine m, Func<byte[]> unlock)
    {
        var vaultId = m.Keyring.VaultId;
        var address = OperatingSystem.IsWindows() ? AgentSocketPath.For(0, vaultId, _ => null) : m.AgentSocket!;
        var options = new AgentServerOptions(address, vaultId, unlock, null, TimeProvider.System, AgentHarness.MyUid);
        var server = AgentServer.StartAsync(options).GetAwaiter().GetResult();
        _agents.Add(server);
        return server;
    }

    /// <summary>
    /// No whitespace-delimited token of 32 or more hex characters, or of 24 or more base64 characters, also once
    /// <c>-</c> and <c>:</c> are stripped from it; and no run of hex groups separated by <c>-</c>, <c>:</c> or spaces
    /// that adds up to 32 hex characters or more (a secret printed grouped).
    /// </summary>
    private static void AssertNoKeyMaterial(string output)
    {
        foreach (var token in output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            Assert.True(!HexToken().IsMatch(token), $"hex-like token in the output: {token}");
            Assert.True(!Base64Token().IsMatch(token), $"base64-like token in the output: {token}");
            // For base64, path segments are matched one by one and only those mixing upper case, lower case and digits
            // (random base64 of 24+ characters does, all but certainly), so a hyphenated file path isn't taken for one.
            var joined = token.Replace("-", "").Replace(":", "");
            Assert.True(!HexToken().IsMatch(joined) && !joined.Split('/').Any(LooksLikeBase64Key), $"grouped key-like token in the output: {token}");
        }
        foreach (Match run in SeparatedHexRun().Matches(output))
            Assert.True(SeparatorChars().Replace(run.Value, "").Length < 32, $"grouped hex in the output: {run.Value}");
    }

    /// <summary>Final review item 8: a value typed on stdin (the recovery key, the vault password) is never printed.</summary>
    private static void AssertNotEchoed(string output, params string[] typed)
    {
        foreach (var value in typed)
            Assert.False(output.Contains(value, StringComparison.Ordinal), "a typed secret appears in the output");
        AssertNoKeyMaterial(output);
    }

    [Fact]
    public void AssertNoKeyMaterial_CatchesGroupedForms()
    {
        var secret = RandomNumberGenerator.GetBytes(20);
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertNoKeyMaterial("key " + BitConverter.ToString(secret)));
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertNoKeyMaterial("key " + BitConverter.ToString(secret).Replace('-', ':')));
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertNoKeyMaterial("key " + BitConverter.ToString(secret).Replace('-', ' ')));
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertNoKeyMaterial("key q83v-EjRW-eJCr-ze8S-NFZ4-kKvN-7xI=")); // grouped base64
        Assert.Throws<Xunit.Sdk.FalseException>(() => AssertNotEchoed("the key was " + Password, Password));
        AssertNoKeyMaterial("(fingerprint ABCD-EF01-2345-6789) slot add --yubikey --recovery-key-stdin");
    }

    private static bool LooksLikeBase64Key(string segment) =>
        Base64Token().IsMatch(segment) && segment.Any(char.IsAsciiLetterUpper) && segment.Any(char.IsAsciiLetterLower)
        && segment.Any(char.IsAsciiDigit);

    [GeneratedRegex("[0-9A-Fa-f]+(?:[-: ]+[0-9A-Fa-f]+)+")]
    private static partial Regex SeparatedHexRun();

    [GeneratedRegex("[-: ]")]
    private static partial Regex SeparatorChars();

    [GeneratedRegex("^[0-9A-Fa-f]{32,}$")]
    private static partial Regex HexToken();

    [GeneratedRegex("^[A-Za-z0-9+/]{24,}={0,2}$")]
    private static partial Regex Base64Token();
}
