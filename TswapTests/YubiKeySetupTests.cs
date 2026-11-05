using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 4: <c>tswap yubikey setup</c> programs slot 2 for HMAC-SHA1 challenge-response, and
/// refuses anything that could lock a vault out (design "tswap yubikey setup"). Runs in process against
/// <see cref="SimulatedYubiKeyService"/> (per-serial slot 2 state and program outcome), or against
/// <see cref="SdkYubiKeyService"/> over <see cref="FakeOtpKeys"/> where a key without a serial or a failing slot read
/// is needed. Vaults come from <see cref="FleetMachine"/> (<c>init</c>) or are written by hand (keyrings the
/// commands can't make). Every setup run's output is checked for key material (<see cref="AssertNoKeyMaterial"/>).
/// </summary>
public sealed partial class YubiKeySetupTests : IDisposable
{
    private const int SerialA = 41111111;
    private const int SerialB = 42222222;
    private const int SerialC = 43333333;

    private readonly List<FleetMachine> _machines = [];
    private readonly string _empty = Directory.CreateTempSubdirectory("tswap-setup-").FullName;

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
        Directory.Delete(_empty, recursive: true);
    }

    private sealed record Result(int Exit, string Out, string Err, FakeConsole Console)
    {
        public string All => Out + Err;
    }

    /// <summary>
    /// Runs <c>tswap yubikey setup</c> in process with <paramref name="keys"/>, the config folder <paramref name="dir"/>
    /// (default: an empty folder, no vault), on a terminal or not, verbose or not. No sudo bypass: setup needs none.
    /// </summary>
    private Result Setup(IYubiKeyService keys, string[] args, string? dir = null, string stdin = "", bool terminal = false,
        bool verbose = false, Action<FakeConsole>? onConsole = null)
    {
        var console = new FakeConsole(stdin) { IsInputRedirected = !terminal };
        onConsole?.Invoke(console);
        string[] full = ["yubikey", "setup", .. args];
        var configDir = dir ?? _empty;
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = configDir, Verbose = verbose, CommandArgs = full };
        var ctx = new CommandContext(console, env, () => VaultStores.Open(configDir, warnings: console.Error), keys,
            new VaultUnlocker(keys), testKey: null, sudoBypass: false);
        var exit = CliRunner.Run(ctx, full);
        var result = new Result(exit, console.OutText, console.ErrorText, console);
        AssertNoKeyMaterial(result.All);
        return result;
    }

    private static SimulatedYubiKeyService Keys(params int[] serials) => SimulatedYubiKeyService.WithKeys(serials);

    private static SimulatedYubiKeyService EmptySlot(params int[] serials)
    {
        var keys = Keys(serials);
        foreach (var s in serials)
            keys.Slot2States[s] = Slot2State.Empty;
        return keys;
    }

    private FleetMachine Machine(SimulatedYubiKeyService keys)
    {
        var m = new FleetMachine("setup", keys);
        _machines.Add(m);
        return m;
    }

    private static string Hidden(int? serial) => YubiKeyAccessTexts.ExplainHidden(serial, YubiKeyAccessTexts.CurrentOs());

    private const string NotSetUpWarning = "couldn't check whether a vault depends on this key";

    // ── touch choice ──────────────────────────────────────────────────────────

    [Fact]
    public void Setup_NeedsTouchChoice()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, []);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("--touch", r.Err);
        Assert.Contains("--no-touch", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_BothTouchFlags_Refused()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, ["--touch", "--no-touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("--touch", r.Err);
        Assert.Contains("--no-touch", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_UnknownArgument_IsAUsageError()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, ["--touch", "--force"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("Usage:", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_SerialNotANumber_IsAUsageError()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, ["--touch", "--serial", "abc"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("Usage:", r.Err);
        Assert.Empty(keys.Programmed);
    }

    // ── an empty slot is programmed ───────────────────────────────────────────

    [Fact]
    public void Setup_EmptySlot_ProgramsWithTouch()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, ["--touch"]);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], keys.Programmed);
        Assert.Contains($"YubiKey {SerialA} slot 2: HMAC-SHA1 challenge-response, touch required", r.Out);
        Assert.Equal(Slot2State.Configured, keys.GetSlot2State(SerialA));
    }

    [Fact]
    public void Setup_EmptySlot_ProgramsWithoutTouch()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, ["--no-touch"]);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, false)], keys.Programmed);
        Assert.Contains($"YubiKey {SerialA} slot 2: HMAC-SHA1 challenge-response, no touch required", r.Out);
        Assert.DoesNotContain("touch the key", r.All);
    }

    /// <summary>
    /// The settings a programmed slot gets (Review Focus 4): HMAC-SHA1 with HMAC_LT64 on, a 20-byte key, touch per
    /// flag, as yubikey-manager 5.9.2's <c>ykman otp chalresp --generate</c> (<c>HmacSha1SlotConfiguration</c>: CHAL_RESP,
    /// CHAL_HMAC, HMAC_LT64; <c>require_touch</c>: CHAL_BTN_TRIG; <c>os.urandom(20)</c>). Sources cited in the task 4 report.
    /// </summary>
    [Fact]
    public void Setup_ProgramsYkmanCompatibleConfig()
    {
        Assert.Equal(new Slot2Programming(HmacSha1: true, SmallChallenge: true, Touch: true, KeyLength: 20), YubicoOtpKeys.Slot2Settings(true));
        Assert.Equal(YubicoOtpKeys.Slot2Settings(true) with { Touch = false }, YubicoOtpKeys.Slot2Settings(false));
    }

    /// <summary>
    /// The bytes the slot is configured with (task 4 AOT fix: tswap builds the SDK's <c>ConfigureSlotCommand</c> itself,
    /// so the SDK's flag builder, which needs dynamic code under NativeAOT, is never reached). They equal yubikey-manager
    /// 5.9.2's <c>HmacSha1SlotConfiguration(key).require_touch(touch)</c>: EXTFLAG SERIAL_API_VISIBLE 0x04 | ALLOW_UPDATE
    /// 0x20; TKTFLAG CHAL_RESP 0x40; CFGFLAG CHAL_HMAC 0x22 | HMAC_LT64 0x04, plus CHAL_BTN_TRIG 0x08 with touch.
    /// </summary>
    [Fact]
    public void Setup_SlotFlagsMatchYkman()
    {
        Assert.Equal((Extended: (byte)0x24, Ticket: (byte)0x40, Configuration: (byte)0x2E), YubicoOtpKeys.Slot2Flags(YubicoOtpKeys.Slot2Settings(true)));
        Assert.Equal((Extended: (byte)0x24, Ticket: (byte)0x40, Configuration: (byte)0x26), YubicoOtpKeys.Slot2Flags(YubicoOtpKeys.Slot2Settings(false)));
    }

    /// <summary>The 20-byte key goes into the configuration as the SDK's operation puts it: 16 bytes AES key, then 4 + 2 zero bytes of uid.</summary>
    [Fact]
    public void Setup_SlotKeyLayoutMatchesTheSdk()
    {
        var key = Enumerable.Range(1, 20).Select(i => (byte)i).ToArray();

        var (aesKey, uid) = YubicoOtpKeys.Slot2KeyLayout(key);

        Assert.Equal(key[..16], aesKey);
        Assert.Equal([17, 18, 19, 20, 0, 0], uid);
    }

    // ── a configured slot ─────────────────────────────────────────────────────

    [Fact]
    public void Setup_ConfiguredSlot_RefusedWithoutReplace()
    {
        var keys = Keys(SerialA); // slot 2 configured

        var r = Setup(keys, ["--touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(
            $"slot 2 of YubiKey {SerialA} is already set up (touch: unknown — the key doesn't report it); a vault using this key " +
            "would no longer open if it were replaced. Use --replace to overwrite it.", r.Err);
        Assert.Empty(keys.Programmed);
        Assert.Empty(keys.Challenges); // never challenged to learn the touch posture
    }

    [Fact]
    public void Setup_Replace_WrongSerialTyped_Refused()
    {
        var keys = Keys(SerialA);

        var r = Setup(keys, ["--touch", "--replace"], stdin: $"{SerialB}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"{SerialA}", r.Err);
        Assert.Contains("doesn't match", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_TypedSerialIsTrimmed()
    {
        var keys = Keys(SerialA);

        var r = Setup(keys, ["--touch", "--replace"], stdin: $"  {SerialA} \n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_NoTerminal_Refused()
    {
        var keys = Keys(SerialA);

        var r = Setup(keys, ["--touch", "--replace"], stdin: $"{SerialA}\n", terminal: false);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("terminal", r.Err);
        Assert.Empty(keys.Programmed);
        Assert.Equal(0, r.Console.Reads);
    }

    [Fact]
    public void Setup_Replace_OutputRedirected_Refused()
    {
        var keys2 = Keys(SerialA);
        var console = new FakeConsole($"{SerialA}\n") { IsInputRedirected = false, IsOutputRedirected = true };
        string[] full = ["yubikey", "setup", "--touch", "--replace"];
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _empty, Verbose = false, CommandArgs = full };
        var ctx = new CommandContext(console, env, () => VaultStores.Open(_empty), keys2, new VaultUnlocker(keys2), null, false);
        var exit = CliRunner.Run(ctx, full);

        Assert.NotEqual(0, exit);
        Assert.Contains("terminal", console.ErrorText);
        Assert.Empty(keys2.Programmed);
    }

    // ── --replace: the vault check ────────────────────────────────────────────

    [Fact]
    public void Setup_Replace_OnlySlotOfVault_Refused()
    {
        var m = Machine(Keys(SerialA));
        m.Ok("", "init", "--yubikey", "--no-recovery");
        Assert.Single(m.Keyring.Slots);

        var r = Setup(m.Keys, ["--touch", "--replace"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("only way", r.Err);
        Assert.Contains($"YubiKey {SerialA}", r.Err);
        Assert.Empty(m.Keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherSlotExists_Proceeds()
    {
        var m = Machine(Keys(SerialA));
        m.Ok("", "init", "--yubikey"); // plus the recovery slot
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], m.Keyring.Slots.Select(s => s.Kind));

        var r = Setup(m.Keys, ["--no-touch", "--replace"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, false)], m.Keys.Programmed);
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    [Fact]
    public void Setup_Replace_AnotherMachinesTpmSlot_CountsAsAnotherWayIn()
    {
        var dir = WriteKeyringVault([YubiKeySlot(SerialA), MachineSlot(TpmLikeBlob())]);

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], keys.Programmed);
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    // Amended 2026-11-05: another key's YubiKey slot counts only when that key is plugged in and its slot opens now.

    /// <summary>A vault with one-key slots on A and B, made by init (A) and slot add (B), so B's slot really opens it.</summary>
    private FleetMachine VaultOnAAndB(string? password = null)
    {
        var m = Machine(Keys(SerialA, SerialB));
        m.Keys.PluggedIn = [SerialB];
        if (password is null)
            m.Ok("", "init", "--yubikey", "--no-recovery");
        else
            m.Ok(password + "\n" + password + "\n", "init", "--yubikey", "--password", "--no-recovery");
        m.Keys.PluggedIn = [SerialA, SerialB];
        var (exit, _, err) = m.RunOnTerminal(password is null ? "" : password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(exit == 0, err);
        Assert.Equal([SerialB, SerialA], m.Keyring.Slots.Select(s => YubiKeySlotBlob.Decode(s.HwBlob!).Serial));
        m.Keys.Challenges.Clear();
        return m;
    }

    [Fact]
    public void Setup_Replace_OtherKeyPluggedAndOpens_Proceeds()
    {
        var m = VaultOnAAndB();

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], m.Keys.Programmed);
        Assert.Contains(m.Keys.Challenges, c => c.Serial == SerialB); // B's slot was checked
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    [Fact]
    public void Setup_Replace_OtherKeyPluggedButDead_Refused()
    {
        var m = VaultOnAAndB();
        m.Keys.ProgramSlot2(SerialB, true); // B's slot 2 got a new secret since: its vault slot no longer opens
        m.Keys.Programmed.Clear();

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(DeadText(SerialB), r.Err);
        Assert.Empty(m.Keys.Programmed);
    }

    private static string DeadText(int other) =>
        $"YubiKey {other}'s slot didn't open (it may have been reprogrammed); this key may be the vault's only working YubiKey, so it's left as it is";

    private static string PlugInText(int other) => $"plug in YubiKey {other} so its slot can be checked, or leave this key as it is";

    [Fact]
    public void Setup_Replace_OtherKeyNoAnswer_Refused()
    {
        var m = VaultOnAAndB();
        m.Keys.NotAnswering.Add(SerialB); // a touch that timed out

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"YubiKey {SerialB} didn't answer; plug it in and touch it when it flashes", r.Err);
        Assert.Empty(m.Keys.Programmed);
    }

    /// <summary>Amended 2026-11-05: the rule applies only when this key has a slot in the keyring.</summary>
    [Fact]
    public void Setup_Replace_KeyNotInKeyring_Proceeds()
    {
        var dir = WriteKeyringVault([YubiKeySlot(SerialB)]); // B not plugged in: no check is needed

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], keys.Programmed);
        Assert.Empty(keys.Challenges);
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    /// <summary>
    /// Another machine's legacy pair slot (its pair serials are in that machine's config, not here) may be on this
    /// key: fail closed, it counts as this key's slot.
    /// </summary>
    [Fact]
    public void Setup_Replace_ForeignLegacyPairSlot_CountsAsThisKeys()
    {
        var dir = WriteKeyringVault([YubiKeySlot(SerialB), MachineSlot(null)]); // own slot: B's; then a pair slot

        var keys = Keys(SerialA); // B not plugged in
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(PlugInText(SerialB), r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherKeyNotPlugged_Refused()
    {
        var dir = WriteKeyringVault([YubiKeySlot(SerialA), YubiKeySlot(SerialB)]);

        var keys = Keys(SerialA); // B is not plugged in
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(PlugInText(SerialB), r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherKeyHidden_Refused()
    {
        var m = VaultOnAAndB();
        m.Keys.Hidden = [SerialB]; // plugged in, but its OTP interface can't be reached: it can't be checked

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(PlugInText(SerialB), r.Err);
        Assert.Empty(m.Keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherKeyBusy_Refused()
    {
        var m = VaultOnAAndB();
        m.Keys.Busy.Add(SerialB);

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"YubiKey {SerialB} is busy (another tswap or app is using it); try again.", r.Err);
        Assert.DoesNotContain("didn't answer", r.Err); // busy is its own case, not a missed touch
        Assert.Empty(m.Keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherKeyPasswordSlot_AsksForThePasswordAtTheTerminal()
    {
        const string password = "correct horse battery staple";
        var m = VaultOnAAndB(password); // B's slot has the vault password, A's doesn't

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\n{password}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains("Vault password:", r.Err);
        Assert.Equal([(SerialA, true)], m.Keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherKeyPasswordSlot_WrongPassword_Refused()
    {
        const string password = "correct horse battery staple";
        var m = VaultOnAAndB(password);

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialA}"], m.Dir, $"{SerialA}\nwrong password\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(DeadText(SerialB), r.Err);
        Assert.Empty(m.Keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherKeyUnplugged_ButTpmSlot_Proceeds()
    {
        var dir = WriteKeyringVault([YubiKeySlot(SerialA), YubiKeySlot(SerialB), MachineSlot(TpmLikeBlob())]);

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], keys.Programmed);
        Assert.Empty(keys.Challenges); // a TPM slot counts without a check
    }

    [Fact]
    public void Setup_Replace_TwoSlotsBothOnThisKey_Refused()
    {
        var dir = WriteKeyringVault([YubiKeySlot(SerialA), YubiKeySlot(SerialA, requiresTouch: false)]);

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("only way", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_OtherSlotUnreadableYubiKey_Refused()
    {
        // A YubiKey slot whose serial can't be read counts as this key's (fail closed).
        var unreadable = YubiKeySlotBlob.Magic.ToArray().Concat(new byte[] { 0xFF, 1, 2, 3 }).ToArray();
        Assert.True(YubiKeySlotBlob.IsYubiKeyBlob(unreadable));
        var dir = WriteKeyringVault([YubiKeySlot(SerialA), MachineSlot(unreadable)]);

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("only way", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_ClassicVaultUsingKey_Refused()
    {
        var m = Machine(Keys(SerialA, SerialB));
        ClassicVaultTestSupport.CreateXorVault(m, SerialA, SerialB);

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialB}"], m.Dir, $"{SerialB}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("classic", r.Err);
        Assert.Contains($"YubiKey {SerialB}", r.Err);
        Assert.Empty(m.Keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_ClassicVaultNotUsingKey_ProceedsWithoutWarning()
    {
        var m = Machine(Keys(SerialA, SerialB, SerialC));
        ClassicVaultTestSupport.CreateXorVault(m, SerialA, SerialB);

        var r = Setup(m.Keys, ["--touch", "--replace", "--serial", $"{SerialC}"], m.Dir, $"{SerialC}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialC, true)], m.Keys.Programmed);
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    /// <summary>
    /// A legacy pair slot (a keyring vault whose config lists this serial among its pair serials, as
    /// <c>migrate --to-records</c> leaves it) is this key's slot, never another way in.
    /// </summary>
    [Fact]
    public void Setup_Replace_LegacyPairSlotsOnly_Refused()
    {
        var dir = WriteLegacyPairVaultWithoutRecovery();

        var keys = Keys(KeyringV3PairFixtureTests.SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{KeyringV3PairFixtureTests.SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("only way", r.Err);
        Assert.Empty(keys.Programmed);
    }

    /// <summary>
    /// Amended 2026-11-05 (second review): a key outside this vault's own pair has no slot in the keyring, so nothing
    /// on it is at risk and setup proceeds (before that amendment this was refused: a pair slot is no way in).
    /// </summary>
    [Fact]
    public void Setup_Replace_LegacyPairOfOtherKeys_KeyNotInKeyring_Proceeds()
    {
        var dir = WriteLegacyPairVaultWithoutRecovery();

        var keys = Keys(SerialC);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialC}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialC, true)], keys.Programmed);
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    [Fact]
    public void Setup_Replace_LegacyPairSlotPlusRecovery_Proceeds()
    {
        var dir = Path.Combine(_empty, "pair");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "config.json"), KeyringV3PairFixtureTests.FixtureConfigJson);

        var keys = Keys(KeyringV3PairFixtureTests.SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{KeyringV3PairFixtureTests.SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(KeyringV3PairFixtureTests.SerialA, true)], keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_EmptySlot_ProgramsWithoutConfirmation()
    {
        var m = Machine(Keys(SerialA));
        m.Ok("", "init", "--yubikey", "--no-recovery"); // this key is the vault's only way in
        m.Keys.Slot2States[SerialA] = Slot2State.Empty;  // but its slot 2 holds nothing to lose

        var r = Setup(m.Keys, ["--touch", "--replace"], m.Dir, "", terminal: false);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialA, true)], m.Keys.Programmed);
        Assert.Equal(0, r.Console.Reads);
        Assert.DoesNotContain(NotSetUpWarning, r.All);
    }

    [Fact]
    public void Setup_Replace_NoVault_WarnsAndProceeds()
    {
        var keys = Keys(SerialA);

        var r = Setup(keys, ["--touch", "--replace"], _empty, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains(NotSetUpWarning, r.Err);
        Assert.Equal([(SerialA, true)], keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_UnreadableVault_WarnsAndProceeds()
    {
        var dir = Path.Combine(_empty, "broken");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "config.json"), "{ this is not json");

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains(NotSetUpWarning, r.Err);
        Assert.Equal([(SerialA, true)], keys.Programmed);
    }

    [Fact]
    public void Setup_Replace_UnreadableKeyring_WarnsAndProceeds()
    {
        var dir = Path.Combine(_empty, "badkeyring");
        Directory.CreateDirectory(dir);
        var config = new Config([], "", DateTime.UtcNow, Keyring: "not base64 at all!");
        File.WriteAllText(Path.Combine(dir, "config.json"), JsonSerializer.Serialize(config, TswapJsonContext.Default.Config));

        var keys = Keys(SerialA);
        var r = Setup(keys, ["--touch", "--replace"], dir, $"{SerialA}\n", terminal: true);

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains(NotSetUpWarning, r.Err);
        Assert.Equal([(SerialA, true)], keys.Programmed);
    }

    // ── which key ─────────────────────────────────────────────────────────────

    [Fact]
    public void Setup_NoKey_SaysNoYubiKey()
    {
        var keys = Keys(SerialA);
        keys.PluggedIn = [];

        var r = Setup(keys, ["--touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("No YubiKey detected", r.Err);
    }

    [Fact]
    public void Setup_OnlyKeyHidden_ExplainsPerOs()
    {
        var keys = EmptySlot(SerialA);
        keys.Hidden = [SerialA];

        var r = Setup(keys, ["--touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(Hidden(SerialA), r.Err);
        Assert.DoesNotContain("not plugged in", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_SeveralKeysAllHidden_ExplainsPerOs()
    {
        var keys = EmptySlot(SerialA, SerialB);
        keys.Hidden = [SerialA, SerialB];

        var r = Setup(keys, ["--touch"], terminal: true, stdin: "1\n");

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(Hidden(SerialA), r.Err);
        Assert.Contains(Hidden(SerialB), r.Err);
        Assert.DoesNotContain("Select YubiKey", r.Err);
        Assert.Equal(0, r.Console.Reads);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_SeveralKeys_NoSerial_Prompts()
    {
        var keys = EmptySlot(SerialA, SerialB);

        var r = Setup(keys, ["--touch"], terminal: true, stdin: "2\n");

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains($"Serial: {SerialA}", r.Err);
        Assert.Contains($"Serial: {SerialB}", r.Err);
        Assert.Equal([(SerialB, true)], keys.Programmed);
    }

    [Fact]
    public void Setup_SeveralKeys_NoTerminal_RefusedWithoutAPrompt()
    {
        var keys = EmptySlot(SerialA, SerialB);

        var r = Setup(keys, ["--touch"], terminal: false, stdin: "2\n");

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("--serial", r.Err);
        Assert.Equal(0, r.Console.Reads);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_SerialNamesTheKey_AmongSeveral()
    {
        var keys = EmptySlot(SerialA, SerialB);

        var r = Setup(keys, ["--touch", "--serial", $"{SerialB}"]);

        Assert.True(r.Exit == 0, r.All);
        Assert.Equal([(SerialB, true)], keys.Programmed);
        Assert.Equal(0, r.Console.Reads);
    }

    [Fact]
    public void Setup_SerialNotPluggedIn_Refused()
    {
        var keys = EmptySlot(SerialA);

        var r = Setup(keys, ["--touch", "--serial", $"{SerialC}"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"YubiKey {SerialC} is not plugged in", r.Err);
        Assert.DoesNotContain(Hidden(null), r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_SerialHiddenKey_ExplainsPerOs()
    {
        var keys = EmptySlot(SerialA, SerialB);
        keys.Hidden = [SerialB];

        var r = Setup(keys, ["--touch", "--serial", $"{SerialB}"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains(Hidden(SerialB), r.Err);
        Assert.DoesNotContain("not plugged in", r.Err);
        Assert.Empty(keys.Programmed);
    }

    [Fact]
    public void Setup_KeyWithoutSerial_Refused()
    {
        var fake = new FakeOtpKeys().WithKey(null);
        var keys = new SdkYubiKeyService(fake, YubiKeyAccessTexts.CurrentOs());

        var r = Setup(keys, ["--touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("a YubiKey was found but its serial number can't be read; tswap needs it", r.Err);
        Assert.Empty(fake.Programs);
    }

    [Fact]
    public void Setup_PromptSaysAnotherKeyHidden()
    {
        var keys = EmptySlot(SerialA, SerialB);
        keys.Hidden = [SerialB];

        var r = Setup(keys, ["--touch"], terminal: true, stdin: "1\n");

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains($"Serial: {SerialA}", r.Err);
        Assert.DoesNotContain($"Serial: {SerialB}", r.Err);
        Assert.Contains(Hidden(SerialB), r.Err);
        Assert.Equal([(SerialA, true)], keys.Programmed);
    }

    [Fact]
    public void Setup_NotPluggedIn_AddsPerOsTextWhenHiddenSerialUnknown()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA).WithHiddenKey(null);
        var keys = new SdkYubiKeyService(fake, YubiKeyAccessTexts.CurrentOs());

        var r = Setup(keys, ["--touch", "--serial", $"{SerialC}"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"YubiKey {SerialC} is not plugged in", r.Err);
        Assert.Contains(Hidden(null), r.Err);
        Assert.Empty(fake.Programs);
    }

    [Fact]
    public void Setup_Slot2StateReadFails_DoesNotProgram()
    {
        var fake = new FakeOtpKeys().WithKey(SerialA);
        fake.Busy.Add(SerialA);
        var keys = new SdkYubiKeyService(fake, YubiKeyAccessTexts.CurrentOs());

        var r = Setup(keys, ["--touch", "--replace"], stdin: $"{SerialA}\n", terminal: true);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains("busy", r.Err);
        Assert.Empty(fake.Programs);
        Assert.Equal(0, r.Console.Reads); // stopped before asking anything
    }

    // ── programming fails ─────────────────────────────────────────────────────

    [Fact]
    public void Setup_ProgramFails_SaysSlotMayBeEmpty()
    {
        var keys = EmptySlot(SerialA);
        keys.ProgramOutcome[SerialA] = OtpFailure.ProgramFailed;

        var r = Setup(keys, ["--touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"slot 2 of YubiKey {SerialA} may now be empty or half-written", r.Err);
        Assert.Contains("tswap yubikey setup --replace", r.Err);
        Assert.DoesNotContain("HMAC-SHA1 challenge-response, touch required", r.Out);
    }

    [Fact]
    public void Setup_VerifyWrongAnswer_SaysMismatch()
    {
        var keys = EmptySlot(SerialA);
        keys.ProgramOutcome[SerialA] = OtpFailure.VerifyWrong;

        var r = Setup(keys, ["--no-touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"slot 2 of YubiKey {SerialA} was programmed but is configured wrongly", r.Err);
        Assert.Contains("settings mismatch", r.Err);
        Assert.Contains("would not open the way a correctly programmed challenge-response slot does", r.Err);
        Assert.Contains("--replace", r.Err);
        Assert.DoesNotContain("HMAC-SHA1 challenge-response, no touch required", r.Out);
    }

    [Fact]
    public void Setup_VerifyFails_SaysProgrammedButUnchecked()
    {
        var keys = EmptySlot(SerialA);
        keys.ProgramOutcome[SerialA] = OtpFailure.VerifyNoAnswer;

        var r = Setup(keys, ["--touch"]);

        Assert.NotEqual(0, r.Exit);
        Assert.Contains($"slot 2 of YubiKey {SerialA} is programmed, but its check failed", r.Err);
        Assert.Contains("slot add --yubikey", r.Err);
        Assert.Contains("challenges it twice", r.Err);
    }

    // ── what setup prints ─────────────────────────────────────────────────────

    [Fact]
    public void Setup_TouchPromptBeforeProgramming()
    {
        var keys = EmptySlot(SerialA);
        FakeConsole? console = null;
        string? atProgram = null;
        keys.OnProgram = _ => atProgram = console!.OutText + console.ErrorText;

        var r = Setup(keys, ["--touch"], onConsole: c => console = c);

        Assert.True(r.Exit == 0, r.All);
        Assert.NotNull(atProgram);
        Assert.Contains("touch the key when it flashes (to check the new slot)", atProgram);
    }

    [Fact]
    public void Setup_PrintsInterruptionNote()
    {
        var keys = EmptySlot(SerialA);
        FakeConsole? console = null;
        string? atProgram = null;
        keys.OnProgram = _ => atProgram = console!.OutText + console.ErrorText;

        var r = Setup(keys, ["--no-touch"], onConsole: c => console = c);

        Assert.True(r.Exit == 0, r.All);
        Assert.Contains(
            "If this is interrupted, slot 2 may be left programmed but unchecked: enrol it with `slot add --yubikey` " +
            "(which challenges it twice), or run setup again with --replace.", atProgram);
    }

    [Fact]
    public void Verbose_SetupListsTransports()
    {
        var keys = EmptySlot(SerialA, SerialB);
        keys.Hidden = [SerialB];
        keys.Transports[SerialA] = "HidKeyboard, HidFido, SmartCard";
        FakeConsole? console = null;
        string? atEnumeration = null;
        keys.OnListSerials = () => atEnumeration ??= console!.OutText;

        var r = Setup(keys, ["--touch", "--serial", $"{SerialA}"], verbose: true, onConsole: c => console = c);

        Assert.True(r.Exit == 0, r.All);
        var lines = r.Out.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var strategy = lines.Where(l => l.Contains("PC/SC")).ToList();
        var keyA = lines.FindIndex(l => l.Contains($"YubiKey {SerialA}:") && l.Contains("HidKeyboard, HidFido, SmartCard"));
        var keyB = lines.FindIndex(l => l.Contains($"YubiKey {SerialB}:") && l.Contains("HidFido"));
        Assert.True(keyA >= 0 && keyB > keyA, r.Out); // FindKeys order
        Assert.Contains("not reachable", lines[keyB]);
        if (OperatingSystem.IsLinux())
        {
            var line = Assert.Single(strategy);
            Assert.EndsWith("unknown (not a published build)", line);
            Assert.True(lines.IndexOf(line) < keyA, r.Out);
            Assert.DoesNotContain("PC/SC", atEnumeration); // printed after the enumeration
        }
        else
        {
            Assert.Empty(strategy);
        }
    }

    [Fact]
    public void Setup_OutputHasNoKeyMaterial()
    {
        // Every run in this class is checked (Setup → AssertNoKeyMaterial); here the paths that print the most.
        foreach (var flag in new[] { "--touch", "--no-touch" })
        {
            var keys = EmptySlot(SerialA, SerialB);
            keys.Hidden = [SerialB];
            var r = Setup(keys, [flag, "--serial", $"{SerialA}"], verbose: true);
            Assert.True(r.Exit == 0, r.All);
        }

        // The check itself catches what it looks for.
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertNoKeyMaterial("key " + Convert.ToHexString(RandomNumberGenerator.GetBytes(20))));
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertNoKeyMaterial("key " + Convert.ToBase64String(RandomNumberGenerator.GetBytes(20))));
    }

    [Fact]
    public void Help_ListsYubiKeySetup()
    {
        var console = new FakeConsole();
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _empty, Verbose = false, CommandArgs = ["--help"] };
        var keys = Keys();
        var ctx = new CommandContext(console, env, () => VaultStores.Open(_empty), keys, new VaultUnlocker(keys), null, false);

        Assert.Equal(0, CliRunner.Run(ctx, ["--help"]));

        var line = Assert.Single(console.OutText.Split('\n'), l => l.Contains("yubikey setup ("));
        Assert.Contains("tswap yubikey setup (--touch|--no-touch) [--serial N] [--replace]", line);
        Assert.DoesNotContain("[sudo]", line);
        var command = CommandRegistry.All.Single(c => c.Name == "yubikey");
        Assert.False(command.RequiresSudo);
        Assert.False(command.NeedsVault);
        var order = CommandRegistry.All.Select(c => c.Name).ToList();
        Assert.Equal(order.IndexOf("slots") + 1, order.IndexOf("yubikey"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// No whitespace-delimited token of 32 or more hex characters, or of 24 or more base64 characters: what a slot
    /// secret (20 bytes) would look like printed either way.
    /// </summary>
    private static void AssertNoKeyMaterial(string output)
    {
        foreach (var token in output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            Assert.True(!HexToken().IsMatch(token), $"hex-like token in setup's output: {token}");
            Assert.True(!Base64Token().IsMatch(token), $"base64-like token in setup's output: {token}");
        }
    }

    [GeneratedRegex("^[0-9A-Fa-f]{32,}$")]
    private static partial Regex HexToken();

    [GeneratedRegex("^[A-Za-z0-9+/]{24,}={0,2}$")]
    private static partial Regex Base64Token();

    private static Slot YubiKeySlot(int serial, bool? requiresTouch = true) =>
        MachineSlot(YubiKeySlotBlob.Create(serial, requiresTouch).Encode());

    private static Slot MachineSlot(byte[]? hwBlob) =>
        new(RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize), RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(48),
            SlotKind.Machine, hwBlob);

    /// <summary>A hardware blob that isn't a YubiKey's (the TPM blob's header; contents don't matter here).</summary>
    private static byte[] TpmLikeBlob() => "TSTP"u8.ToArray().Concat(RandomNumberGenerator.GetBytes(40)).ToArray();

    /// <summary>A keyring vault in the single-file layout, its keyring holding exactly <paramref name="slots"/>.</summary>
    private string WriteKeyringVault(IReadOnlyList<Slot> slots)
    {
        var dir = Path.Combine(_empty, "kr-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize), 1, slots);
        var config = new Config([], "", DateTime.UtcNow, Keyring: Convert.ToBase64String(KeyringCodec.Encode(keyring)),
            KeyringSlotId: Convert.ToBase64String(slots[0].SlotId));
        File.WriteAllText(Path.Combine(dir, "config.json"), JsonSerializer.Serialize(config, TswapJsonContext.Default.Config));
        return dir;
    }

    /// <summary>The legacy pair-keyring fixture (pair 11111111/22222222) with its recovery slot taken out.</summary>
    private string WriteLegacyPairVaultWithoutRecovery()
    {
        var config = KeyringV3PairFixtureTests.FixtureConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var pairOnly = keyring with { Slots = keyring.Slots.Where(s => s.Kind == SlotKind.Machine).ToList() };
        Assert.Single(pairOnly.Slots);
        var dir = Path.Combine(_empty, "pair-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "config.json"), JsonSerializer.Serialize(
            config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(pairOnly)) }, TswapJsonContext.Default.Config));
        return dir;
    }
}
