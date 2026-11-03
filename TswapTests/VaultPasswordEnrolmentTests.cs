using System.Security.Cryptography;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 6, ruling 15: choosing the vault password when a slot is made (<c>init</c>,
/// <c>slot add --yubikey</c>, <c>recover</c>) and showing it in <c>slots</c>. Simulated TPM and YubiKeys.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class VaultPasswordEnrolmentTests : IDisposable
{
    private const int SerialA = RecordVaultTestSupport.SerialA;
    private const string Password = "correct horse battery staple";

    private const string ExplanationLine1 =
        "Add a vault password to this slot? Then every unlock needs it, or a running agent that holds it in memory.";
    private const string VersionLine = "Every machine that opens this vault's password slots needs tswap 0.2.0 or newer.";
    private const string YubiKeyLine =
        "For this slot the password is mixed into the key, not checked by the hardware: someone holding the plugged-in key can guess it offline, so make it long.";
    private const string WindowsLine =
        "Windows locks TPM use after about 4 wrong passwords, for up to 8 hours; run 'tswap agent start' to avoid retyping it.";
    private const string NotThisVaultsPassword =
        "That is not this vault's password (every slot with a password uses the same one).";

    private readonly List<FleetMachine> _machines = [];

    private FleetMachine Machine(string name, bool tpm = true, params int[] serials)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(serials)) { Tpm = tpm ? RandomNumberGenerator.GetBytes(32) : null };
        _machines.Add(m);
        return m;
    }

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
        VaultPasswordChoice.IsWindows = OperatingSystem.IsWindows;
    }

    private static string Twice(string password) => password + "\n" + password + "\n";

    private static Slot OwnSlot(FleetMachine m)
    {
        var id = Convert.FromBase64String(m.Config.KeyringSlotId!);
        return m.Keyring.Slots.Single(s => s.SlotId.AsSpan().SequenceEqual(id));
    }

    private static string VaultPasswordPath(FleetMachine m) => PasswordVaultTestSupport.VaultPasswordPath(m);

    private static string RecoveryKeyFrom(string initOutput)
    {
        var lines = initOutput.ReplaceLineEndings("\n").Split('\n').ToList();
        return lines[lines.IndexOf("Recovery Private Key (base64):") + 1];
    }

    // ------------------------------------------------------------------ init

    [Fact]
    public void Init_TpmWithPassword_CreatesVaultPasswordFile_AndPasswordSlot()
    {
        var m = Machine("init-pw");

        var (exit, _, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        var file = VaultPasswordFile.Decode(File.ReadAllBytes(VaultPasswordPath(m)), m.Keyring.VaultId);
        Assert.Equal(VaultPasswordParams.Default, file.Params);
        Assert.True(SlotPassword.Requires(OwnSlot(m)));
        // The vault opens with the password typed at the prompt, and with nothing else.
        var (createExit, _, createErr) = m.RunOnTerminal(Password + "\n", "create", "db");
        Assert.True(createExit == 0, createErr);
        var (getExit, getOut, getErr) = m.RunOnTerminal(Password + "\n", "get", "db");
        Assert.True(getExit == 0, getErr);
        Assert.False(string.IsNullOrWhiteSpace(getOut));
        var (wrongExit, _, wrongErr) = m.RunOnTerminal("not it\n", "get", "db");
        Assert.NotEqual(0, wrongExit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, wrongErr);
    }

    [Fact]
    public void Init_YubiKeyWithPassword_MakesAVersion2Slot_ThatNeedsThePassword()
    {
        var m = Machine("init-yk-pw", tpm: false, SerialA);

        var (exit, _, stderr) = m.Run(Twice(Password), "init", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        var blob = YubiKeySlotBlob.Decode(OwnSlot(m).HwBlob!);
        Assert.True(blob.RequiresPassword);
        Assert.True(File.Exists(VaultPasswordPath(m)));
        var (createExit, _, createErr) = m.RunOnTerminal(Password + "\n", "create", "db");
        Assert.True(createExit == 0, createErr);
        var (getExit, _, getErr) = m.Run("", "get", "db");
        Assert.NotEqual(0, getExit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, getErr);
    }

    [Fact]
    public void Init_NoPasswordFlag_KeyringBytesAsBefore()
    {
        // Goal 4 pin: --no-password and an unattended init with neither flag make the same password-free
        // vault: no vault-password file, a legacy TPM blob (no TSTP header) of the same size, and a v1
        // YubiKey blob of 74 bytes. (The keyrings' bytes differ only by their random keys and ids.)
        var flagged = Machine("no-pw");
        var plain = Machine("plain");
        flagged.Ok("", "init", "--tpm", "--no-password");
        plain.Ok("", "init", "--tpm");

        foreach (var m in new[] { flagged, plain })
        {
            Assert.False(File.Exists(VaultPasswordPath(m)));
            Assert.Equal(SlotPasswordKind.None, SlotPassword.Classify(OwnSlot(m)));
            Assert.False(TpmSlotBlob.HasHeader(OwnSlot(m).HwBlob));
        }
        Assert.Equal(OwnSlot(plain).HwBlob!.Length, OwnSlot(flagged).HwBlob!.Length);
        Assert.Equal(plain.Keyring.Slots.Select(s => (s.Kind, s.Wrapped.Length)), flagged.Keyring.Slots.Select(s => (s.Kind, s.Wrapped.Length)));
        Assert.Equal(
            KeyringCodec.Encode(plain.Keyring).Length,
            KeyringCodec.Encode(flagged.Keyring).Length);

        var yubiFlagged = Machine("yk-no-pw", tpm: false, SerialA);
        var yubiPlain = Machine("yk-plain", tpm: false, SerialA);
        yubiFlagged.Ok("", "init", "--no-password", "--no-recovery");
        yubiPlain.Ok("", "init", "--no-recovery");
        foreach (var m in new[] { yubiFlagged, yubiPlain })
        {
            var hwBlob = OwnSlot(m).HwBlob!;
            Assert.Equal(YubiKeySlotBlob.EncodedSize, hwBlob.Length);
            Assert.Equal(YubiKeySlotBlob.CurrentVersion, hwBlob[4]);
            Assert.False(File.Exists(VaultPasswordPath(m)));
        }
    }

    [Fact]
    public void Init_NeitherFlag_RedirectedInput_NoPassword_PrintsOneLine()
    {
        var m = Machine("unattended");

        var (exit, stdout, stderr) = m.Run("", "init", "--tpm", "--no-recovery");

        Assert.True(exit == 0, stderr);
        // One line about the password (init's other notices, such as the permissions one, are unchanged).
        Assert.Equal("No vault password for this slot (pass --password to add one).",
            Assert.Single(stderr.ReplaceLineEndings("\n").Split('\n'), l => l.Contains("password", StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(ExplanationLine1, stdout);
        Assert.Equal(0, m.LastConsole!.Reads);
        Assert.False(File.Exists(VaultPasswordPath(m)));
    }

    [Fact]
    public void Init_NeitherFlag_OnATerminal_Asks_YesMakesAPasswordSlot()
    {
        var m = Machine("asked-yes", tpm: false, SerialA);

        // The question, the password twice, "insert the key" Enter, the entropy choice.
        var (exit, stdout, stderr) = m.RunOnTerminal("yes\n" + Twice(Password) + "\n\n", "init", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains("Add a vault password? (yes/no, default no): ", stdout);
        Assert.True(SlotPassword.Requires(OwnSlot(m)));
    }

    [Fact]
    public void Init_NeitherFlag_OnATerminal_DefaultIsNo()
    {
        var m = Machine("asked-no", tpm: false, SerialA);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n\n\n", "init", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains("Add a vault password? (yes/no, default no): ", stdout);
        Assert.False(SlotPassword.Requires(OwnSlot(m)));
        Assert.False(File.Exists(VaultPasswordPath(m)));
    }

    [Fact]
    public void Init_PasswordExplanation_IncludesVersionLine()
    {
        var m = Machine("explained", tpm: false, SerialA);

        var (exit, stdout, stderr) = m.RunOnTerminal("no\n\n\n", "init", "--no-recovery");

        Assert.True(exit == 0, stderr);
        var lines = stdout.ReplaceLineEndings("\n").Split('\n');
        var at = Array.IndexOf(lines, ExplanationLine1);
        Assert.True(at >= 0, stdout);
        Assert.Equal("Without one, anyone who can use this machine's YubiKey as you can open the vault.", lines[at + 1]);
        Assert.Equal(YubiKeyLine, lines[at + 2]);
        Assert.Equal(VersionLine, lines[at + 3]);
        Assert.StartsWith("Add a vault password? (yes/no, default no): ", lines[at + 4]);
    }

    [Fact]
    public void Init_TpmWithPasswordFlag_PrintsTheVersionLine_NotTheYubiKeyLine()
    {
        var m = Machine("tpm-lines");

        var (exit, stdout, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains(VersionLine, stdout);
        Assert.DoesNotContain(YubiKeyLine, stdout);
    }

    [Fact]
    public void Init_SecureEnclaveWithPasswordFlag_PrintsTheEnclaveLineOnce()
    {
        // Review T17 p5 GLM minor 4: the Secure Enclave's explanation line (simulated Enclave, any platform).
        var m = new FleetMachine("se-lines", SimulatedYubiKeyService.WithKeys()) { SecureEnclave = RandomNumberGenerator.GetBytes(32) };
        _machines.Add(m);

        var (exit, stdout, stderr) = m.Run(Twice(Password), "init", "--secure-enclave", "--with-touch", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Single(stdout.ReplaceLineEndings("\n").Split('\n'), line => line == VaultPasswordChoice.SecureEnclaveLine);
        Assert.DoesNotContain(YubiKeyLine, stdout);
    }

    [Fact]
    public void ShortPassword_Warns_DoesNotRefuse()
    {
        var m = Machine("short");

        var (exit, _, stderr) = m.Run(Twice("short"), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains("Warning: this vault password is shorter than 12 characters; a longer one is much harder to guess.", stderr);
        Assert.True(SlotPassword.Requires(OwnSlot(m)));
    }

    [Fact]
    public void LongPassword_NoShortWarning()
    {
        var m = Machine("long");

        var (exit, _, stderr) = m.Run(Twice("twelve chars"), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("shorter than 12 characters", stderr);
    }

    [Fact]
    public void EmptyPassword_IsUsageError()
    {
        var m = Machine("empty");

        var (exit, _, stderr) = m.Run("\n\n", "init", "--tpm", "--password", "--no-recovery");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage: ", stderr);
        Assert.Contains("--no-password", stderr);
        Assert.False(File.Exists(m.ConfigPath));
        Assert.False(Directory.Exists(Path.Combine(m.Dir, "vault")));
    }

    [Fact]
    public void RepeatedPasswordDiffers_Refuses_NothingWritten()
    {
        var m = Machine("differs");

        var (exit, _, stderr) = m.Run(Password + "\n" + Password + "x\n", "init", "--tpm", "--password", "--no-recovery");

        Assert.NotEqual(0, exit);
        Assert.Contains("The two vault passwords differ. Nothing was changed.", stderr);
        Assert.False(File.Exists(m.ConfigPath));
    }

    [Fact]
    public void BothFlags_IsUsageError()
    {
        var m = Machine("both");

        var (exit, _, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-password");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage: ", stderr);
        Assert.False(File.Exists(m.ConfigPath));
    }

    // ------------------------------------------------------------------ slot add --yubikey

    private FleetMachine TpmPasswordVaultWithKeyPlugged(string name)
    {
        var m = Machine(name, tpm: true, SerialA);
        m.Ok(Twice(Password), "init", "--tpm", "--password", "--no-recovery");
        return m;
    }

    [Fact]
    public void SlotAdd_SecondPasswordSlot_WrongPassword_Refuses()
    {
        var m = TpmPasswordVaultWithKeyPlugged("add-wrong");
        var configBefore = m.ConfigText;
        var keyringBefore = File.ReadAllBytes(Path.Combine(m.VaultDir!, RecordVaultStore.KeyringFileName));

        // The unlock's prompt, then the new slot's password, which is not the vault's.
        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n" + "another password\n", "slot", "add", "--yubikey", "--password");

        Assert.NotEqual(0, exit);
        Assert.Contains(NotThisVaultsPassword, stderr);
        Assert.Equal(configBefore, m.ConfigText);
        Assert.Equal(keyringBefore, File.ReadAllBytes(Path.Combine(m.VaultDir!, RecordVaultStore.KeyringFileName)));
        Assert.Empty(m.Keys.Challenges); // refused before the key was enrolled
    }

    [Fact]
    public void SlotAdd_SecondPasswordSlot_RightPassword_Adds()
    {
        var m = TpmPasswordVaultWithKeyPlugged("add-right");
        var fileBefore = File.ReadAllBytes(VaultPasswordPath(m));
        var (createExit, _, createErr) = m.RunOnTerminal(Password + "\n", "create", "db");
        Assert.True(createExit == 0, createErr);

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password");

        Assert.True(exit == 0, stderr);
        var added = m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob));
        Assert.True(YubiKeySlotBlob.Decode(added.HwBlob!).RequiresPassword);
        Assert.Equal(fileBefore, File.ReadAllBytes(VaultPasswordPath(m))); // the same file, not a new one

        // The new slot opens the vault on its own: this machine's TPM is gone, the key and password remain.
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        var (getExit, getOut, getErr) = m.RunOnTerminal(Password + "\n", "get", "db");
        Assert.True(getExit == 0, getErr);
        Assert.False(string.IsNullOrWhiteSpace(getOut));
    }

    [Fact]
    public void SlotAdd_FirstPasswordSlot_OfAPasswordFreeVault_CreatesTheFile()
    {
        var m = Machine("add-first", tpm: true, SerialA);
        m.Ok("", "init", "--tpm", "--no-recovery");

        var (exit, _, stderr) = m.RunOnTerminal(Twice(Password), "slot", "add", "--yubikey", "--password");

        Assert.True(exit == 0, stderr);
        var file = VaultPasswordFile.Decode(File.ReadAllBytes(VaultPasswordPath(m)), m.Keyring.VaultId);
        Assert.Equal(VaultPasswordParams.Default, file.Params);
        Assert.True(YubiKeySlotBlob.Decode(m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob)).HwBlob!).RequiresPassword);
    }

    [Fact]
    public void SlotAdd_NeitherFlag_Unattended_NoPassword_PrintsOneLine()
    {
        var m = Machine("add-unattended", tpm: true, SerialA);
        m.Ok("", "init", "--tpm", "--no-recovery");

        var (exit, _, stderr) = m.Run("", "slot", "add", "--yubikey");

        Assert.True(exit == 0, stderr);
        Assert.Contains("No vault password for this slot (pass --password to add one).", stderr);
        Assert.False(YubiKeySlotBlob.Decode(m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob)).HwBlob!).RequiresPassword);
    }

    // ------------------------------------------------------------------ recover

    [Fact]
    public void Recover_WithPassword_UsesTheVaultPassword()
    {
        var m = Machine("recover", tpm: true, SerialA);
        var recoveryKey = RecoveryKeyFrom(m.Ok(Twice(Password), "init", "--tpm", "--password"));
        var (createExit, _, createErr) = m.RunOnTerminal(Password + "\n", "create", "db");
        Assert.True(createExit == 0, createErr);

        // A wrong password is refused with ruling 15's text, and nothing is enrolled.
        var before = m.ConfigText;
        var (wrongExit, _, wrongErr) = m.Run(recoveryKey + "\nnot the password\n", "recover", "--yubikey", "--password");
        Assert.NotEqual(0, wrongExit);
        Assert.Contains(NotThisVaultsPassword, wrongErr);
        Assert.Equal(before, m.ConfigText);

        var (exit, _, stderr) = m.Run(recoveryKey + "\n" + Password + "\n", "recover", "--yubikey", "--password");

        Assert.True(exit == 0, stderr);
        var added = m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob));
        Assert.True(YubiKeySlotBlob.Decode(added.HwBlob!).RequiresPassword);
        // The recovered slot opens the vault with the vault's password, without the old TPM.
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        var (getExit, _, getErr) = m.RunOnTerminal(Password + "\n", "get", "db");
        Assert.True(getExit == 0, getErr);
    }

    [Fact]
    public void Recover_NoFlag_NoPassword_KeyStillReadWhole()
    {
        var m = Machine("recover-plain", tpm: true, SerialA);
        var recoveryKey = RecoveryKeyFrom(m.Ok("", "init", "--tpm", "--no-password"));

        var (exit, _, stderr) = m.Run(recoveryKey + "\n", "recover", "--yubikey");

        Assert.True(exit == 0, stderr);
        Assert.Contains("No vault password for this slot (pass --password to add one).", stderr);
        Assert.False(YubiKeySlotBlob.Decode(m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob)).HwBlob!).RequiresPassword);
    }

    // ------------------------------------------------------------------ slots

    [Fact]
    public void Slots_MarksPasswordAndWarns()
    {
        var m = TpmPasswordVaultWithKeyPlugged("slots");
        var (addExit, _, addErr) = m.RunOnTerminal(Password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(addExit == 0, addErr);
        var tpmId = Convert.ToHexString(OwnSlot(m).SlotId).ToLowerInvariant()[..8];

        var stdout = m.Ok("", "slots");

        var lines = stdout.ReplaceLineEndings("\n").Split('\n');
        Assert.Contains(lines, l => l.StartsWith(tpmId) && l.EndsWith("TPM, sealed to this machine's TPM, vault password"));
        Assert.Contains(lines, l => l.Contains($"YubiKey {SerialA}, ") && l.EndsWith(", no password"));
        Assert.Contains("1 slot(s) open without the password: keep them away from shared machines.", lines);
    }

    [Fact]
    public void Slots_PasswordFreeVault_NoWarningLine()
    {
        var m = Machine("slots-free");
        m.Ok("", "init", "--tpm");

        var stdout = m.Ok("", "slots");

        Assert.Contains("TPM, sealed to this machine's TPM, no password", stdout);
        Assert.DoesNotContain("open without the password", stdout);
    }

    private static Config ConfigWithMachineBlobs(params byte[][] hwBlobs)
    {
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        List<Slot> slots = [];
        foreach (var hwBlob in hwBlobs)
        {
            var pair = SlotKeyPair.Generate();
            slots.Add(MachineSlotWrap.Wrap(vaultKey, pair.PrivateKey, pair.PublicKey, RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize),
                RandomNumberGenerator.GetBytes(32), KeyringFormat.KeyringFormatVersion, vaultId, 1) with { HwBlob = hwBlob });
        }
        var keyring = new Keyring(KeyringFormat.KeyringFormatVersion, vaultId, 1, slots);
        return new Config([], "", DateTime.UtcNow, RequiresTouch: false, RngMode: RngMode.System, Backend: HardwareBackend.Tpm,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(keyring)), KeyringSlotId: Convert.ToBase64String(slots[0].SlotId));
    }

    /// <summary>A table row of a machine slot: 8 hex characters, then the KIND column "machine".</summary>
    private static bool IsMachineRow(string line) =>
        System.Text.RegularExpressions.Regex.IsMatch(line, @"^[0-9a-f]{8}\s+machine\s");

    private static byte[] TstpBlob(byte version, byte flags) => [.. "TSTP"u8, version, flags, .. RandomNumberGenerator.GetBytes(40)];

    [Fact]
    public void Slots_ShowsNeedsNewerTswap()
    {
        var config = ConfigWithMachineBlobs(TstpBlob(2, 0x01), TpmSlotBlob.Wrap(RandomNumberGenerator.GetBytes(40)));

        var text = SlotsCommand.Format(config);

        var rows = text.ReplaceLineEndings("\n").Split('\n').Where(IsMachineRow).ToList();
        Assert.Equal(2, rows.Count);
        Assert.EndsWith("needs a newer tswap", rows[0]);
        Assert.EndsWith("vault password", rows[1]);
    }

    [Fact]
    public void Slots_ShowsCorrupt_ListsTheRest()
    {
        var config = ConfigWithMachineBlobs(TstpBlob(1, 0x00), RandomNumberGenerator.GetBytes(60), TpmSlotBlob.Wrap(RandomNumberGenerator.GetBytes(40)));

        var text = SlotsCommand.Format(config);

        var rows = text.ReplaceLineEndings("\n").Split('\n').Where(IsMachineRow).ToList();
        Assert.Equal(3, rows.Count);
        Assert.EndsWith("corrupt (restore config.json from backup)", rows[0]);
        Assert.EndsWith("TPM, sealed to this machine's TPM, no password", rows[1]);
        Assert.EndsWith("TPM, sealed to this machine's TPM, vault password", rows[2]);
        Assert.Contains("1 slot(s) open without the password: keep them away from shared machines.", text);
    }

    // ------------------------------------------------------------------ classic vaults, Windows

    [Fact]
    public void ClassicConfig_PasswordFlag_RefusedByTheClassicRefusal()
    {
        var m = Machine("classic", tpm: false, SerialA, RecordVaultTestSupport.SerialB);
        ClassicVaultTestSupport.CreateXorVault(m);
        var before = m.ConfigText;

        var (addExit, _, addErr) = m.Run(Twice(Password), "slot", "add", "--yubikey", "--password");
        var (initExit, _, initErr) = m.Run(Twice(Password), "init", "--password");

        Assert.NotEqual(0, addExit);
        Assert.Contains("This is a classic single-file vault (secrets.json.enc), which tswap 0.2 only migrates.", addErr);
        Assert.NotEqual(0, initExit);
        Assert.Contains("This config folder holds a classic vault.", initErr);
        Assert.Equal(before, m.ConfigText);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void WindowsTpmPassword_PrintsTheLockoutLine()
    {
        VaultPasswordChoice.IsWindows = () => true;
        var tpm = Machine("win-tpm");
        var yubiKey = Machine("win-yk", tpm: false, SerialA);
        var free = Machine("win-free");

        var tpmOut = tpm.Ok(Twice(Password), "init", "--tpm", "--password", "--no-recovery");
        var yubiKeyOut = yubiKey.Ok(Twice(Password), "init", "--password", "--no-recovery");
        var freeOut = free.Ok("", "init", "--tpm", "--no-password", "--no-recovery");

        Assert.Contains(WindowsLine, tpmOut);
        Assert.DoesNotContain(WindowsLine, yubiKeyOut);
        Assert.DoesNotContain(WindowsLine, freeOut);
    }

    [Fact]
    public void NotWindows_NoLockoutLine()
    {
        VaultPasswordChoice.IsWindows = () => false;
        var m = Machine("linux-tpm");

        var stdout = m.Ok(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.DoesNotContain(WindowsLine, stdout);
    }
}
