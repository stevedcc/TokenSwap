using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Guided init (task 5): a plain <c>init</c> at a terminal offers this machine's YubiKeys and chip, builds
/// every picked slot around one vault key in memory, and writes once; nothing is written when it stops,
/// and an existing vault is never overwritten (refused before the first prompt, and again before the write).
/// </summary>
public sealed class GuidedInitTests : IDisposable
{
    private const string PlugIn =
        "Plug in the security keys you want to use with this vault on this machine, then press Enter. (No touch yet: tswap asks when it needs one.)";
    private const string PickPrompt = "Pick one or more, separated by spaces (e.g. 1 3): ";
    private const string TouchPrompt = "Touch ID (or your login password) on every unlock? (y/n): ";
    private const string WhichSlotsPrompt = "Which slots need the password? (e.g. 1 3; Enter = all): ";
    private const string ChangedWhileWaiting = "config.json changed while init was waiting";
    private const string Password = "correct horse battery staple";

    /// <summary>A line a touch on another key's short-press slot types: 44 modhex characters.</summary>
    private const string Otp = "ccccccbhjknlcbdefghijklnrtuvcbdefghijklnrtuv";

    private readonly List<FleetMachine> _machines = [];
    private readonly List<string> _folders = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
        foreach (var f in _folders.Where(Directory.Exists))
            Directory.Delete(f, true);
    }

    private FleetMachine Machine(params int[] serials)
    {
        var m = new FleetMachine("guided", SimulatedYubiKeyService.WithKeys(serials));
        _machines.Add(m);
        return m;
    }

    private string Folder()
    {
        var f = Path.Combine(Path.GetTempPath(), "tswap-guided-folder-" + Guid.NewGuid().ToString("N")[..8]);
        _folders.Add(f);
        return f;
    }

    private static string VaultFolder(FleetMachine m) => Path.Combine(m.Dir, "vault");

    private static void AssertNothingWritten(FleetMachine m)
    {
        Assert.False(File.Exists(m.ConfigPath), "config.json was written");
        Assert.False(Directory.Exists(VaultFolder(m)), "the vault folder was written");
    }

    private static int Count(string text, string part)
    {
        var n = 0;
        for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal))
            n++;
        return n;
    }

    private static OSPlatform ThisOs() =>
        OperatingSystem.IsMacOS() ? OSPlatform.OSX
        : OperatingSystem.IsLinux() ? OSPlatform.Linux
        : OperatingSystem.IsWindows() ? OSPlatform.Windows
        : OSPlatform.FreeBSD;

    private static string ThisOsChip => OperatingSystem.IsMacOS() ? "Secure Enclave" : "TPM";

    /// <summary>Runs <c>names</c> with only <paramref name="serials"/> plugged in (and the chip as set), unattended.</summary>
    private static (int Exit, string Out, string Err) NamesWith(FleetMachine m, string stdin = "", bool terminal = false, params int[] serials)
    {
        var plugged = m.Keys.PluggedIn;
        m.Keys.PluggedIn = [.. serials];
        try
        {
            return terminal ? m.RunOnTerminal(stdin, "names") : m.Run(stdin, "names");
        }
        finally
        {
            m.Keys.PluggedIn = plugged;
        }
    }

    private static void AssertOpensWithKeyAlone(FleetMachine m, int serial)
    {
        var chip = m.SecureEnclave;
        m.SecureEnclave = null;
        try
        {
            var (exit, _, err) = NamesWith(m, serials: serial);
            Assert.True(exit == 0, $"key {serial} alone did not open the vault: {err}");
        }
        finally
        {
            m.SecureEnclave = chip;
        }
    }

    private static YubiKeySlotBlob BlobOf(FleetMachine m, int serial) =>
        m.Keyring.Slots.Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .Select(s => YubiKeySlotBlob.Decode(s.HwBlob!)).Single(b => b.Serial == serial);

    private static Slot SlotOf(FleetMachine m, int serial) =>
        m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob)
            && YubiKeySlotBlob.Decode(s.HwBlob!).Serial == serial);

    private static int[] YubiKeySerials(FleetMachine m) =>
        [.. m.Keyring.Slots.Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .Select(s => YubiKeySlotBlob.Decode(s.HwBlob!).Serial).Order()];

    // ------------------------------------------------------------------ the flow

    [Fact]
    public void Guided_TwoKeysAndSecureEnclave_EachOpensTheVault()
    {
        var m = Machine(11, 12);
        m.SecureEnclave = RandomNumberGenerator.GetBytes(32);

        // Enter, pick all three, touch yes, recovery (default yes), other machines no.
        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2 3\ny\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(PlugIn, stdout);
        Assert.Equal(HardwareBackend.SecureEnclave, m.Config.Backend);
        Assert.Equal([11, 12], YubiKeySerials(m));
        Assert.Equal(4, m.Keyring.Slots.Count); // two keys, the Secure Enclave, the recovery slot
        Assert.Contains("YubiKey 11: no password", stdout);
        Assert.Contains("YubiKey 12: no password", stdout);
        Assert.Contains("Secure Enclave (touch): no password", stdout);

        AssertOpensWithKeyAlone(m, 11);
        AssertOpensWithKeyAlone(m, 12);
        var (seExit, _, seErr) = NamesWith(m); // no key plugged in: the Secure Enclave alone
        Assert.True(seExit == 0, seErr);

        // The recovery key printed once opens it: 'recover' enrols a TPM with it, which then opens it.
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(stdout, "Recovery Private Key \\(base64\\):"));
        m.SecureEnclave = null;
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        m.Keys.PluggedIn = [];
        var (recoverExit, _, recoverErr) = m.Run(RecoveryKeyFrom(stdout) + "\n", "recover", "--tpm");
        Assert.True(recoverExit == 0, recoverErr);
        m.Ok("", "names");
    }

    public static TheoryData<string> ExistingVaults => ["classic", "record", "folder"];

    [Theory]
    [MemberData(nameof(ExistingVaults))]
    public void Guided_RefusesEveryExistingVault_BeforeAnyPrompt(string kind)
    {
        var m = Machine(RecordVaultTestSupport.SerialA, RecordVaultTestSupport.SerialB);
        string[] args = ["init"];
        string expected;
        switch (kind)
        {
            case "classic":
                ClassicVaultTestSupport.CreateXorVault(m);
                expected = "This config folder holds a classic vault. Convert it with 'sudo tswap migrate --to-records'";
                break;
            case "record":
                m.Ok("", "init", "--yubikey");
                expected = "belongs to a shared record-store vault";
                break;
            default:
                var folder = Folder();
                Directory.CreateDirectory(folder);
                File.WriteAllText(Path.Combine(folder, "something"), "x");
                args = ["init", "--folder", folder];
                expected = $"The vault folder {folder} is not empty.";
                break;
        }
        var config = File.Exists(m.ConfigPath) ? File.ReadAllText(m.ConfigPath) : null;
        var challenges = m.Keys.Challenges.Count;

        var (exit, stdout, stderr) = m.RunOnTerminal("yes\n\n1\n\nn\n", args);

        Assert.Equal(1, exit);
        Assert.Contains(expected, stderr);
        Assert.DoesNotContain("Plug in the security keys", stdout);
        Assert.DoesNotContain("Reinitialize?", stdout);
        Assert.Equal(config, File.Exists(m.ConfigPath) ? File.ReadAllText(m.ConfigPath) : null);
        Assert.Equal(challenges, m.Keys.Challenges.Count);
    }

    [Fact]
    public void Guided_NothingFound_SaysWhatWasLookedFor()
    {
        var m = Machine();

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n", "init");

        Assert.Equal(1, exit);
        Assert.Contains("YubiKeys", stderr);
        Assert.Contains(ThisOsChip, stderr);
        Assert.DoesNotContain(PickPrompt, stdout);
        AssertNothingWritten(m);
    }

    [Fact]
    public void Guided_BadPicks_AskAgain_EofAbortsWithNothingWritten()
    {
        var m = Machine(11, 12);

        var (exit, stdout, _) = m.RunOnTerminal("\n0\n9\na\n1 1\n", "init");

        Assert.Equal(1, exit);
        Assert.Equal(5, Count(stdout, PickPrompt)); // asked, then four more times after the four bad picks
        Assert.Contains("1-2", stdout);
        AssertNothingWritten(m);
        Assert.Empty(m.Keys.Challenges);
    }

    [Fact]
    public void Guided_EmptyPick_AsksAgain()
    {
        var m = Machine(11);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n\n1\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(2, Count(stdout, PickPrompt));
        Assert.Equal([11], YubiKeySerials(m));
    }

    [Fact]
    public void Guided_BlockedKey_IsExplained_AndCanBeLeftOut()
    {
        var m = Machine(11);
        var failure = YubiKeyAccessTexts.ExplainHidden(11, ThisOs());
        m.Keys.FailWith[11] = failure;
        m.SecureEnclave = RandomNumberGenerator.GetBytes(32);

        // Enter, pick both, touch yes, recovery, carry on without 11: yes, other machines no.
        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2\ny\n\ny\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(failure, stdout);
        Assert.Contains("Carry on without YubiKey 11? (y/N): ", stdout);
        Assert.Empty(YubiKeySerials(m));
        Assert.Equal(HardwareBackend.SecureEnclave, m.Config.Backend);
        m.Ok("", "names");
    }

    [Fact]
    public void Guided_KeyUnpluggedBeforeEnrolment_OffersToCarryOn()
    {
        var m = Machine(11, 12);
        m.Keys.FailWith[12] = "YubiKey 12 not found";

        var (exit, stdout, _) = m.RunOnTerminal("\n1 2\n\nn\n", "init", "--no-password");

        Assert.Equal(1, exit);
        Assert.Contains("YubiKey 12 not found", stdout);
        Assert.Contains("Carry on without YubiKey 12? (y/N): ", stdout);
        AssertNothingWritten(m);
    }

    [Fact]
    public void Guided_CarryOnWithoutAKey_EnrolsTheRestOnce()
    {
        var m = Machine(11, 12, 13);
        m.Keys.FailWith[12] = "YubiKey 12 not found";

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2 3\n\ny\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        var perSerial = m.Keys.Challenges.GroupBy(c => c.Serial).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<int, int> { [11] = 2, [13] = 2 }, perSerial);
        Assert.Equal([11, 13], YubiKeySerials(m));
        AssertOpensWithKeyAlone(m, 11);
        AssertOpensWithKeyAlone(m, 13);
    }

    [Fact]
    public void Guided_SecureEnclaveTouch_HasNoDefault()
    {
        var m = Machine();
        m.SecureEnclave = RandomNumberGenerator.GetBytes(32);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nx\ny\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(3, Count(stdout, TouchPrompt));
        Assert.Contains("With touch: every unlock asks for Touch ID or your login password. Without: the Secure Enclave opens the vault with no prompt at all (anyone using this Mac as you can open it).", stdout);
        Assert.DoesNotContain("--secure-enclave needs exactly one", stdout);
        Assert.True(m.Config.RequiresTouch);
        // The simulated Secure Enclave records the presence choice in the blob's last byte (1: required).
        var machine = m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine);
        Assert.Equal(1, machine.HwBlob![^1]);
    }

    [Fact]
    public void Guided_SecureEnclaveNoTouch_WarnsAndRecordsNoPresence()
    {
        var m = Machine();
        m.SecureEnclave = RandomNumberGenerator.GetBytes(32);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\nn\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("WARNING (--no-touch)", stderr);
        Assert.False(m.Config.RequiresTouch);
        Assert.Equal(0, m.Keyring.Slots.Single(s => s.Kind == SlotKind.Machine).HwBlob![^1]);
        Assert.Contains("Secure Enclave (no touch): no password", stdout);
    }

    // ------------------------------------------------------------------ the vault password

    [Fact]
    public void Guided_PasswordOnSomeSlots_TheBackupKeyOpensWithoutIt()
    {
        var m = Machine(11, 12);

        // Enter, pick both, password yes (twice), only slot 1 needs it, recovery, other machines no.
        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\nyes\n{Password}\n{Password}\n1\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("Add a vault password? You choose next which of the slots need it.", stdout);
        Assert.DoesNotContain("Add a vault password to this slot?", stdout);
        Assert.Contains(VaultPasswordChoice.YubiKeyLine, stdout);
        Assert.DoesNotContain("the password adds nothing", stdout); // no chip left out
        Assert.Contains(WhichSlotsPrompt, stdout);
        Assert.Contains("YubiKey 11: password", stdout);
        Assert.Contains("YubiKey 12: no password", stdout);
        Assert.True(File.Exists(PasswordVaultTestSupport.VaultPasswordPath(m)));

        var (backupExit, _, backupErr) = NamesWith(m, serials: 12);
        Assert.True(backupExit == 0, backupErr);
        var (noPasswordExit, _, noPasswordErr) = NamesWith(m, serials: 11);
        Assert.NotEqual(0, noPasswordExit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, noPasswordErr);
        var (passwordExit, _, passwordErr) = NamesWith(m, Password + "\n", terminal: true, 11);
        Assert.True(passwordExit == 0, passwordErr);
    }

    [Fact]
    public void Guided_WhichSlots_InvalidAnswer_AsksAgain()
    {
        var m = Machine(11, 12);

        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\nyes\n{Password}\n{Password}\n0\n3\n2\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(3, Count(stdout, WhichSlotsPrompt));
        Assert.False(BlobOf(m, 11).RequiresPassword);
        Assert.True(BlobOf(m, 12).RequiresPassword);
    }

    [Fact]
    public void Guided_PasswordFlags_SkipTheWhichSlotsQuestion()
    {
        var withPassword = Machine(11, 12);
        var (exit, stdout, stderr) = withPassword.RunOnTerminal($"\n1 2\n{Password}\n{Password}\n\nn\n", "init", "--password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.DoesNotContain("Which slots", stdout);
        foreach (var serial in new[] { 11, 12 })
        {
            Assert.NotEqual(0, NamesWith(withPassword, serials: serial).Exit);
            var (okExit, _, okErr) = NamesWith(withPassword, Password + "\n", terminal: true, serial);
            Assert.True(okExit == 0, okErr);
        }

        var noPassword = Machine(11, 12);
        (exit, stdout, stderr) = noPassword.RunOnTerminal("\n1 2\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.DoesNotContain(VaultPasswordChoice.Question, stdout);
        Assert.DoesNotContain("Which slots", stdout);
        Assert.False(File.Exists(PasswordVaultTestSupport.VaultPasswordPath(noPassword)));
        foreach (var serial in new[] { 11, 12 })
        {
            var (okExit, _, okErr) = NamesWith(noPassword, serials: serial);
            Assert.True(okExit == 0, okErr);
        }
    }

    [Fact]
    public void Guided_DroppingTheOnlyPasswordSlot_MakesNoPassword()
    {
        var m = Machine(11, 12);
        m.Keys.FailWith[11] = "YubiKey 11 not found";

        // Password on slot 1 (key 11) only; key 11 fails; carry on.
        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\nyes\n{Password}\n{Password}\n1\n\ny\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.False(File.Exists(PasswordVaultTestSupport.VaultPasswordPath(m)));
        Assert.Contains("Vault password: dropped (no remaining slot needed it)", stdout);
        Assert.False(BlobOf(m, 12).RequiresPassword);
        var (openExit, _, openErr) = NamesWith(m, serials: 12);
        Assert.True(openExit == 0, openErr);
    }

    private const string GuidedPasswordQuestion = "Add a vault password? (yes/no): ";

    [Fact]
    public void Guided_StrayOtpLine_AtThePasswordQuestion_IsSkipped()
    {
        var m = Machine(11, 12);

        // The OTP line neither answers nor aborts; "yes", the password twice, Enter = all slots.
        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\n{Otp}\nyes\n{Password}\n{Password}\n\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("That was a YubiKey's one-time code; it was ignored.", stdout);
        Assert.True(File.Exists(PasswordVaultTestSupport.VaultPasswordPath(m)));
        foreach (var serial in new[] { 11, 12 })
        {
            Assert.NotEqual(0, NamesWith(m, serials: serial).Exit);
            var (okExit, _, okErr) = NamesWith(m, Password + "\n", terminal: true, serial);
            Assert.True(okExit == 0, okErr);
        }
    }

    [Fact]
    public void Guided_EofAtThePasswordQuestion_WritesNothing()
    {
        var m = Machine(11);

        var (exit, stdout, _) = m.RunOnTerminal("\n1\n", "init", "--no-recovery");

        Assert.Equal(1, exit);
        Assert.Contains(GuidedPasswordQuestion, stdout);
        AssertNothingWritten(m);
        Assert.Empty(m.Keys.Challenges);
    }

    [Fact]
    public void Guided_PasswordQuestion_UnrecognisedAnswer_AsksAgain()
    {
        var m = Machine(11);

        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1\nmaybe\nyes\n{Password}\n{Password}\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(2, Count(stdout, GuidedPasswordQuestion));
        Assert.Contains("Add a vault password to this slot?", stdout); // one slot picked
        Assert.True(BlobOf(m, 11).RequiresPassword);
    }

    [Fact]
    public void Guided_ChipLeftOutOfThePassword_IsNoted()
    {
        var m = Machine(11);
        m.Tpm = RandomNumberGenerator.GetBytes(32);

        // Key 11 and the TPM; a password on slot 1 (key 11) only: the TPM opens the vault without it.
        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\nyes\n{Password}\n{Password}\n1\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(
            "Note: the TPM slot opens without the password, so on this machine the password adds nothing; leave a slot out only for a backup key kept elsewhere.",
            stdout);
        Assert.Contains("TPM: no password", stdout);
        Assert.Contains("YubiKey 11: password", stdout);
        var (tpmExit, _, tpmErr) = NamesWith(m); // no key plugged in, no password input: the TPM alone
        Assert.True(tpmExit == 0, tpmErr);
    }

    [Fact]
    public void Guided_PasswordOnTheChipOnly_TheKeyIsTheBackup()
    {
        var m = Machine(11);
        var tpm = RandomNumberGenerator.GetBytes(32);
        m.Tpm = tpm;

        // Key 11 (1) and the TPM (2); the password on the TPM only.
        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\nyes\n{Password}\n{Password}\n2\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("TPM: password", stdout);
        Assert.Contains("YubiKey 11: no password", stdout);
        Assert.DoesNotContain("the password adds nothing", stdout);
        var (noPasswordExit, _, noPasswordErr) = NamesWith(m); // no key: the TPM alone
        Assert.NotEqual(0, noPasswordExit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, noPasswordErr);
        var (passwordExit, _, passwordErr) = NamesWith(m, Password + "\n", terminal: true);
        Assert.True(passwordExit == 0, passwordErr);
        m.Tpm = null;
        var (keyExit, _, keyErr) = NamesWith(m, serials: 11);
        Assert.True(keyExit == 0, keyErr);
    }

    [Fact]
    public void Guided_WhichSlots_UsesThePickNumbers()
    {
        var m = Machine(11, 12, 13);

        // Pick 2 and 3 (keys 12 and 13); "1" was not picked, so it asks again; "3" is key 13.
        var (exit, stdout, stderr) = m.RunOnTerminal($"\n2 3\nyes\n{Password}\n{Password}\n1\n3\n\nn\n", "init");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(2, Count(stdout, WhichSlotsPrompt));
        var listing = stdout[stdout.IndexOf("A slot left out", StringComparison.Ordinal)..stdout.IndexOf(WhichSlotsPrompt, StringComparison.Ordinal)];
        Assert.Contains("  2. YubiKey 12", listing);
        Assert.Contains("  3. YubiKey 13", listing);
        Assert.DoesNotContain("YubiKey 11", listing);
        Assert.False(BlobOf(m, 12).RequiresPassword);
        Assert.True(BlobOf(m, 13).RequiresPassword);
        Assert.Equal([12, 13], YubiKeySerials(m));
    }

    [Fact]
    public void Guided_KeyAndTpm_EachOpensTheVault()
    {
        var m = Machine(11);
        var tpm = RandomNumberGenerator.GetBytes(32);
        m.Tpm = tpm;

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(HardwareBackend.Tpm, m.Config.Backend);
        Assert.False(m.Config.RequiresTouch);
        Assert.Contains("TPM: no password", stdout);
        Assert.Equal([11], YubiKeySerials(m));
        var (tpmExit, _, tpmErr) = NamesWith(m); // no key plugged in: the TPM alone
        Assert.True(tpmExit == 0, tpmErr);
        m.Tpm = null;
        var (keyExit, _, keyErr) = NamesWith(m, serials: 11);
        Assert.True(keyExit == 0, keyErr);
    }

    /// <summary>#253: guided init takes --recovery-key-out too: the key goes to the file, not to stdout.</summary>
    [Fact]
    public void Guided_RecoveryKeyOut_WritesFile()
    {
        var m = Machine(11);
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        var folder = Folder();
        Directory.CreateDirectory(folder);
        var keyFile = Path.Combine(folder, "recovery-key");

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2\n\nn\n", "init", "--no-password", "--recovery-key-out", keyFile);

        Assert.True(exit == 0, stderr + stdout);
        var key = File.ReadAllText(keyFile).TrimEnd('\n');
        Assert.Equal(32, Convert.FromBase64String(key).Length);
        Assert.DoesNotContain(key, stdout);
        Assert.DoesNotContain("Recovery Private Key (base64):", stdout);
        Assert.Contains($"Recovery private key written to {keyFile}", stdout);
        m.Tpm = RandomNumberGenerator.GetBytes(32); // a cleared TPM: the file's key enrols the new one
        var (recoverExit, _, recoverErr) = m.Run(key + "\n", "recover", "--tpm", "--no-password");
        Assert.True(recoverExit == 0, recoverErr);
    }

    [Fact]
    public void Guided_BadPick_WithOneEntry_SaysPick1()
    {
        var m = Machine(11);

        var (exit, stdout, _) = m.RunOnTerminal("\n2\n", "init");

        Assert.Equal(1, exit);
        Assert.Contains("Pick 1", stdout);
        Assert.DoesNotContain("1-1", stdout);
    }

    [Fact]
    public void Guided_NeverAsksRngMode()
    {
        var m = Machine(11);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.DoesNotContain("Password generation entropy source", stdout);
        Assert.Equal(RngMode.System, m.Config.RngMode);
    }

    // ------------------------------------------------------------------ prompts and output

    [Fact]
    public void Guided_OtherMachinesYes_PrintsTheGuide()
    {
        var m = Machine(11);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\ny\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("slot request --tpm request.json", stdout);
        Assert.Contains(m.Dir, stdout);
    }

    [Fact]
    public void Guided_StrayOtpLine_IsSkippedAtThePick()
    {
        var m = Machine(11, 12);

        var (exit, stdout, stderr) = m.RunOnTerminal($"\n{Otp}\n1\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("That was a YubiKey's one-time code; it was ignored.", stdout);
        Assert.Equal([11], YubiKeySerials(m));
    }

    [Fact]
    public void Guided_StrayOtpLine_AtTheCarryOnPrompt_IsSkipped()
    {
        var m = Machine(11, 12);
        m.Keys.FailWith[12] = "YubiKey 12 not found";

        var (exit, stdout, stderr) = m.RunOnTerminal($"\n1 2\n\n{Otp}\ny\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("That was a YubiKey's one-time code; it was ignored.", stdout);
        Assert.Equal([11], YubiKeySerials(m));
    }

    [Fact]
    public void Guided_EofAtOtherMachines_StillPrintsTheRecoveryWarning()
    {
        var m = Machine(11);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("YubiKey 11: no password", stdout);
        Assert.Contains("Vault folder:", stdout);
        // The recovery key's warning is the last block: nothing of the summary or the folder lines after it.
        var warning = stdout.LastIndexOf("⚠️  CRITICAL: BACKUP RECOVERY PRIVATE KEY NOW", StringComparison.Ordinal);
        Assert.True(warning >= 0, stdout);
        var tail = stdout[warning..];
        Assert.Contains("This is a break-glass credential for total hardware loss (YubiKey 11", tail);
        Assert.Contains("lost or destroyed). tswap never stores it anywhere — display here is", tail);
        Assert.Contains("Recovery Private Key (base64):\n" + RecoveryKeyFrom(stdout), tail.ReplaceLineEndings("\n"));
        Assert.DoesNotContain("Vault folder:", tail);
        Assert.DoesNotContain("Config saved to:", tail);
        Assert.DoesNotContain("YubiKey 11: no password", tail);
        m.Ok("", "names");
    }

    [Fact]
    public void PlainInit_WithStdoutRedirected_IsRefused_NothingTouched()
    {
        var m = Machine(11);
        var console = new FakeConsole("\n1\n\nn\n") { IsInputRedirected = false, IsOutputRedirected = true };
        string[] args = ["init", "--no-password"];

        var exit = CliRunner.Run(m.Context(console, args), args);

        Assert.Equal(1, exit);
        Assert.Contains(TswapCli.Commands.InitCommand.NoTerminalRefusal, console.ErrorText);
        Assert.DoesNotContain(PlugIn, console.OutText);
        Assert.Empty(m.Keys.Challenges);
        AssertNothingWritten(m);
    }

    [Fact]
    public void Guided_AnnouncesTheYubiKeyListing()
    {
        var m = Machine(11);
        string? seenAtListing = null;
        var console = new FakeConsole("\n1\n\nn\n") { IsInputRedirected = false };
        m.Keys.OnListSerials = () => seenAtListing ??= console.OutText;
        string[] args = ["init", "--no-password"];

        var exit = CliRunner.Run(m.Context(console, args), args);

        Assert.True(exit == 0, console.ErrorText + console.OutText);
        Assert.NotNull(seenAtListing);
        Assert.EndsWith("Looking for YubiKeys…", seenAtListing!.TrimEnd());
        Assert.True(console.OutText.IndexOf("Looking for YubiKeys…", StringComparison.Ordinal)
            < console.OutText.IndexOf("This machine has:", StringComparison.Ordinal));
    }

    [Fact]
    public void Guided_ChecksEachKeyBeforeItsChallenge()
    {
        var m = Machine(11, 12);
        var seenAtFirstChallenge = new Dictionary<int, string>();
        m.Keys.OnChallenge = serial => seenAtFirstChallenge.TryAdd(serial, m.LastConsole!.OutText);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1 2\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("Checking YubiKey 11…", seenAtFirstChallenge[11]);
        Assert.DoesNotContain("Checking YubiKey 12…", seenAtFirstChallenge[11]);
        Assert.Contains("Checking YubiKey 12…", seenAtFirstChallenge[12]);
        Assert.Contains("YubiKey 12: if it flashes, touch it (that one, not another key).", seenAtFirstChallenge[12]);
    }

    [Fact]
    public void Guided_PicksTypedOutOfOrder_EnrolInListSerialsOrder()
    {
        var m = Machine(11, 12);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n2 1\n\nn\n", "init", "--no-password");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(11, m.Keys.Challenges[0].Serial);
        Assert.Equal(Convert.ToBase64String(SlotOf(m, 11).SlotId), m.Config.KeyringSlotId);
    }

    [Theory]
    [InlineData("test reason", "(not available: test reason)")]
    [InlineData(null, "(not available: reason unknown)")]
    public void Guided_UnusableChip_IsListedUnnumbered(string? reason, string line)
    {
        var m = Machine();
        m.ChipOverride = () => new MachineChip(null, reason);

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n", "init");

        Assert.Equal(1, exit);
        Assert.Contains(line, stdout);
        Assert.DoesNotContain($"1. {ThisOsChip}", stdout);
        Assert.DoesNotContain(PickPrompt, stdout);
        Assert.Contains("YubiKeys", stderr);
        Assert.Contains(ThisOsChip, stderr);
        AssertNothingWritten(m);
    }

    // ------------------------------------------------------------------ failures write nothing

    [Fact]
    public void Guided_ChipEnrolmentFailure_WritesNothing()
    {
        var m = Machine(11);
        m.SecureEnclave = RandomNumberGenerator.GetBytes(32);

        int exit;
        string stderr;
        using (SimulatedHardwareService.ObserveCalls((_, call) =>
               {
                   if (call == "Enroll")
                       throw new TswapException("simulated chip failure");
               }))
            (exit, _, stderr) = m.RunOnTerminal("\n1 2\ny\n\nn\n", "init", "--no-password");

        Assert.Equal(1, exit);
        Assert.Contains("simulated chip failure", stderr);
        AssertNothingWritten(m);
        Assert.Empty(m.Keys.Challenges); // the chip is enrolled first
    }

    [Fact]
    public void Guided_PendingSlotRequest_AsksReinitialize_NoChangesNothing_YesBacksUp()
    {
        var m = Machine(11);
        m.Ok("", "slot", "request", m.PathOf("request.json"));
        var config = File.ReadAllText(m.ConfigPath);

        var (noExit, noOut, noErr) = m.RunOnTerminal("no\n", "init");

        Assert.True(noExit == 0, noErr);
        Assert.Contains("Already initialized. Reinitialize? (yes/no): ", noOut);
        Assert.DoesNotContain(PlugIn, noOut);
        Assert.Equal(config, File.ReadAllText(m.ConfigPath));
        Assert.False(Directory.Exists(VaultFolder(m)));
        Assert.Empty(m.Backups);

        var (yesExit, yesOut, _) = m.RunOnTerminal("yes\n", "init");

        Assert.Equal(1, yesExit); // EOF at step 1
        Assert.Contains(PlugIn, yesOut);
        Assert.Equal(config, File.ReadAllText(Assert.Single(m.Backups)));
        Assert.Equal(config, File.ReadAllText(m.ConfigPath));
        Assert.False(Directory.Exists(VaultFolder(m)));
    }

    [Fact]
    public void Guided_PendingRequestAppearedWhileWaiting_IsRefusedAtTheWrite()
    {
        var m = Machine(11);
        string? pending = null;
        m.Keys.OnChallenge = _ =>
        {
            if (pending is not null)
                return;
            pending = "";
            m.Ok("", "slot", "request", m.PathOf("request.json"));
            pending = File.ReadAllText(m.ConfigPath);
        };

        var (exit, stdout, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.Equal(1, exit);
        Assert.Contains(ChangedWhileWaiting, stderr);
        Assert.Equal(pending, File.ReadAllText(m.ConfigPath));
        Assert.NotNull(m.Config.PendingSlotId);
        Assert.False(Directory.Exists(VaultFolder(m)));
        Assert.DoesNotContain("Recovery Private Key", stdout);
    }

    [Fact]
    public void Guided_PendingRequestChangedWhileWaiting_IsRefusedAtTheWrite()
    {
        var m = Machine(11);
        m.Ok("", "slot", "request", m.PathOf("request.json"));
        var before = File.ReadAllText(m.ConfigPath);
        var other = Machine(11);
        other.Ok("", "slot", "request", other.PathOf("request.json"));
        var otherConfig = File.ReadAllBytes(other.ConfigPath);
        m.Keys.OnChallenge = _ => File.WriteAllBytes(m.ConfigPath, otherConfig);

        var (exit, _, stderr) = m.RunOnTerminal("yes\n\n1\n\nn\n", "init", "--no-password");

        Assert.Equal(1, exit);
        Assert.Contains(ChangedWhileWaiting, stderr);
        Assert.Equal(otherConfig, File.ReadAllBytes(m.ConfigPath));
        Assert.False(Directory.Exists(VaultFolder(m)));
        Assert.Equal(before, File.ReadAllText(Assert.Single(m.Backups)));
    }

    [Fact]
    public void Guided_FolderFilledWhileWaiting_IsRefusedAtTheWrite()
    {
        var m = Machine(11);
        var folder = Folder();
        Directory.CreateDirectory(folder);
        m.Keys.OnChallenge = _ => File.WriteAllText(Path.Combine(folder, "synced-in"), "x");

        var (exit, _, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--folder", folder, "--no-password");

        Assert.Equal(1, exit);
        Assert.Contains($"The vault folder {Path.GetFullPath(folder)} is not empty.", stderr);
        Assert.False(File.Exists(m.ConfigPath));
        Assert.Equal(["synced-in"], Directory.GetFileSystemEntries(folder).Select(Path.GetFileName));
    }

    [Fact]
    public void Guided_ConfigAppearedWhileWaiting_IsRefusedAtTheWrite()
    {
        var m = Machine(11);
        var other = Machine(11);
        other.Ok("", "init", "--yubikey");
        var recordConfig = File.ReadAllBytes(other.ConfigPath);
        m.Keys.OnChallenge = _ => File.WriteAllBytes(m.ConfigPath, recordConfig);

        var (exit, _, stderr) = m.RunOnTerminal("\n1\n\nn\n", "init", "--no-password");

        Assert.Equal(1, exit);
        Assert.Contains("belongs to a shared record-store vault", stderr);
        Assert.Equal(recordConfig, File.ReadAllBytes(m.ConfigPath));
        Assert.False(Directory.Exists(VaultFolder(m)));
    }

    // ------------------------------------------------------------------ --vault-dir is untouched

    [Fact]
    public void VaultDir_JoinStillWorks_WithoutATerminal()
    {
        var shared = Folder();
        var home = Machine(11);
        home.Ok("", "init", "--yubikey", "--folder", shared);
        var m = Machine(11);

        var (exit, _, stderr) = m.Run("", "init", "--vault-dir", shared);

        Assert.True(exit == 0, stderr);
        Assert.Equal(Path.GetFullPath(shared), m.Config.VaultDir);
        m.Ok("", "names");
    }

    [Fact]
    public void VaultDir_WithKeyring_IsTodaysUsageError()
    {
        var shared = Folder();
        var home = Machine(11);
        home.Ok("", "init", "--yubikey", "--folder", shared);
        var m = Machine(11);

        var (exit, _, stderr) = m.Run("", "init", "--vault-dir", shared, "--keyring");

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
        Assert.DoesNotContain("--keyring is gone", stderr);
        AssertNothingWritten(m);
    }
}
