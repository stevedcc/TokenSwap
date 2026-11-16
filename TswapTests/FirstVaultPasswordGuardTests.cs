using System.Security.Cryptography;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T32 (#320): no command makes a vault's first <c>vault-password</c> file while the vault has password slots and
/// the folder's file is missing (not synced yet, or deleted): a freshly salted file would lock out the slots that need the
/// old one. <c>slot add --yubikey</c> and <c>recover</c> with a password refuse before any password prompt, enrolment or
/// write; <c>--no-password</c> still adds the slot. Simulated YubiKeys A, B and C and a simulated TPM.
/// </summary>
public sealed class FirstVaultPasswordGuardTests : IDisposable
{
    private const int SerialA = 61111111;
    private const int SerialB = 62222222;
    private const int SerialC = 63333333;
    private const string Password = "correct horse battery staple";

    private readonly List<FleetMachine> _machines = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
    }

    private static string Twice(string password) => password + "\n" + password + "\n";

    private static string VaultPasswordPath(FleetMachine m) => PasswordVaultTestSupport.VaultPasswordPath(m);

    private static string KeyringPath(FleetMachine m) => Path.Combine(m.VaultDir!, RecordVaultStore.KeyringFileName);

    /// <summary>
    /// The shared state: a TPM vault without a password (its recovery key returned) holding <c>db</c>, whose YubiKey A
    /// slot needs the password, with the folder's <c>vault-password</c> file gone; only B plugged in, its call log empty.
    /// </summary>
    private (FleetMachine M, string RecoveryKey, string Value) TpmVaultWithAPasswordSlotAndNoFile(string name)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(SerialA, SerialB)) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _machines.Add(m);
        m.Keys.PluggedIn = [];
        var recoveryKey = RecordVaultTestSupport.RecoveryKeyFrom(m.Ok("", "init", "--tpm", "--no-password"));
        m.Ok("", "create", "db");
        var value = m.Get("db");
        m.Keys.PluggedIn = [SerialA];
        var (exit, _, stderr) = m.RunOnTerminal(Twice(Password), "slot", "add", "--yubikey", "--password");
        Assert.True(exit == 0, stderr);
        Assert.True(File.Exists(VaultPasswordPath(m)));
        Assert.Contains(m.Keyring.Slots, SlotPassword.Requires);
        File.Delete(VaultPasswordPath(m));
        m.Keys.PluggedIn = [SerialB];
        m.Keys.Challenges.Clear();
        return (m, recoveryKey, value);
    }

    private sealed record Before(byte[] Keyring, byte[] Config, string[] Backups);

    private static Before Snap(FleetMachine m) =>
        new(File.ReadAllBytes(KeyringPath(m)), File.ReadAllBytes(m.ConfigPath), [.. m.Backups.Order()]);

    /// <summary>What every refusal asserts: the text, no password prompt, no file, nothing written, the new key untouched.</summary>
    private static void AssertRefused(FleetMachine m, Before before, int newKey, (int Exit, string Out, string Err) run)
    {
        var (exit, stdout, stderr) = run;
        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordChoice.FirstPasswordWithoutFileText, stderr);
        Assert.DoesNotContain("New vault password", stdout + stderr);
        Assert.DoesNotContain(TerminalPasswordProvider.PromptText, stdout + stderr);
        Assert.False(File.Exists(VaultPasswordPath(m)));
        Assert.Equal(before.Keyring, File.ReadAllBytes(KeyringPath(m)));
        Assert.Equal(before.Config, File.ReadAllBytes(m.ConfigPath));
        Assert.Equal(before.Backups, m.Backups.Order());
        Assert.DoesNotContain(m.Keys.Challenges, c => c.Serial == newKey);
        KeyMaterial.AssertNotEchoed(stdout + stderr, Password);
    }

    /// <summary>With the TPM replaced and only B plugged in, <c>get db</c> opens through B's slot, without a password.</summary>
    private static void AssertBOpensWithoutAPassword(FleetMachine m, string value)
    {
        m.Tpm = RandomNumberGenerator.GetBytes(32);
        m.Keys.PluggedIn = [SerialB];
        var (exit, stdout, stderr) = m.Run("", "get", "db"); // not a terminal: a password slot couldn't ask
        Assert.True(exit == 0, stderr);
        Assert.Equal(value, stdout.Trim());
    }

    [Fact]
    public void SlotAddYubiKey_Password_PasswordSlotsWithoutTheFile_Refused()
    {
        var (m, _, _) = TpmVaultWithAPasswordSlotAndNoFile("guard-add-pw");
        var before = Snap(m);

        var run = m.RunOnTerminal(Twice(Password), "slot", "add", "--yubikey", "--password");

        AssertRefused(m, before, SerialB, run);
    }

    /// <summary>
    /// Amendment A1: <c>Decide</c> asks only without a simulated chip, so this vault is a YubiKey one: A without a password,
    /// B with it (the file then made), the file deleted, then A and a new key C plugged in and "yes" answered.
    /// </summary>
    [Fact]
    public void SlotAddYubiKey_AnsweredYes_PasswordSlotsWithoutTheFile_Refused()
    {
        var m = new FleetMachine("guard-asked", SimulatedYubiKeyService.WithKeys(SerialA, SerialB, SerialC));
        _machines.Add(m);
        m.Keys.PluggedIn = [SerialA];
        m.Ok("", "init", "--yubikey", "--no-password", "--no-recovery");
        m.Ok("s3cret\ns3cret\n", "add", "db");
        m.Keys.PluggedIn = [SerialA, SerialB];
        m.Ok(Twice(Password), "slot", "add", "--yubikey", "--password");
        Assert.True(File.Exists(VaultPasswordPath(m)));
        File.Delete(VaultPasswordPath(m));
        m.Keys.PluggedIn = [SerialA, SerialC];
        m.Keys.Challenges.Clear();
        var before = Snap(m);

        var run = m.RunOnTerminal("yes\n" + Twice(Password), "slot", "add", "--yubikey");

        Assert.Contains(VaultPasswordChoice.Question, run.Item2); // the question was asked, and "yes" chose a password
        AssertRefused(m, before, SerialC, run);
    }

    [Fact]
    public void SlotAddYubiKey_NoPassword_PasswordSlotsWithoutTheFile_Adds()
    {
        var (m, _, value) = TpmVaultWithAPasswordSlotAndNoFile("guard-add-nopw");

        var (exit, _, stderr) = m.RunOnTerminal("", "slot", "add", "--yubikey", "--no-password");

        Assert.True(exit == 0, stderr);
        Assert.False(File.Exists(VaultPasswordPath(m)));
        var slotOfB = m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob) && YubiKeySlotBlob.Decode(s.HwBlob!).Serial == SerialB);
        Assert.False(SlotPassword.Requires(slotOfB));
        AssertBOpensWithoutAPassword(m, value);
    }

    [Fact]
    public void Recover_Password_PasswordSlotsWithoutTheFile_Refused()
    {
        var (m, recoveryKey, _) = TpmVaultWithAPasswordSlotAndNoFile("guard-recover-pw");
        var before = Snap(m);

        var run = m.Run(recoveryKey + "\n" + Twice(Password), "recover", "--yubikey", "--password");

        AssertRefused(m, before, SerialB, run);
        Assert.Equal(Twice(Password), m.LastConsole!.In.ReadToEnd()); // the password part of stdin never read
        KeyMaterial.AssertNotEchoed(run.Out + run.Err, recoveryKey);
    }

    [Fact]
    public void Recover_NoPassword_PasswordSlotsWithoutTheFile_Recovers()
    {
        var (m, recoveryKey, value) = TpmVaultWithAPasswordSlotAndNoFile("guard-recover-nopw");

        var (exit, _, stderr) = m.Run(recoveryKey + "\n", "recover", "--yubikey", "--no-password");

        Assert.True(exit == 0, stderr);
        Assert.False(File.Exists(VaultPasswordPath(m)));
        AssertBOpensWithoutAPassword(m, value);
    }
}
