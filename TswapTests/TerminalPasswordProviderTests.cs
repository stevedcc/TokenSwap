using TswapCore;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 5: the CLI's terminal source of the vault password (<c>TerminalPasswordProvider</c>),
/// which <c>CommandContext.Unlock</c> hands the unlocker as its pass 3 prompt (ruling 13). It reads the
/// vault folder's <c>vault-password</c> file, prompts <c>Vault password: </c> once on stderr, and stretches
/// the answer. A password-free vault never reaches it.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class TerminalPasswordProviderTests
{
    private const string Password = "correct horse battery staple";

    private const string NoTerminalText =
        "This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.";

    private const string MissingFileText =
        "This vault's slot needs the vault password, but the vault folder has no vault-password file. If it is synced, wait for the sync; otherwise restore it from a backup of the folder.";

    private static FleetMachine TpmPasswordMachine()
    {
        var m = new FleetMachine("tpp") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        // One secret, made with the password typed once.
        var (exit, _, err) = m.RunOnTerminal(Password + "\n", "create", "db");
        Assert.True(exit == 0, err);
        return m;
    }

    [Fact]
    public void Prompt_Once_ThenUnlocks()
    {
        using var m = TpmPasswordMachine();

        var (exit, stdout, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.False(string.IsNullOrWhiteSpace(stdout));
        Assert.Equal(1, m.LastConsole!.Reads);
        // The prompt goes to stderr, so stdout stays the command's output.
        Assert.Contains("Vault password: ", stderr);
        Assert.DoesNotContain("Vault password", stdout);
    }

    [Fact]
    public void WrongPassword_FailsWithRuling18Text_AfterOnePrompt()
    {
        using var m = TpmPasswordMachine();

        var (exit, _, stderr) = m.RunOnTerminal("not the password\n", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, stderr);
        Assert.Equal(1, m.LastConsole!.Reads);
    }

    [Fact]
    public void RedirectedInput_ThrowsWithTheRuling13Message()
    {
        using var m = TpmPasswordMachine();

        // stdin holds the password, but it is not a terminal: nothing is read from it.
        var (exit, stdout, stderr) = m.Run(Password + "\n", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Equal($"\n❌ Error: {NoTerminalText}\n", stderr.ReplaceLineEndings("\n"));
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void MissingVaultPasswordFile_ForAPasswordSlot_Refuses()
    {
        using var m = TpmPasswordMachine();
        File.Delete(PasswordVaultTestSupport.VaultPasswordPath(m));

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains(MissingFileText, stderr);
        Assert.Equal(0, m.LastConsole!.Reads); // refused before asking
    }

    [Fact]
    public void MissingVaultPasswordFile_WithoutTerminal_MissingFileMessageWins()
    {
        // Ruling 13: the missing-file message comes before the no-terminal message.
        using var m = TpmPasswordMachine();
        File.Delete(PasswordVaultTestSupport.VaultPasswordPath(m));

        var (exit, _, stderr) = m.Run(Password + "\n", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains(MissingFileText, stderr);
        Assert.DoesNotContain(NoTerminalText, stderr);
    }

    [Fact]
    public void ConflictCopy_Refuses_BeforeAsking()
    {
        using var m = TpmPasswordMachine();
        var path = PasswordVaultTestSupport.VaultPasswordPath(m);
        var other = File.ReadAllBytes(path);
        other[^1] ^= 1;
        File.WriteAllBytes(Path.Combine(m.VaultDir!, "vault-password.sync-conflict-20261103-120000-ABCDEFG"), other);

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains("The vault folder has two different vault-password files", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void PasswordFreeVault_NeverPrompts()
    {
        using var m = new FleetMachine("tpp-free") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };
        m.Ok("", "init", "--tpm", "--no-recovery");
        var (createExit, _, createErr) = m.RunOnTerminal("", "create", "db");
        Assert.True(createExit == 0, createErr);

        var (exit, _, stderr) = m.RunOnTerminal("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
        Assert.DoesNotContain("Vault password", stderr);
    }

    [Fact]
    public void FailedMemoryLock_WarnsThroughTheConsole()
    {
        // Tasks 1-4 leftover: the failed-lock warning goes to the command's IConsole, not Console.Error.
        using var m = TpmPasswordMachine();
        StretchedPassword.SimulateLockFailure = true;
        StretchedPassword.ResetLockWarning();
        try
        {
            var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

            Assert.True(exit == 0, stderr); // a warning, never a refusal
            Assert.Contains("Warning: couldn't lock the stretched vault password's memory against swapping", stderr);
        }
        finally
        {
            StretchedPassword.SimulateLockFailure = false;
            StretchedPassword.ResetLockWarning();
        }
    }
}
