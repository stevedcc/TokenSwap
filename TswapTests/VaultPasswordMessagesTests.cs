using TswapCli;
using TswapCore;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Review T17 p4 MiMo I2: the user-facing texts of rulings 3, 13, 17 and 18, pinned once to the brief's literal
/// words. The behaviour tests compare output with these constants; here the constants themselves are checked, so a
/// reworded text (or one that drifted towards "another machine") fails a test.
/// </summary>
public class VaultPasswordMessagesTests
{
    [Fact]
    public void Ruling18_Texts_AreTheBriefsWords()
    {
        Assert.Equal("Wrong vault password. The TPM counts failed attempts and locks out for a while after several.",
            VaultPasswordMessages.WrongPasswordTpm);
        Assert.Equal("The TPM is in dictionary-attack lockout after failed password attempts; wait and try again.",
            VaultPasswordMessages.TpmLockoutLinux);
        Assert.Equal("Windows has locked TPM use for this user after too many wrong passwords (by default for up to 8 hours, " +
                     "or until an administrator resets the TPM lockout). Slots on this machine without a vault password may be " +
                     "blocked meanwhile too.", VaultPasswordMessages.TpmLockoutWindows);
        Assert.Equal("tswap opened a password-protected TPM key without its password (a tswap bug; please report it).",
            VaultPasswordMessages.WindowsSilentContextBug);
        Assert.Equal("Wrong vault password (or this slot's key changed).", VaultPasswordMessages.WrongPasswordKdf);
        Assert.Equal("Wrong vault password (or this slot was made on another Mac).", VaultPasswordMessages.WrongPasswordSecureEnclave);
    }

    [Fact]
    public void Ruling3And13_Texts_AreTheBriefsWords()
    {
        Assert.Equal("This slot's hardware object needs a password, but its blob doesn't say so: restore config.json from backup, or upgrade tswap.",
            VaultPasswordMessages.StrippedHeader);
        Assert.Equal("This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.",
            VaultPasswordMessages.NoTerminal);
        Assert.Equal("This vault's slot needs the vault password, but the vault folder has no vault-password file. If it is synced, " +
                     "wait for the sync; otherwise restore it from a backup of the folder.", VaultPasswordMessages.MissingFile);
        Assert.Equal("The tswap agent could not unlock either: The simulated TPM is unplugged.",
            VaultPasswordMessages.AgentAlsoFailed("The simulated TPM is unplugged."));
    }

    [Fact]
    public void Ruling17_LockoutWarnings_AreTheBriefsWords()
    {
        Assert.Equal("Warning: this TPM's lockout password is empty, so anyone who can use the TPM can reset its failed-password " +
                     "counter and keep guessing the vault password. Setting one (as root: tpm2_changeauth -c lockout) affects every " +
                     "program that uses this TPM.", TpmLockoutProbe.EmptyLockoutAuthWarning);
        Assert.Equal("Windows locks TPM use after about 4 wrong passwords, for up to 8 hours; run 'tswap agent start' to avoid retyping it.",
            VaultPasswordChoice.WindowsLockoutLine);
    }

    [Fact]
    public void VerifierMismatch_IsTheControllersWords_AndNotAWrongPassword()
    {
        // Review T17 p5 MiMo I2 (controller ruling, fix round 3): the hardware accepted the password but the
        // vault-password file's verifier refused it. One text for agent start and broker unlock; the password was
        // proven by the hardware, so it never reads as a wrong password.
        Assert.Equal("The vault password opened this machine's slot but does not match the vault's vault-password file " +
                     "(it may belong to another vault or be out of sync). Copy vault-password from a machine where the " +
                     "password works, or re-enrol this slot.", VaultPasswordMessages.VerifierMismatch);
        Assert.False(VaultPasswordMessages.VerifierMismatch.StartsWith("Wrong vault password", StringComparison.Ordinal));
    }

    [Fact]
    public void SecureEnclavePresenceFailure_IsItsOwnText_NotTheStrippedHeaders()
    {
        // Review T17 p4 MiMo M5: the shim's -8 on the password unwrap says Touch ID or the login password failed;
        // a stripped header gets the old unwrap's generic text (implementation ruling 2), never this one.
        var text = SecureEnclaveReturnCodes.UnwrapV2Failure(SecureEnclaveReturnCodes.AuthenticationFailed).Message;

        Assert.Equal("Could not unlock with the Secure Enclave: this slot also needs Touch ID or the login password, and that " +
                     "was cancelled, failed, or could not be asked for (code -8).", text);
        Assert.NotEqual(VaultPasswordMessages.StrippedHeader, text);
        Assert.NotEqual(SecureEnclaveReturnCodes.UnwrapFailure(-2).Message, text);
    }
}
