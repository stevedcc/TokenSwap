using System.Security.Cryptography;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T24 task 3 (issue #309 comments 2 and 3): <c>slot request --password</c> says what is wrong with the vault
/// folder: (b) no such folder, (c) no keyring there, (d) password slots but no <c>vault-password</c> file, (e) no vault
/// password yet. (a), no folder known, is <c>VaultPasswordJoinTests.RequestWithPassword_NoFolder_RefusesWithRuling16Text</c>.
/// Each refuses with nothing written: no request file and no config.
/// </summary>
public sealed class SlotRequestPasswordFolderTests : IDisposable
{
    private const string Password = "correct horse battery staple";

    private readonly FleetMachine _joiner = new("folder-joiner", SimulatedYubiKeyService.WithKeys()) { Tpm = RandomNumberGenerator.GetBytes(32) };
    private readonly List<FleetMachine> _others = [];
    private readonly string _files = Directory.CreateTempSubdirectory("tswap-req-folder-").FullName;

    public void Dispose()
    {
        _joiner.Dispose();
        foreach (var m in _others) m.Dispose();
        Directory.Delete(_files, true);
    }

    private string RequestPath => Path.Combine(_files, "request.json");

    private FleetMachine Vault(bool password)
    {
        var m = new FleetMachine("folder-vault", SimulatedYubiKeyService.WithKeys()) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _others.Add(m);
        if (password)
            m.Ok(Password + "\n" + Password + "\n", "init", "--tpm", "--password", "--no-recovery");
        else
            m.Ok("", "init", "--tpm", "--no-password", "--no-recovery");
        return m;
    }

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    private void AssertRefused(int exit, string err, string expected)
    {
        Assert.NotEqual(0, exit);
        Assert.Contains(ErrorLine(expected), err);
        Assert.False(File.Exists(RequestPath));
    }

    [Fact]
    public void FolderMissing_NamesTheFolderAsTypedAndInFull()
    {
        var given = Path.Combine(_files, "no-such", "..", "missing");
        var full = Path.GetFullPath(given);

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "request", "--tpm", "--password", "--vault-dir", given, RequestPath);

        AssertRefused(exit, err,
            $"slot request --vault-dir {given}: there is no folder {full}. Nothing was changed. Check the path; the shared " +
            "vault folder holds the vault's 'keyring' file.");
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    [Fact]
    public void FolderWithoutKeyring_IsNotAVaultFolder()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_files, "empty")).FullName;

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "request", "--tpm", "--password", "--vault-dir", folder, RequestPath);

        AssertRefused(exit, err,
            $"{folder} has no keyring, so it is not a shared vault folder. Nothing was changed. Point --vault-dir at the folder " +
            "the enrolled machines share (its 'keyring' file must be there).");
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    [Fact]
    public void PasswordSlotsButNoVaultPasswordFile_SaysRestoreIt_NotFirstPassword()
    {
        var vault = Vault(password: true);
        File.Delete(PasswordVaultTestSupport.VaultPasswordPath(vault));

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "request", "--tpm", "--password", "--vault-dir", vault.VaultDir!, RequestPath);

        AssertRefused(exit, err,
            $"The vault in {vault.VaultDir} has slots that need the vault password, but the folder has no vault-password file. " +
            "If it is synced, wait for the sync; otherwise restore it from a backup of the folder. Nothing was changed.");
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    private static string NoPasswordYet(string folder) =>
        $"The vault in {folder} has no vault password yet (no slot needs one, and the folder has no vault-password file), so " +
        "there is none to join. The first one is created on a machine that already opens the vault, with sudo tswap slot " +
        "add --tpm --password (or --secure-enclave, --yubikey or --fido2, with --password). If this machine already opens it, " +
        "run that here instead of slot request. Otherwise enrol without --password.";

    [Fact]
    public void NoVaultPasswordYet_ThroughVaultDir_SaysHowToCreateTheFirst()
    {
        var vault = Vault(password: false);

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "request", "--tpm", "--password", "--vault-dir", vault.VaultDir!, RequestPath);

        AssertRefused(exit, err, NoPasswordYet(vault.VaultDir!));
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    [Fact]
    public void NoVaultPasswordYet_ThroughThisRecordVaultsOwnFolder_SaysHowToCreateTheFirst()
    {
        // The issue's oort case: a machine joined to the folder (init --vault-dir), no --vault-dir on the request.
        var vault = Vault(password: false);
        _joiner.Ok("", "init", "--vault-dir", vault.VaultDir!);
        var config = _joiner.ConfigText;

        var (exit, _, err) = _joiner.Run("yes\n" + Password + "\n", "slot", "request", "--tpm", "--password", RequestPath);

        AssertRefused(exit, err, NoPasswordYet(vault.VaultDir!));
        Assert.Equal(config, _joiner.ConfigText);
        Assert.Empty(_joiner.Backups);
    }
}
