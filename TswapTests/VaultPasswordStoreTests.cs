using System.Security.Cryptography;
using TswapCore;
using TswapCore.Broker;
using TswapCore.VaultPassword;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T17 task 4, ruling 2: the <c>vault-password</c> file in the shared vault folder, read and
/// written by <see cref="RecordVaultStore"/> through its file layer. Sync tools' conflicted copies that
/// differ make every password operation refuse; byte-identical copies are removed on the next write;
/// <c>vault merge</c> refuses two different files and copies one that only the other folder has.
/// </summary>
public sealed class VaultPasswordStoreTests : IDisposable
{
    private const string ConflictText =
        "The vault folder has two different vault-password files ({0}). Keep one (delete the other) before using the vault password.";

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _home;
    private readonly FleetMachine _laptop;
    private readonly byte[] _vaultKey;
    private readonly byte[] _vaultId;

    public VaultPasswordStoreTests()
    {
        _home = new FleetMachine("vp-home", _keys);
        _laptop = new FleetMachine("vp-laptop", _keys);
        _keys.PluggedIn = [SerialA];
        _vaultKey = VaultKey(_home, InitRecordVault(_home));
        _vaultId = _home.Keyring.VaultId;
    }

    public void Dispose()
    {
        _home.Dispose();
        _laptop.Dispose();
    }

    private string HomeFile => Path.Combine(_home.VaultDir!, RecordVaultStore.VaultPasswordFileName);

    /// <summary>A valid file for this vault; each call has its own salt, so two calls differ.</summary>
    private VaultPasswordFile NewFile()
    {
        using var stretched = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        return VaultPasswordFile.Create(_vaultKey, _vaultId, stretched, RandomNumberGenerator.GetBytes(32), VaultPasswordParams.Default);
    }

    private static Dictionary<string, string> FolderBytes(string folder) =>
        Directory.GetFiles(folder, "*", SearchOption.AllDirectories)
            .ToDictionary(f => Path.GetRelativePath(folder, f), f => Convert.ToHexString(File.ReadAllBytes(f)));

    [Fact]
    public void NoFile_ReadsAsNull()
    {
        var store = Store(_home);
        Assert.Null(store.ReadVaultPassword(_vaultId));
        Assert.Null(store.ReadVaultPasswordBytes());
    }

    [Fact]
    public void WriteThenRead_RoundTrips_OwnerAndModeAsKeyring()
    {
        var file = NewFile();

        Store(_home).WriteVaultPassword(file);

        var store = Store(_home);
        Assert.Equal(file.Encode(), store.ReadVaultPasswordBytes());
        var read = store.ReadVaultPassword(_vaultId);
        Assert.NotNull(read);
        Assert.Equal(file.Encode(), read!.Encode());
        Assert.True(read.KeyMatches(_vaultKey));
        Assert.Equal(HomeFile, Path.Combine(store.VaultDir, RecordVaultStore.VaultPasswordFileName));

        if (OperatingSystem.IsWindows())
            return;
        var keyring = BrokerNative.LStat(Path.Combine(_home.VaultDir!, RecordVaultStore.KeyringFileName));
        var vaultPassword = BrokerNative.LStat(HomeFile);
        Assert.NotNull(keyring);
        Assert.NotNull(vaultPassword);
        Assert.Equal(BrokerNative.EntryType.Regular, vaultPassword!.Value.Type);
        Assert.Equal(keyring!.Value.Mode, vaultPassword.Value.Mode);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, vaultPassword.Value.Mode);
        Assert.Equal(keyring.Value.Uid, vaultPassword.Value.Uid);
    }

    [Fact]
    public void UnderSudo_TheWrite_IsDoneAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows())
            return; // no identity switch on Windows
        var fake = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0);
        var store = new RecordVaultStore(_home.Dir, new DirectoryOwnerMatcher(fake));

        store.WriteVaultPassword(NewFile());

        Assert.Contains(Path.GetFullPath(HomeFile), fake.Switches.Select(s => s.Path));
    }

    [Fact]
    public void Read_WrongVault_Refuses()
    {
        Store(_home).WriteVaultPassword(NewFile());
        var otherVaultId = (byte[])_vaultId.Clone();
        otherVaultId[0] ^= 1;

        var ex = Assert.Throws<TswapException>(() => Store(_home).ReadVaultPassword(otherVaultId));
        Assert.Contains("vault id", ex.Message);
    }

    [Theory]
    [InlineData("vault-password (conflicted copy 2026-11-03)")]
    [InlineData("vault-password.sync-conflict-20261103-101010-ABCDEFG")]
    [InlineData("vault-password-laptop")]
    public void ConflictCopy_Different_RefusesWithExactMessage(string copyName)
    {
        Store(_home).WriteVaultPassword(NewFile());
        File.WriteAllBytes(Path.Combine(_home.VaultDir!, copyName), NewFile().Encode());
        var expected = string.Format(ConflictText, $"vault-password, {copyName}");

        var store = Store(_home);
        Assert.Equal(expected, Assert.Throws<TswapException>(() => store.ReadVaultPassword(_vaultId)).Message);
        Assert.Equal(expected, Assert.Throws<TswapException>(() => store.ReadVaultPasswordBytes()).Message);
        var before = FolderBytes(_home.VaultDir!);
        Assert.Equal(expected, Assert.Throws<TswapException>(() => store.WriteVaultPassword(NewFile())).Message);
        Assert.Equal(before, FolderBytes(_home.VaultDir!)); // the refused write changed nothing
    }

    [Fact]
    public void ConflictCopy_Identical_IsRemovedOnNextWrite_CanonicalKept()
    {
        var file = NewFile();
        Store(_home).WriteVaultPassword(file);
        var copy = Path.Combine(_home.VaultDir!, "vault-password.sync-conflict-20261103-101010-ABCDEFG");
        var unrelated = Path.Combine(_home.VaultDir!, "vault-password.bak");
        File.WriteAllBytes(copy, file.Encode());
        File.WriteAllBytes(unrelated, NewFile().Encode());

        // Identical copies are not a conflict...
        Assert.Equal(file.Encode(), Store(_home).ReadVaultPasswordBytes());

        // ...and the next password write deletes the redundant copy only.
        Store(_home).WriteVaultPassword(file);

        Assert.False(File.Exists(copy));
        Assert.True(File.Exists(unrelated)); // not a conflict-copy name: never touched
        Assert.Equal(file.Encode(), File.ReadAllBytes(HomeFile));
    }

    [Fact]
    public void Write_OverADifferentFile_Refuses()
    {
        var first = NewFile();
        Store(_home).WriteVaultPassword(first);

        var ex = Assert.Throws<TswapException>(() => Store(_home).WriteVaultPassword(NewFile()));

        Assert.Contains("already has a different vault-password file", ex.Message);
        Assert.Equal(first.Encode(), File.ReadAllBytes(HomeFile));
    }

    [Fact]
    public void PasswordFreeUnlock_StillWorks_WithAConflictCopyPresent()
    {
        _home.Ok("v1", "ingest", "s");
        File.WriteAllBytes(HomeFile, NewFile().Encode());
        File.WriteAllBytes(Path.Combine(_home.VaultDir!, "vault-password (conflicted copy 2026-11-03)"), NewFile().Encode());

        Assert.Equal("v1", _home.Get("s"));
        _home.Ok("v2", "ingest", "t");
        Assert.Equal("v2", _home.Get("t"));
        Assert.Throws<TswapException>(() => Store(_home).ReadVaultPassword(_vaultId)); // password operations still refuse
    }

    [Fact]
    public void VaultMerge_DifferentVaultPasswordFiles_RefusesAndWritesNothing()
    {
        _home.Ok("base", "ingest", "both");
        var laptopDir = CopyVault(_home, _laptop);
        _laptop.Ok("laptop-only", "ingest", "only-laptop");
        File.WriteAllBytes(HomeFile, NewFile().Encode());
        File.WriteAllBytes(Path.Combine(laptopDir, RecordVaultStore.VaultPasswordFileName), NewFile().Encode());
        var homeBefore = FolderBytes(_home.VaultDir!);
        var laptopBefore = FolderBytes(laptopDir);
        var configBefore = _home.ConfigText;

        var (exit, _, err) = _home.Run("", "vault", "merge", laptopDir);

        Assert.NotEqual(0, exit);
        Assert.Contains("different vault-password files", err);
        Assert.Contains("Nothing was merged", err);
        Assert.Equal(homeBefore, FolderBytes(_home.VaultDir!)); // records folder and both files unchanged
        Assert.Equal(laptopBefore, FolderBytes(laptopDir));
        Assert.Equal(configBefore, _home.ConfigText);
    }

    [Fact]
    public void VaultMerge_OneSideHasIt_CopiesIt()
    {
        var laptopDir = CopyVault(_home, _laptop);
        var file = NewFile();
        File.WriteAllBytes(Path.Combine(laptopDir, RecordVaultStore.VaultPasswordFileName), file.Encode());

        var output = _home.Ok("", "vault", "merge", laptopDir);

        Assert.Equal(file.Encode(), File.ReadAllBytes(HomeFile));
        Assert.Contains("vault-password", output);

        // The same files on both sides: nothing more to do.
        Assert.Contains("Nothing to merge", _home.Ok("", "vault", "merge", laptopDir));
    }

    [Fact]
    public void VaultMerge_OnlyThisSideHasIt_KeepsIt_OtherCopyOnlyRead()
    {
        var laptopDir = CopyVault(_home, _laptop);
        var file = NewFile();
        File.WriteAllBytes(HomeFile, file.Encode());
        var laptopBefore = FolderBytes(laptopDir);

        _home.Ok("", "vault", "merge", laptopDir);

        Assert.Equal(file.Encode(), File.ReadAllBytes(HomeFile));
        Assert.Equal(laptopBefore, FolderBytes(laptopDir));
    }
}
