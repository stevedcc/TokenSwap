using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// T5: run as root (sudo) on a folder owned by another user, tswap does its file work as that
/// folder's owner (<see cref="DirectoryOwnerMatcher"/>), so files come out owned by the vault's
/// user and nothing the user planted (a symlink to a root file) reaches root's rights. The
/// identity switch goes through <see cref="IUnixOwnership"/>; these tests fake it, so no real root
/// is needed. The fake can make a file readable only "as root" (outside an identity switch), which
/// is how the read-side tests tell a read as the user from a read as root.
/// </summary>
public class FileOwnershipTests : IDisposable
{
    private const uint UserUid = 1000;
    private const uint UserGid = 1001;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-owner-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly string _rootsFile = Path.Combine(Path.GetTempPath(), "tswap-roots-" + Guid.NewGuid().ToString("N")[..8]);

    public FileOwnershipTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
        File.Delete(_rootsFile);
    }

    /// <summary>
    /// Fake Unix ownership: who we are, who owns every folder, and every identity switch asked
    /// for. <see cref="RootOnly"/> files are unreadable (mode 0000) while a switch is active, as a
    /// root-owned 0600 file is to the user.
    /// </summary>
    internal sealed class FakeOwnership(bool privileged, uint euid, uint dirUid = UserUid, uint dirGid = UserGid) : IUnixOwnership
    {
        public List<(string Path, uint Uid, uint Gid)> Switches { get; } = [];
        public List<string> RootOnly { get; } = [];
        public bool IsPrivileged => privileged;
        public uint EffectiveUid => euid;
        public bool OwnerUnreadable { get; set; }
        public bool SwitchFails { get; set; }
        public (uint Uid, uint Gid)? GetOwner(string path) => OwnerUnreadable ? null : (dirUid, dirGid);

        public IDisposable ActAs(uint uid, uint gid, string path)
        {
            if (OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException(); // never switched on Windows
            if (SwitchFails)
                throw new TswapException($"Could not switch to uid {uid} for {path}; nothing was done with it.");
            Switches.Add((Path.GetFullPath(path), uid, gid));
            foreach (var file in RootOnly)
                File.SetUnixFileMode(file, UnixFileMode.None);
            return new Restore(RootOnly);
        }

        [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
        private sealed class Restore(List<string> rootOnly) : IDisposable
        {
            public void Dispose()
            {
                foreach (var file in rootOnly)
                    File.SetUnixFileMode(file, OwnerOnly);
            }
        }
    }

    private string P(string name) => Path.GetFullPath(Path.Combine(_dir, name));

    private static Config SampleConfig() => new([], "", DateTime.UtcNow);

    private static FakeOwnership AsRoot() => new(privileged: true, euid: 0);

    /// <summary>A "root-owned" file the user must never read: readable only outside a switch.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private void PlantRootsFile(FakeOwnership fake)
    {
        File.WriteAllText(_rootsFile, "root's secret");
        File.SetUnixFileMode(_rootsFile, OwnerOnly);
        fake.RootOnly.Add(_rootsFile);
    }

    [Fact]
    public void Privileged_IntoAnotherUsersFolder_ConfigSecretsAndBackupAreWrittenAsTheFoldersOwner_Mode0600()
    {
        if (OperatingSystem.IsWindows())
            return; // no identity switch on Windows
        var fake = AsRoot();
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.SaveConfig(SampleConfig());
        storage.SaveSecrets(new SecretsDb([]), RandomNumberGenerator.GetBytes(32));
        var backup = storage.BackupConfig();

        // Write config, write secrets, then the backup: read config, create the backup.
        Assert.Equal(
            [P("config.json"), P("secrets.json.enc"), P("config.json"), Path.GetFullPath(backup)],
            fake.Switches.Select(s => s.Path));
        Assert.All(fake.Switches, s => Assert.Equal((UserUid, UserGid), (s.Uid, s.Gid)));
        foreach (var file in new[] { P("config.json"), P("secrets.json.enc"), backup })
            Assert.Equal(OwnerOnly, File.GetUnixFileMode(file));
    }

    [Fact]
    public void Unprivileged_NoSwitchIsRequested()
    {
        var fake = new FakeOwnership(privileged: false, euid: UserUid + 5);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.SaveConfig(SampleConfig());
        storage.BackupConfig();

        Assert.Empty(fake.Switches);
    }

    [Fact]
    public void Privileged_IntoItsOwnFolder_NoSwitchIsRequested()
    {
        var fake = new FakeOwnership(privileged: true, euid: UserUid);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.SaveConfig(SampleConfig());

        Assert.Empty(fake.Switches);
    }

    [Fact]
    public void SudoCommands_SlotMergeAndApprove_WriteConfigBackupAndTheirFilesAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows())
            return; // no identity switch on Windows
        // The hardware test's bug: 'sudo tswap slot merge' left config.json and its backup root-owned.
        var keys = SimulatedYubiKeyService.WithKeys(11111111);
        keys.PluggedIn = [];
        using var router = new FleetMachine("router", keys) { Tpm = RandomNumberGenerator.GetBytes(32) };
        using var desktop = new FleetMachine("desktop", keys);
        router.Ok("", "init", "--tpm");
        keys.PluggedIn = [11111111];
        desktop.Ok("", "slot", "request", desktop.PathOf("request.json"));

        var fake = AsRoot();
        router.Ownership = new DirectoryOwnerMatcher(fake);
        router.Ok("", "slot", "approve", desktop.PathOf("request.json"), desktop.PathOf("approve.json"));
        var approvePaths = fake.Switches.Select(s => s.Path).ToList();
        Assert.Contains(Path.GetFullPath(router.ConfigPath), approvePaths);            // ApprovedSlots
        Assert.Contains(Path.GetFullPath(desktop.PathOf("approve.json")), approvePaths); // the approve file

        desktop.Ok("", "slot", "accept", desktop.PathOf("approve.json"));
        fake.Switches.Clear();
        router.Ok("", "slot", "merge", desktop.PathOf("approve.json.receipt.json"));

        var mergePaths = fake.Switches.Select(s => s.Path).ToList();
        Assert.Contains(Path.GetFullPath(router.ConfigPath), mergePaths);
        Assert.Contains(Path.GetFullPath(Assert.Single(router.Backups)), mergePaths);
        Assert.All(fake.Switches, s => Assert.Equal((UserUid, UserGid), (s.Uid, s.Gid)));
    }

    [Fact]
    public void Privileged_WriteToASymlink_ReplacesTheLink_AndNeverTouchesItsTarget()
    {
        // MiMo review: 'sudo tswap export ~/x.json' with ~/x.json a link to /etc/shadow must not
        // write through the link.
        if (OperatingSystem.IsWindows())
            return;
        File.WriteAllText(_rootsFile, "root's file");
        var link = P("export.json");
        File.CreateSymbolicLink(link, _rootsFile);
        var fake = AsRoot();
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.WriteFile(link, "{\"export\":1}");

        Assert.Equal("root's file", File.ReadAllText(_rootsFile));
        Assert.Null(new FileInfo(link).LinkTarget);
        Assert.Equal("{\"export\":1}", File.ReadAllText(link));
        Assert.Equal([(link, UserUid, UserGid)], fake.Switches);
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(link));
    }

    [Fact]
    public void Privileged_BackupOfAConfigJsonLinkedToARootFile_IsReadAsTheUser_AndFails()
    {
        // GLM review: the backup read config.json through a planted symlink as root and handed the
        // copy to the folder's owner.
        if (OperatingSystem.IsWindows())
            return;
        var fake = AsRoot();
        PlantRootsFile(fake);
        File.CreateSymbolicLink(P("config.json"), _rootsFile);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        var ex = Assert.Throws<TswapException>(() => storage.BackupConfig());

        Assert.Empty(Directory.GetFiles(_dir, "config.json.bak-*"));
        Assert.DoesNotContain("chown", ex.Message); // never advise chowning through a link
    }

    [Fact]
    public void Privileged_LoadingAConfigJsonLinkedToARootFile_IsReadAsTheUser_AndFails()
    {
        if (OperatingSystem.IsWindows())
            return;
        var fake = AsRoot();
        PlantRootsFile(fake);
        File.CreateSymbolicLink(P("config.json"), _rootsFile);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        var ex = Assert.Throws<TswapException>(() => storage.LoadConfig());

        Assert.Contains(P("config.json"), ex.Message);
        Assert.DoesNotContain("chown", ex.Message);
    }

    [Fact]
    public void Privileged_AConfigJsonLeftRootOwnedByAnEarlierSudoRun_SaysHowToFixIt()
    {
        // GLM re-review: a vault file an earlier release wrote as root (0600) is unreadable as the
        // folder's owner; the user must get the fix, not a bare "access denied".
        if (OperatingSystem.IsWindows())
            return;
        var fake = AsRoot();
        new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid))).SaveConfig(SampleConfig());
        fake.RootOnly.Add(P("config.json"));
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        var ex = Assert.Throws<TswapException>(() => storage.LoadConfig());

        Assert.Contains($"sudo chown -h {UserUid}:{UserGid} '{P("config.json")}'", ex.Message);
    }

    [Fact]
    public void AConfigJsonWithAByteOrderMark_StillLoads()
    {
        // GLM re-review: File.ReadAllText stripped a BOM; the byte read must too.
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid)));
        storage.SaveConfig(SampleConfig() with { YubiKeySerials = [42] });
        File.WriteAllBytes(P("config.json"), [0xEF, 0xBB, 0xBF, .. File.ReadAllBytes(P("config.json"))]);

        Assert.Equal([42], storage.LoadConfig().YubiKeySerials);
    }

    [Fact]
    public void AWriteThatFailsAfterTheTempFileExists_LeavesNoTempFile()
    {
        // The target is a non-empty folder, so the final rename fails after the temp is written.
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid)));
        Directory.CreateDirectory(Path.Combine(P("config.json"), "occupied"));

        var ex = Record.Exception(() => storage.SaveConfig(SampleConfig()));

        Assert.True(ex is IOException or UnauthorizedAccessException, $"{ex}"); // Windows: UnauthorizedAccess

        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public void Privileged_TheFoldersOwnerCannotBeRead_RefusesBeforeWriting()
    {
        // MiMo review: a failed statx used to fall back silently to a root-owned file.
        if (OperatingSystem.IsWindows())
            return;
        var fake = AsRoot();
        fake.OwnerUnreadable = true;
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        var ex = Assert.Throws<TswapException>(() => storage.SaveConfig(SampleConfig()));

        Assert.Contains(_dir, ex.Message);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public void Privileged_TheSwitchFails_TheOldFileIsKept_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows())
            return;
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid)));
        storage.SaveConfig(SampleConfig());
        var before = File.ReadAllText(P("config.json"));
        var fake = AsRoot();
        fake.SwitchFails = true;
        var failing = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        var ex = Assert.Throws<TswapException>(() => failing.SaveConfig(SampleConfig() with { YubiKeySerials = [1] }));

        Assert.Contains("nothing was done", ex.Message);
        Assert.Equal(before, File.ReadAllText(P("config.json")));
        Assert.Equal([P("config.json")], Directory.GetFiles(_dir).Select(Path.GetFullPath));
    }

    [DllImport("libc", EntryPoint = "umask")]
    private static extern uint SetUmask(uint mask);

    [Fact]
    public void NewFilesAndFolders_AreOwnerOnly_EvenUnderUmask0()
    {
        if (OperatingSystem.IsWindows())
            return;
        var old = SetUmask(0);
        try
        {
            var vault = Path.Combine(_dir, "new", "tswap");
            var storage = new Storage(vault, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid)));

            storage.SaveConfig(SampleConfig());
            storage.SaveSecrets(new SecretsDb([]), RandomNumberGenerator.GetBytes(32));
            var backup = storage.BackupConfig();
            storage.WriteFile(Path.Combine(vault, "receipt.json"), "{}");

            Assert.Equal(OwnerOnly | UnixFileMode.UserExecute, File.GetUnixFileMode(vault));
            foreach (var file in new[] { "config.json", "secrets.json.enc", Path.GetFileName(backup), "receipt.json" })
                Assert.Equal(OwnerOnly, File.GetUnixFileMode(Path.Combine(vault, file)));
        }
        finally
        {
            SetUmask(old);
        }
    }

    [Fact]
    public void TheRealUnixCalls_ReadTheOwnerOfAFolderAndOfALinkItself()
    {
        if (OperatingSystem.IsWindows())
            return;

        var real = new UnixOwnership();
        var owner = real.GetOwner(_dir);

        Assert.NotNull(owner);
        Assert.Equal(real.EffectiveUid, owner!.Value.Uid); // this process created the folder
        var link = P("link");
        File.CreateSymbolicLink(link, "/"); // the target is root's; the link itself is ours
        Assert.Equal(owner, real.GetOwner(link));
    }
}
