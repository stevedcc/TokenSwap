using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 8 (decision 10, T5, #194): every file of the record store's vault folder and the
/// config dir goes through <see cref="DirectoryOwnerMatcher"/>: under sudo as the folder's owner
/// (T5's fake identity switch and "root-only" file stand in for root), files created 0600 and
/// folders 0700 whatever the umask, and an existing vault with wider modes is tightened on the next
/// write with one notice, while a read changes nothing. Unix only (every test returns on Windows).
/// </summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
public sealed class RecordStoreFileLayerTests : IDisposable
{
    private const uint UserUid = 1000;
    private const uint UserGid = 1001;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode FolderOwnerOnly = OwnerOnly | UnixFileMode.UserExecute;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _m;
    private readonly string _outside = Path.Combine(Path.GetTempPath(), "tswap-outside-" + Guid.NewGuid().ToString("N")[..8]);

    public RecordStoreFileLayerTests()
    {
        _m = new FleetMachine("filelayer", _keys);
        Directory.CreateDirectory(_outside);
    }

    public void Dispose()
    {
        _m.Dispose();
        if (!Directory.Exists(_outside))
            return;
        if (!OperatingSystem.IsWindows())
            foreach (var file in Directory.GetFiles(_outside))
                File.SetUnixFileMode(file, OwnerOnly);
        Directory.Delete(_outside, true);
    }

    private static FileOwnershipTests.FakeOwnership AsRoot() => new(privileged: true, euid: 0);

    private static string Full(string path) => Path.GetFullPath(path);

    [Fact]
    public void UnderSudo_EveryRecordKeyringBackupAndTempFolderWrite_IsDoneAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows())
            return; // no identity switch on Windows
        _keys.PluggedIn = [SerialA, SerialB];
        _m.Ok("1\n2\n\n", "init");
        _keys.PluggedIn = [SerialA];
        _m.Ok("v", "ingest", "s");
        _keys.PluggedIn = [SerialA, SerialB];
        var fake = AsRoot();
        _m.Ownership = new DirectoryOwnerMatcher(fake);

        // The conversion: temp folder (keyring + records), rename, config backup, secrets backup.
        _m.Ok("1\n", "migrate", "--to-records");
        var paths = fake.Switches.Select(s => s.Path).ToList();
        var tempDirs = paths.Where(p => p.Contains("vault.tmp-")).ToList();
        Assert.Contains(tempDirs, p => p.EndsWith("/keyring"));
        Assert.Contains(tempDirs, p => p.Contains("/records/"));
        Assert.Contains(Full(_m.VaultDir!), paths); // the rename into place
        Assert.Contains(Full(Assert.Single(_m.Backups)), paths);
        Assert.Contains(paths, p => p.StartsWith(Full(_m.SecretsPath) + ".bak-"));

        // A record write, a keyring write (slot add) and its config backup.
        fake.Switches.Clear();
        _keys.PluggedIn = [SerialA];
        _m.Ok("w", "ingest", "t");
        Assert.Contains(paths = fake.Switches.Select(s => s.Path).ToList(), p => p.StartsWith(Full(_m.RecordsDir) + "/") && p.Length > _m.RecordsDir.Length + 60);
        Assert.Contains(Full(_m.ConfigPath), paths); // LastHlc
        Assert.All(fake.Switches, s => Assert.Equal((UserUid, UserGid), (s.Uid, s.Gid)));
    }

    [Fact]
    public void UnderSudo_AKeyringWrite_AndItsConfigBackup_AreDoneAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows())
            return;
        _keys.PluggedIn = [SerialA];
        InitRecordVault(_m);
        var fake = AsRoot();
        _m.Ownership = new DirectoryOwnerMatcher(fake);
        _keys.PluggedIn = [SerialA, SerialB];

        _m.Ok("", "slot", "add", "--yubikey");

        var paths = fake.Switches.Select(s => s.Path).ToList();
        Assert.Contains(Full(Path.Combine(_m.VaultDir!, "keyring")), paths);
        Assert.Contains(Full(Assert.Single(_m.Backups)), paths);
        Assert.All(fake.Switches, s => Assert.Equal((UserUid, UserGid), (s.Uid, s.Gid)));
    }

    [Fact]
    public void APlantedLinkToARootOnlyFile_IsNotReadThrough()
    {
        if (OperatingSystem.IsWindows())
            return;
        _keys.PluggedIn = [SerialA];
        var vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("v1", "ingest", "s");
        var record = RecordFile(_m, vaultKey, "s");
        var rootsFile = Path.Combine(_outside, "shadow");
        File.WriteAllText(rootsFile, "root's secret");
        File.SetUnixFileMode(rootsFile, OwnerOnly);
        File.Delete(record);
        File.CreateSymbolicLink(record, rootsFile);
        var fake = AsRoot();
        fake.RootOnly.Add(rootsFile);
        _m.Ownership = new DirectoryOwnerMatcher(fake);

        var get = _m.Run("", "get", "s");
        var names = _m.Run("", "names");
        var rotate = _m.Run("", "rotate", "s");

        Assert.NotEqual(0, get.Exit);
        Assert.Contains(Path.GetFileName(record), get.Err);
        Assert.DoesNotContain("root's secret", get.Out + get.Err + names.Out + names.Err + rotate.Out + rotate.Err);
        Assert.Contains("unreadable", names.Err);
        Assert.NotEqual(0, rotate.Exit);
        Assert.Equal("root's secret", File.ReadAllText(rootsFile));
        Assert.Equal(rootsFile, new FileInfo(record).LinkTarget);
    }

    [Fact]
    public void APlantedLinkToARecordOutsideTheFolder_IsReplacedByAWrite_NeverWrittenThrough()
    {
        if (OperatingSystem.IsWindows())
            return;
        _keys.PluggedIn = [SerialA];
        var vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("v1", "ingest", "s");
        var record = RecordFile(_m, vaultKey, "s");
        var target = Path.Combine(_outside, Path.GetFileName(record));
        File.Move(record, target);
        File.CreateSymbolicLink(record, target);
        var targetBefore = File.ReadAllBytes(target);
        _m.Ownership = new DirectoryOwnerMatcher(AsRoot());

        _m.Ok("", "burn", "s", "seen");

        Assert.Equal(targetBefore, File.ReadAllBytes(target));
        Assert.Null(new FileInfo(record).LinkTarget);
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(record));
        Assert.Contains("seen", _m.Ok("", "burned"));
    }

    [DllImport("libc", EntryPoint = "umask")]
    private static extern uint SetUmask(uint mask);

    [Fact]
    public void NewFoldersAre0700_AndFiles0600_UnderUmask0()
    {
        if (OperatingSystem.IsWindows())
            return;
        _keys.PluggedIn = [SerialA];
        _m.Ok("", "init", "--keyring");
        _m.Ok("v", "ingest", "s");
        var old = SetUmask(0);
        try
        {
            var vaultDir = Path.Combine(_m.Dir, "deep", "new", "vault");
            _m.Ok("", "migrate", "--to-records", "--vault-dir", vaultDir);
            _m.Ok("w", "ingest", "t");
            _m.Ok("", "burn", "t");

            foreach (var folder in new[] { Path.Combine(_m.Dir, "deep"), Path.Combine(_m.Dir, "deep", "new"), vaultDir, Path.Combine(vaultDir, "records") })
                Assert.Equal(FolderOwnerOnly, File.GetUnixFileMode(folder));
            var files = Directory.GetFiles(vaultDir, "*", SearchOption.AllDirectories)
                .Concat([_m.ConfigPath, Assert.Single(_m.Backups)])
                .Concat(Directory.GetFiles(_m.Dir, "secrets.json.enc.bak-*"));
            Assert.All(files, f => Assert.Equal(OwnerOnly, File.GetUnixFileMode(f)));
        }
        finally
        {
            SetUmask(old);
        }
    }

    [Fact]
    public void AVaultWithWiderModes_IsTightenedOnTheNextWrite_WithOneNotice_AndAReadChangesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        _keys.PluggedIn = [SerialA];
        InitRecordVault(_m);
        _m.Ok("v1", "ingest", "a");
        _m.Ok("v2", "ingest", "b");
        var folders = new[] { _m.Dir, _m.VaultDir!, _m.RecordsDir };
        var files = Directory.GetFiles(_m.VaultDir!, "*", SearchOption.AllDirectories).Append(_m.ConfigPath).ToArray();
        const UnixFileMode wideFolder = FolderOwnerOnly | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
        const UnixFileMode wideFile = OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
        foreach (var folder in folders)
            File.SetUnixFileMode(folder, wideFolder);
        foreach (var file in files)
            File.SetUnixFileMode(file, wideFile);

        var read = _m.Run("", "names");
        Assert.Equal(0, read.Exit);
        Assert.All(folders, f => Assert.Equal(wideFolder, File.GetUnixFileMode(f)));
        Assert.All(files, f => Assert.Equal(wideFile, File.GetUnixFileMode(f)));
        Assert.DoesNotContain("tightened", read.Out + read.Err);

        var write = _m.Run("v3", "ingest", "c");

        Assert.Equal(0, write.Exit);
        Assert.All(folders, f => Assert.Equal(FolderOwnerOnly, File.GetUnixFileMode(f)));
        Assert.All(Directory.GetFiles(_m.VaultDir!, "*", SearchOption.AllDirectories).Append(_m.ConfigPath),
            f => Assert.Equal(OwnerOnly, File.GetUnixFileMode(f)));
        var notices = (write.Out + write.Err).Split('\n').Where(l => l.Contains("tightened", StringComparison.OrdinalIgnoreCase)).ToList();
        var notice = Assert.Single(notices);
        Assert.Contains(_m.RecordsDir, notice);
        Assert.Contains(Path.Combine(_m.VaultDir!, "keyring"), notice);
        Assert.Contains(_m.ConfigPath, notice);
    }
}
