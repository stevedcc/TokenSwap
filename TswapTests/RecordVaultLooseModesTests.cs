using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T36 (#347): a Windows peer in a Syncthing folder reports every file as 0644, and Syncthing on Linux applies
/// it to the keyring and records. A command that opens a record vault, a read included, narrows its vault folder
/// (folders 0700, files 0600) with one notice, before the keyring is read; the config folder and <c>config.json</c>
/// stay for the first write, a sudo run narrows nothing at open, another user's file is never changed, and a mode
/// the file system keeps is a warning, not a notice. "Loosen" sets 0644 / 0755, as Syncthing did.
/// </summary>
[UnsupportedOSPlatform("windows")]
public sealed class RecordVaultLooseModesTests : IDisposable
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode FolderOwnerOnly = OwnerOnly | UnixFileMode.UserExecute;
    private const UnixFileMode LooseFile = OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
    private const UnixFileMode LooseFolder = FolderOwnerOnly | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                             | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
    private const string SyncSentence = "A sync tool may have loosened them (see 'Sync transports' in docs/multi-machine.md).";

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _m;
    private readonly List<string> _extraDirs = [];

    public RecordVaultLooseModesTests()
    {
        _m = new FleetMachine("loosemodes", _keys);
        _keys.PluggedIn = [SerialA];
    }

    public void Dispose()
    {
        _m.Dispose();
        foreach (var dir in _extraDirs.Where(Directory.Exists))
            Directory.Delete(dir, true);
    }

    private void InitWithTwoSecrets()
    {
        InitRecordVault(_m);
        _m.Ok("v1", "ingest", "a");
        _m.Ok("v2", "ingest", "b");
    }

    private string Keyring => Path.Combine(_m.VaultDir!, RecordVaultStore.KeyringFileName);
    private string Marker => Path.Combine(_m.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName);

    private static void Loosen(string path) =>
        File.SetUnixFileMode(path, Directory.Exists(path) ? LooseFolder : LooseFile);

    private static UnixFileMode Mode(string path) => File.GetUnixFileMode(path);

    private static List<string> Notices(string stderr) =>
        stderr.ReplaceLineEndings("\n").Split('\n').Where(l => l.StartsWith("Notice: tightened permissions", StringComparison.Ordinal)).ToList();

    /// <summary>The paths a notice names, exactly (one path is never a prefix match for another).</summary>
    private static string[] Named(string notice)
    {
        var list = notice[(notice.IndexOf(" on: ", StringComparison.Ordinal) + 5)..notice.IndexOf(". A sync tool", StringComparison.Ordinal)];
        return list.Split(", ");
    }

    private static (uint Uid, uint Gid) RealOwner(string path) => new UnixOwnership().GetOwner(path)!.Value;

    [UnixFact]
    public void Names_NarrowsASyncLoosenedKeyringAndRecord_WithOneNotice()
    {
        InitWithTwoSecrets();
        var record = Path.Combine(_m.RecordsDir, _m.RecordFiles[0]);
        var untouched = Path.Combine(_m.RecordsDir, _m.RecordFiles[1]);
        string[] loosened = [Keyring, Marker, record, _m.RecordsDir, Path.GetFullPath(_m.VaultDir!)];
        foreach (var path in loosened)
            Loosen(path);

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        var names = stdout.ReplaceLineEndings("\n").Split('\n').Select(l => l.Split(' ')[0]).ToList();
        Assert.Contains("a", names);
        Assert.Contains("b", names);
        foreach (var path in loosened)
            Assert.Equal(Directory.Exists(path) ? FolderOwnerOnly : OwnerOnly, Mode(path));
        var notice = Assert.Single(Notices(stderr));
        Assert.EndsWith(SyncSentence, notice);
        var named = Named(notice);
        Assert.All(loosened, path => Assert.Contains(path, named));
        Assert.DoesNotContain(untouched, named);
        Assert.DoesNotContain("config.json", notice);
    }

    [UnixFact]
    public void Slots_NarrowsBeforeAnyUnlock()
    {
        InitWithTwoSecrets();
        Loosen(Keyring);
        _keys.PluggedIn = [];

        var (exit, _, stderr) = _m.Run("", "slots");

        Assert.Equal(0, exit);
        Assert.Equal(OwnerOnly, Mode(Keyring));
        Assert.Contains(Keyring, Named(Assert.Single(Notices(stderr))));
    }

    [UnixFact]
    public void Slots_NarrowsALoosenedVaultPasswordFile()
    {
        using var m = new FleetMachine("loose-password") { Tpm = RandomNumberGenerator.GetBytes(32) };
        const string password = "correct horse battery staple";
        var (initExit, _, initErr) = m.Run(password + "\n" + password + "\n", "init", "--tpm", "--password", "--no-recovery");
        Assert.True(initExit == 0, initErr);
        var vaultPassword = Path.Combine(m.VaultDir!, RecordVaultStore.VaultPasswordFileName);
        Loosen(vaultPassword);

        var (exit, _, stderr) = m.Run("", "slots");

        Assert.Equal(0, exit);
        Assert.Equal(OwnerOnly, Mode(vaultPassword));
        Assert.Contains(vaultPassword, Named(Assert.Single(Notices(stderr))));
    }

    [UnixFact]
    public void SecondCommand_NoNotice()
    {
        InitWithTwoSecrets();
        Loosen(Keyring);

        var first = _m.Run("", "names");
        var second = _m.Run("", "names");

        Assert.Single(Notices(first.Err));
        Assert.DoesNotContain("tightened", second.Out + second.Err);
    }

    [UnixFact]
    public void AlreadyTight_NoNotice_NoChange()
    {
        InitWithTwoSecrets();
        var paths = Directory.GetFileSystemEntries(_m.VaultDir!, "*", SearchOption.AllDirectories).Append(_m.VaultDir!).ToList();
        var before = paths.ToDictionary(p => p, Mode);

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.DoesNotContain("tightened", stdout + stderr);
        Assert.DoesNotContain("could not narrow", stdout + stderr);
        Assert.All(paths, p => Assert.Equal(before[p], Mode(p)));
    }

    [UnixFact]
    public void ConfigFolderStaysForTheFirstWrite()
    {
        InitWithTwoSecrets();
        Loosen(_m.ConfigPath);
        Loosen(Keyring);

        var read = _m.Run("", "names");

        Assert.Equal(0, read.Exit);
        Assert.Equal(OwnerOnly, Mode(Keyring));
        Assert.Equal(LooseFile, Mode(_m.ConfigPath));
        var readNotice = Assert.Single(Notices(read.Err));
        Assert.DoesNotContain(_m.ConfigPath, Named(readNotice));

        var write = _m.Run("v3", "ingest", "c");

        Assert.Equal(0, write.Exit);
        Assert.Equal(OwnerOnly, Mode(_m.ConfigPath));
        var writeNotice = Assert.Single(Notices(write.Err));
        Assert.Contains(_m.ConfigPath, writeNotice);
        Assert.DoesNotContain(Keyring, writeNotice);
    }

    [UnixFact]
    public void VaultFolderIsTheConfigFolder_OpenLeavesConfigJson()
    {
        InitRecordVault(_m, _m.Dir);
        Assert.Equal(Path.GetFullPath(_m.Dir), Path.GetFullPath(_m.VaultDir!));
        Loosen(_m.ConfigPath);
        Loosen(Keyring);

        var (exit, _, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.Equal(OwnerOnly, Mode(Keyring));
        Assert.Equal(LooseFile, Mode(_m.ConfigPath));
        Assert.DoesNotContain(_m.ConfigPath, Named(Assert.Single(Notices(stderr))));
    }

    [UnixFact]
    public void AFileOfAnotherUser_IsLeftAsItIs_WithAWarning()
    {
        InitWithTwoSecrets();
        var record = Path.Combine(_m.RecordsDir, _m.RecordFiles[0]);
        Loosen(Keyring);
        Loosen(record);
        var (uid, gid) = RealOwner(_m.Dir);
        var fake = new FileOwnershipTests.FakeOwnership(privileged: false, euid: uid, dirUid: uid, dirGid: gid);
        fake.Owners[Path.GetFullPath(Keyring)] = (uid + 7, gid);
        var w = new StringWriter();

        new RecordVaultStore(_m.Dir, new DirectoryOwnerMatcher(fake), warnings: w).LoadConfig();

        Assert.Equal(LooseFile, Mode(Keyring));
        Assert.Equal(OwnerOnly, Mode(record));
        Assert.Contains(RecordVaultStore.OwnedByAnotherWarning(Keyring), w.ToString());
        var notice = Assert.Single(Notices(w.ToString()));
        Assert.Contains(record, Named(notice));
        Assert.DoesNotContain(Keyring, Named(notice));
    }

    private sealed class KeepsModeOf(string keptPath, UnixFileMode kept) : IUnixFileModes
    {
        public UnixFileMode? GetMode(string path) =>
            Path.GetFullPath(path) == Path.GetFullPath(keptPath) ? kept : File.GetUnixFileMode(path);
    }

    [UnixFact]
    public void AModeTheFileSystemKeeps_IsAWarning_NotANotice()
    {
        InitWithTwoSecrets();
        Loosen(Keyring);
        var (uid, gid) = RealOwner(_m.Dir);
        var fake = new FileOwnershipTests.FakeOwnership(privileged: false, euid: uid, dirUid: uid, dirGid: gid);
        var w = new StringWriter();

        new RecordVaultStore(_m.Dir, new DirectoryOwnerMatcher(fake, modes: new KeepsModeOf(Keyring, LooseFile)), warnings: w).LoadConfig();

        Assert.Contains($"Warning: could not narrow the permissions of {Keyring} (the file system kept mode 0644).", w.ToString());
        Assert.DoesNotContain(Notices(w.ToString()), n => Named(n).Contains(Keyring));
    }

    [UnixFact]
    public void Privileged_Open_ChangesNothing_TheWriteNarrows()
    {
        InitWithTwoSecrets();
        Loosen(Keyring);
        var fake = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0);
        var w = new StringWriter();
        var store = new RecordVaultStore(_m.Dir, new DirectoryOwnerMatcher(fake), warnings: w);

        var config = store.LoadConfig();

        Assert.Equal(LooseFile, Mode(Keyring));
        Assert.DoesNotContain("tightened", w.ToString());

        fake.Switches.Clear();
        store.SaveConfig(config);

        Assert.Equal(OwnerOnly, Mode(Keyring));
        Assert.Contains(fake.Switches, s => s.Path == Path.GetFullPath(Keyring));
        Assert.All(fake.Switches, s => Assert.Equal((1000u, 1001u), (s.Uid, s.Gid)));
    }

    [UnixFact]
    public void DetachedStore_NeverNarrowed()
    {
        InitWithTwoSecrets();
        var copy = Path.Combine(Path.GetTempPath(), "tswap-loose-copy-" + Guid.NewGuid().ToString("N")[..8]);
        _extraDirs.Add(copy);
        CopyFolder(_m.VaultDir!, copy);
        var copiedKeyring = Path.Combine(copy, RecordVaultStore.KeyringFileName);
        Loosen(copiedKeyring);

        RecordVaultStore.ForFolder(copy, _m.Config).LoadConfig();

        Assert.Equal(LooseFile, Mode(copiedKeyring));
    }
}
