using System.Text.Json;
using TswapCli.Commands;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T25 (#310): <c>vault move &lt;folder&gt; [--yes]</c> copies this machine's vault folder to a new place, checks
/// the copy, points this machine's config at it, keeps the old folder renamed and checks it once more. No sudo.
/// </summary>
// VaultCommand.MoveSeam is static (commands are registry singletons).
[Collection(StaticSeamCollection.Name)]
public sealed class VaultMoveTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 15, 12, 0, 0, 123, TimeSpan.Zero);
    private const string Stamp = "20261115T120000123Z";

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly string _scratch;

    public VaultMoveTests()
    {
        _m = new FleetMachine("move", _keys) { Time = new FuncTimeProvider(() => T0) };
        _keys.PluggedIn = [SerialA];
        InitRecordVault(_m);
        _m.Ok("alpha-value", "ingest", "alpha");
        _m.Ok("beta-value", "ingest", "beta");
        _scratch = Path.Combine(Path.GetTempPath(), "tswap-move-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_scratch);
    }

    public void Dispose()
    {
        VaultCommand.MoveSeam = null;
        _m.Dispose();
        if (Directory.Exists(_scratch))
            Directory.Delete(_scratch, true);
    }

    private string DefaultFolder => Path.Combine(_m.Dir, "vault");

    private string Target => Path.Combine(_scratch, "sync", "tswap-vault");

    private string MovedName(string folder) => folder + ".moved-" + Stamp;

    /// <summary>Every file and folder under <paramref name="folder"/>, relative: a file's bytes as hex, a folder as "dir".</summary>
    private static SortedDictionary<string, string> Tree(string folder)
    {
        SortedDictionary<string, string> tree = [with(StringComparer.Ordinal)];
        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 };
        foreach (var entry in new DirectoryInfo(folder).EnumerateFileSystemInfos("*", options))
            tree[Path.GetRelativePath(folder, entry.FullName)] = entry is DirectoryInfo ? "dir" : Convert.ToHexString(File.ReadAllBytes(entry.FullName));
        return tree;
    }

    private (byte[] Config, string[] ScratchEntries, SortedDictionary<string, string> Vault, string[] Backups) Before() =>
        (File.ReadAllBytes(_m.ConfigPath), Directory.GetFileSystemEntries(_scratch, "*", SearchOption.AllDirectories), Tree(_m.VaultDir!), _m.Backups);

    /// <summary>A refusal: exit 1, nothing created anywhere, config.json byte for byte unchanged.</summary>
    private void AssertNothingChanged((byte[] Config, string[] ScratchEntries, SortedDictionary<string, string> Vault, string[] Backups) before,
        (int Exit, string Out, string Err) run, string message)
    {
        Assert.Equal(1, run.Exit);
        Assert.Contains(message, run.Err);
        Assert.Equal(before.Config, File.ReadAllBytes(_m.ConfigPath));
        Assert.Equal(before.ScratchEntries, Directory.GetFileSystemEntries(_scratch, "*", SearchOption.AllDirectories));
        Assert.Equal(before.Vault, Tree(_m.VaultDir!));
        Assert.Equal(before.Backups, _m.Backups);
        Assert.Empty(Directory.GetDirectories(Path.GetDirectoryName(_m.VaultDir!)!, Path.GetFileName(_m.VaultDir!) + ".moved-*"));
    }

    // ------------------------------------------------------------------ the move

    [Fact]
    public void Move_DefaultFolder_ThenNamesAndRunWork()
    {
        File.Copy(Path.Combine(DefaultFolder, "keyring"), Path.Combine(DefaultFolder, "keyring (conflicted copy 2026-11-15)"));
        var source = Tree(DefaultFolder);
        Assert.Contains("records", source.Keys);

        var (exit, stdout, stderr) = _m.Run("", "vault", "move", Target);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(Path.GetFullPath(Target), _m.Config.VaultDir);
        using (var config = JsonDocument.Parse(_m.ConfigText))
            Assert.False(config.RootElement.TryGetProperty("Keyring", out _), "config.json carries a Keyring field");
        Assert.Equal(source, Tree(Target)); // exactly the source's files and folders, the conflicted copy included
        Assert.False(Directory.Exists(DefaultFolder));
        Assert.True(Directory.Exists(MovedName(DefaultFolder)));
        Assert.Equal([MovedName(DefaultFolder)], Directory.GetDirectories(_m.Dir, "vault*"));

        Assert.Contains($"The old folder is kept as {MovedName(DefaultFolder)}: delete it when you're happy that the moved vault " +
                        "works ('tswap names', a 'tswap run').", stdout);
        Assert.Contains("Share only the new folder with a sync tool, never the config folder.", stdout);
        Assert.Contains("If 'tswap broker serve' runs on this machine, restart it: it keeps serving, but its template sandbox " +
                        "protects the folders it saw at startup.", stdout);
        Assert.Contains($"If a sync tool syncs {DefaultFolder}, this rename reaches every machine.", stdout);
        KeyMaterial.AssertNone(stdout);
        KeyMaterial.AssertNone(stderr);
        Assert.DoesNotContain("alpha-value", stdout + stderr);

        var names = _m.Ok("", "names");
        Assert.Contains("alpha", names);
        Assert.Contains("beta", names);
        Assert.Equal("alpha-value", _m.Get("alpha"));
        if (OperatingSystem.IsWindows())
            return; // run's child is a POSIX sh script
        var script = Path.Combine(_scratch, "check.sh");
        File.WriteAllText(script, "[ \"$1\" = alpha-value ] && exit 7\nexit 1\n");
        Assert.Equal(7, _m.Run("", "run", "sh", script, "{{alpha}}").Exit);
    }

    [Fact]
    public void Move_OldFolderKept_Renamed()
    {
        var source = Tree(DefaultFolder);

        _m.Ok("", "vault", "move", Target);

        Assert.Equal(source, Tree(MovedName(DefaultFolder)));
    }

    [Fact]
    public void Move_ConfigBackedUp()
    {
        var before = File.ReadAllBytes(_m.ConfigPath);

        var stdout = _m.Ok("", "vault", "move", Target);

        var backup = Assert.Single(_m.Backups);
        Assert.Equal(Path.Combine(_m.Dir, "config.json.bak-" + Stamp), backup);
        Assert.Equal(before, File.ReadAllBytes(backup));
        Assert.Contains($"Previous config backed up to: {backup}", stdout);
    }

    [Fact]
    public void Move_IntoAnExistingEmptyFolder_Works()
    {
        Directory.CreateDirectory(Target);
        var source = Tree(DefaultFolder);

        _m.Ok("", "vault", "move", Target);

        Assert.Equal(source, Tree(Target));
        Assert.Equal(Path.GetFullPath(Target), _m.Config.VaultDir);
    }

    [Fact]
    public void Move_AlreadyMoved_SaysSo()
    {
        _m.Ok("", "vault", "move", Target);
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Target), $"The vault is already in {Path.GetFullPath(Target)}.");
    }

    // ------------------------------------------------------------------ refusals before anything is written

    [Fact]
    public void Move_ClassicVault_RefusedWithTheStandardMessage()
    {
        using var classic = new FleetMachine("move-classic", SimulatedYubiKeyService.WithKeys(SerialA, SerialB));
        ClassicVaultTestSupport.CreateXorVault(classic);
        var before = File.ReadAllBytes(classic.ConfigPath);
        var target = Path.Combine(_scratch, "classic-target");

        var (exit, _, stderr) = classic.Run("", "vault", "move", target);

        Assert.Equal(1, exit);
        Assert.Contains("This is a classic single-file vault (secrets.json.enc), which tswap 0.2 only migrates.", stderr);
        Assert.Equal(before, File.ReadAllBytes(classic.ConfigPath));
        Assert.False(Directory.Exists(target));
    }

    [Fact]
    public void Move_NotInitialized_SaysSo()
    {
        using var empty = new FleetMachine("move-empty", _keys);
        var target = Path.Combine(_scratch, "empty-target");

        var (exit, _, stderr) = empty.Run("", "vault", "move", target);

        Assert.Equal(1, exit);
        Assert.Contains("Not initialized. Run: tswap init", stderr);
        Assert.False(Directory.Exists(target));
        Assert.False(File.Exists(empty.ConfigPath));
    }

    [Fact]
    public void Move_Privileged_RefusedOnUnix_AllowedOnWindows()
    {
        var before = Before();
        _m.Ownership = new DirectoryOwnerMatcher(new FakeRoot());

        var run = _m.Run("", "vault", "move", Target);

        if (OperatingSystem.IsWindows())
        {
            // An elevated prompt is allowed: the root-owned-copy trap is a Unix one.
            Assert.True(run.Exit == 0, run.Err);
            Assert.Equal(Path.GetFullPath(Target), _m.Config.VaultDir);
            return;
        }
        AssertNothingChanged(before, run,
            "Run 'tswap vault move' as yourself, without sudo: it only moves this machine's encrypted files and its own config.");
    }

    [Fact]
    public void Move_VaultFolderIsASymlink_Refused_NamingTheRealFolder()
    {
        var real = Path.Combine(_scratch, "real-vault");
        Directory.Move(DefaultFolder, real);
        Directory.CreateSymbolicLink(DefaultFolder, real);
        var before = Before();

        var run = _m.Run("", "vault", "move", Target);

        AssertNothingChanged(before, run, $"The vault folder {DefaultFolder} is a symlink to {RealPath(real)}.");
        Assert.True(new DirectoryInfo(DefaultFolder).LinkTarget is not null);
    }

    [Fact]
    public void Move_TargetIsASymlinkToAnEmptyFolder_Refused()
    {
        var empty = Path.Combine(_scratch, "empty");
        Directory.CreateDirectory(empty);
        var link = Path.Combine(_scratch, "link");
        Directory.CreateSymbolicLink(link, empty);
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", link), $"{link} is a symlink.");
        Assert.Empty(Directory.GetFileSystemEntries(empty));
    }

    [Fact]
    public void Move_TargetIsTheVaultFolder_SaysAlreadyThere()
    {
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", DefaultFolder + Path.DirectorySeparatorChar), $"The vault is already in {DefaultFolder}.");
    }

    [Fact]
    public void Move_TargetNotEmpty_Refused()
    {
        Directory.CreateDirectory(Target);
        File.WriteAllText(Path.Combine(Target, "something"), "x");
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Target),
            $"The new vault folder {Path.GetFullPath(Target)} is not empty. Give a folder that doesn't exist yet or is empty.");
    }

    [Fact]
    public void Move_TargetIsAFile_Refused()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Target)!);
        File.WriteAllText(Target, "x");
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Target),
            $"The new vault folder {Path.GetFullPath(Target)} is not empty. Give a folder that doesn't exist yet or is empty.");
    }

    [Fact]
    public void Move_TargetInsideTheVaultFolder_Refused()
    {
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Path.Combine(DefaultFolder, "inner")),
            "The new vault folder can't be inside the vault folder");
    }

    [Fact]
    public void Move_TargetIsTheConfigFolder_Refused()
    {
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", _m.Dir),
            "The new vault folder can't be the config folder or inside it");
    }

    [Fact]
    public void Move_TargetInsideTheConfigFolder_Refused()
    {
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Path.Combine(_m.Dir, "shared-vault")),
            "The new vault folder can't be the config folder or inside it");
    }

    // ------------------------------------------------------------------ a folder that isn't the default

    private const string NotDefaultMessage =
        "Moving it changes only this machine's config: other machines keep pointing at the old place, and renaming a folder " +
        "a sync tool shares renames it on every machine. Nothing was moved; pass --yes to move it anyway.";

    private string MoveToSharedFolderFirst()
    {
        var shared = Path.Combine(_scratch, "first");
        _m.Ok("", "vault", "move", shared);
        return Path.GetFullPath(shared);
    }

    [Fact]
    public void Move_NotTheDefaultFolder_WithoutYes_Refused()
    {
        var shared = MoveToSharedFolderFirst();
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Target),
            $"The vault folder {shared} is not this machine's default ({DefaultFolder}). " + NotDefaultMessage);
    }

    [Fact]
    public void Move_NotTheDefaultFolder_WithYes_Works()
    {
        var shared = MoveToSharedFolderFirst();
        var source = Tree(shared);

        var (exit, stdout, stderr) = _m.Run("", "vault", "move", Target, "--yes");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(Path.GetFullPath(Target), _m.Config.VaultDir);
        Assert.Equal(source, Tree(Target));
        Assert.Equal(source, Tree(MovedName(shared)));
        Assert.False(Directory.Exists(shared));
        Assert.DoesNotContain("If a sync tool syncs", stdout); // the default folder's line only
        Assert.Equal("beta-value", _m.Get("beta"));
    }

    // ------------------------------------------------------------------ failures

    [Fact]
    public void Move_SymlinkInsideTheVaultFolder_Refused()
    {
        var elsewhere = Path.Combine(_scratch, "elsewhere.txt");
        File.WriteAllText(elsewhere, "x");
        File.CreateSymbolicLink(Path.Combine(DefaultFolder, "a-link"), elsewhere);
        var before = Before();

        AssertNothingChanged(before, _m.Run("", "vault", "move", Target), "a-link is a symlink");
        Assert.False(Directory.Exists(Target));
    }

    [Fact]
    public void Move_VerifyFails_TargetRemoved_ConfigUnchanged()
    {
        VaultCommand.MoveSeam = (point, path) =>
        {
            if (point != VaultCommand.MoveSeamPoint.FileCopied || Path.GetFileName(path) != "keyring")
                return;
            // One byte of the first slot's public key flipped (after the 22-byte header and the 16-byte slot id): the
            // copy still decodes as this vault's keyring, so only the byte comparison can catch it.
            var bytes = File.ReadAllBytes(path);
            bytes[22 + 16 + 5] ^= 0x01;
            File.WriteAllBytes(path, bytes);
        };
        var before = Before();

        var run = _m.Run("", "vault", "move", Target);

        AssertNothingChanged(before, run, "Step 3 (checking the copy) failed at keyring: the copy differs from the original.");
        Assert.False(Directory.Exists(Path.GetDirectoryName(Target))); // the parent this command made is gone too
        KeyMaterial.AssertNone(run.Err);
    }

    [Fact]
    public void Move_ConfigWriteFails_TargetRemoved_ConfigUnchanged_BackupKept()
    {
        VaultCommand.MoveSeam = (point, _) =>
        {
            if (point == VaultCommand.MoveSeamPoint.ConfigBackedUp)
                throw new IOException("disk full");
        };
        var config = File.ReadAllBytes(_m.ConfigPath);
        var vault = Tree(DefaultFolder);

        var (exit, _, stderr) = _m.Run("", "vault", "move", Target);

        Assert.Equal(1, exit);
        var backup = Assert.Single(_m.Backups);
        Assert.Equal(config, File.ReadAllBytes(backup));
        Assert.Contains($"Step 4 (switching this machine's config) failed: disk full. config.json is unchanged; its backup {backup} stays.", stderr);
        Assert.Equal(config, File.ReadAllBytes(_m.ConfigPath));
        Assert.False(Directory.Exists(Target));
        Assert.Equal(vault, Tree(DefaultFolder));
        Assert.False(Directory.Exists(MovedName(DefaultFolder)));
    }

    [Fact]
    public void Move_RenameOfOldFails_ConfigPointsAtNew_Warns()
    {
        Directory.CreateDirectory(MovedName(DefaultFolder));
        var source = Tree(DefaultFolder);

        var (exit, stdout, stderr) = _m.Run("", "vault", "move", Target);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(Path.GetFullPath(Target), _m.Config.VaultDir);
        Assert.Equal(source, Tree(Target));
        Assert.Equal(source, Tree(DefaultFolder)); // left in place
        Assert.Empty(Directory.GetFileSystemEntries(MovedName(DefaultFolder))); // never overwritten
        Assert.Contains($"Warning: could not rename the old vault folder {DefaultFolder} to {MovedName(DefaultFolder)}", stderr);
        Assert.Contains($"The move has happened: this machine now uses {Path.GetFullPath(Target)}. Check the old folder, then rename or delete it by hand.", stderr);
        Assert.DoesNotContain("delete it when you're happy", stdout);
        Assert.Equal("alpha-value", _m.Get("alpha"));
    }

    [Fact]
    public void Move_OldFolderChangedAfterVerify_WarnsAndNamesIt()
    {
        VaultCommand.MoveSeam = (point, path) =>
        {
            if (point == VaultCommand.MoveSeamPoint.Verified)
                File.WriteAllText(Path.Combine(path, "late-file"), "written by a sync tool");
        };

        var (exit, stdout, stderr) = _m.Run("", "vault", "move", Target);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(Path.GetFullPath(Target), _m.Config.VaultDir);
        Assert.True(File.Exists(Path.Combine(MovedName(DefaultFolder), "late-file")));
        Assert.Contains("The old folder changed after the copy was checked; these differ from the new folder: late-file", stdout);
        Assert.Contains($"Fold it back with 'sudo tswap vault merge {MovedName(DefaultFolder)}' before you delete it.", stdout);
        Assert.DoesNotContain("delete it when you're happy", stdout);
    }

    [Fact]
    public void Move_Usage()
    {
        foreach (var args in new[] { new[] { "vault", "move" }, ["vault", "move", "--yes"], ["vault", "move", "a", "b"], ["vault", "move", "a", "--yes", "--yes"] })
        {
            var (exit, _, stderr) = _m.Run("", args);
            Assert.Equal(1, exit);
            Assert.Contains("Usage: tswap vault move <new-folder> [--yes]", stderr);
        }
    }

    private static string RealPath(string path) =>
        OperatingSystem.IsWindows() ? Path.GetFullPath(path) : TswapCore.Broker.BrokerNative.RealPath(path)!;

    /// <summary>Root as the file layer sees it (<see cref="IUnixOwnership.IsPrivileged"/>), with no real identity switch.</summary>
    private sealed class FakeRoot : IUnixOwnership
    {
        private readonly UnixOwnership _real = new();
        public bool IsPrivileged => true;
        public uint EffectiveUid => 0;
        public (uint Uid, uint Gid)? GetOwner(string path) => _real.GetOwner(path);
        public IDisposable ActAs(uint uid, uint gid, string path) => new Nothing();

        private sealed class Nothing : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
