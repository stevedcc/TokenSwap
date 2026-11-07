using System.Security.Cryptography;
using System.Text;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// #253: <c>init</c> never puts the recovery key on a stdout that isn't a terminal. With stdout redirected, every
/// path that makes a recovery slot refuses unless <c>--recovery-key-out &lt;file&gt;</c> names a new file, which then
/// holds the key (and nothing else does); on a terminal the key is printed as before.
/// </summary>
public sealed class InitRecoveryKeyOutTests : IDisposable
{
    private const int Serial = 11111111;

    private const string RefusalText =
        "'tswap init' prints the recovery key, and stdout is not a terminal here (it could end up in a log or an agent's context). " +
        "Write it to a new file with --recovery-key-out <file>, or use --no-recovery.";

    private readonly List<FleetMachine> _machines = [];
    private readonly List<string> _folders = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
        foreach (var folder in _folders.Where(Directory.Exists))
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.Delete(folder, recursive: true);
        }
    }

    private FleetMachine Machine(string name = "rko")
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(Serial))
        {
            Tpm = RandomNumberGenerator.GetBytes(32),
            SecureEnclave = RandomNumberGenerator.GetBytes(32),
            Fido2Keys = new FakeFido2Keys(),
            Terminal = new FakeTerminal(),
        };
        m.Keys.PluggedIn = [Serial];
        _machines.Add(m);
        return m;
    }

    /// <summary>A folder outside every machine's config and vault folder, for the key file.</summary>
    private string Outside()
    {
        var folder = Path.Combine(Path.GetTempPath(), "tswap-rko-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4)));
        Directory.CreateDirectory(folder);
        _folders.Add(folder);
        return folder;
    }

    private static string DefaultVaultDir(FleetMachine m) => Path.Combine(m.Dir, "vault");

    private static void AssertNothingWritten(FleetMachine m)
    {
        Assert.False(File.Exists(m.ConfigPath));
        Assert.False(Directory.Exists(DefaultVaultDir(m)));
    }

    public static TheoryData<string[]> RecoverySlotPaths =>
    [
        ["--yubikey"],
        ["--tpm"],
        ["--secure-enclave", "--with-touch"],
        ["--fido2"],
    ];

    [Theory]
    [MemberData(nameof(RecoverySlotPaths))]
    public void Init_StdoutRedirected_WithoutRecoveryKeyOut_Refused_NothingWritten(string[] slot)
    {
        var m = Machine();
        m.Fido2Keys!.AddKey(33060005, Fido2TestSlots.Aaguid);
        m.Terminal!.Enqueue(FakeFido2Keys.DefaultPin, FakeFido2Keys.DefaultPin);

        var (exit, stdout, stderr) = m.RunWithStdoutRedirected("", ["init", .. slot, "--no-password"]);

        Assert.Equal(1, exit);
        Assert.Contains(RefusalText, stderr);
        Assert.DoesNotContain("Recovery Private Key", stdout);
        AssertNothingWritten(m);
        Assert.Empty(m.Keys.Challenges);
        Assert.Empty(m.Fido2Keys.Calls);
        Assert.Empty(m.Terminal.Reads);
    }

    [Fact]
    public void Init_StdoutRedirected_NoRecovery_Works()
    {
        var m = Machine();

        var (exit, stdout, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains("No recovery slot generated (--no-recovery)", stdout);
        Assert.True(File.Exists(m.ConfigPath));
    }

    [Fact]
    public void RecoveryKeyOut_KeyOnlyInTheFile()
    {
        var m = Machine();
        var keyFile = Path.Combine(Outside(), "recovery-key");

        var (exit, stdout, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--recovery-key-out", keyFile);

        Assert.True(exit == 0, stderr);
        var content = File.ReadAllText(keyFile);
        Assert.EndsWith("\n", content);
        var key = content.TrimEnd('\n');
        Assert.DoesNotContain("\n", key);
        Assert.Equal(32, Convert.FromBase64String(key).Length);
        Assert.DoesNotContain(key, stdout);
        Assert.DoesNotContain(key, stderr);
        var keyBytes = Convert.FromBase64String(key);
        foreach (var file in new[] { m.Dir, m.VaultDir! }.SelectMany(d => Directory.EnumerateFiles(d, "*", SearchOption.AllDirectories)))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.False(Encoding.UTF8.GetString(bytes).Contains(key, StringComparison.Ordinal), $"{file} holds the key");
            Assert.True(bytes.AsSpan().IndexOf(keyBytes) < 0, $"{file} holds the key's bytes");
        }
        Assert.Contains(Path.GetFullPath(keyFile), stdout);
        Assert.Contains("Move it offline now", stdout);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyFile));
    }

    [Fact]
    public void RecoveryKeyOut_FileOpensTheVault()
    {
        var m = Machine();
        var keyFile = Path.Combine(Outside(), "recovery-key");
        m.Keys.PluggedIn = [];
        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--recovery-key-out", keyFile);
        Assert.True(exit == 0, stderr);
        m.Ok("s3cret\ns3cret\n", "add", "db");

        m.Tpm = null; // the TPM is gone: only the file's key opens the vault now
        m.Keys.PluggedIn = [Serial];
        m.Ok(File.ReadAllText(keyFile), "recover", "--yubikey", "--no-password");

        Assert.Equal("s3cret", m.Get("db"));
        Assert.Contains(Serial, m.Keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void RecoveryKeyOut_UnderSudo_FileOwnedByFolderOwner()
    {
        if (OperatingSystem.IsWindows())
            return; // the folder-owner rule is Unix's (sudo)
        var m = Machine();
        var root = new RecordingRoot();
        m.Ownership = new DirectoryOwnerMatcher(root);
        var outside = Outside();
        var keyFile = Path.Combine(outside, "recovery-key");

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--recovery-key-out", keyFile);

        Assert.True(exit == 0, stderr);
        var owner = new UnixOwnership().GetOwner(outside)!.Value;
        Assert.Contains((owner.Uid, owner.Gid, Path.GetFullPath(keyFile)), root.ActedAs);
    }

    [Fact]
    public void RecoveryKeyOut_ExistingFile_Refused_NothingWritten()
    {
        var m = Machine();
        var keyFile = Path.Combine(Outside(), "recovery-key");
        File.WriteAllText(keyFile, "keep me\n");

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--recovery-key-out", keyFile);

        Assert.Equal(1, exit);
        Assert.Contains($"{Path.GetFullPath(keyFile)} already exists; --recovery-key-out never overwrites a file.", stderr);
        Assert.Equal("keep me\n", File.ReadAllText(keyFile));
        AssertNothingWritten(m);
    }

    [Fact]
    public void RecoveryKeyOut_MissingFolder_Refused_NothingWritten()
    {
        var m = Machine();
        var keyFile = Path.Combine(Outside(), "no-such-folder", "recovery-key");

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--recovery-key-out", keyFile);

        Assert.Equal(1, exit);
        Assert.Contains("doesn't exist", stderr);
        Assert.False(File.Exists(keyFile));
        AssertNothingWritten(m);
    }

    [Theory]
    [InlineData("vault folder")]
    [InlineData("config folder")]
    [InlineData("vault folder, other case")]
    public void RecoveryKeyOut_InsideVaultOrConfigFolder_Refused(string where)
    {
        var m = Machine();
        var vaultDir = Path.Combine(Outside(), "shared-vault");
        var keyFile = where switch
        {
            "vault folder" => Path.Combine(vaultDir, "k"),
            "config folder" => Path.Combine(m.Dir, "k"),
            _ => Path.Combine(vaultDir.ToUpperInvariant(), "k"),
        };
        if (where.EndsWith("other case", StringComparison.Ordinal) && !OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS())
            return; // a case-sensitive file system: another case is another folder

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--folder", vaultDir, "--recovery-key-out", keyFile);

        Assert.Equal(1, exit);
        Assert.Contains("is inside the vault or config folder, which may be synced or backed up: write the recovery key somewhere else.", stderr);
        Assert.False(File.Exists(keyFile));
        Assert.False(File.Exists(m.ConfigPath));
        Assert.False(Directory.Exists(vaultDir));
    }

    [Fact]
    public void RecoveryKeyOut_WithNoRecovery_IsUsageError()
    {
        var m = Machine();
        var keyFile = Path.Combine(Outside(), "recovery-key");

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-recovery", "--recovery-key-out", keyFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        Assert.False(File.Exists(keyFile));
        AssertNothingWritten(m);
    }

    [Fact]
    public void RecoveryKeyOut_WithoutAValue_IsUsageError()
    {
        var m = Machine();

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--recovery-key-out");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        AssertNothingWritten(m);
    }

    [Fact]
    public void RecoveryKeyOut_VaultWriteFails_FileDeleted()
    {
        if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            return; // needs a folder this process can't write into: Unix mode bits, and not root (root writes anyway)
        var m = Machine();
        var locked = Path.Combine(Outside(), "locked");
        Directory.CreateDirectory(locked);
        File.SetUnixFileMode(locked, UnixFileMode.UserRead | UnixFileMode.UserExecute); // 0500
        _folders.Add(locked);
        var keyFile = Path.Combine(Outside(), "recovery-key");

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password",
            "--folder", Path.Combine(locked, "vault"), "--recovery-key-out", keyFile);

        Assert.NotEqual(0, exit);
        Assert.False(File.Exists(keyFile), stderr);
    }

    [Fact]
    public void RecoveryKeyOut_WindowsAclIsCurrentUserOnly()
    {
        if (!OperatingSystem.IsWindows())
            return; // Windows only: the file's ACL (Unix: its mode, in RecoveryKeyOut_KeyOnlyInTheFile)
        var m = Machine();
        var keyFile = Path.Combine(Outside(), "recovery-key");

        var (exit, _, stderr) = m.RunWithStdoutRedirected("", "init", "--tpm", "--no-password", "--recovery-key-out", keyFile);

        Assert.True(exit == 0, stderr);
        AssertCurrentUserOnly(keyFile);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void AssertCurrentUserOnly(string path)
    {
        var security = System.IO.FileSystemAclExtensions.GetAccessControl(new FileInfo(path));
        Assert.True(security.AreAccessRulesProtected);
        var user = System.Security.Principal.WindowsIdentity.GetCurrent().User;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>().ToList();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.Equal(System.Security.AccessControl.AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(user, rule.IdentityReference);
        });
    }

    [Fact]
    public void Init_OnTerminal_PrintsKeyAsBefore()
    {
        var m = Machine();

        var (exit, stdout, stderr) = m.RunOnTerminal("", "init", "--tpm", "--no-password");

        Assert.True(exit == 0, stderr);
        var lines = stdout.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var key = lines[lines.IndexOf("Recovery Private Key (base64):") + 1];
        Assert.Equal(32, Convert.FromBase64String(key).Length);
    }

    /// <summary>Plays root (sudo) over folders the test user owns, recording every switch to a folder's owner.</summary>
    private sealed class RecordingRoot : IUnixOwnership
    {
        private readonly UnixOwnership _real = new();
        public List<(uint Uid, uint Gid, string Path)> ActedAs { get; } = [];
        public bool IsPrivileged => true;
        public uint EffectiveUid => 0;
        public (uint Uid, uint Gid)? GetOwner(string path) => _real.GetOwner(path);

        public IDisposable ActAs(uint uid, uint gid, string path)
        {
            ActedAs.Add((uid, gid, path));
            return new Nothing();
        }

        private sealed class Nothing : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
