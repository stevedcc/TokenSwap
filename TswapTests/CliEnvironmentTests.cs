using TswapCli;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Unit tests for config-dir resolution and invocation-prefix detection — logic that
/// previously ran inline at the top of Program.cs with no direct coverage. Environment
/// access is injected as delegates, so each branch is testable without touching real
/// env vars or the filesystem.
/// </summary>
public class CliEnvironmentTests
{
    // A fixed fake ApplicationData dir keeps the non-sudo branch deterministic
    // (no dependency on the real user profile of the machine running the tests).
    private static readonly string FakeAppData = Path.Combine(Path.GetTempPath(), "fake-appdata");

    private static string Resolve(
        Dictionary<string, string?> env,
        Func<string, bool>? directoryExists = null,
        Action<string, string>? moveDirectory = null,
        TextWriter? log = null,
        bool isPrivileged = false,
        Func<string, UnixPasswdEntry?>? lookupUser = null)
        => CliEnvironment.ResolveConfigDir(
            name => env.GetValueOrDefault(name),
            directoryExists ?? (_ => false),
            moveDirectory ?? ((_, _) => { }),
            log ?? TextWriter.Null,
            isPrivileged,
            getApplicationDataDir: () => FakeAppData,
            lookupUser: lookupUser ?? (_ => null));

    // Brief T7 item 1: the passwd seam. alice is uid 1000 with a home outside /home.
    private static Func<string, UnixPasswdEntry?> Passwd(params (string Name, uint Uid, string Home)[] users)
        => name => users.Where(u => u.Name == name).Select(u => new UnixPasswdEntry(u.Uid, u.Home)).FirstOrDefault();

    [Fact]
    public void ConfigDirOverride_WinsOverEverything()
    {
        var dir = Resolve(new() { ["TSWAP_CONFIG_DIR"] = "/custom/dir", ["SUDO_USER"] = "alice" });
        Assert.Equal("/custom/dir", dir);
    }

    [Fact]
    public void SudoUser_ResolvesToInvokingUsersHome()
    {
        if (OperatingSystem.IsWindows()) return; // SUDO_USER handling is Unix-only

        // isPrivileged: true is the input #176 adds (sudo to root, as `sudo tswap get` runs).
        // Brief T7 item 1 (rule change): the home now comes from the passwd entry, checked against
        // SUDO_UID, so the input gains SUDO_UID and a passwd entry with the conventional home.
        var expectedHome = OperatingSystem.IsMacOS() ? "/Users/alice" : "/home/alice";
        var dir = Resolve(new() { ["SUDO_USER"] = "alice", ["SUDO_UID"] = "1000" }, isPrivileged: true,
            lookupUser: Passwd(("alice", 1000, expectedHome)));
        // T7 fix round 1 (MiMo's review): on macOS the user's own folder is under
        // Library/Application Support, so sudo must use that too. The old assertion
        // (<home>/.config/tswap on macOS as well) encoded that pre-existing divergence.
        Assert.Equal(OperatingSystem.IsMacOS()
            ? Path.Combine(expectedHome, "Library", "Application Support", "tswap")
            : Path.Combine(expectedHome, ".config", "tswap"), dir);
    }

    // T7 fix round 1 (MiMo, critical): sudo and the user's own resolution give the same folder, per
    // platform (macOS simulated through the isMacOS seam, so this runs on Linux too).
    [Theory]
    [InlineData(false, "/home/alice", "/home/alice/.config")]
    [InlineData(true, "/Users/alice", "/Users/alice/Library/Application Support")]
    public void PrivilegedAndUnprivileged_ResolveTheSameFolder(bool macOS, string home, string appData)
    {
        if (OperatingSystem.IsWindows()) return;
        var files = new HashSet<string>();

        var own = CliEnvironment.ResolveConfigDir(name => name == "HOME" ? home : null, _ => false, (_, _) => { },
            TextWriter.Null, isPrivileged: false, getApplicationDataDir: () => appData, fileExists: files.Contains, isMacOS: macOS);
        var underSudo = CliEnvironment.ResolveConfigDir(
            name => name switch { "SUDO_USER" => "alice", "SUDO_UID" => "1000", "HOME" => "/root", _ => null },
            _ => false, (_, _) => { }, TextWriter.Null, isPrivileged: true, getApplicationDataDir: () => "/root/.config",
            lookupUser: Passwd(("alice", 1000, home)), fileExists: files.Contains, isMacOS: macOS);

        Assert.Equal(Path.Combine(appData, "tswap"), own);
        Assert.Equal(own, underSudo);
    }

    // Coordinator addition: a macOS vault may still be in the folder sudo used to pick
    // (<home>/.config/tswap, since a300bf8). Never move or pick silently: say what to do.
    private static string ResolveMac(HashSet<string> files, bool privileged)
        => CliEnvironment.ResolveConfigDir(
            name => name switch { "HOME" => privileged ? "/var/root" : "/Users/alice", "SUDO_USER" => privileged ? "alice" : null, "SUDO_UID" => "501", _ => null },
            _ => false, (_, _) => { }, TextWriter.Null, isPrivileged: privileged,
            getApplicationDataDir: () => privileged ? "/var/root/Library/Application Support" : "/Users/alice/Library/Application Support",
            lookupUser: Passwd(("alice", 501, "/Users/alice")), fileExists: files.Contains, isMacOS: true);

    private const string MacLibraryConfig = "/Users/alice/Library/Application Support/tswap/config.json";
    private const string MacLegacyConfig = "/Users/alice/.config/tswap/config.json";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MacOS_VaultOnlyInTheLegacyFolder_StopsNamingBothPathsAndTheFix(bool privileged)
    {
        if (OperatingSystem.IsWindows()) return;
        var files = new HashSet<string> { MacLegacyConfig };

        var ex = Assert.Throws<TswapException>(() => ResolveMac(files, privileged));

        Assert.Contains("/Users/alice/.config/tswap", ex.Message);
        Assert.Contains("/Users/alice/Library/Application Support/tswap", ex.Message);
        Assert.Contains("TSWAP_CONFIG_DIR", ex.Message);
        Assert.Contains("Move", ex.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MacOS_VaultInBothFolders_Refuses_NamingBoth(bool privileged)
    {
        if (OperatingSystem.IsWindows()) return;
        var files = new HashSet<string> { MacLegacyConfig, MacLibraryConfig };

        var ex = Assert.Throws<TswapException>(() => ResolveMac(files, privileged));

        Assert.Contains("/Users/alice/.config/tswap", ex.Message);
        Assert.Contains("/Users/alice/Library/Application Support/tswap", ex.Message);
        Assert.Contains("both", ex.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MacOS_VaultInTheLibraryFolderOnly_IsUsed(bool privileged)
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Equal("/Users/alice/Library/Application Support/tswap", ResolveMac([MacLibraryConfig], privileged));
        Assert.Equal("/Users/alice/Library/Application Support/tswap", ResolveMac([], privileged)); // a fresh account
    }

    [Fact]
    public void Linux_TheLegacyMacFolderIsNotConsulted()
    {
        if (OperatingSystem.IsWindows()) return;
        var files = new HashSet<string> { "/home/alice/.config/tswap/config.json" };

        var dir = CliEnvironment.ResolveConfigDir(name => name == "HOME" ? "/home/alice" : null, _ => false, (_, _) => { },
            TextWriter.Null, isPrivileged: false, getApplicationDataDir: () => "/home/alice/.config", fileExists: files.Contains, isMacOS: false);

        Assert.Equal("/home/alice/.config/tswap", dir);
    }

    // Brief T7 item 1 (#178): the home is the passwd entry's, not /home/<name>.
    [Fact]
    public void SudoUser_HomeOutsideHome_IsTakenFromPasswd()
    {
        if (OperatingSystem.IsWindows()) return;

        var dir = Resolve(new() { ["SUDO_USER"] = "svc", ["SUDO_UID"] = "990" }, isPrivileged: true,
            lookupUser: Passwd(("svc", 990, "/var/lib/svc")));

        Assert.Equal("/var/lib/svc/.config/tswap", dir);
    }

    // Brief T7 item 1 (#107): SUDO_USER is only trusted when SUDO_UID matches its passwd uid.
    [Fact]
    public void SudoUser_UidMismatch_Refuses_NamingBothValues()
    {
        if (OperatingSystem.IsWindows()) return;

        var ex = Assert.Throws<TswapCore.TswapException>(() => Resolve(
            new() { ["SUDO_USER"] = "alice", ["SUDO_UID"] = "1001" }, isPrivileged: true,
            lookupUser: Passwd(("alice", 1000, "/home/alice"))));

        Assert.Contains("1001", ex.Message);
        Assert.Contains("1000", ex.Message);
        Assert.Contains("alice", ex.Message);
    }

    [Fact]
    public void SudoUser_UidMissing_Refuses()
    {
        if (OperatingSystem.IsWindows()) return;

        var ex = Assert.Throws<TswapCore.TswapException>(() => Resolve(
            new() { ["SUDO_USER"] = "alice" }, isPrivileged: true,
            lookupUser: Passwd(("alice", 1000, "/home/alice"))));

        Assert.Contains("SUDO_UID", ex.Message);
        Assert.Contains("not set", ex.Message);
    }

    [Fact]
    public void SudoUser_UidNotNumeric_Refuses()
    {
        if (OperatingSystem.IsWindows()) return;

        var ex = Assert.Throws<TswapCore.TswapException>(() => Resolve(
            new() { ["SUDO_USER"] = "alice", ["SUDO_UID"] = "1000x" }, isPrivileged: true,
            lookupUser: Passwd(("alice", 1000, "/home/alice"))));

        Assert.Contains("SUDO_UID", ex.Message);
        Assert.Contains("1000x", ex.Message);
        Assert.Contains("not a number", ex.Message);
    }

    [Fact]
    public void SudoUser_UnknownUser_Refuses()
    {
        if (OperatingSystem.IsWindows()) return;

        var ex = Assert.Throws<TswapCore.TswapException>(() => Resolve(
            new() { ["SUDO_USER"] = "mallory", ["SUDO_UID"] = "1000" }, isPrivileged: true,
            lookupUser: Passwd(("alice", 1000, "/home/alice"))));

        Assert.Contains("mallory", ex.Message);
        Assert.Contains("no such user", ex.Message);
    }

    // #178: root running `sudo tswap ...` has SUDO_USER=root: root's own folder, not /home/root.
    [Fact]
    public void SudoUser_Root_UsesRootsOwnFolder()
    {
        if (OperatingSystem.IsWindows()) return;

        var looked = false;
        var dir = Resolve(new() { ["SUDO_USER"] = "root", ["SUDO_UID"] = "0" }, isPrivileged: true,
            lookupUser: _ => { looked = true; return new UnixPasswdEntry(0, "/root"); });

        Assert.Equal(Path.Combine(FakeAppData, "tswap"), dir);
        Assert.False(looked);
    }

    [Fact]
    public void SudoUid_Zero_UsesRootsOwnFolder()
    {
        if (OperatingSystem.IsWindows()) return;

        var dir = Resolve(new() { ["SUDO_USER"] = "toor", ["SUDO_UID"] = "0" }, isPrivileged: true,
            lookupUser: Passwd(("toor", 0, "/home/toor")));

        Assert.Equal(Path.Combine(FakeAppData, "tswap"), dir);
    }

    [Fact]
    public void ConfigDirOverride_WinsOverAMismatchedSudoUid()
    {
        var dir = Resolve(new() { ["TSWAP_CONFIG_DIR"] = "/custom/dir", ["SUDO_USER"] = "alice", ["SUDO_UID"] = "1" },
            isPrivileged: true, lookupUser: Passwd(("alice", 1000, "/home/alice")));
        Assert.Equal("/custom/dir", dir);
    }

    // Fix round 1 (MiMo): struct passwd differs on other Unixes; the lookup only reads it on Linux and
    // macOS and elsewhere finds no user (so sudo refuses as "no such user" rather than misread memory).
    [Fact]
    public void UnixPasswd_OnAnUnsupportedPlatform_FindsNoUser()
    {
        Assert.Null(UnixPasswd.Lookup(Environment.UserName, platformSupported: false));
    }

    // Fix round 1 (MiMo): privileged without SUDO_USER (a root service, `su`) uses HOME's folder, not
    // a fixed root folder: with plain `su` the caller's HOME survives, and that folder is used.
    [Theory]
    [InlineData("/root", "/root/.config/tswap")]
    [InlineData("/home/alice", "/home/alice/.config/tswap")]
    public void Privileged_WithoutSudoUser_UsesHomesFolder(string home, string expected)
    {
        if (!OperatingSystem.IsLinux()) return; // the XDG rules (macOS and Windows take .NET's folder)
        Func<string, string?> env = name => name == "HOME" ? home : null;

        var dir = CliEnvironment.ResolveConfigDir(env, _ => false, (_, _) => { }, TextWriter.Null, isPrivileged: true,
            getApplicationDataDir: () => CliEnvironment.ApplicationDataDir(env), lookupUser: _ => throw new InvalidOperationException("no lookup without SUDO_USER"));

        Assert.Equal(expected, dir);
    }

    // The real lookup (no seam): this test process's own user resolves to its uid and an absolute home.
    [Fact]
    public void UnixPasswd_LooksUpTheCurrentUser()
    {
        if (OperatingSystem.IsWindows()) return;

        var entry = UnixPasswd.Lookup(Environment.UserName);

        Assert.NotNull(entry);
        Assert.Equal(new UnixOwnership().EffectiveUid, entry.Uid);
        Assert.True(Path.IsPathRooted(entry.Home), entry.Home);
        Assert.Null(UnixPasswd.Lookup("no-such-user-" + Guid.NewGuid().ToString("N")[..8]));
    }

    // Issue #176: `sudo -u <non-root>` keeps SUDO_USER = the caller; the target user's own
    // vault must win, so SUDO_USER only counts when the process is privileged.
    [Fact]
    public void SudoUser_NotPrivileged_UsesCurrentUsersApplicationData()
    {
        var dir = Resolve(new() { ["SUDO_USER"] = "alice" }, isPrivileged: false);
        Assert.Equal(Path.Combine(FakeAppData, "tswap"), dir);
    }

    [Fact]
    public void Privileged_WithoutSudoUser_UsesApplicationData()
    {
        var dir = Resolve(new(), isPrivileged: true);
        Assert.Equal(Path.Combine(FakeAppData, "tswap"), dir);
    }

    [Fact]
    public void NoSudoUser_UsesApplicationData()
    {
        var dir = Resolve(new());
        Assert.Equal(Path.Combine(FakeAppData, "tswap"), dir);
    }

    [Fact]
    public void LegacyDir_MigratedOnce_WithLogMessage()
    {
        string? movedFrom = null, movedTo = null;
        var log = new StringWriter();
        var legacy = Path.Combine(FakeAppData, "tswap-poc");

        var dir = Resolve(new(),
            directoryExists: path => path == legacy, // legacy exists, new dir doesn't
            moveDirectory: (from, to) => { movedFrom = from; movedTo = to; },
            log: log);

        Assert.Equal(legacy, movedFrom);
        Assert.Equal(dir, movedTo);
        Assert.Contains("Migrated config directory", log.ToString());
    }

    [Fact]
    public void LegacyDir_NotMigrated_WhenNewDirExists()
    {
        var moved = false;
        Resolve(new(), directoryExists: _ => true, moveDirectory: (_, _) => moved = true);
        Assert.False(moved);
    }

    [Fact]
    public void LegacyDir_NotMigrated_WhenOverrideSet()
    {
        var moved = false;
        Resolve(new() { ["TSWAP_CONFIG_DIR"] = "/x" },
            directoryExists: _ => true, moveDirectory: (_, _) => moved = true);
        Assert.False(moved);
    }

    // Issue #175: .NET's GetFolderPath returns "" for a folder that doesn't exist; a config dir
    // built from that is relative to wherever tswap happens to run. Refuse instead.
    [Fact]
    public void EmptyApplicationData_Throws_NamingTheOverride()
    {
        var ex = Assert.Throws<TswapCore.TswapException>(() => CliEnvironment.ResolveConfigDir(
            _ => null, _ => false, (_, _) => { }, TextWriter.Null, isPrivileged: false,
            getApplicationDataDir: () => ""));

        Assert.Contains("TSWAP_CONFIG_DIR", ex.Message);
    }

    // Issue #175, per platform: the folder the binary really uses (DefaultApplicationDataDir,
    // what FromSystem passes) is absolute and in the user's own profile, never relative.
    // Read-only: it resolves a path and creates or writes nothing, so it is safe on a
    // developer's machine (unlike the Linux-only end-to-end test, which runs init).

    [Fact]
    public void DefaultApplicationDataDir_OnMacOS_IsLibraryApplicationSupport()
    {
        if (!OperatingSystem.IsMacOS()) return; // until #181: reported as Passed elsewhere

        // .NET resolves it through the OS (NSApplicationSupportDirectory), which always exists
        // for a real user, so the "fresh user without the folder" case of #175 can't occur here.
        var dir = CliEnvironment.DefaultApplicationDataDir();

        Assert.True(Path.IsPathRooted(dir), $"not absolute: '{dir}'");
        Assert.EndsWith(Path.Combine("Library", "Application Support"), dir.TrimEnd('/'));
    }

    [Fact]
    public void DefaultApplicationDataDir_OnLinux_IsXdgConfigHomeOrHomeDotConfig()
    {
        if (!OperatingSystem.IsLinux()) return; // until #181: reported as Passed elsewhere

        var dir = CliEnvironment.DefaultApplicationDataDir();
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        var expected = !string.IsNullOrEmpty(xdg) && Path.IsPathRooted(xdg)
            ? xdg
            : Path.Combine(Environment.GetEnvironmentVariable("HOME")!, ".config");

        Assert.True(Path.IsPathRooted(dir), $"not absolute: '{dir}'");
        Assert.Equal(expected.TrimEnd('/'), dir.TrimEnd('/'));
    }

    [Fact]
    public void DefaultApplicationDataDir_OnWindows_IsAppData()
    {
        if (!OperatingSystem.IsWindows()) return; // until #181: reported as Passed elsewhere

        var dir = CliEnvironment.DefaultApplicationDataDir();

        Assert.True(Path.IsPathRooted(dir), $"not absolute: '{dir}'");
        Assert.Equal(Environment.GetEnvironmentVariable("APPDATA")!.TrimEnd('\\'), dir.TrimEnd('\\'));
    }

    [Fact]
    public void DetectInvocationPrefix_NullProcessPath_DefaultsToTswap()
    {
        Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix(null));
    }

    [Fact]
    public void DetectInvocationPrefix_UsesFileNameWithoutExtension()
    {
        Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix("/usr/local/bin/tswap"));
        Assert.Equal("ts", CliEnvironment.DetectInvocationPrefix("/home/u/.local/bin/ts"));
        if (OperatingSystem.IsWindows()) // backslash is a separator only on Windows
            Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix(@"C:\tools\tswap.exe"));
        Assert.Equal("tswap", CliEnvironment.DetectInvocationPrefix(
            Path.Combine("some", "dir", OperatingSystem.IsWindows() ? "tswap.exe" : "tswap")));
    }
}
