using TswapCore;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 item 1: <c>tswap broker route|socket add|remove</c> need sudo, write <c>broker.json</c>
/// through T5's file layer (folder owner, 0600, atomic), and what they write loads in <c>serve</c>.
/// </summary>
public class BrokerCommandTests : IDisposable
{
    private readonly FleetMachine _m = new("broker");

    public void Dispose() => _m.Dispose();

    private string BrokerJson => BrokerConfigFile.PathIn(_m.Dir);

    private static readonly string[] AddGithub =
    [
        "broker", "route", "add", "github", "--upstream", "https://github.com/stevedcc", "--auth", "basic",
        "--user", "x-access-token", "--secret", "gh-token", "--path", @"croft\.git/", "--methods", "GET,POST",
    ];

    private static readonly string[] AddLane =
        ["broker", "socket", "add", "lane1", "--uids", "100999,200000-265535", "--routes", "github", "--socket-dir", "/run/tswap-broker"];

    [Fact]
    public void WithoutSudo_ConfigChangesAreRefused_AndNothingIsWritten()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (Windows CI runs elevated)
        if (OperatingSystem.IsWindows())
            return; // broker is Unix only
        _m.Sudo = false;

        foreach (var args in new[] { AddGithub, AddLane, ["broker", "route", "remove", "github"], ["broker", "socket", "remove", "lane1"] })
        {
            var (exit, _, err) = _m.Run("", args);
            Assert.NotEqual(0, exit);
            Assert.Contains("requires", err);
        }
        Assert.False(File.Exists(BrokerJson));
        Assert.Empty(Directory.GetFiles(_m.Dir));
    }

    [Fact]
    public void WithoutSudo_AnExistingFileIsLeftUnchanged()
    {
        if (Environment.IsPrivilegedProcess || OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddGithub);
        var before = File.ReadAllBytes(BrokerJson);
        _m.Sudo = false;

        var (exit, _, err) = _m.Run("", "broker", "route", "add", "other", "--upstream", "https://a.example", "--auth", "bearer", "--secret", "k", "--path", "");

        Assert.NotEqual(0, exit);
        Assert.Contains("requires", err);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    [Fact]
    public void SimulatedSudo_RouteAdd_WritesAsTheFolderOwner_Mode0600_Atomically_AndLoadsInServe()
    {
        if (OperatingSystem.IsWindows())
            return;
        var fake = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0);
        _m.Ownership = new DirectoryOwnerMatcher(fake);
        // An existing broker.json with a second hard link: an atomic write (new file, then rename)
        // leaves the other link's content alone; a write in place would change both.
        _m.Ok("", "broker", "route", "add", "first", "--upstream", "https://a.example", "--auth", "bearer", "--secret", "k", "--path", "");
        var elsewhere = Path.Combine(_m.Dir, "elsewhere.json");
        var ln = System.Diagnostics.Process.Start("ln", [BrokerJson, elsewhere])!;
        ln.WaitForExit();
        Assert.Equal(0, ln.ExitCode);
        var before = File.ReadAllText(elsewhere);
        fake.Switches.Clear();

        _m.Ok("", AddGithub);

        Assert.Contains(fake.Switches, s => s.Path == Path.GetFullPath(BrokerJson) && s.Uid == 1000 && s.Gid == 1001);
        Assert.All(fake.Switches, s => Assert.Equal((1000u, 1001u), (s.Uid, s.Gid)));
        var info = new FileInfo(BrokerJson);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, info.UnixFileMode);
        Assert.Equal(before, File.ReadAllText(elsewhere));
        Assert.DoesNotContain("github", before);
        Assert.Contains("github", File.ReadAllText(BrokerJson));
        Assert.Empty(Directory.GetFiles(_m.Dir, "*.tmp"));

        var policy = BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _m.Dir);
        var route = policy.Routes["github"];
        Assert.Equal(BrokerAuthType.Basic, route.AuthType);
        Assert.Equal("gh-token", route.SecretName);
        Assert.Equal("/stevedcc", route.BasePath);
    }

    [Fact]
    public void Sudo_AddsAndRemoves_RoutesAndSockets()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddGithub);
        _m.Ok("", AddLane);

        var policy = BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _m.Dir);
        Assert.Equal("/run/tswap-broker", policy.SocketDir);
        Assert.True(policy.Sockets["lane1"].AllowsUid(100999));
        Assert.Contains("github", policy.Sockets["lane1"].Routes);

        // A route still allowed on a socket can't be removed.
        var (exit, _, err) = _m.Run("", "broker", "route", "remove", "github");
        Assert.NotEqual(0, exit);
        Assert.Contains("lane1", err);

        _m.Ok("", "broker", "socket", "remove", "lane1");
        _m.Ok("", "broker", "route", "remove", "github");
        policy = BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _m.Dir);
        Assert.Empty(policy.Routes);
        Assert.Empty(policy.Sockets);
    }

    [Fact]
    public void Sudo_InvalidRoute_IsRefused_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows())
            return;
        var (exit, _, err) = _m.Run("", "broker", "route", "add", "plain", "--upstream", "http://a.example", "--auth", "bearer", "--secret", "k", "--path", "");

        Assert.NotEqual(0, exit);
        Assert.Contains("https://", err);
        Assert.False(File.Exists(BrokerJson));
    }

    [Fact]
    public void Sudo_DuplicateRoute_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddGithub);
        var before = File.ReadAllBytes(BrokerJson);

        var (exit, _, err) = _m.Run("", AddGithub);

        Assert.NotEqual(0, exit);
        Assert.Contains("already exists", err);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    [Fact]
    public void ConcurrentEdit_HoldingTheEditLock_IsRefused_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddGithub);
        var before = File.ReadAllBytes(BrokerJson);

        using (BrokerConfigFile.LockForEdit(DirectoryOwnerMatcher.Default, _m.Dir))
        {
            var (exit, _, err) = _m.Run("", "broker", "route", "add", "other", "--upstream", "https://a.example", "--auth", "bearer", "--secret", "k", "--path", "");
            Assert.NotEqual(0, exit);
            Assert.Contains("Another 'tswap broker' change", err);
            Assert.Equal(before, File.ReadAllBytes(BrokerJson));
        }

        _m.Ok("", "broker", "route", "add", "other", "--upstream", "https://a.example", "--auth", "bearer", "--secret", "k", "--path", "");
        Assert.Contains("\"other\"", File.ReadAllText(BrokerJson));
    }

    private string EditLock => Path.Combine(_m.Dir, BrokerConfigFile.EditLockFileName);

    private static readonly string[] AddOther =
        ["broker", "route", "add", "other", "--upstream", "https://a.example", "--auth", "bearer", "--secret", "k", "--path", ""];

    [Fact]
    public void EditLock_ThatCantBeOpened_IsACleanErrorNamingTheFile_NotAConcurrentChange()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(EditLock); // a folder where the lock file should be

        var (exit, _, err) = _m.Run("", AddOther);

        Assert.NotEqual(0, exit);
        Assert.Contains(EditLock, err);
        Assert.DoesNotContain("Another 'tswap broker' change", err);
        Assert.False(File.Exists(BrokerJson));
    }

    [Fact]
    public void EditLock_ThatIsASymlink_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        var target = Path.Combine(_m.Dir, "elsewhere");
        File.WriteAllText(target, "");
        File.CreateSymbolicLink(EditLock, target);

        var (exit, _, err) = _m.Run("", AddOther);

        Assert.NotEqual(0, exit);
        Assert.Contains("not a regular file", err);
        Assert.False(File.Exists(BrokerJson));
    }

    [Fact]
    public void EditLock_IsTightenedTo0600()
    {
        if (OperatingSystem.IsWindows())
            return;
        File.WriteAllText(EditLock, "");
        File.SetUnixFileMode(EditLock, (UnixFileMode)0b110_110_110);

        _m.Ok("", AddOther);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(EditLock));
    }
}
