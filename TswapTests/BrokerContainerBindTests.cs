using System.Text;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>Brief I224 task 4: deriving a container's unit from a process's cgroup (<c>socket bind --pid</c>).</summary>
public class BrokerContainerDeriveTests
{
    private const string Fedora =
        "/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_0123abcd.slice/libpod-4567ef.scope/container";

    [Fact]
    public void PlainPodman_GivesTheContainersScope_WithThePerInstanceWarning()
    {
        var d = BrokerContainerUnit.Derive(Fedora);
        Assert.Equal("/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_0123abcd.slice/libpod-4567ef.scope", d.Unit);
        Assert.Null(d.Refusal);
        Assert.True(d.PerInstance);
    }

    [Fact]
    public void PlainPodmanWithoutAPod_IsPerInstanceToo()
    {
        var d = BrokerContainerUnit.Derive("/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-4567ef.scope/container");
        Assert.Equal("/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-4567ef.scope", d.Unit);
        Assert.True(d.PerInstance);
    }

    [Fact]
    public void AUserQuadlet_GivesItsService_WithoutAWarning()
    {
        var d = BrokerContainerUnit.Derive("/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service/libpod-payload-x");
        Assert.Equal("/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service", d.Unit);
        Assert.Null(d.Refusal);
        Assert.False(d.PerInstance);
    }

    [Fact]
    public void ASystemQuadlet_GivesItsService()
    {
        var d = BrokerContainerUnit.Derive("/system.slice/lane1.service/libpod-payload-x");
        Assert.Equal("/system.slice/lane1.service", d.Unit);
        Assert.False(d.PerInstance);
    }

    [Fact]
    public void TheUserManagersInitScope_IsRefused()
    {
        var d = BrokerContainerUnit.Derive("/user.slice/user-1001.slice/user@1001.service/init.scope");
        Assert.Null(d.Unit);
        Assert.Equal("/user.slice/user-1001.slice/user@1001.service/init.scope is not a container (the user manager itself)", d.Refusal);
    }

    [Fact]
    public void ALoginSession_IsRefused() =>
        Assert.Equal("/user.slice/user-1001.slice/session-3.scope is not a container (a login session)",
            BrokerContainerUnit.Derive("/user.slice/user-1001.slice/session-3.scope").Refusal);

    [Theory]
    [InlineData("/user.slice/user-1001.slice")]
    [InlineData("/user.slice/user-1001.slice/user@1001.service")]
    [InlineData("/")]
    public void APathWithNoUnit_IsRefused(string path)
    {
        var d = BrokerContainerUnit.Derive(path);
        Assert.Null(d.Unit);
        Assert.Equal("it names no systemd unit (.service or .scope) other than a user manager", d.Refusal);
    }

    [Theory]
    [InlineData("/../user.slice/lane1.service")]
    [InlineData("/user.slice/../lane1.service/x")]
    public void APathWithDotDot_IsRefused(string path)
    {
        var d = BrokerContainerUnit.Derive(path);
        Assert.Null(d.Unit);
        Assert.Equal("it has a \"..\" segment: the process is outside this cgroup namespace's view", d.Refusal);
    }
}

/// <summary>
/// Brief I224 task 4: <c>sudo tswap broker socket bind</c> and <c>socket add</c>'s binding options, through the
/// CLI with <see cref="BrokerCommand"/>'s seams standing in for <c>/proc</c> and the platform.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class BrokerSocketBindCommandTests : IDisposable
{
    private readonly FleetMachine _m = new("brokerbind4");
    private readonly Dictionary<string, string> _proc = new(StringComparer.Ordinal);

    private const string Fedora =
        "/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_0123abcd.slice/libpod-4567ef.scope/container";
    private const string FedoraUnit =
        "/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_0123abcd.slice/libpod-4567ef.scope";
    private const string Quadlet = "/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service";
    private const string Label = "system_u:system_r:container_t:s0:c168,c863";

    public BrokerSocketBindCommandTests()
    {
        BrokerCommand.ReadProcFile = path => _proc.TryGetValue(path, out var text) ? Encoding.ASCII.GetBytes(text) : null;
        BrokerCommand.IsLinux = () => true;
    }

    public void Dispose()
    {
        BrokerCommand.ResetSeamsForTests();
        _m.Dispose();
    }

    private string BrokerJson => BrokerConfigFile.PathIn(_m.Dir);

    private static readonly string[] AddRoute =
        ["broker", "route", "add", "github", "--upstream", "https://github.com/stevedcc", "--auth", "bearer", "--secret", "gh", "--path", ""];

    private void AddSocket(string name = "lane1", params ReadOnlySpan<string> binding) =>
        _m.Ok("", ["broker", "socket", "add", name, "--uids", "100999", "--routes", "github", "--socket-dir", "/run/tswap-broker", .. binding]);

    /// <summary>A v0.1 broker.json: sockets with neither "container" nor "uid_only".</summary>
    private void WriteV01(params string[] sockets)
    {
        var json = $$"""
            { "version": 1, "socket_dir": "/run/tswap-broker",
              "sockets": [ {{string.Join(", ", sockets.Select(s => $$"""{ "name": "{{s}}", "uids": ["100999"], "routes": [] }"""))}} ],
              "routes": [] }
            """;
        File.WriteAllText(BrokerJson, json);
        if (!OperatingSystem.IsWindows()) // the callers return early on Windows; this keeps CA1416 satisfied
            File.SetUnixFileMode(BrokerJson, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private BrokerSocketConfig RawSocket(string name) => BrokerConfigFile.ReadRaw(DirectoryOwnerMatcher.Default, _m.Dir)!.Sockets.Single(s => s.Name == name);

    private BrokerPolicy Load() => BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _m.Dir);

    // ------------------------------------------------------------------ socket bind, each option

    [Fact]
    public void Bind_Pid_WritesTheDerivedUnit_AndWarnsAboutAPerInstanceBinding()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        _proc["/proc/4242/cgroup"] = "0::" + Fedora + "\n";

        var (exit, stdout, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", "4242");

        Assert.True(exit == 0, stderr);
        Assert.Contains($"socket lane1 bound to {FedoraUnit}", stdout);
        Assert.Contains("warning: this binds one container instance; it changes when the container is recreated (re-run socket bind then). A Quadlet unit gives a stable name.", stderr);
        Assert.Contains("SIGHUP", stdout);
        var socket = RawSocket("lane1");
        Assert.Equal(FedoraUnit, socket.Container!.Cgroup);
        Assert.Null(socket.Container.SelinuxLabel);
        Assert.Null(socket.UidOnly);
        Assert.Equal(FedoraUnit, Load().Sockets["lane1"].Container!.Cgroup);
    }

    [Fact]
    public void Bind_Pid_OfAQuadletPayload_GivesTheService_WithoutTheWarning()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        _proc["/proc/77/cgroup"] = "0::" + Quadlet + "/libpod-payload-x\n";

        var (exit, stdout, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", "77");

        Assert.True(exit == 0, stderr);
        Assert.Contains($"socket lane1 bound to {Quadlet}", stdout);
        Assert.DoesNotContain("warning:", stderr);
        Assert.Equal(Quadlet, RawSocket("lane1").Container!.Cgroup);
    }

    [Fact]
    public void Bind_PidWithLabel_RecordsTheProcessesLabel_AndSaysWhatItMeans()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        _proc["/proc/77/cgroup"] = "0::" + Quadlet + "/libpod-payload-x\n";
        _proc["/proc/77/attr/current"] = Label + "\0\n";

        var (exit, stdout, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", "77", "--with-label");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Label, RawSocket("lane1").Container!.SelinuxLabel);
        Assert.Contains($"label {Label}", stdout);
        Assert.Contains("changes on each container start unless the unit pins SecurityLabelLevel=", stdout);
        Assert.Contains("SO_PEERSEC", stdout);
        Assert.Equal(Label, Load().Sockets["lane1"].Container!.SelinuxLabel);
    }

    [Fact]
    public void Bind_PidWithLabel_ThatIsNotAWholeLabel_IsRefused_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var before = File.ReadAllBytes(BrokerJson);
        _proc["/proc/77/cgroup"] = "0::" + Quadlet + "\n";
        _proc["/proc/77/attr/current"] = "unconfined\n";

        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", "77", "--with-label");

        Assert.NotEqual(0, exit);
        Assert.Contains("socket lane1: process 77's label unconfined is not a whole SELinux label", stderr);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    [Fact]
    public void Bind_Cgroup_WritesItAsGiven()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");

        var (exit, stdout, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--cgroup", Quadlet);

        Assert.True(exit == 0, stderr);
        Assert.Contains($"socket lane1 bound to {Quadlet}", stdout);
        Assert.Equal(Quadlet, RawSocket("lane1").Container!.Cgroup);
        Assert.Null(RawSocket("lane1").UidOnly);
    }

    [Fact]
    public void Bind_Cgroup_ThatIsNotAContainer_IsRefused_WithTheD1Message_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var before = File.ReadAllBytes(BrokerJson);

        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--cgroup", "/user.slice/user-1001.slice/user@1001.service");

        Assert.NotEqual(0, exit);
        Assert.Contains("socket lane1: container.cgroup /user.slice/user-1001.slice/user@1001.service is not a container (the user manager: every process of that user)", stderr);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    [Fact]
    public void Bind_UidOnly_RemovesTheContainer()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--cgroup", Quadlet);
        Assert.NotNull(RawSocket("lane1").Container);

        var (exit, stdout, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--uid-only");

        Assert.True(exit == 0, stderr);
        Assert.Contains("socket lane1 is uid-only", stdout);
        Assert.Null(RawSocket("lane1").Container);
        Assert.Equal(true, RawSocket("lane1").UidOnly);
        Assert.Null(Load().Sockets["lane1"].Container);
    }

    // ------------------------------------------------------------------ --pid refusals show the path read

    [Theory]
    [InlineData("0::/user.slice/user-1001.slice/user@1001.service/init.scope\n",
        "socket lane1: can't bind to process 9: /user.slice/user-1001.slice/user@1001.service/init.scope is not a container (the user manager itself); its cgroup is /user.slice/user-1001.slice/user@1001.service/init.scope")]
    [InlineData("0::/user.slice/user-1001.slice\n",
        "socket lane1: can't bind to process 9: it names no systemd unit (.service or .scope) other than a user manager; its cgroup is /user.slice/user-1001.slice")]
    [InlineData("0::/../x/lane1.service\n",
        "socket lane1: can't bind to process 9: it has a \"..\" segment: the process is outside this cgroup namespace's view; its cgroup is /../x/lane1.service")]
    // I224 fix round 1 (F5, both p1): a relative v2 path is not a cgroup v2 line either
    [InlineData("0::a.service\n",
        "socket lane1: can't bind to process 9: /proc/9/cgroup is not one cgroup v2 line (0::/...): 0::a.service\\n")]
    [InlineData("1:name=systemd:/a.service\n0::/a.service\n",
        "socket lane1: can't bind to process 9: /proc/9/cgroup is not one cgroup v2 line (0::/...): 1:name=systemd:/a.service\\n0::/a.service\\n")]
    public void Bind_Pid_Refusals_NameThePathRead(string content, string message)
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        _proc["/proc/9/cgroup"] = content;

        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", "9");

        Assert.NotEqual(0, exit);
        Assert.Contains(message, stderr);
        Assert.Equal(true, RawSocket("lane1").UidOnly);
    }

    [Fact]
    public void Bind_Pid_ThatCantBeRead_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", "31337");
        Assert.NotEqual(0, exit);
        Assert.Contains("socket lane1: can't bind to process 31337: /proc/31337/cgroup can't be read (is the process running?)", stderr);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("abc")]
    public void Bind_Pid_ThatIsNotAPid_IsRefused(string pid)
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--pid", pid);
        Assert.NotEqual(0, exit);
        Assert.Contains("--pid must be a process id", stderr);
    }

    // ------------------------------------------------------------------ option rules

    [Theory]
    [InlineData("")]
    [InlineData("--uid-only --cgroup " + Quadlet)]
    [InlineData("--pid 7 --uid-only")]
    [InlineData("--pid 7 --cgroup " + Quadlet)]
    public void Bind_NeedsExactlyOneOfTheThree(string optionText)
    {
        var options = optionText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var (exit, _, stderr) = _m.Run("", ["broker", "socket", "bind", "lane1", .. options]);
        Assert.NotEqual(0, exit);
        Assert.Contains("exactly one of --pid <pid>, --cgroup <path> or --uid-only", stderr);
    }

    [Theory]
    [InlineData("")]
    [InlineData("--uid-only --cgroup " + Quadlet)]
    public void SocketAdd_NeedsExactlyOneOfTheThree_AndWritesNothing(string optionText)
    {
        var options = optionText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        var before = File.ReadAllBytes(BrokerJson);
        var (exit, _, stderr) = _m.Run("", ["broker", "socket", "add", "lane1", "--uids", "100999", "--routes", "github", "--socket-dir", "/run/tswap-broker", .. options]);
        Assert.NotEqual(0, exit);
        Assert.Contains("exactly one of --pid <pid>, --cgroup <path> or --uid-only", stderr);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    [Theory]
    [InlineData("--uid-only --with-label")]
    [InlineData("--cgroup " + Quadlet + " --with-label")]
    public void WithLabel_GoesWithPidOnly(string optionText)
    {
        var options = optionText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var (exit, _, stderr) = _m.Run("", ["broker", "socket", "bind", "lane1", .. options]);
        Assert.NotEqual(0, exit);
        Assert.Contains("--with-label goes with --pid only", stderr);
    }

    [Fact]
    public void SocketAdd_WithEachOption_WritesTheBinding()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        _proc["/proc/77/cgroup"] = "0::" + Quadlet + "/libpod-payload-x\n";
        AddSocket("a", "--pid", "77");
        AddSocket("b", "--cgroup", "/system.slice/lane2.service");
        AddSocket("c", "--uid-only");
        var policy = Load();
        Assert.Equal(Quadlet, policy.Sockets["a"].Container!.Cgroup);
        Assert.Equal("/system.slice/lane2.service", policy.Sockets["b"].Container!.Cgroup);
        Assert.Null(policy.Sockets["c"].Container);
        Assert.Equal(true, RawSocket("c").UidOnly);
    }

    [Fact]
    public void Bind_AnUnknownSocket_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "nope", "--uid-only");
        Assert.NotEqual(0, exit);
        Assert.Contains("No socket named 'nope'", stderr);
    }

    [Fact]
    public void Bind_WithoutSudo_IsRefused_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var before = File.ReadAllBytes(BrokerJson);
        _m.Sudo = false;
        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--cgroup", Quadlet);
        Assert.NotEqual(0, exit);
        Assert.Contains("requires", stderr);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    // ------------------------------------------------------------------ a v0.1 file (r2 GLM N1)

    [Theory]
    [InlineData("--uid-only")]
    [InlineData("--cgroup " + Quadlet)]
    [InlineData("--pid 77")]
    public void Bind_OnAV01File_Succeeds_AndTheFileThenLoads(string optionText)
    {
        var options = optionText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (OperatingSystem.IsWindows())
            return;
        WriteV01("lane1");
        _proc["/proc/77/cgroup"] = "0::" + Quadlet + "\n";
        Assert.Contains("names no container", Assert.Throws<BrokerConfigException>(Load).Message);

        var (exit, _, stderr) = _m.Run("", ["broker", "socket", "bind", "lane1", .. options]);

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("still to bind", stderr);
        Assert.NotNull(Load().Sockets["lane1"]);
    }

    [Fact]
    public void Bind_OneOfTwoV01Sockets_Writes_AndNamesTheOther()
    {
        if (OperatingSystem.IsWindows())
            return;
        WriteV01("lane1", "lane2");

        var (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane1", "--uid-only");

        Assert.True(exit == 0, stderr);
        Assert.Contains("still to bind before serve starts: lane2", stderr);
        Assert.Equal(true, RawSocket("lane1").UidOnly);
        Assert.Contains("socket lane2 names no container", Assert.Throws<BrokerConfigException>(Load).Message);

        (exit, _, stderr) = _m.Run("", "broker", "socket", "bind", "lane2", "--cgroup", Quadlet);
        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("still to bind", stderr);
        Assert.Equal(Quadlet, Load().Sockets["lane2"].Container!.Cgroup);
    }

    // ------------------------------------------------------------------ platform

    [Theory]
    [InlineData("--pid 77")]
    [InlineData("--cgroup " + Quadlet)]
    [InlineData("--pid 77 --with-label")]
    public void OffLinux_ContainerOptions_AreRefused(string optionText)
    {
        var options = optionText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (OperatingSystem.IsWindows())
            return;
        BrokerCommand.IsLinux = () => false;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var before = File.ReadAllBytes(BrokerJson);

        var (exit, _, stderr) = _m.Run("", ["broker", "socket", "bind", "lane1", .. options]);
        Assert.NotEqual(0, exit);
        Assert.Contains("binding a socket to a container needs Linux; use --uid-only", stderr);
        (exit, _, stderr) = _m.Run("", ["broker", "socket", "add", "lane2", "--uids", "1", "--socket-dir", "/run/tswap-broker", .. options]);
        Assert.NotEqual(0, exit);
        Assert.Contains("binding a socket to a container needs Linux; use --uid-only", stderr);
        Assert.Equal(before, File.ReadAllBytes(BrokerJson));
    }

    [Fact]
    public void OffLinux_UidOnly_Works()
    {
        if (OperatingSystem.IsWindows())
            return;
        BrokerCommand.IsLinux = () => false;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        _m.Ok("", "broker", "socket", "bind", "lane1", "--uid-only");
        Assert.Equal(true, RawSocket("lane1").UidOnly);
    }

    // ------------------------------------------------------------------ the write path

    [Fact]
    public void SimulatedSudo_Bind_WritesAsTheFolderOwner_Mode0600_Atomically()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddRoute);
        AddSocket("lane1", "--uid-only");
        var fake = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0);
        _m.Ownership = new DirectoryOwnerMatcher(fake);
        var elsewhere = Path.Combine(_m.Dir, "elsewhere.json");
        var ln = System.Diagnostics.Process.Start("ln", [BrokerJson, elsewhere])!;
        ln.WaitForExit();
        Assert.Equal(0, ln.ExitCode);
        var before = File.ReadAllText(elsewhere);

        _m.Ok("", "broker", "socket", "bind", "lane1", "--cgroup", Quadlet);

        Assert.Contains(fake.Switches, s => s.Path == Path.GetFullPath(BrokerJson) && s.Uid == 1000 && s.Gid == 1001);
        Assert.All(fake.Switches, s => Assert.Equal((1000u, 1001u), (s.Uid, s.Gid))); // temp file and final file as the owner
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, new FileInfo(BrokerJson).UnixFileMode);
        Assert.Equal(before, File.ReadAllText(elsewhere)); // a new file renamed over it, not written in place
        Assert.Contains(Quadlet, File.ReadAllText(BrokerJson));
        Assert.Empty(Directory.GetFiles(_m.Dir, "*.tmp"));
    }
}
