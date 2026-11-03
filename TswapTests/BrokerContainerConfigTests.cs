using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief I224 task 1: a socket names its container (<c>container.cgroup</c>, optional
/// <c>container.selinux_label</c>) or says <c>uid_only: true</c> (D1); the shared unit predicate; the
/// uid-0 warning; and where <c>serve</c> refuses to start (D2), each D2 fact behind a
/// <see cref="BrokerContainerHost"/> seam.
/// </summary>
public class BrokerContainerConfigTests
{
    private const string Unit = "/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service";
    private const string Label = "system_u:system_r:container_t:s0:c12,c34";

    /// <summary>A v0.1-shaped broker.json: a socket with neither "container" nor "uid_only".</summary>
    private const string V01Json = """
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          "sockets": [
            { "name": "lane1", "uids": ["100999", "200000-265535"], "routes": ["github"] }
          ],
          "routes": [
            {
              "name": "github",
              "upstream": "https://github.com/stevedcc",
              "auth": { "type": "basic", "user": "x-access-token", "secret": "{{gh-token}}" },
              "path": "croft\\.git/"
            }
          ]
        }
        """;

    /// <summary>One socket <c>lane1</c> with <paramref name="binding"/> (JSON members after "routes", or "").</summary>
    private static string WithSocket(string binding, string uids = "\"100999\"") => $$"""
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          "sockets": [ { "name": "lane1", "uids": [{{uids}}], "routes": []{{(binding.Length > 0 ? ", " + binding : "")}} } ],
          "routes": []
        }
        """;

    private static string Container(string cgroup, string? label = null) =>
        $$"""
        "container": { "cgroup": {{JsonSerializer.Serialize(cgroup)}}{{(label is null ? "" : ", \"selinux_label\": " + JsonSerializer.Serialize(label))}} }
        """;

    private static string Refused(string json) =>
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json)).Message;

    // ------------------------------------------------------------------ the shared predicate (D1)

    [Theory]
    [InlineData("user@1001.service", "the user manager: every process of that user")]
    [InlineData("user@0.service", "the user manager: every process of that user")]
    [InlineData("init.scope", "the user manager itself")]
    [InlineData("manager.scope", "the user manager itself")]
    [InlineData("session-3.scope", "a login session")]
    [InlineData("session-c2.scope", "a login session")]
    [InlineData("-.scope", "the root scope")]
    [InlineData("user-1001.slice", "not a systemd unit")]
    [InlineData("app.slice", "not a systemd unit")]
    [InlineData("container", "not a systemd unit")]
    [InlineData("lane1.service.d", "not a systemd unit")]
    public void UnitPredicate_RefusesUnitsThatAreNotContainers_WithTheirReason(string lastSegment, string reason) =>
        Assert.Equal(reason, BrokerContainerUnit.Refusal(lastSegment));

    [Theory]
    [InlineData("lane1.service")]
    [InlineData("libpod-abc.scope")]
    [InlineData("tswap-test-1a2b.scope")]
    [InlineData("user@.service")] // a template name, not a user manager instance
    public void UnitPredicate_AcceptsContainerUnits(string lastSegment) =>
        Assert.Null(BrokerContainerUnit.Refusal(lastSegment));

    // ------------------------------------------------------------------ D1: accepted

    [Fact]
    public void Container_WithCgroupAndLabel_IsCompiledOntoTheSocket()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var policy = BrokerPolicy.Parse(WithSocket(Container(Unit, Label)));
        var container = policy.Sockets["lane1"].Container;
        Assert.NotNull(container);
        Assert.Equal(Unit, container.Cgroup);
        Assert.Equal(Label, container.SelinuxLabel);
    }

    [Fact]
    public void Container_WithoutLabel_HasANullLabel()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var container = BrokerPolicy.Parse(WithSocket(Container("/system.slice/lane1.service"))).Sockets["lane1"].Container;
        Assert.NotNull(container);
        Assert.Equal("/system.slice/lane1.service", container.Cgroup);
        Assert.Null(container.SelinuxLabel);
    }

    [Fact]
    public void UidOnly_True_LeavesTheSocketUnbound()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var policy = BrokerPolicy.Parse(WithSocket("\"uid_only\": true"));
        Assert.Null(policy.Sockets["lane1"].Container);
        Assert.True(policy.Sockets["lane1"].AllowsUid(100999));
    }

    [Fact]
    public void Container_RoundTripsThroughTheJsonContext()
    {
        var config = BrokerPolicy.Deserialize(WithSocket(Container(Unit, Label)));
        var again = BrokerPolicy.Deserialize(BrokerPolicy.Serialize(config));
        Assert.Equal(Unit, again.Sockets[0].Container!.Cgroup);
        Assert.Equal(Label, again.Sockets[0].Container!.SelinuxLabel);
        Assert.Null(again.Sockets[0].UidOnly);
        Assert.Contains("\"selinux_label\"", BrokerPolicy.Serialize(config));
    }

    [Fact]
    public void Container_UnknownField_IsRefusedByTheStrictParser()
    {
        var message = Refused(WithSocket("""
            "container": { "cgroup": "/system.slice/lane1.service", "pid": 7 }
            """));
        Assert.Contains("can't be read", message);
    }

    // ------------------------------------------------------------------ D1: refused, with the exact messages

    [Theory]
    [InlineData("/user.slice/user-1001.slice/user@1001.service", "the user manager: every process of that user")]
    [InlineData("/user.slice/user-1001.slice/user@1001.service/init.scope", "the user manager itself")]
    [InlineData("/user.slice/user-1001.slice/session-3.scope", "a login session")]
    [InlineData("/user.slice/user-1001.slice/session-c2.scope", "a login session")]
    [InlineData("/user.slice/user-1001.slice", "not a systemd unit")]
    [InlineData("/-.scope", "the root scope")]
    public void Cgroup_ThatIsNotAContainer_IsRefused_WithTheD1Message(string cgroup, string reason) =>
        Assert.Equal($"socket lane1: container.cgroup {cgroup} is not a container ({reason})", Refused(WithSocket(Container(cgroup))));

    [Theory]
    [InlineData("/a/b.service/", "it ends with /")]
    [InlineData("/a/../b.service", "it has an empty, . or .. segment")]
    [InlineData("/a/./b.service", "it has an empty, . or .. segment")]
    [InlineData("/a//b.service", "it has an empty, . or .. segment")]
    [InlineData("a/b.service", "it doesn't start with /")]
    [InlineData("/a/b c.service", "it may use printable ASCII only, no spaces")]
    [InlineData("/a/bé.service", "it may use printable ASCII only, no spaces")]
    [InlineData("", "it doesn't start with /")]
    public void Cgroup_ThatIsNotAValidPath_IsRefused(string cgroup, string reason) =>
        Assert.Equal($"socket lane1: container.cgroup {BrokerContainerIdentity.Shown(cgroup)} is not a valid cgroup path ({reason})",
            Refused(WithSocket(Container(cgroup))));

    // I224 fix round 1 (MiMo p1 M4): a "container" with no usable "cgroup" is refused when the file is read
    // (BrokerContainerConfig.Cgroup is required and non-null in the JSON context), never bound to nothing.
    [Theory]
    [InlineData("\"container\": { }")]
    [InlineData("\"container\": { \"selinux_label\": \"system_u:system_r:container_t:s0:c12,c34\" }")]
    public void Container_WithoutACgroup_IsRefused(string binding)
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Equal("broker.json can't be read: JSON deserialization for type 'TswapCore.Broker.BrokerContainerConfig' was missing required properties including: 'cgroup'.",
            Refused(WithSocket(binding)));
    }

    [Fact]
    public void Container_WithANullCgroup_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var message = Refused(WithSocket("\"container\": { \"cgroup\": null }"));

        // The JSON reader's own text, up to the line and byte position it appends.
        Assert.StartsWith("broker.json can't be read: The constructor parameter 'Cgroup' on type 'TswapCore.Broker.BrokerContainerConfig' " +
            "doesn't allow null values. Consider updating its nullability annotation. Path: $.sockets[0].container.cgroup | ", message);
    }

    [Fact]
    public void Cgroup_Of1025Bytes_IsRefused_And1024BytesIsAccepted()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var ok = "/" + new string('a', 1024 - 1 - ".service".Length) + ".service";
        Assert.Equal(1024, ok.Length);
        Assert.Equal(ok, BrokerPolicy.Parse(WithSocket(Container(ok))).Sockets["lane1"].Container!.Cgroup);

        var tooLong = "/" + new string('a', 1025 - 1 - ".service".Length) + ".service";
        Assert.Equal(1025, tooLong.Length);
        Assert.Equal($"socket lane1: container.cgroup {BrokerContainerIdentity.Shown(tooLong)} is not a valid cgroup path (it is longer than 1024 bytes)",
            Refused(WithSocket(Container(tooLong))));
    }

    [Fact]
    public void Shown_CapsALongPathAndReplacesUnprintables()
    {
        Assert.Equal("/a/b?c.service", BrokerContainerIdentity.Shown("/a/b\nc.service"));
        var shown = BrokerContainerIdentity.Shown("/" + new string('a', 2000));
        Assert.Equal(1024 + 1, shown.Length);
        Assert.EndsWith("…", shown);
    }

    [Fact]
    public void BothContainerAndUidOnly_AreRefused() =>
        Assert.Equal("socket lane1 has both \"container\" and \"uid_only\": remove one",
            Refused(WithSocket(Container(Unit) + ", \"uid_only\": true")));

    [Fact]
    public void NeitherContainerNorUidOnly_IsRefused() =>
        Assert.Equal(
            "socket lane1 names no container: run \"sudo tswap broker socket bind lane1 --pid <pid>\" or \"sudo tswap broker socket bind lane1 --uid-only\"",
            Refused(WithSocket("")));

    [Fact]
    public void AV01BrokerJson_IsRefused_WithTheD1Message() =>
        Assert.Equal(
            "socket lane1 names no container: run \"sudo tswap broker socket bind lane1 --pid <pid>\" or \"sudo tswap broker socket bind lane1 --uid-only\"",
            Refused(V01Json));

    [Fact]
    public void UidOnly_False_IsRefused() =>
        Assert.Equal("socket lane1: \"uid_only\": false is not allowed (say true or leave it out)",
            Refused(WithSocket("\"uid_only\": false")));

    [Fact]
    public void UidOnly_False_WithAContainer_IsRefusedToo() =>
        Assert.Equal("socket lane1: \"uid_only\": false is not allowed (say true or leave it out)",
            Refused(WithSocket(Container(Unit) + ", \"uid_only\": false")));

    [Theory]
    [InlineData("a::b:c")]
    [InlineData("a:b:c")]
    [InlineData("system_u:system_r:container_t:s0 c1")]
    [InlineData("system_u:system_r:container_t:")]
    [InlineData(":system_r:container_t:s0")]
    [InlineData("system_u:system_r:container_t:s0é")]
    [InlineData("")]
    public void Label_ThatIsNotAWholeSelinuxLabel_IsRefused(string label) =>
        Assert.Equal(
            $"socket lane1: container.selinux_label {BrokerContainerIdentity.Shown(label)} is not a whole SELinux label " +
            "(user:role:type:level, each part non-empty printable ASCII without spaces, at most 256 bytes)",
            Refused(WithSocket(Container(Unit, label))));

    [Fact]
    public void Label_Of257Bytes_IsRefused_And256IsAccepted()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var prefix = "system_u:system_r:container_t:s0:c";
        var ok = prefix + new string('1', 256 - prefix.Length);
        Assert.Equal(ok, BrokerPolicy.Parse(WithSocket(Container(Unit, ok))).Sockets["lane1"].Container!.SelinuxLabel);
        var tooLong = ok + "1";
        Assert.StartsWith("socket lane1: container.selinux_label ", Refused(WithSocket(Container(Unit, tooLong))));
    }

    [Fact]
    public void Label_ThatTheKernelReaderAccepts_ButHasNoLevel_IsStillRefused()
    {
        // D1: at least as strict as PeerIdentity.SelinuxLabel, and stricter on purpose (a container's label has a level).
        Assert.NotNull(TswapCore.Agent.PeerIdentity.SelinuxLabel("a:b:c"u8));
        Assert.StartsWith("socket lane1: container.selinux_label a:b:c ", Refused(WithSocket(Container(Unit, "a:b:c"))));
    }

    // ------------------------------------------------------------------ the editing commands' suspended rule (r2 GLM N1)

    [Fact]
    public void RequireBindingFalse_AcceptsASocketWithNeither_ButEveryOtherRuleStillApplies()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var policy = BrokerPolicy.Validate(BrokerPolicy.Deserialize(V01Json), requireBinding: false);
        Assert.Null(policy.Sockets["lane1"].Container);

        var both = BrokerPolicy.Deserialize(WithSocket(Container(Unit) + ", \"uid_only\": true"));
        Assert.Equal("socket lane1 has both \"container\" and \"uid_only\": remove one",
            Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Validate(both, requireBinding: false)).Message);
        var bad = BrokerPolicy.Deserialize(WithSocket(Container("/user.slice/user-1001.slice")));
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Validate(bad, requireBinding: false));
        var falseUidOnly = BrokerPolicy.Deserialize(WithSocket("\"uid_only\": false"));
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Validate(falseUidOnly, requireBinding: false));
    }

    [Fact]
    public void UnboundSocketNames_ListsSocketsWithNeitherField_InFileOrder()
    {
        var config = BrokerPolicy.Deserialize("""
            { "version": 1, "socket_dir": "/s", "routes": [], "sockets": [
              { "name": "b", "uids": ["1"], "routes": [] },
              { "name": "a", "uids": ["1"], "routes": [], "uid_only": true },
              { "name": "c", "uids": ["1"], "routes": [] } ] }
            """);
        Assert.Equal(["b", "c"], BrokerPolicy.UnboundSocketNames(config));
    }

    // ------------------------------------------------------------------ D1: the uid-0 warning

    [Theory]
    [InlineData("\"0\"")]
    [InlineData("\"0-65535\"")]
    [InlineData("\"100999\", \"0-5\"")]
    public void Uids_ThatIncludeZero_AreAccepted_WithTheWarning(string uids)
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var policy = BrokerPolicy.Parse(WithSocket("\"uid_only\": true", uids));
        Assert.Equal(["socket lane1 admits uid 0: every root process and rootful container on this host has it"], policy.Warnings);
    }

    [Fact]
    public void Uids_WithoutZero_GiveNoWarning()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Empty(BrokerPolicy.Parse(WithSocket("\"uid_only\": true", "\"1-65535\"")).Warnings);
    }

    // ------------------------------------------------------------------ D2: serve's start checks (seams)

    /// <summary>A host on which every D2 check passes.</summary>
    private static readonly BrokerContainerHost GoodHost = BrokerContainerHost.Real with
    {
        IsLinux = () => true,
        PeerPidfdAvailable = () => true,
        ReadOwnCgroup = () => "0::/user.slice/user-1000.slice/user@1000.service/app.slice/tswap-broker.service\n"u8.ToArray(),
        SelinuxEnabled = () => true,
    };

    private static BrokerPolicy ServePolicy(string socketDir, string lane1Binding, string uids = "\"1\"") => BrokerPolicy.Parse($$"""
        {
          "version": 1,
          "socket_dir": {{JsonSerializer.Serialize(socketDir)}},
          "sockets": [
            { "name": "lane1", "uids": [{{uids}}], "routes": [], {{lane1Binding}} },
            { "name": "other", "uids": ["1"], "routes": [], "uid_only": true }
          ],
          "routes": []
        }
        """);

    [Fact]
    public void StartRefusal_OnAGoodHost_IsNull()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Null(GoodHost.StartRefusal(ServePolicy("/s", Container(Unit, Label))));
    }

    [Fact]
    public void StartRefusal_NotLinux_NamesTheSocket()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Equal("socket lane1: \"container\" needs Linux (the broker reads the client's cgroup from /proc); use \"uid_only\": true on this platform",
            (GoodHost with { IsLinux = () => false }).StartRefusal(ServePolicy("/s", Container(Unit))));
    }

    [Fact]
    public void StartRefusal_NoPeerPidfd_NamesTheSocket()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Equal("socket lane1: \"container\" needs SO_PEERPIDFD (Linux 6.5 or later), which this kernel doesn't give",
            (GoodHost with { PeerPidfdAvailable = () => false }).StartRefusal(ServePolicy("/s", Container(Unit))));
    }

    [Theory]
    [InlineData("12:pids:/user.slice\n0::/user.slice/a.service\n")] // hybrid
    [InlineData("1:name=systemd:/user.slice/a.service\n")]          // v1
    [InlineData("0::user.slice/a.service\n")]                       // not absolute
    [InlineData("")]
    public void StartRefusal_NotPureCgroupV2_NamesTheSocket(string ownCgroup)
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Equal("socket lane1: \"container\" needs a cgroup v2 host (/proc/self/cgroup must be one \"0::/...\" line)",
            (GoodHost with { ReadOwnCgroup = () => Encoding.UTF8.GetBytes(ownCgroup) }).StartRefusal(ServePolicy("/s", Container(Unit))));
    }

    [Fact]
    public void StartRefusal_OwnCgroupUnreadable_NamesTheSocket()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Equal("socket lane1: \"container\" needs a cgroup v2 host (/proc/self/cgroup must be one \"0::/...\" line)",
            (GoodHost with { ReadOwnCgroup = () => null }).StartRefusal(ServePolicy("/s", Container(Unit))));
    }

    [Theory]
    [InlineData("0::/../../user.slice/a.service\n")]
    [InlineData("0::/..")]
    public void StartRefusal_OwnCgroupWithDotDot_NamesTheSocket(string ownCgroup)
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Equal("socket lane1: \"container\" needs serve in the host's root cgroup namespace (/proc/self/cgroup has a \"..\" segment)",
            (GoodHost with { ReadOwnCgroup = () => Encoding.UTF8.GetBytes(ownCgroup) }).StartRefusal(ServePolicy("/s", Container(Unit))));
    }

    [Theory]
    [InlineData("0::/user.slice/a.service")]   // no trailing newline
    [InlineData("0::/user.slice/a.service\n")]
    [InlineData("0::/\n")]                     // the root cgroup itself
    public void StartRefusal_OwnCgroupV2Line_Passes(string ownCgroup)
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        Assert.Null((GoodHost with { ReadOwnCgroup = () => Encoding.UTF8.GetBytes(ownCgroup) }).StartRefusal(ServePolicy("/s", Container(Unit))));
    }

    [Fact]
    public void StartRefusal_LabelWithoutSelinux_NamesTheSocket()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var host = GoodHost with { SelinuxEnabled = () => false };
        Assert.Equal("socket lane1: container.selinux_label needs SELinux, which is not enabled (no /sys/fs/selinux/enforce)",
            host.StartRefusal(ServePolicy("/s", Container(Unit, Label))));
        Assert.Null(host.StartRefusal(ServePolicy("/s", Container(Unit)))); // no label: SELinux not needed
    }

    [Fact]
    public void StartRefusal_UidOnlySockets_NeverConsultTheHost()
    {
        if (OperatingSystem.IsWindows())
            return; // socket_dir must be a POSIX absolute path; the broker refuses Windows
        var host = new BrokerContainerHost
        {
            IsLinux = () => throw new InvalidOperationException("consulted"),
            PeerPidfdAvailable = () => throw new InvalidOperationException("consulted"),
            ReadOwnCgroup = () => throw new InvalidOperationException("consulted"),
            SelinuxEnabled = () => throw new InvalidOperationException("consulted"),
        };
        Assert.Null(host.StartRefusal(ServePolicy("/s", "\"uid_only\": true")));
    }

    [Fact]
    public void RealProbe_OnLinux_FindsSoPeerPidfd()
    {
        if (!OperatingSystem.IsLinux())
            return; // the probe is Linux only (Global constraints: this fails, never skips, on a Linux kernel without SO_PEERPIDFD)
        Assert.True(BrokerContainerHost.Real.PeerPidfdAvailable(), "socketpair() + getsockopt(SO_PEERPIDFD) failed: the kernel is older than 6.5");
        Assert.True(BrokerContainerHost.Real.IsLinux());
    }

    [Fact]
    public void RealProbe_OffLinux_IsFalse()
    {
        if (OperatingSystem.IsLinux())
            return;
        Assert.False(BrokerContainerHost.Real.PeerPidfdAvailable());
        Assert.False(BrokerContainerHost.Real.IsLinux());
    }

    // ------------------------------------------------------------------ D2 through a real serve: refusals, start lines, warnings

    private static async Task<(BrokerServer? Server, Exception? Error)> TryStartAsync(BrokerHarness h, BrokerPolicyHolder holder, BrokerContainerHost host)
    {
        try
        {
            return (await BrokerServer.StartAsync(new BrokerServerOptions
            {
                AllowOwnUidForTests = true,
                Policy = holder,
                Secrets = h.Secrets,
                Forwarder = h.FakeForwarder,
                Log = new BrokerLog(h.LogText, null, h.Clock),
                Time = h.Clock,
                ContainerHost = host,
            }), null);
        }
        catch (TswapException ex)
        {
            return (null, ex);
        }
    }

    [Fact]
    public async Task Serve_RefusesToStart_WhenAD2CheckFails_AndCreatesNoSocket()
    {
        if (OperatingSystem.IsWindows())
            return; // serve is Unix only
        await using var h = new BrokerHarness();
        var holder = new BrokerPolicyHolder(ServePolicy(h.SocketDir, Container(Unit)));
        var (server, error) = await TryStartAsync(h, holder, GoodHost with { PeerPidfdAvailable = () => false });
        if (server is not null)
            await server.StopAsync(); // a broken check must not leave a listening server behind
        Assert.Null(server);
        Assert.Equal("socket lane1: \"container\" needs SO_PEERPIDFD (Linux 6.5 or later), which this kernel doesn't give", error!.Message);
        Assert.False(File.Exists(h.SocketPath("lane1")));
        Assert.False(File.Exists(h.SocketPath("other")));
    }

    [Fact]
    public async Task Serve_LogsOneLinePerSocket_AndTheWarnings_AtStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        await using var h = new BrokerHarness();
        var holder = new BrokerPolicyHolder(ServePolicy(h.SocketDir, Container(Unit, Label), uids: "\"0-65535\""));
        var (server, error) = await TryStartAsync(h, holder, GoodHost);
        Assert.Null(error);
        try
        {
            var log = h.LogText.ToString();
            Assert.Contains($"event socket lane1: container {Unit} label {Label}\n", log.ReplaceLineEndings("\n"));
            Assert.Contains("event socket other: uid-only (any process with a listed uid is admitted)\n", log.ReplaceLineEndings("\n"));
            Assert.Contains("event socket lane1 admits uid 0: every root process and rootful container on this host has it\n", log.ReplaceLineEndings("\n"));
        }
        finally
        {
            await server!.StopAsync();
        }
    }

    [Fact]
    public async Task Serve_StartLine_WithoutALabel_HasNoLabelPart()
    {
        if (OperatingSystem.IsWindows())
            return;
        await using var h = new BrokerHarness();
        var holder = new BrokerPolicyHolder(ServePolicy(h.SocketDir, Container(Unit)));
        var (server, error) = await TryStartAsync(h, holder, GoodHost);
        Assert.Null(error);
        try
        {
            Assert.Contains($"event socket lane1: container {Unit}\n", h.LogText.ToString().ReplaceLineEndings("\n"));
        }
        finally
        {
            await server!.StopAsync();
        }
    }

    [Fact]
    public async Task Reload_ThatFailsAD2Check_KeepsTheOldConfig_AndLogsWhy()
    {
        if (OperatingSystem.IsWindows())
            return;
        await using var h = new BrokerHarness();
        var holder = new BrokerPolicyHolder(ServePolicy(h.SocketDir, "\"uid_only\": true"));
        var (server, error) = await TryStartAsync(h, holder, GoodHost with { SelinuxEnabled = () => false });
        Assert.Null(error);
        try
        {
            var before = holder.Current;
            Assert.False(server!.Reload(() => ServePolicy(h.SocketDir, Container(Unit, Label))));
            Assert.Same(before, holder.Current);
            Assert.Contains("config reload refused, keeping the current config: socket lane1: container.selinux_label needs SELinux",
                h.LogText.ToString());
        }
        finally
        {
            await server!.StopAsync();
        }
    }

    [Fact]
    public async Task Reload_ThatSucceeds_LogsTheNewConfigsWarnings()
    {
        if (OperatingSystem.IsWindows())
            return;
        await using var h = new BrokerHarness();
        var holder = new BrokerPolicyHolder(ServePolicy(h.SocketDir, "\"uid_only\": true"));
        var (server, error) = await TryStartAsync(h, holder, GoodHost);
        Assert.Null(error);
        try
        {
            Assert.DoesNotContain("admits uid 0", h.LogText.ToString());
            Assert.True(server!.Reload(() => ServePolicy(h.SocketDir, "\"uid_only\": true", uids: "\"0\"")));
            var log = h.LogText.ToString().ReplaceLineEndings("\n");
            var reloaded = log.IndexOf("event config reloaded\n", StringComparison.Ordinal);
            var warning = log.IndexOf("event socket lane1 admits uid 0: every root process and rootful container on this host has it\n", StringComparison.Ordinal);
            Assert.True(reloaded >= 0 && warning > reloaded, log);
        }
        finally
        {
            await server!.StopAsync();
        }
    }
}

/// <summary>
/// Brief I224 task 1: the editing commands (<c>socket add</c>, <c>route add</c> ...) write a file whose sockets
/// still need binding, and say which (D1, r2 GLM N1); <c>socket add --uid-only</c> writes <c>"uid_only": true</c>.
/// <remarks>I224 fix round 1 (MiMo p1 I1): in the static-seam collection, as <see cref="BrokerSocketBindCommandTests"/> is,
/// because it drives <c>BrokerCommand</c> (and its static seams) in-process through <see cref="FleetMachine"/>.</remarks>
[Collection(StaticSeamCollection.Name)]
public class BrokerContainerCommandTests : IDisposable
{
    private readonly FleetMachine _m = new("brokerbind");

    public void Dispose() => _m.Dispose();

    private static readonly string[] AddGithub =
    [
        "broker", "route", "add", "github", "--upstream", "https://github.com/stevedcc", "--auth", "basic",
        "--user", "x-access-token", "--secret", "gh-token", "--path", @"croft\.git/",
    ];

    [Fact]
    public void AnEditingCommand_OnAV01File_Writes_AndNamesTheSocketStillToBind()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        // Task 4 made socket add require a binding, so the unbound socket comes from a v0.1 file.
        var path = BrokerConfigFile.PathIn(_m.Dir);
        File.WriteAllText(path, """
            { "version": 1, "socket_dir": "/run/tswap-broker", "routes": [],
              "sockets": [ { "name": "lane1", "uids": ["100999"], "routes": [] } ] }
            """);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        // serve (every other load) applies the rule.
        Assert.Contains("socket lane1 names no container",
            Assert.Throws<BrokerConfigException>(() => BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _m.Dir)).Message);

        // An editing command still writes, and says so.
        var (exit, _, err) = _m.Run("", AddGithub);
        Assert.Equal(0, exit);
        Assert.Contains("still to bind before serve starts: lane1", err);
        var raw = BrokerConfigFile.ReadRaw(DirectoryOwnerMatcher.Default, _m.Dir)!;
        Assert.Equal("lane1", Assert.Single(raw.Sockets).Name);
        Assert.Equal("github", Assert.Single(raw.Routes).Name);
    }

    [Fact]
    public void SocketAdd_UidOnly_WritesUidOnlyTrue_AndLoads()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", AddGithub);
        var (exit, _, err) = _m.Run("", "broker", "socket", "add", "lane1", "--uids", "100999", "--routes", "github", "--socket-dir", "/run/tswap-broker", "--uid-only");
        Assert.Equal(0, exit);
        Assert.DoesNotContain("still to bind", err);
        Assert.Equal(true, BrokerConfigFile.ReadRaw(DirectoryOwnerMatcher.Default, _m.Dir)!.Sockets[0].UidOnly);
        Assert.Null(BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _m.Dir).Sockets["lane1"].Container);
    }
}
