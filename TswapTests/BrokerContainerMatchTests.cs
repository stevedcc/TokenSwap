using System.Net.Sockets;
using System.Text;
using Microsoft.Win32.SafeHandles;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief I224 task 2: the cgroup v2 parser (D3.3), the matcher (D3.6) and <see cref="BrokerContainerMatch.Observe"/>
/// (D3.1-5) through <see cref="PeerIdentity"/>'s seams, plus one real observation of this test process.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class BrokerContainerMatchTests : IDisposable
{
    private const string Unit = "/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service";
    private const string Label = "system_u:system_r:container_t:s0:c12,c34";
    private const string Fedora =
        "/user.slice/user-1000.slice/user@1000.service/user.slice/user-libpod_pod_0123abcd.slice/libpod-4567ef.scope/container";

    public void Dispose() => PeerIdentity.ResetSeamsForTests();

    // ------------------------------------------------------------------ the parser (D3.3)

    [Theory]
    [InlineData("0::" + Fedora + "\n", Fedora)]
    [InlineData("0::" + Fedora, Fedora)]
    [InlineData("0::" + Unit + "/libpod-payload-0123\n", Unit + "/libpod-payload-0123")]
    [InlineData("0::" + Unit + "/libpod-payload-0123", Unit + "/libpod-payload-0123")]
    public void Parse_AcceptsOneV2Line_WithOrWithoutTheNewline(string content, string path) =>
        Assert.Equal(path, PeerIdentity.ParseCgroupV2(Encoding.ASCII.GetBytes(content)));

    [Theory]
    [InlineData("0::/a.service\n0::/b.service\n")]  // two lines
    [InlineData("12:pids:/a.service\n0::/a.service\n")]
    [InlineData("1:name=systemd:/a.service\n")]     // a v1 line
    [InlineData("0::a.service\n")]                  // relative
    [InlineData("0::/a/../b.service\n")]            // outside the broker's namespace root
    [InlineData("0::/../b.service\n")]
    [InlineData("0::/a//b.service\n")]              // an empty segment
    [InlineData("0::/a/./b.service\n")]
    [InlineData("0::/a.service/\n")]                // a trailing slash is an empty segment
    [InlineData("0::/\n")]                          // the root: an empty segment
    [InlineData("0::\n")]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("0::/a.service\n\n")]
    public void Parse_RefusesAnythingElse(string content) =>
        Assert.Null(PeerIdentity.ParseCgroupV2(Encoding.ASCII.GetBytes(content)));

    [Fact]
    public void Parse_KeepsAPathWithASpace_WhichThenMismatches()
    {
        var path = PeerIdentity.ParseCgroupV2("0::/app.slice/lane1 x.service\n"u8);
        Assert.Equal("/app.slice/lane1 x.service", path);
        var result = BrokerContainerMatch.Check(new BrokerContainerIdentity("/app.slice/lane1.service", null), path!, null);
        Assert.False(result.Allowed);
        Assert.Equal("cgroup-mismatch", result.Reason);
    }

    [Fact]
    public void Parse_DecodesInvalidUtf8WithReplacementCharacters_AndTheResultCanNotMatch()
    {
        byte[] content = [.. "0::/app.slice/lane1"u8, 0xC3, .. ".service\n"u8];
        var path = PeerIdentity.ParseCgroupV2(content);
        Assert.Equal("/app.slice/lane1�.service", path);
        Assert.Equal("cgroup-mismatch", BrokerContainerMatch.Check(new BrokerContainerIdentity("/app.slice/lane1.service", null), path!, null).Reason);
    }

    // ------------------------------------------------------------------ the matcher (D3.6)

    [Theory]
    [InlineData(Unit)]
    [InlineData(Unit + "/libpod-payload-0123")]
    [InlineData(Unit + "/libpod-0123.scope/container")]
    public void Check_EqualOrUnder_IsAllowed(string observed)
    {
        var result = BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, null), observed, null);
        Assert.True(result.Allowed);
        Assert.Null(result.Reason);
        Assert.Equal(observed, result.ObservedCgroup);
    }

    [Theory]
    [InlineData("/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service-x")] // review focus 1
    [InlineData("/user.slice/user-1001.slice/user@1001.service/app.slice/lane10.service")]
    [InlineData("/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service-x/libpod-payload-1")]
    [InlineData("/user.slice/user-1001.slice/user@1001.service/app.slice")]                  // the parent
    [InlineData("/user.slice/user-1001.slice/user@1001.service/app.slice/LANE1.service")]    // ordinal
    [InlineData("/x" + Unit)]                                                                 // not Contains
    public void Check_SiblingsPrefixesAndParents_AreRefused(string observed)
    {
        var result = BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, null), observed, null);
        Assert.False(result.Allowed);
        Assert.Equal("cgroup-mismatch", result.Reason);
    }

    [Fact]
    public void Check_LabelEqual_IsAllowed() =>
        Assert.True(BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, Label), Unit, Label).Allowed);

    [Fact]
    public void Check_LabelDifferent_IsLabelMismatch()
    {
        var result = BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, Label), Unit, "system_u:system_r:container_t:s0:c12,c35");
        Assert.False(result.Allowed);
        Assert.Equal("label-mismatch", result.Reason);
    }

    [Fact]
    public void Check_LabelMissing_IsIdentityUnreadable()
    {
        var result = BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, Label), Unit, null);
        Assert.False(result.Allowed);
        Assert.Equal("identity-unreadable", result.Reason);
    }

    [Fact]
    public void Check_NoLabelBound_IgnoresTheObservedLabel() =>
        Assert.True(BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, null), Unit, "anything:at:all:s0").Allowed);

    [Fact]
    public void Check_CgroupMismatch_WinsOverALabelMismatch() =>
        Assert.Equal("cgroup-mismatch", BrokerContainerMatch.Check(new BrokerContainerIdentity(Unit, Label), "/other.service", "a:b:c:d").Reason);

    // ------------------------------------------------------------------ Observe through the seams (D3.1-5)

    private static readonly BrokerContainerIdentity Bound = new(Unit, Label);

    /// <summary>A peer whose pidfd and directory "fds" are valid-looking handles nobody owns.</summary>
    private static PeerProcess FakePeer(bool pidfd = true) =>
        new(4242, pidfd ? new SafeFileHandle(new IntPtr(100000), ownsHandle: false) : null, new SafeFileHandle(new IntPtr(100001), ownsHandle: false));

    /// <summary>Seams for a peer that passes every step, as uid 100999 in <see cref="Unit"/>'s payload cgroup.</summary>
    private static void AllGood()
    {
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Opened(FakePeer());
        PeerIdentity.ReadStatusUid = _ => 100999;
        PeerIdentity.ReadCgroup = _ => Encoding.ASCII.GetBytes("0::" + Unit + "/libpod-payload-1\n");
        PeerIdentity.ReadPeerLabel = _ => Label;
        PeerIdentity.PidfdAlive = _ => true;
    }

    private static BrokerContainerResult Observe(BrokerContainerIdentity? bound = null)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        return BrokerContainerMatch.Observe(socket, 100999, bound ?? Bound);
    }

    [Fact]
    public void Observe_AllGood_IsAllowed_WithTheObservedFacts()
    {
        AllGood();
        var result = Observe();
        Assert.True(result.Allowed, result.Reason);
        Assert.Equal(Unit + "/libpod-payload-1", result.ObservedCgroup);
        Assert.Equal(Label, result.ObservedLabel);
    }

    [Fact]
    public void Observe_NoPidfd_IsNoPidfd_TheFallbackIsNotAPass()
    {
        AllGood();
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Opened(FakePeer(pidfd: false));
        var result = Observe();
        Assert.False(result.Allowed);
        Assert.Equal("no-pidfd", result.Reason);
    }

    [Fact]
    public void Observe_NoPidfd_AndNoDirectory_IsNoPidfd()
    {
        AllGood();
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Failed(pid: 4242, gotPidfd: false, pidfdAlive: false, errno: 2);
        Assert.Equal("no-pidfd", Observe().Reason);
    }

    [Theory]
    [InlineData(2)]  // ENOENT
    [InlineData(13)] // EACCES
    public void Observe_ProcHiddenWhileThePidfdLives_IsProcHidden(int errno)
    {
        AllGood();
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Failed(pid: 4242, gotPidfd: true, pidfdAlive: true, errno: errno);
        var result = Observe();
        Assert.False(result.Allowed);
        Assert.Equal("proc-hidden", result.Reason);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(13)]
    public void Observe_DirectoryGoneAndPidfdDead_IsPeerExited(int errno)
    {
        AllGood();
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Failed(pid: 4242, gotPidfd: true, pidfdAlive: false, errno: errno);
        Assert.Equal("peer-exited", Observe().Reason);
    }

    [Fact]
    public void Observe_DirectoryFailsWithAnotherErrno_IsIdentityUnreadable()
    {
        AllGood();
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Failed(pid: 4242, gotPidfd: true, pidfdAlive: true, errno: 24); // EMFILE
        Assert.Equal("identity-unreadable", Observe().Reason);
    }

    [Fact]
    public void Observe_StatusUidDiffers_IsRefused()
    {
        AllGood();
        PeerIdentity.ReadStatusUid = _ => 100998;
        var result = Observe();
        Assert.False(result.Allowed);
        Assert.Equal("identity-unreadable", result.Reason);
    }

    [Fact]
    public void Observe_StatusUnreadable_IsIdentityUnreadable()
    {
        AllGood();
        PeerIdentity.ReadStatusUid = _ => null;
        Assert.Equal("identity-unreadable", Observe().Reason);
    }

    [Fact]
    public void Observe_PidfdDeadAfterTheReads_IsPeerExited()
    {
        // Review focus 2: the peer exited (and its pid may be reused) while we read; never admitted.
        AllGood();
        var reads = 0;
        PeerIdentity.ReadCgroup = _ =>
        {
            reads++;
            return Encoding.ASCII.GetBytes("0::" + Unit + "\n");
        };
        PeerIdentity.PidfdAlive = _ =>
        {
            Assert.Equal(1, reads); // checked after the reads
            return false;
        };
        var result = Observe();
        Assert.False(result.Allowed);
        Assert.Equal("peer-exited", result.Reason);
    }

    [Fact]
    public void Observe_CgroupUnparsable_IsIdentityUnreadable()
    {
        AllGood();
        PeerIdentity.ReadCgroup = _ => "1:name=systemd:/x.service\n"u8.ToArray();
        Assert.Equal("identity-unreadable", Observe().Reason);
        PeerIdentity.ReadCgroup = _ => null;
        Assert.Equal("identity-unreadable", Observe().Reason);
    }

    [Fact]
    public void Observe_LabelMissing_WhenBound_IsIdentityUnreadable()
    {
        AllGood();
        PeerIdentity.ReadPeerLabel = _ => null;
        Assert.Equal("identity-unreadable", Observe().Reason);
    }

    [Fact]
    public void Observe_LabelNotBound_IsNeverRead()
    {
        AllGood();
        PeerIdentity.ReadPeerLabel = _ => throw new InvalidOperationException("SO_PEERSEC read without a bound label");
        var result = Observe(new BrokerContainerIdentity(Unit, null));
        Assert.True(result.Allowed, result.Reason);
        Assert.Null(result.ObservedLabel);
    }

    [Fact]
    public void Observe_Mismatches_KeepTheObservedFacts()
    {
        AllGood();
        PeerIdentity.ReadCgroup = _ => "0::/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service-x\n"u8.ToArray();
        var result = Observe();
        Assert.Equal("cgroup-mismatch", result.Reason);
        Assert.Equal("/user.slice/user-1001.slice/user@1001.service/app.slice/lane1.service-x", result.ObservedCgroup);

        AllGood();
        PeerIdentity.ReadPeerLabel = _ => "system_u:system_r:container_t:s0:c1,c2";
        result = Observe();
        Assert.Equal("label-mismatch", result.Reason);
        Assert.Equal("system_u:system_r:container_t:s0:c1,c2", result.ObservedLabel);
    }

    public static TheoryData<string> Steps => ["open", "status", "cgroup", "label", "alive"];

    [Theory]
    [MemberData(nameof(Steps))]
    public void Observe_ASeamThatThrows_IsIdentityUnreadable_NeverPropagated(string step)
    {
        AllGood();
        var boom = new InvalidOperationException("boom");
        switch (step)
        {
            case "open": PeerIdentity.OpenPeerDetailed = _ => throw boom; break;
            case "status": PeerIdentity.ReadStatusUid = _ => throw boom; break;
            case "cgroup": PeerIdentity.ReadCgroup = _ => throw boom; break;
            case "label": PeerIdentity.ReadPeerLabel = _ => throw boom; break;
            case "alive": PeerIdentity.PidfdAlive = _ => throw boom; break;
        }
        var result = Observe();
        Assert.False(result.Allowed);
        Assert.Equal("identity-unreadable", result.Reason);
    }

    // ------------------------------------------------------------------ the real thing (Linux)

    [Fact]
    public async Task Observe_Real_ReturnsThisProcesssOwnCgroup_AndIsAllowedWhenBoundToIt()
    {
        if (!OperatingSystem.IsLinux())
            return; // SO_PEERPIDFD and /proc are Linux; this fails (never skips) on a Linux kernel without SO_PEERPIDFD
        PeerIdentity.ResetSeamsForTests();
        var own = PeerIdentity.ParseCgroupV2(File.ReadAllBytes("/proc/self/cgroup"));
        Assert.NotNull(own);

        var dir = Path.Combine(Path.GetTempPath(), "tswap-cg-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "s.sock");
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(path));
            listener.Listen(1);
            using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await client.ConnectAsync(new UnixDomainSocketEndPoint(path));
            using var accepted = await listener.AcceptAsync();

            var uid = new UnixOwnership().EffectiveUid;
            var result = BrokerContainerMatch.Observe(accepted, uid, new BrokerContainerIdentity(own, null));
            Assert.True(result.Allowed, result.Reason);
            Assert.Equal(own, result.ObservedCgroup);

            var other = BrokerContainerMatch.Observe(accepted, uid, new BrokerContainerIdentity(own + "-x", null));
            Assert.Equal("cgroup-mismatch", other.Reason);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
