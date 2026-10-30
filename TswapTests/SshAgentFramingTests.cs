using System.Buffers.Binary;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T10 item 1: the agent protocol's framing and identities, on a real Unix socket
/// (<c>&lt;name&gt;.ssh.sock</c>), with messages built by the test.
/// </summary>
public class SshAgentFramingTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;
    private readonly SshAgentHarness _h = new();

    private static readonly byte[] K1 = SshAgentMessages.Ed25519Blob(1);
    private static readonly byte[] K2 = SshAgentMessages.Ed25519Blob(2);
    private static readonly byte[] K3 = SshAgentMessages.Ed25519Blob(3);

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private static SshAgentOptions Agent(BrokerPolicy policy) => new()
    {
        Keys = new Dictionary<string, SshAgentKey>
        {
            ["k1"] = new("k1", "key-one", K1),
            ["k2"] = new("k2", "key-two", K2),
            ["k3"] = new("k3", "key-three", K3),
        },
        KeySource = new FakeSshKeySource(_ => null),
    };

    private Task StartAsync(string? config = null, bool allowOwnUid = true) =>
        _h.StartAsync(config ?? _h.Config(), Agent, allowOwnUid: allowOwnUid);

    [Fact]
    public async Task Identities_ListOnlyTheKeysOnThisSocketsAllowList()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync(_h.Config(lane1Keys: ["k1"], otherKeys: ["k2", "k3"]));

        using var lane1 = await _h.ConnectAsync("lane1");
        var ids = SshAgentMessages.ParseIdentities((await lane1.RequestAsync(SshAgentMessages.RequestIdentities))!);
        using var other = await _h.ConnectAsync("other");
        var otherIds = SshAgentMessages.ParseIdentities((await other.RequestAsync(SshAgentMessages.RequestIdentities))!);

        var only = Assert.Single(ids);
        Assert.Equal(K1, only.Blob);
        Assert.Equal("k1", only.Comment); // the comment is the key's name only
        Assert.Equal([K2, K3], otherIds.Select(i => i.Blob));
        Assert.Equal(["k2", "k3"], otherIds.Select(i => i.Comment));
    }

    [Fact]
    public async Task OnlySocketsWithKeys_GetAnAgentSocket_ConnectableByAnyone()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();

        Assert.True(File.Exists(_h.AgentSocket("lane1")));
        Assert.True(File.Exists(_h.AgentSocket("other")));
        Assert.False(File.Exists(_h.AgentSocket("plain")));
        Assert.Equal(Path.Combine(_h.Broker.SocketDir, "lane1.ssh.sock"), _h.AgentSocket("lane1"));
        Assert.Equal((UnixFileMode)0b110_110_110, File.GetUnixFileMode(_h.AgentSocket("lane1")));
    }

    [Theory]
    [InlineData(SshAgentProtocol.AddIdentity)]
    [InlineData(SshAgentProtocol.RemoveIdentity)]
    [InlineData(SshAgentProtocol.RemoveAllIdentities)]
    [InlineData(SshAgentProtocol.AddSmartcardKey)]
    [InlineData(SshAgentProtocol.RemoveSmartcardKey)]
    [InlineData(SshAgentProtocol.Lock)]
    [InlineData(SshAgentProtocol.Unlock)]
    [InlineData(SshAgentProtocol.AddIdConstrained)]
    [InlineData(SshAgentProtocol.AddSmartcardKeyConstrained)]
    [InlineData(1)]   // SSH-1 request identities (reserved)
    [InlineData(99)]  // unknown
    public async Task RefusedRequestType_GetsFailure_AndTheConnectionStaysOpen(byte type)
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");

        var reply = await client.RequestAsync([type, 0, 0, 0, 4, (byte)'a', (byte)'b', (byte)'c', (byte)'d']);

        Assert.Equal(SshAgentProtocol.FailureReply, reply);
        // Still open: the next request is answered.
        Assert.Single(SshAgentMessages.ParseIdentities((await client.RequestAsync(SshAgentMessages.RequestIdentities))!));
    }

    [Theory]
    [InlineData("query")]
    [InlineData("restrict-destination-v00@openssh.com")]
    [InlineData("session-bind@openssh.comX")]
    public async Task UnknownExtension_GetsFailure_AndTheConnectionStaysOpen(string name)
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");

        var reply = await client.RequestAsync(new SshWriter().Byte(SshAgentProtocol.Extension).String(name).ToArray());

        Assert.Equal(SshAgentProtocol.FailureReply, reply); // RFC 9987 §5.8: not SSH_AGENT_EXTENSION_FAILURE
        Assert.Single(SshAgentMessages.ParseIdentities((await client.RequestAsync(SshAgentMessages.RequestIdentities))!));
    }

    [Fact]
    public async Task IdentitiesRequestWithTrailingBytes_GetsFailure()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");

        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync([SshAgentProtocol.RequestIdentities, 0]));
    }

    [Theory]
    [InlineData(SshAgentProtocol.MaxMessageLength + 1)]
    [InlineData(uint.MaxValue)]
    [InlineData(0)]
    public async Task OversizeOrEmptyFrame_ClosesTheConnection_Unanswered(uint length)
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var header = new byte[5];
        BinaryPrimitives.WriteUInt32BigEndian(header, length);
        header[4] = SshAgentProtocol.RequestIdentities;

        await client.SendRawAsync(header);

        Assert.True(await client.ClosedWithoutReplyAsync());
        await _h.Broker.WaitForLogAsync("ssh-connection socket=lane1.ssh");
        Assert.Contains("reason=frame-length", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task MaximumSizeFrame_IsReadAndAnswered()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");
        var body = new byte[SshAgentProtocol.MaxMessageLength];
        body[0] = SshAgentProtocol.AddIdentity;

        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(body));
    }

    [Fact]
    public async Task TruncatedFrame_ClosesTheConnection_Unanswered()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();
        using var client = await _h.ConnectAsync("lane1");

        await client.SendRawAsync([0, 0, 0, 10, SshAgentProtocol.RequestIdentities, 1, 2]);
        client.Socket.Shutdown(System.Net.Sockets.SocketShutdown.Send);

        Assert.True(await client.ClosedWithoutReplyAsync());
        await _h.Broker.WaitForLogAsync("reason=truncated");
    }

    [Fact]
    public async Task UidNotOnTheList_IsClosedBeforeAnythingIsParsed_AndLogged()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var otherUid = BrokerHarness.MyUid == 0 ? 1u : BrokerHarness.MyUid - 1;
        await StartAsync(_h.Config(lane1Uids: $"\"{otherUid}\""));
        using var client = await _h.ConnectAsync("lane1");

        await client.SendFrameAsync(SshAgentMessages.RequestIdentities);

        Assert.True(await client.ClosedWithoutReplyAsync());
        await _h.Broker.WaitForLogAsync("refused-connection socket=lane1.ssh");
        Assert.Contains($"refused-connection socket=lane1.ssh uid={BrokerHarness.MyUid} pid={Environment.ProcessId} reason=uid-not-allowed", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task ThePeerWithTheBrokersOwnUid_IsClosed()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync(allowOwnUid: false);
        using var client = await _h.ConnectAsync("lane1");

        await client.SendFrameAsync(SshAgentMessages.RequestIdentities);

        Assert.True(await client.ClosedWithoutReplyAsync());
        await _h.Broker.WaitForLogAsync("refused-connection socket=lane1.ssh");
        Assert.Contains("reason=own-uid", _h.Broker.LogText.ToString());
    }

    [Fact]
    public async Task AReloadThatDropsTheUid_ClosesAnOpenConnection_AtItsNextRequest()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        var server = await _h.StartAsync(_h.Config(), p => Agent(p));
        using var client = await _h.ConnectAsync("lane1");
        Assert.Single(SshAgentMessages.ParseIdentities((await client.RequestAsync(SshAgentMessages.RequestIdentities))!));

        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(lane1Uids: $"\"{BrokerHarness.MyUid + 1}\""))));
        await client.SendFrameAsync(SshAgentMessages.RequestIdentities);

        Assert.True(await client.ClosedWithoutReplyAsync());
    }

    [Fact]
    public async Task StopRemovesTheAgentSockets()
    {
        if (SshTestSkip.OnWindows(_output))
            return;
        await StartAsync();

        await _h.Server!.StopAsync();

        Assert.False(File.Exists(_h.AgentSocket("lane1")));
        Assert.False(File.Exists(_h.AgentSocket("other")));
    }
}
