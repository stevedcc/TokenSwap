using System.Text;
using TswapCore.Broker.SshAgent;
using Xunit;

namespace TswapTests;

/// <summary>One real OpenSSH session's agent traffic: the client key (test-only), the server host key blob and the client's frames in order.</summary>
public sealed record RecordedSshSession(string Name, string ClientKeyPem, string HostKeyBlob, string[] ClientFrames);

/// <summary>
/// Brief T10 item 3: the frames a real <c>ssh</c> (OpenSSH 10.2p1) sent through a recording relay
/// (<see cref="SshAgentSshdTests.CaptureFixtures_WhenAsked"/>), replayed against the agent. They carry
/// the protocol checks where <c>sshd</c> can't run (CI without it, macOS): items 1 and 2's parsers
/// read real frames, and the bind and sign succeed exactly as in the live run.
/// </summary>
public class SshAgentRecordedFramesTests : IAsyncLifetime
{
    private readonly SshAgentHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    public static TheoryData<string> SessionNames => [.. SshAgentRecordedFrames.Sessions.Select(s => s.Name)];

    private static RecordedSshSession Session(string name) => SshAgentRecordedFrames.Sessions.Single(s => s.Name == name);

    private static byte[] Frame(RecordedSshSession s, int i) => Convert.FromBase64String(s.ClientFrames[i]);

    private async Task<FakeSshKeySource> StartAsync(RecordedSshSession session, string allowedHost)
    {
        var pem = Encoding.ASCII.GetBytes(session.ClientKeyPem);
        var source = new FakeSshKeySource(_ => (byte[])pem.Clone());
        await _h.StartAsync(_h.Config(keys: [("deploy", "client-key", [allowedHost])], lane1Keys: ["deploy"], otherKeys: []),
            policy => new SshAgentOptions { Keys = SshAgentKeyLoader.Load(policy, source), KeySource = source, AllowOwnUidForTests = true });
        return source;
    }

    [Fact]
    public void TheFixturesCoverEveryKeyType()
    {
        Assert.Equal(["ecdsa-client-ecdsa-host", "ed25519-client-ed25519-host", "rsa-client-ed25519-host"], SshAgentRecordedFrames.Sessions.Select(s => s.Name).Order());
        Assert.All(SshAgentRecordedFrames.Sessions, s => Assert.Equal(3, s.ClientFrames.Length));
    }

    [Theory]
    [MemberData(nameof(SessionNames))]
    public void RecordedFrames_ParseAsIdentitiesBindAndAUserauthSignRequest(string name)
    {
        var session = Session(name);
        var keyBlob = SshTestKeyMaker.PublicBlob(Encoding.ASCII.GetBytes(session.ClientKeyPem));
        var hostBlob = Convert.FromBase64String(session.HostKeyBlob);

        // OpenSSH binds the connection first, then lists identities, then signs.
        var bind = new SshReader(Frame(session, 0));
        Assert.Equal(SshAgentProtocol.Extension, bind.ReadByte());
        Assert.Equal(SshAgentProtocol.SessionBindExtension, Encoding.ASCII.GetString(bind.ReadString()));
        Assert.Equal(hostBlob, bind.ReadString().ToArray());
        var sessionId = bind.ReadString().ToArray();
        var hostSignature = bind.ReadString().ToArray();
        Assert.Equal(0, bind.ReadByte()); // not forwarding
        bind.EnsureEnd();
        Assert.Null(SshPublicKey.Parse(hostBlob).VerifyRefusal(sessionId, hostSignature));

        Assert.Equal(SshAgentMessages.RequestIdentities, Frame(session, 1));

        var sign = new SshReader(Frame(session, 2));
        Assert.Equal(SshAgentProtocol.SignRequest, sign.ReadByte());
        Assert.Equal(keyBlob, sign.ReadString().ToArray());
        var data = sign.ReadString().ToArray();
        var flags = sign.ReadUInt32();
        sign.EnsureEnd();
        var type = SshPublicKey.Parse(keyBlob).Type;
        Assert.Null(SshKeySigner.FlagsRefusal(type, flags));
        var key = new SshAgentKey("deploy", "client-key", keyBlob);
        // OpenSSH 10.2 against its own sshd uses the host-bound method (PROTOCOL), which the agent accepts.
        Assert.True(data.AsSpan().IndexOf("publickey-hostbound-v00@openssh.com"u8) >= 0);
        Assert.Null(SshUserauth.Refusal(data, new SshBinding(hostBlob, sessionId, SshFingerprint.Of(hostBlob)), key, flags));
    }

    [Theory]
    [MemberData(nameof(SessionNames))]
    public async Task ReplayedSession_BindsAndSigns_AsInTheLiveRun(string name)
    {
        if (OperatingSystem.IsWindows())
            return;
        var session = Session(name);
        var hostBlob = Convert.FromBase64String(session.HostKeyBlob);
        var source = await StartAsync(session, SshFingerprint.Of(hostBlob));
        var loads = source.Reads;
        using var client = await _h.ConnectAsync("lane1");

        Assert.Equal(new[] { SshAgentProtocol.Success }, await client.RequestAsync(Frame(session, 0)));
        var ids = SshAgentMessages.ParseIdentities((await client.RequestAsync(Frame(session, 1)))!);
        Assert.Equal("deploy", Assert.Single(ids).Comment);
        var reply = await client.RequestAsync(Frame(session, 2));

        var reader = new SshReader(reply);
        Assert.Equal(SshAgentProtocol.SignResponse, reader.ReadByte());
        var signature = reader.ReadString().ToArray();
        reader.EnsureEnd();
        var request = new SshReader(Frame(session, 2));
        request.ReadByte();
        var keyBlob = request.ReadString().ToArray();
        var data = request.ReadString().ToArray();
        Assert.True(SshBindMessages.Verify(keyBlob, data, signature));
        Assert.Equal(1, source.Reads - loads);
    }

    [Theory]
    [MemberData(nameof(SessionNames))]
    public async Task ReplayedSession_WithTheHostNotAllowed_IsRefusedAtTheBind(string name)
    {
        if (OperatingSystem.IsWindows())
            return;
        var session = Session(name);
        var source = await StartAsync(session, SshAgentHarness.SomeHostFingerprint);
        var loads = source.Reads;
        using var client = await _h.ConnectAsync("lane1");

        Assert.Equal(new[] { SshAgentProtocol.ExtensionFailure }, await client.RequestAsync(Frame(session, 0)));
        Assert.True(await client.ClosedWithoutReplyAsync());
        Assert.Equal(0, source.Reads - loads);
    }

    [Theory]
    [MemberData(nameof(SessionNames))]
    public async Task ReplayedSignRequest_WithoutTheBind_IsRefused(string name)
    {
        if (OperatingSystem.IsWindows())
            return;
        var session = Session(name);
        var source = await StartAsync(session, SshFingerprint.Of(Convert.FromBase64String(session.HostKeyBlob)));
        var loads = source.Reads;
        using var client = await _h.ConnectAsync("lane1");

        Assert.Equal(SshAgentProtocol.FailureReply, await client.RequestAsync(Frame(session, 2)));
        Assert.Equal(0, source.Reads - loads);
    }
}
