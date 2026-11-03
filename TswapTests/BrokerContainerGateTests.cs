using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief I224 task 3, end to end (Linux): an in-process <c>serve</c> with a socket bound to a container,
/// and a client in a cgroup D1 accepts (<see cref="BrokerContainerClient"/>: a transient systemd scope
/// running <c>tswap broker forward</c>, or this process's own cgroup). Each test writes which client path it
/// took.
/// </summary>
[Trait("Category", "E2E")]
public sealed class BrokerContainerGateEndToEndTests : IClassFixture<TswapBinaryFixture>, IAsyncLifetime
{
    private readonly string _binary;
    private readonly ITestOutputHelper _output;
    private readonly BrokerHarness _h = new();
    private readonly List<BrokerContainerClient> _clients = [];
    private BrokerServer? _server;
    private BrokerPolicyHolder? _holder;
    private readonly TaskCompletionSource<BrokerPeer> _admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>A valid unit path no test process is in.</summary>
    private const string Elsewhere = "/user.slice/user-1000.slice/user@1000.service/app.slice/tswap-test-nobody.scope";

    private static readonly byte[] K1 = SshAgentMessages.Ed25519Blob(1);

    public BrokerContainerGateEndToEndTests(TswapBinaryFixture binary, ITestOutputHelper output)
    {
        _binary = binary.BinaryPath;
        _output = output;
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (var c in _clients)
            await c.DisposeAsync();
        if (_server is not null)
            await _server.StopAsync();
        await _h.DisposeAsync();
    }

    private static string Binding(string? cgroup) =>
        cgroup is null ? "\"uid_only\": true" : $"\"container\": {{ \"cgroup\": {JsonSerializer.Serialize(cgroup)} }}";

    /// <summary>One socket <c>lane1</c> (this uid, route <c>echo</c>, ssh key <c>k1</c>) bound to <paramref name="cgroup"/> (null: uid-only).</summary>
    private string Config(string? cgroup) => $$"""
        {
          "version": 1,
          "socket_dir": {{JsonSerializer.Serialize(_h.SocketDir)}},
          "sockets": [ { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": ["echo"], "ssh_keys": ["k1"], {{Binding(cgroup)}} } ],
          "routes": [ { "name": "echo", "upstream": "https://upstream.example/base", "auth": { "type": "bearer", "secret": "{{"{{tok}}"}}" }, "path": "" } ],
          "ssh_keys": [ { "name": "k1", "secret": "key-one", "allowed_host_keys": ["{{SshAgentHarness.SomeHostFingerprint}}"] } ]
        }
        """;

    private async Task StartAsync(string? cgroup, Action? beforeIdentityRead = null)
    {
        var policy = BrokerPolicy.Parse(Config(cgroup));
        _holder = new BrokerPolicyHolder(policy);
        _server = await BrokerServer.StartAsync(_h.Options() with
        {
            Policy = _holder,
            SshAgent = new SshAgentOptions
            {
                Keys = new Dictionary<string, SshAgentKey> { ["k1"] = new("k1", "key-one", K1) },
                KeySource = new FakeSshKeySource(_ => null),
            },
            OnAdmittedForTests = peer => _admitted.TrySetResult(peer),
            BeforeIdentityReadForTests = beforeIdentityRead,
        });
    }

    private void Reload(string? cgroup) => Assert.True(_server!.Reload(() => BrokerPolicy.Parse(Config(cgroup))));

    private string Log => _h.LogText.ToString();

    private async Task<BrokerContainerClient?> ClientAsync(string target, bool requireScope = false, bool @delegate = false)
    {
        if (!OperatingSystem.IsLinux())
            return null; // SO_PEERPIDFD and /proc: Linux only
        var client = await BrokerContainerClient.StartAsync(_binary, target, reason => _output.WriteLine($"SKIPPED: {reason}"),
            requireScope, @delegate);
        if (client is null)
            return null;
        _clients.Add(client);
        _output.WriteLine($"client path: {client.Mode} ({client.Cgroup})");
        return client;
    }

    /// <summary>
    /// Sends <paramref name="request"/> and reads until the broker closes. A gate refusal can close the connection
    /// before the request is written (EPIPE/ECONNRESET on the send): that is zero response bytes too.
    /// </summary>
    internal static async Task<byte[]> ExchangeAsync(Socket socket, string request)
    {
        try
        {
            await socket.SendAsync(Encoding.ASCII.GetBytes(request));
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.Shutdown or SocketError.ConnectionReset)
        {
            return [];
        }
        var received = new MemoryStream();
        var buffer = new byte[8192];
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // a hang fails the test
        while (true)
        {
            int n;
            try
            {
                n = await socket.ReceiveAsync(buffer, SocketFlags.None, guard.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                break;
            }
            if (n == 0)
                break;
            received.Write(buffer, 0, n);
        }
        return received.ToArray();
    }

    private const string Get = "GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\n";

    // 1
    [Fact]
    public async Task BoundToTheClientsCgroup_TheRequestIsForwarded()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(client.Cgroup);
        using var socket = await client.ConnectAsync();
        var text = Encoding.ASCII.GetString(await ExchangeAsync(socket, Get));
        Assert.StartsWith("HTTP/1.1 200", text);
        Assert.EndsWith("ok https://upstream.example/base/a", text);
        Assert.Equal(1, _h.FakeForwarder.Calls);
        Assert.Equal(client.Cgroup, (await _admitted.Task).Cgroup);
        Assert.DoesNotContain("refused-connection", Log);
    }

    // 2
    [Fact]
    public async Task BoundToAnotherUnit_TheConnectionIsClosedUnanswered_AndTheObservedPathIsLogged()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(Elsewhere);
        using var socket = await client.ConnectAsync();
        Assert.Empty(await ExchangeAsync(socket, Get));
        Assert.Equal(0, _h.FakeForwarder.Calls);
        Assert.Equal(0, _h.Secrets.Unlocks);
        await _h.WaitForLogAsync("reason=cgroup-mismatch");
        Assert.Contains($"refused-connection socket=lane1 uid={BrokerHarness.MyUid} ", Log);
        Assert.Contains($"reason=cgroup-mismatch cgroup=\"{client.Cgroup}\"", Log);
    }

    // 2b: review focus 5
    [Fact]
    public async Task ReviewFocus5_AHostProcessWithAListedUid_OutsideTheBoundScope_IsRefusedCgroupMismatch()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1"), requireScope: true) is not { } scope)
            return;
        await StartAsync(scope.Cgroup);
        // The client is this test process itself: the same uid, but not in the scope.
        using (var direct = await ConnectUnixAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1")))
            Assert.Empty(await ExchangeAsync(direct, Get));
        Assert.Equal(0, _h.FakeForwarder.Calls);
        await _h.WaitForLogAsync("reason=cgroup-mismatch");
        Assert.Contains($"reason=cgroup-mismatch cgroup=\"{BrokerContainerClient.OwnCgroup()}\"", Log);
    }

    // 3
    [Fact]
    public async Task TheSshAgentSocketOfAMismatchingSocket_ClosesBeforeTheFirstFrame()
    {
        if (await ClientAsync(SshAgentListener.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(Elsewhere);
        using var agent = new SshAgentTestClient(await client.ConnectAsync());
        await agent.SendFrameAsync(SshAgentMessages.RequestIdentities);
        Assert.True(await agent.ClosedWithoutReplyAsync());
        await _h.WaitForLogAsync("reason=cgroup-mismatch");
        Assert.Contains($"refused-connection socket=lane1.ssh uid={BrokerHarness.MyUid} ", Log);
        Assert.Contains($"cgroup=\"{client.Cgroup}\"", Log);
    }

    // 5, HTTP
    [Fact]
    public async Task ARebindAfterAcceptAndBeforeTheRequest_GetsZeroResponseBytes()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(client.Cgroup);
        using var socket = await client.ConnectAsync();
        await socket.SendAsync(Array.Empty<byte>());
        var admitted = await _admitted.Task.WaitAsync(TimeSpan.FromSeconds(30)); // accepted by the gate, with its identity
        Assert.Equal(client.Cgroup, admitted.Cgroup);

        Reload(Elsewhere);

        Assert.Empty(await ExchangeAsync(socket, Get));
        Assert.Equal(0, _h.FakeForwarder.Calls);
        await _h.WaitForLogAsync("reason=cgroup-mismatch");
        Assert.Contains($"reason=cgroup-mismatch cgroup=\"{client.Cgroup}\"", Log);
    }

    // 5, HTTP: unbind after accept (I224 fix round 1, MiMo p1 M3 / GLM p1 m5)
    [Fact]
    public async Task AnUnbindAfterAcceptAndBeforeTheRequest_IsForwarded()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(client.Cgroup);
        using var socket = await client.ConnectAsync();
        await socket.SendAsync(Array.Empty<byte>());
        var admitted = await _admitted.Task.WaitAsync(TimeSpan.FromSeconds(30)); // accepted by the gate, with its identity
        Assert.Equal(client.Cgroup, admitted.Cgroup);

        Reload(null);

        var text = Encoding.ASCII.GetString(await ExchangeAsync(socket, Get));
        Assert.StartsWith("HTTP/1.1 200", text);
        Assert.EndsWith("ok https://upstream.example/base/a", text);
        Assert.Equal(1, _h.FakeForwarder.Calls);
        Assert.DoesNotContain("refused-connection", Log);
    }

    // Review focus 2, end to end (I224 fix round 1, MiMo p1 M3)
    [Fact]
    public async Task AClientThatConnectsAndExits_IsRefused_AndNothingIsForwarded()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1"), requireScope: true) is not { } client)
            return;
        var atTheGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var exited = new ManualResetEventSlim();
        await StartAsync(client.Cgroup, beforeIdentityRead: () =>
        {
            atTheGate.TrySetResult();
            exited.Wait(TimeSpan.FromSeconds(30)); // a failing test can't hold the gate for longer
        });
        try
        {
            using var socket = await client.ConnectAsync();
            await socket.SendAsync(Encoding.ASCII.GetBytes(Get));
            await atTheGate.Task.WaitAsync(TimeSpan.FromSeconds(30)); // the relay's connection, its identity not read yet

            // The connecting process (the relay) exits and is reaped while its connection waits at the gate.
            await client.DisposeAsync();
            _clients.Remove(client);
            exited.Set();

            Assert.Empty(await ExchangeAsync(socket, ""));
            await _h.WaitForLogAsync("refused-connection socket=lane1 ");
        }
        finally
        {
            exited.Set();
        }
        Assert.False(_admitted.Task.IsCompleted); // never admitted
        Assert.Equal(0, _h.FakeForwarder.Calls);
        Assert.Equal(0, _h.Secrets.Unlocks);
        // peer-exited: the pidfd is dead. A kernel that gives no pidfd for an exited peer refuses no-pidfd;
        // a reused pid would show another cgroup. Each is a refusal; an admission is not.
        Assert.Matches("refused-connection socket=lane1 uid=[0-9]+ pid=[0-9]+ reason=(peer-exited|no-pidfd|cgroup-mismatch)", Log);
        _output.WriteLine($"refusal: {System.Text.RegularExpressions.Regex.Match(Log, "reason=[a-z-]+").Value}");
    }

    // Review focus 1, end to end (I224 fix round 1, MiMo p1 M3): a sibling whose name has the bound unit as a prefix
    [Fact]
    public async Task BoundToAPrefixOfTheClientsCgroupName_IsRefusedCgroupMismatch()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1"), requireScope: true, @delegate: true) is not { } client)
            return;
        // The client moves into <scope>/lane1.service-x; the socket is bound to <scope>/lane1.service, a bare
        // string prefix of the client's path but not its folder.
        var sibling = Path.Combine("/sys/fs/cgroup" + client.Cgroup, "lane1.service-x");
        try
        {
            Directory.CreateDirectory(sibling);
            File.WriteAllText(Path.Combine(sibling, "cgroup.procs"), client.RelayPid!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _output.WriteLine($"SKIPPED: can't create a child cgroup under {client.Cgroup} (no cgroup delegation): {ex.Message}");
            return;
        }
        try
        {
            await StartAsync(client.Cgroup + "/lane1.service");
            using var socket = await client.ConnectAsync();
            Assert.Empty(await ExchangeAsync(socket, Get));
            Assert.Equal(0, _h.FakeForwarder.Calls);
            await _h.WaitForLogAsync("reason=cgroup-mismatch");
            Assert.Contains($"reason=cgroup-mismatch cgroup=\"{client.Cgroup}/lane1.service-x\"", Log);
        }
        finally
        {
            await client.DisposeAsync(); // the relay leaves the child cgroup empty, so it can go
            _clients.Remove(client);
            RemoveEmptiedChildCgroup(sibling);
        }
    }

    /// <summary>
    /// Removes a child cgroup once its last process is gone (I224 round 2, G4): rmdir fails with EBUSY
    /// (an IOException) while <c>cgroup.procs</c> still lists a process the kernel hasn't finished moving out,
    /// so it waits for that file to read empty (bounded) and tries again. Gone already (systemd removed the
    /// emptied scope with its child) is fine.
    /// </summary>
    private static void RemoveEmptiedChildCgroup(string dir)
    {
        bool Emptied()
        {
            try
            {
                return File.ReadAllText(Path.Combine(dir, "cgroup.procs")).Trim().Length == 0;
            }
            catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException)
            {
                return true; // gone with its scope
            }
        }
        for (var attempt = 0; ; attempt++)
        {
            Assert.True(SpinWait.SpinUntil(Emptied, TimeSpan.FromSeconds(10)), $"{dir} still has processes after 10 s");
            try
            {
                Directory.Delete(dir);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                return; // systemd already removed the emptied transient scope, with its child
            }
            catch (IOException) when (attempt < 3)
            {
                // EBUSY: a process was still being moved out when rmdir ran; wait for cgroup.procs again
            }
        }
    }

    // 5, ssh: rebind between two messages
    [Fact]
    public async Task ARebindBetweenTwoSshMessages_RefusesTheSecond()
    {
        if (await ClientAsync(SshAgentListener.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(client.Cgroup);
        using var agent = new SshAgentTestClient(await client.ConnectAsync());
        Assert.Single(SshAgentMessages.ParseIdentities((await agent.RequestAsync(SshAgentMessages.RequestIdentities))!));

        Reload(Elsewhere);

        await agent.SendFrameAsync(SshAgentMessages.RequestIdentities);
        Assert.True(await agent.ClosedWithoutReplyAsync());
        await _h.WaitForLogAsync("reason=cgroup-mismatch");
        Assert.Contains($"refused-connection socket=lane1.ssh uid={BrokerHarness.MyUid} ", Log);
    }

    // 5, ssh: unbind between two messages
    [Fact]
    public async Task AnUnbindBetweenTwoSshMessages_AnswersTheSecond()
    {
        if (await ClientAsync(SshAgentListener.SocketPath(_h.SocketDir, "lane1")) is not { } client)
            return;
        await StartAsync(client.Cgroup);
        using var agent = new SshAgentTestClient(await client.ConnectAsync());
        Assert.Single(SshAgentMessages.ParseIdentities((await agent.RequestAsync(SshAgentMessages.RequestIdentities))!));

        Reload(null);

        Assert.Single(SshAgentMessages.ParseIdentities((await agent.RequestAsync(SshAgentMessages.RequestIdentities))!));
        Assert.DoesNotContain("refused-connection", Log);
    }

    // 5, ssh: a uid-only socket bound between two messages (r3 MiMo R1)
    [Fact]
    public async Task BindingAUidOnlySocketBetweenTwoSshMessages_RefusesTheSecond_IdentityUnreadable()
    {
        if (!OperatingSystem.IsLinux())
            return;
        await StartAsync(null);
        using var agent = new SshAgentTestClient(await ConnectUnixAsync(SshAgentListener.SocketPath(_h.SocketDir, "lane1")));
        Assert.Single(SshAgentMessages.ParseIdentities((await agent.RequestAsync(SshAgentMessages.RequestIdentities))!));
        Assert.Null((await _admitted.Task).Cgroup); // accepted with no stored identity

        Reload(Elsewhere);

        await agent.SendFrameAsync(SshAgentMessages.RequestIdentities);
        Assert.True(await agent.ClosedWithoutReplyAsync());
        await _h.WaitForLogAsync("reason=identity-unreadable");
        Assert.Contains($"refused-connection socket=lane1.ssh uid={BrokerHarness.MyUid} ", Log);
    }

    // 5, HTTP: a uid-only socket bound after accept (r3 MiMo R1)
    [Fact]
    public async Task BindingAUidOnlySocketAfterAccept_RefusesTheRequest_IdentityUnreadable()
    {
        if (!OperatingSystem.IsLinux())
            return;
        await StartAsync(null);
        using var socket = await ConnectUnixAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1"));
        await _admitted.Task.WaitAsync(TimeSpan.FromSeconds(30));

        Reload(Elsewhere);

        Assert.Empty(await ExchangeAsync(socket, Get));
        Assert.Equal(0, _h.FakeForwarder.Calls);
        await _h.WaitForLogAsync("reason=identity-unreadable");
    }

    // 7
    [Fact]
    public async Task AProcessInAChildCgroupOfTheBoundUnit_IsAdmitted()
    {
        if (await ClientAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1"), requireScope: true, @delegate: true) is not { } client)
            return;
        var child = Path.Combine("/sys/fs/cgroup" + client.Cgroup, "tswap-child");
        try
        {
            Directory.CreateDirectory(child);
            File.WriteAllText(Path.Combine(child, "cgroup.procs"), client.RelayPid!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _output.WriteLine($"SKIPPED: can't create a child cgroup under {client.Cgroup} (no cgroup delegation): {ex.Message}");
            return;
        }
        try
        {
            await StartAsync(client.Cgroup);
            using var socket = await client.ConnectAsync();
            var text = Encoding.ASCII.GetString(await ExchangeAsync(socket, Get));
            Assert.StartsWith("HTTP/1.1 200", text);
            Assert.Equal(client.Cgroup + "/tswap-child", (await _admitted.Task).Cgroup);
        }
        finally
        {
            await client.DisposeAsync(); // the relay leaves the child cgroup empty, so it can go
            _clients.Remove(client);
            try
            {
                Directory.Delete(child);
            }
            catch (DirectoryNotFoundException)
            {
                // systemd already removed the emptied transient scope, with its child
            }
        }
    }

    internal static async Task<Socket> ConnectUnixAsync(string path)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path));
        return socket;
    }
}

/// <summary>
/// Brief I224 task 3 through <see cref="PeerIdentity"/>'s seams: the once-per-serve <c>proc-hidden</c> event and
/// the escaping and cap of an attacker-influenced observed cgroup in the log.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class BrokerContainerGateSeamTests : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();
    private BrokerServer? _server;
    private const string Unit = "/user.slice/user-1000.slice/user@1000.service/app.slice/lane1.service";

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        PeerIdentity.ResetSeamsForTests();
        if (_server is not null)
            await _server.StopAsync();
        await _h.DisposeAsync();
    }

    private async Task StartAsync()
    {
        var holder = new BrokerPolicyHolder(BrokerPolicy.Parse($$"""
            {
              "version": 1,
              "socket_dir": {{JsonSerializer.Serialize(_h.SocketDir)}},
              "sockets": [ { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": ["echo"], "container": { "cgroup": "{{Unit}}" } } ],
              "routes": [ { "name": "echo", "upstream": "https://upstream.example/base", "auth": { "type": "bearer", "secret": "{{"{{tok}}"}}" }, "path": "" } ]
            }
            """));
        _server = await BrokerServer.StartAsync(_h.Options() with
        {
            Policy = holder,
            ContainerHost = BrokerContainerHost.Real with { IsLinux = () => true, PeerPidfdAvailable = () => true, ReadOwnCgroup = () => "0::/a.service\n"u8.ToArray() },
        });
    }

    private const string Get = "GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\n";

    private async Task<byte[]> RefusedAsync()
    {
        using var socket = await BrokerContainerGateEndToEndTests.ConnectUnixAsync(BrokerServer.SocketPath(_h.SocketDir, "lane1"));
        return await BrokerContainerGateEndToEndTests.ExchangeAsync(socket, Get);
    }

    [Fact]
    public async Task ProcHidden_IsRefused_AndTheHidepidEventIsLoggedOncePerServe()
    {
        if (OperatingSystem.IsWindows())
            return;
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Failed(4242, gotPidfd: true, pidfdAlive: true, errno: 13);
        await StartAsync();
        Assert.Empty(await RefusedAsync());
        Assert.Empty(await RefusedAsync());
        await _h.WaitForLogAsync("reason=proc-hidden");
        var log = _h.LogText.ToString();
        Assert.Equal(2, log.Split("reason=proc-hidden").Length - 1);
        const string hint = "event can't see client processes in /proc (hidepid?): mount /proc with gid=<group> and add the vault user to it";
        Assert.Equal(1, log.Split(hint).Length - 1);
        Assert.Equal(0, _h.FakeForwarder.Calls);
    }

    [Fact]
    public async Task AnObservedCgroup_IsEscapedThenCappedAt256_InTheLog()
    {
        if (OperatingSystem.IsWindows())
            return;
        var hostile = "/evil\nrequest socket=lane1 \"x\\" + new string('a', 400);
        PeerIdentity.OpenPeerDetailed = _ => PeerOpenResult.Opened(new PeerProcess(4242,
            new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(100000), ownsHandle: false),
            new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(100001), ownsHandle: false)));
        PeerIdentity.ReadStatusUid = _ => BrokerHarness.MyUid;
        PeerIdentity.ReadCgroup = _ => Encoding.UTF8.GetBytes("0::" + hostile.Replace("\n", "\u2028") + "\n");
        PeerIdentity.PidfdAlive = _ => true;
        await StartAsync();
        Assert.Empty(await RefusedAsync());
        await _h.WaitForLogAsync("reason=cgroup-mismatch");
        var line = _h.LogText.ToString().Split('\n').Single(l => l.Contains("reason=cgroup-mismatch"));
        var value = line[(line.IndexOf("cgroup=\"", StringComparison.Ordinal) + "cgroup=\"".Length)..].TrimEnd('\r');
        Assert.EndsWith("\"", value);
        value = value[..^1];
        Assert.StartsWith("/evil\\u2028request socket=lane1 \\\"x\\\\aaa", value);
        Assert.Equal(BrokerLog.MaxObservedLength, value.Length);
    }
}

/// <summary>Brief I224 H5, the request handler's half: an exception escaping it is the uniform 502, logged once by type.</summary>
public sealed class BrokerInternalErrorTests : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private sealed class ThrowingForwarder : IBrokerForwarder
    {
        public Task<BrokerForwardOutcome> ForwardAsync(HttpContext http, BrokerForwardRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("secret-looking message s3cr3t");
    }

    [Fact]
    public async Task AForwarderThatThrows_GetsTheUniform502_AndOneInternalErrorLine()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync(forwarder: new ThrowingForwarder());
        var thrown = await _h.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\n");

        // The uniform 502 of another failure, at the same (manual) clock time.
        _h.Secrets = new FakeBrokerSecrets(_ => throw new BrokerSecretException("unusable"));
        await _h.Server!.StopAsync();
        await _h.StartAsync();
        var uniform = await _h.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 502", Encoding.ASCII.GetString(uniform));
        Assert.Equal(Encoding.ASCII.GetString(uniform), Encoding.ASCII.GetString(thrown));
        var log = _h.LogText.ToString();
        Assert.Equal(1, log.Split("reason=internal-error").Length - 1);
        Assert.Contains("status=502 bytes_in=0 bytes_out=0 unlocks=1", log);
        Assert.Contains("reason=internal-error type=InvalidOperationException", log);
        Assert.DoesNotContain("secret-looking", log);
        Assert.DoesNotContain("s3cr3t", log);
    }

    /// <summary>A response body whose every write fails, as a connection that went away mid-answer.</summary>
    private sealed class FailingBody : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new IOException("the client went away");
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new IOException("the client went away"));
    }

    /// <summary>Throws after making the uniform 502's write fail too (I224 fix round 1, F2).</summary>
    private sealed class ThrowingForwarderWithAFailingBody : IBrokerForwarder
    {
        public Task<BrokerForwardOutcome> ForwardAsync(HttpContext http, BrokerForwardRequest request, CancellationToken cancellationToken)
        {
            http.Response.Body = new FailingBody();
            throw new InvalidOperationException("secret-looking message s3cr3t");
        }
    }

    /// <summary>
    /// Starts a 200 answer, then throws (I224 fix round 1, F2: the log shows the status that was sent).
    /// Sends the 200 headers, then throws once the client has read them (<see cref="HeadersRead"/>). Without that
    /// wait the throw could abort the connection before Kestrel had written the headers to the socket (FlushAsync
    /// doesn't promise that); macOS CI then read nothing (PR #232, run 41697297718).
    /// </summary>
    private sealed class ThrowingForwarderAfterTheHeaders : IBrokerForwarder
    {
        public TaskCompletionSource HeadersRead { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<BrokerForwardOutcome> ForwardAsync(HttpContext http, BrokerForwardRequest request, CancellationToken cancellationToken)
        {
            http.Response.StatusCode = 200;
            await http.Response.StartAsync(cancellationToken);
            await http.Response.Body.FlushAsync(cancellationToken);
            await HeadersRead.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
            throw new InvalidOperationException("secret-looking message s3cr3t");
        }
    }

    /// <summary>The one <c>internal-error</c> line of the log (fails when there are none or several).</summary>
    private string TheInternalErrorLine() =>
        Assert.Single(_h.LogText.ToString().Split('\n'), line => line.Contains("reason=internal-error", StringComparison.Ordinal));

    [Fact]
    public async Task AForwarderThatThrows_WhenThe502CantBeWrittenEither_AbortsTheConnection_AndLogsOnce()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync(forwarder: new ThrowingForwarderWithAFailingBody());

        // Connection: close, so a Kestrel 500 (keep-alive otherwise) would end the exchange and show.
        var response = await _h.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n");

        Assert.Equal("", Encoding.ASCII.GetString(response)); // aborted unanswered: no 502, and no Kestrel 500
        await _h.WaitForLogAsync("reason=internal-error");
        var line = TheInternalErrorLine();
        Assert.Contains(" status=502 ", line);
        Assert.Contains("reason=internal-error type=InvalidOperationException", line);
        Assert.DoesNotContain("s3cr3t", _h.LogText.ToString());
    }

    [Fact]
    public async Task AForwarderThatThrowsAfterTheHeaders_AbortsTheConnection_AndLogsTheStatusSent()
    {
        if (OperatingSystem.IsWindows())
            return;
        var forwarder = new ThrowingForwarderAfterTheHeaders();
        await _h.StartAsync(forwarder: forwarder);

        // Read the headers first, then let the forwarder throw, then read to the end (abort or close).
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_h.SocketPath("lane1")));
        await client.SendAsync(Encoding.ASCII.GetBytes("GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\n"));
        var received = new MemoryStream();
        var buffer = new byte[8192];
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // a hang fails the test
        while (true)
        {
            int n;
            try
            {
                n = await client.ReceiveAsync(buffer, SocketFlags.None, guard.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                break;
            }
            if (n == 0)
                break;
            received.Write(buffer, 0, n);
            if (Encoding.ASCII.GetString(received.ToArray()).Contains("\r\n\r\n", StringComparison.Ordinal))
                forwarder.HeadersRead.TrySetResult();
        }
        var response = Encoding.ASCII.GetString(received.ToArray());

        Assert.StartsWith("HTTP/1.1 200", response);
        Assert.Contains("\r\n\r\n", response); // the whole header block arrived, so the forwarder threw its own exception
        Assert.DoesNotContain("502", response);
        Assert.DoesNotContain("\r\n0\r\n\r\n", response); // aborted: the chunked body never ends
        await _h.WaitForLogAsync("reason=internal-error");
        var line = TheInternalErrorLine();
        Assert.Contains(" status=200 ", line);
        Assert.Contains("reason=internal-error type=InvalidOperationException", line);
    }
}
