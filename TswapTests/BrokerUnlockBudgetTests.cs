using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T13 item 2: a per-socket unlock budget (<see cref="BrokerLimits.MaxUnlocksPerSocketPerMinute"/>
/// = 20) under the unchanged global one (30). The check order is <c>locked-out</c>, then
/// <c>socket-unlock-rate</c>, then <c>unlock-rate</c>; the reason is log-only, and the caller gets
/// the same uniform refusal as for the global limit.
/// </summary>
public class BrokerUnlockBudgetTests(ITestOutputHelper output) : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private static string J(string s) => JsonSerializer.Serialize(s);

    /// <summary>Fills <paramref name="socket"/>'s budget (or part of it) with attempts, each allowed first.</summary>
    private static void Attempts(BrokerUnlockGuard guard, string socket, int count)
    {
        for (var i = 0; i < count; i++)
        {
            Assert.Null(guard.Refusal(socket));
            guard.RecordAttempt(socket);
            guard.RecordSuccess(socket);
        }
    }

    // ------------------------------------------------------------------ the guard

    [Fact]
    public void ASocketAt20AttemptsInAMinute_IsRefusedWithSocketUnlockRate_AnotherSocketStillUnlocks()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var clock = new BrokerManualClock();
        var guard = new BrokerUnlockGuard(new BrokerLimits(), clock);

        Attempts(guard, "A", 20);

        Assert.Equal("socket-unlock-rate", guard.Refusal("A"));
        Assert.Null(guard.Refusal("B"));
    }

    [Fact]
    public void AAt20_BAt10_AThirdSocketGetsUnlockRate_AndAStillGetsSocketUnlockRate()
    {
        if (OperatingSystem.IsWindows())
            return;
        var clock = new BrokerManualClock();
        var guard = new BrokerUnlockGuard(new BrokerLimits(), clock);
        Attempts(guard, "A", 20);
        Attempts(guard, "B", 10);

        Assert.Equal("unlock-rate", guard.Refusal("C"));
        Assert.Equal("socket-unlock-rate", guard.Refusal("A")); // the socket's own budget is checked before the global one
        Assert.Equal("unlock-rate", guard.Refusal("B"));
    }

    [Fact]
    public void AfterTheMinutePasses_ASocketAtItsBudgetUnlocksAgain()
    {
        if (OperatingSystem.IsWindows())
            return;
        var clock = new BrokerManualClock();
        var guard = new BrokerUnlockGuard(new BrokerLimits(), clock);
        Attempts(guard, "A", 20);

        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal("socket-unlock-rate", guard.Refusal("A"));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Null(guard.Refusal("A"));
        Attempts(guard, "A", 20);
        Assert.Equal("socket-unlock-rate", guard.Refusal("A"));
    }

    [Fact]
    public void ASocketBothLockedOutAndAtItsBudget_ReportsLockedOut()
    {
        if (OperatingSystem.IsWindows())
            return;
        var clock = new BrokerManualClock();
        var limits = new BrokerLimits();
        var guard = new BrokerUnlockGuard(limits, clock);
        for (var i = 0; i < 20; i++)
        {
            Assert.Null(guard.Refusal("A"));
            guard.RecordAttempt("A");
            if (i < 20 - limits.FailuresBeforeLockout)
                guard.RecordSuccess("A");
            else
                guard.RecordFailure("A"); // the last three fail: locked out at the 20th attempt
        }

        Assert.Equal("locked-out", guard.Refusal("A"));
    }

    // ------------------------------------------------------------------ through the paths

    private static string LogLines(BrokerHarness h, string socket, string reason) =>
        string.Join('\n', h.LogText.ToString().Split('\n').Where(l => l.Contains($"socket={socket} ", StringComparison.Ordinal) && l.Contains($"reason={reason}", StringComparison.Ordinal)));

    [Fact]
    public async Task ARouteSocketAtItsBudget_GetsTheUniform503_ByteIdenticalToAnUnlockRateRefusal()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        for (var i = 0; i < 20; i++)
            Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));

        var socketRate = await _h.GetAsync("lane1", "/echo/a");

        Assert.Equal(20, _h.Secrets.Unlocks);
        Assert.Equal(503, BrokerHarness.StatusOf(socketRate));
        Assert.NotEmpty(LogLines(_h, "lane1", "socket-unlock-rate"));

        for (var i = 0; i < 10; i++)
            Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("other", "/second/a")));
        var globalRate = await _h.GetAsync("other", "/second/a");

        Assert.Equal(30, _h.Secrets.Unlocks);
        Assert.NotEmpty(LogLines(_h, "other", "unlock-rate"));
        Assert.Equal(globalRate, socketRate);
    }

    /// <summary>Sockets lane1 and other, each allowed template <c>t</c> (one secret, rate 60).</summary>
    private string TemplateConfig(SandboxBed bed) => $$$"""
        {
          "version": 1,
          "socket_dir": {{{J(_h.SocketDir)}}},
          "sockets": [
            { "name": "lane1", "uids": ["{{{BrokerHarness.MyUid}}}"], "routes": [], "templates": ["t"] },
            { "name": "other", "uids": ["{{{BrokerHarness.MyUid}}}"], "routes": [], "templates": ["t"] }
          ],
          "routes": [],
          "templates": [ {
            "name": "t",
            "argv": ["/bin/bash", {{{J(bed.Script("printf ok"))}}}],
            "args": {},
            "env": { "S": "{{tok}}" },
            "binds": [ { "path": {{{J(bed.Work)}}} } ],
            "rate": 60
          } ]
        }
        """;

    private async Task<string> CallTemplateAsync(string socket) =>
        Encoding.Latin1.GetString(await _h.SendRawAsync(socket,
            "POST /_template/t HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"));

    [Fact]
    public async Task ATemplateSocketAtItsBudget_GetsTheUniform503_ByteIdenticalToAnUnlockRateRefusal()
    {
        if (!SandboxBed.CanRun(output))
            return;
        using var bed = new SandboxBed();
        _h.Secrets = new FakeBrokerSecrets(_ => "a-generated-template-secret-value");
        await _h.StartAsync(TemplateConfig(bed));
        for (var i = 0; i < 20; i++)
            Assert.Equal(200, BrokerHarness.StatusOf(await CallTemplateAsync("lane1")));

        var socketRate = await CallTemplateAsync("lane1");

        Assert.Equal(20, _h.Secrets.Unlocks);
        Assert.Equal(503, BrokerHarness.StatusOf(socketRate));
        Assert.NotEmpty(LogLines(_h, "lane1", "socket-unlock-rate"));

        for (var i = 0; i < 10; i++)
            Assert.Equal(200, BrokerHarness.StatusOf(await CallTemplateAsync("other")));
        var globalRate = await CallTemplateAsync("other");

        Assert.Equal(30, _h.Secrets.Unlocks);
        Assert.NotEmpty(LogLines(_h, "other", "unlock-rate"));
        Assert.Equal(globalRate, socketRate);
    }

    private static readonly TestHostKey X = TestHostKey.NewEd25519();
    private static readonly byte[] KeyA = SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32));
    private static readonly byte[] BlobA = SshTestKeyMaker.PublicBlob(KeyA);

    [Fact]
    public async Task AnSshAgentSocketAtItsBudget_GetsSshAgentFailure_LoggedAsSocketUnlockRate()
    {
        if (SshTestSkip.OnWindows(output))
            return;
        await using var ssh = new SshAgentHarness();
        var config = $$"""
            {
              "version": 1,
              "socket_dir": {{J(ssh.Broker.SocketDir)}},
              "sockets": [ { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "ssh_keys": ["a"] } ],
              "routes": [],
              "ssh_keys": [ { "name": "a", "secret": "sa", "allowed_host_keys": ["{{X.Fingerprint}}"] } ]
            }
            """;
        var source = new FakeSshKeySource(_ => (byte[])KeyA.Clone());
        await ssh.StartAsync(config, p => new SshAgentOptions { Keys = SshAgentKeyLoader.Load(p, source), KeySource = source });
        using var client = await ssh.ConnectAsync("lane1");
        var sid = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(new[] { SshAgentProtocol.Success }, await client.RequestAsync(SshBindMessages.Bind(X.Blob, sid, X.Sign(sid))));
        var request = SshBindMessages.SignRequest(BlobA, SshBindMessages.Userauth(sid, "ssh-ed25519", BlobA));
        var reads = source.Reads;
        for (var i = 0; i < 20; i++)
            Assert.Equal(SshAgentProtocol.SignResponse, (await client.RequestAsync(request))![0]);

        var refused = await client.RequestAsync(request);

        Assert.Equal(SshAgentProtocol.FailureReply, refused);
        Assert.Equal(20, source.Reads - reads); // refused before any unlock
        await ssh.Broker.WaitForLogAsync("reason=socket-unlock-rate");
        Assert.Contains("result=refused reason=socket-unlock-rate", ssh.Broker.LogText.ToString());
    }
}
