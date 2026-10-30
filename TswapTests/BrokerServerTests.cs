using System.Diagnostics;
using System.Net.Sockets;
using TswapCore;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 item 2: the socket server and identity (decisions 2, 3 and 7), on real Unix sockets in
/// a temp folder, with this process's uid allowed or not.
/// </summary>
public class BrokerServerTests : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    [Fact]
    public async Task AllowedUid_GetsAnAnswer_FromTheSocketItArrivedOn()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();

        var response = await _h.GetAsync("lane1", "/echo/a/b");

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.EndsWith("ok https://upstream.example/base/a/b", response);
        Assert.Equal(1, _h.Secrets.Unlocks);
        Assert.Contains($"socket=lane1 uid={BrokerHarness.MyUid} pid={Environment.ProcessId} route=echo method=GET path=\"a/b\" status=200", _h.LogText.ToString());
    }

    [Fact]
    public async Task PeerCredentials_AreTheConnectingProcesses_ReadFromTheAcceptedSocket()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();

        // Another process connects: the logged pid is that client's, not this (listening) process's,
        // so the credentials come from the accepted connection, not the listening socket.
        var psi = new ProcessStartInfo("curl", ["-s", "--unix-socket", _h.SocketPath("lane1"), "http://broker/echo/x"])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var curl = Process.Start(psi)!;
        var output = await curl.StandardOutput.ReadToEndAsync();
        await curl.WaitForExitAsync();

        Assert.Equal("ok https://upstream.example/base/x", output);
        Assert.Contains($"socket=lane1 uid={BrokerHarness.MyUid} pid={curl.Id} route=echo", _h.LogText.ToString());
        Assert.DoesNotContain($"pid={Environment.ProcessId} ", _h.LogText.ToString());
    }

    [Fact]
    public async Task UidNotOnTheList_IsClosedWithNothingReturned_AndLogged()
    {
        if (OperatingSystem.IsWindows())
            return;
        var otherUid = BrokerHarness.MyUid == 0 ? 1u : BrokerHarness.MyUid - 1;
        await _h.StartAsync(_h.Config(lane1Uids: $"\"{otherUid}\", \"{BrokerHarness.MyUid + 1}-{BrokerHarness.MyUid + 100}\""));

        var response = await _h.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: broker\r\n\r\n");

        Assert.Empty(response);
        Assert.Equal(0, _h.Secrets.Unlocks);
        Assert.Equal(0, _h.FakeForwarder.Calls);
        Assert.Contains($"refused-connection socket=lane1 uid={BrokerHarness.MyUid} pid={Environment.ProcessId} reason=uid-not-allowed", _h.LogText.ToString());
        Assert.DoesNotContain("request socket=", _h.LogText.ToString());
    }

    [Fact]
    public async Task OneRequestPerConnection_SoAReloadThatDropsTheUid_RefusesTheNextRequest()
    {
        if (OperatingSystem.IsWindows())
            return;
        var server = await _h.StartAsync();
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_h.SocketPath("lane1")));
        // A keep-alive request (and a pipelined second one): answered once, with Connection: close.
        await client.SendAsync("GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\nGET /echo/b HTTP/1.1\r\nHost: b\r\n\r\n"u8.ToArray());
        var received = new MemoryStream();
        var buffer = new byte[4096];
        int n;
        while ((n = await client.ReceiveAsync(buffer)) > 0)
            received.Write(buffer, 0, n);
        var text = System.Text.Encoding.ASCII.GetString(received.ToArray());
        Assert.StartsWith("HTTP/1.1 200", text);
        Assert.Contains("\r\nConnection: close\r\n", text);
        Assert.Equal(1, text.Split("HTTP/1.1 ").Length - 1);
        Assert.Equal(1, _h.Secrets.Unlocks);

        Assert.True(server.Reload(() => BrokerPolicy.Parse(_h.Config(lane1Uids: $"\"{BrokerHarness.MyUid + 1}\""))));

        Assert.Empty(await _h.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: b\r\n\r\n"));
        Assert.Equal(1, _h.Secrets.Unlocks);
    }

    [Fact]
    public async Task SocketDir_GroupWritable_RefusesToStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        File.SetUnixFileMode(_h.SocketDir, (UnixFileMode)0b111_111_000);

        var ex = await Assert.ThrowsAsync<TswapException>(() => _h.StartAsync());

        Assert.Contains("writable by group or others", ex.Message);
        Assert.Empty(Directory.GetFileSystemEntries(_h.SocketDir));
    }

    [Fact]
    public async Task SocketDir_WorldWritable_RefusesToStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        File.SetUnixFileMode(_h.SocketDir, (UnixFileMode)0b111_101_011);

        var ex = await Assert.ThrowsAsync<TswapException>(() => _h.StartAsync());
        Assert.Contains("writable by group or others", ex.Message);
    }

    [Fact]
    public async Task SocketDir_WrongOwner_RefusesToStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        var someoneElse = new FileOwnershipTests.FakeOwnership(privileged: false, euid: BrokerHarness.MyUid, dirUid: BrokerHarness.MyUid + 1);

        var ex = await Assert.ThrowsAsync<TswapException>(() => _h.StartAsync(ownership: someoneElse));

        Assert.Contains("not owned by this user", ex.Message);
        Assert.Empty(Directory.GetFileSystemEntries(_h.SocketDir));
    }

    [Fact]
    public async Task SocketDir_Symlink_RefusesToStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        var real = Path.Combine(_h.Root, "real");
        Directory.CreateDirectory(real);
        File.SetUnixFileMode(real, (UnixFileMode)0b111_000_000);
        Directory.Delete(_h.SocketDir);
        Directory.CreateSymbolicLink(_h.SocketDir, real);

        var ex = await Assert.ThrowsAsync<TswapException>(() => _h.StartAsync());

        Assert.Contains("symlink", ex.Message);
        Assert.Empty(Directory.GetFileSystemEntries(real));
    }

    [Fact]
    public async Task RunningAsRoot_RefusesToStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        var root = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0, dirUid: 0);

        var ex = await Assert.ThrowsAsync<TswapException>(() => _h.StartAsync(ownership: root));
        Assert.Contains("never as root", ex.Message);
    }

    [Fact]
    public async Task SecondServe_OnTheSameSocketDir_Refuses_AndTheFirstKeepsServing()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();

        var ex = await Assert.ThrowsAsync<TswapException>(() => BrokerServer.StartAsync(_h.Options()));

        Assert.Contains("Another 'tswap broker serve' is running", ex.Message);
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
    }

    [Fact]
    public async Task StaleSocket_FromAKilledServe_IsCleanedUpUnderTheLock()
    {
        if (OperatingSystem.IsWindows())
            return;
        // A socket file left behind (bound, never unlinked), as a killed serve leaves it. .NET unlinks
        // a bound socket's file on dispose, so the file is renamed into place first.
        var bound = Path.Combine(_h.SocketDir, "bound.sock");
        using (var stale = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
        {
            stale.Bind(new UnixDomainSocketEndPoint(bound));
            File.Move(bound, _h.SocketPath("lane1"));
        }
        Assert.Equal(BrokerNative.EntryType.Socket, BrokerNative.LStat(_h.SocketPath("lane1"))!.Value.Type);

        await _h.StartAsync();

        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        Assert.Contains("started", _h.LogText.ToString());
    }

    [Fact]
    public async Task NonSocketAtTheSocketPath_IsNotRemoved_AndStopsTheStart()
    {
        if (OperatingSystem.IsWindows())
            return;
        File.WriteAllText(_h.SocketPath("lane1"), "not a socket");

        var ex = await Assert.ThrowsAsync<TswapException>(() => _h.StartAsync());

        Assert.Contains("not a stale socket", ex.Message);
        Assert.Equal("not a socket", File.ReadAllText(_h.SocketPath("lane1")));
        // The lock was released: a later start (once the file is gone) works.
        File.Delete(_h.SocketPath("lane1"));
        await _h.StartAsync();
    }

    [Fact]
    public async Task Sockets_Are0666_AndGoneAfterAStop_AndTheLockIsReleased()
    {
        if (OperatingSystem.IsWindows())
            return;
        var server = await _h.StartAsync();
        Assert.Equal([_h.SocketPath("lane1"), _h.SocketPath("other")], server.SocketPaths);
        foreach (var path in server.SocketPaths)
            Assert.Equal((UnixFileMode)0b110_110_110, BrokerNative.LStat(path)!.Value.Mode);

        await server.StopAsync();

        Assert.All(server.SocketPaths, p => Assert.Equal(BrokerNative.EntryType.Missing, BrokerNative.LStat(p)!.Value.Type));
        Assert.Contains("stopped", _h.LogText.ToString());
        await using var again = await BrokerServer.StartAsync(_h.Options());
    }

    // ------------------------------------------------------------------ limits

    [Fact]
    public async Task Limiter_PerSocketAndTotalSlots_Defaults()
    {
        var limits = new BrokerLimits();
        Assert.Equal(4, limits.PerSocketInFlight);
        Assert.Equal(8, limits.TotalInFlight);
        Assert.Equal(16, limits.MaxQueued);
        Assert.Equal(TimeSpan.FromSeconds(30), limits.MaxQueueWait);
        Assert.Equal(3, limits.FailuresBeforeLockout);
        Assert.Equal(TimeSpan.FromMinutes(5), limits.Lockout);
        Assert.Equal(30, limits.MaxFailedUnlocksPerMinute);

        var clock = new BrokerManualClock();
        var limiter = new BrokerLimiter(limits, clock);
        var held = new List<IDisposable>();
        for (var i = 0; i < 4; i++)
            held.Add((await limiter.TryAcquireAsync("a", default))!);

        // A fifth on socket a queues; socket b still gets slots, up to 8 in total.
        var fifthA = limiter.TryAcquireAsync("a", default);
        Assert.False(fifthA.IsCompleted);
        for (var i = 0; i < 4; i++)
            held.Add((await limiter.TryAcquireAsync("b", default))!);
        var ninth = limiter.TryAcquireAsync("c", default);
        Assert.False(ninth.IsCompleted);
        Assert.Equal(2, limiter.Queued);

        // Releasing one of a's slots: c (first in line for a total slot) gets it; a's fifth now has
        // a per-socket slot but still waits for a total one.
        held[0].Dispose();
        var cSlot = await ninth;
        Assert.NotNull(cSlot);
        Assert.False(fifthA.IsCompleted);
        held[4].Dispose(); // one of b's
        Assert.NotNull(await fifthA);
        Assert.Equal(0, limiter.Queued);
    }

    [Fact]
    public async Task Limiter_BoundedQueue_17thWaiterGetsNoSlotAtOnce()
    {
        var limiter = new BrokerLimiter(new BrokerLimits(), new BrokerManualClock());
        for (var i = 0; i < 8; i++)
            Assert.NotNull(await limiter.TryAcquireAsync("s" + (i % 2), default));
        var waiting = Enumerable.Range(0, 16).Select(i => limiter.TryAcquireAsync("w" + i, default)).ToList();
        Assert.All(waiting, w => Assert.False(w.IsCompleted));

        var overflow = await limiter.TryAcquireAsync("x", default);

        Assert.Null(overflow);
        Assert.Equal(16, limiter.Queued);
    }

    [Fact]
    public async Task Limiter_WaitsAtMost30Seconds_OnTheInjectedClock()
    {
        var clock = new BrokerManualClock();
        var limiter = new BrokerLimiter(new BrokerLimits(), clock);
        for (var i = 0; i < 4; i++)
            Assert.NotNull(await limiter.TryAcquireAsync("a", default));
        var waiter = limiter.TryAcquireAsync("a", default);

        clock.Advance(TimeSpan.FromSeconds(29));
        Assert.False(waiter.IsCompleted);
        clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Null(await waiter);
        Assert.Equal(0, limiter.Queued);
    }

    [Fact]
    public async Task Server_NoSlotWithin30Seconds_Gives503()
    {
        if (OperatingSystem.IsWindows())
            return;
        _h.FakeForwarder.Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var inFlight = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _h.FakeForwarder.Entered += n => { if (n == 4) inFlight.TrySetResult(); };
        await _h.StartAsync();
        var held = Enumerable.Range(0, 4).Select(_ => _h.GetAsync("lane1", "/echo/a")).ToList();
        await inFlight.Task; // four requests hold lane1's four slots

        var fifth = _h.GetAsync("lane1", "/echo/a");
        await WaitForQueueAsync(1);
        _h.Clock.Advance(TimeSpan.FromSeconds(30));
        var response = await fifth;

        Assert.Equal(503, BrokerHarness.StatusOf(response));
        Assert.Contains("status=503", _h.LogText.ToString());
        Assert.Contains("reason=busy", _h.LogText.ToString());
        Assert.Equal(4, _h.Secrets.Unlocks); // the refused request never unlocked
        _h.FakeForwarder.Gate.SetResult();
        foreach (var r in held)
            Assert.Equal(200, BrokerHarness.StatusOf(await r));
    }

    private async Task WaitForQueueAsync(int count)
    {
        var limiter = _h.Server!.Limiter;
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Check(int queued) { if (queued >= count) reached.TrySetResult(); }
        limiter.QueueChanged += Check;
        try
        {
            Check(limiter.Queued);
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(30));
        }
        finally
        {
            limiter.QueueChanged -= Check;
        }
    }

    // ------------------------------------------------------------------ unlock failures

    [Fact]
    public async Task ThreeUnlockFailures_LockOutThatSocket_ForFiveMinutes_OtherSocketsStillWork()
    {
        if (OperatingSystem.IsWindows())
            return;
        _h.Secrets.Fail = true;
        await _h.StartAsync();

        for (var i = 0; i < 3; i++)
            Assert.Equal(502, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        var refused = await _h.GetAsync("lane1", "/echo/a");

        Assert.Equal(503, BrokerHarness.StatusOf(refused));
        Assert.Equal(3, _h.Secrets.Unlocks); // the refusal did not unlock
        Assert.Contains("locked out", _h.LogText.ToString());
        Assert.Contains("reason=locked-out", _h.LogText.ToString());

        // Refusals never count: more of them don't extend the lockout.
        for (var i = 0; i < 5; i++)
            Assert.Equal(503, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));

        // Another socket is not locked out.
        _h.Secrets.Fail = false;
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("other", "/second/a")));

        _h.Clock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));
        Assert.Equal(503, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        _h.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
    }

    [Fact]
    public async Task ASuccessfulUnlock_EndsTheRunOfFailures()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        _h.Secrets.Fail = true;
        for (var i = 0; i < 2; i++)
            Assert.Equal(502, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        _h.Secrets.Fail = false;
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        _h.Secrets.Fail = true;
        for (var i = 0; i < 2; i++)
            Assert.Equal(502, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));

        Assert.Equal(502, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a"))); // third in a row: tried, then locked out
        Assert.Equal(503, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
    }

    [Fact]
    public void GlobalUnlockLimit_30FailedUnlocksAMinute_ThenRefused_RefusalsDontCount()
    {
        var clock = new BrokerManualClock();
        var guard = new BrokerUnlockGuard(new BrokerLimits(), clock);
        for (var i = 0; i < 30; i++)
        {
            Assert.Null(guard.Refusal("s" + i));
            guard.RecordFailure("s" + i); // one failure per socket: no socket is locked out
        }

        Assert.Equal("unlock-rate", guard.Refusal("fresh"));
        for (var i = 0; i < 10; i++)
            Assert.Equal("unlock-rate", guard.Refusal("fresh")); // refusals add nothing
        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal("unlock-rate", guard.Refusal("fresh"));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Null(guard.Refusal("fresh"));
    }
}
