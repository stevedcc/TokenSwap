using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 10: the agent server and client on real Unix sockets in temp folders (rulings 6, 7,
/// 8, 11, 20 and 21), with the peer checks' seams standing in for other uids, user namespaces,
/// SELinux labels and dead pidfds.
/// </summary>
public class AgentServerTests : IAsyncLifetime
{
    private readonly AgentHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private AgentAnswer ClientUnlock(byte[]? vaultId = null, uint? expectedUid = null) =>
        AgentClient.Unlock(_h.SocketPath, vaultId ?? _h.VaultId, expectedUid ?? AgentHarness.MyUid,
            AgentClient.DefaultConnectTimeout, AgentClient.DefaultResponseTimeout);

    // ------------------------------------------------------------------ peer checks (rulings 7 and 20)

    [Fact]
    public async Task Server_RefusesOtherUid()
    {
        if (OperatingSystem.IsWindows())
            return;
        var server = await _h.StartAsync();
        PeerIdentity.ReadCredentials = socket => (AgentHarness.MyUid + 1, Environment.ProcessId);

        Assert.Null(await _h.RawAsync(AgentOp.Unlock));
        Assert.Null(await _h.RawAsync(AgentOp.Status));

        Assert.Equal(0, _h.UnlockCalls);
        Assert.Equal(2, server.RefusedPeers);
        Assert.Contains($"refused a peer: uid {AgentHarness.MyUid + 1}", _h.LogText);
    }

    [Fact]
    public async Task Server_AcceptsUidZero()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        PeerIdentity.ReadCredentials = socket => (0u, Environment.ProcessId);

        var answer = await _h.RawAsync(AgentOp.Unlock);

        Assert.Equal(AgentStatus.Ok, answer?.Status);
        Assert.Equal(_h.Key, answer?.Payload);
    }

    [Fact]
    public async Task Server_RefusesPeerInAnotherUserNamespace()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var server = await _h.StartAsync();
        PeerIdentity.ReadUserNamespace = _ => "user:[4026533193]"; // podman unshare's, not ours

        Assert.Null(await _h.RawAsync(AgentOp.Unlock));

        Assert.Equal(0, _h.UnlockCalls);
        Assert.Equal(1, server.RefusedPeers);
        Assert.Contains("peer in another user namespace", _h.LogText);
    }

    [Fact]
    public async Task Server_SameUserNamespace_ReadThroughTheRealProc_IsAccepted()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var calls = 0;
        PeerIdentity.ReadUserNamespace = peer => { calls++; return PeerIdentity.DefaultReadUserNamespace(peer); };
        await _h.StartAsync();

        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Unlock))?.Status);
        Assert.Equal(1, calls);
        Assert.Equal(new FileInfo("/proc/self/ns/user").LinkTarget, PeerIdentity.ReadOwnUserNamespace());
        Assert.StartsWith("user:[", PeerIdentity.ReadOwnUserNamespace());
    }

    [Fact]
    public async Task Client_NoNamespaceCheckOnAgentServer()
    {
        if (OperatingSystem.IsWindows())
            return;
        // A fake server that answers with the key: no PeerIdentity runs on its side.
        Directory.CreateDirectory(_h.Folder);
        using var listener = Listen(_h.SocketPath);
        var serving = ServeOnceAsync(listener, AgentProtocol.EncodeResponse(AgentStatus.Ok, _h.Key));
        PeerIdentity.OpenPeer = _ => throw new InvalidOperationException("the agent client must not open the server's /proc");
        PeerIdentity.ReadUserNamespace = _ => throw new InvalidOperationException("no namespace check on the agent server");
        PeerIdentity.ReadPeerLabel = _ => throw new InvalidOperationException("no label check on the agent server");

        var answer = await Task.Run(() => ClientUnlock());

        Assert.Equal(_h.Key, Assert.IsType<AgentAnswer.Unlocked>(answer).VaultKey);
        await serving;
    }

    [Theory]
    [InlineData("container_t")]
    [InlineData("spc_t")]
    [InlineData("container_runtime_t")]
    public async Task Server_RefusesContainerLabel(string type)
    {
        if (!OperatingSystem.IsLinux())
            return;
        var server = await _h.StartAsync();
        PeerIdentity.ReadPeerLabel = _ => $"system_u:system_r:{type}:s0:c12,c34";

        Assert.Null(await _h.RawAsync(AgentOp.Unlock));

        Assert.Equal(0, _h.UnlockCalls);
        Assert.Equal(1, server.RefusedPeers);
        Assert.Contains($"peer label {type}", _h.LogText);
    }

    [Fact]
    public async Task Server_NoSelinux_SkipsLabelCheck()
    {
        if (!OperatingSystem.IsLinux())
            return;
        await _h.StartAsync();
        PeerIdentity.ReadPeerLabel = _ => null; // ENOPROTOOPT, or an empty label

        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Unlock))?.Status);

        // And the real reader on this machine: a label (SELinux) or nothing, never an error.
        PeerIdentity.ResetSeamsForTests();
        using var listener = Listen(Path.Combine(_h.Root.FullName, "label.sock"));
        using var client = await AgentHarness.ConnectAsync(Path.Combine(_h.Root.FullName, "label.sock"));
        using var accepted = await listener.AcceptAsync();
        var label = PeerIdentity.ReadPeerLabel(accepted);
        Assert.True(label is null || label.Split(':').Length >= 3, label);
    }

    [Fact]
    public async Task Client_RefusesAServerOfAnotherUid()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();

        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => ClientUnlock(expectedUid: AgentHarness.MyUid + 1)));

        Assert.Contains(_h.SocketPath, ex.Message);
        Assert.Contains($"uid {AgentHarness.MyUid}", ex.Message);
        Assert.Equal(0, _h.UnlockCalls); // refused before the request was sent
    }

    [Fact]
    public async Task AgentSockVariable_CannotBypassServerUidCheck()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        // The vault's owner is another uid; TSWAP_AGENT_SOCK points at a socket this uid serves.
        var owner = AgentHarness.MyUid + 1;
        var path = AgentSocketPath.For(owner, _h.VaultId, name => name == AgentSocketPath.Variable ? _h.SocketPath : null);
        Assert.Equal(_h.SocketPath, path);

        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() =>
            AgentClient.Unlock(path, _h.VaultId, owner, AgentClient.DefaultConnectTimeout, AgentClient.DefaultResponseTimeout)));

        Assert.Contains("not the vault owner", ex.Message);
        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task UidZeroPeer_UnreadableNamespace_Accepted_LabelStillChecked()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var server = await _h.StartAsync();
        PeerIdentity.ReadCredentials = _ => (0u, Environment.ProcessId);
        PeerIdentity.OpenPeer = _ => null;              // hidepid=2: /proc/<pid> unreadable
        PeerIdentity.ReadUserNamespace = _ => null;

        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Unlock))?.Status);

        PeerIdentity.ReadPeerLabel = _ => "system_u:system_r:container_t:s0:c1,c2";
        Assert.Null(await _h.RawAsync(AgentOp.Unlock));
        Assert.Equal(1, _h.UnlockCalls);
        Assert.Equal(1, server.RefusedPeers);
        Assert.Contains("peer label container_t", _h.LogText);
    }

    [Fact]
    public async Task NonRootPeer_UnreadableNamespace_Refused()
    {
        if (!OperatingSystem.IsLinux())
            return;
        await _h.StartAsync();
        PeerIdentity.ReadUserNamespace = _ => null;

        Assert.Null(await _h.RawAsync(AgentOp.Unlock));

        PeerIdentity.ResetSeamsForTests();
        PeerIdentity.OpenPeer = _ => null; // the peer exited before /proc/<pid> was opened
        Assert.Null(await _h.RawAsync(AgentOp.Status));
        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task PidfdDeadAfterDirOpen_Refused()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var server = await _h.StartAsync();
        var opened = false;
        PeerIdentity.OpenPeer = socket =>
        {
            var peer = PeerIdentity.DefaultOpenPeer(socket);
            opened = peer is not null;
            Assert.True(peer?.HasPidfd, "this kernel (>= 6.3) gives SO_PEERPIDFD");
            return peer;
        };
        PeerIdentity.PidfdAlive = _ => false;

        Assert.Null(await _h.RawAsync(AgentOp.Unlock));

        Assert.True(opened);
        Assert.Equal(0, _h.UnlockCalls);
        Assert.Equal(1, server.RefusedPeers);
        Assert.Contains("exited", _h.LogText);
    }

    [Fact]
    public async Task PidfdAlive_IsTrueForALiveProcess_ThroughTheRealSyscall()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var alive = new List<bool>();
        PeerIdentity.PidfdAlive = peer => { var a = PeerIdentity.DefaultPidfdAlive(peer); alive.Add(a); return a; };
        await _h.StartAsync();

        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Status))?.Status);
        Assert.Equal([true], alive);
    }

    [Fact]
    public async Task StatusUidDiffersFromCred_Refused()
    {
        if (!OperatingSystem.IsLinux())
            return;
        await _h.StartAsync();
        PeerIdentity.ReadStatusUid = _ => AgentHarness.MyUid + 1;

        Assert.Null(await _h.RawAsync(AgentOp.Unlock));

        Assert.Equal(0, _h.UnlockCalls);
        Assert.Contains("status uid", _h.LogText);

        // The real reader agrees with the credential.
        PeerIdentity.ResetSeamsForTests();
        uint? read = null;
        PeerIdentity.ReadStatusUid = peer => read = PeerIdentity.DefaultReadStatusUid(peer);
        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Status))?.Status);
        Assert.Equal(AgentHarness.MyUid, read);
    }

    [Fact]
    public async Task NoPeerPidfd_FallsBackToDirAndStatusUid()
    {
        if (!OperatingSystem.IsLinux())
            return;
        await _h.StartAsync();
        int namespaces = 0, statuses = 0;
        PeerIdentity.OpenPeer = socket => PeerIdentity.DefaultOpenPeer(socket, usePidfd: false); // ENOPROTOOPT: kernel < 6.3
        PeerIdentity.PidfdAlive = _ => throw new InvalidOperationException("no pidfd to check");
        PeerIdentity.ReadUserNamespace = peer => { namespaces++; return PeerIdentity.DefaultReadUserNamespace(peer); };
        PeerIdentity.ReadStatusUid = peer => { statuses++; return PeerIdentity.DefaultReadStatusUid(peer); };

        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Unlock))?.Status);
        Assert.Equal((1, 1), (namespaces, statuses));

        // Without a pidfd the status uid is still checked.
        PeerIdentity.ReadStatusUid = _ => AgentHarness.MyUid + 1;
        Assert.Null(await _h.RawAsync(AgentOp.Unlock));
    }

    [Fact]
    public async Task NoProc_AgentAllowsOnlyRoot_ControlSocketNoOne()
    {
        if (!OperatingSystem.IsLinux())
            return;
        PeerIdentity.ProcMounted = () => false;
        var server = await _h.StartAsync();

        // Agent socket: a non-root peer is refused; the agent says so once.
        Assert.Null(await _h.RawAsync(AgentOp.Status));
        Assert.Null(await _h.RawAsync(AgentOp.Status));
        Assert.Equal(2, server.RefusedPeers);
        Assert.Single(_h.Log, line => line == "/proc is not mounted: peers can't be checked, so only root may use the agent.");
        Assert.Equal(PeerIdentity.NoProcAgentMessage, "/proc is not mounted: peers can't be checked, so only root may use the agent.");
        // Root still may.
        PeerIdentity.ReadCredentials = _ => (0u, Environment.ProcessId);
        Assert.Equal(AgentStatus.Ok, (await _h.RawAsync(AgentOp.Status))?.Status);

        // The broker's control socket (task 12 reuses this policy): nobody, root included.
        var controlPath = Path.Combine(_h.Root.FullName, "control.sock");
        using var listener = Listen(controlPath);
        foreach (var uid in new[] { AgentHarness.MyUid, 0u })
        {
            PeerIdentity.ReadCredentials = _ => (uid, Environment.ProcessId);
            using var client = await AgentHarness.ConnectAsync(controlPath);
            using var accepted = await listener.AcceptAsync();
            var verdict = PeerIdentity.Check(accepted, PeerPolicy.BrokerControl(AgentHarness.MyUid));
            Assert.False(verdict.Allowed);
            if (uid != 0)
                Assert.Equal("/proc is not mounted: peers can't be checked, so the broker can't be unlocked, locked or queried.", verdict.Reason);
        }
        Assert.Equal("/proc is not mounted: peers can't be checked, so the broker can't be unlocked, locked or queried.",
            PeerIdentity.NoProcControlMessage);
    }

    [Fact]
    public async Task BrokerControlPolicy_RefusesUidZero_ChecksNamespaceAndLabel()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var controlPath = Path.Combine(_h.Root.FullName, "control.sock");
        using var listener = Listen(controlPath);

        async Task<PeerVerdict> CheckAsync()
        {
            using var client = await AgentHarness.ConnectAsync(controlPath);
            using var accepted = await listener.AcceptAsync();
            return PeerIdentity.Check(accepted, PeerPolicy.BrokerControl(AgentHarness.MyUid));
        }

        Assert.True((await CheckAsync()).Allowed);
        PeerIdentity.ReadCredentials = _ => (0u, Environment.ProcessId);
        Assert.False((await CheckAsync()).Allowed);
        PeerIdentity.ResetSeamsForTests();
        PeerIdentity.ReadUserNamespace = _ => "user:[1]";
        Assert.Equal("peer in another user namespace", (await CheckAsync()).Reason);
        PeerIdentity.ResetSeamsForTests();
        PeerIdentity.ReadPeerLabel = _ => "u:r:spc_t:s0";
        Assert.Equal("peer label spc_t", (await CheckAsync()).Reason);
    }

    // ------------------------------------------------------------------ unlocks (ruling 8)

    [Fact]
    public async Task Unlock_OtherVault_NeverCallsUnlockVault()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        var other = RandomNumberGenerator.GetBytes(16);

        Assert.IsType<AgentAnswer.OtherVault>(await Task.Run(() => ClientUnlock(vaultId: other)));
        Assert.IsType<AgentAnswer.OtherVault>(await Task.Run(() =>
            AgentClient.Status(_h.SocketPath, other, AgentHarness.MyUid)));

        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task PrefixCollision_SaysAnotherVaultsAgent()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        // Another vault whose id shares the first 8 bytes: the same socket name, so it reaches this agent.
        var other = _h.VaultId.ToArray();
        other[15] ^= 0xFF;
        Assert.Equal(AgentSocketPath.SocketName(_h.VaultId), AgentSocketPath.SocketName(other));

        var answer = await Task.Run(() => ClientUnlock(vaultId: other));

        Assert.IsType<AgentAnswer.OtherVault>(answer);
        Assert.Equal($"Another vault's agent holds {_h.SocketPath}; set TSWAP_AGENT_SOCK to a different path for this vault.",
            AgentSocketPath.OtherVaultMessage(_h.SocketPath));
        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task Unlock_Ok_ReturnsKey_ServerZeroesItsCopy()
    {
        if (OperatingSystem.IsWindows())
            return;
        var observed = new List<byte[]>();
        AgentServer.AfterSendObserver = frame => { lock (observed) observed.Add(frame.ToArray()); };
        await _h.StartAsync();

        var answer = await Task.Run(() => ClientUnlock());

        Assert.Equal(_h.Key, Assert.IsType<AgentAnswer.Unlocked>(answer).VaultKey);
        // The server's frame (length, header, K_v) is all zeros after the send...
        var frame = Assert.Single(observed);
        Assert.Equal(4 + 8 + 32, frame.Length);
        Assert.All(frame, b => Assert.Equal(0, b));
        // ...and so is the K_v array UnlockVault returned.
        Assert.All(Assert.Single(_h.HandedOut), b => Assert.Equal(0, b));
    }

    [Fact]
    public void Unlocked_ToString_HoldsNoKey()
    {
        var key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var text = new AgentAnswer.Unlocked(key).ToString();
        Assert.DoesNotContain(Convert.ToHexString(key)[..8], text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(key)[..8], text);
        Assert.DoesNotContain("1, 2, 3", text);
    }

    [Fact]
    public async Task HardwareFailed_PayloadHoldsNoSecret()
    {
        if (OperatingSystem.IsWindows())
            return;
        var stretched = RandomNumberGenerator.GetBytes(32);
        var key = RandomNumberGenerator.GetBytes(32);
        var raw = Encoding.Latin1.GetString(stretched);
        _h.Unlock = () => throw new VaultPasswordRefusedException(
            $"Wrong vault password. stretched={Convert.ToHexString(stretched)} lower={Convert.ToHexStringLower(stretched)} " +
            $"b64={Convert.ToBase64String(stretched)} key={Convert.ToBase64String(key)} hexkey={Convert.ToHexStringLower(key)} " +
            $"raw={raw} {new string('x', 600)}");
        await _h.StartAsync();

        var response = await _h.RawAsync(AgentOp.Unlock);

        Assert.Equal(AgentStatus.HardwareFailed, response?.Status);
        var payload = response!.Value.Payload;
        Assert.True(payload.Length <= 512, $"{payload.Length} bytes");
        var text = Encoding.UTF8.GetString(payload);
        Assert.StartsWith("Wrong vault password.", text);
        foreach (var secret in new[] { stretched, key })
        {
            Assert.DoesNotContain(Convert.ToHexString(secret), text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Convert.ToBase64String(secret), text);
            Assert.DoesNotContain(Convert.ToBase64String(secret).TrimEnd('='), text);
            Assert.False(payload.AsSpan().IndexOf(secret) >= 0, "the raw bytes are in the payload");
            Assert.DoesNotContain(Encoding.Latin1.GetString(secret), Encoding.Latin1.GetString(payload));
        }

        // Through the client: a HardwareFailed answer with that text.
        var answer = await Task.Run(() => ClientUnlock());
        Assert.Equal(text, Assert.IsType<AgentAnswer.HardwareFailed>(answer).Message);
    }

    [Fact]
    public async Task HardwareFailed_KeepsAnOrdinaryBackendText()
    {
        if (OperatingSystem.IsWindows())
            return;
        const string message = "TPM operation failed while unsealing the key: tpm2_unseal exited 1 (see /tmp/x.log).";
        _h.Unlock = () => throw new TswapException(message);
        await _h.StartAsync();

        Assert.Equal(message, Assert.IsType<AgentAnswer.HardwareFailed>(await Task.Run(() => ClientUnlock())).Message);

        // A non-tswap exception says only that the unlock failed, never its message.
        _h.Unlock = () => throw new InvalidOperationException("internal detail");
        var other = Assert.IsType<AgentAnswer.HardwareFailed>(await Task.Run(() => ClientUnlock())).Message;
        Assert.DoesNotContain("internal detail", other);
    }

    [Fact]
    public async Task Expiry_ZeroesAndStops_AtTheDeadline_EvenWhileBusy()
    {
        if (OperatingSystem.IsWindows())
            return;
        var deadline = _h.Clock.GetUtcNow() + TimeSpan.FromMinutes(5);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new ManualResetEventSlim();
        _h.Unlock = () => { entered.SetResult(); release.Wait(); return _h.Key.ToArray(); };
        var held = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        var freed = new List<byte[]>();
        StretchedPassword.BeforeFreeObserver = memory => { lock (freed) freed.Add(memory.ToArray()); };
        try
        {
            var server = await _h.StartAsync(_h.Options(expiresAt: deadline) with { Held = held });

            // Status reports the expiry.
            var running = Assert.IsType<AgentAnswer.Running>(await Task.Run(() =>
                AgentClient.Status(_h.SocketPath, _h.VaultId, AgentHarness.MyUid)));
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(deadline.ToUnixTimeSeconds()), running.ExpiresAt);

            var inFlight = _h.RawAsync(AgentOp.Unlock);
            await entered.Task;
            _h.Clock.Advance(TimeSpan.FromMinutes(4));
            Assert.False(server.Stopped.IsCompleted);
            _h.Clock.Advance(TimeSpan.FromMinutes(1));

            Assert.Equal(AgentStatus.Expired, (await inFlight)?.Status);
            await server.Stopped;
            var zeroed = Assert.Single(freed);
            Assert.All(zeroed, b => Assert.Equal(0, b));
            Assert.Throws<ObjectDisposedException>(() => held.CopyTo(new byte[32]));
            Assert.Equal(BrokerNative.EntryType.Missing, BrokerNative.LStat(_h.SocketPath)!.Value.Type);
            Assert.IsType<AgentAnswer.NotRunning>(await Task.Run(() => ClientUnlock()));
        }
        finally
        {
            release.Set();
            StretchedPassword.BeforeFreeObserver = null;
        }
    }

    [Fact]
    public async Task ExpiryInThePast_StopsAtOnce()
    {
        if (OperatingSystem.IsWindows())
            return;
        var server = await _h.StartAsync(_h.Options(expiresAt: _h.Clock.GetUtcNow() - TimeSpan.FromSeconds(1)));
        await server.Stopped;
        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task OneUnlockAtATime()
    {
        if (OperatingSystem.IsWindows())
            return;
        int running = 0, maxRunning = 0;
        var entered = new[] { new SemaphoreSlim(0), };
        var release = new SemaphoreSlim(0);
        _h.Unlock = () =>
        {
            var now = Interlocked.Increment(ref running);
            InterlockedMax(ref maxRunning, now);
            entered[0].Release();
            release.Wait();
            Interlocked.Decrement(ref running);
            return _h.Key.ToArray();
        };
        var queued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await _h.StartAsync();

        var first = _h.RawAsync(AgentOp.Unlock);
        await entered[0].WaitAsync();
        AgentServer.UnlockQueuedObserver = () => queued.TrySetResult();
        var second = _h.RawAsync(AgentOp.Unlock);
        await queued.Task;                       // the second request is at the gate...
        Assert.Equal(1, _h.UnlockCalls);         // ...and has not reached UnlockVault
        release.Release();
        Assert.Equal(AgentStatus.Ok, (await first)?.Status);
        await entered[0].WaitAsync();
        release.Release();
        Assert.Equal(AgentStatus.Ok, (await second)?.Status);

        Assert.Equal(2, _h.UnlockCalls);
        Assert.Equal(1, maxRunning);
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        while (value > (current = Volatile.Read(ref target)) &&
               Interlocked.CompareExchange(ref target, value, current) != current)
        {
        }
    }

    [Fact]
    public async Task StopAndStatus_BypassTheUnlockGate()
    {
        if (OperatingSystem.IsWindows())
            return;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new ManualResetEventSlim();
        _h.Unlock = () => { entered.TrySetResult(); release.Wait(); return _h.Key.ToArray(); };
        var queued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            var server = await _h.StartAsync();
            var blocked = _h.RawAsync(AgentOp.Unlock);
            await entered.Task;
            AgentServer.UnlockQueuedObserver = () => queued.TrySetResult();
            var waiting = _h.RawAsync(AgentOp.Unlock);
            await queued.Task;

            Assert.IsType<AgentAnswer.Running>(await Task.Run(() => AgentClient.Status(_h.SocketPath, _h.VaultId, AgentHarness.MyUid)));
            Assert.IsType<AgentAnswer.Stopped>(await Task.Run(() => AgentClient.Stop(_h.SocketPath, _h.VaultId, AgentHarness.MyUid)));

            // Both the unlock in UnlockVault and the one waiting at the gate answer Expired.
            Assert.Equal(AgentStatus.Expired, (await blocked)?.Status);
            Assert.Equal(AgentStatus.Expired, (await waiting)?.Status);
            await server.Stopped;
            Assert.Equal(1, _h.UnlockCalls);
        }
        finally
        {
            release.Set();
        }
    }

    [Fact]
    public async Task SeventeenthConnection_ClosedAtAccept()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        var idle = new List<Socket>();
        try
        {
            for (var i = 0; i < 16; i++)
                idle.Add(await AgentHarness.ConnectAsync(_h.SocketPath)); // send nothing: each holds a connection

            // The 17th is closed unanswered...
            Assert.Null(await _h.RawAsync(AgentOp.Status));
            Assert.Equal(0, _h.UnlockCalls);

            // ...while each of the 16 is still served.
            Assert.Equal(AgentStatus.Ok, (await AgentHarness.SendOnAsync(idle[0],
                AgentProtocol.EncodeRequest((byte)AgentOp.Status, _h.VaultId)))?.Status);
        }
        finally
        {
            foreach (var socket in idle)
                socket.Dispose();
        }
    }

    [Fact]
    public async Task SlowClient_ClosedAfterFiveSeconds_WithoutAnAnswer()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        using var slow = await AgentHarness.ConnectAsync(_h.SocketPath);
        var reading = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        AgentServer.ReadStartedObserver = () => reading.TrySetResult();
        await slow.SendAsync(AgentProtocol.EncodeRequest((byte)AgentOp.Unlock, _h.VaultId)[..10]); // half a request

        var answer = AgentHarness.SendOnAsync(slow, []);
        await reading.Task; // the server's 5 s deadline is set
        _h.Clock.Advance(TimeSpan.FromSeconds(4));
        Assert.False(answer.IsCompleted);
        _h.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Null(await answer);
        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task MalformedRequest_AnswersMalformed_UnknownOpToo()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        var badMagic = AgentProtocol.EncodeRequest((byte)AgentOp.Unlock, _h.VaultId);
        badMagic[7] = (byte)'X';

        Assert.Equal(AgentStatus.Malformed, (await AgentHarness.RawAsync(_h.SocketPath, badMagic))?.Status);
        Assert.Equal(AgentStatus.Malformed, (await AgentHarness.RawAsync(_h.SocketPath,
            AgentProtocol.EncodeRequest(99, _h.VaultId)))?.Status);
        // An agent request carries no payload.
        Assert.Equal(AgentStatus.Malformed, (await AgentHarness.RawAsync(_h.SocketPath,
            AgentProtocol.EncodeRequest((byte)AgentOp.Unlock, _h.VaultId, new byte[32])))?.Status);
        Assert.Equal(0, _h.UnlockCalls);
    }

    [Fact]
    public async Task Client_ConnectDeadline_TwoSeconds()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        using var listener = Listen(_h.SocketPath); // exists, but the connect never completes (seam)
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        AgentClient.Time = _h.Clock;
        AgentClient.Connect = async (socket, endpoint, token) =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, token);
        };

        var answer = Task.Run(() => ClientUnlock());
        await started.Task;
        _h.Clock.Advance(TimeSpan.FromMilliseconds(1999));
        Assert.False(answer.IsCompleted);
        _h.Clock.Advance(TimeSpan.FromMilliseconds(1));

        Assert.IsType<AgentAnswer.NotRunning>(await answer);
        Assert.Equal(TimeSpan.FromSeconds(2), AgentClient.DefaultConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(120), AgentClient.DefaultResponseTimeout);
    }

    [Fact]
    public async Task Client_ResponseDeadline_IsNotRunning()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        using var listener = Listen(_h.SocketPath); // the kernel accepts into the backlog; nobody answers
        AgentClient.Time = _h.Clock;
        var sent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        AgentClient.RequestSentObserver = () => sent.TrySetResult();

        var answer = Task.Run(() => ClientUnlock());
        await sent.Task;
        _h.Clock.Advance(TimeSpan.FromSeconds(119));
        Assert.False(answer.IsCompleted);
        _h.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.IsType<AgentAnswer.NotRunning>(await answer);
    }

    [Fact]
    public void Client_MissingFolder_IsNotRunning_CreatesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.False(Directory.Exists(_h.Folder));

        Assert.IsType<AgentAnswer.NotRunning>(ClientUnlock());
        Assert.IsType<AgentAnswer.NotRunning>(AgentClient.Status(_h.SocketPath, _h.VaultId, AgentHarness.MyUid));
        Assert.IsType<AgentAnswer.NotRunning>(AgentClient.Stop(_h.SocketPath, _h.VaultId, AgentHarness.MyUid));

        Assert.False(Directory.Exists(_h.Folder));
        Assert.Empty(_h.Root.EnumerateFileSystemInfos());
    }

    [Fact]
    public async Task Client_MalformedAnswer_IsMalformed()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        using var listener = Listen(_h.SocketPath);
        // An Ok answer to an unlock whose key isn't 32 bytes.
        var serving = ServeOnceAsync(listener, AgentProtocol.EncodeResponse(AgentStatus.Ok, new byte[31]));

        Assert.IsType<AgentAnswer.Malformed>(await Task.Run(() => ClientUnlock()));
        await serving;
    }

    // ------------------------------------------------------------------ starts (rulings 6 and 21)

    [Fact]
    public async Task Start_CreatesTheFolder0700_AndTheSocket()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.False(Directory.Exists(_h.Folder));

        var server = await _h.StartAsync();

        Assert.Equal(_h.SocketPath, server.SocketPath);
        var folder = BrokerNative.LStat(_h.Folder)!.Value;
        Assert.Equal((UnixFileMode)0b111_000_000, folder.Mode);
        Assert.Equal(AgentHarness.MyUid, folder.Uid);
        Assert.Equal(BrokerNative.EntryType.Socket, BrokerNative.LStat(_h.SocketPath)!.Value.Type);
        Assert.Equal(BrokerNative.EntryType.Regular,
            BrokerNative.LStat(Path.Combine(_h.Folder, $"agent-{AgentSocketPath.Prefix(_h.VaultId)}.lock"))!.Value.Type);
        var running = Assert.IsType<AgentAnswer.Running>(await Task.Run(() => AgentClient.Status(_h.SocketPath, _h.VaultId, AgentHarness.MyUid)));
        Assert.Null(running.ExpiresAt);
        Assert.Equal(0u, running.RefusedPeers);
    }

    [Fact]
    public async Task StaleSocket_StartReplacesIt_ClientFallsBack()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        File.SetUnixFileMode(_h.Folder, (UnixFileMode)0b111_000_000);
        // An agent killed without cleaning up: the socket file stays, nothing listens. (.NET unlinks a
        // bound socket's path on Dispose, so bind elsewhere and move the file into place.)
        var elsewhere = Path.Combine(_h.Root.FullName, "dead.sock");
        using (Listen(elsewhere))
            File.Move(elsewhere, _h.SocketPath);
        Assert.Equal(BrokerNative.EntryType.Socket, BrokerNative.LStat(_h.SocketPath)!.Value.Type);

        // The CLI falls back at once (connection refused), well within its connect deadline.
        AgentClient.Time = _h.Clock; // never advanced: a hang would not end
        Assert.IsType<AgentAnswer.NotRunning>(await Task.Run(() => ClientUnlock()));

        await _h.StartAsync();
        Assert.Equal(_h.Key, Assert.IsType<AgentAnswer.Unlocked>(await Task.Run(() => ClientUnlock())).VaultKey);
    }

    [Fact]
    public async Task TwoConcurrentStarts_ExactlyOneReady_OtherAlreadyRunning()
    {
        if (OperatingSystem.IsWindows())
            return;
        var starts = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => Task.Run(async () =>
        {
            try
            {
                return (Server: await AgentServer.StartAsync(_h.Options()), Error: (string?)null);
            }
            catch (TswapException ex)
            {
                return (Server: (AgentServer?)null, Error: ex.Message);
            }
        })));

        var ready = Assert.Single(starts, s => s.Server is not null);
        var refused = Assert.Single(starts, s => s.Server is null);
        Assert.Equal($"An agent for this vault is already running ({_h.SocketPath}).", refused.Error);
        Assert.IsType<AgentAnswer.Running>(await Task.Run(() => AgentClient.Status(_h.SocketPath, _h.VaultId, AgentHarness.MyUid)));
        await ready.Server!.DisposeAsync();
    }

    [Fact]
    public async Task LiveAgent_SecondStart_AlreadyRunning_LiveSocketUntouched()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        var before = BrokerNative.Identify(_h.SocketPath, follow: false);

        var ex = await Assert.ThrowsAsync<TswapException>(() => AgentServer.StartAsync(_h.Options()));

        Assert.Equal($"An agent for this vault is already running ({_h.SocketPath}).", ex.Message);
        Assert.Equal(1, ex.ExitCode);
        if (OperatingSystem.IsLinux())
            Assert.Equal(before, BrokerNative.Identify(_h.SocketPath, follow: false));
        Assert.IsType<AgentAnswer.Unlocked>(await Task.Run(() => ClientUnlock()));
    }

    [Fact]
    public async Task LockHeld_SaysAlreadyRunning()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        File.SetUnixFileMode(_h.Folder, (UnixFileMode)0b111_000_000);
        using var held = UnixLockFile.TryTake(Path.Combine(_h.Folder, $"agent-{AgentSocketPath.Prefix(_h.VaultId)}.lock"), out _);
        Assert.NotNull(held);

        var ex = await Assert.ThrowsAsync<TswapException>(() => AgentServer.StartAsync(_h.Options()));

        Assert.Equal($"An agent for this vault is already running ({_h.SocketPath}).", ex.Message);
        Assert.Equal(BrokerNative.EntryType.Missing, BrokerNative.LStat(_h.SocketPath)!.Value.Type);
    }

    [Fact]
    public async Task Probe_AcceptsButNeverAnswers_RefusesWithoutReplacing()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        File.SetUnixFileMode(_h.Folder, (UnixFileMode)0b111_000_000);
        using var squatter = Listen(_h.SocketPath); // accepts (into the backlog) and never answers
        var before = BrokerNative.Identify(_h.SocketPath, follow: false);

        var ex = await Assert.ThrowsAsync<TswapException>(() =>
            AgentServer.StartAsync(_h.Options() with { Time = TimeProvider.System, ProbeTimeout = TimeSpan.FromMilliseconds(200) }));

        Assert.Equal($"{_h.SocketPath} is in use by a process that doesn't answer; stop it, or remove the socket by hand.", ex.Message);
        if (OperatingSystem.IsLinux())
            Assert.Equal(before, BrokerNative.Identify(_h.SocketPath, follow: false));
        Assert.Equal(TimeSpan.FromSeconds(2), _h.Options().ProbeTimeout);
    }

    [Fact]
    public async Task Probe_SomethingAnswers_AlreadyRunning()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        File.SetUnixFileMode(_h.Folder, (UnixFileMode)0b111_000_000);
        using var listener = Listen(_h.SocketPath); // an agent without the lock (e.g. another lock path) that answers
        var serving = ServeOnceAsync(listener, AgentProtocol.EncodeResponse(AgentStatus.Ok, AgentProtocol.EncodeStatusPayload(null, 0)));

        var ex = await Assert.ThrowsAsync<TswapException>(() => AgentServer.StartAsync(_h.Options()));

        Assert.Equal($"An agent for this vault is already running ({_h.SocketPath}).", ex.Message);
        await serving;
    }

    [Fact]
    public async Task NonSocketFileAtPath_Refused()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        File.SetUnixFileMode(_h.Folder, (UnixFileMode)0b111_000_000);
        await File.WriteAllTextAsync(_h.SocketPath, "not a socket");

        var ex = await Assert.ThrowsAsync<TswapException>(() => AgentServer.StartAsync(_h.Options()));

        Assert.Equal($"{_h.SocketPath} exists and is not a stale socket of this user; remove it by hand.", ex.Message);
        Assert.Equal("not a socket", await File.ReadAllTextAsync(_h.SocketPath));
    }

    [Fact]
    public async Task Serve_RefusesRoot_LeavesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        var ex = await Assert.ThrowsAsync<TswapException>(() =>
            AgentServer.StartAsync(_h.Options(ownership: new AgentOwnership(privileged: true)) with { VaultUserName = "alice" }));

        Assert.Equal("Don't run the agent as root: run 'tswap agent start' as the vault user (alice), without sudo.", ex.Message);
        Assert.Empty(_h.Root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories)); // no folder, socket, lock or temp file
    }

    [Fact]
    public async Task Serve_FolderChecksApply_ToAnExistingFolder()
    {
        if (OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(_h.Folder);
        File.SetUnixFileMode(_h.Folder, (UnixFileMode)0b111_101_101);

        var ex = await Assert.ThrowsAsync<TswapException>(() => AgentServer.StartAsync(_h.Options()));

        Assert.Contains("0755", ex.Message);
        Assert.Empty(Directory.EnumerateFileSystemEntries(_h.Folder));
    }

    [Fact]
    public async Task Stop_RemovesTheSocket_ReleasesTheLock_SoANewStartWorks()
    {
        if (OperatingSystem.IsWindows())
            return;
        var server = await _h.StartAsync();
        Assert.IsType<AgentAnswer.Stopped>(await Task.Run(() => AgentClient.Stop(_h.SocketPath, _h.VaultId, AgentHarness.MyUid)));
        await server.Stopped;
        Assert.Equal(BrokerNative.EntryType.Missing, BrokerNative.LStat(_h.SocketPath)!.Value.Type);

        await _h.StartAsync();
        Assert.IsType<AgentAnswer.Unlocked>(await Task.Run(() => ClientUnlock()));
    }

    // ------------------------------------------------------------------ hardening (ruling 12)

    [Fact]
    public void Hardening_LinuxDumpableFailure_Refuses_OtherFailuresWarn()
    {
        var warnings = new List<string>();
        var failingDumpable = new ProcessHardening.Steps(
            MakeNonDumpable: () => false, DenyAttach: () => true, ZeroCoreLimit: () => true, DenyProcessAccess: () => true);
        var ex = Assert.Throws<TswapException>(() =>
            ProcessHardening.HardenHolder(warnings.Add, failingDumpable, ProcessHardening.Platform.Linux));
        Assert.Contains("PR_SET_DUMPABLE", ex.Message);

        var failingMac = new ProcessHardening.Steps(
            MakeNonDumpable: () => true, DenyAttach: () => false, ZeroCoreLimit: () => false, DenyProcessAccess: () => true);
        ProcessHardening.HardenHolder(warnings.Add, failingMac, ProcessHardening.Platform.MacOs);
        Assert.Equal(2, warnings.Count);
        Assert.Contains(warnings, w => w.Contains("PT_DENY_ATTACH"));
        Assert.Contains(warnings, w => w.Contains("RLIMIT_CORE"));

        warnings.Clear();
        var failingWindows = new ProcessHardening.Steps(
            MakeNonDumpable: () => true, DenyAttach: () => true, ZeroCoreLimit: () => true, DenyProcessAccess: () => false);
        ProcessHardening.HardenHolder(warnings.Add, failingWindows, ProcessHardening.Platform.Windows);
        Assert.Contains("DACL", Assert.Single(warnings));

        // Each platform runs only its own steps.
        var calls = new List<string>();
        var counting = new ProcessHardening.Steps(
            MakeNonDumpable: () => { calls.Add("dumpable"); return true; },
            DenyAttach: () => { calls.Add("deny-attach"); return true; },
            ZeroCoreLimit: () => { calls.Add("core"); return true; },
            DenyProcessAccess: () => { calls.Add("dacl"); return true; });
        ProcessHardening.HardenHolder(warnings.Add, counting, ProcessHardening.Platform.Linux);
        ProcessHardening.HardenHolder(warnings.Add, counting, ProcessHardening.Platform.MacOs);
        ProcessHardening.HardenHolder(warnings.Add, counting, ProcessHardening.Platform.Windows);
        Assert.Equal(["dumpable", "deny-attach", "core", "dacl"], calls);
    }

    [Fact]
    public void Hardening_WindowsDacl_PrependsTheDenyAce()
    {
        const string sid = "S-1-5-21-1-2-3-1001";
        Assert.Equal($"D:P(D;;0x7a;;;{sid})(A;;0x1fffff;;;SY)",
            ProcessHardening.WithDenyAce("D:P(A;;0x1fffff;;;SY)", sid));
        Assert.Equal($"O:BAD:(D;;0x7a;;;{sid})(A;;GA;;;BA)",
            ProcessHardening.WithDenyAce("O:BAD:(A;;GA;;;BA)", sid));
        Assert.Equal($"D:(D;;0x7a;;;{sid})", ProcessHardening.WithDenyAce("D:", sid));
    }

    // ------------------------------------------------------------------ Windows

    [Fact]
    public async Task Windows_Client_RefusesServerOfAnotherSid()
    {
        if (!OperatingSystem.IsWindows())
            return;
        await _h.StartAsync();
        Assert.IsType<AgentAnswer.Unlocked>(await Task.Run(() => ClientUnlock()));

        WindowsPipeIdentity.ReadServerSid = _ => "S-1-5-21-9-9-9-4242";
        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => ClientUnlock()));
        Assert.Contains("S-1-5-21-9-9-9-4242", ex.Message);
        Assert.Equal(1, _h.UnlockCalls);
        WindowsPipeIdentity.ReadServerSid = WindowsPipeIdentity.DefaultReadServerSid;
    }

    // ------------------------------------------------------------------ helpers

    private static Socket Listen(string path)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Bind(new UnixDomainSocketEndPoint(path));
        socket.Listen(16);
        return socket;
    }

    /// <summary>Accepts one connection, reads one request and answers <paramref name="response"/>.</summary>
    private static async Task ServeOnceAsync(Socket listener, byte[] response)
    {
        using var accepted = await listener.AcceptAsync();
        using var stream = new NetworkStream(accepted, ownsSocket: false);
        await AgentProtocol.ReadFrameAsync(stream, CancellationToken.None);
        await stream.WriteAsync(response);
    }
}
