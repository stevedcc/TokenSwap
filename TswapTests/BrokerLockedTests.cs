using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using TswapCore.Broker.Templates;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 12 (rulings 12, 13, 14 and 20): a broker whose slot has the vault password starts
/// locked; every request is refused like a busy one and never counted as an unlock failure;
/// <c>broker unlock</c> proves the password over the control socket and the broker holds it until
/// <c>broker lock</c> or its timeout; the process is dumpable only while it holds nothing; both ends of
/// the control socket check each other.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class BrokerLockedTests : IAsyncLifetime
{
    private readonly ControlHarness _c = new();
    private readonly List<IAsyncDisposable> _more = [];
    private readonly List<IDisposable> _disposables = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (var d in _more)
            await d.DisposeAsync();
        foreach (var d in _disposables)
            d.Dispose();
        await _c.DisposeAsync();
        BrokerCommand.ResetSeamsForTests();
        AgentClient.ResetSeamsForTests();
    }

    private static uint MyUid => ControlHarness.MyUid;

    private const string TokRef = "\"{{tok}}\"";

    private static int Index(List<string> events, string e) => events.IndexOf(e);

    private static int LastIndex(List<string> events, string e) => events.LastIndexOf(e);

    /// <summary>A broker on HTTP sockets whose lock state is <see cref="ControlHarness.State"/>.</summary>
    private async Task<BrokerHarness> HttpBrokerAsync(BrokerLimits? limits = null)
    {
        var h = new BrokerHarness();
        _more.Add(h);
        await h.StartAsync(limits: limits, password: _c.State);
        return h;
    }

    private async Task<(BrokerHarness H, BrokerServer Server)> HttpBrokerWithSourceAsync(IBrokerSecretSource source)
    {
        var h = new BrokerHarness();
        _more.Add(h);
        var holder = new BrokerPolicyHolder(BrokerPolicy.Parse(h.Config()));
        var server = await BrokerServer.StartAsync(h.Options() with { Policy = holder, Secrets = source, Password = _c.State });
        _more.Add(server);
        return (h, server);
    }

    // ================================================================== the locked answer

    [Fact]
    public async Task LockedBroker_HttpAnswerIsByteIdenticalToTheBusyRefusal()
    {
        if (OperatingSystem.IsWindows())
            return;
        _c.NewState();
        var locked = await HttpBrokerAsync();
        var lockedBytes = await locked.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: broker\r\nConnection: close\r\n\r\n");

        // A password-free broker at its unlock-rate ceiling: the refusal it already gives (same clock).
        var limited = new BrokerHarness();
        _more.Add(limited);
        await limited.StartAsync(limits: new BrokerLimits { MaxUnlocksPerMinute = 0 });
        var limitedBytes = await limited.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: broker\r\nConnection: close\r\n\r\n");

        Assert.Equal(503, BrokerHarness.StatusOf(Encoding.Latin1.GetString(lockedBytes)));
        Assert.Equal(limitedBytes, lockedBytes);
        Assert.Contains("reason=unlock-rate", limited.LogText.ToString());
        Assert.Contains("status=503", locked.LogText.ToString());
        Assert.Contains("reason=locked", locked.LogText.ToString());
        Assert.Equal(0, locked.Secrets.Unlocks);
    }

    [Fact]
    public async Task LockedBroker_SshAgentAndCall_GetTheirUniformRefusal()
    {
        if (OperatingSystem.IsWindows())
            return;
        _c.NewState();

        // The ssh-agent endpoint: every request, the identities list included, is SSH_AGENT_FAILURE.
        var ssh = new SshAgentHarness();
        _more.Add(ssh);
        var source = new CountingKeySource();
        await ssh.StartAsync(ssh.Config(), _ => new SshAgentOptions { Keys = new Dictionary<string, SshAgentKey>(), KeySource = source },
            password: _c.State);
        using (var client = await ssh.ConnectAsync("lane1"))
        {
            var identities = await client.RequestAsync(SshAgentMessages.RequestIdentities);
            Assert.Equal(new byte[] { SshAgentProtocol.Failure }, identities);
            // A sign request: refused the same way, before any check that could unlock.
            var sign = new SshWriter().Byte(SshAgentProtocol.SignRequest).String(SshAgentMessages.Ed25519Blob(1)).String([1, 2]).UInt32(0).ToArray();
            var signed = await client.RequestAsync(sign);
            Assert.Equal(new byte[] { SshAgentProtocol.Failure }, signed);
        }
        Assert.Equal(0, source.Reads);
        Assert.Contains("reason=locked", ssh.Broker.LogText.ToString());

        // broker call: the 503 every refused template call gets, so the client exits 125.
        using var bed = new SandboxBed();
        var h = new BrokerHarness();
        _more.Add(h);
        var script = bed.Script("echo ran", "t.sh");
        var config = $$"""
            {
              "version": 1,
              "socket_dir": {{JsonSerializer.Serialize(h.SocketDir)}},
              "sockets": [ { "name": "lane1", "uids": ["{{MyUid}}"], "routes": [], "templates": ["t"] } ],
              "routes": [],
              "templates": [ { "name": "t", "argv": ["/bin/bash", {{JsonSerializer.Serialize(script)}}], "args": {},
                               "env": { "S": {{TokRef}} }, "binds": [ { "path": {{JsonSerializer.Serialize(bed.Work)}} } ] } ]
            }
            """;
        await h.StartAsync(config, password: _c.State);
        var errors = new StringWriter();
        var exit = await BrokerTemplateClient.CallAsync(h.SocketPath("lane1"), "t", new Dictionary<string, string>(),
            new MemoryStream(), new MemoryStream(), errors);
        Assert.Equal(BrokerTemplateClient.BrokerError, exit);
        Assert.Contains("503", errors.ToString());
        await h.WaitForLogAsync("reason=locked"); // logged after the answer is written
        Assert.Equal(0, h.Secrets.Unlocks);
    }

    [Fact]
    public async Task Locked_IsNotCountedAsUnlockFailure()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        var h = await HttpBrokerAsync();

        for (var i = 0; i < 50; i++)
            Assert.Equal(503, BrokerHarness.StatusOf(await h.GetAsync("lane1", "/echo/a")));
        Assert.Equal(0, h.Secrets.Unlocks);

        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());

        Assert.Equal(200, BrokerHarness.StatusOf(await h.GetAsync("lane1", "/echo/a")));
        Assert.Equal(1, h.Secrets.Unlocks);
    }

    // ================================================================== unlock, lock, status

    [Fact]
    public async Task Unlock_ThenStatus_ThenLock_InProcess()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        var before = Assert.IsType<BrokerControlAnswer.State>(await _c.StatusAsync());
        Assert.False(before.Unlocked);

        var expires = _c.Clock.GetUtcNow().AddHours(8);
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync(expiresAt: expires));
        var during = Assert.IsType<BrokerControlAnswer.State>(await _c.StatusAsync());
        Assert.True(during.Unlocked);
        Assert.Equal(expires.ToUnixTimeSeconds(), during.ExpiresAt!.Value.ToUnixTimeSeconds());
        Assert.False(_c.State.IsLocked);
        Assert.Equal(_c.Right, _c.HeldBytes());

        Assert.IsType<BrokerControlAnswer.Done>(await _c.LockAsync());
        Assert.True(_c.State.IsLocked);
        Assert.False(Assert.IsType<BrokerControlAnswer.State>(await _c.StatusAsync()).Unlocked);
        Assert.Throws<BrokerLockedException>(() => _c.State.CloneHeld());
    }

    [Fact]
    public async Task Unlock_WrongPassword_StaysLocked_SaysWrongPassword()
    {
        if (OperatingSystem.IsWindows())
            return;
        // The real proof (simulated TPM password slot) through the CLI's 'broker unlock'.
        using var m = new FleetMachine("bk-wrong") { Tpm = RandomNumberGenerator.GetBytes(32) };
        var fleet = await RealVaultBrokerAsync(m);

        var (exit, _, stderr) = m.RunOnTerminal("not the password\n", "broker", "unlock");

        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, stderr);
        Assert.True(fleet.State.IsLocked);
        Assert.Throws<BrokerLockedException>(() => fleet.State.CloneHeld());

        // The right one then opens it, and status and lock say so.
        var (ok, okOut, okErr) = m.RunOnTerminal(Password + "\n", "broker", "unlock");
        Assert.True(ok == 0, okErr);
        Assert.Contains("The broker is unlocked.", okOut);
        Assert.Contains(BrokerCommand.RamDisclosure, okErr);
        Assert.False(fleet.State.IsLocked);
        Assert.Contains("The broker is unlocked", m.Ok("", "broker", "status"));
        Assert.Contains("The broker is locked.", m.Ok("", "broker", "lock"));
        Assert.True(fleet.State.IsLocked);
        Assert.Contains("The broker is locked.", m.Ok("", "broker", "status"));
    }

    [Fact]
    public async Task BrokerUnlock_RamDisclosureOnStderr_BeforeThePrompt()
    {
        // Review T17 p3 GLM I1/M3: the disclosure is said before the user types the password, on stderr.
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-disclose") { Tpm = RandomNumberGenerator.GetBytes(32) };
        await RealVaultBrokerAsync(m);

        var (exit, stdout, stderr) = m.RunOnTerminal(Password + "\n", "broker", "unlock");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain(BrokerCommand.RamDisclosure, stdout);
        var disclosure = stderr.IndexOf(BrokerCommand.RamDisclosure, StringComparison.Ordinal);
        Assert.True(disclosure >= 0, stderr);
        Assert.Equal(disclosure, stderr.LastIndexOf(BrokerCommand.RamDisclosure, StringComparison.Ordinal));
        Assert.True(disclosure < stderr.IndexOf(TerminalPasswordProvider.PromptText, StringComparison.Ordinal), stderr);
    }

    [Fact]
    public void BrokerUnlock_NoBrokerRunning_SaysSoBeforeThePrompt()
    {
        // Review T17 p3 GLM I1 (second half): a broker that doesn't answer is found before the password is typed.
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-absent") { Tpm = RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var path = Path.Combine(_c.Root.FullName, "absent", "control.sock");
        BrokerCommand.ControlPathOverride = (_, _) => path;

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "broker", "unlock");

        Assert.NotEqual(0, exit);
        Assert.Contains($"No 'tswap broker serve' answers at {path}; is it running?", stderr);
        Assert.DoesNotContain(TerminalPasswordProvider.PromptText, stderr);
    }

    private const string Password = "correct horse battery staple";

    /// <summary>
    /// A record vault with one simulated TPM password slot on <paramref name="m"/>, and this harness's
    /// control server proving with the real unlocker (as serve does); 'broker unlock|lock|status' on
    /// <paramref name="m"/> reach it through the control-path seam.
    /// </summary>
    private async Task<ControlHarness> RealVaultBrokerAsync(FleetMachine m)
    {
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var vaultId = m.Keyring.VaultId;
        var c = new ControlHarness(vaultId);
        _more.Add(c);
        var store = new RecordVaultStore(m.Dir);
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm!)]);
        await c.StartAsync(prove: candidate => BrokerPasswordProof.Prove(store, unlocker, candidate));
        BrokerCommand.ControlPathOverride = (_, _) => c.SocketPath;
        return c;
    }

    [Fact]
    public async Task UnlockWhileUnlocked_RefusedBeforePayloadRead()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        var reads = _c.Events.Count(e => e == "payload-read");
        var proofs = _c.ProveCalls;

        Assert.Equal(BrokerPasswordState.AlreadyUnlockedText, ControlHarness.Refusal(await _c.UnlockAsync(right: false)));

        Assert.Equal(reads, _c.Events.Count(e => e == "payload-read"));
        Assert.Equal(proofs, _c.ProveCalls);
        Assert.Equal(_c.Right, _c.HeldBytes());
    }

    [Fact]
    public async Task TwoConcurrentUnlocks_OneFails()
    {
        if (OperatingSystem.IsWindows())
            return;
        // Right first, wrong second: the second is refused as already unlocked, its payload never read.
        await _c.StartAsync();
        _c.ProveGate = ControlHarness.NewSignal();
        var first = _c.UnlockAsync(right: true);
        await _c.ProveEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var second = _c.UnlockAsync(right: false);
        await _c.QueuedAsync(2);
        Assert.Equal(1, _c.Events.Count(e => e == "payload-read")); // the second payload waits in the kernel
        _c.ProveGate.SetResult();

        Assert.IsType<BrokerControlAnswer.Done>(await first);
        Assert.Equal(BrokerPasswordState.AlreadyUnlockedText, ControlHarness.Refusal(await second));
        Assert.Equal(1, _c.Events.Count(e => e == "payload-read"));
        Assert.Equal(_c.Right, _c.HeldBytes());
    }

    [Fact]
    public async Task TwoConcurrentUnlocks_WrongFirst_RightSecond_Unlocks()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        _c.ProveGate = ControlHarness.NewSignal();
        var first = _c.UnlockAsync(right: false);
        await _c.ProveEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var second = _c.UnlockAsync(right: true);
        await _c.QueuedAsync(2);
        Assert.Equal(1, _c.Events.Count(e => e == "payload-read"));
        _c.ProveGate.SetResult();

        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ControlHarness.Refusal(await first));
        Assert.IsType<BrokerControlAnswer.Done>(await second);
        Assert.Equal(2, _c.Events.Count(e => e == "payload-read"));
        Assert.Equal(_c.Right, _c.HeldBytes());
    }

    // ================================================================== ruling 12: the dumpable transitions

    [Fact]
    public void DumpableTransitions_LockedStart_IsDumpable_PasswordFree_NeverDumpable()
    {
        BrokerPasswordState.HardenAtStart(_c.Hardening(), password: true, _ => { });
        Assert.Equal(["set-dumpable:True", "dumpable:True"], _c.Events);

        var mark = _c.Mark;
        BrokerPasswordState.HardenAtStart(_c.Hardening(), password: false, _ => { });
        Assert.Equal(["set-dumpable:False", "dumpable:False"], _c.EventsSince(mark));
    }

    [Fact]
    public void DumpableTransitions_PasswordFreeStart_CantBecomeNonDumpable_Refuses()
    {
        var ex = Assert.Throws<TswapException>(() =>
            BrokerPasswordState.HardenAtStart(_c.Hardening(dumpableWorks: false), password: false, _ => { }));
        Assert.Contains("non-dumpable", ex.Message);
    }

    [Fact]
    public async Task DumpableTransitions_Unlock_NonDumpableBeforeThePayloadRead()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        var mark = _c.Mark;

        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());

        var events = _c.EventsSince(mark);
        Assert.True(Index(events, "dumpable:False") >= 0, string.Join(", ", events));
        Assert.True(Index(events, "dumpable:False") < Index(events, "payload-read"), string.Join(", ", events));
        Assert.DoesNotContain("dumpable:True", events);
    }

    [Fact]
    public async Task DumpableTransitions_Lock_ZeroesAndUnloadsBeforeDumpable()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        var mark = _c.Mark;

        Assert.IsType<BrokerControlAnswer.Done>(await _c.LockAsync());

        Assert.Equal(["free", "ssh-unloaded", "set-dumpable:True", "dumpable:True"], _c.EventsSince(mark));
    }

    [Fact]
    public async Task DumpableTransitions_Timeout_ZeroesAndUnloadsBeforeDumpable()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync(expiresAt: _c.Clock.GetUtcNow().AddMinutes(5)));
        var mark = _c.Mark;
        var locked = ControlHarness.NewSignal();
        BrokerPasswordState.DumpableObserver = d =>
        {
            _c.Add($"dumpable:{d}");
            if (d)
                locked.TrySetResult();
        };

        _c.Clock.Advance(TimeSpan.FromMinutes(5));
        await locked.Task.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Equal(["free", "ssh-unloaded", "set-dumpable:True", "dumpable:True"], _c.EventsSince(mark));
        Assert.True(_c.State.IsLocked);
        Assert.Contains("timeout", _c.LogText);
    }

    [Fact]
    public async Task DumpableTransitions_FailedProof_ClonesAndCandidateFreedBeforeDumpable()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        var mark = _c.Mark;

        var answer = await _c.UnlockAsync(right: false);

        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ControlHarness.Refusal(answer));
        var events = _c.EventsSince(mark);
        var dumpable = LastIndex(events, "dumpable:True");
        Assert.True(dumpable > 0, string.Join(", ", events));
        // The proof's clone and the candidate: both zeroed and freed before the broker is dumpable again.
        Assert.Equal(2, events.Take(dumpable).Count(e => e == "free"));
        Assert.True(Index(events, "payload-read") < Index(events, "free"));
        Assert.DoesNotContain("free-NOT-zeroed", events);
        Assert.True(_c.State.IsLocked);
    }

    [Fact]
    public async Task DumpableTransitions_LockCantMakeDumpableAgain_StopsServe()
    {
        // Ruling 12 (controller ruling, review T17 p2 MiMo I3): a failed PR_SET_DUMPABLE 1 on the way
        // back to locked is fatal for serve, like the other transitions.
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        Assert.Empty(_c.FatalReasons);
        _c.DumpableOneFails = true;

        await _c.LockAsync();

        var reason = Assert.Single(_c.FatalReasons);
        Assert.Contains("PR_SET_DUMPABLE", reason);
        Assert.True(_c.State.IsLocked);
        Assert.Throws<BrokerLockedException>(() => _c.State.CloneHeld());
    }

    [Fact]
    public async Task DumpableTransitions_FailedProofCantMakeDumpableAgain_StopsServe()
    {
        // Review T17 p2 GLM M-1 / MiMo I3: the failed proof's way back to locked is a transition too.
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        _c.DumpableOneFails = true;

        var answer = await _c.UnlockAsync(right: false);

        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ControlHarness.Refusal(answer));
        var reason = Assert.Single(_c.FatalReasons);
        Assert.Contains("PR_SET_DUMPABLE", reason);
        Assert.True(_c.State.IsLocked);
    }

    [Fact]
    public async Task Unlock_SshKeyCantLoad_StaysLocked_NamesTheKey_NotCountedByTheGuard()
    {
        if (OperatingSystem.IsWindows())
            return;
        var loads = 0;
        _c.LoadSshKeys = () =>
        {
            loads++;
            throw new SshKeyLoadException("deploy", "secret 'deploy-key' is not in the vault",
                "Ssh key 'deploy' (secret 'deploy-key'): secret 'deploy-key' is not in the vault.");
        };
        await _c.StartAsync();

        // More failures than the guard allows before a lockout: none of them is counted.
        for (var i = 0; i < new BrokerLimits().FailuresBeforeLockout + 1; i++)
        {
            var mark = _c.Mark;
            Assert.Equal("ssh key 'deploy' can't be loaded: secret 'deploy-key' is not in the vault",
                ControlHarness.Refusal(await _c.UnlockAsync()));
            Assert.True(_c.State.IsLocked);
            var events = _c.EventsSince(mark);
            // Drained, zeroed and unloaded before it is dumpable (and so unlockable) again.
            Assert.True(Index(events, "ssh-unloaded") < LastIndex(events, "dumpable:True"), string.Join(", ", events));
            // The proof's clone and the held password (the client's own copy is freed after the answer).
            Assert.Equal(2, events.Take(LastIndex(events, "dumpable:True")).Count(e => e == "free"));
        }
        Assert.Null(_c.Guard.Refusal(BrokerControlServer.GuardKey));

        // The key fixed: the next unlock succeeds.
        _c.LoadSshKeys = () => loads++;
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        Assert.False(_c.State.IsLocked);
    }

    [Fact]
    public async Task WrongPasswords_AreCountedByTheGuard()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        for (var i = 0; i < new BrokerLimits().FailuresBeforeLockout; i++)
            Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ControlHarness.Refusal(await _c.UnlockAsync(right: false)));
        var proofs = _c.ProveCalls;
        var reads = _c.Events.Count(e => e == "payload-read");

        Assert.Equal(BrokerControlServer.TooManyFailuresText, ControlHarness.Refusal(await _c.UnlockAsync(right: true)));

        Assert.Equal(proofs, _c.ProveCalls);
        Assert.Equal(reads, _c.Events.Count(e => e == "payload-read"));
        Assert.True(_c.State.IsLocked);
    }

    [Fact]
    public async Task MissingVaultPasswordFile_IsNotCountedByTheGuard()
    {
        // Review T17 p2 MiMo minor 2: a broken configuration (no vault-password file, or conflicting
        // copies) must not trip the brute-force guard and then refuse the right password.
        if (OperatingSystem.IsWindows())
            return;
        var missing = true;
        await _c.StartAsync(prove: candidate =>
            missing ? throw new VaultPasswordUnavailableException(VaultPasswordMessages.MissingFile) : _c.Prove(candidate));
        for (var i = 0; i < new BrokerLimits().FailuresBeforeLockout + 1; i++)
            Assert.Equal(VaultPasswordMessages.MissingFile, ControlHarness.Refusal(await _c.UnlockAsync()));
        missing = false;

        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        Assert.False(_c.State.IsLocked);
    }

    // ================================================================== returns to locked with work in flight

    /// <summary>A route secret source whose unlock takes a clone of the held password, as the real one does, and can block.</summary>
    private sealed class ProviderSecrets(BrokerPasswordState state) : IBrokerSecretSource
    {
        public TaskCompletionSource? Gate { get; set; }
        public TaskCompletionSource Entered { get; } = ControlHarness.NewSignal();

        public BrokerSecret Read(string secretName)
        {
            using var clone = state.Provider();
            Entered.TrySetResult();
            Gate?.Task.GetAwaiter().GetResult();
            return new BrokerSecret("value"u8.ToArray());
        }
    }

    [Fact]
    public async Task LockWithUnlockInFlight_DrainsBeforeDumpable_HttpRequest()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        var secrets = new ProviderSecrets(_c.State) { Gate = ControlHarness.NewSignal() };
        var (h, _) = await HttpBrokerWithSourceAsync(secrets);
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());

        var request = h.GetAsync("lane1", "/echo/a");
        await secrets.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var drain = ControlHarness.NewSignal();
        BrokerPasswordState.DrainWaitObserver = () =>
        {
            _c.Add("drain-wait");
            drain.TrySetResult();
        };
        var mark = _c.Mark;
        var lockAnswer = _c.LockAsync();
        await drain.Task.WaitAsync(TimeSpan.FromSeconds(30));

        // The lock waits for the request: nothing zeroed, nothing dumpable yet, and new requests already refused.
        Assert.False(lockAnswer.IsCompleted);
        Assert.Equal(["drain-wait"], _c.EventsSince(mark));
        Assert.True(_c.State.IsLocked);
        Assert.Equal(503, BrokerHarness.StatusOf(await h.GetAsync("lane1", "/echo/a")));

        secrets.Gate.SetResult();
        Assert.Equal(200, BrokerHarness.StatusOf(await request));
        Assert.IsType<BrokerControlAnswer.Done>(await lockAnswer);
        // The request's clone, then the held password, then the keys, and only then dumpable.
        Assert.Equal(["drain-wait", "free", "free", "ssh-unloaded", "set-dumpable:True", "dumpable:True"], _c.EventsSince(mark));
    }

    [Fact]
    public async Task TimeoutWithUnlockInFlight_DrainsBeforeDumpable_HttpRequest()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        var secrets = new ProviderSecrets(_c.State) { Gate = ControlHarness.NewSignal() };
        var (h, _) = await HttpBrokerWithSourceAsync(secrets);
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync(expiresAt: _c.Clock.GetUtcNow().AddMinutes(10)));

        var request = h.GetAsync("lane1", "/echo/a");
        await secrets.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var drain = ControlHarness.NewSignal();
        var dumpable = ControlHarness.NewSignal();
        BrokerPasswordState.DrainWaitObserver = () =>
        {
            _c.Add("drain-wait");
            drain.TrySetResult();
        };
        BrokerPasswordState.DumpableObserver = d =>
        {
            _c.Add($"dumpable:{d}");
            if (d)
                dumpable.TrySetResult();
        };
        var mark = _c.Mark;
        _c.Clock.Advance(TimeSpan.FromMinutes(10));
        await drain.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(["drain-wait"], _c.EventsSince(mark));

        secrets.Gate.SetResult();
        Assert.Equal(200, BrokerHarness.StatusOf(await request));
        await dumpable.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(["drain-wait", "free", "free", "ssh-unloaded", "set-dumpable:True", "dumpable:True"], _c.EventsSince(mark));
    }

    [Fact]
    public async Task LockWithUnlockInFlight_DrainsBeforeDumpable_ProofInFlight()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        _c.ProveGate = ControlHarness.NewSignal();
        var unlock = _c.UnlockAsync();
        await _c.ProveEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var drain = ControlHarness.NewSignal();
        BrokerPasswordState.DrainWaitObserver = () =>
        {
            _c.Add("drain-wait");
            drain.TrySetResult();
        };
        var mark = _c.Mark;
        var lockAnswer = _c.LockAsync();
        await drain.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.False(lockAnswer.IsCompleted);

        _c.ProveGate.SetResult();

        Assert.Equal(BrokerPasswordState.LockedWhileUnlockingText, ControlHarness.Refusal(await unlock));
        Assert.IsType<BrokerControlAnswer.Done>(await lockAnswer);
        var events = _c.EventsSince(mark);
        var dumpable = LastIndex(events, "dumpable:True");
        // The proof's K_v, its clone and the candidate: all zeroed before dumpable 1.
        Assert.True(Index(events, "key-zeroed") >= 0 && Index(events, "key-zeroed") < dumpable, string.Join(", ", events));
        Assert.Equal(2, events.Take(dumpable).Count(e => e == "free"));
        Assert.DoesNotContain("free-NOT-zeroed", events);
        Assert.True(_c.State.IsLocked);
        Assert.Throws<BrokerLockedException>(() => _c.State.CloneHeld());
    }

    [Fact]
    public async Task UnlockQueuedAtLock_RefusedBeforePayloadRead()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();
        _c.ProveGate = ControlHarness.NewSignal();
        var first = _c.UnlockAsync();
        await _c.ProveEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var queued = _c.UnlockAsync();
        await _c.QueuedAsync(2);
        var drain = ControlHarness.NewSignal();
        BrokerPasswordState.DrainWaitObserver = () => drain.TrySetResult();
        var lockAnswer = _c.LockAsync();
        await drain.Task.WaitAsync(TimeSpan.FromSeconds(30));

        _c.ProveGate.SetResult();

        Assert.Equal(BrokerPasswordState.LockedWhileUnlockingText, ControlHarness.Refusal(await first));
        Assert.Equal(BrokerPasswordState.LockedWhileUnlockingText, ControlHarness.Refusal(await queued));
        Assert.IsType<BrokerControlAnswer.Done>(await lockAnswer);
        Assert.Equal(1, _c.Events.Count(e => e == "payload-read"));
        Assert.Equal(1, _c.ProveCalls);
    }

    [Fact]
    public async Task LockAfterTheProofHeld_NoSshKeys_AnswersLockedWhileUnlocking()
    {
        // Review T17 p2 (MiMo B1, GLM I-1): with no ssh keys configured, a return to locked that runs
        // after the candidate is held but before the answer is sent must not be answered "Ok".
        if (OperatingSystem.IsWindows())
            return;
        Assert.Null(_c.LoadSshKeys);
        await _c.StartAsync();
        var locks = 0;
        BrokerControlServer.ProofHeldObserver = () =>
        {
            locks++;
            _c.State.ReturnToLockedAsync("lock").GetAwaiter().GetResult();
        };

        var answer = await _c.UnlockAsync();

        Assert.Equal(1, locks);
        Assert.Equal(BrokerPasswordState.LockedWhileUnlockingText, ControlHarness.Refusal(answer));
        Assert.True(_c.State.IsLocked);
        Assert.Throws<BrokerLockedException>(() => _c.State.CloneHeld());
        Assert.DoesNotContain("unlocked", _c.LogText);
    }

    // ================================================================== macOS (seam order; the steps are faked, so this runs everywhere)

    [Fact]
    public async Task MacOs_DenyAttachBeforeFirstPayloadRead()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync(ProcessHardening.Platform.MacOs);

        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        var events = _c.Events;
        Assert.True(Index(events, "deny-attach-native") >= 0, string.Join(", ", events));
        Assert.True(Index(events, "deny-attach") < Index(events, "payload-read"), string.Join(", ", events));

        // For the process lifetime: a later unlock doesn't apply it again.
        Assert.IsType<BrokerControlAnswer.Done>(await _c.LockAsync());
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        Assert.Equal(1, _c.Events.Count(e => e == "deny-attach-native"));
    }

    [Fact]
    public void MacOs_CoreLimitZeroAtStart()
    {
        BrokerPasswordState.HardenAtStart(_c.Hardening(ProcessHardening.Platform.MacOs), password: true, _ => { });
        Assert.Contains("core-limit", _c.Events);
        Assert.DoesNotContain("deny-attach-native", _c.Events); // only before the first payload read

        var mark = _c.Mark;
        BrokerPasswordState.HardenAtStart(_c.Hardening(ProcessHardening.Platform.MacOs), password: false, _ => { });
        Assert.Equal(["core-limit"], _c.EventsSince(mark));
    }

    [Fact]
    public async Task MacOs_UnlockAtUnlockedBroker_ServerSaysAlreadyUnlocked()
    {
        if (OperatingSystem.IsWindows())
            return;
        // On macOS the client can't tell (no namespace link); the server refuses without reading the payload.
        await _c.StartAsync(ProcessHardening.Platform.MacOs);
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());

        Assert.Equal(BrokerPasswordState.AlreadyUnlockedText, ControlHarness.Refusal(await _c.UnlockAsync()));
        Assert.Equal(1, _c.Events.Count(e => e == "payload-read"));
    }

    // ================================================================== the client's checks of the server (ruling 14)

    private FakeControlServer FakeServer(byte[]? answer = null)
    {
        Directory.CreateDirectory(_c.RunDir);
        var fake = new FakeControlServer(Path.Combine(_c.RunDir, "fake.sock"), answer);
        _disposables.Add(fake);
        return fake;
    }

    private BrokerControlAnswer ClientUnlock(string path)
    {
        using var password = _c.Password();
        return BrokerControlClient.Unlock(path, _c.VaultId, MyUid, password, null);
    }

    [Fact]
    public async Task UnlockClient_UnreadableServerLink_RefusesNothingSent()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var fake = FakeServer(FakeControlServer.Answer(AgentStatus.Ok));
        PeerIdentity.ReadUserNamespace = _ => null; // EACCES: a non-dumpable (unlocked, or not the real) broker

        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => ClientUnlock(fake.Path_)));

        Assert.Equal(BrokerControlClient.UnreadableServerLinkText, ex.Message);
        await fake.Served.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(fake.Received);
    }

    [Fact]
    public async Task UnlockClient_RefusesServerOfAnotherUid()
    {
        if (OperatingSystem.IsWindows())
            return;
        var fake = FakeServer(FakeControlServer.Answer(AgentStatus.Ok));
        PeerIdentity.ReadCredentials = _ => (MyUid + 1, 4242);

        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => ClientUnlock(fake.Path_)));

        Assert.Contains($"uid {MyUid + 1}", ex.Message);
        await fake.Served.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(fake.Received);
    }

    [Fact]
    public async Task UnlockClient_RefusesServerInAnotherUserNamespace_NeverSends()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var fake = FakeServer(FakeControlServer.Answer(AgentStatus.Ok));
        PeerIdentity.ReadUserNamespace = _ => "user:[4026531999]";

        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => ClientUnlock(fake.Path_)));

        Assert.Contains("peer in another user namespace", ex.Message);
        await fake.Served.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(fake.Received);
    }

    [Fact]
    public async Task UnlockClient_RefusesServerWithContainerLabel()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var fake = FakeServer(FakeControlServer.Answer(AgentStatus.Ok));
        PeerIdentity.ReadPeerLabel = _ => "system_u:system_r:container_t:s0:c1,c2";

        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => ClientUnlock(fake.Path_)));

        Assert.Contains("peer label container_t", ex.Message);
        await fake.Served.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(fake.Received);
    }

    [Fact]
    public async Task LockAndStatus_NoNamespaceCheck_UidAndLabelOnly()
    {
        if (!OperatingSystem.IsLinux())
            return;
        // A server in another user namespace (a non-dumpable unlocked broker reads that way too): lock and status still work.
        PeerIdentity.ReadUserNamespace = _ => "user:[4026531999]";
        var lockServer = FakeServer(FakeControlServer.Answer(AgentStatus.Ok));
        Assert.IsType<BrokerControlAnswer.Done>(await Task.Run(() => BrokerControlClient.Lock(lockServer.Path_, _c.VaultId, MyUid)));
        _disposables.Remove(lockServer);
        lockServer.Dispose();

        var statusServer = FakeServer(FakeControlServer.Answer(AgentStatus.Ok, BrokerControlProtocol.EncodeStatus(true, null, 0)));
        Assert.True(Assert.IsType<BrokerControlAnswer.State>(
            await Task.Run(() => BrokerControlClient.Status(statusServer.Path_, _c.VaultId, MyUid))).Unlocked);
        _disposables.Remove(statusServer);
        statusServer.Dispose();

        // A container's label: refused, nothing sent.
        PeerIdentity.ReadPeerLabel = _ => "system_u:system_r:spc_t:s0";
        var labelled = FakeServer(FakeControlServer.Answer(AgentStatus.Ok));
        var ex = await Assert.ThrowsAsync<TswapException>(() => Task.Run(() => BrokerControlClient.Lock(labelled.Path_, _c.VaultId, MyUid)));
        Assert.Contains("peer label spc_t", ex.Message);
        await labelled.Served.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(labelled.Received);
    }

    [Fact]
    public async Task StatusClient_SilentServer_NotRunningAfterTwoSeconds()
    {
        // Review T17 p5 GLM I1, implementation ruling 3: a squatter that accepts and never answers can't hang
        // 'broker status'. ('broker lock' waits up to 120 s by design: it may have to drain a running unlock.)
        if (!OperatingSystem.IsLinux())
            return;
        var silent = FakeServer(answer: null);
        BrokerControlClient.Time = _c.Clock;

        var answer = Task.Run(() => BrokerControlClient.Status(silent.Path_, _c.VaultId, MyUid));
        await silent.FirstBytes.WaitAsync(TimeSpan.FromSeconds(30));
        _c.Clock.Advance(BrokerControlClient.StatusResponseTimeout - TimeSpan.FromMilliseconds(1));
        Assert.False(answer.IsCompleted);
        _c.Clock.Advance(TimeSpan.FromMilliseconds(1));

        // Well within the fake server's own 30 s guard, after which its end of file would also read as NotRunning.
        Assert.IsType<BrokerControlAnswer.NotRunning>(await answer.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(TimeSpan.FromSeconds(2), BrokerControlClient.StatusResponseTimeout);
    }

    // ================================================================== the server's checks of its peers (ruling 20)

    [Fact]
    public async Task ControlSocket_RefusesUidZeroAndOthers()
    {
        if (OperatingSystem.IsWindows())
            return;
        var server = await _c.StartAsync();

        PeerIdentity.ReadCredentials = _ => (0, Environment.ProcessId);
        Assert.Null(await AgentHarness.RawAsync(_c.SocketPath, _c.UnlockFrame(_c.Right)));
        PeerIdentity.ReadCredentials = _ => (MyUid + 1, Environment.ProcessId);
        Assert.Null(await AgentHarness.RawAsync(_c.SocketPath, _c.Frame(BrokerControlOp.Status)));

        Assert.Equal(2, server.RefusedPeers);
        Assert.Contains("uid 0", _c.LogText);
        Assert.Contains($"uid {MyUid + 1}", _c.LogText);
        Assert.Equal(0, _c.ProveCalls);
        Assert.DoesNotContain("payload-read", _c.Events);
        Assert.True(_c.State.IsLocked);
    }

    [Fact]
    public async Task ControlSocket_RefusesPeerInAnotherUserNamespace()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var server = await _c.StartAsync();
        PeerIdentity.ReadUserNamespace = _ => "user:[4026531999]";

        Assert.Null(await AgentHarness.RawAsync(_c.SocketPath, _c.UnlockFrame(_c.Right)));

        Assert.Equal(1, server.RefusedPeers);
        Assert.Contains("peer in another user namespace", _c.LogText);
        Assert.Equal(0, _c.ProveCalls);
        Assert.DoesNotContain("payload-read", _c.Events);
    }

    [Theory]
    [InlineData("container_t")]
    [InlineData("spc_t")]
    [InlineData("container_runtime_t")]
    public async Task ControlSocket_RefusesContainerLabel(string type)
    {
        if (!OperatingSystem.IsLinux())
            return;
        var server = await _c.StartAsync();
        PeerIdentity.ReadPeerLabel = _ => $"system_u:system_r:{type}:s0:c1,c2";

        Assert.Null(await AgentHarness.RawAsync(_c.SocketPath, _c.UnlockFrame(_c.Right)));

        Assert.Equal(1, server.RefusedPeers);
        Assert.Contains($"peer label {type}", _c.LogText);
        Assert.Equal(0, _c.ProveCalls);
    }

    [Fact]
    public async Task ControlSocket_NoProc_NothingMayConnect_SaidOnce()
    {
        if (!OperatingSystem.IsLinux())
            return;
        PeerIdentity.ProcMounted = () => false;
        await _c.StartAsync();

        Assert.Null(await AgentHarness.RawAsync(_c.SocketPath, _c.Frame(BrokerControlOp.Status)));
        Assert.Null(await AgentHarness.RawAsync(_c.SocketPath, _c.Frame(BrokerControlOp.Status)));

        Assert.Equal(1, _c.LogText.Split('\n').Count(l => l.Contains(PeerIdentity.NoProcControlMessage) && !l.Contains("refused")));
    }

    [Fact]
    public async Task ControlSocket_OtherVaultAndMalformed_NeverProve()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();

        var other = await AgentHarness.RawAsync(_c.SocketPath,
            AgentProtocol.EncodeRequest((byte)BrokerControlOp.Unlock, RandomNumberGenerator.GetBytes(16), _c.Right));
        Assert.Equal(AgentStatus.OtherVault, other?.Status);
        var shortPayload = await AgentHarness.RawAsync(_c.SocketPath, _c.UnlockFrame(new byte[31]));
        Assert.Equal(AgentStatus.Malformed, shortPayload?.Status);
        var agentOp = await AgentHarness.RawAsync(_c.SocketPath, AgentProtocol.EncodeRequest((byte)AgentOp.Unlock, _c.VaultId));
        Assert.Equal(AgentStatus.Malformed, agentOp?.Status);

        Assert.Equal(0, _c.ProveCalls);
        Assert.DoesNotContain("payload-read", _c.Events);
        Assert.DoesNotContain("dumpable:False", _c.Events);
    }

    // ================================================================== folders, locks, stale sockets (rulings 6 and 21)

    [Fact]
    public async Task BrokerServe_CreatesTheRunFolder_WhenMissing()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.False(Directory.Exists(_c.RunDir));

        await _c.StartAsync();

        foreach (var dir in new[] { _c.RunDir, Path.GetDirectoryName(_c.SocketPath)! })
        {
            var stat = BrokerNative.LStat(dir)!.Value;
            Assert.Equal(BrokerNative.EntryType.Directory, stat.Type);
            Assert.Equal((UnixFileMode)0b111_000_000, stat.Mode & (UnixFileMode)0b111_111_111);
            Assert.Equal(MyUid, stat.Uid);
        }
        Assert.Equal((UnixFileMode)0b110_000_000, BrokerNative.LStat(_c.SocketPath)!.Value.Mode & (UnixFileMode)0b111_111_111);
        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
    }

    [Fact]
    public async Task ControlSocket_FolderIs0700()
    {
        if (OperatingSystem.IsWindows())
            return;
        var folder = Path.GetDirectoryName(_c.SocketPath)!;
        Directory.CreateDirectory(folder);
        File.SetUnixFileMode(_c.RunDir, (UnixFileMode)0b111_000_000);
        File.SetUnixFileMode(folder, (UnixFileMode)0b111_101_101);

        var ex = await Assert.ThrowsAsync<TswapException>(() => _c.StartAsync());

        Assert.Contains("not 0700", ex.Message);
        Assert.False(File.Exists(_c.SocketPath));
        Assert.Empty(Directory.EnumerateFileSystemEntries(folder));
    }

    [Fact]
    public async Task BrokerServe_AsRoot_Refuses_LeavesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        var ex = await Assert.ThrowsAsync<TswapException>(() => _c.StartAsync(ownership: new AgentOwnership(privileged: true)));

        Assert.Contains("never as root", ex.Message);
        Assert.False(Directory.Exists(_c.RunDir));
        Assert.Empty(Directory.EnumerateFileSystemEntries(_c.Root.FullName));
    }

    [Fact]
    public void BrokerServe_AsRoot_ServeCommandRefusesBeforeCreatingAnything()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-root") { Tpm = RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        BrokerCommand.Ownership = new AgentOwnership(privileged: true);
        BrokerCommand.ControlPathOverride = (_, _) => _c.SocketPath;

        var (exit, _, stderr) = m.Run("", "broker", "serve");

        Assert.NotEqual(0, exit);
        Assert.Contains("never as root", stderr);
        Assert.False(Directory.Exists(_c.RunDir));
    }

    [Fact]
    public async Task ControlSocket_Stale_ReplacedUnderTheLock()
    {
        if (OperatingSystem.IsWindows())
            return;
        var folder = Path.GetDirectoryName(_c.SocketPath)!;
        Directory.CreateDirectory(folder);
        File.SetUnixFileMode(_c.RunDir, (UnixFileMode)0b111_000_000);
        File.SetUnixFileMode(folder, (UnixFileMode)0b111_000_000);
        StaleSocketAt(_c.SocketPath);

        // While another process holds the lock, the stale socket is left alone.
        var lockPath = Path.ChangeExtension(_c.SocketPath, ".lock");
        var held = await BrokerHarness.HoldLockInAnotherProcessAsync(lockPath);
        if (OperatingSystem.IsLinux())
            Assert.NotNull(held); // review T17 p5 M3: util-linux flock is there; the headline half must run
        if (held is not null)
        {
            using (held)
            {
                var ex = await Assert.ThrowsAsync<TswapException>(() => _c.StartAsync());
                Assert.Equal(BrokerControlServer.AlreadyRunning(_c.SocketPath), ex.Message);
                Assert.Equal(BrokerNative.EntryType.Socket, BrokerNative.LStat(_c.SocketPath)!.Value.Type);
            }
        }

        await _c.StartAsync();
        Assert.False(Assert.IsType<BrokerControlAnswer.State>(await _c.StatusAsync()).Unlocked);
    }

    [Fact]
    public async Task ControlSocket_NotASocketAtThePath_Refused()
    {
        if (OperatingSystem.IsWindows())
            return;
        var folder = Path.GetDirectoryName(_c.SocketPath)!;
        Directory.CreateDirectory(folder);
        File.SetUnixFileMode(_c.RunDir, (UnixFileMode)0b111_000_000);
        File.SetUnixFileMode(folder, (UnixFileMode)0b111_000_000);
        File.WriteAllText(_c.SocketPath, "not a socket");

        var ex = await Assert.ThrowsAsync<TswapException>(() => _c.StartAsync());

        Assert.Equal($"{_c.SocketPath} exists and is not a stale socket of this user; remove it by hand.", ex.Message);
        Assert.Equal("not a socket", File.ReadAllText(_c.SocketPath));
    }

    [Fact]
    public async Task SecondServe_AlreadyRunning()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _c.StartAsync();

        var ex = await Assert.ThrowsAsync<TswapException>(() => BrokerControlServer.StartAsync(_c.Options()));

        Assert.Equal(BrokerControlServer.AlreadyRunning(_c.SocketPath), ex.Message);
        Assert.IsType<BrokerControlAnswer.State>(await _c.StatusAsync());
    }

    private static void StaleSocketAt(string path)
    {
        // .NET unlinks a bound socket's path on Dispose: bind elsewhere and move the file into place.
        var elsewhere = path + ".tmp";
        using (var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
        {
            s.Bind(new UnixDomainSocketEndPoint(elsewhere));
            File.Move(elsewhere, path);
        }
        Assert.Equal(BrokerNative.EntryType.Socket, BrokerNative.LStat(path)!.Value.Type);
    }

    // ================================================================== the CLI's refusals before connecting

    [Fact]
    public void SudoBrokerUnlock_RefusedBeforeConnect()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-sudo") { Tpm = RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        BrokerCommand.Ownership = new AgentOwnership(privileged: true);
        var connects = 0;
        BrokerControlClient.ConnectObserver = _ => connects++;

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "broker", "unlock");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Run 'tswap broker unlock' as the vault user ({BrokerNative.NameOf(MyUid)}), without sudo.", stderr);
        Assert.Equal(0, connects);
        Assert.Equal(0, m.LastConsole!.Reads); // no password asked
    }

    [Fact]
    public void PasswordFreeBroker_Unchanged_UnlockSaysNeverLocked_WithoutConnecting()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-free") { Tpm = RandomNumberGenerator.GetBytes(32) };
        m.Ok("", "init", "--tpm", "--no-password", "--no-recovery");
        var connects = 0;
        BrokerControlClient.ConnectObserver = _ => connects++;

        foreach (var op in new[] { "unlock", "lock", "status" })
        {
            var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "broker", op);
            Assert.NotEqual(0, exit);
            Assert.Contains(BrokerCommand.NeverLockedText, stderr);
        }
        Assert.Equal(0, connects);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    private static void BrokerUnlock_OwnSlotNeedsNewerTswapOrCorrupt_RefusedBeforeConnect(byte flags, string text)
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-flags") { Tpm = RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var id8 = SetOwnSlotFlags(m, flags);
        var connects = 0;
        BrokerControlClient.ConnectObserver = _ => connects++;

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "broker", "unlock");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Slot {id8}: {text}", stderr);
        Assert.Equal(0, connects);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void BrokerUnlock_OwnSlotNeedsNewerTswap_RefusedBeforeConnect() =>
        BrokerUnlock_OwnSlotNeedsNewerTswapOrCorrupt_RefusedBeforeConnect(0x02, "needs a newer tswap (blob version 1 or unknown flags); upgrade tswap.");

    [Fact]
    public void BrokerUnlock_OwnSlotCorrupt_RefusedBeforeConnect() =>
        BrokerUnlock_OwnSlotNeedsNewerTswapOrCorrupt_RefusedBeforeConnect(0x00, SlotPassword.CorruptText);

    private void Serve_OwnSlotCorruptOrNeedsNewerTswap_Refuses(byte flags, string text)
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-serve-flags") { Tpm = RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var id8 = SetOwnSlotFlags(m, flags);
        BrokerCommand.ControlPathOverride = (_, _) => _c.SocketPath;

        var (exit, _, stderr) = m.Run("", "broker", "serve");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Slot {id8}: {text}", stderr);
        Assert.False(Directory.Exists(_c.RunDir));
    }

    [Fact]
    public void Serve_OwnSlotCorrupt_Refuses() => Serve_OwnSlotCorruptOrNeedsNewerTswap_Refuses(0x00, SlotPassword.CorruptText);

    [Fact]
    public void Serve_OwnSlotNeedsNewerTswap_Refuses() =>
        Serve_OwnSlotCorruptOrNeedsNewerTswap_Refuses(0x02, "needs a newer tswap (blob version 1 or unknown flags); upgrade tswap.");

    /// <summary>Rewrites the flags byte of <paramref name="m"/>'s own TSTP slot header; returns the slot's id8.</summary>
    private static string SetOwnSlotFlags(FleetMachine m, byte flags)
    {
        var store = new RecordVaultStore(m.Dir);
        var config = store.LoadConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var ownId = Convert.FromBase64String(config.KeyringSlotId!);
        var slots = keyring.Slots.Select(s =>
        {
            if (!s.SlotId.AsSpan().SequenceEqual(ownId))
                return s;
            var blob = s.HwBlob!.ToArray();
            Assert.True(TpmSlotBlob.HasHeader(blob));
            blob[5] = flags;
            return s with { HwBlob = blob };
        }).ToList();
        // Straight into the vault folder's keyring file: a save would (rightly) refuse a changed slot.
        File.WriteAllBytes(Path.Combine(m.VaultDir!, RecordVaultStore.KeyringFileName), KeyringCodec.Encode(keyring with { Slots = slots }));
        return Convert.ToHexString(ownId).ToLowerInvariant()[..8];
    }

    // ================================================================== serve never asks an agent (ruling 13)

    [Fact]
    public void Serve_NeverAsksTheAgent()
    {
        if (OperatingSystem.IsWindows())
            return;
        // Every unlock serve makes (the proof, a route's secret, an ssh key) uses these sources: no agent.
        using var held = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        var sources = BrokerPasswordProof.SourcesFor(held.Clone);
        Assert.Null(sources.AskAgent);
        Assert.NotNull(sources.Prompt);
        Assert.Null(BrokerPasswordProof.SourcesFor(null).AskAgent);

        // And the real proof on a password vault, with any agent connection failing the test.
        using var m = new FleetMachine("bk-agent") { Tpm = RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var agentAsked = 0;
        AgentClient.Connect = (_, _, _) =>
        {
            agentAsked++;
            throw new InvalidOperationException("serve asked an agent");
        };
        var store = new RecordVaultStore(m.Dir);
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm!)]);
        var file = store.ReadVaultPassword(m.Keyring.VaultId)!;
        using var candidate = VaultPasswordKdf.Stretch(Password, file.Salt, file.Params);

        var key = BrokerPasswordProof.Prove(store, unlocker, candidate);

        Assert.Equal(32, key.Length);
        Assert.True(file.KeyMatches(key));
        Assert.Equal(0, agentAsked);
        CryptographicOperations.ZeroMemory(key);

        // A route's secret through the held password: also no agent.
        var (added, _, addErr) = m.RunOnTerminal("route-value\nroute-value\n" + Password + "\n", "add", "tok");
        Assert.True(added == 0, addErr);
        var source = new VaultBrokerSecretSource(store, unlocker, candidate.Clone);
        using var secret = source.Read("tok");
        Assert.Equal("route-value"u8.ToArray(), secret.Value.ToArray());
        Assert.Equal(0, agentAsked);
    }

    [Fact]
    public void Prove_RightHardwareButWrongVerifier_IsWrongPassword()
    {
        if (OperatingSystem.IsWindows())
            return;
        // A planted vault-password whose verifier is for another password: the hardware opens, the proof fails.
        using var m = new FleetMachine("bk-verifier") { Tpm = RandomNumberGenerator.GetBytes(32) };
        var vaultKey = PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var store = new RecordVaultStore(m.Dir);
        var file = store.ReadVaultPassword(m.Keyring.VaultId)!;
        using (var other = VaultPasswordKdf.Stretch("another password entirely", file.Salt, file.Params))
        {
            var planted = VaultPasswordFile.Create(vaultKey, m.Keyring.VaultId, other, file.Salt, file.Params);
            File.WriteAllBytes(PasswordVaultTestSupport.VaultPasswordPath(m), planted.Encode());
        }
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm!)]);
        using var candidate = VaultPasswordKdf.Stretch(Password, file.Salt, file.Params);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => BrokerPasswordProof.Prove(store, unlocker, candidate));

        Assert.StartsWith("Wrong vault password", ex.Message);
    }

    [Fact]
    public void Prove_ConflictingVaultPasswordCopies_IsUnavailable_NotAWrongPassword()
    {
        // Review T17 fix round 1: a conflict in the vault-password files is a configuration problem the
        // control server must not count as a wrong password (MissingVaultPasswordFile_IsNotCountedByTheGuard).
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("bk-conflict") { Tpm = RandomNumberGenerator.GetBytes(32) };
        var vaultKey = PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var store = new RecordVaultStore(m.Dir);
        var file = store.ReadVaultPassword(m.Keyring.VaultId)!;
        using (var other = VaultPasswordKdf.Stretch("another password entirely", file.Salt, file.Params))
            File.WriteAllBytes(PasswordVaultTestSupport.VaultPasswordPath(m) + ".sync-conflict-20261103-101010-ABCDEFG",
                VaultPasswordFile.Create(vaultKey, m.Keyring.VaultId, other, file.Salt, file.Params).Encode());
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm!)]);
        using var candidate = VaultPasswordKdf.Stretch(Password, file.Salt, file.Params);

        var ex = Assert.Throws<VaultPasswordUnavailableException>(() => BrokerPasswordProof.Prove(store, unlocker, candidate));

        Assert.StartsWith("The vault folder has two different vault-password files", ex.Message);
    }

    /// <summary>
    /// A mixed vault on <paramref name="m"/>: its TPM slot has the password, and a plugged-in YubiKey slot has none.
    /// The YubiKey's challenge log is cleared.
    /// </summary>
    private static void MixedVault(FleetMachine m)
    {
        PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var (added, _, addErr) = m.RunOnTerminal(Password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(added == 0, addErr);
        m.Keys.Challenges.Clear();
    }

    [Fact]
    public void Prove_MixedVault_UsesThePasswordSlot()
    {
        if (OperatingSystem.IsWindows())
            return;
        // Task 12 (fix after the merge): 'broker unlock' proves the password on a password slot of this
        // machine, even when a password-free slot here would open the vault without it.
        using var m = new FleetMachine("bk-mixed", SimulatedYubiKeyService.WithKeys(RecordVaultTestSupport.SerialA))
            { Tpm = RandomNumberGenerator.GetBytes(32) };
        MixedVault(m);
        var store = new RecordVaultStore(m.Dir);
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm!)]);
        var file = store.ReadVaultPassword(m.Keyring.VaultId)!;
        using var candidate = VaultPasswordKdf.Stretch(Password, file.Salt, file.Params);
        var tpmUnlocks = 0;

        byte[] key;
        using (SimulatedHardwareService.ObserveCalls((backend, call) =>
               {
                   if (backend == HardwareBackend.Tpm && call == "Unlock")
                       tpmUnlocks++;
               }))
            key = BrokerPasswordProof.Prove(store, unlocker, candidate);

        Assert.True(file.KeyMatches(key));
        CryptographicOperations.ZeroMemory(key);
        Assert.Equal(1, tpmUnlocks);
        Assert.Empty(m.Keys.Challenges);
    }

    [Fact]
    public void Prove_MixedVault_WrongPassword_RefusedByThePasswordSlot()
    {
        if (OperatingSystem.IsWindows())
            return;
        // The password-free YubiKey slot would open the vault; the wrong password is refused by the password
        // slot's hardware (ruling 18's text), not only by the verifier.
        using var m = new FleetMachine("bk-mixed-wrong", SimulatedYubiKeyService.WithKeys(RecordVaultTestSupport.SerialA))
            { Tpm = RandomNumberGenerator.GetBytes(32) };
        MixedVault(m);
        var store = new RecordVaultStore(m.Dir);
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm!)]);
        var file = store.ReadVaultPassword(m.Keyring.VaultId)!;
        using var candidate = VaultPasswordKdf.Stretch("not the password", file.Salt, file.Params);

        var ex = Assert.ThrowsAny<TswapException>(() => BrokerPasswordProof.Prove(store, unlocker, candidate));

        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, ex.Message);
        Assert.DoesNotContain(BrokerPasswordProof.WrongPasswordVerifierText, ex.Message);
        Assert.Empty(m.Keys.Challenges);
    }

    // ================================================================== ssh keys load after the first unlock

    [Fact]
    public async Task SshKeys_LoadAfterFirstUnlock()
    {
        if (!SshTestKeys.HaveTools)
            return;
        using var keys = new SshTestKeys();
        var path = keys.Generate("deploy", "ed25519");
        var source = new CountingKeySource { Values = { ["deploy-key"] = File.ReadAllBytes(path) } };
        var policy = BrokerPolicy.Parse($$"""
            {
              "version": 1,
              "socket_dir": "/tmp",
              "sockets": [ { "name": "lane1", "uids": ["{{MyUid}}"], "routes": [], "ssh_keys": ["deploy"] } ],
              "routes": [],
              "ssh_keys": [ { "name": "deploy", "secret": "deploy-key", "allowed_host_keys": ["{{SshAgentHarness.SomeHostFingerprint}}"] } ]
            }
            """);
        var deferred = new DeferredSshKeys();
        _c.LoadSshKeys = () => deferred.Load(policy, source);
        await _c.StartAsync();
        _c.State.UnloadSshKeys = deferred.Unload;

        Assert.Empty(deferred.Current);
        Assert.Equal(0, source.Reads);

        Assert.IsType<BrokerControlAnswer.Done>(await _c.UnlockAsync());
        Assert.Equal(1, source.Reads);
        Assert.Equal(SshTestKeys.BlobOf(path + ".pub"), deferred.Current["deploy"].PublicBlob);

        Assert.IsType<BrokerControlAnswer.Done>(await _c.LockAsync());
        Assert.Empty(deferred.Current);
    }

    /// <summary>An ssh key source from a dictionary, counting reads.</summary>
    private sealed class CountingKeySource : ISshKeySource
    {
        public Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);
        public int Reads;

        public byte[] ReadKey(string secretName)
        {
            Interlocked.Increment(ref Reads);
            return Values.TryGetValue(secretName, out var v)
                ? v.ToArray()
                : throw new BrokerSecretException($"secret '{secretName}' is not in the vault");
        }
    }

    // ================================================================== SELinux (ruling 14)

    [Fact]
    public void Cil_DeclaresControlTypeAndNoContainerRule()
    {
        var cil = File.ReadAllText(Path.Combine(RepoRoot(), "contrib", "selinux", "tswap-broker.cil"));
        // Comments out: only rules count.
        var rules = string.Join('\n', cil.Split('\n').Select(l => l.Split(';')[0]));
        static string Squash(string s) => System.Text.RegularExpressions.Regex.Replace(s, @"\s+", " ");
        var text = Squash(rules);

        Assert.Contains("(type tswap_broker_control_t)", text);
        foreach (var attribute in new[] { "file_type", "non_security_file_type", "non_auth_file_type" })
            Assert.Contains($"(typeattributeset {attribute} (tswap_broker_control_t))", text);
        foreach (var dir in new[] { "user_tmp_t", "cache_home_t", "user_home_t", "data_home_t" })
            Assert.Contains($"(typetransition tswap_broker_t {dir} sock_file \"control.sock\" tswap_broker_control_t)", text);
        // Deviation from the brief (reported): user_runtime_t is not a type in Fedora's targeted policy
        // (/run/user/<uid> is user_tmp_t, covered above), and a rule naming an unknown type stops the
        // module from loading at all.
        Assert.DoesNotContain("user_runtime_t", text);
        Assert.Contains("(allow tswap_broker_t tswap_broker_control_t (sock_file (create write getattr setattr unlink open read)))", text);
        Assert.Contains("(allow tswap_broker_t self (unix_stream_socket (create bind listen accept read write getattr setattr setopt getopt shutdown)))", text);
        Assert.DoesNotMatch(@"\(allow container_t tswap_broker_control_t", text);
        Assert.DoesNotMatch(@"\(allow [a-z_]*container[a-z_]* tswap_broker_control_t", text);
        // Brackets balance (a CIL file that doesn't parse loads nothing).
        Assert.Equal(rules.Count(c => c == '('), rules.Count(c => c == ')'));
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "TokenSwap.slnx")))
                return dir.FullName;
        throw new InvalidOperationException("repo root not found");
    }
}
