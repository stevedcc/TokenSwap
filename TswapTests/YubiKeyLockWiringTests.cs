using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T29, task 2: the decorators that take the YubiKey lock around every device call, the composition helpers in
/// <see cref="CliHost"/>, and two <c>names</c> at once in process (B7.1's shape).
/// </summary>
public sealed class YubiKeyLockWiringTests : IDisposable
{
    private static readonly TimeSpan Wait30 = TimeSpan.FromSeconds(30);
    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-yklw-").FullName;
    private readonly BrokerManualClock _clock = new();

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private YubiKeyLock NewLock(TextWriter? notices = null, Action<TimeSpan>? pause = null, string? path = null) =>
        new(() => path ?? Path.Combine(_dir, YubiKeyLock.FileName), notices ?? new StringWriter(), _clock, pause: pause ?? (_ => throw new InvalidOperationException("unexpected pause")));

    // ------------------------------------------------------------------ LockedYubiKeyService

    /// <summary>Implements every member of <see cref="IYubiKeyService"/>, each recording its name and whether the lock was held.</summary>
    private sealed class RecordingYubiKeys : IYubiKeyService
    {
        public YubiKeyLock? Lock { get; set; }
        public List<(string Member, bool Held)> Calls { get; } = [];

        private T Record<T>(string member, T value)
        {
            Calls.Add((member, Lock?.HeldByThisThread == true));
            return value;
        }

        public static readonly IReadOnlyList<int> Serials = [41];
        public static readonly byte[] Response = [1, 2, 3];
        public static readonly YubiKeyResponse WithTouch = new([4], true);
        public static readonly IReadOnlyList<YubiKeyInfo> Keys = [new(42, false, "HidFido")];

        public bool IsSimulated => Record(nameof(IsSimulated), true);
        public IReadOnlyList<int> ListSerials() => Record(nameof(ListSerials), Serials);
        public byte[] Challenge(int serial, string challenge) => Record(nameof(Challenge), Response);
        public bool? DetectTouchRequirement(int serial) => Record(nameof(DetectTouchRequirement), (bool?)false);
        public YubiKeyResponse ChallengeReportingTouch(int serial, string challenge) => Record(nameof(ChallengeReportingTouch), WithTouch);
        public IReadOnlyList<YubiKeyInfo> FindKeys() => Record(nameof(FindKeys), Keys);
        public string? DescribeUnreachable() => Record(nameof(DescribeUnreachable), "unreachable");
        public Slot2State GetSlot2State(int serial) => Record(nameof(GetSlot2State), Slot2State.Empty);
        public void ProgramSlot2(int serial, bool requireTouch) => Record(nameof(ProgramSlot2), 0);
    }

    /// <summary>Each member of <see cref="IYubiKeyService"/>: how to call it, what the recording inner returns, and whether it is locked.</summary>
    private static readonly Dictionary<string, (Func<IYubiKeyService, object?> Call, object? Expected, bool Locked)> YubiKeyRows = new()
    {
        ["IsSimulated"] = (s => s.IsSimulated, true, false),
        ["ListSerials"] = (s => s.ListSerials(), RecordingYubiKeys.Serials, true),
        ["Challenge"] = (s => s.Challenge(41, "c"), RecordingYubiKeys.Response, true),
        ["DetectTouchRequirement"] = (s => s.DetectTouchRequirement(41), false, true),
        ["ChallengeReportingTouch"] = (s => s.ChallengeReportingTouch(41, "c"), RecordingYubiKeys.WithTouch, true),
        ["FindKeys"] = (s => s.FindKeys(), RecordingYubiKeys.Keys, true),
        ["DescribeUnreachable"] = (s => s.DescribeUnreachable(), "unreachable", true),
        ["GetSlot2State"] = (s => s.GetSlot2State(41), Slot2State.Empty, true),
        ["ProgramSlot2"] = (s => { s.ProgramSlot2(41, true); return null; }, null, true),
    };

    public static TheoryData<string> YubiKeyMembers => [.. YubiKeyRows.Keys];

    /// <summary>The member names of <paramref name="type"/>: its methods, with property getters under the property's name.</summary>
    private static SortedSet<string> MemberNames(Type type) =>
        [.. type.GetMethods(BindingFlags.Public | BindingFlags.Instance).Select(m => m.Name.StartsWith("get_", StringComparison.Ordinal) ? m.Name[4..] : m.Name)];

    [Fact]
    public void LockedYubiKeyService_TheRowsNameEveryMemberOfTheInterface() =>
        Assert.Equal(MemberNames(typeof(IYubiKeyService)), new SortedSet<string>(YubiKeyRows.Keys));

    [Theory]
    [MemberData(nameof(YubiKeyMembers))]
    public void LockedYubiKeyService_ForwardsEachMember_UnderTheLock_ExceptIsSimulated(string member)
    {
        var lk = NewLock();
        var inner = new RecordingYubiKeys { Lock = lk };
        IYubiKeyService locked = new LockedYubiKeyService(inner, lk);
        var row = YubiKeyRows[member];

        var result = row.Call(locked);

        Assert.Equal([(member, row.Locked)], inner.Calls);
        if (row.Expected is null || row.Expected.GetType().IsValueType || row.Expected is string)
            Assert.Equal(row.Expected, result);
        else
            Assert.Same(row.Expected, result);
        Assert.False(lk.HeldByThisThread);
    }

    // ------------------------------------------------------------------ LockedFido2Keys

    private sealed class RecordingFido2Keys : IFido2Keys
    {
        public YubiKeyLock? Lock { get; set; }
        public List<(string Member, bool Held)> Calls { get; } = [];
        public bool? PinHeld { get; private set; }

        private T Record<T>(string member, T value)
        {
            Calls.Add((member, Lock?.HeldByThisThread == true));
            return value;
        }

        public static readonly IReadOnlyList<Fido2KeyInfo> Listed = [new(new Fido2KeyRef("k"), 7, Guid.NewGuid(), true, 8)];
        public static readonly Fido2Made Made = new([1], Guid.NewGuid(), 7, true);
        public static readonly Fido2Output Output = new([2], [3], true);
        public static readonly Fido2KeyInfo Holder = new(new Fido2KeyRef("h"), null, Guid.NewGuid(), false, null, "Other");

        public bool CanList => Record(nameof(CanList), true);
        public IReadOnlyList<Fido2KeyInfo> Find() => Record(nameof(Find), Listed);
        public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin) => Record(nameof(MakeCredential), Made);

        public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
        {
            pin(3);
            return Record(nameof(GetHmacSecret), Output);
        }

        public Fido2KeyInfo? FindHolder(byte[] credentialId) => Record(nameof(FindHolder), Holder);
        public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin) => Record(nameof(SetPin), 0);
        public Libfido2Status? OtherBrands => Record(nameof(OtherBrands), (Libfido2Status?)Libfido2Status.Loaded);
    }

    private static byte[] NoPin(int? retries) => [];

    private static readonly Dictionary<string, (Func<IFido2Keys, object?> Call, object? Expected, bool Locked)> Fido2Rows = new()
    {
        ["CanList"] = (k => k.CanList, true, false),
        ["OtherBrands"] = (k => k.OtherBrands, Libfido2Status.Loaded, false),
        ["Find"] = (k => k.Find(), RecordingFido2Keys.Listed, true),
        ["MakeCredential"] = (k => k.MakeCredential(null, new byte[16], [], NoPin), RecordingFido2Keys.Made, true),
        ["GetHmacSecret"] = (k => k.GetHmacSecret(null, [([1], [2])], NoPin), RecordingFido2Keys.Output, true),
        ["FindHolder"] = (k => k.FindHolder([1]), RecordingFido2Keys.Holder, true),
        ["SetPin"] = (k => { k.SetPin(new Fido2KeyRef("k"), NoPin); return null; }, null, true),
    };

    public static TheoryData<string> Fido2Members => [.. Fido2Rows.Keys];

    [Fact]
    public void LockedFido2Keys_TheRowsNameEveryMemberOfTheInterface() =>
        Assert.Equal(MemberNames(typeof(IFido2Keys)), new SortedSet<string>(Fido2Rows.Keys));

    /// <summary>
    /// The records come back as the very instances the inner returned (never rebuilt), so a field added to
    /// <see cref="Fido2KeyInfo"/> later passes through.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fido2Members))]
    public void LockedFido2Keys_ForwardsEachMember_UnderTheLock_ExceptCanListAndOtherBrands(string member)
    {
        var lk = NewLock();
        var inner = new RecordingFido2Keys { Lock = lk };
        IFido2Keys locked = new LockedFido2Keys(inner, lk);
        var row = Fido2Rows[member];

        var result = row.Call(locked);

        Assert.Equal([(member, row.Locked)], inner.Calls);
        if (row.Expected is null || row.Expected.GetType().IsValueType)
            Assert.Equal(row.Expected, result);
        else
            Assert.Same(row.Expected, result);
        Assert.False(lk.HeldByThisThread);
    }

    /// <summary>B7.2: the FIDO2 PIN prompt runs inside the device call, so inside the lock.</summary>
    [Fact]
    public void LockedFido2Keys_ThePinDelegateRunsWithTheLockHeld()
    {
        var lk = NewLock();
        IFido2Keys locked = new LockedFido2Keys(new RecordingFido2Keys { Lock = lk }, lk);
        var heldAtPin = new List<bool>();

        locked.GetHmacSecret(null, [([1], [2])], retries =>
        {
            heldAtPin.Add(lk.HeldByThisThread);
            return [];
        });

        Assert.Equal([true], heldAtPin);
    }

    [Fact]
    public void LockedDecorators_LetTheInnersExceptionThrough_AndRelease()
    {
        var lk = NewLock();
        var boom = new YubiKeyDeviceException(OtpFailure.Busy, 41, "busy");
        IYubiKeyService locked = new LockedYubiKeyService(new ThrowingYubiKeys(boom), lk);

        Assert.Same(boom, Assert.Throws<YubiKeyDeviceException>(() => locked.ListSerials()));
        Assert.False(lk.HeldByThisThread);
        Assert.Empty(locked.ListSerials()); // released: the next call takes the lock again
    }

    private sealed class ThrowingYubiKeys(Exception boom) : IYubiKeyService
    {
        private int _calls;
        public bool IsSimulated => false;
        public IReadOnlyList<int> ListSerials() => _calls++ == 0 ? throw boom : [];
        public byte[] Challenge(int serial, string challenge) => throw boom;
        public bool? DetectTouchRequirement(int serial) => throw boom;
    }

    // ------------------------------------------------------------------ CliHost composition

    [Fact]
    public void CliHost_YubiKeyService_Hardware_IsLocked_AndReachesTheRealServiceUnderTheLock()
    {
        var lk = NewLock();
        var recording = new RecordingYubiKeys { Lock = lk };

        var service = CliHost.YubiKeyService(testKey: null, hardwareLock: lk, verbose: null, real: () => recording);

        Assert.IsType<LockedYubiKeyService>(service);
        Assert.Same(RecordingYubiKeys.Serials, service.ListSerials());
        Assert.Equal([("ListSerials", true)], recording.Calls);
    }

    [Fact]
    public void CliHost_YubiKeyService_TestMode_IsTheTestKeyService() =>
        Assert.IsType<TestKeyYubiKeyService>(CliHost.YubiKeyService(new byte[32], null, null));

    [Fact]
    public void CliHost_WithLock_WrapsTheFido2Keys_OnlyWithALock()
    {
        var lk = NewLock();
        var fake = new RecordingFido2Keys();

        var wrapped = Assert.IsType<LockedFido2Keys>(CliHost.WithLock(fake, lk));

        Assert.Same(fake, wrapped.Inner);
        Assert.Same(lk, wrapped.Lock);
        Assert.Same(fake, CliHost.WithLock(fake, null));
    }

    [Fact]
    public void CliHost_HardwareLock_IsMadeForHardware_AndOffInTestMode()
    {
        Func<string> path = () => Path.Combine(_dir, YubiKeyLock.FileName);
        Assert.NotNull(CliHost.HardwareLock(null, _ => null, path, new StringWriter(), _clock, DirectoryOwnerMatcher.Default));
        Assert.Null(CliHost.HardwareLock(new byte[32], _ => null, path, new StringWriter(), _clock, DirectoryOwnerMatcher.Default));
    }

#if DEBUG
    [Fact]
    public void CliHost_HardwareLock_TestModeWithTheVariable_IsMade() =>
        Assert.NotNull(CliHost.HardwareLock(new byte[32], name => name == "TSWAP_TEST_YUBIKEY_LOCK" ? "1" : null,
            () => Path.Combine(_dir, YubiKeyLock.FileName), new StringWriter(), _clock, DirectoryOwnerMatcher.Default));
#endif

    // ------------------------------------------------------------------ two names at once (B7.1)

    /// <summary>
    /// Forwards every member to <paramref name="inner"/>, counting how many calls are active at once: an overlap (two
    /// device calls at the same time) is counted and sets <see cref="Overlapped"/>. <see cref="BeforeChallenge"/> runs
    /// inside a challenge, before the inner's.
    /// </summary>
    private sealed class OverlapDetector(IYubiKeyService inner) : IYubiKeyService
    {
        private int _active;
        private int _overlaps;
        public int Overlaps => Volatile.Read(ref _overlaps);
        public ManualResetEventSlim Overlapped { get; } = new();
        public Action? BeforeChallenge { get; set; }

        private T Guard<T>(Func<T> call)
        {
            if (Interlocked.Increment(ref _active) > 1)
            {
                Interlocked.Increment(ref _overlaps);
                Overlapped.Set();
            }
            try
            {
                return call();
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }

        public bool IsSimulated => inner.IsSimulated;
        public IReadOnlyList<int> ListSerials() => Guard(inner.ListSerials);
        public byte[] Challenge(int serial, string challenge) => Guard(() =>
        {
            BeforeChallenge?.Invoke();
            return inner.Challenge(serial, challenge);
        });
        public bool? DetectTouchRequirement(int serial) => Guard(() => inner.DetectTouchRequirement(serial));
        public YubiKeyResponse ChallengeReportingTouch(int serial, string challenge) => Guard(() =>
        {
            BeforeChallenge?.Invoke();
            return inner.ChallengeReportingTouch(serial, challenge);
        });
        public IReadOnlyList<YubiKeyInfo> FindKeys() => Guard(inner.FindKeys);
        public string? DescribeUnreachable() => Guard(inner.DescribeUnreachable);
        public Slot2State GetSlot2State(int serial) => Guard(() => inner.GetSlot2State(serial));
        public void ProgramSlot2(int serial, bool requireTouch) => Guard(() => { inner.ProgramSlot2(serial, requireTouch); return 0; });
    }

    [Fact]
    public void TwoNamesAtOnce_TheSecondWaitsForTheFirstsTouch_AndBothList()
    {
        using var machine = new FleetMachine("ykl-names", SimulatedYubiKeyService.WithKeys(RecordVaultTestSupport.SerialA));
        RecordVaultTestSupport.InitRecordVault(machine);
        machine.Ok("alpha-value\n", "ingest", "alpha");
        machine.Ok("beta-value\n", "ingest", "beta");
        machine.Keys.Challenges.Clear();
        var detector = new OverlapDetector(machine.Keys);
        var lockPath = Path.Combine(_dir, ".cache", "tswap", YubiKeyLock.FileName);
        using var bWaiting = new ManualResetEventSlim();
        using var aDone = new ManualResetEventSlim();
        var bLog = new ObservedLog();
        var aLocked = new LockedYubiKeyService(detector, NewLock(path: lockPath));
        var bLocked = new LockedYubiKeyService(detector, new YubiKeyLock(() => lockPath, bLog, _clock, pause: _ =>
        {
            bWaiting.Set();
            Assert.True(aDone.Wait(Wait30));
        }));
        var aConsole = new FakeConsole();
        var bConsole = new FakeConsole();
        var aCtx = machine.Context(aConsole, ["names"]) with { YubiKeys = aLocked, Unlocker = new VaultUnlocker(aLocked) };
        var bCtx = machine.Context(bConsole, ["names"]) with { YubiKeys = bLocked, Unlocker = new VaultUnlocker(bLocked) };
        var aThread = Environment.CurrentManagedThreadId;
        Thread? b = null;
        var bExit = -1;
        Exception? bFailure = null;
        detector.BeforeChallenge = () =>
        {
            if (Environment.CurrentManagedThreadId != aThread || b is not null)
                return;
            b = new Thread(() =>
            {
                try { bExit = CliRunner.Run(bCtx, ["names"]); }
                catch (Exception e) { bFailure = e; }
            });
            b.Start();
            WaitHandle.WaitAny([bWaiting.WaitHandle, detector.Overlapped.WaitHandle], Wait30);
        };

        var aExit = CliRunner.Run(aCtx, ["names"]);
        aDone.Set();
        Assert.NotNull(b);
        Assert.True(b.Join(Wait30));

        Assert.Null(bFailure);
        Assert.Equal(0, aExit);
        Assert.Equal(0, bExit);
        Assert.Equal(0, detector.Overlaps);
        foreach (var output in new[] { aConsole.OutText, bConsole.OutText })
        {
            Assert.Contains("alpha", output);
            Assert.Contains("beta", output);
        }
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine + YubiKeyLock.GoingOnLine + Environment.NewLine, bLog.ToString());
        Assert.Equal(2, machine.Keys.Challenges.Count);
    }

    // ------------------------------------------------------------------ the broker's wait budget (A2)

    /// <summary>Amendment A2: a route's unlock (and a template's: the same <c>UnlockAsync</c>) runs under the broker's budget.</summary>
    [UnixFact("the broker is Unix-only (Unix sockets and kernel peer credentials)")]
    public async Task BrokerRouteUnlock_RunsWithTheBrokersYubiKeyWaitBudget()
    {
        await using var h = new BrokerHarness();
        var budgets = new List<TimeSpan?>();
        h.Secrets.UnlockStarted += _ =>
        {
            lock (budgets)
                budgets.Add(YubiKeyLock.CurrentWaitBudget);
        };
        await h.StartAsync();

        Assert.Equal(200, BrokerHarness.StatusOf(await h.GetAsync("lane1", "/echo/a")));

        Assert.Equal([new BrokerLimits().YubiKeyWaitBudget], budgets);
    }

    private sealed class BudgetRecordingKeySource(byte[] key) : ISshKeySource
    {
        public List<TimeSpan?> Budgets { get; } = [];

        public byte[] ReadKey(string secretName)
        {
            lock (Budgets)
                Budgets.Add(YubiKeyLock.CurrentWaitBudget);
            return (byte[])key.Clone();
        }
    }

    /// <summary>Amendment A2: an ssh-agent signature's unlock runs under the broker's budget.</summary>
    [UnixFact("the broker is Unix-only (Unix sockets and kernel peer credentials)")]
    public async Task SshAgentSignUnlock_RunsWithTheBrokersYubiKeyWaitBudget()
    {
        await using var h = new SshAgentHarness();
        var host = TestHostKey.NewEd25519();
        var key = SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32));
        var blob = SshTestKeyMaker.PublicBlob(key);
        var source = new BudgetRecordingKeySource(key);
        var config = $$"""
            {
              "version": 1,
              "socket_dir": {{JsonSerializer.Serialize(h.Broker.SocketDir)}},
              "sockets": [ { "name": "lane1", "uid_only": true, "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "ssh_keys": ["a"] } ],
              "routes": [],
              "ssh_keys": [ { "name": "a", "secret": "sa", "allowed_host_keys": ["{{host.Fingerprint}}"] } ]
            }
            """;
        await h.StartAsync(config, p => new SshAgentOptions { Keys = SshAgentKeyLoader.Load(p, source), KeySource = source });
        lock (source.Budgets)
            source.Budgets.Clear(); // the load's reads ran outside any unlock

        using var client = await h.ConnectAsync("lane1");
        var sid = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(new[] { SshAgentProtocol.Success }, await client.RequestAsync(SshBindMessages.Bind(host.Blob, sid, host.Sign(sid))));
        var reply = await client.RequestAsync(SshBindMessages.SignRequest(blob, SshBindMessages.Userauth(sid, "ssh-ed25519", blob)));

        Assert.NotEqual(SshAgentProtocol.FailureReply, reply);
        Assert.Equal([new BrokerLimits().YubiKeyWaitBudget], source.Budgets);
    }
}

/// <summary>
/// Brief T29, amendment A3: the lock's owner switch runs only in a privileged process, and <c>broker serve</c> and
/// <c>agent serve</c> (the multi-threaded ones) still refuse root before any device call, so before any lock take.
/// In the static-seam collection: it sets <see cref="BrokerCommand.Ownership"/>.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class YubiKeyLockServeAsRootTests : IDisposable
{
    public void Dispose() => BrokerCommand.ResetSeamsForTests();

    private static (FleetMachine Machine, LockedYubiKeyService Locked, Func<int> Resolves) Machine(string name)
    {
        var machine = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(RecordVaultTestSupport.SerialA));
        RecordVaultTestSupport.InitRecordVault(machine);
        machine.Keys.Challenges.Clear();
        var resolves = 0;
        var lk = new YubiKeyLock(() =>
        {
            resolves++;
            return Path.Combine(machine.Dir, YubiKeyLock.FileName);
        }, new StringWriter(), new BrokerManualClock(), pause: _ => throw new InvalidOperationException("unexpected pause"));
        return (machine, new LockedYubiKeyService(machine.Keys, lk), () => resolves);
    }

    [UnixFact]
    public void BrokerServe_AsRoot_RefusesBeforeAnyLockTake()
    {
        var (machine, locked, resolves) = Machine("ykl-broker-root");
        using var _ = machine;
        BrokerCommand.Ownership = new AgentOwnership(privileged: true);
        var console = new FakeConsole();
        var ctx = machine.Context(console, ["broker", "serve"]) with { YubiKeys = locked, Unlocker = new VaultUnlocker(locked) };

        var exit = CliRunner.Run(ctx, ["broker", "serve"]);

        Assert.NotEqual(0, exit);
        Assert.Contains("never as root", console.ErrorText);
        Assert.Equal(0, resolves());
        Assert.Empty(machine.Keys.Challenges);
    }

    [UnixFact]
    public void AgentServe_AsRoot_RefusesBeforeAnyLockTake()
    {
        var (machine, locked, resolves) = Machine("ykl-agent-root");
        using var _ = machine;
        machine.Ownership = new DirectoryOwnerMatcher(new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0,
            dirUid: new UnixOwnership().EffectiveUid, dirGid: 0));
        var console = new FakeConsole();
        var ctx = machine.Context(console, ["agent", "serve", "--foreground"]) with { YubiKeys = locked, Unlocker = new VaultUnlocker(locked) };

        var exit = CliRunner.Run(ctx, ["agent", "serve", "--foreground"]);

        Assert.NotEqual(0, exit);
        Assert.Contains("Don't run the agent as root", console.ErrorText);
        Assert.Equal(0, resolves());
        Assert.Empty(machine.Keys.Challenges);
    }
}
