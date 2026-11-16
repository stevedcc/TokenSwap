using TswapCli;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T29, task 1: the per-user cross-process YubiKey lock. Each test works in its own temp folder; "held
/// elsewhere" means the test holds the same path itself (<see cref="UnixLockFile.TryTake"/> on Unix, a
/// <see cref="FileShare.None"/> stream on Windows), time is a <see cref="BrokerManualClock"/> and the notices a
/// <see cref="StringWriter"/>. No test sleeps: the pause seam counts, advances the clock or waits on an event.
/// </summary>
public sealed class YubiKeyLockTests : IDisposable
{
    private static readonly TimeSpan Wait30 = TimeSpan.FromSeconds(30);
    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-ykl-").FullName;
    private readonly BrokerManualClock _clock = new();
    private readonly StringWriter _notices = new();

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string LockPath => Path.Combine(_dir, YubiKeyLock.FileName);

    private YubiKeyLock NewLock(Action<TimeSpan>? pause = null, string? path = null, DirectoryOwnerMatcher? owner = null) =>
        new(() => path ?? LockPath, _notices, _clock, owner, pause ?? (_ => throw new InvalidOperationException("unexpected pause")));

    /// <summary>The test's own holder of <paramref name="path"/>, or null when someone else holds it.</summary>
    internal static FileStream? TryHold(string path)
    {
        if (!OperatingSystem.IsWindows())
            return UnixLockFile.TryTake(path, out _);
        try
        {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException e) when ((e.HResult & 0xFFFF) is 32 or 33)
        {
            return null;
        }
    }

    internal static FileStream Hold(string path) => TryHold(path) ?? throw new InvalidOperationException($"{path} is held");

    private static void AssertFree(string path)
    {
        using var again = TryHold(path);
        Assert.NotNull(again);
    }

    [Fact]
    public void Free_RunsTheCallOnce_ReturnsItsValue_PrintsNothing_AndReleases()
    {
        var lk = NewLock();
        var calls = 0;

        var result = lk.Run(() => ++calls * 7);

        Assert.Equal(7, result);
        Assert.Equal(1, calls);
        Assert.Equal("", _notices.ToString());
        AssertFree(LockPath);
    }

    [Fact]
    public void HeldElsewhere_ReleasedOnTheThirdPause_WaitsThenRunsOnce_WithBothLines()
    {
        var holder = Hold(LockPath);
        var released = false;
        var pauses = new List<TimeSpan>();
        var lk = NewLock(pause: interval =>
        {
            pauses.Add(interval);
            if (pauses.Count == 3)
            {
                holder.Dispose();
                released = true;
            }
        });
        var ranAfterRelease = new List<bool>();

        lk.Run(() => ranAfterRelease.Add(released));

        Assert.Equal([true], ranAfterRelease);
        Assert.Equal([YubiKeyLock.PollInterval, YubiKeyLock.PollInterval, YubiKeyLock.PollInterval], pauses);
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine + YubiKeyLock.GoingOnLine + Environment.NewLine, _notices.ToString());
    }

    [Fact]
    public void HeldPastTheTimeout_ThrowsBusy_AndASecondRunThrowsTheSameAtOnce()
    {
        using var holder = Hold(LockPath);
        var pauses = 0;
        var lk = NewLock(pause: _ =>
        {
            pauses++;
            _clock.Advance(TimeSpan.FromSeconds(30));
        });
        var calls = 0;

        var first = Assert.Throws<YubiKeyDeviceException>(() => lk.Run(() => calls++));

        Assert.Equal(OtpFailure.Busy, first.Kind);
        Assert.Null(first.Serial);
        Assert.Equal(YubiKeyLock.TimeoutText, first.Message);
        Assert.Equal(2, pauses);
        Assert.Equal(0, calls);
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine, _notices.ToString());

        var second = Assert.Throws<YubiKeyDeviceException>(() => lk.Run(() => calls++));

        Assert.Equal(OtpFailure.Busy, second.Kind);
        Assert.Null(second.Serial);
        Assert.Equal(YubiKeyLock.TimeoutText, second.Message);
        Assert.Equal(2, pauses);
        Assert.Equal(0, calls);
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine, _notices.ToString());
    }

    /// <summary>
    /// Amendment A1: a remembered timeout re-probes once without waiting; once the other holder is done the next take
    /// succeeds and clears it, so a later contention waits again (a long-lived serve recovers).
    /// </summary>
    [Fact]
    public void AfterATimeout_TheLockFreed_TheNextTakeSucceeds_AndALaterContentionWaitsAgain()
    {
        var holder = Hold(LockPath);
        var pauses = 0;
        Action<TimeSpan> pause = _ =>
        {
            pauses++;
            _clock.Advance(TimeSpan.FromSeconds(30));
        };
        var lk = NewLock(pause: interval => pause(interval));
        Assert.Throws<YubiKeyDeviceException>(() => lk.Run(() => 0));
        holder.Dispose();
        _notices.GetStringBuilder().Clear();
        pauses = 0;

        Assert.Equal(5, lk.Run(() => 5));
        Assert.Equal(0, pauses);
        Assert.Equal("", _notices.ToString());

        var holder2 = Hold(LockPath);
        pause = _ =>
        {
            pauses++;
            holder2.Dispose();
        };
        Assert.Equal(6, lk.Run(() => 6));
        Assert.Equal(1, pauses);
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine + YubiKeyLock.GoingOnLine + Environment.NewLine, _notices.ToString());
    }

    /// <summary>
    /// Amendment A2: a caller's wait budget (the broker's: <see cref="BrokerLimits.YubiKeyWaitBudget"/>) ends the wait
    /// before the broker abandons the unlock, with the text built from that budget.
    /// </summary>
    [Fact]
    public void ABrokerBudget_EndsTheWaitWithinTheBudget_BeforeTheBrokersUnlockTimeout()
    {
        var limits = new BrokerLimits();
        Assert.Equal(limits.UnlockTimeout - TimeSpan.FromSeconds(5), limits.YubiKeyWaitBudget);
        using var holder = Hold(LockPath);
        var lk = NewLock(pause: _ => _clock.Advance(TimeSpan.FromSeconds(5)));
        var started = _clock.GetTimestamp();

        YubiKeyDeviceException thrown;
        using (YubiKeyLock.WithWaitBudget(limits.YubiKeyWaitBudget))
        {
            Assert.Equal(limits.YubiKeyWaitBudget, YubiKeyLock.CurrentWaitBudget);
            thrown = Assert.Throws<YubiKeyDeviceException>(() => lk.Run(() => 0));
        }

        var waited = _clock.GetElapsedTime(started);
        Assert.Equal(limits.YubiKeyWaitBudget, waited);
        Assert.True(waited < limits.UnlockTimeout);
        Assert.Equal(OtpFailure.Busy, thrown.Kind);
        Assert.Equal(YubiKeyLock.TimeoutTextFor(limits.YubiKeyWaitBudget), thrown.Message);
        Assert.Contains("for 25 seconds", thrown.Message);
        Assert.Null(YubiKeyLock.CurrentWaitBudget);
    }

    [Fact]
    public void TheTimeoutText_IsBuiltFromTheTimeout()
    {
        Assert.Equal(
            "Another tswap has been using the YubiKey or security key for 60 seconds, so this one stopped waiting. Try again " +
            "when it's done (if it is waiting for a touch or a PIN in another terminal, answer or cancel it there).",
            YubiKeyLock.TimeoutText);
        Assert.Equal(YubiKeyLock.TimeoutTextFor(YubiKeyLock.Timeout), YubiKeyLock.TimeoutText);
        Assert.Equal(TimeSpan.FromSeconds(60), YubiKeyLock.Timeout);
        Assert.Equal(TimeSpan.FromMilliseconds(100), YubiKeyLock.PollInterval);
    }

    [Fact]
    public void TheCallThrows_TheSameExceptionComesOut_AndTheLockIsReleased()
    {
        var lk = NewLock();
        var boom = new InvalidDataException("boom");

        var thrown = Assert.Throws<InvalidDataException>(() => lk.Run(() => throw boom));

        Assert.Same(boom, thrown);
        AssertFree(LockPath);
        Assert.False(lk.HeldByThisThread);
    }

    [Fact]
    public void FolderMissing_IsCreated0700_AndTheCallRunsWithTheLockHeld()
    {
        var home = Directory.CreateDirectory(Path.Combine(_dir, "home")).FullName;
        var path = Path.Combine(home, ".cache", "tswap", YubiKeyLock.FileName);
        var lk = NewLock(path: path);
        bool? heldDuringCall = null;

        lk.Run(() =>
        {
            using var probe = TryHold(path);
            heldDuringCall = probe is null;
        });

        Assert.True(heldDuringCall);
        Assert.True(Directory.Exists(Path.Combine(home, ".cache")));
        Assert.True(Directory.Exists(Path.Combine(home, ".cache", "tswap")));
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode only = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Assert.Equal(only, File.GetUnixFileMode(Path.Combine(home, ".cache")));
            Assert.Equal(only, File.GetUnixFileMode(Path.Combine(home, ".cache", "tswap")));
        }
        Assert.Equal("", _notices.ToString());
    }

    /// <summary>The notices hold exactly one line, a <see cref="YubiKeyLock.Warning"/> with a non-empty reason; returns the reason.</summary>
    private string AssertOneWarning()
    {
        var lines = _notices.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        var line = Assert.Single(lines);
        var prefix = "Warning: tswap couldn't take its YubiKey lock (";
        var suffix = "), so tswap processes using the key at the same time could disturb each other.";
        Assert.StartsWith(prefix, line);
        Assert.EndsWith(suffix, line);
        var reason = line[prefix.Length..^suffix.Length];
        Assert.NotEmpty(reason);
        Assert.Equal(YubiKeyLock.Warning(reason), line);
        return reason;
    }

    [Fact]
    public void TheFolderCantBeCreated_BothRunsRunTheirCalls_AndTheWarningIsPrintedOnce()
    {
        var home = Directory.CreateDirectory(Path.Combine(_dir, "home")).FullName;
        File.WriteAllText(Path.Combine(home, ".cache"), "a file, not a folder");
        var lk = NewLock(path: Path.Combine(home, ".cache", "tswap", YubiKeyLock.FileName));
        var calls = 0;

        lk.Run(() => calls++);
        lk.Run(() => calls++);

        Assert.Equal(2, calls);
        AssertOneWarning();
    }

    [Fact]
    public void TheLockPathThrows_BothRunsRunTheirCalls_AndTheWarningIsPrintedOnce()
    {
        var resolves = 0;
        var lk = new YubiKeyLock(() =>
        {
            resolves++;
            throw new TswapException("no home folder here");
        }, _notices, _clock, pause: _ => throw new InvalidOperationException("unexpected pause"));
        var calls = 0;

        lk.Run(() => calls++);
        lk.Run(() => calls++);

        Assert.Equal(2, calls);
        Assert.Equal(1, resolves);
        Assert.Equal(YubiKeyLock.Warning("no home folder here") + Environment.NewLine, _notices.ToString());
        Assert.Equal(
            "Warning: tswap couldn't take its YubiKey lock (no home folder here), so tswap processes using the key at the same time could disturb each other.",
            YubiKeyLock.Warning("no home folder here"));
    }

    [Fact]
    public void TheLockPathIsAFolder_BothRunsRunTheirCalls_AndTheWarningIsPrintedOnce()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir, YubiKeyLock.FileName)).FullName;
        var lk = NewLock(path: folder);
        var calls = 0;

        lk.Run(() => calls++);
        lk.Run(() => calls++);

        Assert.Equal(2, calls);
        AssertOneWarning();
    }

    private static Func<string, string?> Env(params (string Name, string Value)[] values) =>
        name => values.Where(v => v.Name == name).Select(v => v.Value).FirstOrDefault();

    private static Func<string, UnixPasswdEntry?> Alice(uint uid = 1000) =>
        name => name == "alice" ? new UnixPasswdEntry(uid, "/home/alice") : null;

    [UnixFact]
    public void LockPath_Home_IsUnderDotCache_IgnoringTheConfigFolderVariables()
    {
        Assert.Equal("/home/alice/.cache/tswap/yubikey.lock",
            CliEnvironment.YubiKeyLockPath(Env(("HOME", "/home/alice")), isPrivileged: false));
        Assert.Equal("/home/alice/.cache/tswap/yubikey.lock",
            CliEnvironment.YubiKeyLockPath(Env(("HOME", "/home/alice"), ("TSWAP_CONFIG_DIR", "/srv/router"), ("XDG_CONFIG_HOME", "/srv/cfg")), isPrivileged: false));
    }

    [UnixFact]
    public void LockPath_UnderSudo_IsTheInvokingUsersHome()
    {
        Assert.Equal("/home/alice/.cache/tswap/yubikey.lock",
            CliEnvironment.YubiKeyLockPath(Env(("SUDO_USER", "alice"), ("SUDO_UID", "1000"), ("HOME", "/root")), isPrivileged: true, lookupUser: Alice()));
    }

    [UnixFact]
    public void LockPath_UnderSudo_ASudoUidThatDoesntMatch_Refuses()
    {
        var thrown = Assert.Throws<TswapException>(() =>
            CliEnvironment.YubiKeyLockPath(Env(("SUDO_USER", "alice"), ("SUDO_UID", "1001"), ("HOME", "/root")), isPrivileged: true, lookupUser: Alice()));

        Assert.Equal("SUDO_UID 1001 doesn't match the uid of SUDO_USER 'alice' (1000), so tswap won't use that user's vault.", thrown.Message);
    }

    [UnixFact]
    public void LockPath_PrivilegedWithoutSudoUser_IsHomes()
    {
        Assert.Equal("/root/.cache/tswap/yubikey.lock",
            CliEnvironment.YubiKeyLockPath(Env(("HOME", "/root")), isPrivileged: true, lookupUser: Alice()));
    }

    [UnixFact]
    public void LockPath_NoHome_Refuses()
    {
        Assert.Throws<TswapException>(() => CliEnvironment.YubiKeyLockPath(Env(), isPrivileged: false));
        Assert.Throws<TswapException>(() => CliEnvironment.YubiKeyLockPath(Env(("HOME", "relative/home")), isPrivileged: false));
    }

    [WindowsFact]
    public void LockPath_Windows_IsUnderLocalAppData()
    {
        Assert.Equal(@"C:\x\tswap\yubikey.lock", CliEnvironment.YubiKeyLockPath(Env(("LOCALAPPDATA", @"C:\x")), isPrivileged: false));
    }

    [UnixFact]
    public void UnderSudo_TheFolderAndTheFileAreMadeAsTheFoldersOwner_AndTheCallRunsOutsideTheSwitch()
    {
        var fake = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0, dirUid: 1000, dirGid: 1001);
        var home = Directory.CreateDirectory(Path.Combine(_dir, "home")).FullName;
        var folder = Path.Combine(home, ".cache", "tswap");
        var path = Path.Combine(folder, YubiKeyLock.FileName);
        var lk = NewLock(path: path, owner: new DirectoryOwnerMatcher(fake));
        (uint, uint)? identityDuringCall = (1, 1);

        lk.Run(() => identityDuringCall = fake.Current);

        Assert.Null(identityDuringCall);
        Assert.Contains((Path.GetFullPath(folder), 1000u, 1001u), fake.Switches);
        Assert.Contains((Path.GetFullPath(path), 1000u, 1001u), fake.Switches);
        Assert.Equal("", _notices.ToString());
    }

    [Fact]
    public void TwoThreadsOnOneLock_RunOneAfterTheOther_AndTheSecondPrintsBothLines()
    {
        using var call1Entered = new ManualResetEventSlim();
        using var call1Release = new ManualResetEventSlim();
        using var run1Returned = new ManualResetEventSlim();
        using var thread2Paused = new ManualResetEventSlim();
        var active = 0;
        var maxActive = 0;
        var calls = 0;
        void Call(Action inside)
        {
            var now = Interlocked.Increment(ref active);
            InterlockedMax(ref maxActive, now);
            Interlocked.Increment(ref calls);
            inside();
            Interlocked.Decrement(ref active);
        }
        var lk = NewLock(pause: _ =>
        {
            thread2Paused.Set();
            Assert.True(run1Returned.Wait(Wait30));
        });
        Exception? failure1 = null, failure2 = null;
        var t1 = new Thread(() =>
        {
            try
            {
                lk.Run(() => Call(() =>
                {
                    call1Entered.Set();
                    Assert.True(call1Release.Wait(Wait30));
                }));
            }
            catch (Exception e) { failure1 = e; }
            finally { run1Returned.Set(); }
        });
        var t2 = new Thread(() =>
        {
            try { lk.Run(() => Call(() => { })); }
            catch (Exception e) { failure2 = e; }
        });

        t1.Start();
        Assert.True(call1Entered.Wait(Wait30));
        t2.Start();
        Assert.True(thread2Paused.Wait(Wait30));
        call1Release.Set();
        Assert.True(t1.Join(Wait30));
        Assert.True(t2.Join(Wait30));

        Assert.Null(failure1);
        Assert.Null(failure2);
        Assert.Equal(2, calls);
        Assert.Equal(1, maxActive);
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine + YubiKeyLock.GoingOnLine + Environment.NewLine, _notices.ToString());
    }

    [Fact]
    public void TwoInstancesOnOnePath_TheSecondWaitsForTheFirstsCall_ThenRuns()
    {
        using var call1Entered = new ManualResetEventSlim();
        using var call1Release = new ManualResetEventSlim();
        using var run1Returned = new ManualResetEventSlim();
        using var secondPaused = new ManualResetEventSlim();
        var first = NewLock();
        var secondNotices = new StringWriter();
        var second = new YubiKeyLock(() => LockPath, secondNotices, _clock, pause: _ =>
        {
            secondPaused.Set();
            Assert.True(run1Returned.Wait(Wait30));
        });
        var order = new List<string>();
        Exception? failure1 = null, failure2 = null;
        var t1 = new Thread(() =>
        {
            try
            {
                first.Run(() =>
                {
                    call1Entered.Set();
                    Assert.True(call1Release.Wait(Wait30));
                    lock (order) order.Add("first");
                });
            }
            catch (Exception e) { failure1 = e; }
            finally { run1Returned.Set(); }
        });
        var t2 = new Thread(() =>
        {
            try { second.Run(() => { lock (order) order.Add("second"); }); }
            catch (Exception e) { failure2 = e; }
        });

        t1.Start();
        Assert.True(call1Entered.Wait(Wait30));
        t2.Start();
        Assert.True(secondPaused.Wait(Wait30));
        lock (order) Assert.Empty(order);
        call1Release.Set();
        Assert.True(t1.Join(Wait30));
        Assert.True(t2.Join(Wait30));

        Assert.Null(failure1);
        Assert.Null(failure2);
        Assert.Equal(["first", "second"], order);
        Assert.Equal(YubiKeyLock.WaitingLine + Environment.NewLine + YubiKeyLock.GoingOnLine + Environment.NewLine, secondNotices.ToString());
        Assert.Equal("", _notices.ToString());
    }

    [Fact]
    public void ANestedRunOnTheSameThread_Throws_AndTheOuterLockIsStillReleased()
    {
        var lk = NewLock();
        var heldInside = false;

        var thrown = Assert.Throws<InvalidOperationException>(() => lk.Run(() =>
        {
            heldInside = lk.HeldByThisThread;
            return lk.Run(() => 1);
        }));

        Assert.Equal("The YubiKey lock is already held by this thread.", thrown.Message);
        Assert.True(heldInside);
        Assert.False(lk.HeldByThisThread);
        AssertFree(LockPath);
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int seen;
        while ((seen = Volatile.Read(ref target)) < value && Interlocked.CompareExchange(ref target, value, seen) != seen)
        {
        }
    }
}
