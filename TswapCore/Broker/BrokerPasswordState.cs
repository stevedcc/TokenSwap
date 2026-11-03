using System.Runtime.InteropServices;
using TswapCore.Agent;
using TswapCore.VaultPassword;

namespace TswapCore.Broker;

/// <summary>
/// A request that needs an unlock reached a locked password broker (brief T17 ruling 14). It is answered
/// like a busy request and is never an unlock failure: <see cref="BrokerUnlockGuard"/> never counts it.
/// </summary>
public sealed class BrokerLockedException() : Exception("the broker is locked");

/// <summary>
/// The process-hardening steps a password broker takes at its transitions (brief T17 ruling 12); tests
/// swap them so the test process itself is never made non-dumpable.
/// </summary>
/// <param name="SetDumpable">Linux <c>prctl(PR_SET_DUMPABLE, 0|1)</c>; true when it worked (a no-op elsewhere).</param>
/// <param name="DenyAttach">macOS <c>ptrace(PT_DENY_ATTACH)</c>, for the process lifetime.</param>
/// <param name="ZeroCoreLimit">Unix <c>setrlimit(RLIMIT_CORE, 0)</c>.</param>
/// <param name="Platform">Which of them apply.</param>
public sealed record BrokerHardening(Func<bool, bool> SetDumpable, Func<bool> DenyAttach, Func<bool> ZeroCoreLimit,
    ProcessHardening.Platform Platform)
{
    public static BrokerHardening Native { get; } =
        new(BrokerNative.SetDumpable, ProcessHardening.DenyAttach, ProcessHardening.ZeroCoreLimit, ProcessHardening.Current);
}

/// <summary>
/// What a password broker holds, and when (brief T17 rulings 12 and 14).
/// <list type="bullet">
/// <item><b>Locked</b> (the start, and after every return to locked): nothing held, the process dumpable
/// (Linux), so <c>broker unlock</c> can read its user-namespace link.</item>
/// <item><b>A proof</b> (<c>broker unlock</c>, one at a time): non-dumpable before the payload is read;
/// a failed proof zeroes its candidate, then makes the process dumpable again.</item>
/// <item><b>Unlocked</b>: the stretched password held (native, locked memory). Every per-request unlock
/// takes a lease (<see cref="TryEnter"/>) and gets <see cref="StretchedPassword.Clone"/>s
/// (<see cref="Provider"/>).</item>
/// <item><b>A return to locked</b> (<c>broker lock</c>, the timeout, a failed deferred ssh-key load), in
/// order: stop taking new unlocks; wait for every lease and a proof in flight; zero the held password;
/// unload the ssh keys; only then dumpable again.</item>
/// </list>
/// The process is non-dumpable whenever any secret is in its memory, and dumpable only when locked with
/// nothing held.
/// </summary>
public sealed class BrokerPasswordState : IDisposable
{
    public const string AlreadyUnlockedText = "The broker is already unlocked.";
    public const string LockedWhileUnlockingText = "The broker was locked while unlocking; run 'tswap broker unlock' again.";

    // ------------------------------------------------------------------ seams (ruling 12)

    /// <summary>Test seam: every dumpable transition that took effect.</summary>
    internal static Action<bool>? DumpableObserver;

    /// <summary>Test seam: the ssh keys were unloaded (a return to locked).</summary>
    internal static Action? SshKeysUnloadedObserver;

    /// <summary>Test seam: macOS's <c>PT_DENY_ATTACH</c> was applied (before the first payload read).</summary>
    internal static Action? DenyAttachObserver;

    /// <summary>Test seam: a proof's <c>K_v</c>, after it was zeroed.</summary>
    internal static Action<ReadOnlySpan<byte>>? KeyZeroedObserver;

    /// <summary>Test seam: a return to locked is waiting for in-flight unlocks (only when there are some).</summary>
    internal static Action? DrainWaitObserver;

    internal static void ResetSeamsForTests()
    {
        DumpableObserver = null;
        SshKeysUnloadedObserver = null;
        DenyAttachObserver = null;
        KeyZeroedObserver = null;
        DrainWaitObserver = null;
    }

    // ------------------------------------------------------------------ state

    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _transitions = new(1, 1);
    private readonly BrokerHardening _hardening;
    private readonly TimeProvider _time;
    private readonly Action<string> _log;
    private readonly Action<string> _onFatal;
    private StretchedPassword? _held;
    private DateTimeOffset? _expiresAt;
    private bool _unlocked;
    private bool _locking;
    private bool _proofInFlight;
    private int _leases;
    private int _generation;
    private TaskCompletionSource? _idle;
    private ITimer? _expiry;
    private int _denyAttachDone;

    /// <param name="hardening">The native steps (<see cref="BrokerHardening.Native"/>), or fakes in tests.</param>
    /// <param name="time">The clock of the timeout.</param>
    /// <param name="log">Event lines (locked, unlocked, the timeout).</param>
    /// <param name="onFatal">A hardening step that must work failed: <c>serve</c> stops.</param>
    public BrokerPasswordState(BrokerHardening hardening, TimeProvider time, Action<string>? log = null, Action<string>? onFatal = null)
    {
        _hardening = hardening;
        _time = time;
        _log = log ?? (static _ => { });
        _onFatal = onFatal ?? (static _ => { });
    }

    /// <summary>
    /// <c>serve</c>'s first step (ruling 12). Linux: a password broker starts dumpable (locked, nothing
    /// held), a password-free one non-dumpable as before; either failing refuses to start. macOS:
    /// <c>RLIMIT_CORE</c> 0, password or not (a failure is a warning); <c>PT_DENY_ATTACH</c> waits for the
    /// first unlock's payload.
    /// </summary>
    public static void HardenAtStart(BrokerHardening hardening, bool password, Action<string> warn)
    {
        switch (hardening.Platform)
        {
            case ProcessHardening.Platform.Linux:
                if (!hardening.SetDumpable(password))
                    throw new TswapException(password
                        ? $"Could not make this process dumpable while it is locked (prctl PR_SET_DUMPABLE, errno {Marshal.GetLastPInvokeError()}); 'tswap broker unlock' could not check it, so not serving."
                        : $"Could not make this process non-dumpable (prctl PR_SET_DUMPABLE, errno {Marshal.GetLastPInvokeError()}); not serving.");
                DumpableObserver?.Invoke(password);
                break;
            case ProcessHardening.Platform.MacOs:
                if (!hardening.ZeroCoreLimit())
                    warn("Warning: setrlimit(RLIMIT_CORE, 0) failed; a crash could write a core file holding the vault password.");
                break;
        }
    }

    /// <summary>True unless the password is held and new unlocks are taken (false from the first step of a return to locked).</summary>
    public bool IsLocked
    {
        get
        {
            lock (_gate)
                return !_unlocked || _locking;
        }
    }

    /// <summary>When the held password is zeroed again (the unlock's timeout), or null for none.</summary>
    public DateTimeOffset? ExpiresAt
    {
        get
        {
            lock (_gate)
                return _unlocked ? _expiresAt : null;
        }
    }

    /// <summary>Counts the returns to locked; an unlock that queued before one is refused (ruling 12).</summary>
    public int Generation
    {
        get
        {
            lock (_gate)
                return _generation;
        }
    }

    /// <summary>Unloads the deferred ssh keys at every return to locked (set by <c>serve</c>).</summary>
    public Action? UnloadSshKeys { get; set; }

    /// <summary>
    /// A lease for one per-request unlock, or null when the broker is locked (or returning to locked). While
    /// any lease is open the held password stays; a return to locked waits for every lease to be disposed.
    /// </summary>
    public IDisposable? TryEnter()
    {
        lock (_gate)
        {
            if (!_unlocked || _locking)
                return null;
            _leases++;
            return new Lease(this);
        }
    }

    /// <summary>A copy of the held password for one unlock (ruling 4); the caller disposes it. Throws <see cref="BrokerLockedException"/> when nothing is held.</summary>
    public StretchedPassword CloneHeld()
    {
        lock (_gate)
            return _held?.Clone() ?? throw new BrokerLockedException();
    }

    /// <summary>The unlocks' password source: <see cref="CloneHeld"/>.</summary>
    public VaultPasswordProvider Provider => CloneHeld;

    private void Leave()
    {
        lock (_gate)
        {
            _leases--;
            SignalIdleIfDone();
        }
    }

    private void SignalIdleIfDone()
    {
        if (_idle is not null && _leases == 0 && !_proofInFlight)
        {
            _idle.TrySetResult();
            _idle = null;
        }
    }

    private sealed class Lease(BrokerPasswordState state) : IDisposable
    {
        private int _done;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0)
                state.Leave();
        }
    }

    // ------------------------------------------------------------------ the proof (broker unlock)

    /// <summary>
    /// On an unlock request's turn, before its payload is read: null when it may go on (the process is
    /// then non-dumpable, and on macOS <c>PT_DENY_ATTACH</c> applies), or the refusal to answer.
    /// <paramref name="arrivedGeneration"/> is <see cref="Generation"/> when the request arrived.
    /// </summary>
    internal string? BeginProof(int arrivedGeneration)
    {
        lock (_gate)
        {
            if (_unlocked && !_locking)
                return AlreadyUnlockedText;
            if (_locking || _generation != arrivedGeneration)
                return LockedWhileUnlockingText;
            _proofInFlight = true;
        }
        if (!SetDumpable(false))
        {
            EndProof();
            const string reason = "Could not make this process non-dumpable (prctl PR_SET_DUMPABLE) before reading the vault password; stopping.";
            _onFatal(reason);
            return reason;
        }
        if (_hardening.Platform == ProcessHardening.Platform.MacOs && Interlocked.Exchange(ref _denyAttachDone, 1) == 0)
        {
            if (!_hardening.DenyAttach())
                _log("warning: ptrace(PT_DENY_ATTACH) failed; a debugger of this user could attach to serve");
            DenyAttachObserver?.Invoke();
        }
        return null;
    }

    /// <summary>
    /// A proof failed (or its payload never came): zeroes the candidate, then makes the process dumpable
    /// again (nothing else is held while locked).
    /// </summary>
    internal void FailProof(StretchedPassword? candidate)
    {
        candidate?.Dispose();
        bool dumpable;
        lock (_gate)
        {
            dumpable = !_unlocked && !_locking;
            EndProofLocked();
        }
        if (dumpable)
            MakeDumpableAgainOrStop();
    }

    /// <summary>
    /// The way back to locked ends with <c>PR_SET_DUMPABLE 1</c>; like every transition of a password
    /// broker (ruling 12), a failure there stops <c>serve</c> (it would refuse every <c>broker unlock</c>).
    /// </summary>
    private void MakeDumpableAgainOrStop()
    {
        if (!SetDumpable(true))
            _onFatal($"Could not make this process dumpable again after locking (prctl PR_SET_DUMPABLE, errno {Marshal.GetLastPInvokeError()}); 'tswap broker unlock' could not check it, so stopping.");
    }

    /// <summary>
    /// A proof succeeded. Holds <paramref name="candidate"/> and returns true, unless a return to locked
    /// began since the request arrived: then the candidate is zeroed and false is returned (the return to
    /// locked makes the process dumpable once this proof has ended).
    /// </summary>
    internal bool CompleteProof(StretchedPassword candidate, DateTimeOffset? expiresAt, int arrivedGeneration)
    {
        bool keep;
        // One lock for the decision and the hold: a return to locked can't begin between them.
        lock (_gate)
        {
            keep = !_locking && _generation == arrivedGeneration;
            if (keep)
            {
                _held = candidate;
                _expiresAt = expiresAt;
                _unlocked = true;
                EndProofLocked();
            }
        }
        if (!keep)
        {
            candidate.Dispose();
            EndProof();
            return false;
        }
        if (expiresAt is { } deadline)
        {
            var due = deadline - _time.GetUtcNow();
            var timer = _time.CreateTimer(_ => _ = ReturnToLockedAsync("timeout"), null,
                due < TimeSpan.Zero ? TimeSpan.Zero : due, Timeout.InfiniteTimeSpan);
            lock (_gate)
                _expiry = timer;
        }
        return true;
    }

    private void EndProof()
    {
        lock (_gate)
            EndProofLocked();
    }

    private void EndProofLocked()
    {
        _proofInFlight = false;
        SignalIdleIfDone();
    }

    // ------------------------------------------------------------------ back to locked

    /// <summary>
    /// <c>broker lock</c>, the timeout, or a failed deferred ssh-key load (ruling 12), in order: stop taking
    /// new unlocks; wait for every in-flight unlock (leases, and a proof in flight) to finish and dispose
    /// its clones; zero the held password; unload the ssh keys; only then make the process dumpable.
    /// </summary>
    public async Task ReturnToLockedAsync(string reason)
    {
        await _transitions.WaitAsync().ConfigureAwait(false);
        try
        {
            Task idle;
            bool wasUnlocked;
            bool wait;
            ITimer? expiry;
            lock (_gate)
            {
                wasUnlocked = _unlocked;
                if (!wasUnlocked && !_proofInFlight)
                {
                    _generation++; // nothing to undo; an unlock queued now is refused all the same
                    return;
                }
                _locking = true;
                _generation++;
                wait = _leases > 0 || _proofInFlight;
                idle = wait ? (_idle = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).Task : Task.CompletedTask;
                expiry = _expiry;
                _expiry = null;
            }
            expiry?.Dispose();
            if (wait)
                DrainWaitObserver?.Invoke();
            await idle.ConfigureAwait(false);

            StretchedPassword? held;
            lock (_gate)
            {
                held = _held;
                _held = null;
                _expiresAt = null;
                _unlocked = false;
            }
            held?.Dispose();
            try
            {
                UnloadSshKeys?.Invoke();
            }
            finally
            {
                SshKeysUnloadedObserver?.Invoke();
            }
            MakeDumpableAgainOrStop();
            if (wasUnlocked)
                _log($"locked ({reason})");
        }
        finally
        {
            lock (_gate)
                _locking = false;
            _transitions.Release();
        }
    }

    private bool SetDumpable(bool dumpable)
    {
        if (!_hardening.SetDumpable(dumpable))
            return false;
        DumpableObserver?.Invoke(dumpable);
        return true;
    }

    /// <summary>Zeroes the held password (serve's stop).</summary>
    public void Dispose()
    {
        StretchedPassword? held;
        ITimer? expiry;
        lock (_gate)
        {
            held = _held;
            _held = null;
            _unlocked = false;
            expiry = _expiry;
            _expiry = null;
        }
        expiry?.Dispose();
        held?.Dispose();
    }
}
