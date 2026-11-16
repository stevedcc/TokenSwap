using TswapCore.Agent;

namespace TswapCore.Vault;

/// <summary>
/// Brief T29 (#273, #173, #42, #301): the per-user, cross-process exclusive lock every call that can reach a YubiKey
/// or security key is made under (<see cref="LockedYubiKeyService"/>, <see cref="Fido2.LockedFido2Keys"/>), so a
/// second tswap waits for the first instead of colliding with it (or taking its touch). One lock for every key and
/// both interfaces: a listing can't know the serial it will meet.
///
/// <para><b>Where.</b> <paramref name="lockPath"/> (resolved once, at the first take) is
/// <c>&lt;home&gt;/.cache/tswap/yubikey.lock</c> on Linux and macOS (the invoking user's home under sudo) or
/// <c>%LOCALAPPDATA%\tswap\yubikey.lock</c> on Windows, independent of the config folder. A missing folder is created
/// through <see cref="DirectoryOwnerMatcher.CreateDirectory"/> (0700, as the nearest existing folder's owner), and
/// the file is opened inside <see cref="DirectoryOwnerMatcher.AsOwner{T}"/>: under sudo it is made and opened as the
/// invoking user, and the device call then runs as root, outside the switch. The switch only happens in a privileged
/// process, which is never a multi-threaded one: <c>broker serve</c> and <c>agent serve</c> refuse root
/// (<c>BrokerCommand</c>'s <c>Ownership.IsPrivileged</c> checks, <c>AgentCommand.RefuseRoot</c>), so the CLI's
/// "one thread, one operation at a time" rule of the process-wide switch holds (amendment A3).</para>
///
/// <para><b>How.</b> Unix: <see cref="UnixLockFile.TryTake"/> (an exclusive <c>flock</c> taken at open, #236).
/// Windows: a <see cref="FileShare.None"/> stream; a sharing or lock violation means held elsewhere. The file is
/// never deleted and holds no data; the kernel (or Windows' handle close) releases it when the process dies.
/// Within one process a <see cref="SemaphoreSlim"/> gate, tried without blocking before the file, serialises
/// threads (two opens in one process would conflict on <c>flock</c> too).</para>
///
/// <para><b>Waiting.</b> A held try prints <see cref="WaitingLine"/> once, pauses <see cref="PollInterval"/>
/// (<paramref name="pause"/>) and tries again, for at most the wait budget (<see cref="Timeout"/>, or a caller's,
/// <see cref="WithWaitBudget"/>); then it throws <see cref="OtpFailure.Busy"/> with <see cref="TimeoutTextFor"/>
/// and remembers it: a later take tries once without waiting and throws the same at once while still held, or takes
/// the lock and forgets (amendment A1). A take that waited prints <see cref="GoingOnLine"/> before its call.</para>
///
/// <para><b>Can't take it</b> (no usable home, the folder can't be made, the path isn't a regular file, an owner
/// switch fails): <see cref="Warning"/> once, and this and every later call of the process run without the file
/// lock (the in-process gate still applies). Nothing is retried as root.</para>
/// </summary>
/// <param name="owner">The file layer (null: <see cref="DirectoryOwnerMatcher.Default"/>).</param>
/// <param name="pause">The wait between tries (null: <see cref="Thread.Sleep(TimeSpan)"/>); a test seam.</param>
public sealed class YubiKeyLock(Func<string> lockPath, TextWriter notices, TimeProvider time,
    DirectoryOwnerMatcher? owner = null, Action<TimeSpan>? pause = null)
{
    public const string FileName = "yubikey.lock";
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(100);
    public const string WaitingLine = "Waiting for another tswap to finish with the YubiKey or security key (it may be waiting for a touch or a PIN)...";
    public const string GoingOnLine = "The other tswap is done; going on (touch the key again if it flashes).";

    /// <summary>The timeout's text for a wait of <paramref name="waited"/> (amendment A4: built from the budget, never a literal).</summary>
    public static string TimeoutTextFor(TimeSpan waited) =>
        $"Another tswap has been using the YubiKey or security key for {waited.TotalSeconds:0} seconds, so this one stopped waiting. " +
        "Try again when it's done (if it is waiting for a touch or a PIN in another terminal, answer or cancel it there).";

    /// <summary>The timeout's text for the default budget, <see cref="Timeout"/>.</summary>
    public static readonly string TimeoutText = TimeoutTextFor(Timeout);

    public static string Warning(string reason) =>
        $"Warning: tswap couldn't take its YubiKey lock ({reason}), so tswap processes using the key at the same time could disturb each other.";

    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;

    private static readonly AsyncLocal<TimeSpan?> s_waitBudget = new();

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly DirectoryOwnerMatcher _owner = owner ?? DirectoryOwnerMatcher.Default;
    private readonly Action<TimeSpan> _pause = pause ?? Thread.Sleep;
    private string? _path;
    private bool _fileLockOff;
    private int _holderThread;
    private string? _rememberedTimeout;

    /// <summary>
    /// Amendment A2: takes made in this scope (this thread and the tasks it starts) wait at most
    /// <paramref name="budget"/> instead of <see cref="Timeout"/>. The broker's unlock paths pass
    /// <c>BrokerLimits.YubiKeyWaitBudget</c>, so a lock wait ends before the broker abandons the unlock. An ambient
    /// scope because the take happens deep inside the unlock (<c>VaultUnlocker</c>, the decorators), which the broker
    /// doesn't reach into.
    /// </summary>
    public static IDisposable WithWaitBudget(TimeSpan budget)
    {
        var previous = s_waitBudget.Value;
        s_waitBudget.Value = budget;
        return new Restore(previous);
    }

    /// <summary>The budget of the current <see cref="WithWaitBudget"/> scope, or null outside one.</summary>
    internal static TimeSpan? CurrentWaitBudget => s_waitBudget.Value;

    /// <summary>True when the calling thread holds this lock (tests; the decorators never nest).</summary>
    internal bool HeldByThisThread => Volatile.Read(ref _holderThread) == Environment.CurrentManagedThreadId;

    public T Run<T>(Func<T> call)
    {
        using var _ = Take();
        return call();
    }

    public void Run(Action call)
    {
        using var _ = Take();
        call();
    }

    /// <summary>
    /// Takes the lock, waiting at most <paramref name="waitBudget"/> (null: the current <see cref="WithWaitBudget"/>
    /// scope's, else <see cref="Timeout"/>); held until the result is disposed. Throws
    /// <see cref="YubiKeyDeviceException"/> (<see cref="OtpFailure.Busy"/>) when the budget runs out, and
    /// <see cref="InvalidOperationException"/> on a thread that already holds it.
    /// </summary>
    public IDisposable Take(TimeSpan? waitBudget = null)
    {
        if (HeldByThisThread)
            throw new InvalidOperationException("The YubiKey lock is already held by this thread.");
        var budget = waitBudget ?? CurrentWaitBudget ?? Timeout;
        var started = time.GetTimestamp();
        var waited = false;
        while (true)
        {
            if (TryTakeOnce() is { } held)
            {
                Volatile.Write(ref _rememberedTimeout, null);
                if (waited)
                    notices.WriteLine(GoingOnLine);
                return held;
            }
            if (Volatile.Read(ref _rememberedTimeout) is { } remembered)
                throw new YubiKeyDeviceException(OtpFailure.Busy, null, remembered);
            if (!waited)
            {
                notices.WriteLine(WaitingLine);
                waited = true;
            }
            if (time.GetElapsedTime(started) >= budget)
            {
                var text = TimeoutTextFor(budget);
                Volatile.Write(ref _rememberedTimeout, text);
                throw new YubiKeyDeviceException(OtpFailure.Busy, null, text);
            }
            _pause(PollInterval);
        }
    }

    /// <summary>One try of the gate and then the file, neither blocking: the held lock, or null when either is held.</summary>
    private Held? TryTakeOnce()
    {
        if (!_gate.Wait(0))
            return null;
        FileStream? file = null;
        try
        {
            if (!_fileLockOff)
            {
                file = TryTakeFile(out var heldElsewhere);
                if (heldElsewhere)
                {
                    _gate.Release(); // amendment A4: the gate is never held across a pause
                    return null;
                }
            }
        }
        catch
        {
            _gate.Release();
            throw;
        }
        Volatile.Write(ref _holderThread, Environment.CurrentManagedThreadId);
        return new Held(this, file);
    }

    /// <summary>
    /// The file lock (under the gate, so one thread at a time), or null: held elsewhere, or the file lock is off now
    /// (the warning printed).
    /// </summary>
    private FileStream? TryTakeFile(out bool heldElsewhere)
    {
        heldElsewhere = false;
        try
        {
            var path = _path ??= lockPath();
            _owner.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            var (stream, held) = _owner.AsOwner(path, () => Open(path));
            heldElsewhere = held;
            return stream;
        }
        catch (Exception e) when (e is TswapException or IOException or UnauthorizedAccessException)
        {
            _fileLockOff = true;
            notices.WriteLine(Warning(e.Message));
            return null;
        }
    }

    private static (FileStream? Stream, bool HeldElsewhere) Open(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            var stream = UnixLockFile.TryTake(path, out var heldElsewhere);
            return (stream, heldElsewhere);
        }
        try
        {
            return (new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None), false);
        }
        catch (IOException e) when ((e.HResult & 0xFFFF) is ErrorSharingViolation or ErrorLockViolation)
        {
            return (null, true);
        }
    }

    private sealed class Held(YubiKeyLock owner, FileStream? file) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            try
            {
                file?.Dispose();
            }
            finally
            {
                Volatile.Write(ref owner._holderThread, 0);
                owner._gate.Release();
            }
        }
    }

    private sealed class Restore(TimeSpan? previous) : IDisposable
    {
        public void Dispose() => s_waitBudget.Value = previous;
    }
}
