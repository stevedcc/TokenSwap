using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;

namespace TswapCli;

/// <summary>What <see cref="FilledFiles"/> did to a filled copy while cleaning up (a test seam).</summary>
internal enum CleanupKind
{
    /// <summary>The file was overwritten with <see cref="CleanupStep.Length"/> zero bytes (and flushed).</summary>
    Zeroed,

    /// <summary>The file was deleted.</summary>
    Deleted,
}

/// <summary>One cleanup operation on a filled copy, reported after it was done.</summary>
internal sealed record CleanupStep(CleanupKind Kind, string Path, long Length);

/// <summary>
/// Issue #251: what <see cref="FilledFiles"/> takes from the machine, so tests can fake it: the roots,
/// the current directory (relative <c>{{@path}}</c> tokens resolve against it), the folder name
/// generator, <c>lstat</c>, the effective uid, the clock (the sweep's one-hour cutoff), the signal
/// registration (the trigger), how a signal reaches the child's process group, and a recorder of
/// cleanup steps.
/// </summary>
internal sealed record FilledFilesEnvironment
{
    /// <summary><c>$XDG_RUNTIME_DIR</c>; used (Unix) only when it is the user's own private folder.</summary>
    public required string? XdgRuntimeDir { get; init; }

    /// <summary>The fallback root, and the only one on Windows (<see cref="Path.GetTempPath"/>).</summary>
    public required string TempRoot { get; init; }

    /// <summary>The folder relative <c>{{@path}}</c> tokens resolve against.</summary>
    public required string CurrentDirectory { get; init; }

    /// <summary>A new folder name: <c>tswap-run-</c> and 16 CSPRNG hex characters.</summary>
    public Func<string> NewFolderName { get; init; } = () => "tswap-run-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));

    /// <summary><c>lstat</c>: type, permission bits and owner uid of a path itself (Unix).</summary>
    public Func<string, (BrokerNative.EntryType Type, UnixFileMode Mode, uint Uid)?> Stat { get; init; } = BrokerNative.LStat;

    /// <summary>The effective uid (Unix).</summary>
    public Func<uint> EffectiveUid { get; init; } = () => new UnixOwnership().EffectiveUid;

    /// <summary>The sweep's clock.</summary>
    public TimeProvider Time { get; init; } = TimeProvider.System;

    /// <summary>
    /// Registers the handler for SIGINT, SIGTERM and SIGHUP (Ctrl+C and Ctrl+Break on Windows), called
    /// with the signal's number instead of terminating tswap, until the result is disposed.
    /// </summary>
    public Func<Action<int>, IDisposable> RegisterSignals { get; init; } = RunSignals.Register;

    /// <summary>
    /// Sends a signal to the process group of each child tswap started (9: kill them) and returns how
    /// many children it found.
    /// </summary>
    public Func<int, int> SignalChildren { get; init; } = ChildProcesses.Signal;

    /// <summary>
    /// Whether tswap ends as soon as the handler for this signal returns, whatever it does: on Windows
    /// the console's close, logoff and shutdown events (SIGHUP, SIGTERM), which can't be cancelled.
    /// The handler then kills the child and cleans up before it returns.
    /// </summary>
    public Func<int, bool> SignalEndsProcess { get; init; } = signal => OperatingSystem.IsWindows() && signal is 1 or 15;

    /// <summary>How long an interrupted child gets to exit before it is killed.</summary>
    public TimeSpan ChildGrace { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Told about each cleanup step once it was done (tests).</summary>
    public Action<CleanupStep>? Recorder { get; init; }

    /// <summary>The real machine.</summary>
    public static FilledFilesEnvironment FromSystem() => new()
    {
        XdgRuntimeDir = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR"),
        TempRoot = Path.GetTempPath(),
        CurrentDirectory = Environment.CurrentDirectory,
    };
}

/// <summary>
/// Issue #251: the filled copies of one <c>run</c>'s <c>{{@path}}</c> tokens. They live in a private
/// folder (<c>tswap-run-&lt;16 hex&gt;</c>, mode 0700, or an ACL granting only the current user on
/// Windows) under <c>$XDG_RUNTIME_DIR</c> when that is the user's own private folder, else the temp
/// folder; each source file gets its own numbered subfolder keeping its base name. A <c>.lock</c> in
/// the folder is held until cleanup, so the sweep of a later run never touches a live folder.
/// <see cref="Dispose"/> zeroes every copy, deletes the folder and releases the lock. Signals
/// (registered at construction, before the folder exists) are forwarded to the child's process
/// group; cleanup waits for the child.
/// </summary>
internal sealed class FilledFiles : IDisposable
{
    private const UnixFileMode PrivateFolder = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const int KillSignal = 9;
    private const int FolderAttempts = 16;

    private readonly FilledFilesEnvironment _env;
    private readonly IDisposable _signals;
    private readonly Dictionary<string, string> _copies = new(SourcePathComparer);
    private readonly List<string> _files = [];
    private readonly Lock _gate = new();
    private readonly ManualResetEventSlim _childExited = new();
    private string? _folder;
    private IDisposable? _lock;
    private int _nextSubfolder = 1;
    private int? _signal;
    private bool _childRunning;
    private bool _forwarding;
    private bool _disposed;
    private Task? _forwardTask;
    private readonly Lock _cleanupGate = new();
    private bool _cleanedUp;

    /// <summary>The same source file, as resolved paths compare on this OS.</summary>
    public static StringComparer SourcePathComparer =>
        OperatingSystem.IsLinux() ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase;

    public FilledFiles(FilledFilesEnvironment env)
    {
        _env = env;
        _signals = env.RegisterSignals(OnSignal);
    }

    /// <summary>
    /// Writes <paramref name="content"/> (the filled file) as the copy of <paramref name="sourcePath"/>
    /// and returns the copy's path; the same source path gives the same copy. The folder and the lock
    /// are made on the first call.
    /// </summary>
    public string Add(string sourcePath, string content)
    {
        // Under the cleanup lock: a process-ending signal's cleanup never runs halfway through a copy,
        // and no copy is made after it.
        lock (_cleanupGate)
        {
            if (_cleanedUp)
                throw new TswapException("Interrupted: the filled copies were removed.");
            return AddLocked(sourcePath, content);
        }
    }

    private string AddLocked(string sourcePath, string content)
    {
        if (_copies.TryGetValue(sourcePath, out var existing))
            return existing;
        EnsureFolder();
        var subfolder = Path.Combine(_folder!, (_nextSubfolder++).ToString(CultureInfo.InvariantCulture));
        if (!TryCreatePrivateFolder(subfolder))
            throw new TswapException($"Couldn't create {subfolder}: it already exists.");
        var copy = Path.Combine(subfolder, Path.GetFileName(sourcePath));
        var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content);
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = PrivateFile;
            using var stream = new FileStream(copy, options);
            _files.Add(copy); // ours from here on: cleanup zeroes and deletes it, also after a failed write
            stream.Write(bytes);
            stream.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
        _copies[sourcePath] = copy;
        return copy;
    }

    /// <summary>
    /// Runs the child (<paramref name="run"/>) and returns its exit code; a signal that came before it
    /// started means it never starts (128 + signal).
    /// </summary>
    public int RunChild(Func<int> run)
    {
        lock (_gate)
        {
            if (_signal is { } early)
                return 128 + early;
            _childRunning = true;
        }
        try
        {
            return run();
        }
        finally
        {
            lock (_gate)
                _childRunning = false;
            _childExited.Set();
        }
    }

    // How long a process-ending signal's handler waits for the killed child before cleaning up: Windows
    // allows a close event's handler about 5 seconds in all.
    private static readonly TimeSpan EndingWait = TimeSpan.FromSeconds(2);

    private void OnSignal(int signal)
    {
        if (_env.SignalEndsProcess(signal))
        {
            // Review minor 4: tswap ends when this returns, so nothing can wait for the child: kill it,
            // give it a moment to let go of the copies, and clean up here (bounded).
            bool running;
            lock (_gate)
            {
                _signal ??= signal;
                running = _childRunning;
            }
            if (running)
            {
                _env.SignalChildren(KillSignal);
                _childExited.Wait(EndingWait < _env.ChildGrace ? EndingWait : _env.ChildGrace);
            }
            CleanUp();
            return;
        }

        bool startForwarding, forwardAgain;
        lock (_gate)
        {
            _signal ??= signal;
            startForwarding = _childRunning && !_forwarding;
            forwardAgain = _childRunning && _forwarding;
            _forwarding |= startForwarding;
            // Assigned under the gate, so Dispose (which reads it under the gate) can't miss a task
            // that has started.
            if (startForwarding)
                _forwardTask = Task.Run(() => Forward(signal));
        }
        if (forwardAgain)
            _env.SignalChildren(signal);
        // No child running: RunChild never starts it (or it has exited), and Dispose cleans up.
    }

    // The signal reaches the child's process group (retried until the child exists: the signal may
    // come just as it starts); after the grace period it is killed. Cleanup runs once it has exited.
    private void Forward(int signal)
    {
        var clock = Stopwatch.StartNew();
        var sent = false;
        while (true)
        {
            if (!sent)
                sent = _env.SignalChildren(signal) > 0;
            var left = _env.ChildGrace - clock.Elapsed;
            if (left <= TimeSpan.Zero)
            {
                if (!_childExited.IsSet)
                    _env.SignalChildren(KillSignal);
                return;
            }
            if (_childExited.Wait(sent ? left : TimeSpan.FromMilliseconds(Math.Min(50, left.TotalMilliseconds))))
                return;
        }
    }

    private void EnsureFolder()
    {
        if (_folder is not null)
            return;
        var root = ChooseRoot();
        for (var attempt = 0; attempt < FolderAttempts && _folder is null; attempt++)
        {
            var path = Path.Combine(root, _env.NewFolderName());
            if (TryCreatePrivateFolder(path))
                _folder = path;
        }
        if (_folder is null)
            throw new TswapException($"Couldn't create a private folder in {root}: every name tried already exists.");
        _lock = TakeLock(Path.Combine(_folder, ".lock"));
    }

    private string ChooseRoot()
    {
        if (OperatingSystem.IsWindows())
            return _env.TempRoot;
        var xdg = _env.XdgRuntimeDir;
        return !string.IsNullOrEmpty(xdg) && Path.IsPathRooted(xdg) && IsPrivateRoot(xdg) ? xdg : _env.TempRoot;
    }

    // $XDG_RUNTIME_DIR counts only as a directory (not a symlink) owned by this user that no group or
    // other user can write to.
    private bool IsPrivateRoot(string path) =>
        _env.Stat(path) is { Type: BrokerNative.EntryType.Directory } s
        && s.Uid == _env.EffectiveUid()
        && (s.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) == 0;

    /// <summary>
    /// Creates <paramref name="path"/> exclusively with its final permissions (Unix <c>mkdir(0700)</c>;
    /// Windows an ACL granting only the current user, inheritance removed) and verifies them; false
    /// when the path already exists (a directory, a file or a symlink: never written through).
    /// </summary>
    private bool TryCreatePrivateFolder(string path)
    {
        if (OperatingSystem.IsWindows())
            return WindowsPrivateFolder.TryCreate(path);
        if (FilledFilesNative.mkdir(path, (uint)PrivateFolder) != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            if (errno == FilledFilesNative.Eexist)
                return false;
            throw new TswapException($"Couldn't create {path} (errno {errno}).");
        }
        if (_env.Stat(path) is not { Type: BrokerNative.EntryType.Directory } s || s.Uid != _env.EffectiveUid()
            || (s.Mode & (UnixFileMode)0x1FF) != PrivateFolder) // the permission bits (a setgid parent's bit is harmless)
            throw new TswapException($"{path} isn't a private folder owned by you (mode 0700) after creating it; nothing was written.");
        return true;
    }

    private static IDisposable TakeLock(string path)
    {
        if (OperatingSystem.IsWindows())
            return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
        return UnixLockFile.TryTake(path, out _) ?? throw new TswapException($"Couldn't lock {path}.");
    }

    /// <summary>
    /// Issue #251: removes every <c>tswap-run-*</c> folder of both roots owned by this user that is
    /// older than one hour and not in use (its <c>.lock</c> can be taken, or it has none): left behind
    /// by a run that was killed. Its files are zeroed first. A live folder is never touched; anything
    /// that can't be read or removed is skipped.
    /// </summary>
    public void SweepStale()
    {
        var cutoff = _env.Time.GetUtcNow().UtcDateTime - TimeSpan.FromHours(1);
        List<string> roots = [_env.TempRoot];
        if (!OperatingSystem.IsWindows() && !string.IsNullOrEmpty(_env.XdgRuntimeDir) && Path.IsPathRooted(_env.XdgRuntimeDir)
            && IsPrivateRoot(_env.XdgRuntimeDir))
            roots.Insert(0, _env.XdgRuntimeDir);
        foreach (var root in roots.Distinct(SourcePathComparer))
        {
            List<string> folders;
            try
            {
                folders = Directory.EnumerateDirectories(root, "tswap-run-*").ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            foreach (var folder in folders)
            {
                try
                {
                    SweepOne(folder, cutoff);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException)
                {
                    // Not ours, in use, or gone meanwhile: skipped, never fatal.
                }
            }
        }
    }

    private void SweepOne(string folder, DateTime cutoff)
    {
        if (OperatingSystem.IsWindows())
        {
            if (File.GetAttributes(folder).HasFlag(FileAttributes.ReparsePoint) || !WindowsPrivateFolder.IsPrivate(folder))
                return;
        }
        else if (_env.Stat(folder) is not { Type: BrokerNative.EntryType.Directory } s || s.Uid != _env.EffectiveUid()
                 || (s.Mode & (UnixFileMode)0x1FF) != PrivateFolder)
        {
            return; // not a folder tswap made: another user's, a link, or one others can write into
        }
        if (Directory.GetLastWriteTimeUtc(folder) >= cutoff)
            return;

        var lockPath = Path.Combine(folder, ".lock");
        IDisposable? held = null;
        if (OperatingSystem.IsWindows())
        {
            if (File.Exists(lockPath))
                held = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None); // a sharing violation: live, skipped
        }
        else if (_env.Stat(lockPath) is not { Type: BrokerNative.EntryType.Missing })
        {
            held = UnixLockFile.TryTake(lockPath, out var busy);
            if (busy || held is null)
                return;
        }
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint, // never follow or zero through a symlink
                IgnoreInaccessible = true,
            };
            foreach (var file in Directory.EnumerateFiles(folder, "*", options).ToList())
                if (!string.Equals(file, lockPath, StringComparison.Ordinal))
                    // A hard link is only unlinked: zeroing it would zero the file it shares (Windows:
                    // the folder's ACL already keeps others from planting one).
                    ZeroAndDelete(file, record: false, zero: OperatingSystem.IsWindows() || FilledFilesNative.LinkCount(file) == 1);
            if (OperatingSystem.IsWindows())
            {
                // Windows can't delete a folder holding an open file.
                held?.Dispose();
                held = null;
            }
            Directory.Delete(folder, recursive: true);
        }
        finally
        {
            held?.Dispose();
        }
    }

    /// <summary>Zeroes every copy, deletes the folder, releases the lock, and unregisters the signals.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        try
        {
            CleanUp();
            // The forwarding task ends once the child has exited (RunChild has set the event).
            Task? forwarding;
            lock (_gate)
                forwarding = _forwardTask;
            forwarding?.Wait(_env.ChildGrace);
            // _childExited is deliberately not disposed: a process-ending signal's handler (or a late
            // forwarding task) may still wait on it after this returns, and a ManualResetEventSlim whose
            // WaitHandle is never read holds no kernel handle, so there is nothing to release.
        }
        finally
        {
            _signals.Dispose();
        }
    }

    // Once, from Dispose or from a process-ending signal's handler, whichever comes first.
    private void CleanUp()
    {
        lock (_cleanupGate)
        {
            if (_cleanedUp)
                return;
            _cleanedUp = true;
            foreach (var file in _files)
                ZeroAndDelete(file, record: true);
            if (_folder is not null)
            {
                // Unix: the folder goes while the lock is held. Windows can't delete a folder holding an
                // open file: the lock (delete-on-close) is released first.
                if (OperatingSystem.IsWindows())
                    ReleaseLock();
                try
                {
                    Directory.Delete(_folder, recursive: true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Best effort: the next run's sweep removes it.
                }
            }
            ReleaseLock();
        }
    }

    private void ReleaseLock()
    {
        _lock?.Dispose();
        _lock = null;
    }

    // Best effort: tmpfs and SSDs may keep copies of the old blocks.
    private void ZeroAndDelete(string file, bool record, bool zero = true)
    {
        try
        {
            long length = 0;
            if (zero)
            {
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None);
                length = stream.Length;
                var zeros = new byte[(int)Math.Min(length, 64 * 1024)];
                for (var left = length; left > 0; left -= zeros.Length)
                    stream.Write(zeros, 0, (int)Math.Min(zeros.Length, left));
                stream.Flush(flushToDisk: true);
            }
            if (record && zero)
                _env.Recorder?.Invoke(new CleanupStep(CleanupKind.Zeroed, file, length));
            File.Delete(file);
            if (record)
                _env.Recorder?.Invoke(new CleanupStep(CleanupKind.Deleted, file, length));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception again) when (again is IOException or UnauthorizedAccessException)
            {
                // Left for the folder delete, or the next sweep.
            }
        }
    }
}
