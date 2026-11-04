using TswapCore.Broker;

namespace TswapCore.Agent;

/// <summary>
/// An exclusive, non-blocking <c>flock</c> on a lock file (brief T17 ruling 21), the pattern of
/// <c>BrokerServer.TakeLock</c>: the file is opened (created 0600 when missing), locked, and held until
/// the returned stream is disposed. The kernel releases the lock when the process dies, however it dies.
/// </summary>
public static class UnixLockFile
{
    /// <summary>
    /// The locked stream, or null with <paramref name="heldElsewhere"/> true when another holder has
    /// the lock. Throws <see cref="TswapException"/> when the file can't be opened or locked for
    /// another reason, or isn't a regular file.
    /// </summary>
    public static FileStream? TryTake(string path, out bool heldElsewhere)
    {
        // flock is Unix; the Windows agent uses a named pipe and never reaches this.
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Lock files are Unix-only.");
        heldElsewhere = false;
        if (BrokerNative.LStat(path) is { Type: not (BrokerNative.EntryType.Missing or BrokerNative.EntryType.Regular) })
            throw new TswapException($"{path} is not a regular file; remove it.");
        FileStream stream;
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                // FileShare.None: .NET takes the exclusive flock at open, in one request. FileShare.ReadWrite took a shared flock that the explicit exclusive flock below then had to upgrade, and upgrade semantics differ by platform (Linux drops the shared lock first, so one taker always wins; where a failed upgrade keeps it, two takers can both lose, which macOS CI hit, #236). Never upgrade.
                Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            stream = new FileStream(path, options);
        }
        catch (IOException ex) when (ex.HResult == BrokerNative.WouldBlockErrno)
        {
            heldElsewhere = true;
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException($"Can't open the lock file {path}: {ex.Message}");
        }
        if (!BrokerNative.TryLockExclusive(stream.SafeFileHandle, out heldElsewhere, out var errno))
        {
            stream.Dispose();
            if (heldElsewhere)
                return null;
            throw new TswapException($"Can't lock {path} (flock errno {errno}).");
        }
        return stream;
    }
}
