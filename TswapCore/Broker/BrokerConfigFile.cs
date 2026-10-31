using System.Text;
using TswapCore.Broker.Templates;

namespace TswapCore.Broker;

/// <summary>
/// Reads and writes <c>broker.json</c> next to the vault's <c>config.json</c> (decision 9) through
/// T5's file layer (<see cref="DirectoryOwnerMatcher"/>): written atomically (temp file, then a
/// rename that replaces a symlink rather than writing through it), mode 0600, and under sudo as
/// the vault folder's owner. Every load validates the whole file.
/// </summary>
public static class BrokerConfigFile
{
    public const string FileName = "broker.json";

    public static string PathIn(string configDir) => Path.Combine(configDir, FileName);

    /// <summary>
    /// The raw config, or null when there is no <c>broker.json</c> yet. The file must be a regular
    /// file, not group- or world-writable, and owned by the vault folder's owner
    /// (<paramref name="ownership"/>; null: the real one); one that can't be read is a
    /// <see cref="BrokerConfigException"/>.
    /// </summary>
    public static BrokerConfig? ReadRaw(DirectoryOwnerMatcher owner, string configDir, IUnixOwnership? ownership = null)
    {
        var path = PathIn(configDir);
        if (!owner.FileExists(path))
            return null;
        CheckMode(path);
        CheckOwner(path, configDir, ownership ?? new UnixOwnership());
        byte[] bytes;
        try
        {
            bytes = owner.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new BrokerConfigException($"{path} can't be read: {ex.Message}");
        }
        using var reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return BrokerPolicy.Deserialize(reader.ReadToEnd());
    }

    /// <summary>
    /// Loads and validates <c>broker.json</c>; a missing, unreadable or invalid file is a
    /// <see cref="BrokerConfigException"/>. Templates' binds are checked against
    /// <paramref name="host"/> (null: <see cref="BrokerHostContext.ForVault"/> of this folder).
    /// </summary>
    public static BrokerPolicy Load(DirectoryOwnerMatcher owner, string configDir, IUnixOwnership? ownership = null, BrokerHostContext? host = null)
    {
        var raw = ReadRaw(owner, configDir, ownership)
            ?? throw new BrokerConfigException($"{PathIn(configDir)} does not exist. Add routes and sockets with 'sudo tswap broker route add' and 'sudo tswap broker socket add'.");
        return BrokerPolicy.Validate(raw, HostFor(raw, configDir, host));
    }

    /// <summary>The host context for a config's templates: the given one, else the vault folder's own (only built when there are templates).</summary>
    private static BrokerHostContext? HostFor(BrokerConfig config, string configDir, BrokerHostContext? host) =>
        host ?? (config.Templates is { Count: > 0 } && OperatingSystem.IsLinux() ? BrokerHostContext.ForVault(configDir, null) : null);

    public const string EditLockFileName = "broker.json.lock";

    /// <summary>
    /// The lock for <c>route|socket add|remove</c>'s read-modify-write: an exclusive, non-blocking
    /// <c>flock</c> on <c>broker.json.lock</c>, opened as the folder's owner under sudo, which must be
    /// a regular file and is tightened to 0600 (like broker.log). Only another holder of the lock is
    /// reported as a concurrent change; any other failure is an error naming the file. Nothing is
    /// read or written when it fails.
    /// </summary>
    public static IDisposable LockForEdit(DirectoryOwnerMatcher owner, string configDir)
    {
        if (OperatingSystem.IsWindows())
            throw new TswapException("'tswap broker' is not supported on Windows.");
        owner.CreateDirectory(configDir);
        var path = Path.GetFullPath(Path.Combine(configDir, EditLockFileName));
        if (owner.AsOwner(path, () => BrokerNative.LStat(path)) is { Type: not (BrokerNative.EntryType.Missing or BrokerNative.EntryType.Regular) })
            throw new TswapException($"{path} is not a regular file; remove it.");
        FileStream stream;
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.ReadWrite };
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            stream = owner.AsOwner(path, () => new FileStream(path, options));
        }
        catch (IOException ex) when (ex.HResult == BrokerNative.WouldBlockErrno)
        {
            // .NET's own open-time flock found the lock held by another process (on Unix .NET
            // reports the errno, EWOULDBLOCK, as the HResult).
            throw new TswapException($"Another 'tswap broker' change is running on {configDir}; try again when it has finished.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException($"Can't open the broker.json edit lock {path}: {ex.Message}");
        }
        if (!BrokerNative.TryLockExclusive(stream.SafeFileHandle, out var heldElsewhere, out var errno))
        {
            stream.Dispose();
            throw heldElsewhere
                ? new TswapException($"Another 'tswap broker' change is running on {configDir}; try again when it has finished.")
                : new TswapException($"Can't lock the broker.json edit lock {path} (flock errno {errno}).");
        }
        try
        {
            File.SetUnixFileMode(stream.SafeFileHandle, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            stream.Dispose(); // and so the flock: a failed start never keeps the lock
            throw;
        }
        return stream;
    }

    /// <summary>Validates <paramref name="config"/> (templates against <paramref name="host"/>, as <see cref="Load"/>), then writes it (nothing is written when it is invalid).</summary>
    public static void Save(DirectoryOwnerMatcher owner, string configDir, BrokerConfig config, BrokerHostContext? host = null)
    {
        BrokerPolicy.Validate(config, HostFor(config, configDir, host));
        var path = PathIn(configDir);
        owner.CreateDirectory(configDir);
        owner.WriteAtomic(path, Encoding.UTF8.GetBytes(BrokerPolicy.Serialize(config) + "\n"));
        owner.Tighten(path); // 0600 even if an earlier file had a wider mode
    }

    /// <summary>Refuses a <c>broker.json</c> not owned by the vault folder's owner.</summary>
    private static void CheckOwner(string path, string configDir, IUnixOwnership ownership)
    {
        if (OperatingSystem.IsWindows())
            return;
        var file = ownership.GetOwner(path);
        var folder = ownership.GetOwner(Path.GetFullPath(configDir));
        if (file is not { } f || folder is not { } d)
            throw new BrokerConfigException($"Can't read the owner of {path} or its folder.");
        if (f.Uid != d.Uid)
            throw new BrokerConfigException($"{path} is owned by uid {f.Uid}, not by the vault folder's owner (uid {d.Uid}); only the vault user's own broker.json is used.");
    }

    /// <summary>Refuses a <c>broker.json</c> that another uid could have changed (group- or world-writable).</summary>
    private static void CheckMode(string path)
    {
        if (OperatingSystem.IsWindows())
            return;
        var info = new FileInfo(path);
        if (info.LinkTarget is not null)
            throw new BrokerConfigException($"{path} is a symlink; broker.json must be a regular file.");
        if ((info.UnixFileMode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new BrokerConfigException($"{path} is writable by group or others; make it 0600 (chmod 600 {path}).");
    }
}

/// <summary>
/// The config <c>serve</c> is using (decision 9): replaced as a whole on SIGHUP when the new file
/// validates, kept when it doesn't. A request reads <see cref="Current"/> once and keeps it.
/// </summary>
public sealed class BrokerPolicyHolder(BrokerPolicy initial)
{
    private BrokerPolicy _current = initial;

    public BrokerPolicy Current => Volatile.Read(ref _current);

    /// <summary>
    /// Loads a new config with <paramref name="load"/>; on success swaps it in and returns true, on
    /// failure keeps the current one, reports why to <paramref name="log"/> and returns false.
    /// </summary>
    public bool TryReload(Func<BrokerPolicy> load, Action<string> log)
    {
        BrokerPolicy next;
        try
        {
            next = load();
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            log($"config reload refused, keeping the current config: {ex.Message}");
            return false;
        }
        Volatile.Write(ref _current, next);
        log("config reloaded");
        return true;
    }
}
