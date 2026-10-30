using System.Text;

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

    /// <summary>The raw config, or null when there is no <c>broker.json</c> yet.</summary>
    public static BrokerConfig? ReadRaw(DirectoryOwnerMatcher owner, string configDir)
    {
        var path = PathIn(configDir);
        if (!owner.FileExists(path))
            return null;
        CheckMode(path);
        using var reader = new StreamReader(new MemoryStream(owner.ReadAllBytes(path)), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return BrokerPolicy.Deserialize(reader.ReadToEnd());
    }

    /// <summary>Loads and validates <c>broker.json</c>; a missing or invalid file is a <see cref="BrokerConfigException"/>.</summary>
    public static BrokerPolicy Load(DirectoryOwnerMatcher owner, string configDir)
    {
        var raw = ReadRaw(owner, configDir)
            ?? throw new BrokerConfigException($"{PathIn(configDir)} does not exist. Add routes and sockets with 'sudo tswap broker route add' and 'sudo tswap broker socket add'.");
        return BrokerPolicy.Validate(raw);
    }

    /// <summary>Validates <paramref name="config"/>, then writes it (nothing is written when it is invalid).</summary>
    public static void Save(DirectoryOwnerMatcher owner, string configDir, BrokerConfig config)
    {
        BrokerPolicy.Validate(config);
        var path = PathIn(configDir);
        owner.CreateDirectory(configDir);
        owner.WriteAtomic(path, Encoding.UTF8.GetBytes(BrokerPolicy.Serialize(config) + "\n"));
        owner.Tighten(path); // 0600 even if an earlier file had a wider mode
    }

    /// <summary>Refuses a <c>broker.json</c> that another uid could have changed (group- or world-writable).</summary>
    private static void CheckMode(string path)
    {
        if (OperatingSystem.IsWindows())
            return;
        var info = new FileInfo(path);
        if (info.LinkTarget != null)
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
