using System.Text;
using TswapCore.Broker;

namespace TswapCore.Agent;

/// <summary>
/// Where the agent of a vault listens (brief T17 ruling 6), and the checks on its folder.
/// <list type="bullet">
/// <item><b>Linux:</b> <c>/run/user/&lt;uid&gt;/tswap</c> when <c>/run/user/&lt;uid&gt;</c> exists and
/// belongs to <c>&lt;uid&gt;</c>; otherwise <c>&lt;home of uid&gt;/.cache/tswap/run</c>.</item>
/// <item><b>macOS:</b> <c>&lt;home of uid&gt;/Library/Caches/tswap/run</c>.</item>
/// <item><b>Windows:</b> the named pipe <c>tswap-agent-&lt;user SID&gt;-&lt;16 hex&gt;</c>
/// (<see cref="WindowsPipeIdentity"/>).</item>
/// </list>
/// <c>&lt;uid&gt;</c> is the vault owner's (the owner of the vault's config folder), so <c>sudo tswap get</c>
/// finds the owner's agent although sudo drops the environment. The socket is
/// <c>agent-&lt;first 16 hex chars of the vault id&gt;.sock</c>; <see cref="Variable"/> overrides the whole
/// path on Unix, for clients and servers alike. Clients never create anything here; <c>agent serve</c> and
/// <c>broker serve</c> create the folder (<see cref="EnsureFolder"/>) after their root refusal.
/// </summary>
public static class AgentSocketPath
{
    /// <summary>The <c>SSH_AUTH_SOCK</c>-like override (Unix only).</summary>
    public const string Variable = "TSWAP_AGENT_SOCK";

    /// <summary>macOS's <c>sun_path</c> limit, in UTF-8 bytes (Linux allows 107).</summary>
    public const int MaxUtf8Bytes = 103;

    private const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>What <see cref="For(uint, byte[], Func{string, string?}, Inputs)"/> reads from the machine (tests swap it).</summary>
    internal sealed record Inputs(string RunUserRoot, Func<uint, string?> HomeOf, IUnixOwnership Ownership, bool MacOs)
    {
        public static Inputs Machine => new("/run/user", BrokerNative.HomeOf, new UnixOwnership(), OperatingSystem.IsMacOS());
    }

    /// <summary>The first 16 hex characters (lowercase) of <paramref name="vaultId"/>.</summary>
    public static string Prefix(byte[] vaultId) => Convert.ToHexStringLower(vaultId)[..16];

    /// <summary><c>agent-&lt;16 hex&gt;.sock</c>.</summary>
    public static string SocketName(byte[] vaultId) => $"agent-{Prefix(vaultId)}.sock";

    /// <summary>
    /// The agent's socket path (on Windows, its pipe name) for the vault <paramref name="vaultId"/>
    /// owned by <paramref name="ownerUid"/>. <paramref name="env"/> reads <see cref="Variable"/>. Throws
    /// <see cref="TswapException"/> when the path is over <see cref="MaxUtf8Bytes"/> UTF-8 bytes or the
    /// owner has no home folder.
    /// </summary>
    public static string For(uint ownerUid, byte[] vaultId, Func<string, string?> env)
    {
        if (OperatingSystem.IsWindows())
            return WindowsPipeIdentity.PipeName(
                WindowsPipeIdentity.CurrentUserSid() ?? throw new TswapException("Can't read this user's SID for the agent's pipe name."),
                vaultId);
        return For(ownerUid, vaultId, env, Inputs.Machine);
    }

    internal static string For(uint ownerUid, byte[] vaultId, Func<string, string?> env, Inputs inputs)
    {
        var overridden = env(Variable);
        var path = string.IsNullOrEmpty(overridden)
            ? Path.Combine(Folder(ownerUid, inputs), SocketName(vaultId))
            : Path.GetFullPath(overridden);
        CheckLength(path);
        return path;
    }

    /// <summary>
    /// The broker's control socket, <c>&lt;agent socket folder&gt;/broker-&lt;16 hex&gt;/control.sock</c>
    /// (ruling 14). <see cref="Variable"/> doesn't move it: that variable is the agent's.
    /// </summary>
    public static string BrokerControlFor(uint ownerUid, byte[] vaultId) => BrokerControlFor(ownerUid, vaultId, Inputs.Machine);

    internal static string BrokerControlFor(uint ownerUid, byte[] vaultId, Inputs inputs)
    {
        var path = Path.Combine(Folder(ownerUid, inputs), $"broker-{Prefix(vaultId)}", "control.sock");
        CheckLength(path);
        return path;
    }

    /// <summary>The default socket folder of <paramref name="ownerUid"/> (ruling 6), whether or not it exists.</summary>
    internal static string Folder(uint ownerUid, Inputs inputs)
    {
        if (!inputs.MacOs)
        {
            var runUser = Path.Combine(inputs.RunUserRoot, ownerUid.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (BrokerNative.LStat(runUser) is { Type: BrokerNative.EntryType.Directory } &&
                inputs.Ownership.GetOwner(runUser)?.Uid == ownerUid)
                return Path.Combine(runUser, "tswap");
        }
        var home = inputs.HomeOf(ownerUid);
        if (string.IsNullOrEmpty(home))
            throw new TswapException($"uid {ownerUid} has no home folder for the agent's socket; set {Variable}.");
        return inputs.MacOs
            ? Path.Combine(home, "Library", "Caches", "tswap", "run")
            : Path.Combine(home, ".cache", "tswap", "run");
    }

    /// <summary>Refuses a socket path over <see cref="MaxUtf8Bytes"/> UTF-8 bytes, naming <see cref="Variable"/>.</summary>
    public static void CheckLength(string path)
    {
        var bytes = Encoding.UTF8.GetByteCount(path);
        if (bytes > MaxUtf8Bytes)
            throw new TswapException(
                $"The agent socket path {path} is {bytes} bytes, over the {MaxUtf8Bytes}-byte limit for a socket; set {Variable} to a shorter path.");
    }

    /// <summary>The client's text for an agent that answered "other vault" (ruling 6: two vaults share a 16-hex prefix).</summary>
    public static string OtherVaultMessage(string path) =>
        $"Another vault's agent holds {path}; set {Variable} to a different path for this vault.";

    // ------------------------------------------------------------------ the folder

    /// <summary>
    /// For <c>agent serve</c> and <c>broker serve</c> only, after their root refusal: creates
    /// <paramref name="dir"/> (and any missing folder above it) with mode 0700 when it is missing, then
    /// applies <see cref="CheckFolder"/>. An existing folder is never repaired.
    /// </summary>
    public static string EnsureFolder(string dir, uint uid, IUnixOwnership ownership)
    {
        var full = Path.GetFullPath(dir);
        if (BrokerNative.LStat(full) is { Type: BrokerNative.EntryType.Missing })
        {
            try
            {
                if (OperatingSystem.IsWindows())
                    throw new PlatformNotSupportedException();
                // One folder at a time, top down: Directory.CreateDirectory gives the mode only to the
                // last folder it makes, and the ones above it would get the umask's default.
                var missing = new Stack<string>();
                for (var d = full; d is not null && BrokerNative.LStat(d) is { Type: BrokerNative.EntryType.Missing }; d = Path.GetDirectoryName(d))
                    missing.Push(d);
                while (missing.TryPop(out var d))
                    Directory.CreateDirectory(d, Private);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new TswapException($"Can't create the socket folder {full}: {ex.Message}");
            }
        }
        return CheckFolder(full, uid, ownership);
    }

    /// <summary>
    /// Ruling 6's checks, as <c>BrokerServer.CheckSocketDir</c> does them: <paramref name="dir"/> exists
    /// and is a folder (<c>lstat</c>, so a symlink is refused), is owned by <paramref name="uid"/>, has
    /// mode 0700, and every folder above its real path is owned by <paramref name="uid"/> or root and not
    /// group- or other-writable (a root-owned sticky folder such as <c>/tmp</c> is allowed). Returns the
    /// real path. A failing folder is refused, never repaired.
    /// </summary>
    public static string CheckFolder(string dir, uint uid, IUnixOwnership ownership)
    {
        var full = Path.GetFullPath(dir);
        var stat = BrokerNative.LStat(full) ?? throw new TswapException($"Can't read the socket folder {full}.");
        switch (stat.Type)
        {
            case BrokerNative.EntryType.Missing:
                throw new TswapException($"The socket folder {full} does not exist.");
            case BrokerNative.EntryType.Symlink:
                throw new TswapException($"The socket folder {full} is a symlink; refusing it.");
            case not BrokerNative.EntryType.Directory:
                throw new TswapException($"The socket folder {full} is not a folder; refusing it.");
        }
        var owner = ownership.GetOwner(full)?.Uid;
        if (owner != uid)
            throw new TswapException(
                $"The socket folder {full} is not owned by uid {uid} (its owner is uid {owner?.ToString() ?? "?"}); refusing it.");
        if ((stat.Mode & (UnixFileMode)0b111_111_111) != Private || (stat.Mode & ~(UnixFileMode)0b111_111_111) != 0)
            throw new TswapException(
                $"The socket folder {full} has mode {Octal(stat.Mode)}, not 0700; refusing it (fix or remove it by hand).");

        var real = BrokerNative.RealPath(full) ?? throw new TswapException($"Can't resolve the socket folder {full}.");
        for (var parent = Path.GetDirectoryName(real); parent is not null; parent = Path.GetDirectoryName(parent))
            CheckParent(parent, uid, ownership);
        return real;
    }

    private static void CheckParent(string parent, uint uid, IUnixOwnership ownership)
    {
        var stat = BrokerNative.LStat(parent) ?? throw new TswapException($"Can't read {parent} (a folder above the socket folder).");
        var owner = ownership.GetOwner(parent)?.Uid;
        if (owner is null || (owner != 0 && owner != uid))
            throw new TswapException(
                $"{parent} (a folder above the socket folder) is owned by uid {owner?.ToString() ?? "?"}; every folder above it must be root's or uid {uid}'s.");
        var writable = (stat.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0;
        var rootSticky = owner == 0 && (stat.Mode & UnixFileMode.StickyBit) != 0;
        if (writable && !rootSticky)
            throw new TswapException(
                $"{parent} (a folder above the socket folder) is writable by group or others; refusing it.");
    }

    private static string Octal(UnixFileMode mode) => "0" + Convert.ToString((int)mode & 0xFFF, 8).PadLeft(3, '0');
}
