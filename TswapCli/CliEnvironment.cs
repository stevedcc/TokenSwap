using TswapCore;

namespace TswapCli;

/// <summary>
/// Everything the CLI derives from its process environment before dispatch:
/// invocation prefix (for usage text), config directory, verbose flag, and the
/// argument list with global flags stripped. Pure construction — the static
/// helpers take their environment access as parameters so every resolution
/// branch is unit-testable.
/// </summary>
public sealed class CliEnvironment
{
    public required string Prefix { get; init; }
    public required string ConfigDir { get; init; }
    public required bool Verbose { get; init; }

    /// <summary>Command-line args with -v/--verbose removed.</summary>
    public required string[] CommandArgs { get; init; }

    public static CliEnvironment FromSystem(string[] args) => new()
    {
        Prefix = DetectInvocationPrefix(Environment.ProcessPath),
        ConfigDir = ResolveConfigDir(
            Environment.GetEnvironmentVariable,
            Directory.Exists,
            Directory.Move,
            Console.Error,
            Environment.IsPrivilegedProcess,
            DefaultApplicationDataDir),
        Verbose = args.Any(a => a is "-v" or "--verbose"),
        CommandArgs = args.Where(a => a is not ("-v" or "--verbose")).ToArray(),
    };

    /// <summary>
    /// The per-user config base: $XDG_CONFIG_HOME or $HOME/.config on Unix, %APPDATA% on Windows.
    /// DoNotVerify because the default option returns "" when the folder doesn't exist yet (a
    /// fresh account), which would make the config dir relative to the current folder (#175);
    /// tswap creates its own folder below it on init.
    /// </summary>
    public static string DefaultApplicationDataDir()
        => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify);

    /// <summary>
    /// Detect how tswap was invoked to show correct usage examples.
    /// </summary>
    public static string DetectInvocationPrefix(string? processPath)
        => processPath == null ? "tswap" : Path.GetFileNameWithoutExtension(processPath);

    /// <summary>
    /// Resolves the config directory:
    /// <list type="bullet">
    /// <item>TSWAP_CONFIG_DIR overrides everything (used by tests).</item>
    /// <item>Under sudo <b>to root</b> on Unix (<paramref name="isPrivileged"/>), resolves
    /// relative to the invoking user's home so "sudo tswap get" finds the same database as
    /// "tswap create". The home is the passwd entry's (<paramref name="lookupUser"/>, default
    /// <see cref="UnixPasswd.Lookup"/>), used only when SUDO_UID matches its uid; SUDO_USER=root
    /// or SUDO_UID=0 is root's own folder. <c>sudo -i</c> also sets SUDO_USER, so it too uses the
    /// invoking user's vault (#178). Under <c>sudo -u &lt;non-root user&gt;</c> SUDO_USER still names the
    /// caller, but the target user's own vault is the right one, so SUDO_USER is ignored
    /// unless the process is privileged (#176). SUDO_USER is only set on Unix; on Windows,
    /// UAC elevation preserves APPDATA.</item>
    /// <item>Migrates the legacy tswap-poc directory to tswap (one-time, silent, only
    /// on the standard path, not when TSWAP_CONFIG_DIR is overridden).</item>
    /// </list>
    /// </summary>
    /// <summary>
    /// Brief T7 item 1 (#178, #107): the home of the user who ran sudo, from the system's passwd
    /// entry for <paramref name="sudoUser"/>, trusted only when <paramref name="sudoUid"/> (SUDO_UID)
    /// is that entry's uid. Null for root (SUDO_USER=root or SUDO_UID=0): root's own folder, not a
    /// redirect. Anything else that doesn't add up refuses, naming the values.
    /// </summary>
    private static string? InvokingUserHome(string sudoUser, string? sudoUid, Func<string, UnixPasswdEntry?> lookupUser)
    {
        if (sudoUser == "root" || sudoUid == "0")
            return null;
        if (sudoUid == null)
            throw new TswapException(
                $"SUDO_USER is '{sudoUser}' but SUDO_UID is not set, so tswap can't check whose vault to use. " +
                "Run tswap through sudo itself, or set TSWAP_CONFIG_DIR to the folder to use.");
        if (!uint.TryParse(sudoUid, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var uid))
            throw new TswapException(
                $"SUDO_UID '{sudoUid}' is not a number (SUDO_USER is '{sudoUser}'), so tswap can't check whose vault to use.");
        var entry = lookupUser(sudoUser)
            ?? throw new TswapException(
                $"SUDO_USER '{sudoUser}': no such user in the system's user database, so tswap can't find their vault.");
        if (entry.Uid != uid)
            throw new TswapException(
                $"SUDO_UID {uid} doesn't match the uid of SUDO_USER '{sudoUser}' ({entry.Uid}), so tswap won't use that user's vault.");
        if (!Path.IsPathRooted(entry.Home))
            throw new TswapException(
                $"The home folder of SUDO_USER '{sudoUser}' ('{entry.Home}') is not an absolute path. Set TSWAP_CONFIG_DIR to the folder to use.");
        return entry.Home;
    }

    public static string ResolveConfigDir(
        Func<string, string?> getEnv,
        Func<string, bool> directoryExists,
        Action<string, string> moveDirectory,
        TextWriter log,
        bool isPrivileged,
        Func<string>? getApplicationDataDir = null,
        Func<string, UnixPasswdEntry?>? lookupUser = null)
    {
        var configDirOverride = getEnv("TSWAP_CONFIG_DIR");
        if (configDirOverride != null)
            return configDirOverride;

        var sudoUser = getEnv("SUDO_USER");
        string appDataDir;
        if (sudoUser != null && isPrivileged && !OperatingSystem.IsWindows()
            && InvokingUserHome(sudoUser, getEnv("SUDO_UID"), lookupUser ?? UnixPasswd.Lookup) is { } userHome)
        {
            appDataDir = Path.Combine(userHome, ".config");
        }
        else
        {
            appDataDir = (getApplicationDataDir ?? DefaultApplicationDataDir)();
        }
        var configDir = Path.Combine(appDataDir, "tswap");
        if (!Path.IsPathRooted(configDir))
            throw new TswapException(
                "Cannot determine the config folder (no home folder to put it under). Set HOME, or TSWAP_CONFIG_DIR to the folder to use.");

        // Migrate legacy config directory tswap-poc -> tswap (one-time, silent).
        var legacyDir = Path.Combine(appDataDir, "tswap-poc");
        if (directoryExists(legacyDir) && !directoryExists(configDir))
        {
            moveDirectory(legacyDir, configDir);
            log.WriteLine($"Migrated config directory: {legacyDir} -> {configDir}");
        }

        return configDir;
    }
}
