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
    /// <item>Under sudo on Unix, resolves relative to the invoking user's home so
    /// "sudo tswap get" finds the same database as "tswap create". SUDO_USER is only
    /// set on Unix; on Windows, UAC elevation preserves APPDATA.</item>
    /// <item>Migrates the legacy tswap-poc directory to tswap (one-time, silent, only
    /// on the standard path, not when TSWAP_CONFIG_DIR is overridden).</item>
    /// </list>
    /// </summary>
    public static string ResolveConfigDir(
        Func<string, string?> getEnv,
        Func<string, bool> directoryExists,
        Action<string, string> moveDirectory,
        TextWriter log,
        Func<string>? getApplicationDataDir = null)
    {
        var configDirOverride = getEnv("TSWAP_CONFIG_DIR");
        if (configDirOverride != null)
            return configDirOverride;

        var sudoUser = getEnv("SUDO_USER");
        string appDataDir;
        if (sudoUser != null && !OperatingSystem.IsWindows())
        {
            var userHome = OperatingSystem.IsMacOS()
                ? Path.Combine("/Users", sudoUser)
                : Path.Combine("/home", sudoUser);
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
