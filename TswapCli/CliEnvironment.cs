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
    private Lazy<string> _configDir = new(() => throw new InvalidOperationException("No config folder was given."));

    public required string Prefix { get; init; }

    /// <summary>
    /// The config folder, resolved at first use (brief T7 item 3, #180): commands that need no
    /// vault (help, <c>prompt</c>, <c>completion</c>, ...) never read it, so they work without a
    /// home folder. Setting it gives a fixed folder (tests); <see cref="ConfigDirResolver"/>
    /// gives the deferred resolution.
    /// </summary>
    public string ConfigDir
    {
        get => _configDir.Value;
        init => _configDir = new(() => value);
    }

    /// <summary>Resolves <see cref="ConfigDir"/> on first use, once (a failure is rethrown on every use).</summary>
    public Func<string> ConfigDirResolver
    {
        init => _configDir = new(value);
    }

    public required bool Verbose { get; init; }

    /// <summary>
    /// <c>TSWAP_YUBIKEY_SERIAL</c> as given (brief T7 item 4): the YubiKey an unlock uses when several
    /// are plugged in. Null when unset. <c>sudo</c> drops it by default, which is intended.
    /// </summary>
    public string? YubiKeySerialVariable { get; init; }

    /// <summary>Command-line args with the leading global -v/--verbose flags removed.</summary>
    public required string[] CommandArgs { get; init; }

    public static CliEnvironment FromSystem(string[] args)
        => Create(args, Environment.GetEnvironmentVariable, Environment.IsPrivilegedProcess, Environment.ProcessPath, Console.Error);

    /// <summary>
    /// The environment for <paramref name="args"/>, with the process environment passed in
    /// (<see cref="CliHost"/>). The config folder is not resolved here, only on first use.
    /// </summary>
    public static CliEnvironment Create(
        string[] args, Func<string, string?> getEnv, bool isPrivileged, string? processPath, TextWriter log)
    {
        var (verbose, commandArgs) = SplitGlobalFlags(args);
        return new()
        {
            Prefix = DetectInvocationPrefix(processPath),
            ConfigDirResolver = () => ResolveConfigDir(
                getEnv,
                Directory.Exists,
                Directory.Move,
                log,
                isPrivileged,
                () => ApplicationDataDir(getEnv)),
            Verbose = verbose,
            CommandArgs = commandArgs,
            YubiKeySerialVariable = getEnv("TSWAP_YUBIKEY_SERIAL"),
        };
    }

    /// <summary>
    /// Splits off tswap's global flags (<c>-v</c>/<c>--verbose</c>): only the leading run before
    /// the command name (brief T7 item 2, #182). Everything from the command name on is the
    /// command's, so <c>tswap run grep -v x {{s}}</c> keeps grep's <c>-v</c> and a burn reason
    /// that is literally <c>-v</c> is kept.
    /// </summary>
    public static (bool Verbose, string[] CommandArgs) SplitGlobalFlags(string[] args)
    {
        var i = 0;
        while (i < args.Length && args[i] is "-v" or "--verbose")
            i++;
        return (i > 0, args[i..]);
    }

    /// <summary>
    /// The per-user config base: $XDG_CONFIG_HOME or $HOME/.config on Unix, %APPDATA% on Windows.
    /// DoNotVerify because the default option returns "" when the folder doesn't exist yet (a
    /// fresh account), which would make the config dir relative to the current folder (#175);
    /// tswap creates its own folder below it on init.
    /// </summary>
    public static string DefaultApplicationDataDir() => ApplicationDataDir(Environment.GetEnvironmentVariable);

    /// <summary>
    /// <see cref="DefaultApplicationDataDir"/> with the environment passed in. On Linux (and other
    /// Unixes but macOS) per the XDG Base Directory spec: <c>$XDG_CONFIG_HOME</c> when it is an
    /// absolute path (a relative one is ignored, #180), else <c>$HOME/.config</c> when HOME is an
    /// absolute path, else "" (the caller refuses). macOS and Windows: .NET's folder.
    /// </summary>
    public static string ApplicationDataDir(Func<string, string?> getEnv)
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS())
            return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        var xdg = getEnv("XDG_CONFIG_HOME");
        if (!string.IsNullOrEmpty(xdg) && Path.IsPathRooted(xdg))
            return xdg;
        var home = getEnv("HOME");
        return !string.IsNullOrEmpty(home) && Path.IsPathRooted(home) ? Path.Combine(home, ".config") : "";
    }

    /// <summary>
    /// Detect how tswap was invoked to show correct usage examples.
    /// </summary>
    public static string DetectInvocationPrefix(string? processPath)
        => processPath is null ? "tswap" : Path.GetFileNameWithoutExtension(processPath);

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
        if (sudoUid is null)
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

    /// <summary>
    /// macOS only (T7 fix round 1): from a300bf8 until T7, sudo used <c>&lt;home&gt;/.config/tswap</c>
    /// while the user's own commands used <c>~/Library/Application Support/tswap</c>, so a vault may
    /// be in either. Nothing is moved or picked silently: with a vault only in the old folder, or in
    /// both, tswap stops and says what to do.
    /// </summary>
    private static void RefuseAmbiguousMacVault(string configDir, string legacyDir, Func<string, bool> fileExists)
    {
        if (string.Equals(Path.GetFullPath(configDir), Path.GetFullPath(legacyDir), StringComparison.Ordinal))
            return;
        var inCurrent = fileExists(Path.Combine(configDir, "config.json"));
        var inLegacy = fileExists(Path.Combine(legacyDir, "config.json"));
        if (inLegacy && inCurrent)
            throw new TswapException(
                $"There is a tswap vault in both {configDir} and {legacyDir} (an older tswap used the second under sudo). " +
                $"tswap won't pick one silently: keep the one you use, move the other aside, or set TSWAP_CONFIG_DIR to the folder to use.");
        if (inLegacy)
            throw new TswapException(
                $"No vault in {configDir}, but there is one in {legacyDir} (an older tswap used that folder under sudo). " +
                $"Move it: mv \"{legacyDir}\" \"{configDir}\" (with the parent folder created), or set TSWAP_CONFIG_DIR={legacyDir}. " +
                "tswap didn't create or move anything.");
    }

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
    public static string ResolveConfigDir(
        Func<string, string?> getEnv,
        Func<string, bool> directoryExists,
        Action<string, string> moveDirectory,
        TextWriter log,
        bool isPrivileged,
        Func<string>? getApplicationDataDir = null,
        Func<string, UnixPasswdEntry?>? lookupUser = null,
        Func<string, bool>? fileExists = null,
        bool? isMacOS = null)
    {
        var configDirOverride = getEnv("TSWAP_CONFIG_DIR");
        if (configDirOverride is not null)
            return configDirOverride;

        var macOS = isMacOS ?? OperatingSystem.IsMacOS();
        var sudoUser = getEnv("SUDO_USER");
        string appDataDir;
        string? home;
        if (sudoUser is not null && isPrivileged && !OperatingSystem.IsWindows()
            && InvokingUserHome(sudoUser, getEnv("SUDO_UID"), lookupUser ?? (name => UnixPasswd.Lookup(name))) is { } userHome)
        {
            // T7 fix round 1 (MiMo's review): the same per-platform folder as the user's own
            // resolution. Linux: <home>/.config (the user's XDG_CONFIG_HOME isn't known under sudo);
            // macOS: <home>/Library/Application Support, .NET's ApplicationData there.
            home = userHome;
            appDataDir = macOS ? Path.Combine(userHome, "Library", "Application Support") : Path.Combine(userHome, ".config");
        }
        else
        {
            home = getEnv("HOME");
            appDataDir = (getApplicationDataDir ?? DefaultApplicationDataDir)();
        }
        var configDir = Path.Combine(appDataDir, "tswap");
        if (!Path.IsPathRooted(configDir))
        {
            var xdg = getEnv("XDG_CONFIG_HOME");
            var xdgNote = !OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS() && !string.IsNullOrEmpty(xdg) && !Path.IsPathRooted(xdg)
                ? $" XDG_CONFIG_HOME ('{xdg}') is ignored because it is not an absolute path."
                : "";
            throw new TswapException(
                "Cannot determine the config folder (no home folder to put it under). Set HOME, or TSWAP_CONFIG_DIR to the folder to use." + xdgNote);
        }

        if (macOS && !string.IsNullOrEmpty(home) && Path.IsPathRooted(home))
            RefuseAmbiguousMacVault(configDir, Path.Combine(home, ".config", "tswap"), fileExists ?? File.Exists);

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
