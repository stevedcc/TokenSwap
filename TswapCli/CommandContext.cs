using TswapCore;
using TswapCore.Vault;

namespace TswapCli;

/// <summary>
/// Everything a command needs to execute, wired once at the composition root.
/// <paramref name="TestKey"/> is non-null only in Debug builds with TSWAP_TEST_KEY
/// set; <paramref name="SudoBypass"/> likewise only via TSWAP_TEST_SUDO_BYPASS.
/// </summary>
public sealed record CommandContext(
    IConsole Console,
    CliEnvironment Env,
    IVaultStore Storage,
    IYubiKeyService YubiKeys,
    VaultUnlocker Unlocker,
    byte[]? TestKey,
    bool SudoBypass)
{
    // Brief T7 item 3 (#180): the store is opened at first use, so a command that never touches
    // it (help, prompt, completion, ...) never resolves the config folder.
    //
    // `Storage` in this initializer is the primary constructor's PARAMETER (initializers see
    // parameters before members), not the Storage property below, which reads _storage.Value.
    // Renaming the parameter doesn't silently turn this into recursion: the initializer would then
    // name the property, which a field initializer can't (error CS0236), so it stops compiling
    // (checked). Don't "fix" that by moving this into a member that reads the property.
    // CommandContextTests covers both constructors.
    private Lazy<IVaultStore> _storage = new(() => Storage);

    /// <summary>
    /// A context whose store is opened by <paramref name="openStorage"/> on first use (the binary's
    /// composition, <see cref="CliHost"/>).
    /// </summary>
    public CommandContext(
        IConsole console,
        CliEnvironment env,
        Func<IVaultStore> openStorage,
        IYubiKeyService yubiKeys,
        VaultUnlocker unlocker,
        byte[]? testKey,
        bool sudoBypass)
        : this(console, env, (IVaultStore)null!, yubiKeys, unlocker, testKey, sudoBypass)
    {
        _storage = new(openStorage);
    }

    /// <summary>The vault store, opened on first use.</summary>
    public IVaultStore Storage => _storage.Value;

    /// <summary>Brief T6 test seams for <c>migrate --to-records</c> (null outside tests).</summary>
    public RecordMigrationSeams? MigrationSeams { get; init; }

    public string Prefix => Env.Prefix;
    public bool Verbose => Env.Verbose;

    /// <summary>
    /// Unlocks the vault; with several YubiKeys plugged in, <see cref="UnlockSelection"/> decides.
    /// <paramref name="warnIfNoTouch"/> (the changed-posture notice) is suppressed for commands that never expose
    /// secret values on stdout/stderr (names, burned, burn, check), and in test mode
    /// (matching the historical test-key bypass, which skipped the warning).
    /// </summary>
    public byte[] Unlock(Config config, bool warnIfNoTouch = true)
    {
        // Brief T7 item 5: no banner; one line only for a touch posture that changed since it was
        // last acknowledged.
        if (warnIfNoTouch && TestKey == null)
            SecurityWarnings.NoticeIfChanged(Console, config);
        return Unlocker.Unlock(config, UnlockSelection());
    }

    /// <summary>
    /// How an unlock picks among several plugged-in YubiKeys (brief T7 item 4, #198):
    /// <c>TSWAP_YUBIKEY_SERIAL</c> if set; on a terminal a prompt on stderr (the touch-required key
    /// is the default); otherwise never a prompt (the unattended order).
    /// </summary>
    public YubiKeySelection UnlockSelection() => new()
    {
        Serial = ParseYubiKeySerialVariable(),
        Ask = Console.IsInputRedirected ? null : AskWhichKey,
    };

    private int? ParseYubiKeySerialVariable()
    {
        var value = Env.YubiKeySerialVariable;
        if (string.IsNullOrEmpty(value))
            return null;
        if (!int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var serial))
            throw new TswapException($"TSWAP_YUBIKEY_SERIAL '{value}' is not a YubiKey serial number.");
        return serial;
    }

    /// <summary>The terminal prompt of an unlock: on stderr, so stdout stays the command's output.</summary>
    private int AskWhichKey(IReadOnlyList<int> serials, IReadOnlyList<bool?> postures, int defaultSerial)
    {
        var e = Console.Error;
        var defaultNumber = 1;
        e.WriteLine("\nSeveral YubiKeys that can unlock this vault are plugged in:");
        for (int i = 0; i < serials.Count; i++)
        {
            var posture = postures[i] switch { true => "touch required", false => "no touch", null => "touch unknown" };
            var isDefault = serials[i] == defaultSerial;
            if (isDefault)
                defaultNumber = i + 1;
            e.WriteLine($"  {i + 1}. Serial: {serials[i]} ({posture}{(isDefault ? ", default" : "")})");
        }
        while (true)
        {
            e.Write($"Select YubiKey (1-{serials.Count}, default {defaultNumber}): ");
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(input)) // a blank answer or end of input: the default
                return defaultSerial;
            if (int.TryParse(input, out var choice) && choice >= 1 && choice <= serials.Count)
                return serials[choice - 1];
            e.WriteLine($"Enter a number between 1 and {serials.Count}, or press Enter for the default.");
        }
    }

    /// <summary>Loads the secrets database, surfacing recoverable-vault warnings on stderr.</summary>
    public TswapCore.SecretsDb LoadSecrets(byte[] key)
        => Storage.LoadSecrets(key, Console.Error);

    /// <summary>Resolves a connected YubiKey serial, prompting when several are present.</summary>
    public int SelectSerial(int? requiredSerial = null)
        => Unlocker.SelectConnectedSerial(ChooseSerial, requiredSerial);

    /// <summary>
    /// The key <c>create</c>/<c>rotate</c> ask for YubiKey entropy (any plugged-in key will do), chosen
    /// like an unlock's (brief T7 item 4): <c>TSWAP_YUBIKEY_SERIAL</c>, the stderr prompt on a
    /// terminal, otherwise the first plugged-in key without a prompt (an agent's <c>create</c> must
    /// not block).
    /// </summary>
    public int SelectEntropySerial()
    {
        var serials = YubiKeys.ListSerials();
        if (serials.Count == 0)
            throw new TswapException("No YubiKey detected. Please insert YubiKey.");
        return UnlockSelection().Order(serials, serials.Select(_ => (bool?)null).ToList(), serials)[0];
    }

    /// <summary>
    /// Picks one of <paramref name="serials"/>: the only one directly, else the prompt. Throws
    /// <see cref="TswapException"/> for an empty list. Used where only some of the plugged-in keys
    /// qualify (brief T4: enrolling a key that has no slot yet).
    /// </summary>
    public int ChooseSerialAmong(IReadOnlyList<int> serials)
    {
        if (serials.Count == 0)
            throw new TswapException("No YubiKey detected. Please insert YubiKey.");
        return serials.Count == 1 ? serials[0] : ChooseSerial(serials);
    }

    private int ChooseSerial(IReadOnlyList<int> serials)
    {
        Console.Error.WriteLine("\nMultiple YubiKeys detected:");
        for (int i = 0; i < serials.Count; i++)
            Console.Error.WriteLine($"  {i + 1}. Serial: {serials[i]}");
        Console.Error.Write($"Select YubiKey (1-{serials.Count}): ");
        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(input))
            return serials[0]; // blank/EOF = default to the first key
        if (!int.TryParse(input, out var choice) || choice < 1 || choice > serials.Count)
            throw new TswapException($"Invalid selection. Enter a number between 1 and {serials.Count}.");
        return serials[choice - 1];
    }

    /// <summary>
    /// Writes a file this command produces (receipt, request, approve or export file) through the
    /// store's safe writer (<see cref="TswapCore.IFileVaultStore.WriteFile"/>), so under sudo it
    /// gets its folder's owner and a symlink at the path is replaced, never written through.
    /// </summary>
    public void WriteOutputFile(string path, string contents)
    {
        if (Storage is TswapCore.IFileVaultStore fileStore)
            fileStore.WriteFile(path, contents);
        else
            TswapCore.DirectoryOwnerMatcher.Default.WriteAtomic(path, System.Text.Encoding.UTF8.GetBytes(contents));
    }

    /// <param name="reason">Brief T6: why sudo is needed here, for a command that needs it only sometimes.</param>
    public void RequireSudo(string commandName, string? reason = null)
    {
        if (SudoBypass) return;
        if (!Environment.IsPrivilegedProcess)
        {
            var msg = OperatingSystem.IsWindows()
                ? $"The '{commandName}' command requires an administrator prompt.\nRun tswap from an elevated command prompt."
                : $"The '{commandName}' command requires sudo.\nRun: sudo {Prefix} {commandName} ...";
            if (reason != null)
                msg += "\n" + reason;
            throw new TswapException(msg);
        }
    }
}
