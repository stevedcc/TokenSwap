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
    /// Unlocks the vault, prompting for YubiKey selection if several are present.
    /// <paramref name="warnIfNoTouch"/> is suppressed for commands that never expose
    /// secret values on stdout/stderr (names, burned, burn, check), and in test mode
    /// (matching the historical test-key bypass, which skipped the warning).
    /// </summary>
    public byte[] Unlock(Config config, bool warnIfNoTouch = true)
    {
        if (warnIfNoTouch && TestKey == null)
            SecurityWarnings.WarnIfNoTouch(Console, config);
        return Unlocker.Unlock(config, ChooseSerial);
    }

    /// <summary>Loads the secrets database, surfacing recoverable-vault warnings on stderr.</summary>
    public TswapCore.SecretsDb LoadSecrets(byte[] key)
        => Storage.LoadSecrets(key, Console.Error);

    /// <summary>Resolves a connected YubiKey serial, prompting when several are present.</summary>
    public int SelectSerial(int? requiredSerial = null)
        => Unlocker.SelectConnectedSerial(ChooseSerial, requiredSerial);

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
        Console.Out.WriteLine("\nMultiple YubiKeys detected:");
        for (int i = 0; i < serials.Count; i++)
            Console.Out.WriteLine($"  {i + 1}. Serial: {serials[i]}");
        Console.Out.Write($"Select YubiKey (1-{serials.Count}): ");
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
