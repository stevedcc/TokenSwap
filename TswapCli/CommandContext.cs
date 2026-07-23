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
    Storage Storage,
    IYubiKeyService YubiKeys,
    VaultUnlocker Unlocker,
    byte[]? TestKey,
    bool SudoBypass)
{
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

    public void RequireSudo(string commandName)
    {
        if (SudoBypass) return;
        if (!Environment.IsPrivilegedProcess)
        {
            var msg = OperatingSystem.IsWindows()
                ? $"The '{commandName}' command requires an administrator prompt.\nRun tswap from an elevated command prompt."
                : $"The '{commandName}' command requires sudo.\nRun: sudo {Prefix} {commandName} ...";
            throw new TswapException(msg);
        }
    }
}
