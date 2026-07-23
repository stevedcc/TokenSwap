using TswapCore;

namespace TswapCli;

/// <summary>
/// Renders security warning banners. The *decision* (does this config warrant a
/// warning?) is a one-line check on <see cref="Config.RequiresTouch"/>; the console
/// rendering lives here so TswapCore stays free of console I/O.
/// </summary>
public static class SecurityWarnings
{
    /// <summary>
    /// Print a warning to stderr if YubiKey slots don't require touch or status is unknown.
    /// </summary>
    public static void WarnIfNoTouch(IConsole console, Config config)
    {
        if (config.RequiresTouch == true)
            return;

        var e = console.Error;
        console.SetForeground(ConsoleColor.Yellow);
        e.WriteLine("\n╔═══════════════════════════════════════════════════════════════════╗");

        if (config.RequiresTouch == false)
        {
            e.WriteLine("║  [!]  SECURITY WARNING: YubiKey slots configured without touch    ║");
            e.WriteLine("╠═══════════════════════════════════════════════════════════════════╣");
            e.WriteLine("║  Your YubiKeys are configured without requiring button press.     ║");
            e.WriteLine("║  This means any process can unlock the vault if the key is        ║");
            e.WriteLine("║  inserted, weakening the security model.                          ║");
        }
        else // config.RequiresTouch == null
        {
            e.WriteLine("║  [!]  SECURITY WARNING: YubiKey touch requirement unknown         ║");
            e.WriteLine("╠═══════════════════════════════════════════════════════════════════╣");
            e.WriteLine("║  Unable to detect if your YubiKeys require button press.          ║");
            e.WriteLine("║  This may indicate ykman is not installed or detection failed.    ║");
            e.WriteLine("║  If touch is not required, any process can unlock the vault.      ║");
        }

        e.WriteLine("║                                                                   ║");
        e.WriteLine("║  Recommended: Run 'tswap migrate' to upgrade to touch-required    ║");
        e.WriteLine("║  slots for better security.                                       ║");
        e.WriteLine("╚═══════════════════════════════════════════════════════════════════╝");
        console.ResetColor();
        e.WriteLine();
    }
}
