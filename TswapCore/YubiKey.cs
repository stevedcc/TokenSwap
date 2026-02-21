using System.Diagnostics;

namespace TswapCore;

public class YubiKey
{
    /// <summary>
    /// Checks if a YubiKey slot is configured to require touch.
    /// Returns null if detection fails.
    /// </summary>
    public static bool? DetectTouchRequirement(int serial, int slot = 2)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ykman",
                Arguments = $"--device {serial} otp info",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null)
                return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
                return null;

            // Parse output to check if slot 2 has "Require touch" enabled
            // Example output: "Slot 2: configured" with flags on same or subsequent lines
            var lines = output.Split('\n');
            bool foundSlot = false;
            foreach (var line in lines)
            {
                var slotInfo = line.ToLower();
                
                if (slotInfo.Contains($"slot {slot}:"))
                {
                    foundSlot = true;
                    // Check if "require touch" is on the same line
                    if (slotInfo.Contains("require touch"))
                    {
                        return slotInfo.Contains("yes") || slotInfo.Contains("true");
                    }
                }
                else if (foundSlot && slotInfo.Contains("require touch"))
                {
                    // "Require touch" on subsequent line after slot declaration
                    return slotInfo.Contains("yes") || slotInfo.Contains("true");
                }
                else if (foundSlot && slotInfo.Trim() == "")
                {
                    // Empty line after slot - no more slot info
                    break;
                }
            }

            return false; // Slot configured but no touch requirement found
        }
        catch
        {
            return null; // Detection failed
        }
    }

    /// <summary>
    /// Print a warning if YubiKey slots don't require touch
    /// </summary>
    public static void WarnIfNoTouch(Config config)
    {
        if (config.RequiresTouch == false)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n╔═══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║  ⚠️  SECURITY WARNING: YubiKey slots configured without touch    ║");
            Console.WriteLine("╠═══════════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║  Your YubiKeys are configured without requiring button press.    ║");
            Console.WriteLine("║  This means any process can unlock the vault if the key is       ║");
            Console.WriteLine("║  inserted, weakening the security model.                         ║");
            Console.WriteLine("║                                                                   ║");
            Console.WriteLine("║  Recommended: Run 'tswap migrate' to upgrade to touch-required   ║");
            Console.WriteLine("║  slots for better security.                                       ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
