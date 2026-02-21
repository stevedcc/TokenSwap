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
            // Example output line: "Slot 2: configured  Require touch: yes"
            var lines = output.Split('\n');
            foreach (var line in lines)
            {
                if (line.Contains($"Slot {slot}:"))
                {
                    // Check if "Require touch" appears after the slot line or in the same line
                    var slotInfo = line.ToLower();
                    
                    // Check if "require touch" and "yes" are present
                    if (slotInfo.Contains("require touch"))
                    {
                        return slotInfo.Contains("yes") || slotInfo.Contains("true");
                    }
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
