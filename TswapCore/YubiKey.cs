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

            return ParseTouchRequirement(output, slot);
        }
        catch
        {
            return null; // Detection failed
        }
    }

    /// <summary>
    /// Parse ykman otp info output to determine if a slot requires touch.
    /// Returns true if touch is required, false if not required, null if slot not found/configured.
    /// </summary>
    internal static bool? ParseTouchRequirement(string output, int slot = 2)
    {
        if (string.IsNullOrEmpty(output))
            return null;

        // Parse output to check if slot has "Require touch" enabled
        // Example output: "Slot 2: configured" with flags on same or subsequent lines
        var lines = output.Split('\n');
        bool foundSlot = false;
        bool slotConfigured = false;
        
        foreach (var line in lines)
        {
            var slotInfo = line.ToLower();
            
            // Check if this is a different slot line (reset state)
            if (slotInfo.Contains("slot ") && slotInfo.Contains(":"))
            {
                // If we were tracking a slot and hit a new slot, we're done
                if (foundSlot && !slotInfo.Contains($"slot {slot}:"))
                {
                    break;
                }
                
                if (slotInfo.Contains($"slot {slot}:"))
                {
                    foundSlot = true;
                    
                    // Check if slot is actually configured (not empty)
                    if (slotInfo.Contains("empty"))
                    {
                        return null; // Slot not configured
                    }
                    
                    if (slotInfo.Contains("configured"))
                    {
                        slotConfigured = true;
                    }
                    
                    // Check if "require touch" or just "touch" is on the same line
                    if (slotInfo.Contains("require touch") || slotInfo.Contains("touch:"))
                    {
                        return slotInfo.Contains("yes") || slotInfo.Contains("true");
                    }
                }
            }
            else if (foundSlot && slotConfigured && (slotInfo.Contains("require touch") || slotInfo.Contains("touch:")))
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

        // If we found the slot and it's configured but no touch requirement, it's configured without touch
        if (foundSlot && slotConfigured)
            return false;

        // Slot not found or not configured
        return null;
    }

    /// <summary>
    /// Print a warning if YubiKey slots don't require touch or status is unknown
    /// </summary>
    public static void WarnIfNoTouch(Config config)
    {
        if (config.RequiresTouch != true)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n╔═══════════════════════════════════════════════════════════════════╗");
            
            if (config.RequiresTouch == false)
            {
                Console.WriteLine("║  ⚠️  SECURITY WARNING: YubiKey slots configured without touch    ║");
                Console.WriteLine("╠═══════════════════════════════════════════════════════════════════╣");
                Console.WriteLine("║  Your YubiKeys are configured without requiring button press.    ║");
                Console.WriteLine("║  This means any process can unlock the vault if the key is       ║");
                Console.WriteLine("║  inserted, weakening the security model.                         ║");
            }
            else // config.RequiresTouch == null
            {
                Console.WriteLine("║  ⚠️  SECURITY WARNING: YubiKey touch requirement unknown         ║");
                Console.WriteLine("╠═══════════════════════════════════════════════════════════════════╣");
                Console.WriteLine("║  Unable to detect if your YubiKeys require button press.         ║");
                Console.WriteLine("║  This may indicate ykman is not installed or detection failed.   ║");
                Console.WriteLine("║  If touch is not required, any process can unlock the vault.     ║");
            }
            
            Console.WriteLine("║                                                                   ║");
            Console.WriteLine("║  Recommended: Run 'tswap migrate' to upgrade to touch-required   ║");
            Console.WriteLine("║  slots for better security.                                       ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
