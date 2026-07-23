using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;

namespace TswapCli.Commands;

public sealed class InitCommand : ICliCommand
{
    public string Name => "init";
    public string HelpUsage => "init";
    public string Description => "Initialize with 2 YubiKeys";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var c = ctx.Console;

        if (File.Exists(ctx.Storage.ConfigFile))
        {
            c.Out.Write("Already initialized. Reinitialize? (yes/no): ");
            if (c.ReadLine()?.ToLower() != "yes")
                return 0;
        }

        if (ctx.TestKey != null)
        {
            // Test mode: create synthetic config without YubiKey interaction
            var testConfig = new Config(
                new List<int> { TestKeyYubiKeyService.Serial1, TestKeyYubiKeyService.Serial2 },
                new string('0', 40), // 20-byte zero XOR share (hex)
                DateTime.UtcNow,
                null,
                "system",
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            );
            ctx.Storage.SaveConfig(testConfig);
            if (!File.Exists(ctx.Storage.SecretsFile))
                ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), ctx.TestKey);
            c.Out.WriteLine("Initialized (test mode)");
            return 0;
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - YubiKey Initialization       ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");

        // Generate a vault-unique unlock challenge so the HMAC response cannot be
        // pre-computed by someone who briefly accesses a YubiKey without the config.
        var unlockChallenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        // Challenge first YubiKey
        c.Out.WriteLine("Insert YubiKey #1 and press Enter...");
        if (!c.IsInputRedirected)
            c.ReadLine();
        var serial1 = ctx.SelectSerial();
        var k1 = ctx.YubiKeys.Challenge(serial1, unlockChallenge);

        // Challenge second YubiKey
        c.Out.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
        if (!c.IsInputRedirected)
            c.ReadLine();
        var serial2 = ctx.SelectSerial();

        if (serial1 == serial2)
            throw new TswapException("Same YubiKey detected. Please use two different YubiKeys.");

        var k2 = ctx.YubiKeys.Challenge(serial2, unlockChallenge);

        // Detect touch requirement for both keys
        c.Out.WriteLine("\nDetecting YubiKey slot configuration...");
        var touch1 = ctx.YubiKeys.DetectTouchRequirement(serial1);
        var touch2 = ctx.YubiKeys.DetectTouchRequirement(serial2);

        bool? requiresTouch = null;
        if (touch1.HasValue && touch2.HasValue)
        {
            requiresTouch = touch1.Value && touch2.Value;
        }

        // Compute XOR redundancy
        var xorShare = Crypto.XorBytes(k1, k2);

        // Choose RNG mode for secret generation
        c.Out.WriteLine("\nPassword generation entropy source:");
        c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
        c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
        c.Out.Write("Choose [1/2, default 1]: ");
        var rngChoice = c.ReadLine()?.Trim();
        var rngMode = rngChoice == "2" ? "yubikey" : "system";

        // Save config
        var config = new Config(
            new List<int> { serial1, serial2 },
            Convert.ToHexString(xorShare),
            DateTime.UtcNow,
            requiresTouch,
            rngMode,
            unlockChallenge
        );

        // Re-initialisation generates a new master key (new challenge + new XOR share), so any
        // existing vault is no longer decryptable with it. Back up both files before writing
        // new ones so recovery (restore both .bak files together) remains possible.
        // Config is backed up first — if anything fails mid-init the old config still matches
        // the old vault backup.
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        var newVaultKey = Crypto.DeriveKey(k1, k2);
        if (File.Exists(ctx.Storage.ConfigFile))
        {
            var configBackup = ctx.Storage.ConfigFile + ".bak-" + timestamp;
            File.Copy(ctx.Storage.ConfigFile, configBackup);
        }
        ctx.Storage.SaveConfig(config);
        if (File.Exists(ctx.Storage.SecretsFile))
        {
            var vaultBackup = ctx.Storage.SecretsFile + ".bak-" + timestamp;
            File.Move(ctx.Storage.SecretsFile, vaultBackup);
            c.SetForeground(ConsoleColor.Yellow);
            c.Out.WriteLine($"\nExisting vault moved to backup: {vaultBackup}");
            c.Out.WriteLine("Previous config backed up alongside it. To recover old secrets:");
            c.Out.WriteLine("  restore both .bak files under their original names.");
            c.ResetColor();
        }
        ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), newVaultKey);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"YubiKey Serials: {serial1}, {serial2}");

        // Report touch requirement status
        if (requiresTouch == true)
        {
            c.SetForeground(ConsoleColor.Green);
            c.Out.WriteLine("✓ Touch requirement: ENABLED (recommended)");
            c.ResetColor();
        }
        else if (requiresTouch == false)
        {
            c.SetForeground(ConsoleColor.Yellow);
            c.Out.WriteLine("⚠️  Touch requirement: DISABLED");
            c.Out.WriteLine("\nSECURITY NOTICE: Your YubiKeys are configured without button press");
            c.Out.WriteLine("requirement. Any process with access to inserted keys can unlock vault.");
            c.Out.WriteLine("\nTo enable touch requirement:");
            c.Out.WriteLine("  1. ykman otp delete 2      (for each key)");
            c.Out.WriteLine("  2. ykman otp chalresp --generate --touch 2");
            c.Out.WriteLine("  3. tswap init              (reinitialize)");
            c.ResetColor();
        }

        c.Out.WriteLine($"Entropy mode:    {(rngMode == "yubikey" ? "YubiKey hardware (two touches per create)" : "System RNG (one touch per create)")}");

        c.Out.WriteLine("\n⚠️  CRITICAL: BACKUP XOR SHARE NOW\n");
        c.Out.WriteLine("XOR Share (hex):");
        c.Out.WriteLine(config.RedundancyXor);
        c.Out.WriteLine("\nBackup locations required:");
        c.Out.WriteLine("  [ ] Password manager (Bitwarden/1Password)");
        c.Out.WriteLine("  [ ] Printed copy (home safe)");
        c.Out.WriteLine("  [ ] Second printed copy (off-site)");
        c.Out.WriteLine("  [ ] Git repository");
        c.Out.WriteLine($"\nConfig saved to: {ctx.Storage.ConfigFile}");
        return 0;
    }
}
