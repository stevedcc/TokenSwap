namespace TswapCli.Commands;

public sealed class MigrateCommand : ICliCommand
{
    public string Name => "migrate";
    public string HelpUsage => "migrate";
    public string Description => "Guide to upgrade slots for touch requirement";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var c = ctx.Console;

        c.Out.WriteLine("\n╔════════════════════════════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Security Configuration Migration                    ║");
        c.Out.WriteLine("╚════════════════════════════════════════════════════════════════╝\n");

        var config = ctx.Storage.LoadConfig();

        // Each setting is checked independently so that a partially-migrated or
        // manually-edited config still gets prompted for whichever fields are missing.
        bool needsRngPrompt          = config.RngMode == null;
        bool needsChallengeMigration = config.UnlockChallenge == null;
        bool needsTouchMigration  = config.RequiresTouch != true;
        bool needsReInit          = needsChallengeMigration || needsTouchMigration;

        // ── Status ───────────────────────────────────────────────────────────────
        c.Out.WriteLine("Current configuration:");
        c.Out.WriteLine($"  YubiKey #1:       {config.YubiKeySerials[0]}");
        c.Out.WriteLine($"  YubiKey #2:       {config.YubiKeySerials[1]}");

        c.SetForeground(config.RequiresTouch == true ? ConsoleColor.Green : ConsoleColor.Yellow);
        c.Out.WriteLine(config.RequiresTouch == true
            ? "  Touch:            ENABLED ✓"
            : "  Touch:            not enabled ⚠");
        c.ResetColor();

        c.SetForeground(needsRngPrompt ? ConsoleColor.Yellow : ConsoleColor.Green);
        c.Out.WriteLine(needsRngPrompt
            ? "  Entropy mode:     not configured (defaults to system RNG) ⚠"
            : $"  Entropy mode:     {config.RngMode} ✓");
        c.ResetColor();

        c.SetForeground(needsChallengeMigration ? ConsoleColor.Yellow : ConsoleColor.Green);
        c.Out.WriteLine(needsChallengeMigration
            ? "  Unlock challenge: not set (fixed predictable challenge) ⚠"
            : "  Unlock challenge: vault-unique ✓");
        c.ResetColor();

        if (!needsRngPrompt && !needsReInit)
        {
            c.Out.WriteLine("\n✓ All security settings are up to date. No migration needed.");
            return 0;
        }

        // ── Entropy mode: update in place, no re-init required ───────────────────
        if (needsRngPrompt)
        {
            c.Out.WriteLine("\n── Entropy mode for 'create' (no re-init required) ─────────────");
            c.Out.WriteLine("Password generation entropy source:");
            c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
            c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary");
            c.Out.Write("Choose [1/2, default 1]: ");
            var rngChoice = c.ReadLine()?.Trim();
            var newRngMode = rngChoice == "2" ? "yubikey" : "system";
            config = config with { RngMode = newRngMode };
            ctx.Storage.SaveConfig(config);
            c.SetForeground(ConsoleColor.Green);
            c.Out.WriteLine($"✓ Entropy mode set to: {(newRngMode == "yubikey" ? "YubiKey hardware" : "System RNG")}");
            c.ResetColor();
        }

        // ── Items requiring re-init ───────────────────────────────────────────────
        if (needsReInit)
        {
            c.Out.WriteLine("\n── Settings requiring re-initialization ─────────────────────────");
            if (needsChallengeMigration)
            {
                c.Out.WriteLine("  • Unlock challenge: a vault-unique challenge requires re-challenging");
                c.Out.WriteLine("    both YubiKeys and re-encrypting the vault with a new master key.");
            }
            if (needsTouchMigration)
                c.Out.WriteLine("  • Touch requirement: YubiKey slots must be reconfigured.");

            c.Out.WriteLine("\n⚠️  IMPORTANT: Ensure your XOR share is backed up before proceeding.");

            c.Out.Write("\nShow detailed re-initialization instructions? (yes/no): ");
            if ((c.ReadLine()?.ToLower() ?? "") is "yes" or "y")
            {
                int step = 1;
                c.Out.WriteLine("\n" + new string('═', 64));
                c.Out.WriteLine("RE-INITIALIZATION GUIDE");
                c.Out.WriteLine(new string('═', 64) + "\n");

                c.Out.WriteLine($"Step {step++}: Export all secrets to an encrypted backup (requires sudo)");
                c.Out.WriteLine("  sudo tswap export ~/tswap-backup.enc");
                c.Out.WriteLine("  # Choose a strong passphrase — you will need it to import\n");

                if (needsTouchMigration)
                {
                    c.Out.WriteLine($"Step {step++}: Reconfigure YubiKey slots to require touch");
                    c.Out.WriteLine("  Insert YubiKey #1");
                    c.Out.WriteLine($"  ykman --device {config.YubiKeySerials[0]} otp delete 2");
                    c.Out.WriteLine($"  ykman --device {config.YubiKeySerials[0]} otp chalresp --generate --touch 2");
                    c.Out.WriteLine("  Remove YubiKey #1, insert YubiKey #2");
                    c.Out.WriteLine($"  ykman --device {config.YubiKeySerials[1]} otp delete 2");
                    c.Out.WriteLine($"  ykman --device {config.YubiKeySerials[1]} otp chalresp --generate --touch 2\n");
                }

                c.Out.WriteLine($"Step {step++}: Reinitialize tswap (generates a new vault-unique unlock challenge)");
                c.Out.WriteLine("  tswap init\n");

                c.Out.WriteLine($"Step {step}: Restore secrets from backup");
                c.Out.WriteLine("  sudo tswap import ~/tswap-backup.enc\n");

                c.Out.WriteLine(new string('═', 64));
            }
        }
        return 0;
    }
}
