using TswapCore;

namespace TswapCli.Commands;

public sealed class MigrateCommand : ICliCommand
{
    public string Name => "migrate";
    public string HelpUsage => "migrate [--to-records [--vault-dir <dir>]]";
    public string Description => "Guide to upgrade slots for touch requirement; --to-records (sudo) converts the vault to one file per secret, shareable by sync tools";
    public bool RequiresSudo => false;

    /// <summary>Brief T16-S1 (ruling 5): every form of migrate works on a classic vault (converting it is the point).</summary>
    public bool WorksOnClassicVault => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        // Brief T6 decision 8: the record store conversion.
        if (args.Contains("--to-records") || args.Contains("--vault-dir"))
            return RecordMigration.Run(ctx, args);

        var c = ctx.Console;

        c.Out.WriteLine("\n╔════════════════════════════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Security Configuration Migration                    ║");
        c.Out.WriteLine("╚════════════════════════════════════════════════════════════════╝\n");

        var config = ctx.Storage.LoadConfig();

        // This whole command is YubiKey-specific (touch-requirement slots, XOR-redundancy
        // entropy choices) and unconditionally indexes YubiKeySerials[0]/[1] below, which a
        // TPM/Secure Enclave vault never populates (YubiKeySerials: []) — bail out with a clear
        // message instead of an index-out-of-range crash, same reasoning as the backend guard
        // in SecurityWarnings.WarnIfNoTouch.
        if (config.Backend is not (null or HardwareBackend.YubiKey))
        {
            c.Out.WriteLine($"'migrate' only applies to YubiKey vaults. This vault uses the " +
                $"'{config.Backend?.DisplayName}' backend, which has no touch/entropy settings to migrate.");
            return 0;
        }

        // Brief T7 item 5 / fix round 1: migrate is where the touch posture is reviewed. Each slot
        // whose posture changed since it was acknowledged is explained (its own posture, stderr) and
        // only those are acknowledged; everyday commands then stay quiet.
        var changed = SecurityWarnings.Changed(config);
        if (changed.Count > 0)
        {
            foreach (var (slot, _) in changed)
                SecurityWarnings.ExplainRecordedTouch(c, slot.Label, slot.Posture);
            config = SecurityWarnings.Acknowledge(config, [.. changed.Select(x => x.Slot.Key)]);
            ctx.Storage.SaveConfig(config);
        }

        // Fix round 2 (MiMo F2): what reaches here is a YubiKey vault (TPM and Secure Enclave vaults
        // returned above). A pending 'slot request' has no vault yet.
        if (config.Keyring is null && config.PendingSlotId is not null)
        {
            c.Out.WriteLine($"This machine has a pending slot request; nothing to migrate. Finish it first: {ctx.Prefix} slot accept <approve-file>");
            return 0;
        }

        // A classic vault (no keyring, no pending request) needs its two serials; anything else is
        // a damaged config, reported as the unlock reports it.
        if (config.Keyring is null && config.YubiKeySerials is not { Count: 2 })
            throw new TswapException(
                $"Config is corrupted: expected exactly 2 YubiKey serials, found {config.YubiKeySerials?.Count ?? 0}. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        // A one-key YubiKey keyring vault (brief T4) has no pair fields: the classic guide below
        // doesn't apply. (A legacy pair keyring vault has both serials and takes the classic path.)
        if (config.YubiKeySerials is not { Count: 2 })
        {
            c.Out.WriteLine("This is a keyring vault: each YubiKey is its own slot ('tswap slots' shows each key's touch");
            c.Out.WriteLine("setting). To give a key a touch requirement, one key at a time and with another way into the vault");
            c.Out.WriteLine("available (another enrolled key, this machine's TPM or Secure Enclave, or the recovery key):");
            c.Out.WriteLine($"  {ctx.Prefix} yubikey setup --replace --touch --serial N");
            c.Out.WriteLine($"  {ElevatedCommand.Line(ctx.Prefix, "slot add --yubikey")}   # enrols the reprogrammed key again");
            c.Out.WriteLine($"  {ctx.Prefix} names   # with only that key plugged in: it opens the vault alone");
            c.Out.WriteLine($"Only if no other way in is left: pipe the recovery key into {ElevatedCommand.Line(ctx.Prefix, "recover --yubikey")}");
            c.Out.WriteLine($"({ctx.Prefix} yubikey setup replaces the old command-line tool: ykman is no longer needed.)");
            return 0;
        }

        // Each setting is checked independently so that a partially-migrated or
        // manually-edited config still gets prompted for whichever fields are missing.
        bool needsRngPrompt          = config.RngMode is null;
        bool needsChallengeMigration = config.UnlockChallenge is null;
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
            : $"  Entropy mode:     {config.RngMode?.DisplayName} ✓");
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
            var newRngMode = rngChoice == "2" ? RngMode.YubiKey : RngMode.System;
            config = config with { RngMode = newRngMode };
            ctx.Storage.SaveConfig(config);
            c.SetForeground(ConsoleColor.Green);
            c.Out.WriteLine($"✓ Entropy mode set to: {(newRngMode == RngMode.YubiKey ? "YubiKey hardware" : "System RNG")}");
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

            c.Out.Write("\nShow detailed conversion instructions? (yes/no): ");
            if ((c.ReadLine()?.ToLower() ?? "") is "yes" or "y")
            {
                int step = 1;
                c.Out.WriteLine("\n" + new string('═', 64));
                c.Out.WriteLine("CONVERSION GUIDE");
                c.Out.WriteLine(new string('═', 64) + "\n");

                // Task 4b: convert, then (a legacy pair keyring vault) give each key its own slot, then the touch
                // upgrade one key at a time: reprogram, re-enrol through another way in, check it alone.
                var first = config.YubiKeySerials[0];
                var second = config.YubiKeySerials[1];
                var pairKeyring = config.Keyring is not null;
                c.Out.WriteLine($"Step {step++}: Export all secrets to an encrypted backup (requires sudo)");
                c.Out.WriteLine($"  {ElevatedCommand.Line(ctx.Prefix, "export ~/tswap-backup.enc")}");
                c.Out.WriteLine("  # Choose a strong passphrase — you will need it to import\n");

                c.Out.WriteLine($"Step {step++}: Convert the vault (a classic vault is converted, never re-initialized)");
                c.Out.WriteLine($"  {ElevatedCommand.Line(ctx.Prefix, "migrate --to-records")}");
                c.Out.WriteLine(pairKeyring
                    ? "  # The vault keeps its pair slot, which belongs to both keys together.\n"
                    : "  # Each YubiKey gets its own slot, and a recovery slot is added: keep the recovery key it shows.\n");

                if (needsTouchMigration && pairKeyring)
                {
                    c.Out.WriteLine($"Step {step++}: Give each YubiKey its own slot (a first enrolment), one key at a time, both keys plugged in");
                    c.Out.WriteLine($"  {ElevatedCommand.Line(ctx.Prefix, "slot add --yubikey")}   # YubiKey #1 ({first})");
                    c.Out.WriteLine($"  {ElevatedCommand.Line(ctx.Prefix, "slot add --yubikey")}   # YubiKey #2 ({second})\n");
                }

                if (needsTouchMigration)
                {
                    c.Out.WriteLine($"Step {step++}: Give each YubiKey a touch requirement, one key at a time");
                    c.Out.WriteLine("  # Reprogramming a key replaces slot 2's secret, so its slot stops opening the vault; with another way");
                    c.Out.WriteLine("  # in (the other key, or the recovery key) it is enrolled again. Finish and check one key before the next.");
                    foreach (var (number, serial, other) in new[] { (1, first, second), (2, second, first) })
                    {
                        c.Out.WriteLine($"  # YubiKey #{number} ({serial}), with YubiKey #{3 - number} ({other}) also plugged in:");
                        c.Out.WriteLine($"  {ctx.Prefix} yubikey setup --replace --touch --serial {serial}");
                        c.Out.WriteLine($"  {ElevatedCommand.Line(ctx.Prefix, "slot add --yubikey")}   # enrols it again (pick YubiKey {serial} if asked)");
                        c.Out.WriteLine($"  {ctx.Prefix} names   # with only YubiKey #{number} plugged in: it opens the vault alone");
                    }
                    c.Out.WriteLine($"  # {ctx.Prefix} yubikey setup replaces the old command-line tool: ykman is no longer needed.");
                    c.Out.WriteLine($"  # Only if no other way in is left: pipe the recovery key into {ElevatedCommand.Line(ctx.Prefix, "recover --yubikey")}\n");
                }

                c.Out.WriteLine(new string('═', 64));
            }
        }
        return 0;
    }
}

